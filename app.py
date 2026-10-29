"""LedgerTrace API. Local only: meant for 127.0.0.1:8002, talks to nobody."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import analysis
import db

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
COOKIE = "lt_session"
TTL = 8 * 3600
MAX_BODY = 16 * 1024
ORIGINS = ["http://localhost:8002", "http://127.0.0.1:8002"]
ADDR = r"^sim1[a-z]{3,4}[0-9]{5}$"
TXID = r"^[0-9a-f]{16}$"
PATTERN_KINDS = ("peel_chain", "fan_out", "fan_in", "mixer_like")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")

ph = PasswordHasher()
DUMMY = ph.hash("not-a-real-password")
db.init()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=True,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-CSRF-Token"])


@app.middleware("http")
async def harden(request: Request, call_next):
    size = request.headers.get("content-length", "0")
    if size.isascii() and size.isdigit() and int(size) > MAX_BODY:
        return JSONResponse({"detail": "payload too large"}, status_code=413)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


class Creds(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=10, max_length=128)


class CaseIn(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[\w .,\-]+$")
    seed_txid: str = Field(pattern=TXID)
    seed_vout: int = Field(0, ge=0, le=63)
    method: Literal["poison", "haircut", "fifo"] = "haircut"
    max_hops: int = Field(8, ge=1, le=12)


# ---- auth plumbing -------------------------------------------------------

_hits = defaultdict(deque)


def throttle(key, limit, window=60):
    q, now = _hits[key], time.monotonic()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "too many requests, wait a minute", headers={"Retry-After": str(window)})
    q.append(now)


def ip_of(request: Request):
    return request.client.host if request.client else "?"


def digest(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def open_session(c, uid, response):
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
    c.execute("INSERT INTO sessions(token_hash, user_id, csrf, expires_at) VALUES(?,?,?,?)",
              (digest(tok), uid, csrf, int(time.time()) + TTL))
    # No Secure flag on purpose: this only ever runs on plain-http localhost.
    response.set_cookie(COOKIE, tok, max_age=TTL, httponly=True, samesite="strict", path="/")
    return csrf


def current(request: Request):
    tok, row = request.cookies.get(COOKIE), None
    if tok:
        with db.conn() as c:
            row = c.execute("SELECT u.id, u.username, s.csrf, s.expires_at FROM sessions s "
                            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (digest(tok),)).fetchone()
    if not row or row["expires_at"] < time.time():
        raise HTTPException(401, "not logged in")
    return dict(row)


def mutating(request: Request, user=Depends(current)):
    sent = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(sent.encode(), user["csrf"].encode()):
        raise HTTPException(403, "bad CSRF token")
    origin = request.headers.get("origin")
    if origin and origin not in ORIGINS:
        raise HTTPException(403, "bad origin")
    return user


@app.post("/api/register")
def register(body: Creds, request: Request, response: Response):
    throttle("auth:" + ip_of(request), 8)
    with db.conn() as c:
        try:
            uid = c.execute("INSERT INTO users(username, pw_hash, created_at) VALUES(?,?,?)",
                            (body.username, ph.hash(body.password), db.now())).lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "username taken")
        csrf = open_session(c, uid, response)
    return {"username": body.username, "csrf": csrf}


@app.post("/api/login")
def login(body: Creds, request: Request, response: Response):
    throttle("auth:" + ip_of(request), 8)
    with db.conn() as c:
        u = c.execute("SELECT id, pw_hash FROM users WHERE username = ?", (body.username,)).fetchone()
        try:
            ph.verify(u["pw_hash"] if u else DUMMY, body.password)
            ok = u is not None
        except (VerificationError, InvalidHashError):
            ok = False
        if not ok:
            raise HTTPException(401, "wrong username or password")
        csrf = open_session(c, u["id"], response)
    return {"username": body.username, "csrf": csrf}


@app.post("/api/logout")
def logout(request: Request, response: Response, user=Depends(mutating)):
    with db.conn() as c:
        c.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(request.cookies[COOKIE]),))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current)):
    return {"username": user["username"], "csrf": user["csrf"]}


# ---- ledger browsing -----------------------------------------------------

@app.get("/api/stats")
def stats(user=Depends(current)):
    with db.conn() as c:
        one = lambda sql: c.execute(sql).fetchone()[0]
        return {"txs": one("SELECT COUNT(*) FROM txs"), "addresses": one("SELECT COUNT(DISTINCT address) FROM outputs"),
                "clusters": one("SELECT COUNT(DISTINCT cluster) FROM clusters"), "patterns": one("SELECT COUNT(*) FROM patterns"),
                "labelled": one("SELECT COUNT(*) FROM addresses"),
                "flags": [dict(r) for r in c.execute("SELECT txid, kind, note FROM flags")]}


@app.get("/api/patterns")
def patterns(kind: str = Query("", max_length=16), user=Depends(current)):
    if kind and kind not in PATTERN_KINDS:
        raise HTTPException(422, "unknown pattern kind")
    with db.conn() as c:
        rows = c.execute("SELECT kind, txid, size, detail FROM patterns WHERE (? = '' OR kind = ?) "
                         "ORDER BY size DESC, txid LIMIT 100", (kind, kind)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/risk")
def risk(limit: int = Query(15, ge=1, le=50), user=Depends(current)):
    with db.conn() as c:
        rows = c.execute("SELECT r.address, r.score, r.reasons, COALESCE(a.label, '') AS label FROM risk_scores r "
                         "LEFT JOIN addresses a ON a.address = r.address ORDER BY r.score DESC, r.address LIMIT ?",
                         (limit,)).fetchall()
    return [{"address": r["address"], "label": r["label"], "score": r["score"], "reasons": json.loads(r["reasons"])}
            for r in rows]


@app.get("/api/address/{addr}")
def address(addr: str = Path(..., pattern=ADDR), user=Depends(current)):
    with db.conn() as c:
        seen = c.execute("SELECT COUNT(*) FROM outputs WHERE address = ?", (addr,)).fetchone()[0]
        if not seen:
            raise HTTPException(404, "address not found")
        label = c.execute("SELECT label, kind FROM addresses WHERE address = ?", (addr,)).fetchone()
        cl = c.execute("SELECT cluster FROM clusters WHERE address = ?", (addr,)).fetchone()
        size = c.execute("SELECT COUNT(*) FROM clusters WHERE cluster = ?", (cl["cluster"],)).fetchone()[0] if cl else 1
        bal = c.execute("SELECT COALESCE(SUM(value), 0) FROM outputs WHERE address = ? AND spent_by IS NULL", (addr,)).fetchone()[0]
        rk = c.execute("SELECT score, reasons FROM risk_scores WHERE address = ?", (addr,)).fetchone()
        recent = c.execute(
            "SELECT t.txid, t.height, t.ts FROM txs t JOIN outputs o ON o.txid = t.txid WHERE o.address = ? "
            "UNION SELECT t.txid, t.height, t.ts FROM txs t JOIN inputs i ON i.txid = t.txid "
            "JOIN outputs p ON p.txid = i.prev_txid AND p.n = i.prev_n WHERE p.address = ? "
            "ORDER BY height DESC LIMIT 15", (addr, addr)).fetchall()
    return {"address": addr, "label": label["label"] if label else "", "kind": label["kind"] if label else "user",
            "cluster": cl["cluster"] if cl else None, "cluster_size": size, "balance": bal,
            "risk": rk["score"] if rk else 0, "reasons": json.loads(rk["reasons"]) if rk else [],
            "recent": [dict(r) for r in recent]}


@app.get("/api/tx/{txid}")
def tx(txid: str = Path(..., pattern=TXID), user=Depends(current)):
    with db.conn() as c:
        t = c.execute("SELECT txid, seq, height, ts FROM txs WHERE txid = ?", (txid,)).fetchone()
        if not t:
            raise HTTPException(404, "transaction not found")
        ins = c.execute("SELECT p.address, p.value, i.prev_txid, i.prev_n FROM inputs i "
                        "JOIN outputs p ON p.txid = i.prev_txid AND p.n = i.prev_n WHERE i.txid = ? ORDER BY i.n", (txid,)).fetchall()
        outs = c.execute("SELECT n, address, value, spent_by FROM outputs WHERE txid = ? ORDER BY n", (txid,)).fetchall()
    return {**dict(t), "inputs": [dict(r) for r in ins], "outputs": [dict(r) for r in outs]}


# ---- cases ---------------------------------------------------------------

@app.post("/api/cases")
def create_case(body: CaseIn, user=Depends(mutating)):
    throttle(f"case:{user['id']}", 20)
    with db.conn() as c:
        try:
            cid = analysis.open_case(c, user["id"], body.name, body.seed_txid, body.seed_vout, body.method, body.max_hops)
        except KeyError:
            raise HTTPException(404, "seed output not found")
    return {"id": cid}


@app.get("/api/compare")
def compare(txid: str = Query(..., pattern=TXID), vout: int = Query(0, ge=0, le=63),
            hops: int = Query(8, ge=1, le=12), user=Depends(current)):
    with db.conn() as c:
        try:
            return analysis.compare(c, txid, vout, hops)
        except KeyError:
            raise HTTPException(404, "seed output not found")


@app.get("/api/cases")
def cases(user=Depends(current)):
    with db.conn() as c:
        rows = c.execute("SELECT id, name, method, max_hops, created_at, summary FROM cases WHERE user_id = ? "
                         "ORDER BY id DESC LIMIT 30", (user["id"],)).fetchall()
    return [{**dict(r), "summary": json.loads(r["summary"])} for r in rows]


def load_case(c, cid, uid):
    r = c.execute("SELECT id, name, seed_txid, seed_vout, method, max_hops, created_at, summary, graph FROM cases "
                  "WHERE id = ? AND user_id = ?", (cid, uid)).fetchone()
    if not r:
        raise HTTPException(404, "case not found")
    hits = c.execute("SELECT address, txid, hops, taint, kind, label FROM case_hits WHERE case_id = ? "
                     "ORDER BY taint DESC, hops LIMIT 100", (cid,)).fetchall()
    return {**dict(r), "summary": json.loads(r["summary"]), "graph": json.loads(r["graph"]), "hits": [dict(h) for h in hits]}


@app.get("/api/cases/{cid}")
def case_detail(cid: int, user=Depends(current)):
    with db.conn() as c:
        return load_case(c, cid, user["id"])


def cell(v):
    return re.sub(r"[|\r\n]+", " ", str(v)).replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


@app.get("/api/cases/{cid}/report.md")
def case_report(cid: int, user=Depends(current)):
    with db.conn() as c:
        k = load_case(c, cid, user["id"])
    s = k["summary"]
    pct = lambda v: f"{v / s['seed_value']:.1%}" if s["seed_value"] else "n/a"
    out = [f"# LedgerTrace case: {cell(k['name'])}", "",
           f"- Seed output: `{k['seed_txid']}:{k['seed_vout']}` ({s['seed_value']} units)",
           f"- Method: {k['method']}, up to {k['max_hops']} hops", f"- Opened: {k['created_at']}",
           f"- Transactions touched: {s['txs_touched']} (deepest hop {s['max_hop']})", "",
           "## Exposure", "", "| Destination | Tainted units | Share of seed |", "|---|---|---|",
           f"| Exchanges | {s['exchange']} | {pct(s['exchange'])} |", f"| Mixers | {s['mixer']} | {pct(s['mixer'])} |",
           f"| Dormant (unspent) | {s['dormant']} | {pct(s['dormant'])} |", "",
           "## Hits", "", "| Address | Kind | Label | Hops | Tainted units | Tx |", "|---|---|---|---|---|---|"]
    out += [f"| {cell(h['address'])} | {cell(h['kind'])} | {cell(h['label'])} | {h['hops']} | {h['taint']} | {cell(h['txid'])} |"
            for h in k["hits"]]
    out += ["", "## Caveats", "",
            "- Hit values are per destination and are not de-duplicated across hops.",
            "- Taint methods are conventions (poison over-attributes, haircut dilutes, FIFO assumes ordering), not facts about ownership.",
            "- Simulated data only. Heuristics are leads for a human investigator, not proof.", ""]
    return PlainTextResponse("\n".join(out), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="ledgertrace-case-{cid}.md"'})


# ---- frontend ------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


app.mount("/static", StaticFiles(directory=WEB), name="static")
