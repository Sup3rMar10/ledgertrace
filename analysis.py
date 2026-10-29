"""Graph analysis over a simulated UTXO ledger: clustering, change detection, patterns, taint tracing, risk.

Every heuristic here is a hint with known failure modes (CoinJoin, shared wallets, address reuse).
Output is investigative leads, never proof of ownership.
"""
import heapq
import json
from collections import Counter

import db

TAINT_METHODS = ("poison", "haircut", "fifo")


class Ledger:
    """In-memory view of the DB: txs by txid (seq order), outputs by (txid, n), labels, first-seen seq."""

    def __init__(self, c):
        self.txs, self.out, self.label, self.first = {}, {}, {}, {}
        for r in c.execute("SELECT txid, seq, height FROM txs ORDER BY seq"):
            self.txs[r["txid"]] = {"seq": r["seq"], "height": r["height"], "ins": [], "outs": []}
        for r in c.execute("SELECT txid, prev_txid, prev_n FROM inputs ORDER BY txid, n"):
            self.txs[r["txid"]]["ins"].append((r["prev_txid"], r["prev_n"]))
        for r in c.execute("SELECT txid, n, address, value, spent_by FROM outputs ORDER BY txid, n"):
            self.txs[r["txid"]]["outs"].append((r["address"], r["value"]))
            self.out[(r["txid"], r["n"])] = (r["address"], r["value"], r["spent_by"])
        for r in c.execute("SELECT address, label, kind FROM addresses"):
            self.label[r["address"]] = (r["label"], r["kind"])
        for t in self.txs.values():
            for a, _ in t["outs"]:
                self.first.setdefault(a, t["seq"])


# ---- heuristics ------------------------------------------------------------

def mixer_like(t):
    vals = [v for _, v in t["outs"]]
    return len(t["ins"]) >= 4 and len(vals) >= 4 and Counter(vals).most_common(1)[0][1] >= 4


def clusters(L):
    """Common-input-ownership: addresses spent together share an owner. Skips CoinJoin-like txs."""
    parent = {}

    def find(a):
        parent.setdefault(a, a)
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    for t in L.txs.values():
        if len(t["ins"]) < 2 or mixer_like(t):
            continue
        addrs = [L.out[k][0] for k in t["ins"]]
        root = find(addrs[0])
        for a in addrs[1:]:
            parent[find(a)] = root
    ids = {}
    return {a: ids.setdefault(find(a), len(ids)) for a in L.first}


def change_index(L, t):
    """One-time-change heuristic: of two outputs, the one paying a never-seen-before address is change."""
    if len(t["outs"]) != 2 or mixer_like(t):
        return None
    spenders = {L.out[k][0] for k in t["ins"]}
    fresh = [j for j, (a, _) in enumerate(t["outs"]) if L.first[a] == t["seq"] and a not in spenders]
    return fresh[0] if len(fresh) == 1 else None


def peel_chains(L, min_len=4):
    found, seen = [], set()
    for tid in L.txs:
        if tid in seen:
            continue
        chain, pays, cur = [], 0, tid
        while cur:
            t = L.txs[cur]
            ci = change_index(L, t) if len(t["ins"]) == 1 else None
            if ci is None:
                break
            pay, total = t["outs"][1 - ci][1], L.out[t["ins"][0]][1]
            if pay > 0.35 * total:
                break
            chain.append(cur)
            pays += pay
            cur = L.out[(cur, ci)][2]
        if len(chain) >= min_len:
            seen.update(chain)
            found.append({"kind": "peel_chain", "txid": chain[0], "size": len(chain), "txids": chain,
                          "detail": f"{len(chain)} hops, {pays} units peeled off in small payments"})
    return found


def fan_patterns(L):
    out = []
    for tid, t in L.txs.items():
        addrs = {a for a, _ in t["outs"]}
        if t["ins"] and len(t["ins"]) <= 2 and len(addrs) >= 6:
            out.append({"kind": "fan_out", "txid": tid, "size": len(addrs), "txids": [tid],
                        "detail": f"{len(t['ins'])} input(s) split across {len(addrs)} addresses"})
        if len(t["ins"]) >= 6 and len(t["outs"]) <= 2:
            out.append({"kind": "fan_in", "txid": tid, "size": len(t["ins"]), "txids": [tid],
                        "detail": f"{len(t['ins'])} inputs consolidated into {len(t['outs'])} output(s)"})
        if mixer_like(t):
            value, n = Counter(v for _, v in t["outs"]).most_common(1)[0]
            out.append({"kind": "mixer_like", "txid": tid, "size": len(t["ins"]), "txids": [tid],
                        "detail": f"{len(t['ins'])} inputs, {n} equal outputs of {value} (CoinJoin-style)"})
    return out


def detect_patterns(L):
    return peel_chains(L) + fan_patterns(L)


# ---- taint tracing -----------------------------------------------------------

def fifo_share(in_val, in_taint, outs):
    """Outputs consume the concatenated inputs in order; tainted units sit at the front of each input."""
    spans, pos = [], 0
    for v, t in zip(in_val, in_taint):
        if t:
            spans.append((pos, pos + t))
        pos += v
    res, o = [], 0
    for v in outs:
        res.append(sum(max(0, min(o + v, e) - max(o, s)) for s, e in spans))
        o += v
    return res


def trace(L, seed, method, max_hops):
    """Propagate taint forward from output `seed`. Returns tainted units per output, hops per tx, edges."""
    if seed not in L.out:
        raise KeyError(seed)
    tv, hop, heap, edges = {seed: L.out[seed][1]}, {}, [], {}

    def push(key, h):
        sp = L.out[key][2]
        if not sp or h > max_hops:
            return
        if sp not in hop:
            heapq.heappush(heap, (L.txs[sp]["seq"], sp))
            hop[sp] = h
        elif h < hop[sp]:
            hop[sp] = h

    push(seed, 1)
    while heap:  # spenders always have a higher seq than what they spend, so this pops in ledger order
        _, tid = heapq.heappop(heap)
        t = L.txs[tid]
        in_val = [L.out[k][1] for k in t["ins"]]
        in_taint = [tv.get(k, 0) for k in t["ins"]]
        total, dirty = sum(in_val), sum(in_taint)
        if dirty == 0:
            continue
        outs = [v for _, v in t["outs"]]
        if method == "poison":
            share = outs
        elif method == "haircut":
            share = [v * dirty // total for v in outs]
        else:
            share = fifo_share(in_val, in_taint, outs)
        for j, s in enumerate(share):
            if s <= 0:
                continue
            tv[(tid, j)] = s
            for k, tnt in zip(t["ins"], in_taint):
                if tnt:
                    e = edges.setdefault((L.out[k][0], t["outs"][j][0]), [0, tid])
                    e[0] += s * tnt // dirty
            push((tid, j), hop[tid] + 1)
    return {"tv": tv, "hop": hop, "edges": edges}


def summarize(L, seed, res):
    tv, hop = res["tv"], res["hop"]
    by, hits = Counter(), []
    for key, v in tv.items():
        if key == seed:
            continue
        addr, _, spent = L.out[key]
        label, kind = L.label.get(addr, ("", None))
        k = kind if kind in ("exchange", "mixer") else "dormant" if spent is None else None
        if not k:
            continue
        by[k] += v
        hits.append({"address": addr, "txid": key[0], "hops": hop[key[0]], "taint": v, "kind": k, "label": label})
    hits.sort(key=lambda x: (-x["taint"], x["hops"]))
    return {"seed_value": L.out[seed][1], "exchange": by["exchange"], "mixer": by["mixer"], "dormant": by["dormant"],
            "txs_touched": len(hop), "max_hop": max(hop.values(), default=0), "hits": hits}


def graph(L, seed, res, limit=200):
    tv, hop = res["tv"], res["hop"]
    top = sorted(res["edges"].items(), key=lambda kv: -kv[1][0])[:limit]
    seed_addr = L.out[seed][0]
    best, spent = {seed_addr: 0}, {}
    for key in tv:
        a = L.out[key][0]
        h = 0 if key == seed else hop[key[0]]
        best[a] = min(best.get(a, h), h)
        spent[a] = spent.get(a, False) or L.out[key][2] is not None
    names = {seed_addr} | {a for (a, b), _ in top} | {b for (a, b), _ in top}
    nodes = []
    for a in sorted(names, key=lambda x: (best.get(x, 99), x)):
        label, kind = L.label.get(a, ("", "user"))
        nodes.append({"id": a, "hops": best.get(a, 99), "kind": kind, "label": label, "unspent": not spent.get(a, True)})
    return {"nodes": nodes, "edges": [{"from": a, "to": b, "value": v, "txid": t} for (a, b), (v, t) in top]}


def open_case(c, uid, name, txid, vout, method, hops):
    """Run a trace, store the case, hits and graph. Raises KeyError if the seed output doesn't exist."""
    L = Ledger(c)
    seed = (txid, vout)
    res = trace(L, seed, method, hops)
    s = summarize(L, seed, res)
    g = graph(L, seed, res)
    hits = s.pop("hits")
    cid = c.execute("INSERT INTO cases(user_id, name, seed_txid, seed_vout, method, max_hops, created_at, summary, graph) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (uid, name, txid, vout, method, hops, db.now(), json.dumps(s), json.dumps(g))).lastrowid
    c.executemany("INSERT INTO case_hits(case_id, address, txid, hops, taint, kind, label) VALUES(?,?,?,?,?,?,?)",
                  [(cid, h["address"], h["txid"], h["hops"], h["taint"], h["kind"], h["label"]) for h in hits])
    return cid


def compare(c, txid, vout, hops):
    L = Ledger(c)
    seed = (txid, vout)
    out = []
    for m in TAINT_METHODS:
        s = summarize(L, seed, trace(L, seed, m, hops))
        s.pop("hits")
        out.append({"method": m, **s})
    return out


# ---- risk ----------------------------------------------------------------------

def risk_scores(L, cl, patterns, thefts):
    pts = {}

    def add(a, p, why):
        if p > 0:
            pts.setdefault(a, []).append((p, why))

    inflow = Counter()
    for t in L.txs.values():
        for a, v in t["outs"]:
            inflow[a] += v
    for seed in thefts:
        taint = Counter()
        for key, v in trace(L, seed, "haircut", 8)["tv"].items():
            taint[L.out[key][0]] += v
        for a, v in taint.items():
            f = min(1.0, v / inflow[a])
            add(a, round(60 * f), f"{f:.0%} of value received traces to flagged theft within 8 hops")
    for a, (_, kind) in L.label.items():
        if kind == "thief":
            add(a, 100, "labelled as holding theft proceeds")
        elif kind == "mixer":
            add(a, 30, "labelled mixer service")
    for p in patterns:
        for tid in p["txids"]:
            t = L.txs[tid]
            if p["kind"] == "peel_chain":
                for k in t["ins"]:
                    add(L.out[k][0], 15, "spends inside a peel chain")
            elif p["kind"] == "fan_out":
                for a, _ in t["outs"]:
                    add(a, 10, "receives from a fan-out split")
            elif p["kind"] == "mixer_like":
                for a, _ in t["outs"]:
                    add(a, 25, "output of a CoinJoin-style transaction")
    scores = {a: (min(100, sum(p for p, _ in v)), [w for _, w in sorted(v, reverse=True)]) for a, v in pts.items()}
    members = Counter(cl.values())
    top = {}
    for a, (s, _) in scores.items():
        top[cl[a]] = max(top.get(cl[a], 0), s)
    for a, cid in cl.items():
        if members[cid] > 1 and top.get(cid, 0) * 0.8 > scores.get(a, (0, []))[0]:
            s, why = scores.get(a, (0, []))
            scores[a] = (round(top[cid] * 0.8), why + ["same wallet cluster (common-input) as a higher-risk address"])
    return {a: (s, why[:6]) for a, (s, why) in scores.items() if s >= 10}


def run_all(c):
    """Recompute clusters, patterns and risk scores from the stored ledger."""
    L = Ledger(c)
    cl, pats = clusters(L), detect_patterns(L)
    thefts = [(r["txid"], 0) for r in c.execute("SELECT txid FROM flags WHERE kind = 'theft'")]
    scores = risk_scores(L, cl, pats, thefts)
    for table in ("clusters", "patterns", "risk_scores"):
        c.execute(f"DELETE FROM {table}")
    c.executemany("INSERT INTO clusters(address, cluster) VALUES(?,?)", list(cl.items()))
    c.executemany("INSERT INTO patterns(kind, txid, size, detail) VALUES(?,?,?,?)",
                  [(p["kind"], p["txid"], p["size"], p["detail"]) for p in pats])
    now = db.now()
    c.executemany("INSERT INTO risk_scores(address, score, reasons, updated_at) VALUES(?,?,?,?)",
                  [(a, s, json.dumps(why), now) for a, (s, why) in scores.items()])
    return {"clusters": len(set(cl.values())), "patterns": len(pats), "risky": len(scores)}
