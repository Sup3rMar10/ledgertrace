"use strict";
// All server text goes in via textContent / createElement / setAttribute on SVG. Never innerHTML.
const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
let csrf = "", flag = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function svg(tag, attrs, text) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

const num = (n) => Number(n).toLocaleString();

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && path !== "/api/login") showAuth();
    const d = data.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "request failed (" + r.status + ")");
  }
  return data;
}

// ---- auth ------------------------------------------------------------------

function showAuth() {
  csrf = "";
  $("auth").hidden = false;
  $("app").hidden = true;
  $("logout").hidden = true;
  $("who").textContent = "";
}

async function showApp(me) {
  csrf = me.csrf;
  $("auth").hidden = true;
  $("app").hidden = false;
  $("logout").hidden = false;
  $("who").textContent = me.username;
  try {
    await Promise.all([loadStats(), loadCases(), loadPatterns(), loadRisk()]);
  } catch (e) {
    $("case-msg").textContent = e.message;
  }
}

async function authenticate(kind) {
  const msg = $("auth-msg");
  msg.textContent = "";
  try {
    const me = await api("/api/" + kind, { method: "POST", body: { username: $("u").value.trim(), password: $("p").value } });
    $("p").value = "";
    await showApp(me);
  } catch (e) {
    msg.textContent = e.message;
  }
}

$("login-form").addEventListener("submit", (e) => { e.preventDefault(); authenticate("login"); });
$("register").addEventListener("click", () => { if ($("login-form").reportValidity()) authenticate("register"); });
$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) { /* already logged out */ }
  showAuth();
});

// ---- overview, patterns, risk ---------------------------------------------------

async function loadStats() {
  const s = await api("/api/stats");
  const dl = $("stats");
  dl.replaceChildren();
  for (const k of ["txs", "addresses", "clusters", "patterns", "labelled"]) dl.append(el("dt", "", k), el("dd", "", num(s[k])));
  flag = s.flags[0] || null;
  $("flag-wrap").hidden = !flag;
  if (flag) $("use-flag").textContent = "use flagged seed: " + flag.note;
}

$("use-flag").addEventListener("click", () => {
  if (!flag) return;
  $("c-txid").value = flag.txid;
  $("c-vout").value = 0;
  $("c-name").value = "Flagged theft";
});

async function loadPatterns() {
  const rows = await api("/api/patterns");
  $("patterns").tBodies[0].replaceChildren(...rows.map((p) => {
    const tr = el("tr");
    for (const v of [p.kind.replace(/_/g, " "), p.size, p.detail]) tr.append(el("td", "", String(v)));
    const td = el("td");
    const b = el("button", "link mono", p.txid);
    b.type = "button";
    b.addEventListener("click", () => { $("c-txid").value = p.txid; $("c-vout").value = 0; $("c-txid").focus(); });
    td.append(b);
    tr.append(td);
    return tr;
  }));
}

function meter(score) {
  const m = document.createElement("meter");
  m.min = 0; m.max = 100; m.low = 33; m.high = 66; m.optimum = 0; m.value = score;
  m.setAttribute("aria-label", "risk score " + score + " of 100");
  return m;
}

function riskCard(r) {
  const d = el("article", "rcard");
  const why = el("details");
  const ul = el("ul");
  ul.append(...r.reasons.map((x) => el("li", "", x)));
  why.append(el("summary", "", "Why"), ul);
  d.append(el("h4", "mono", r.address), el("p", "muted", r.label || "unlabelled"), meter(r.score), el("strong", "num", " " + r.score), why);
  return d;
}

async function loadRisk() {
  $("risk").replaceChildren(...(await api("/api/risk?limit=12")).map(riskCard));
}

// ---- cases -------------------------------------------------------------------------

function caseBody() {
  return { name: $("c-name").value.trim(), seed_txid: $("c-txid").value.trim(), seed_vout: Number($("c-vout").value),
    method: $("c-method").value, max_hops: Number($("c-hops").value) };
}

$("case-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("case-msg");
  msg.textContent = "Tracing...";
  try {
    const r = await api("/api/cases", { method: "POST", body: caseBody() });
    msg.textContent = "";
    await Promise.all([openCase(r.id), loadCases()]);
  } catch (err) {
    msg.textContent = err.message;
  }
});

$("compare").addEventListener("click", async () => {
  const b = caseBody(), msg = $("case-msg");
  if (!/^[0-9a-f]{16}$/.test(b.seed_txid)) { msg.textContent = "Enter a 16-character transaction id first."; return; }
  msg.textContent = "";
  try {
    const rows = await api("/api/compare?txid=" + b.seed_txid + "&vout=" + b.seed_vout + "&hops=" + b.max_hops);
    const t = el("table");
    t.append(el("caption", "sr-only", "Exposure by taint method"));
    const head = el("tr");
    for (const h of ["Method", "Exchanges", "Mixers", "Dormant", "Txs touched"]) head.append(el("th", "", h));
    const thead = el("thead");
    thead.append(head);
    const tbody = el("tbody");
    for (const r of rows) {
      const tr = el("tr");
      for (const v of [r.method, num(r.exchange), num(r.mixer), num(r.dormant), r.txs_touched]) tr.append(el("td", "", String(v)));
      tbody.append(tr);
    }
    t.append(thead, tbody);
    $("cmp").replaceChildren(t, el("p", "muted", "Seed value " + num(rows[0].seed_value) + " units. Same ledger, three conventions, three answers."));
    $("cmp").hidden = false;
  } catch (err) {
    msg.textContent = err.message;
  }
});

async function loadCases() {
  const rows = await api("/api/cases");
  $("cases").replaceChildren(...rows.map((r) => {
    const li = el("li");
    const b = el("button", "link", r.name + " (" + r.method + ", " + r.max_hops + " hops)");
    b.type = "button";
    b.addEventListener("click", () => openCase(r.id).catch((err) => { $("case-msg").textContent = err.message; }));
    li.append(b);
    return li;
  }));
}

async function openCase(id) {
  const k = await api("/api/cases/" + id);
  const s = k.summary, pct = (v) => (s.seed_value ? ((100 * v) / s.seed_value).toFixed(1) + "%" : "n/a");
  $("result").hidden = false;
  $("export").href = "/api/cases/" + id + "/report.md";
  const dl = $("exposure");
  dl.replaceChildren();
  for (const [label, v] of [["Seed value", num(s.seed_value) + " units"], ["Reached exchanges", num(s.exchange) + " (" + pct(s.exchange) + ")"],
    ["Reached mixers", num(s.mixer) + " (" + pct(s.mixer) + ")"], ["Dormant, unspent", num(s.dormant) + " (" + pct(s.dormant) + ")"],
    ["Transactions touched", s.txs_touched], ["Deepest hop", s.max_hop], ["Method", k.method]]) {
    dl.append(el("dt", "", label), el("dd", "", String(v)));
  }
  drawGraph(k.graph, s.seed_value);
  $("hits").tBodies[0].replaceChildren(...k.hits.map((h) => {
    const tr = el("tr");
    for (const v of [h.kind, h.address, h.label || "-", h.hops, num(h.taint)]) tr.append(el("td", "", String(v)));
    return tr;
  }));
  $("result").scrollIntoView({ block: "start" });
}

function drawGraph(g, seedValue) {
  const cols = {};
  for (const n of g.nodes) (cols[n.hops] = cols[n.hops] || []).push(n);
  const hops = Object.keys(cols).map(Number).sort((a, b) => a - b);
  const pos = new Map();
  let maxRows = 1;
  hops.forEach((h, ci) => {
    cols[h].forEach((n, ri) => pos.set(n.id, { x: 16 + ci * 210, y: 20 + ri * 32 }));
    maxRows = Math.max(maxRows, cols[h].length);
  });
  const W = 16 + hops.length * 210 + 20, H = 40 + maxRows * 32;
  const root = svg("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img",
    "aria-label": "Taint flow graph with " + g.nodes.length + " addresses and " + g.edges.length + " flows" });
  for (const e of g.edges) {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) continue;
    const ratio = seedValue ? e.value / seedValue : 0;
    const w = ratio > 0.5 ? "w4" : ratio > 0.2 ? "w3" : ratio > 0.05 ? "w2" : "w1";
    const x1 = a.x + 150, y1 = a.y + 11, x2 = b.x, y2 = b.y + 11;
    const p = svg("path", { d: "M" + x1 + " " + y1 + " C" + (x1 + 35) + " " + y1 + " " + (x2 - 35) + " " + y2 + " " + x2 + " " + y2, class: "edge " + w });
    p.append(svg("title", {}, num(e.value) + " units via " + e.txid));
    root.append(p);
  }
  for (const n of g.nodes) {
    const p = pos.get(n.id);
    const grp = svg("g", { class: "gnode " + n.kind + (n.unspent ? " unspent" : "") });
    grp.append(svg("rect", { x: p.x, y: p.y, width: 150, height: 22, rx: 4 }),
      svg("text", { x: p.x + 75, y: p.y + 15, "text-anchor": "middle" }, n.id),
      svg("title", {}, n.id + (n.label ? " (" + n.label + ")" : "") + (n.unspent ? ", unspent" : "")));
    root.append(grp);
  }
  $("graph").replaceChildren(root);
}

// ---- address lookup -----------------------------------------------------------------

$("addr-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("addr-msg");
  msg.textContent = "";
  $("addr-card").replaceChildren();
  try {
    const a = await api("/api/address/" + encodeURIComponent($("a-in").value.trim()));
    const dl = el("dl", "kv");
    for (const [k, v] of [["address", a.address], ["label", a.label || "unlabelled"], ["wallet cluster", a.cluster === null ? "-" : "#" + a.cluster + " (" + a.cluster_size + " addresses)"],
      ["unspent balance", num(a.balance) + " units"], ["risk score", a.risk + "/100"]]) dl.append(el("dt", "", k), el("dd", "mono", String(v)));
    const ul = el("ul");
    ul.append(...a.reasons.map((x) => el("li", "", x)));
    const tx = el("ul", "plain");
    for (const t of a.recent) {
      const li = el("li");
      const b = el("button", "link mono", t.txid + " (height " + t.height + ")");
      b.type = "button";
      b.addEventListener("click", () => { $("c-txid").value = t.txid; $("c-vout").value = 0; });
      li.append(b);
      tx.append(li);
    }
    $("addr-card").replaceChildren(dl, meter(a.risk), a.reasons.length ? ul : el("p", "muted", "No risk reasons recorded."),
      el("h4", "", "Recent transactions (click to use as a seed)"), tx);
  } catch (err) {
    msg.textContent = err.message;
  }
});

api("/api/me").then(showApp, showAuth);
