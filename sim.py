"""Generate a deterministic simulated UTXO ledger (made-up labels only), load it into SQLite and analyse it.

Storyline: background payments, one simulated theft that is split, peeled, mixed and cashed out, plus a
benign payroll batch that looks suspicious on purpose (a false positive for the docs to talk about).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher

import analysis
import db

FEE = 500
N_USERS = 40
MINUTES_PER_HEIGHT = 80


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.txs, self.utxo, self.labels, self.n, self.height = [], {}, {}, 0, 0

    def addr(self, kind):
        self.n += 1
        return f"sim1{kind}{self.n:05d}"

    def emit(self, ins, outs):
        self.height += 1
        txid = hashlib.sha256(f"{len(self.txs)}|{ins}|{outs}".encode()).hexdigest()[:16]
        for k in ins:
            del self.utxo[k]
        for j, (a, v) in enumerate(outs):
            self.utxo[(txid, j)] = (a, v)
        self.txs.append({"txid": txid, "seq": len(self.txs), "height": self.height, "ins": list(ins), "outs": list(outs)})
        return txid

    def pay(self, key, to, fee=FEE):
        """Spend one output paying `to`; the remainder goes to a fresh change address at a random position."""
        value = self.utxo[key][1]
        rest = value - sum(v for _, v in to) - fee
        assert rest >= 0, "overspend"
        outs, ci = list(to), None
        if rest > 0:
            ci = self.rng.randrange(len(outs) + 1)
            outs.insert(ci, (self.addr("chg"), rest))
        txid = self.emit([key], outs)
        return txid, ((txid, ci) if ci is not None else None), [(txid, j) for j in range(len(outs)) if j != ci]


def build(seed=11):
    g = Gen(seed)
    rng = g.rng
    users = [g.addr("usr") for _ in range(N_USERS)]
    bg = {i: [] for i in range(N_USERS)}          # user index -> spendable outputs
    exch = [g.addr("exch") for _ in range(3)]
    for i, a in enumerate(exch):
        g.labels[a] = (f"ExchangeSim {'ABC'[i]} deposit", "exchange")
    mixer, hot = g.addr("mix"), g.addr("hot")
    g.labels[mixer] = ("MixerSim pool", "mixer")
    g.labels[hot] = ("ExchangeSim A hot wallet", "exchange")

    for i, a in enumerate(users):
        bg[i].append((g.emit([], [(a, rng.randint(3, 9) * 1_000_000)]), 0))
    for a in exch + [mixer]:                        # pre-fund so they are never "fresh" addresses later
        g.emit([], [(a, 1_000)])
    hot_tid = g.emit([], [(hot, 30_000_000)])

    def background(steps):
        for _ in range(steps):
            i = rng.choice([u for u in bg if bg[u]])
            if rng.random() < 0.12 and len(bg[i]) >= 2:    # consolidation: same owner, several inputs
                ks = [bg[i].pop() for _ in range(min(3, len(bg[i])))]
                tid = g.emit(ks, [(g.addr("usr"), sum(g.utxo[k][1] for k in ks) - FEE)])
                bg[i].append((tid, 0))
                continue
            key = bg[i].pop(rng.randrange(len(bg[i])))
            amt = (g.utxo[key][1] * rng.randint(5, 40) // 100) // 10_000 * 10_000
            if amt < 10_000:
                bg[i].append(key)
                continue
            j = None
            if rng.random() < 0.12:
                dest = rng.choice(exch)
            else:
                j = rng.choice([u for u in range(N_USERS) if u != i])
                dest = users[j] if rng.random() < 0.7 else g.addr("usr")
            _, ck, pk = g.pay(key, [(dest, amt)])
            if ck:
                bg[i].append(ck)
            if j is not None:
                bg[j].append(pk[0])

    background(120)
    victim, thief = g.addr("vic"), g.addr("thf")
    g.labels[victim] = ("Victim wallet (simulated)", "victim")
    g.labels[thief] = ("Theft proceeds holder (simulated)", "thief")
    vt = g.emit([], [(victim, 5_000_000)])
    theft = g.emit([(vt, 0)], [(thief, 5_000_000 - 1_000)])
    background(30)

    each = (4_999_000 - 1_000) // 8
    fan = g.emit([(theft, 0)], [(g.addr("usr"), each) for _ in range(8)])

    def peel(key, hops):
        for _ in range(hops):
            amt = max(10_000, g.utxo[key][1] // rng.randint(6, 12) // 1_000 * 1_000)
            to_user = rng.random() < 0.5
            j = rng.randrange(N_USERS)
            _, ck, pk = g.pay(key, [(users[j] if to_user else rng.choice(exch), amt)])
            if to_user:
                bg[j].append(pk[0])
            key = ck
        return key

    ends = [peel((fan, j), 6) for j in range(4)]
    merged = g.utxo[ends[0]][1] + g.utxo[ends[1]][1] - FEE   # chains 0 and 1 are re-merged by one wallet
    g.emit([ends[0], ends[1]], [(exch[0], merged)])
    for k in ends[2:]:                                        # chains 2 and 3 cash out separately
        g.emit([k], [(rng.choice(exch), g.utxo[k][1] - FEE)])

    deposits = [(g.emit([(fan, j)], [(mixer, g.utxo[(fan, j)][1] - FEE)]), 0) for j in (4, 5)]
    rich = [(i, k) for i in bg for k in bg[i] if g.utxo[k][1] >= 800_000]
    for i, k in rng.sample(rich, 3):                          # strangers put money in the same pool
        bg[i].remove(k)
        _, ck, pk = g.pay(k, [(mixer, 600_000)])
        if ck:
            bg[i].append(ck)
        deposits.append(pk[0])
    pooled = sum(g.utxo[k][1] for k in deposits)
    each_out = (pooled - FEE) // len(deposits)
    mix = g.emit(deposits, [(g.addr("mxo"), each_out) for _ in deposits])
    g.emit([(mix, 0)], [(exch[1], each_out - FEE)])
    g.emit([(mix, 1)], [(exch[2], each_out - FEE)])           # outputs 2-4 stay unspent

    staff = rng.sample(range(N_USERS), 12)                    # benign payroll batch, flagged as a fan-out
    ptid = g.emit([(hot_tid, 0)], [(users[i], 500_000) for i in staff] + [(g.addr("hot"), 30_000_000 - 6_000_000 - FEE)])
    g.labels[g.utxo[(ptid, 12)][0]] = ("ExchangeSim A hot wallet", "exchange")
    for n, i in enumerate(staff):
        bg[i].append((ptid, n))
    background(80)
    return g, theft


def load(c, g, theft):
    base = datetime.now(timezone.utc) - timedelta(minutes=MINUTES_PER_HEIGHT * g.height)
    for t in g.txs:
        ts = (base + timedelta(minutes=MINUTES_PER_HEIGHT * t["height"])).isoformat(timespec="seconds")
        c.execute("INSERT INTO txs(txid, seq, height, ts) VALUES(?,?,?,?)", (t["txid"], t["seq"], t["height"], ts))
        c.executemany("INSERT INTO inputs(txid, n, prev_txid, prev_n) VALUES(?,?,?,?)",
                      [(t["txid"], n, p, k) for n, (p, k) in enumerate(t["ins"])])
        c.executemany("INSERT INTO outputs(txid, n, address, value) VALUES(?,?,?,?)",
                      [(t["txid"], n, a, v) for n, (a, v) in enumerate(t["outs"])])
    c.execute("UPDATE outputs SET spent_by = (SELECT i.txid FROM inputs i WHERE i.prev_txid = outputs.txid AND i.prev_n = outputs.n)")
    c.executemany("INSERT INTO addresses(address, label, kind) VALUES(?,?,?)", [(a, l, k) for a, (l, k) in g.labels.items()])
    c.execute("INSERT INTO flags(txid, kind, note) VALUES(?,?,?)", (theft, "theft", "Simulated theft from the victim wallet"))


def main():
    db.init()
    g, theft = build()
    with db.conn() as c:
        for table in ("case_hits", "cases", "risk_scores", "patterns", "clusters", "flags", "addresses",
                      "outputs", "inputs", "txs"):
            c.execute(f"DELETE FROM {table}")
        row = c.execute("SELECT id FROM users WHERE username = ?", ("demo",)).fetchone()
        uid = row["id"] if row else c.execute(
            "INSERT INTO users(username, pw_hash, created_at) VALUES(?,?,?)",
            ("demo", PasswordHasher().hash("demo-pass-1234"), db.now())).lastrowid
        load(c, g, theft)
        stats = analysis.run_all(c)
        analysis.open_case(c, uid, "Simulated theft, haircut", theft, 0, "haircut", 8)
        analysis.open_case(c, uid, "Simulated theft, poison", theft, 0, "poison", 8)
    print(f"Seeded {len(g.txs)} transactions; {stats}. Log in as demo / demo-pass-1234 (local only).")


if __name__ == "__main__":
    main()
