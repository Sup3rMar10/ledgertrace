# Build steps and interview notes

## Steps
1. Design the simulated ledger in `sim.py`: background payments with change, consolidation, one theft that is fanned out, peeled, mixed and cashed out, and a benign payroll batch as a deliberate false positive.
2. Store it in SQLite (`txs`, `inputs`, `outputs`, labels, flags) with a stable `seq` ordering.
3. Write `analysis.py`: in-memory `Ledger`, clustering, change detection, peel/fan/mixer patterns, three taint methods, graph extraction, additive risk scoring.
4. Write `db.py` and `app.py`: argon2 login, httpOnly session cookie, CSRF, localhost-only CORS and hosts, rate limits, strict regexes on every identifier, parameterised SQL.
5. Build `web/`: overview, case builder with method comparison, SVG flow graph, hits table, pattern list, address lookup, risk cards, Markdown export.
6. Write the docs. Nothing has been executed yet: first run is `pip install -r requirements.txt`, `python sim.py`, `uvicorn app:app --host 127.0.0.1 --port 8002`.

## Interview Q&A

**1. What is the common-input-ownership heuristic and when does it fail?**
Inputs spent together in one UTXO transaction were probably signed by one entity, so their addresses can be merged into a cluster. It fails on CoinJoin and similar collaborative transactions, on payjoin, and on exchanges or custodians that batch for many customers, so mixer-like transactions are excluded here.

**2. How do you identify change outputs?**
Heuristics: the output to a never-before-seen address when the other is reused, the non-round amount when the payment is round, the output with the same script type as the inputs, and the one never reused later. Each is probabilistic and wallets can defeat them; this project uses only the first, abstains when both outputs are fresh, and never claims certainty.

**3. Poison, haircut and FIFO: how do they differ and which is right?**
Poison taints every output of a transaction that touches tainted input (maximum recall, heavy over-attribution). Haircut taints proportionally, so taint dilutes as funds mix. FIFO assigns taint by input/output order. None is a physical fact; they are accounting conventions, and courts and regulators have used different ones, so show the comparison and state the method.

**4. What is a peel chain?**
A long sequence of transactions that each spend one input into a small payment and a large change output, repeatedly, to move funds while paying out little pieces (often to exchanges). It is spotted by a run of 1-input/2-output transactions with a small payment and a detectable change output, then followed through the change.

**5. How do mixers work and how are they detected?**
Custodial mixers pool deposits and pay out from a different set of addresses; CoinJoin lets many users build one transaction with equal-value outputs so inputs and outputs are hard to pair. Detection looks for equal-value output sets, many-input/many-output shapes, and known service addresses; the privacy set is limited by how many participants are honest strangers.

**6. What are the false-positive and due-process risks?**
Payroll looks like a fan-out, exchange withdrawals look like peel chains, and a victim's address can be tainted by the thief's later mistakes. Attribution errors harm real people, so outputs should be leads with stated confidence, reviewed by a human, with an audit trail of method and parameters (which the stored cases provide).

**7. How does tracing change on account-based chains?**
No UTXO graph: balances are fungible within an account, so taint needs conventions (FIFO or LIFO by transfer), and you must follow internal transactions, token events and contract calls, plus bridges and DEX swaps that change the asset. Clustering by common input does not exist, so you lean on funding patterns, deposit addresses and timing.

**8. What would you add for production?**
A real indexer over a node (RPC or ETL into a columnar store or graph database), reorg handling, curated and licensed entity labels, case management with audit logs, sanctions-list screening, and calibrated risk scores validated on labelled incidents. Add monitoring for stale data and per-heuristic precision tracking before anyone acts on a score.
