# LedgerTrace
> 🔍 Follow the money, politely, through a ledger that doesn't exist.
## What it does
Loads a simulated UTXO ledger, clusters wallets, spots peel chains, fan-outs and mixers, and traces tainted funds three different ways (poison, haircut, FIFO).
## Run it
`pip install -r requirements.txt`, `python sim.py`, `uvicorn app:app --host 127.0.0.1 --port 8002`, then open localhost:8002 (demo / demo-pass-1234).
## Favourite finding 🤷
The payroll batch: a perfectly innocent exchange payout that the fan-out detector flags with total confidence. Heuristics are great at being confidently wrong.
## Honest disclaimer ⚠️
Untested prototype. Leads, not evidence. Every heuristic has failure modes (CoinJoin, shared wallets, address reuse) and the data is simulated. Never accuse anyone based on this. Download and use at your own discretion.
## Things that went wrong while building this
- It was written without ever being run, so expect a typo or two on first launch.
- Three taint methods give three answers on the same ledger, which is the point, but also an uncomfortable demo.

Built with patience and a suspicious mind. Follow the change address.
