# Threat model (local MVP)
Attackers: a hostile web page in the same browser, anything else on the LAN, and the analyst's own over-confidence. Not in scope: deployment.
## Wrong conclusions (the real risk)
- Heuristics misattribute: CoinJoin and shared wallets break common-input clustering; address reuse breaks change detection.
- Taint methods are conventions. Poison over-attributes, haircut dilutes toward zero, FIFO depends on an arbitrary ordering. Reports say so.
- Labels are simulated. Real labelled data is wrong sometimes; treat every output as a lead that needs corroboration.
## XSS and injected text
- Addresses, labels and notes would be attacker-influenced in a real ledger. The UI uses textContent and SVG setAttribute only.
- CSP is `script-src 'self'; style-src 'self'`. Markdown export escapes `< > | `` ` `` and newlines.
## Resource abuse
- Hops capped at 12, case names at 80 chars, bodies at 16 KB; cases are rate limited to 20/min per user.
- Each trace loads the whole ledger into memory; fine for a few thousand simulated txs, not for real chain data.
- Graph output is trimmed to the 200 heaviest edges; `/api/compare` has no extra throttle beyond the global caps.
## Privacy and misuse
- Wallet clustering and tracing are dual-use. This build only ever sees invented `sim1...` addresses; do not point it at real people.
- Per-user case isolation is enforced in SQL (`user_id = ?`); the ledger itself is shared and read-only to users.
## Untrusted input handling
- Parameterised SQL only; addresses and txids are validated by strict regexes before any query.
- argon2 hashes, hashed session tokens, httpOnly SameSite=Strict cookie, CSRF header plus Origin check, Host and CORS locked to localhost.
- No network calls, keys, wallets or RPC anywhere.
