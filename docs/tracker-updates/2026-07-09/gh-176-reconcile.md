# GitHub #176 — cassette tracker reconciliation

Posted 2026-07-09. Reconciled the long-standing Linear-Done vs GitHub-open
mismatch on wire cassette coverage: Linear TIN-950 Done covers exactly what
shipped — the scrubbed current-release auth-failure fixtures and replay
smoke from `#299`. GitHub `#176` stays open for what did not ship: quota/
rate-limit cassettes and all-fallbacks-exhausted cassettes. Remaining scope
is re-pointed by provider: Anthropic-side to TIN-2722 (E2 quota-signal
fixture), Codex-side to `#212`/TIN-1824.

References: Linear TIN-950 (Done), TIN-2722, TIN-1824; GitHub `#176`,
`#299`, `#212`.
