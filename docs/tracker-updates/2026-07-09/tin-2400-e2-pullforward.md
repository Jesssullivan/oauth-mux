# TIN-2400 — E2 quota-signal fixture pulled forward as TIN-2722

Posted 2026-07-09. TIN-2400 (model-class quota granularity, parent) gets a
new child ticket, TIN-2722, marked Urgent: the E2 Anthropic quota-signal
fixture. P0 pure-core work (TIN-2407) already landed in `#439` but is
unconsumed by design — no model-class quota claim is made until TIN-2722
lands a committed `test/evidence/quota-observation/` proving Anthropic's
real rate-limit signals. Design of record stays
`docs/spec/model-quota-granularity-2026-07-03.md`.

References: Linear TIN-2400 (parent), TIN-2407 (P0, landed), TIN-2722 (new,
Urgent); GitHub `#436`, `#439`.
