Update after the 2026-05-08 installed-runtime dogfood:

TIN-951 / #177 should no longer cite dogfood-9 as the latest state. Dogfood-9
remains historical failed-quota evidence, but the repaired installed-runtime
path has now produced successful managed quota handoff evidence.

Preserved proof:

- `docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson`
- `docs/evidence/codex-managed-quota-handoff-20260508/status-summary.json`
- `docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`

Observed shape:

- installed command path: `oauth-mux codex resume <id>`
- runtime identity recorded an installed/local `oauth-mux` binary with no
  mismatch
- selected account: `codex:default`
- quota event: `429 usage_limit_reached`, classified `quota_exhausted`,
  `delivered_to_codex:false`
- swap/retry: `codex:default` -> `codex:max-2`, with
  `dropped:"x-codex-turn-state"`
- fallback response: `codex:max-2` returned `status:200`
- summarizer verdict: `successful_live_quota_handoff`

Supersession, 2026-05-09: the deliberately engineered managed-session
exhaustion run has now been captured in
`docs/evidence/codex-engineered-quota-handoff-20260509/`. Same-thread
semantics, mid-turn recovery, unmanaged bare `codex` hot-swap, and broader
auth/quota/tier permutations remain separate proof lanes.

Recommended tracker state: close the installed managed quota-handoff acceptance
if #177 is scoped to managed Codex quota handoff evidence. Open or keep
separate issues for same-thread semantics, unmanaged daemon handoff, and the
remaining permutation matrix.
