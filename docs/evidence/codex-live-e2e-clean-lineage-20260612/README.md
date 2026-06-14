# Live Codex mux e2e — clean-lineage pass (2026-06-12)

First committed live proof of the home-is-store default on a **clean, untagged
main lineage** (no `-dirty` build), and the recorded retest that closed the
GH #366 regression sentinel.

## Run

- Harness: `scripts/live-codex-mux-e2e.sh` (TIN-1852 lane), real provider call
  confirmed via `OMUX_LIVE_CODEX_E2E_CONFIRM=real-provider-calls`.
- Binary: repo-local build, `build_id v0.1.12-57-g6801bbb`,
  sha256 `562074dca69d18c35d3400a4168297ee5fd6b926c014c1fb47fca6c1d352f792`
  (main at 6801bbb — includes #367/#370 home-is-store, #379 flock fix,
  #380 chooser fix, #381 Claude endpoint constants).
- Result: `live-codex-mux-e2e: PASS`, exit_code 0.

## Invariants verified (trust-gate conditions)

- Managed transaction completed against the live provider; expected token
  returned on stdout; observed child model `gpt-5.5`.
- `session_authority: "isolated"` (route-local persistent home; no canonical
  bridge) — see `status-excerpt.ndjson`.
- **Canonical `~/.codex/state_5.sqlite` byte-stable**: identical before/after
  counts (`total_threads` 843, `managed_bridge` 3, `old_oauth_mux_codex` 2),
  `integrity_check: ok` — see `sqlite-counts.json`.
- **Zero scrub leaks**: no token/config material under
  `~/.codex/.oauth-mux/managed-codex-homes` (root absent), no durable session
  bridges — see `scrub-check.json`.
- **Child exited cleanly** (`session_ended`, exit 0): the GH #366
  answer-then-hang did **not** reproduce on this lineage.

## Reproduce

```bash
zig build
OMUX_LIVE_CODEX_E2E_CONFIRM=real-provider-calls \
  OMUX_LIVE_E2E_BIN=$PWD/zig-out/bin/oauth-mux \
  ./scripts/live-codex-mux-e2e.sh
```

Full raw artifacts (gitignored) for this run:
`dist/live-qa/tin1852-20260612T171039Z` on the recording machine.
