# Concurrent distinct-account live proof (2026-06-12)

The last trust-gate condition (docs/spec/codex-mux-trustable-architecture-2026-06-03.md):
**two distinct managed account sessions run concurrently without refresh-token
reuse or canonical sqlite authority poisoning** — proven live.

## Run

- Binary: repo-local build `v0.1.13-3-g0ca2a03` (post-#386 main).
- Two managed sessions launched simultaneously, pinned to two distinct-identity
  codex accounts (`codex:max-3`, `codex:max-4`), each `exec` returning a unique
  token against the live provider.
- Both exited 0 with their expected tokens on stdout.

## Invariants verified

- `session_authority:"isolated"` in both sessions' `session_started` frames —
  see `status-excerpt.ndjson`.
- **Zero lock conflicts**: no `SessionAuthorityLocked` /
  `duplicate_upstream_identity` / `RepairInProgress` in either session's output
  (distinct accounts + distinct upstream identities run concurrently by design;
  the locks exist to refuse *same*-identity concurrency).
- **Canonical `~/.codex/state_5.sqlite` byte-stable across the concurrent run**:
  identical before/after (`total` 843, `managed_bridge` 3, `old_poison` 2),
  `integrity: ok` — see `counts-before.json` / `counts-after.json`.

## Reproduce

`bash /tmp/concurrent-leg.sh`-equivalent: two `oauth-mux codex --account <a|b>
-- exec --skip-git-repo-check "<unique token>"` in parallel with separate
`--json-status-file`s; compare canonical sqlite counts before/after.

Raw artifacts (gitignored) on the recording machine:
`dist/live-qa/tin1852-concurrent-20260612T185324Z`.
