# Engineered Codex Quota Handoff Proof - 2026-05-09

This directory preserves the reviewed evidence shape from the installed
`oauth-mux codex resume 019e0eb2-c081-7400-9561-c52c3320bbc7` dogfood window
after the low-weekly route was intentionally driven to exhaustion.

The live source artifact was an installed-runtime status file under the
operator's oauth-mux state directory:

```text
<oauth-mux-state>/codex/status/managed-1778362718969.ndjson
```

The full artifact remains in operator-local state. This directory stores:

- `status-excerpt.ndjson`: the minimal redacted event sequence showing
  successful `codex:max-2` traffic, provider `429 usage_limit_reached`, a
  same-turn retry to `codex:max-3`, and successful fallback `200` traffic.
- `status-summary.json`: the installed status oracle output after fixing the
  status summarizer lifetime bug.

Interpretation:

- Proven: live managed quota handoff from `codex:max-2` to `codex:max-3` in
  one brokered Codex status artifact. The provider-originated 429 was not
  delivered to Codex; oauth-mux dropped `x-codex-turn-state`, retried on
  `codex:max-3`, and received `status:200`.
- Proven: the same artifact contains successful `codex:max-2` responses before
  the quota event, so this is stronger than the earlier load/resume handoff
  where the selected account was already exhausted at first observed turn.
- This is the current headline proof for managed Codex live quota handoff.
- Caveat: `session_started.selected_account` in this artifact is
  `codex:max-3`; use the proxy turn sequence as the account-exhaustion proof.
  A sibling artifact from the same window,
  `<oauth-mux-state>/codex/status/managed-1778362134778.ndjson`, starts with
  `codex:max-2` selected and also summarizes as `successful_live_quota_handoff`,
  but its first observed `codex:max-2` responses turn is already the quota 429.
- Still not proven: same-thread provider semantic continuity across account
  boundaries.

The summarizer verdict for the full live artifact was:

```text
successful_live_quota_handoff
```

Additional active-session observation from the same dogfood window:

- `oauth-mux codex status-latest --json` later selected another still-growing
  installed-runtime artifact,
  `<oauth-mux-state>/codex/status/managed-1778276571386.ndjson`.
- That artifact also summarizes as `successful_live_quota_handoff`, with
  traffic on both `codex:max-2` and `codex:max-3`, two provider
  `usage_limit_reached` quota events, and fallback `200` responses.
- Because the artifact was still active at review time, it is supporting
  observation rather than the minimal preserved proof excerpt in this
  directory.

Validation command:

```bash
oauth-mux codex status-latest \
  --status-file <oauth-mux-state>/codex/status/managed-1778362718969.ndjson \
  --json
```
