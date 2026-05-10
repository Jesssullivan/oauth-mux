# Managed Codex Quota Handoff Proof — 2026-05-08

This directory preserves the reviewed evidence shape from the installed
`oauth-mux codex resume 019e082b-fa84-7593-aef4-631753902d78` dogfood run.

The live source artifact was an installed-runtime status file under the
operator's oauth-mux state directory:

```text
<oauth-mux-state>/codex/status/managed-1778273610565.ndjson
```

The source artifact continued to grow while the managed session stayed alive,
so this directory stores:

- `status-excerpt.ndjson`: the minimal redacted event sequence that proves the
  handoff.
- `status-summary.json`: the status oracle output from the live artifact after
  the successful handoff and later continued traffic.

Interpretation:

- Proven: installed managed resume/load quota handoff from `codex:default` to
  `codex:max-2`.
- Superseded by stronger 2026-05-09 evidence for the engineered managed-session
  shape; see `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Still separate: same-thread continuity semantics, mid-turn streaming
  recovery, unmanaged bare-`codex` daemon handoff, and non-Codex providers.

The summarizer verdict for the full live artifact was:

```text
successful_live_quota_handoff
```

Validation command:

```bash
python3 scripts/summarize-codex-status.py \
  <status.ndjson> \
  --require-brokered --require-fallback-sequence
```
