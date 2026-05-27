# Dogfood Process Fanout Runbook

Status: observational support diagnostic. This is not a stay-afloat claim.

Use this runbook when Codex/Claude dogfood feels persistently slow, duplicated,
or memory-heavy and you need to distinguish normal accumulated sessions from
orphan helper fanout or a suspected RSS leak.

The snapshot path is no-spend and non-mutating:

- it does not call provider APIs;
- it does not mutate oauth-mux config, route health, or credential stores;
- it does not kill processes;
- it does not sleep in the foreground;
- it does not prove a heap leak from a single sample.

## Snapshot

Write a redacted Markdown and JSON snapshot:

```bash
just dogfood-process-snapshot
```

For Codex Max dogfood labeling:

```bash
just codex-max-process-snapshot
```

For machine-readable output on stdout:

```bash
just dogfood-process-snapshot-json
```

The report groups visible Codex, Claude, and oauth-mux process trees and records:

- parent PID / PPID;
- elapsed time;
- instantaneous CPU percent from `ps`;
- RSS in KiB and MiB;
- current `RLIMIT_NOFILE` soft/hard limits;
- visible per-process file descriptor counts for agent/helper processes;
- helper child count;
- listening TCP ports visible through `lsof`;
- duplicate helper command groups;
- helper/listener processes that are not inside a visible agent tree.
- an `evidence_gate` verdict for whether the current process/fd state is clean
  enough for unannotated live reliability or quota-cassette claims.

Commands, temp paths, home paths, and common bearer/token spellings are redacted.
The script intentionally does not read process environments.

## Bounded Comparison

To compare two snapshots without running a foreground wait:

```bash
python3 scripts/dogfood-process-snapshot.py --out dist/dogfood/process --tag baseline
python3 scripts/dogfood-process-snapshot.py --out dist/dogfood/process --tag current
python3 scripts/dogfood-process-snapshot.py \
  --compare dist/dogfood/process/process-snapshot-BASELINE.json \
            dist/dogfood/process/process-snapshot-CURRENT.json
```

For a delayed follow-up, schedule the wait in a detached background process:

```bash
python3 scripts/dogfood-process-snapshot.py \
  --out dist/dogfood/process \
  --tag baseline \
  --schedule-followup-seconds 300
```

That command returns after scheduling the follow-up. The background follow-up
writes a second snapshot and a comparison artifact in the same output directory.

Default RSS growth suspicion requires both:

- at least 64 MiB same-PID RSS growth;
- at least 25 percent same-PID RSS growth.

Treat the result as `suspected_rss_growth`, not a proven heap leak, until the
same process keeps growing across repeated samples without an active workload
explanation.

## Classification

Use these labels when filing follow-up evidence:

- `accumulated_sessions`: old Codex/Claude parent processes are still active.
- `orphan_helper_fanout`: helper/listener processes are visible outside a known
  agent tree.
- `duplicate_helper_spawn`: repeated helper command signatures are visible.
- `suspected_rss_growth`: same PID crosses the configured growth threshold.
- `stable_or_session_churn`: processes are stable, appeared, or disappeared
  without same-PID growth.

## TIN-1591 Evidence Gate

Before using dogfood evidence for live reliability claims, collect a no-spend
snapshot and inspect:

```bash
python3 scripts/dogfood-process-snapshot.py --json \
  | jq '{summary, process_summary, resource_limits, fd_summary, evidence_gate, safe_cleanup}'
```

Treat the evidence as contaminated when the snapshot shows active work you
cannot classify, such as:

- any visible oauth-mux/Codex process, including managed Codex children;
- duplicated MCP/helper groups without a known active parent session;
- orphan listener candidates on the first snapshot;
- active capture, CI watch, or local release-proof processes;
- file descriptor usage close enough to the soft limit that a live run could
  fail locally before proving provider behavior.

The machine-readable gate is intentionally conservative:

- `evidence_gate.process_fd_clean_baseline` must be `true` before treating
  dogfood state as a clean baseline.
- `evidence_gate.unannotated_live_claims_admitted` must be `true` before making
  broad live reliability claims without an explicit process/fd caveat.
- `evidence_gate.quota_cassette_claims_admitted` must be `true` before using a
  quota/rate-limit cassette as clean process/fd evidence.
- `evidence_gate.local_release_validation_admitted` can remain `true` even when
  live claims are blocked; release/install checks can proceed with the caveat
  that process fanout is not clean reliability proof.
- `evidence_gate.fd_soft_limit_pct_threshold` is currently `70.0`. The
  percentage uses the collector process's soft `nofile` limit as a local
  pressure proxy; it is not a per-target process rlimit read.

Containment is enough to proceed with local release/install validation. Real
cassette or live quota claims need either a clean baseline or an explicit note
that the process/fd state was known, bounded, and unrelated to the observed
provider behavior.

## Cleanup Rules

No automation should kill processes from this report.

Leave sessions alone when:

- the shell or agent session is active;
- a check, deploy, smoke, or live dogfood command is running;
- the owner or workspace is unclear.

Close manually only after confirming the session is idle or obsolete. If a
helper appears orphaned, collect a second snapshot first so the follow-up can
show whether it persists outside a parent session.

If cleanup is needed, ask the operator which PID or parent session to close.
Then use the normal shell/session exit path first. Use `kill` only with explicit
operator approval and a PID list copied from the latest snapshot.

## What This Does Not Prove

This diagnostic does not prove:

- unmanaged Codex hot-swap;
- same-thread provider continuity;
- daemon-owned stay-afloat;
- provider health or route selection correctness;
- a heap leak from one process sample.

Use `oauth-mux codex status-latest --json`, `codex preflight`, route diagnostics,
and managed status artifacts for route/session truth. Use this runbook only for
agent process topology and resource evidence.
