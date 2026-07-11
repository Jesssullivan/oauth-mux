# Supervised Harness Restart Contract — OBSOLETE

> **SUPERSEDED 2026-07-11; DO NOT EXECUTE.** This file is historical input,
> not active design authority. Binding invariants moved to
> `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` and
> `docs/security/omux-v0.2-threat-model-2026-07-11.md`. It is pending deletion
> under the v0.2 deletion ledger; Git is the archive. Preserve cited immutable
> evidence and shipped release history.
Date: 2026-05-02 (original); demoted 2026-05-03.
Status: **OBSOLETE**. Restart is not a product behavior. Do not use this
file as a contract, milestone, or fallback path.

This document originally tracked a "supervised restart" claim level for
the Codex stay-afloat path. That framing was wrong. Restart is a session-
ending failure, not a stay-afloat outcome. The product is in-place
account swap with no restart; see the anchor:

> **`docs/spec/broker-mcp-contract-2026-05-03.md`** — the product anchor.

The success metric, copied here verbatim so this file does not relapse:

> The user runs `oauth-mux <harness>` (e.g. `oauth-mux codex`). The
> harness behaves like the real one. The active subscription account
> exhausts its quota. **Another credited account is seamlessly
> substituted in place.** The harness process is not restarted. The
> user is not prompted.

## What survived from the original document

Two pieces of work remain valid; both are diagnostic, neither is the
product:

1. `stay-afloat observe` (formerly `stay-afloat supervise`) classifying
   the Codex usage-limit screen from captured child output. This
   produces typed evidence that the broker can consume via
   `quota/observe` once the broker MCP surface lands, but it is not a
   recovery path; it observes a failure that already occurred.
2. The hardcoded `relaunch_admitted = false` invariant in
   `runStayAfloatObserve` (`src/main.zig`). This stays during
   migration so that nobody can accidentally re-enable restart by
   flipping one constant. Phase 4 of the broker contract removes the
   surrounding flags entirely.

## What is being deleted

- The `--max-restarts` and `--restart-on-exit-code` and
  `--restart-on-codex-usage-limit` CLI flags (Phase 4).
- The `supervised_restart` field from claim JSON (Phase 4).
- Any spec or doc sentence framing supervise-restart as a "product near-
  term shape" or "fallback if seamless mux is hard."
- Linear ticket TIN-911's original goal text ("Design supervised harness
  restart mediation"); rewritten to point at this demotion.

## Why this matters

The maintainer has called out that the team kept regressing into restart-
as-success framing whenever in-place swap looked hard. That regression
ends here. If you find yourself writing "we'll fall back to wrapper
restart if the broker can't do X," you have made the same mistake.
Delete the sentence and re-read the broker contract.

## Pointer

All forward work happens against `docs/spec/broker-mcp-contract-2026-05-03.md`
(the broker) and `docs/spec/codex-adapter-contract-2026-05-03.md` (the
Codex adapter). This file remains only so that older PR descriptions and
git log entries linking to it land somewhere coherent.
