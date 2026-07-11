# oauth-mux v0.2 Deletion Ledger

Status: active execution ledger; deletion is gated

Date: 2026-07-11

Program: GitHub #463; Linear TIN-2057

## Safety Order

1. Freeze v0.1.15 truth: tag characterization tests and immutable evidence;
   identify stable install, keepalive, enrollment, status, and Codex behavior.
2. Add the v0.2 manifest, adapter JSON-RPC contract, `omux` entrypoint, Claude
   sidecar, and replacement tests behind prerelease-only paths.
3. Prove replacement behavior remotely and collect the golden evidence packet.
4. Remove public references and packaging exposure before deleting code.
5. Delete unreachable implementation and tests; keep historical evidence and
   release records. Run remote check/release proof after every removal slice.
6. Promote v0.2 only after the full golden gate. v0.1.15 remains stable until
   then, and compatibility shims remain for the documented migration window.

"Delete" below never means rewrite release history, remove committed evidence,
or break the current stable channel before replacement proof exists.

## Ledger

| Surface | Exact current surfaces | Required action and gate |
| --- | --- | --- |
| Experimental socket daemon | `src/daemon.zig`; daemon socket paths in `src/paths.zig`; `src/cli.zig` `daemon start/stop/status/events/handoffs/tick/run/loop`; corresponding dispatch/tests in `src/main.zig`; `docs/daemon-boundary.md`; daemon socket/status sections in `docs/lifecycle.md`, `docs/onboarding.md`, and `docs/adoption.md` | Remove socket daemon and its public CLI after the resident refresh/observation service has its own bounded contract and migration tests. Do not replace it with a request proxy service; session proxying belongs only to the sidecar. Preserve any v0.1.15 diagnostic schemas needed to read old snapshots. |
| Supervisor and restart aliases | `src/cli.zig` legacy `stay-afloat supervise`, `daemon supervise`, `daemon loop`, restart flags and completions; `docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`; restart/supervisor sections in `docs/adoption.md` and `docs/stay-afloat-wrappers.md` | First mark unavailable in v0.2 help/JSON with a migration message, then delete parser, dispatch, completion, smoke, and docs paths after sidecar handoff proof. Never translate them into a hidden relaunch. |
| Prepared-fallback public paths | `prepared_fallback` claim/output fields and stay-afloat planning paths in `src/main.zig`; public explanations in `docs/lifecycle.md`, `docs/adoption.md`, `docs/productionization-ledger.md`, and adapter/spec examples | Retain old schema decoding where compatibility requires it, but stop emitting or presenting prepared fallback as a v0.2 action. Delete public commands and examples only after the broker sidecar exposes replacement route/lease state. Preserve old evidence verbatim. |
| Proof-only public CLI verbs | `stay-afloat next/launch/observe/refresh/handoffs/handoff`; `codex broker-plan`, `broker-session-plan`, `broker-session-smoke`, `broker-run`, `broker-fallback-drill`, `broker-smoke`, `broker-refresh-smoke`, `broker-401-smoke`, and `broker-quota-smoke`; related help/completions/tests in `src/cli.zig` and dispatch/output in `src/main.zig` | Inventory exact compatibility use first. Move still-useful fixtures behind test binaries or scripts, remove them from public help in the first v0.2 prerelease, and delete production dispatch after equivalent sidecar tests exist. Keep operator-safe `status`, `doctor`, and repair surfaces only when they serve the managed product. |
| Retired npm staging and dead workflows | `dist/npm/`; npm staging in `scripts/release-local.sh`, `scripts/release-smoke.sh`, and `scripts/release-handoff.sh`; `scripts/npm-ci-publish.sh`; `.github/workflows/npm-publish.yml`; retired-lane instructions in `docs/release-runbook.md` and `docs/registry-dry-runs-and-rollback.md` | The manifest release graph must omit npm first. Then remove tarball staging, smoke assumptions, publish script, and dead publish workflow. Keep `.github/workflows/npm-deprecate.yml` and `scripts/npm-ci-deprecate.sh` only while registry deprecation maintenance is needed; preserve historical release records. |
| Unproven provider built-ins | `generic_def`, `gemini_def`, `vercel_def`, `github_def`, `linear_def`, `figma_def`, `flakehub_def`, and `mcp_def` in `src/provider_schema.zig`; their starter config/help/dispatch in `src/main.zig`, `src/provider.zig`, config fixtures, provider proof specs, onboarding, and provider truth matrix | Produce a generated reference list before removal. Keep Claude and Codex product paths; add OpenCode only through conformance. Remove other built-ins from v0.2 enrollment/routing/help before deleting implementations. Do not reuse Claude/Codex OAuth for Gemini. Preserve provider research and evidence as historical inputs, clearly non-shipped. |
| Federation and FFI programs | Federation/ffi-sdk rows and plans in `docs/productionization-ledger.md`, `docs/plans/keepalive-push-2026-07-02.md`, and any linked build/release backlog; future C ABI or shared-library exports if found during implementation | Mark canceled immediately. Remove build targets, headers, bindings, packaging, and public roadmap promises if any exist. The only extension boundary is the versioned adapter contract plus JSON-RPC. After binding invariants migrate, delete superseded planning text; Git preserves history. |
| Superseded specs and plans | `docs/spec/model-quota-granularity-2026-07-03.md`; `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md`; `docs/spec/claude-managed-hotswap-experiment-2026-07-14.md`; `docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md`; `docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`; `docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md`; `docs/spec/background-stay-afloat-daemon-contract-2026-05-02.md`; `docs/spec/supervised-harness-restart-contract-2026-05-02.md` | Add superseded banners/authority links first. After binding invariants and implementation references migrate, delete the files; Git is the archive. Never delete the immutable evidence they cite, and leave no superseded document in the active authority chain. |
| E1 canonical-keychain experiment | `docs/spec/claude-managed-hotswap-experiment-2026-07-14.md` (TIN-2721/#447); references in `CHANGELOG.md` and `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md` | Cancel as a product gate. Preserve the v0.1.15 changelog statement and any already-captured immutable evidence, but remove the experiment from active runbooks once the sidecar golden experiment exists. Never mutate a canonical Claude identity to prove v0.2. |
| PR #459 synthetic browser cassette | Historical commit `5bd304d`: `test/evidence/browser-account-juggling/README.md`, `test/evidence/browser-account-juggling/dry-run-20260711T050543Z/manifest.json`, `test/evidence/browser-account-juggling/dry-run-20260711T050543Z/transcript.jsonl`, and PR-specific changes to `src/fixture_redaction.zig`; browser-evidence references in the 2026-07-09 valet note | PR #459 was canceled; its cassette paths are absent from current HEAD. Do not re-land or present them as live proof. `src/fixture_redaction.zig` predates and outlives PR #459, so retain current non-browser consumers and reject only the canceled PR-specific delta. Preserve commit/PR history. |

## Removal Invariants

- Immutable `docs/evidence/`, `test/evidence/`, release notes, tags, and signed
  artifacts are not retroactively edited to match v0.2 terminology.
- No deletion may remove the only reader/migration path for stable v0.1.15 state
  before the v0.2 upgrader proves preservation or an explicit safe conversion.
- Public docs are narrowed before code is removed, so prerelease users cannot
  discover a path scheduled for deletion.
- Code removal follows dependency order: public entrypoint, dispatch, state and
  implementation, fixtures/tests, then stale documentation.
- Each slice names what replaced it, the remote proof run, and the evidence path.
- If replacement proof fails, retain stable behavior and revert the prerelease
  exposure; do not delete through the failure.
