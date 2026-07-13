# v0.2 Phase 1 contract reset - evidence packet

- Date: 2026-07-13
- Program: GitHub #463 / Linear TIN-2057
- Packet status: **draft; not landed**
- Claim class: source-only contract draft pending final-head proof
- Live broker claim: none

## Result

Landed PRs #464-#474 establish one v0.2 authority, remove retired npm
publication staging, make `omux` the primary future executable identity, and
introduce the Zig-owned declaration manifest. Open PR #475 prepares a
managed-harness JSON-RPC surface v2 that declares seven lifecycle methods as
explicitly `not_implemented`. This packet remains draft until that declaration
and every Phase-1 proof gate below are landed and recorded.

This packet does not prove a Claude sidecar, managed launch, account switch,
exact-model continuity under live exhaustion, OpenCode conformance, installed
v0.2 prerelease, or the TIN-2057 golden story.

## Landed baseline

| PR | Merge/head | Bounded result | Authoritative proof |
| --- | --- | --- | --- |
| #464 | `7cfde30` | v0.2 authority, deletion ledger, threat model | CI 29170399541 |
| #465 | `2692977` | retired npm staging removed and guarded | CI 29170928345; Release Proof 29171875453 |
| #466 | `5989228` | platform-aware Claude first-run assertion | CI 29172166345 |
| #467 | `816e5c0` | superseded-authority guard | CI 29173335167 |
| #468 | `91d1f8f` | v0.2 migration safety net | CI 29188693082 |
| #469 | `343db62` | one binary, `omux` primary, compatibility identity | CI 29189752448; Release Proof 29190341121 |
| #470 | `5340fcb` | Zig-owned release declaration | CI 29222368305; Release Proof 29223128275 |
| #471 | `0a2f1e3` | Nix consumes release identity | CI 29224760895; Release Proof 29225510811 |
| #472 | `c43a529` | stable archive/package layout consumes declaration | CI 29233911192; Release Proof 29235234075 |
| #473 | `57844fb` | repository-scoped GF App checkout | CI 29231628581 |
| #474 | `bb3e5ff` | workflow versions derive from Zig authority | CI 29248993672; Release Proof 29250121003 |
| #475 | draft after `66572c3` | managed-harness surface-v2 declaration and reproducible exact-ref proof checkout | final-head CI, Remote Check, and Release Proof pending |

The post-TIN-2808 no-spend Remote Validate E2E on current pre-#475 main passed
as run 29277105818 at exact head `bb3e5ff`. This proves the remote v0.1.15
substrate and scoped GF checkout, not v0.2 continuity.

The first #475 Remote Check, run 29279869383 at `d43af47`, reached and passed
the Zig build and test stages, then failed because the dispatched checkout did
not contain the immutable v0.1.15 baseline commit required by the
characterization gate. Commit `66572c3` makes Remote Validate fetch full
history and adds a smoke assertion for that proof invariant. Run 29280783526
is the corrective proof for old head `66572c3`, not the amended declaration.
Release Proof 29281192288 was canceled before execution after review found the
contract gaps now being corrected.

## Managed-harness declaration

Zig authority: `src/managed_harness_contract.zig`

Checked projection: `schemas/managed-harness-jsonrpc-v2.schema.json`

Declared lifecycle:

- `surface/info`
- `harness/preflight`
- `session/launch`
- `route/lease_snapshot`
- `session/transition`
- `repair/handoff`
- `session/teardown`

The schema declares all methods `not_implemented` and defines their error
shape; there is no managed-harness runtime dispatcher. The schema binds
method-specific request and result shapes, opaque handles, exact-model demand,
a maximum of two upstream attempts, typed leases, cleanup, and action-required
results, a narrow typed scalar extension namespace that rejects sensitive and
identity-bearing names, error `-32099` for declared
unsupported methods, and `-32601` for unknown methods. Shipped broker surface
v1 remains unchanged. The release declaration continues to label the managed
surface `planned_unshipped`.

## Prompt 78 contract matrix

| Required compatibility contract | Phase-1 declaration | Runtime proof |
| --- | --- | --- |
| Managed carrier | OS-CSPRNG 256-bit capability, base64url, memory/session/child-bound, constant-time and never logged; named Claude carriers; auth stripping and elected OAuth injection; loopback bind; fixed Anthropic origin and system TLS; `CONNECT`, absolute-form, caller-selected upstreams, and auth redirects rejected; bad capability is local 401 with zero upstream | unimplemented; TIN-1829 |
| Exact model and retry table | transition owns the only model demand; attempts inherit it; same-route retries inherit handles; one pre-body 401/403/429 alternate must use distinct account and route handles | declaration tests include mismatched-model, changed-same-route, reused-alternate, third-attempt, and unsafe-replay negatives; runtime unimplemented |
| Replay memory | 32 MiB/request, 64 MiB/sidecar, 256 MiB/host; atomic PID/heartbeat/expiry reservations; stale reclamation; chunked/unknown overflow streams once with backpressure; cancellation releases; no disk spool | unimplemented; sidecar memory/property proof |
| No unsafe replay | ambiguous transport, cancellation, and started responses propagate the original failure or response unchanged; provider 5xx passes through to native retry | declaration negative fixtures only; fake-upstream runtime matrix remains |
| Bounded wait | one trusted-reset wait, at most 30 seconds and within request deadline; re-elect once; otherwise typed 429 plus trusted `Retry-After` | unimplemented; clock-injected state-machine proof |
| Shared leases and staleness | typed opaque session/account/route lease with PID, heartbeat, expiry, owner state; stale owners reclaimed; unavailable state advisory; asymmetric route ranking frozen | unimplemented; cross-process concurrency proof |
| Action required and repair | typed exact-model exhaustion action; provider-owned re-enrollment; automatic stale-backup restore false | unimplemented; repair integration proof |
| Teardown | typed success requires sidecar termination, capability disposal, lease release, and replay-reservation release | declaration only; lifecycle proof remains |
| Redaction | opaque handles and redacted labels only; identity and credential names reserved out; extensions limited to typed `x_flag_*`, `x_count_*`, and `x_ratio_*` scalars; no request-body persistence | schema/fixture tests only; live log/evidence proof remains |

Implementation mechanics remain owned by the v0.2 plan and threat model. The
observable constants above are now part of surface v2 rather than delegated to
unversioned prose.

## Review and local debugging

Local checks are non-authoritative. The amended head must include Zig 0.14.1
module tests, full `zig build test`, native build, schema drift, positive and
negative Draft 2020-12 instances, semantic cross-attempt validation, test-root
coverage, authority drift, endpoint-free validation, secret scanning, JSON
projection assertions, action linting, v0.1.15 release characterization, and
diff checks.

## Phase-1 definition-of-done proof table

| Gate | Required evidence | Current state |
| --- | --- | --- |
| Authority reconciliation | `AGENTS.md`, plan, authority map, threat model, #463, and TIN-2057 agree; superseded designs guarded | landed in #464/#467; final consistency audit pending |
| Retired npm red/green boundary | guard fixture and #465 final CI/Release Proof | landed; packet must cite guard artifact and command exactly |
| Zig serialization and identity invariants | existing refresh flock, identity collapse, and shipped Codex observable contracts remain green | pending final-head remote regression citation |
| Threat-model consistency | carrier, origin, replay, memory, lease, teardown, and redaction schema match the named threat model | amended declaration present; final-head adversarial review and remote proof pending |
| Single version and release authority | `build.zig.zon` -> Zig declaration/manifest; package/workflow projections cannot diverge | landed #469-#474; final manifest-drift citation pending |
| Final-head remote repository check | `just check <final-ref>` on GF/Just/Nix | pending amended #475 head |
| Public source build | clean Just/Nix build with private checkout credentials, GF endpoints, and Tinyland runtime inputs absent | pending independent proof; private GF execution alone is insufficient |
| Secret and private-runtime exclusion | `secrets-scan-dir.sh`, `endpoint-free-check.sh`, and fork boundary guard | pending final-head citation |
| Dependency, license, and provenance | dependency graph plus license/provenance/SBOM contract check | pending final-head citation |
| Schema and manifest drift | generated managed-harness schema, instance fixtures, semantic validator, and release-manifest drift | pending final-head citation |
| v0.1.15 release characterization | supported archive/package outputs after npm subtraction | prior release proofs exist; final exact citation pending |
| Release proof | exact amended branch through `release-proof` | pending; 29281192288 canceled before execution |
| Management and operator reconciliation | #463, TIN-1798/TIN-2057, initiative status, Prompt 78, release runbook, migration ledger, and claim matrix agree | pending final links and stale-update correction |
| Prohibited-claim audit | no beta, live broker, installed prerelease, full provider, FFI/federation, or Zig-REAPI claim without named proof | draft packet is bounded; final repo/tracker audit pending |

GF runner execution is not Bazel REAPI proof; TIN-2105 remains parallel and
nonblocking.

Adversarial review found and the implementation fixed:

1. invalid null JSON-Schema keywords;
2. method/result rules that were descriptive but not wire-bound;
3. sensitive extension names admitted at the first level;
4. unreferenced error schemas; and
5. nested sensitive-name bypass through additive objects.

That verdict applied to old head `66572c3` and is invalidated by the amended
contract. A final-head review of source, generated schema, fixtures, and this
packet is pending.

## Management reconciliation

- GitHub #463 correction: issue comment `4962819408`; final Phase-1 result link
  remains pending.
- Linear TIN-1798 correction comment `de6d44d3` and TIN-2057 correction comment
  `7079c081` record the open proof boundary; final proof links remain pending.
- Initiative update `e5ebbdb1` was rewritten on 2026-07-13 as an at-risk
  correction; Phase 1 is not complete while this packet and the
  public-source/provenance gates remain open.
- Prompt 78 remains `running` until the landed evidence and management surfaces
  satisfy every definition-of-done row.
- Release runbook, migration ledger, and claim matrix require final consistency
  confirmation after #475 lands.

## Claim ledger

| Claim | State after Phase 1 | Strongest evidence |
| --- | --- | --- |
| Stable v0.1.15 distribution and Codex reference behavior | shipped | v0.1.15 release characterization, changelog, releases, committed evidence |
| Retired npm cannot re-enter supported staging | remotely proven | #465 CI + Release Proof |
| Release identity/declaration has one Zig authority | remotely proven source contract | #469-#474 CI and Release Proof runs |
| Managed-harness surface v2 is checked and versioned | draft declaration; unlanded | #475 amended schema and final remote checks pending |
| Managed Claude sidecar accepts authenticated traffic | unimplemented | future TIN-1829 proof |
| One safe alternate preserves exact model in one process | unimplemented | future TIN-2077/TIN-2057 proof |
| Codex and OpenCode conform to surface v2 | unimplemented | future TIN-1798 adapter proofs |
| 2xClaude + 2xCodex golden continuity | unproven | TIN-2057 remains open |
| Three clean non-maintainer beta installs | unproven | six-week beta exit gate |

## Next gate

After every Phase-1 gate above closes, the next implementation and proof gate is
the already-active TIN-1829: an authenticated, per-session Claude sidecar
skeleton with fixed upstream authority, bad-capability zero-upstream proof,
streaming pass-through, lifecycle cleanup, and no account-rotation claim.

TIN-1798 stays In Progress for Codex, Claude, and OpenCode lifecycle round trips.
TIN-2057 stays open with zero v0.2 golden bullets credited by this packet.
TIN-2050's exact publication projection, signed v0.2 SBOM/provenance, and
TIN-2723's Linux systemd/secret-tool proof remain separate open delivery gates.
