# Provider-free checkpoint and signed source delivery — 2026-10-07

Authority: user-ratified October 6 Codex resume / installed browser proof;
AGENTS.md; R-HOOK-CONVERGENCE-20261004, R-N12 and R-N13.
This is a continuation of the incomplete fifteen-hour objective, not a new goal.

The five-hour checkpoint ran from 2026-10-06 20:13:12 UTC to
2026-10-07 01:13:12 UTC. Source delivery completed afterward at 01:15:31 UTC.
The product remains experimental and unshipped. Five historical scoped parent
gates passed; six remain open. Elapsed time closed no gate.

## Delivered source

[PR #527](https://github.com/Jesssullivan/oauth-mux/pull/527) is merged.
Owner-signed head `f878ea367778ef3846cc2985b252ceb8f32cbc2a` has sole parent
`134e4603b16c539316c1ea72194cae523cedab9f` and tree
`2d013554bad5257ff31f2a051af4522cea14b08d`. Local signature verification passed.
The clean 967-file checkout matched the reviewed manifest: 704 upserts,
315 explicit deletions and 263 preserved main files.

Server squash `a4bf48e9ba8a55732e4b14d41f636d5acf8d928c` independently read back
with that exact tree, the reviewed base as its only parent and a valid server
signature. The owner-signed branch remains. Only the obsolete required CI
status-check subresource was removed; every other protection field read back
unchanged. Linear history and admin/conversation protections remain enabled.

All project execution stayed serialized through the locked Nix/Bazel guard:

| Gate | Terminal result | Epoch |
|---|---|---|
| Source/model, native snapshot, docs, format and source capture | 17/17 pass; 247 Zig cases in snapshot target | 23772bec-f237-46b4-8226-97461905eaeb |
| Measured actor, docs and source capture | 3/3 pass; 246 Zig cases across actor import closure | fc6a1cb0-4101-4dfe-bc5d-fd22bcacab9a |
| Retained-input qualification and guard/source predicates | 7/7 pass; sealed input reverified after cleanup | 8e1eed54-a03f-46c5-b1f9-4055336017a5 |
| Public source archive | Build passed | cc24e63a-0445-4b26-bc0a-469cdf316e7f |

All four terminal receipts report controller/workload exit zero, empty owned
descendants, no controller failure and no rejection. The graph digest is
`44eb0165e1e35444cf68f542d2cb076489a589a0b0841e028e39be4f07879199`.
Limits remained 4 GiB memory, no swap, 512 tasks, two CPUs and 1200 seconds.
The 246-case actor import closure contains four direct actor tests; it is not
246 distinct actor scenarios.

The 119,923,125-byte retained native archive stays outside Git. Its qualification
proves byte/custody identity, not source lineage or fresh native compilation.
Embedded backend/archive provenance remains null/dirty. Guard and extension
source fields are caller assertions; Git signature/tree verification is a
separate binding. Packaging success creates no release or support claim.

## User outcomes still open

Native44d7 failed the single detach RPC before acknowledgement/status and cold
resume. Observer158b reported fork EAGAIN before CLI execution; the resource
cause and original CLI cause remain unknown. No installed cold resume,
accepted-history/tool preservation, unmodified Codex support or live same-process
handoff is established. An absent acknowledgement leaves mutation outcome
unknown; diagnosis must not repeat that detach.

Yoga fixed-system-Nix qualification and inspection passed. Destination
registration/content verification then refused its metadata predicate.
Missing-versus-mismatch and corruption remain unclassified. No copying,
controller wrapper, live Wayland or human toolbar consent is proved. The user
already confirmed participation at Yoga's local Wayland desktop once isolated
setup is ready; no provider login is required.

HM9337 reached its deadline without an admitted compact source pair.
Genuine offline Home Manager evaluation is unrun. Its private filesystem residue
remains preserved; empty descendants do not imply successful filesystem removal.

No provider calls, fleet activation, product release, extension store/site
publication, Darwin proof or achieved SLO/SLA is included. Omux continues to own
each application's authentication integration. There is no vendor Omux hook to
await; its delivery and proof remain version-specific.

## Durable state and next work

The [source delivery receipt](../tracker-updates/integrated-delivery-source-2026-10-07.json)
records signing, isolated gates, the exact protection delta, merge readbacks and
exact Linear comment readbacks for TIN-5338, TIN-2063 and TIN-2057. Their issue
scopes and states were preserved. This receipt and these checkpoint updates are
post-head evidence in the original workspace, not files claimed inside f878ea.

The [five-hour checkpoint](../../.goal/omux-native-browser-2026-10-06.json) retains
the original [fifteen-hour objective](../../.goal/omux-integrated-delivery-2026-10-05.json)
and eleven acceptance scopes. Its delivery subgate passed only for source
delivery; the six parent implementation/installed-proof gates stay open.

Root remains the only executor. Reattached source agents are preparing optional
single-call detach stage diagnostics and separately scoped held-cgroup process
counter observations. Proposals stay excluded and unapplied until review.
Model custody/privacy/one-invocation/default behavior before one qualified
installed diagnostic; preserve all limits and acceptance assertions. Next
parallel leads are the closed Yoga first-failed metadata predicate and a bounded,
qualified compact Home Manager producer. No automatic installed retry is queued.

The original index cacheTREE refresh earlier in the session is preserved as a
fact: prior full semantic state is unknown. Source materialization used a fresh
review index and working-file custody witnesses, rather than asserting that the
mixed original index represented the source change.
