---
title: Native runtime retirement and same-process generation review
date: 2026-10-04
status: review
summary: Read-only source inspection identifies incomplete runtime generation cleanup and a teardown race; a separate proposed epoch must bind retirement to the exact native runtime without clearing unresolved or accepted custody.
refs:
  - R-N11
  - R-N12
  - R-N13
  - R-HOOK-CONVERGENCE-20261004
  - docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md
  - docs/agent-notes/2026-10-04-sess-omux-owner-codex-core.md
---

R-N13: root authorized this documentation-only mutation. The SDK status candidate,
Omux runtime, manifests, patches, binaries and historical receipts remain frozen.
This review ran no build, test, generator, executable or provider action. Root owns
classification and indexing. The proposed changes below are unimplemented and do
not inherit the current status or installed interoperability proofs.

The inspected SDK root is
`/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004/source`,
restored from official commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d` and the
preserved 164-change owner candidate before the separate seven-file status delta.
Locations below refer to source inspection of that recovery epoch; they are not
execution evidence.

## Exact implemented paths

| Source path under the inspected root | Observation |
| --- | --- |
| `codex-rs/core/src/auth_broker.rs:343`, `prepare_thread_identity` | Any existing `ThreadId` returns `Prepared` without allocating a new generation. A new map entry increments the checked process-local counter. Persisted thread identity therefore does not itself distinguish replacement native runtimes. |
| `codex-rs/core/src/session/session.rs:854`, `Session::new` | Resume retains the native conversation UUID. Configured construction prepares managed registration before background authorization/work; unconfigured construction attempts optional native metadata preparation. Neither call carries an exact runtime identity. |
| `codex-rs/core/src/thread_manager.rs:2099`, `spawn_thread` | Resume returns the existing running `Arc<CodexThread>`. For a nonrunning existing runtime it removes the map entry and constructs a replacement, without a corresponding registry retirement transition. Returning the same running Arc must continue to preserve its generation. |
| `codex-rs/core/src/thread_manager.rs:1332`, removal methods | Generic removal can leave other Arc holders alive. `remove_thread_if_matches` protects a replacement map entry from delayed cleanup, but does not retire native registry metadata. |
| `codex-rs/core/src/thread_manager.rs:1377`, `shutdown_all_threads_bounded` | Completed shutdowns are removed by thread UUID; failed or timed-out shutdowns remain tracked. Removal is not an authenticated owner detach. A future change must also match the exact runtime when removing completed entries. |
| `codex-rs/core/src/thread_manager.rs:2310`, `finalize_thread_spawn` | The actual runtime is published before managed registration completes; readiness/resume exposure follows the exact admission ACK. This fence must remain when introducing runtime generations. |
| `codex-rs/core/src/session/mod.rs:1059`, `SessionIo::shutdown_and_wait` | Sends `Op::Shutdown` and awaits the session-loop termination future. This is stronger than Arc disappearance or a closed submission channel. |
| `codex-rs/core/src/session/handlers.rs:286`, shutdown handlers | Shutdown cancels/aborts native tasks, stops execution/MCP/hooks, and flushes/closes native persistence before completion. It does not produce daemon owner retirement authority. |
| `codex-rs/app-server/src/request_processors/thread_processor.rs:1262`, `finalize_thread_teardown` | Production app-server teardown **does call** `auth_broker::forget`. Not-loaded unsubscribe and explicit removal use this function; a loaded idle resume with changed overrides also calls it after shutdown. The earlier broad assertion that production never calls `forget` was incorrect. Core itself has no production caller. |
| `codex-rs/app-server/src/request_processors/thread_processor.rs:1311`, `prepare_thread_for_removal` | Removes the runtime before waiting for shutdown, proceeds on submit failure/timeout, then calls final teardown. A map removal alone cannot authorize generation replacement. |
| `codex-rs/app-server/src/request_processors/thread_lifecycle.rs:418`, `unload_thread_without_subscribers` | Idle unload waits for shutdown and uses pointer-matched removal, but does **not** call `forget`. Native identity metadata can therefore survive a real completed unload. |
| `codex-rs/app-server/src/request_processors/thread_processor.rs:2384`, revert/reload | Waits for shutdown and event drainage, removes the runtime, then resumes the same persisted UUID while retaining subscriptions. It does not run full final teardown; native generation allocation must cover this path too. |
| `codex-rs/core/src/auth_broker.rs:799`, request/work guards | `NativeWorkGuard` and `BrokerRequestGuard` counters are keyed by thread UUID. Cleanup currently has no expected runtime/generation argument. A replacement must not share cleanup authority with stale guards or old runtime holders. |

## Concrete cleanup race

`auth_broker::forget` checks pending/attached custody under one lock, releases it,
calls separately locked `unregister`, then locks again and unconditionally removes
the detached marker and thread identity. A concurrent real owner preparation can
insert pending registration after the first check. `unregister` then correctly
refuses to clear pending authority, but the final phase still removes its identity.
No runtime token distinguishes an old teardown caller from the new preparation.

This is a source-level race finding, not a reproduced failure. The current status
reader fails closed on inconsistent metadata. Fixing the race by clearing more
state, resetting the global registry or treating shutdown as detach is prohibited.

## Proposed next epoch boundary

Keep the persisted native thread UUID, rollout and original logical request UUID
unchanged. Introduce an internal exact runtime token held by the actual Session,
with a checked thread-instance generation reserved atomically before managed
authorization or native work. Returning an already running Arc reuses that token;
constructing a different runtime cannot reuse it merely because its thread UUID
matches. Unconfigured metadata-unavailable construction remains ordinary ambient
behavior, with honest unsupported identity/listing rather than forced adoption.

Registry transitions should distinguish constructing, live, stopping and completed
runtime lifetime from pending, unresolved, attached and exactly retired custody.
Matching the actual runtime token and current generation, rejecting any pending or
unresolved registration, and checking native/request/ancillary activity must occur
under one registry lock. An expected pointer/token also guards delayed manager and
app-server cleanup. No lock may span a shutdown wait or daemon callback.

For the bounded managed same-process journey, perform authorized exact detach while
the native runtime and verified endpoint remain loaded, await its real outcome,
then complete shutdown before replacing the runtime. Attached or unresolved
shutdown cannot silently become retired. Withheld/lost ACKs remain blocked; local
guard drainage does not settle daemon accepted or uncertain request custody. A
native retirement ACK alone does not prove the daemon committed its final outcome.
Retain immutable old references, operations and daemon history while a new runtime
awaits its own actual admission. Retag guards by exact runtime identity so stale
completion cannot decrement or clear replacement state. Never replay an accepted
stream or restart tool execution to recover generation state.

The first implementation should cover constructor reservation, actual loop
termination, pointer-matched map removal, idle unload, explicit removal and
revert/reload through shared transitions. It must replace the multi-lock `forget`
pattern with a result that reports refusal rather than an unconditional cleanup.
Session drop or channel closure can retain a blocked tombstone; neither grants
retirement. This requires a separately reviewed SDK source/artifact epoch.

## Required gates and limits

- Genuine same-process runtime: configure/register, native metadata rename, exact
  detach, completed unload and resume the same UUID; prove unchanged process
  incarnation/owner/endpoint, strictly newer thread-instance generation, new
  registration operation and preserved native history prefix/settings checkpoints.
- Rejoin the same running Arc and prove no generation increment. Concurrent resume
  attempts must not construct two live runtime authorities or rollout writers.
- Hold real task/request activity, withhold registration ACK, and exercise shutdown
  failure/timeout; replacement must refuse before authorization or readiness.
- Delay old pointer-matched cleanup and old guard destruction across a permitted
  replacement; neither may remove or alter the replacement token/counters.
- Exercise malformed/lost committed replies and old-generation callbacks against
  the real verified carrier; preserve unresolved custody and immutable request
  identity, with no synthetic authority setters or global resets.
- Run focused core/app-server lifetime tests and the declared eight production
  compilation targets under locked Nix/Bazel, followed by an actual installed
  provider-free same-process unload/resume gate. Provider-backed accepted-stream,
  tool and seamless account handoff remain separate authorized live gates.

The current ordinary **cold** resume target starts a fresh native process and owner
after acknowledged detach and clean exit. It does not exercise same-process runtime
replacement, and this finding does not invalidate that narrower target or the
read-only status hook. It also does not convert their eventual passes into a
same-process continuity claim. No new generation or retirement implementation was
made or tested during this review.
