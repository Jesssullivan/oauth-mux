# Reauth Orchestrator Designation: Mediator-on-top-of-Engine

Status: DECISION (TIN-2064). Updated: 2026-06-12. Adversarially reviewed;
this revision incorporates the review's corrections (seam inventories, lock
truth, current-vs-target framing, the missing flow-composition workstream).

## The conflict

Two "reauth orchestrator" shapes exist:

- **The engine** — `src/enroll/reauth.zig` (`ReauthOrchestrator`, merged in
  #344): a Flow-enum **executor**. Given an approved flow
  (`device_code` / `redirect_loopback` / `command_owned` / `pat_paste`) it
  runs it over injected seams and returns a result. It knows *how* to
  re-login; it has no opinion about *whether* or *when*.
- **The mediator** — `src/reauth/orchestrator.zig` (branch
  `reauth-orchestrator`, draft #378): a **state machine** over account
  lifecycle (`idle → needs_reauth → handoff_emitted → awaiting_user →
  evidence_refresh → warm | dead | escalated`) with an `ActionClass`
  discriminator (`refresh_due` / `auth_revoked` / `capability_degraded` /
  `unreauthable`). Mediation-not-control: the only credential-mutating
  machine action is refresh; `auth_revoked` emits a redacted user-mediated
  handoff and waits; `unreauthable` escalates and is skipped (never-halt).
  It deliberately has **no login seam**.

## Decision

**Both are canonical, at different layers: the mediator decides, the engine
executes — and the consent boundary sits exactly between them.**

1. **The mediator is the account-lifecycle authority.** It owns state,
   never-halt policy, escalation (un-reauthable / duplicate-identity), and
   *when* a handoff is raised. It never runs a login — unchanged, ever.
2. **The engine is the flow executor.** It owns *how* an approved flow runs.
3. **The seam between them is operator consent.** The mediator's
   `emit_handoff` produces the redacted handoff record. Operator approval —
   via CLI verbs (TIN-1806) or UI (#347) — invokes the *execution path* for
   the chosen flow. The engine's result becomes new evidence; the mediator
   observes it on `evidence_refresh` and transitions to `warm`. The mediator
   never gains a login seam; the engine never gains lifecycle state.

### Current state vs target (honesty section)

The review established that **approval still does not reach the engine**:
the mediator's emitted `next_action` for `auth_revoked` points at
vendor-CLI paths (`oauth-mux codex login-device <slot>`, which shells the
vendor's own `codex login --device-auth`; `env CLAUDE_CONFIG_DIR=… claude
/login`). As of the flow-composition car, a production `RunFlowFn` exists for
the `device_code` arm, and `device_code.zig` / `browser_launch.zig` are wired
into the main test root. That does **not** mean any provider has flipped to
engine-run yet: no approval verb or UI action invokes the engine, loopback
still lacks a live `awaitCallback` seam, and `command_owned` / `pat_paste`
remain non-engine-run by design.

That is acceptable and intended: **vendor-CLI delegation remains a valid
execution path forever** (it is the contract-pinned path for Claude — see
Contract note). The engine becomes the executor for flows as they gain
production bindings, via a named workstream:

**TRAIN CAR — "flow composition" (inserted into TIN-2053 before #347/#354
wiring):**
- Done in #422: production `RunFlowFn` composition for `device_code.zig` (RFC
  8628), plus main-test-root wiring for `device_code.zig` and
  `browser_launch.zig`.
- Still pending: `callback_server.zig` loopback PKCE composition needs a live
  `awaitCallback` seam, and `browser_launch.zig` is not yet consumed by a live
  runner.
- Done in #378: `HandoffRecord` has a correlation id so approval verbs can name
  what they approve.
- Done in #378: `MediationKind` gained `command_owned` / `pat_paste` variants
  and `consentFor` stopped hardcoding `.device_login` for every provider.
- Still pending: approval verbs / UI wiring that invoke `oauth-mux reauth run
  <handoff-id>` for engine-run flows.

Graduation implementation note (2026-06-14): #378 now implements the mediator
side of those deltas and wires the module into the main test root. #422 adds
the first production flow-composition runner for `device_code`, but approval
still cannot invoke engine-run flows.

Approval-surface implementation note (2026-06-14): TIN-1806 now has the first
CLI surface shape: `oauth-mux reauth start|wait|drain|run`. `start` queues a
redacted user-mediated handoff under the per-account repair lock, `wait`
observes pending/resolved state, `drain` lists pending handoffs, and `run`
refuses with `engine_run_available:false` until a provider is explicitly
flipped to engine-run. This is intentionally command-owned only; it does not
silently invoke browser, device, vendor CLI, or credential-write flows.

### Binding map (corrected to the real seams)

Mediator seams (`orchestrator.zig`): `clock`, `read_evidence`, `refresh`,
`emit_handoff` — exactly four; no login seam.

| Mediator seam | Binds to |
| --- | --- |
| `clock` | injected monotonic/wall clock (tests inject; daemon binds real) |
| `read_evidence` | route readiness / health / probe evidence (no provider call) |
| `refresh` | broker-owned serialized refresh (TIN-1791) under the per-account lock — identity-lock participation is future work (TIN-2043), not current behavior |
| `emit_handoff` | typed redacted handoff records (stay-afloat surface; web UI #347 later) |

Engine seams (`reauth.zig`): `run_flow`, `confirm_identity`, `write_store`,
`process_spawn` — exactly four.

| Engine seam | Binds to |
| --- | --- |
| `run_flow` | the flow-composition layer: `device_code` is composed; loopback / browser launch execution remain pending; command-owned remains vendor delegation |
| `confirm_identity` | identity-hash compare (`identity_hash.zig`; clone-gate semantics from #344) |
| `write_store` | atomic `writeFileReplace` 0600; invoked only under the externally-held account lock (see Locks) |
| `process_spawn` | OS process spawn (browser/vendor-CLI); `browser_launch.zig` has its own seam bundle consumed by `run_flow` impls, not bound here directly |

### Locks (corrected)

- The **mediator** holds no credential locks; it reads evidence and emits
  records.
- The **engine acquires no locks of its own** (verified: no lock logic in
  `src/enroll/`); it is designed to run **under an externally held
  per-account lock** owned by the approval surface (the CLI verb / UI action
  acquires the same `provider:account` lock domain as refresh/session before
  invoking `begin()`).
- **Self-revocation prevention does NOT live at store-write time.** By the
  time a flow result is written, the upstream login has already minted a new
  chain. The real prevention is the mediator's pre-emptive classification:
  `unreauthable` accounts (login would revoke a live same-identity session
  or hit a step-up wall) are routed to `escalated` and never offered a login
  handoff at all. The approval surface additionally try-takes the identity
  lock *before* invoking any flow (refuse-on-conflict, before any provider
  interaction) — a flow-composition requirement, not an engine-internal one.
- CLI verbs (TIN-1806) talk to the **mediator** for state/handoffs and to
  the **approval/execution surface** for engine-run flows, keeping the
  consent boundary visible in the command surface.

## Contract note (2026-05-14 in-agent-reauth-handoff)

Explicit auditable approval executing a login is permitted by the contract,
so this designation is contract-sound. The contract **pins Claude as
command-owned** (upstream `claude /login` user-mediated). Moving Claude to an
engine-run loopback-PKCE flow (#354's material) is a **provider-boundary
amendment** that must be made explicitly in that contract — until amended,
Claude's execution path remains vendor-CLI delegation even after the engine
productionizes for other providers. Vocabulary unification rides #378: the
mediator now imports the shipped `types.RepairOwner` vocabulary and uses the
contract's redaction boolean names.

## Why not the alternatives

- *Engine-only*: an executor that decides when to log in violates
  mediation-not-control; never-halt invariants would be re-derived inside
  flow code that holds credentials. Refuted.
- *Mediator-only*: gives the state machine a login seam — the exact thing
  its contract forbids; flow mechanics would bloat a module valuable
  *because* it is pure. Refuted.

## Consequences for the unparking train (TIN-2053)

Revised order (the review showed the original "unchanged order" claim was
not supportable):

1. #378 graduates from draft with build wiring **plus the named deltas**:
   handoff correlation ids, `MediationKind` extension, flow-aware
   `next_action`, contract-vocabulary unification.
2. **Flow composition** (new car, above) — prerequisite for any
   approval-invokes-engine behavior.
3. TIN-1806 CLI verbs (mediator state/handoffs + approved execution) —
   **before** #347, whose action buttons target these verbs' surface.
4. #347 web UI: reauth board reads mediator records; actions call the
   approval surface.
5. #354 Claude adapter: rebase first (its branch predates the merged engine
   and would remove it); engine-side flow material lands **behind the
   contract amendment**; the `loggedIn:false → auth_revoked` evidence
   mapping is new work to build (it does not exist on the branch), gated on
   TIN-2060 (keychain ground truth) + TIN-2054 (guard parity).
6. #355 warm scheduler: its `RefreshFn` (returns `RefreshResult`) binds to
   the same broker-owned refresh as the mediator's `refresh` (returns
   `void`) via a thin adapter — same authority, different signatures.

Acceptance for TIN-2064: this document + designation notes on #378 and the
merged #344 + the TIN-2053 order update above.
