//! Reauth orchestrator: the pure state-machine connective tissue that composes
//! the loopback callback server (PR#349), the Claude reauth adapter (PR#354),
//! the warm scheduler (PR#355) and the oauth-mux CLI handoff surface — without
//! ever performing a login itself.
//!
//! North star (in-agent-reauth-handoff contract, 2026-05-14): the orchestrator
//! MEDIATES, it does NOT run logins. It reads diagnostic evidence, EMITS a
//! redacted user-mediated handoff record, WAITS for operator-confirmed evidence,
//! refreshes route evidence, and only marks an account selectable once evidence
//! says so. It NEVER silently runs browser/device auth, upstream CLI login,
//! provider probes, credential rewrites, or session-store repairs.
//!
//! North star (resilience / never-halt): a dead or blocked account (e.g. the
//! AAS-locked, un-reauthable Codex `max-1` of openai/codex#25737, or its
//! same-account duplicate `max-2`) must NEVER block live accounts. When such an
//! account degrades, the orchestrator surfaces an ESCALATION handoff that
//! explicitly forbids the revocation-inducing `login-device` path, instead of
//! looping forever or emitting a destructive login handoff. Live accounts keep
//! flowing past it.
//!
//! Build constraints honored here: greenfield NEW FILE; pure core over injected
//! fn-pointer + *anyopaque seams; std.testing.allocator leak-checked; Zig 0.14.1
//! idioms. GRADUATED from draft (TIN-2048/TIN-2064): now wired into `zig build
//! test` (its tests no longer compile to nothing), and it imports `../types.zig`
//! for the SHARED `RepairOwner` vocabulary ONLY — that is the designation spec's
//! contract-vocabulary unification, not an I/O dependency. The module still owns
//! NO credentials, opens NO sockets, starts NO provider probes on its own, and
//! performs NO login. All real work stays behind the four seams below.
//!
//! The three real subsystems are reached only through the seams; in production
//! the broker binds them to callback_server / claude_reauth / warm_scheduler,
//! and the tests bind them to deterministic fakes.

const std = @import("std");
const types = @import("../types.zig");

/// Who owns the destructive/credential-mutating step. The orchestrator only ever
/// mediates; the owner of the repair is recorded so an agent never assumes
/// credential control. Unified onto the shipped `types.RepairOwner` vocabulary
/// (designation spec 2026-06-12, §"contract-vocabulary unification") so the
/// emitted record speaks the same owner language as `provider_schema` /
/// `secret.writebackPlan`: `oauth_mux_refresh` (broker rotates the chain),
/// `upstream_cli_login` (operator runs the vendor login), `manual_only` (no
/// automated repair — a provider/policy fix or a human retiring the slot).
pub const RepairOwner = types.RepairOwner;

// ─────────────────────────────────────────────────────────────────────────────
// States
//
//   idle ── needs_reauth ── handoff_emitted ── awaiting_user ── evidence_refresh
//             │                                                      │
//             ├── (refresh-only path, no login) ── evidence_refresh ─┤
//             │                                                      ├─→ warm
//             └── (un-reauthable / budget-exhausted) ── escalated    └─→ dead
//
//   `escalated` is the never-halt sink for accounts that must NOT be re-logged
//   in (max-1 #25737, or its same-account duplicate max-2). It surfaces a
//   redacted escalation handoff and is then SKIPPED — the orchestrator returns
//   to servicing live accounts. `dead` is the sink for a refused/abandoned
//   handoff that is safe to retire. Neither sink halts the loop.
// ─────────────────────────────────────────────────────────────────────────────

pub const State = enum {
    /// Token healthy; nothing to do. The warm scheduler keeps it hot.
    idle,
    /// Evidence says the route is not selectable and a credential action is
    /// needed. We have NOT yet decided refresh-vs-handoff-vs-escalate.
    needs_reauth,
    /// A redacted, user-mediated handoff record has been emitted to the CLI
    /// surface (`stay-afloat handoffs`). No login has run.
    handoff_emitted,
    /// Waiting for the operator to complete the out-of-band action. The
    /// orchestrator polls evidence; it does NOT touch credentials.
    awaiting_user,
    /// Re-reading diagnostic evidence to learn whether the account became
    /// selectable. Pure evidence read; no provider probe.
    evidence_refresh,
    /// Evidence proves the route is live + selectable. Hand back to the warm
    /// scheduler as a kept-warm account.
    warm,
    /// Terminal-but-recoverable sink: handoff refused/abandoned or the slot is a
    /// retire-me duplicate. Skipped by the loop; cleared only by the operator.
    dead,
    /// Never-halt sink for un-reauthable accounts (login would revoke a live
    /// session and/or hit an OTP wall). A redacted escalation handoff is raised
    /// that FORBIDS login-device; the account is then skipped. Live accounts
    /// continue.
    escalated,
};

/// Why an account left `idle` / what kind of action evidence implies. This is
/// the discriminator the orchestrator uses to choose refresh vs. handoff vs.
/// escalate — it is NOT a credential and carries no secret.
pub const ActionClass = enum {
    /// Token simply aged toward expiry. SAFE machine action: rotate the existing
    /// refresh chain (refresh-only, never re-login). Drives the warm path.
    refresh_due,
    /// Auth death (token_revoked / refresh_token_reused). Needs a user-mediated
    /// re-login handoff — UNLESS the account is un-reauthable (see below).
    auth_revoked,
    /// A capability/tier 4xx on a live account (e.g. max-3 codex-max
    /// degraded:unknown_4xx). This is PROVIDER evidence, not auth death: it must
    /// be probed/inspected, NEVER reauthed.
    capability_degraded,
    /// The account cannot be safely re-logged-in at all: a fresh login would hit
    /// a step-up wall and/or revoke the only live session of the SAME upstream
    /// account (max-1 #25737; max-2 == max-1). Escalation only.
    unreauthable,
};

// ─────────────────────────────────────────────────────────────────────────────
// Handoff record + consent fields (in-agent-reauth-handoff contract §record)
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of out-of-band action the operator must take. The orchestrator
/// emits the *shape* of the action; it never performs it. The four interactive
/// re-login shapes mirror the contract's four flows (device_code /
/// redirect_loopback / command_owned / pat_paste) so a record can name any of
/// them (designation spec: "MediationKind cannot express two of the four flows").
pub const MediationKind = enum {
    /// No mediation needed (refresh-only path, or already warm).
    none,
    /// Operator runs a device-code login in a fresh incognito context
    /// (login-device preferred over loopback to avoid profile-cookie
    /// bleed-through across multiple Chrome/Workspace profiles).
    device_login,
    /// Operator runs a redirect-loopback browser login (callback_server path).
    redirect_loopback,
    /// Provider login is owned by the vendor CLI itself (contract-pinned for
    /// Claude: `claude /login`). oauth-mux scaffolds the isolated config dir but
    /// the upstream login is the vendor's, never oauth-mux's.
    command_owned,
    /// Operator pastes a personal-access-token / API key (no browser). No
    /// current provider selects this; the variant exists so the record can
    /// express the contract's fourth flow when a provider gains it.
    pat_paste,
    /// Run a read-only capability probe (NOT reauth): max-3 unknown_4xx.
    capability_probe,
    /// Human escalation only: do NOT run any login. The route is un-reauthable;
    /// recovery is a provider/policy fix (#25737) or retiring the slot.
    escalation,
};

/// How an approved flow is EXECUTED once consent is given — flow-aware
/// `next_action` selection (designation spec). Today every provider is
/// `command_owned` (vendor-CLI delegation, valid forever and contract-pinned for
/// Claude); `engine_run` flips on per-provider only when the flow-composition
/// train car binds a production `RunFlowFn`, behind the contract amendment.
pub const FlowExecution = enum { command_owned, engine_run };

/// Which execution path a provider's re-login flow takes. Both current providers
/// are command-owned (the engine has no production `RunFlowFn` yet — see the
/// designation spec's "current state vs target"). Flipping a provider to
/// `engine_run` is a one-line change gated on the flow-composition car + the
/// Claude contract amendment.
pub fn flowExecutionFor(provider: []const u8) FlowExecution {
    _ = provider; // codex (login-device) + claude (claude /login) are both command-owned today
    return .command_owned;
}

/// The consent fields the contract requires on every handoff record. These are
/// the load-bearing safety booleans an agent reads before deciding whether it
/// may proceed unattended. The orchestrator PRESERVES exactly these and never
/// downgrades a destructive step to agent_safe.
pub const Consent = struct {
    /// Can an agent run this step unattended with no side effects? True iff the
    /// step neither prompts a human, mutates state, nor consumes a metered
    /// provider call.
    agent_safe: bool,
    /// Does the step require a human (browser/device prompt, OTP, etc.)?
    interactive: bool,
    /// Does the step mutate oauth-mux-owned state (scaffold config / isolated
    /// CODEX_HOME|CLAUDE_CONFIG_DIR)? Login itself is the operator's, not ours.
    mutating: bool,
    /// Does the step consume a metered provider call (a probe / refresh that
    /// hits the upstream)? The orchestrator never lets an agent_safe step do so.
    spends_provider_calls: bool,
    /// Optional budget cap surfaced to the operator (e.g. "1 probe call").
    /// Empty string = unbounded/not-applicable; never a secret.
    budget: []const u8,
    /// Mediation kind — the *shape* of the operator action.
    mediation: MediationKind,
    /// Who owns the destructive step.
    repair_owner: RepairOwner,

    /// Derive the agent_safe invariant from the other three booleans so it can
    /// never be set inconsistently. agent_safe ⇔ not interactive ∧ not mutating
    /// and consumes no metered provider call.
    pub fn deriveAgentSafe(interactive: bool, mutating: bool, spends: bool) bool {
        return !interactive and !mutating and !spends;
    }
};

/// The redaction booleans the contract requires alongside the record: an
/// assertion that no forbidden field was emitted. The orchestrator constructs
/// records from masked hints only; this struct is the machine-checkable witness
/// that the redaction held.
pub const Redaction = struct {
    /// Were raw token / refresh / key / auth-header values printed? Never.
    token_values_printed: bool = false,
    /// Were raw (unhashed, unmasked) account ids printed? Never — only the short
    /// non-reversible hash hint appears.
    raw_account_ids_printed: bool = false,
    /// Were session ids / state nonces printed? Never.
    session_ids_printed: bool = false,
    /// Were credential file paths / full auth or model response bodies printed?
    /// Never.
    credential_paths_printed: bool = false,

    /// The witness holds iff NOTHING forbidden was printed.
    pub fn allRedacted(self: Redaction) bool {
        return !self.token_values_printed and !self.raw_account_ids_printed and
            !self.session_ids_printed and !self.credential_paths_printed;
    }
};

/// A single emitted handoff record. Every string field is a masked hint or a
/// non-secret label; the struct as a whole is what `stay-afloat handoffs`
/// surfaces. The orchestrator builds these; it never executes them.
pub const HandoffRecord = struct {
    /// Stable correlation id naming THIS handoff so an approval verb can say
    /// exactly what it approves (`oauth-mux reauth run <correlation-id>` / ack / clear). It
    /// is the account routing key ("codex:max-1") — deterministic, non-secret,
    /// and unique per account (the state machine emits at most one live handoff
    /// per account episode). Added at graduation (designation spec: "HandoffRecord
    /// gains a correlation id").
    correlation_id: []const u8,
    /// Provider label ("codex" / "claude"). Non-secret.
    provider: []const u8,
    /// Account slot label ("max-1"). Non-secret slot name, NOT the upstream id.
    account_slot: []const u8,
    /// Masked email hint ("j***@sulliwood.org"). Never raw.
    email_hint: []const u8,
    /// Short account-id hash hint ("38079d6acec6"). Non-reversible; used to
    /// detect same-account duplicates without revealing the raw id.
    account_id_hint: []const u8,
    /// Redacted next-action template for the operator or approval surface, OR
    /// for an escalation, the explicit instruction NOT to run it. Dynamic
    /// placeholders are resolved by the surface from `correlation_id` and
    /// `account_slot`; the pure core allocates nothing and never embeds secrets.
    next_action: []const u8,
    /// Human-readable, redacted reason.
    reason: []const u8,
    /// Consent fields (above).
    consent: Consent,
    /// Redaction witness (above).
    redaction: Redaction,
    /// True iff this is the never-halt escalation record (forbids login).
    is_escalation: bool = false,
};

// ─────────────────────────────────────────────────────────────────────────────
// Account model (orchestrator-local; mirrors warm_scheduler.Account shape but is
// independent — no @import).
// ─────────────────────────────────────────────────────────────────────────────

pub const Account = struct {
    /// Stable routing key / slot label ("codex:max-1"). Non-secret.
    key: []const u8,
    provider: []const u8,
    account_slot: []const u8,
    email_hint: []const u8,
    account_id_hint: []const u8,
    /// Current state in the machine.
    state: State = .idle,
    /// Why it left idle (set by the evidence read).
    action: ActionClass = .refresh_due,
    /// True if this slot resolves to the SAME upstream account as another live
    /// slot (max-2 == max-1). A login here would revoke the sibling — strict
    /// loss. Forces the unreauthable/escalation path.
    same_account_as_live: bool = false,
    /// True if the account is currently live+selectable per the last evidence
    /// read. The un-reauthable-but-LIVE max-1 has this true while alive.
    live: bool = false,
    /// How many evidence polls we have done while awaiting_user (bounds the
    /// wait so we never spin forever).
    polls: u32 = 0,
    /// How many distinct handoffs we have emitted for this account (bounds
    /// re-emission; past the cap we retire to `dead`, never loop).
    handoffs_emitted: u32 = 0,
};

pub const Policy = struct {
    /// Max evidence polls before an unanswered handoff is retired to `dead`
    /// (never-halt: bounded wait, not an infinite spin).
    max_polls: u32 = 240,
    /// Max handoff re-emissions before giving up on an account.
    max_handoffs: u32 = 3,
};

// ─────────────────────────────────────────────────────────────────────────────
// Injected seams (fn pointers + *anyopaque ctx). Pure core; all I/O lives behind
// these. Exhaustive error sets, no `else` prong. The orchestrator NEVER does the
// work itself — these are the only doors to the real subsystems, and the
// "login" door is deliberately ABSENT.
// ─────────────────────────────────────────────────────────────────────────────

/// Monotonic-ish clock (Unix ms). Same shape as warm_scheduler.ClockFn.
pub const ClockFn = *const fn (ctx: *anyopaque) i64;

/// Read fresh diagnostic evidence for one account (`accounts list --json` /
/// `route explain --json`, agent-safe read). Returns the evidence the
/// orchestrator classifies. MUST NOT make provider calls or touch creds.
pub const EvidenceError = error{ OutOfMemory, EvidenceUnavailable };
pub const Evidence = struct {
    /// Route is live + selectable right now.
    selectable: bool,
    /// The action class the diagnostics imply.
    action: ActionClass,
};
pub const ReadEvidenceFn = *const fn (ctx: *anyopaque, account_key: []const u8) EvidenceError!Evidence;

/// Refresh-ONLY seam: rotate the existing refresh chain for an account that is
/// merely `refresh_due`. Bound in production to warm_scheduler.RefreshFn (which
/// runs under the per-account flock so refreshes are serialized — never racing
/// a second refresh of the same chain, which would self-revoke). This is the
/// ONLY machine action that mutates a credential, and it is rotation only, never
/// a re-login. Same error set as warm_scheduler.RefreshError.
pub const RefreshError = error{ OutOfMemory, RefreshFailed };
pub const RefreshFn = *const fn (ctx: *anyopaque, account_key: []const u8) RefreshError!void;

/// Emit a redacted handoff record onto the CLI surface (`stay-afloat`
/// handoffs). The orchestrator owns the record's CONTENT and safety; this seam
/// only persists/surfaces it. MUST NOT execute the action it describes.
pub const EmitError = error{ OutOfMemory, EmitFailed };
pub const EmitHandoffFn = *const fn (ctx: *anyopaque, record: HandoffRecord) EmitError!void;

pub const Seams = struct {
    clock: ClockFn,
    clock_ctx: *anyopaque,
    read_evidence: ReadEvidenceFn,
    read_evidence_ctx: *anyopaque,
    refresh: RefreshFn,
    refresh_ctx: *anyopaque,
    emit_handoff: EmitHandoffFn,
    emit_handoff_ctx: *anyopaque,
};

// ─────────────────────────────────────────────────────────────────────────────
// Pure transition core.
// ─────────────────────────────────────────────────────────────────────────────

/// What one `step` did, for the operator UI / logs. Counters only; no secrets.
pub const StepReport = struct {
    from: State,
    to: State,
    /// True iff a handoff record was emitted this step.
    emitted_handoff: bool = false,
    /// True iff a refresh-only rotation ran this step.
    refreshed: bool = false,
    /// True iff this step routed the account into the never-halt escalation
    /// sink (un-reauthable). Live accounts are unaffected.
    escalated: bool = false,
};

/// Classify raw evidence into the action class, applying the same-account-as-live
/// override: an `auth_revoked` (or even `refresh_due`) signal on a slot that
/// shares its upstream account with a LIVE sibling is UN-REAUTHABLE, because any
/// login/refresh that mints a new chain orphans the sibling's only live chain.
/// This is the pure guard that prevents emitting a destructive `login-device`.
pub fn classify(ev: Evidence, account: Account) ActionClass {
    // Capability degradation on a live route is never auth death.
    if (ev.action == .capability_degraded) return .capability_degraded;
    // The same-account-as-live guard dominates any auth signal: re-auth here is
    // strict loss. (max-2 == max-1.)
    if (account.same_account_as_live and ev.action == .auth_revoked) return .unreauthable;
    // An explicitly un-reauthable account stays un-reauthable.
    if (account.action == .unreauthable) return .unreauthable;
    return ev.action;
}

/// The interactive mediation shape for an `auth_revoked` re-login, by provider.
/// Claude is contract-pinned command-owned (`claude /login`, user-mediated);
/// Codex and the default use device-code login. This is why `consentFor` no
/// longer hardcodes `.device_login` for every provider.
pub fn reauthMediationFor(provider: []const u8) MediationKind {
    if (std.mem.eql(u8, provider, "claude")) return .command_owned;
    return .device_login;
}

/// Build the consent fields for a given action class + provider. This is where
/// the contract safety booleans are fixed; `agent_safe` is always derived, never
/// asserted. `repair_owner` speaks the shipped `types.RepairOwner` vocabulary.
pub fn consentFor(action: ActionClass, provider: []const u8) Consent {
    return switch (action) {
        .refresh_due => .{
            // Refresh-only rotation: machine-safe, no human, no model/provider
            // workload call. The broker-owned token endpoint call is explicit in
            // the refresh seam. Mutating (writes the new chain), so NOT
            // agent_safe-without-side-effect; the broker owns it.
            .agent_safe = Consent.deriveAgentSafe(false, true, false),
            .interactive = false,
            .mutating = true,
            .spends_provider_calls = false,
            .budget = "refresh-only",
            .mediation = .none,
            .repair_owner = .oauth_mux_refresh,
        },
        .auth_revoked => .{
            // User-mediated login. Interactive + the operator's upstream login
            // is the destructive step. The orchestrator only scaffolds
            // (mutating) and waits. Mediation shape is per-provider.
            .agent_safe = Consent.deriveAgentSafe(true, true, false),
            .interactive = true,
            .mutating = true,
            .spends_provider_calls = false,
            .budget = "1 interactive login",
            .mediation = reauthMediationFor(provider),
            .repair_owner = .upstream_cli_login,
        },
        .capability_degraded => .{
            // Read-only probe (NOT reauth). Agent-safe is false only because it
            // uses one bounded probe call. No credential repair is owned by
            // anyone (it is a provider/tier evidence question), so manual_only.
            .agent_safe = Consent.deriveAgentSafe(false, false, true),
            .interactive = false,
            .mutating = false,
            .spends_provider_calls = true,
            .budget = "1 probe call",
            .mediation = .capability_probe,
            .repair_owner = .manual_only,
        },
        .unreauthable => .{
            // Escalation only. NOT interactive for the agent (there is no safe
            // action to take), NOT mutating, and makes no provider call. The
            // destructive login is explicitly forbidden; recovery is a
            // provider/policy fix (#25737) or a human retiring the slot — no
            // automated owner, so manual_only.
            .agent_safe = Consent.deriveAgentSafe(false, false, false),
            .interactive = false,
            .mutating = false,
            .spends_provider_calls = false,
            .budget = "do-not-login",
            .mediation = .escalation,
            .repair_owner = .manual_only,
        },
    };
}

/// Build the redacted next-action template for a record. For the escalation
/// case this is the *negative* instruction that keeps an operator/agent from
/// running the revocation-inducing login. Returns a borrowed static slice; no
/// allocation, no secret.
/// Flow-aware: a command-owned provider gets its vendor-CLI command template;
/// an engine-run provider gets `oauth-mux reauth run <correlation-id>`.
pub fn nextActionFor(action: ActionClass, provider: []const u8) []const u8 {
    return switch (action) {
        .refresh_due => "broker refreshes existing chain (serialized per account); no operator action",
        .auth_revoked => switch (flowExecutionFor(provider)) {
            .engine_run => "oauth-mux reauth run <correlation-id>  (engine-run flow; explicit, auditable approval invokes the engine)",
            .command_owned => if (std.mem.eql(u8, provider, "codex"))
                "oauth-mux codex login-device <account-slot>  (fresh incognito; per-account CODEX_HOME; verify account_id_hint != live sibling)"
            else
                "env CLAUDE_CONFIG_DIR=<isolated> claude /login  (fresh incognito; file-based store, do not touch keychain)",
        },
        .capability_degraded => "oauth-mux probe --provider <provider> --account <account-slot> --capability <capability> --json  (probe only; DO NOT reauth)",
        .unreauthable => "DO NOT run login-device: un-reauthable (revokes the only live session + hits #25737 OTP wall). Escalate to provider/policy fix or retire the slot.",
    };
}

/// Construct a fully-redacted handoff record for an account+action. Pure; the
/// caller (`step`) decides when to emit it. The redaction witness is asserted
/// to hold by construction (we only ever copy masked hints / static strings).
pub fn buildHandoff(account: Account, action: ActionClass) HandoffRecord {
    return .{
        .correlation_id = account.key,
        .provider = account.provider,
        .account_slot = account.account_slot,
        .email_hint = account.email_hint,
        .account_id_hint = account.account_id_hint,
        .next_action = nextActionFor(action, account.provider),
        .reason = switch (action) {
            .refresh_due => "token approaching expiry; refresh-only",
            .auth_revoked => "route not selectable; auth revoked; user-mediated re-login required",
            .capability_degraded => "capability 4xx on a live route; classify via probe, not reauth",
            .unreauthable => "un-reauthable account; login would revoke a live session and hit an OTP wall",
        },
        .consent = consentFor(action, account.provider),
        .redaction = .{}, // all `*_printed = false` by construction
        .is_escalation = (action == .unreauthable),
    };
}

/// The orchestrator. Holds only policy + the seam bundle; no credentials, no
/// sockets, no allocation of its own beyond what seams own.
pub const Orchestrator = struct {
    policy: Policy = .{},
    seams: Seams,

    fn now(self: *const Orchestrator) i64 {
        return self.seams.clock(self.seams.clock_ctx);
    }

    /// Advance ONE account by one step of the state machine. Pure dispatch over
    /// the injected seams; mutates `account.state` in place and returns what it
    /// did. NEVER blocks, NEVER logs in, NEVER halts: every terminal-ish state
    /// (`warm`, `dead`, `escalated`) is a no-op that lets the caller move on to
    /// the next (live) account.
    pub fn step(self: *const Orchestrator, account: *Account) (EvidenceError || RefreshError || EmitError)!StepReport {
        const from = account.state;
        switch (account.state) {
            // ── Live sinks / steady states ──────────────────────────────────
            .warm, .idle => {
                // Re-read evidence; a healthy account may need a refresh or may
                // have just died. This is the only place a live account can be
                // pulled into the machine.
                const ev = try self.seams.read_evidence(self.seams.read_evidence_ctx, account.key);
                account.live = ev.selectable;
                if (ev.selectable and ev.action == .refresh_due) {
                    // Stay warm; the warm scheduler owns the actual cadence.
                    account.state = .warm;
                    return .{ .from = from, .to = .warm };
                }
                account.action = classify(ev, account.*);
                account.state = .needs_reauth;
                return .{ .from = from, .to = .needs_reauth };
            },

            // ── Decide: refresh-only vs handoff vs escalate ────────────────
            .needs_reauth => {
                switch (account.action) {
                    .refresh_due => {
                        // SAFE machine action: rotate the existing chain. No
                        // handoff, no login. On failure, fall to evidence_refresh
                        // (the warm scheduler's backoff/dead handling owns the
                        // rest); we never re-login here.
                        self.seams.refresh(self.seams.refresh_ctx, account.key) catch |err| switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            error.RefreshFailed => {
                                account.state = .evidence_refresh;
                                return .{ .from = from, .to = .evidence_refresh };
                            },
                        };
                        account.state = .warm;
                        account.live = true;
                        return .{ .from = from, .to = .warm, .refreshed = true };
                    },
                    .unreauthable => {
                        // NEVER-HALT: emit the escalation handoff that FORBIDS
                        // login, then park in `escalated`. The caller proceeds to
                        // live accounts; max-1 stays alive and monitored.
                        const rec = buildHandoff(account.*, .unreauthable);
                        try self.seams.emit_handoff(self.seams.emit_handoff_ctx, rec);
                        account.state = .escalated;
                        account.handoffs_emitted += 1;
                        return .{ .from = from, .to = .escalated, .emitted_handoff = true, .escalated = true };
                    },
                    .auth_revoked, .capability_degraded => {
                        // Emit a user-mediated handoff (re-login or probe). We do
                        // NOT run it.
                        if (account.handoffs_emitted >= self.policy.max_handoffs) {
                            // Bounded re-emission: retire rather than loop.
                            account.state = .dead;
                            return .{ .from = from, .to = .dead };
                        }
                        const rec = buildHandoff(account.*, account.action);
                        try self.seams.emit_handoff(self.seams.emit_handoff_ctx, rec);
                        account.state = .handoff_emitted;
                        account.handoffs_emitted += 1;
                        return .{ .from = from, .to = .handoff_emitted, .emitted_handoff = true };
                    },
                }
            },

            // ── Emitted → start waiting for the operator ───────────────────
            .handoff_emitted => {
                account.polls = 0;
                account.state = .awaiting_user;
                return .{ .from = from, .to = .awaiting_user };
            },

            // ── Poll evidence while the operator acts (bounded) ────────────
            .awaiting_user => {
                account.polls += 1;
                if (account.polls > self.policy.max_polls) {
                    // Never-halt: bounded wait. Give up to `dead` (retire-able);
                    // we do NOT keep an account pinned forever.
                    account.state = .dead;
                    return .{ .from = from, .to = .dead };
                }
                account.state = .evidence_refresh;
                return .{ .from = from, .to = .evidence_refresh };
            },

            // ── Re-read evidence; promote to warm only if selectable ───────
            .evidence_refresh => {
                const ev = try self.seams.read_evidence(self.seams.read_evidence_ctx, account.key);
                account.live = ev.selectable;
                if (ev.selectable) {
                    // Contract: retry/mark-selectable ONLY after evidence says so.
                    account.state = .warm;
                    account.polls = 0;
                    return .{ .from = from, .to = .warm };
                }
                // Re-classify: a freshly-revealed same-account/un-reauthable
                // signal must escalate, not re-emit a destructive login.
                account.action = classify(ev, account.*);
                if (account.action == .unreauthable) {
                    account.state = .needs_reauth; // will emit escalation next step
                    return .{ .from = from, .to = .needs_reauth };
                }
                // Still not selectable: keep waiting (bounded by polls).
                account.state = .awaiting_user;
                return .{ .from = from, .to = .awaiting_user };
            },

            // ── Never-halt sinks: no-op, let the caller move on ────────────
            .escalated, .dead => {
                return .{ .from = from, .to = account.state };
            },
        }
    }

    /// Drive every account one step. Returns aggregate counters. A blocked or
    /// dead account is a single no-op step; it can NEVER stall the others — this
    /// is the loop-level never-halt guarantee.
    pub fn tickAll(self: *const Orchestrator, accounts: []Account) (EvidenceError || RefreshError || EmitError)!TickReport {
        var report = TickReport{};
        for (accounts) |*a| {
            const r = try self.step(a);
            if (r.emitted_handoff) report.handoffs_emitted += 1;
            if (r.refreshed) report.refreshed += 1;
            if (r.escalated) report.escalated += 1;
            switch (a.state) {
                .warm => report.warm += 1,
                .dead => report.dead += 1,
                .escalated => report.parked_escalated += 1,
                else => report.in_flight += 1,
            }
        }
        return report;
    }
};

pub const TickReport = struct {
    warm: u32 = 0,
    dead: u32 = 0,
    parked_escalated: u32 = 0,
    in_flight: u32 = 0,
    handoffs_emitted: u32 = 0,
    refreshed: u32 = 0,
    escalated: u32 = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests — std.testing.allocator clean, deterministic fakes for every seam.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A scripted fake binding all four seams. Deterministic; records what the
/// orchestrator asked it to do so tests can assert the orchestrator never logs
/// in and only refreshes when allowed.
const Fake = struct {
    now_ms: i64 = 1_000_000,
    // Scripted evidence, consumed FIFO per key (falls back to `default_ev`).
    default_ev: Evidence = .{ .selectable = false, .action = .auth_revoked },
    ev_queue: std.ArrayList(Evidence),
    // Behavior toggles.
    refresh_should_fail: bool = false,
    refresh_oom: bool = false,
    emit_should_fail: bool = false,
    // Witnesses.
    refresh_calls: u32 = 0,
    emit_calls: u32 = 0,
    last_record: ?HandoffRecord = null,

    fn init(alloc: std.mem.Allocator) Fake {
        return .{ .ev_queue = std.ArrayList(Evidence).init(alloc) };
    }
    fn deinit(self: *Fake) void {
        self.ev_queue.deinit();
    }

    fn clock(ctx: *anyopaque) i64 {
        const self: *Fake = @ptrCast(@alignCast(ctx));
        return self.now_ms;
    }
    fn readEvidence(ctx: *anyopaque, _: []const u8) EvidenceError!Evidence {
        const self: *Fake = @ptrCast(@alignCast(ctx));
        if (self.ev_queue.items.len > 0) return self.ev_queue.orderedRemove(0);
        return self.default_ev;
    }
    fn refresh(ctx: *anyopaque, _: []const u8) RefreshError!void {
        const self: *Fake = @ptrCast(@alignCast(ctx));
        self.refresh_calls += 1;
        if (self.refresh_oom) return error.OutOfMemory;
        if (self.refresh_should_fail) return error.RefreshFailed;
    }
    fn emit(ctx: *anyopaque, record: HandoffRecord) EmitError!void {
        const self: *Fake = @ptrCast(@alignCast(ctx));
        self.emit_calls += 1;
        self.last_record = record;
        if (self.emit_should_fail) return error.EmitFailed;
    }

    fn seams(self: *Fake) Seams {
        return .{
            .clock = clock,
            .clock_ctx = self,
            .read_evidence = readEvidence,
            .read_evidence_ctx = self,
            .refresh = refresh,
            .refresh_ctx = self,
            .emit_handoff = emit,
            .emit_handoff_ctx = self,
        };
    }
};

fn testAccount(key: []const u8) Account {
    return .{
        .key = key,
        .provider = "codex",
        .account_slot = "max-x",
        .email_hint = "j***@sulliwood.org",
        .account_id_hint = "38079d6acec6",
    };
}

test "consent agent_safe is derived, never asserted inconsistently" {
    const c = consentFor(.auth_revoked, "codex");
    try testing.expect(c.interactive);
    try testing.expect(!c.agent_safe); // interactive ⇒ not agent_safe
    // Unified vocabulary: the operator's upstream login owns the repair.
    try testing.expectEqual(RepairOwner.upstream_cli_login, c.repair_owner);

    const probe = consentFor(.capability_degraded, "codex");
    try testing.expect(probe.spends_provider_calls);
    try testing.expect(!probe.agent_safe); // provider call => not agent_safe
    // No automated credential repair owner for a capability/tier question.
    try testing.expectEqual(RepairOwner.manual_only, probe.repair_owner);

    const esc = consentFor(.unreauthable, "codex");
    try testing.expect(!esc.interactive and !esc.mutating and !esc.spends_provider_calls);
    // even with all-false inputs, escalation is "do-not-login", owner manual_only.
    try testing.expectEqualStrings("do-not-login", esc.budget);
    try testing.expectEqual(MediationKind.escalation, esc.mediation);
    try testing.expectEqual(RepairOwner.manual_only, esc.repair_owner);
}

test "graduation: claude reauth is command-owned, codex is device_login" {
    // Contract pins Claude as command-owned (`claude /login`).
    try testing.expectEqual(MediationKind.command_owned, consentFor(.auth_revoked, "claude").mediation);
    try testing.expectEqual(MediationKind.command_owned, reauthMediationFor("claude"));
    // Codex and the default use device-code login.
    try testing.expectEqual(MediationKind.device_login, consentFor(.auth_revoked, "codex").mediation);
    try testing.expectEqual(MediationKind.device_login, reauthMediationFor("anything-else"));
    // Refresh-only rotation is owned by the broker.
    try testing.expectEqual(RepairOwner.oauth_mux_refresh, consentFor(.refresh_due, "codex").repair_owner);
}

test "graduation: handoff carries a stable correlation id = account key" {
    var acct = testAccount("codex:max-1");
    acct.account_slot = "max-1";
    const rec = buildHandoff(acct, .auth_revoked);
    try testing.expectEqualStrings("codex:max-1", rec.correlation_id);
    // It is the routing key, not a secret, and not the raw account id.
    try testing.expect(std.mem.indexOf(u8, rec.correlation_id, rec.account_id_hint) == null);
}

test "graduation: next_action is flow-aware" {
    // Current providers are command-owned today: codex -> login-device, claude -> /login.
    try testing.expectEqual(FlowExecution.command_owned, flowExecutionFor("codex"));
    try testing.expectEqual(FlowExecution.command_owned, flowExecutionFor("claude"));
    try testing.expect(std.mem.indexOf(u8, nextActionFor(.auth_revoked, "codex"), "login-device <account-slot>") != null);
    try testing.expect(std.mem.indexOf(u8, nextActionFor(.auth_revoked, "claude"), "claude /login") != null);
    // Command-owned login remains an account-slot template because the Codex CLI
    // verb accepts slots. Engine-run approval uses correlation ids.
    try testing.expect(std.mem.indexOf(u8, nextActionFor(.auth_revoked, "codex"), "<correlation-id>") == null);
}

test "redaction witness holds by construction on every record" {
    inline for (.{ ActionClass.refresh_due, .auth_revoked, .capability_degraded, .unreauthable }) |a| {
        const rec = buildHandoff(testAccount("codex:max-x"), a);
        try testing.expect(rec.redaction.allRedacted());
        // No raw secret can appear: fields are masked hints / static strings.
        try testing.expect(std.mem.indexOf(u8, rec.email_hint, "***") != null);
    }
}

test "classify: same-account-as-live auth_revoked becomes unreauthable (max-2 == max-1)" {
    var acct = testAccount("codex:max-2");
    acct.same_account_as_live = true;
    const ev = Evidence{ .selectable = false, .action = .auth_revoked };
    try testing.expectEqual(ActionClass.unreauthable, classify(ev, acct));
}

test "classify: capability_degraded on a live route is never auth death (max-3)" {
    const acct = testAccount("codex:max-3");
    const ev = Evidence{ .selectable = false, .action = .capability_degraded };
    try testing.expectEqual(ActionClass.capability_degraded, classify(ev, acct));
}

test "refresh-only path: healthy refresh_due rotates the chain, never emits a login handoff" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    fake.default_ev = .{ .selectable = true, .action = .refresh_due };

    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-1");
    acct.state = .idle;

    // idle → warm (still healthy)
    var r = try orch.step(&acct);
    try testing.expectEqual(State.warm, r.to);

    // Force a due refresh by classifying as needs_reauth/refresh_due directly.
    acct.state = .needs_reauth;
    acct.action = .refresh_due;
    r = try orch.step(&acct);
    try testing.expectEqual(State.warm, r.to);
    try testing.expect(r.refreshed);
    try testing.expectEqual(@as(u32, 1), fake.refresh_calls);
    try testing.expectEqual(@as(u32, 0), fake.emit_calls); // NO login handoff
}

test "auth_revoked emits exactly one user-mediated handoff and waits (no login run)" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-2");
    acct.state = .needs_reauth;
    acct.action = .auth_revoked;

    const r = try orch.step(&acct);
    try testing.expectEqual(State.handoff_emitted, r.to);
    try testing.expect(r.emitted_handoff);
    try testing.expectEqual(@as(u32, 1), fake.emit_calls);
    try testing.expectEqual(@as(u32, 0), fake.refresh_calls); // never refreshed/logged in
    try testing.expect(!fake.last_record.?.is_escalation);
    try testing.expectEqual(MediationKind.device_login, fake.last_record.?.consent.mediation);
}

test "never-halt: unreauthable account emits a do-not-login escalation and parks" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-1");
    acct.same_account_as_live = true;
    acct.state = .needs_reauth;
    acct.action = .unreauthable;

    const r = try orch.step(&acct);
    try testing.expectEqual(State.escalated, r.to);
    try testing.expect(r.escalated and r.emitted_handoff);
    try testing.expect(fake.last_record.?.is_escalation);
    try testing.expectEqual(MediationKind.escalation, fake.last_record.?.consent.mediation);
    // The next-action string forbids login.
    try testing.expect(std.mem.indexOf(u8, fake.last_record.?.next_action, "DO NOT run login-device") != null);

    // Parked: stepping again is a no-op (never-halt sink).
    const calls_before = fake.emit_calls;
    const r2 = try orch.step(&acct);
    try testing.expectEqual(State.escalated, r2.to);
    try testing.expectEqual(calls_before, fake.emit_calls); // no re-emit, no spin
}

test "tickAll: a parked/dead account never blocks live ones (loop-level never-halt)" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    fake.default_ev = .{ .selectable = true, .action = .refresh_due };
    const orch = Orchestrator{ .seams = fake.seams() };

    var accounts = [_]Account{
        blk: {
            var a = testAccount("codex:max-1");
            a.state = .escalated; // un-reauthable, parked
            break :blk a;
        },
        blk: {
            var a = testAccount("codex:max-3");
            a.state = .idle; // live
            break :blk a;
        },
    };

    const rep = try orch.tickAll(&accounts);
    try testing.expectEqual(State.escalated, accounts[0].state); // still parked
    try testing.expectEqual(State.warm, accounts[1].state); // live one advanced
    try testing.expectEqual(@as(u32, 1), rep.parked_escalated);
    try testing.expectEqual(@as(u32, 1), rep.warm);
}

test "awaiting_user is bounded: an unanswered handoff retires to dead, never spins" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    // Evidence never becomes selectable.
    fake.default_ev = .{ .selectable = false, .action = .auth_revoked };
    const orch = Orchestrator{ .policy = .{ .max_polls = 2 }, .seams = fake.seams() };

    var acct = testAccount("codex:max-2");
    acct.state = .awaiting_user;
    acct.polls = 0;

    // poll 1: awaiting_user → evidence_refresh → (not selectable) → awaiting_user
    var r = try orch.step(&acct);
    try testing.expectEqual(State.evidence_refresh, r.to);
    r = try orch.step(&acct);
    try testing.expectEqual(State.awaiting_user, r.to);
    // poll 2 ...
    r = try orch.step(&acct);
    try testing.expectEqual(State.evidence_refresh, r.to);
    r = try orch.step(&acct);
    try testing.expectEqual(State.awaiting_user, r.to);
    // poll 3 exceeds max_polls=2 → dead (bounded, no infinite spin)
    r = try orch.step(&acct);
    try testing.expectEqual(State.dead, r.to);
}

test "evidence_refresh promotes to warm only when evidence says selectable" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-3");
    acct.state = .evidence_refresh;

    // First read: not selectable → stay awaiting.
    fake.default_ev = .{ .selectable = false, .action = .auth_revoked };
    var r = try orch.step(&acct);
    try testing.expectEqual(State.awaiting_user, r.to);

    // Now evidence says selectable → warm (contract: only then).
    acct.state = .evidence_refresh;
    fake.default_ev = .{ .selectable = true, .action = .refresh_due };
    r = try orch.step(&acct);
    try testing.expectEqual(State.warm, r.to);
}

test "evidence_refresh that reveals same-account signal escalates, not re-login" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-2");
    acct.same_account_as_live = true;
    acct.state = .evidence_refresh;
    fake.default_ev = .{ .selectable = false, .action = .auth_revoked };

    const r = try orch.step(&acct);
    try testing.expectEqual(State.needs_reauth, r.to);
    try testing.expectEqual(ActionClass.unreauthable, acct.action);
    // Next step emits the escalation, never a login handoff.
    const r2 = try orch.step(&acct);
    try testing.expectEqual(State.escalated, r2.to);
    try testing.expect(fake.last_record.?.is_escalation);
}

test "transient refresh OOM propagates without state corruption (retry next tick)" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    fake.refresh_oom = true;
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-1");
    acct.state = .needs_reauth;
    acct.action = .refresh_due;

    try testing.expectError(error.OutOfMemory, orch.step(&acct));
    // State unchanged → next tick retries; no spurious login/handoff.
    try testing.expectEqual(State.needs_reauth, acct.state);
    try testing.expectEqual(@as(u32, 0), fake.emit_calls);
}

test "refresh failure (not OOM) falls to evidence_refresh, never to a login handoff" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    fake.refresh_should_fail = true;
    const orch = Orchestrator{ .seams = fake.seams() };
    var acct = testAccount("codex:max-1");
    acct.state = .needs_reauth;
    acct.action = .refresh_due;

    const r = try orch.step(&acct);
    try testing.expectEqual(State.evidence_refresh, r.to);
    try testing.expectEqual(@as(u32, 0), fake.emit_calls); // refresh-only, no login emitted
}

test "bounded re-emission: past max_handoffs an account retires to dead, not a loop" {
    var fake = Fake.init(testing.allocator);
    defer fake.deinit();
    const orch = Orchestrator{ .policy = .{ .max_handoffs = 1 }, .seams = fake.seams() };
    var acct = testAccount("codex:max-2");
    acct.state = .needs_reauth;
    acct.action = .auth_revoked;
    acct.handoffs_emitted = 1; // already at cap

    const r = try orch.step(&acct);
    try testing.expectEqual(State.dead, r.to);
    try testing.expectEqual(@as(u32, 0), fake.emit_calls);
}
