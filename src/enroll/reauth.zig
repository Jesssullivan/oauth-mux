//! ReauthOrchestrator: COOKIELESS REAUTH ENGINE
//!
//! Coordinates one of four enrollment flows to obtain a token + provider-confirmed
//! identity, then runs an IDENTITY-CONFIRM gate, and only on confirm invokes a
//! writeStore callback.
//!
//! All side-effecting work is behind INJECTED SEAMS (function pointers bundled in
//! a small interface struct) so the engine is testable with NO network, NO real
//! browser, and NO real file writes. The module imports only `std` to stay
//! self-contained (no build_options / module graph).
//!
//! Flow dispatch is ENUM DISPATCH (a switch on a tagged enum), NOT a vtable.
//!
//! References: RFC 8628 (device), RFC 7636 (PKCE), RFC 8252 (loopback).

const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// The four enrollment flows. The orchestrator dispatches on this with a switch.
pub const Flow = enum {
    /// RFC 8628 device authorization grant. No PKCE, no loopback listener.
    device_code,
    /// RFC 8252 loopback redirect with PKCE (RFC 7636).
    redirect_loopback,
    /// Delegate to an upstream CLI (e.g. `codex login`) that owns the browser.
    command_owned,
    /// User pastes a personal access token / pre-minted credential.
    pat_paste,
};

/// The provider-confirmed identity + token material produced by a flow.
/// All slices are owned by the caller's allocator (the engine frees them on
/// reject / store-failure, or returns ownership on success).
pub const FlowOutcome = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_at: ?i64 = null,
    /// Provider-confirmed email (may be empty if the provider does not return one).
    email: []const u8,
    /// Provider-confirmed stable account identifier. This is the clone-dedup key.
    account_id: []const u8,
};

/// Final successful enrollment result returned to the caller. Same shape as
/// FlowOutcome; kept distinct so the public success type is named clearly.
pub const EnrollmentResult = FlowOutcome;

pub const IdentityConfirmDecision = enum { confirm, reject };

/// Why the confirm gate decided as it did. Carried out of the prompt seam so the
/// engine can map a rejection to a precise typed error without re-deriving it.
pub const ConfirmReason = enum {
    /// User (or policy) accepted the identity.
    accepted,
    /// User declined at the prompt.
    user_declined,
    /// account_id already enrolled for this provider (the max-4 clone lesson).
    already_enrolled,
    /// Provider identity did not match the intended provider:account.
    identity_mismatch,
};

pub const ConfirmResult = struct {
    decision: IdentityConfirmDecision,
    reason: ConfirmReason,
};

pub const EnrollError = error{
    FlowFailed,
    /// Confirm gate returned reject because the user declined.
    UserDeclined,
    /// Confirm gate returned reject because account_id is already enrolled.
    AlreadyEnrolled,
    /// Confirm gate returned reject because the identity did not match intent.
    IdentityMismatch,
    /// The confirm seam itself errored (could not prompt).
    ConfirmUnavailable,
    StoreWriteFailed,
    OutOfMemory,
};

// ─────────────────────────────────────────────────────────────────────────────
// SEAM INTERFACES (injected function pointers; no real I/O in the engine)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the selected flow. The concrete impl (device_code, loopback, ...) is bound
/// at wire-up time. It must return an allocator-owned FlowOutcome. `flow_ctx` is an
/// opaque pointer to flow-specific configuration (endpoints, client_id, ...).
pub const RunFlowFn = *const fn (
    allocator: std.mem.Allocator,
    flow: Flow,
    flow_ctx: *anyopaque,
) error{ FlowFailed, OutOfMemory }!FlowOutcome;

/// Identity-confirm gate. Given the provider-confirmed identity and the set of
/// account_ids already enrolled for this provider, decide confirm/reject.
///
/// REDACTION happens at this seam (the prompt/log impl), NOT inside the engine —
/// the engine passes the raw email/account_id through untouched.
///
/// `existing_account_ids` enables CLONE PREVENTION for `account add`: an impl can
/// compare the confirmed account_id against the list and return
/// `.already_enrolled` to block a duplicate enrollment.
pub const ConfirmIdentityFn = *const fn (
    allocator: std.mem.Allocator,
    confirm_ctx: *anyopaque,
    provider: []const u8,
    email: []const u8,
    account_id: []const u8,
    existing_account_ids: []const []const u8,
) error{ Unavailable, OutOfMemory }!ConfirmResult;

/// Persist the enrollment. Invoked ONLY after the confirm gate returns `.confirm`.
pub const WriteStoreFn = *const fn (
    allocator: std.mem.Allocator,
    store_ctx: *anyopaque,
    provider: []const u8,
    outcome: FlowOutcome,
) error{ WriteFailed, OutOfMemory }!void;

/// Spawn a child process and optionally capture stdout. Used by command_owned and
/// by the browser launcher when wired together. Injected so tests never spawn.
pub const ProcessSpawnFn = *const fn (
    allocator: std.mem.Allocator,
    spawn_ctx: *anyopaque,
    argv: []const []const u8,
) error{ SpawnFailed, OutOfMemory }!?[]const u8;

/// The bundle of injected seams. Each seam carries its own opaque context pointer
/// so callers can bind closures/state without globals.
pub const Seams = struct {
    run_flow: RunFlowFn,
    confirm_identity: ConfirmIdentityFn,
    write_store: WriteStoreFn,
    process_spawn: ProcessSpawnFn,

    flow_ctx: *anyopaque,
    confirm_ctx: *anyopaque,
    store_ctx: *anyopaque,
    spawn_ctx: *anyopaque,
};

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

pub const ReauthOrchestrator = struct {
    allocator: std.mem.Allocator,
    seams: Seams,
    /// Provider identity (e.g. "codex", "claude"). Borrowed; not owned.
    provider: []const u8,
    /// account_ids already enrolled for this provider. Borrowed; not owned.
    /// Empty for first-time enrollment; populated for `account add` clone checks.
    existing_account_ids: []const []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        seams: Seams,
        provider: []const u8,
        existing_account_ids: []const []const u8,
    ) ReauthOrchestrator {
        return .{
            .allocator = allocator,
            .seams = seams,
            .provider = provider,
            .existing_account_ids = existing_account_ids,
        };
    }

    /// Free an outcome's owned slices. Used on the reject / store-failure paths.
    fn freeOutcome(self: *const ReauthOrchestrator, outcome: FlowOutcome) void {
        self.allocator.free(outcome.access_token);
        if (outcome.refresh_token) |rt| self.allocator.free(rt);
        self.allocator.free(outcome.email);
        self.allocator.free(outcome.account_id);
    }

    /// Drive the full enrollment:
    ///   run flow -> obtain token + identity -> confirm gate -> writeStore (on confirm)
    ///
    /// On success returns the EnrollmentResult (caller owns its slices).
    /// On any rejection or failure, all token material is freed and a typed error
    /// is returned WITHOUT calling writeStore.
    pub fn begin(self: *const ReauthOrchestrator, flow: Flow) EnrollError!EnrollmentResult {
        // 1. Run the selected flow (enum dispatch lives inside the injected runner;
        //    the orchestrator itself stays flow-agnostic so the seam is a single
        //    point of substitution in tests).
        const outcome = self.seams.run_flow(
            self.allocator,
            flow,
            self.seams.flow_ctx,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.FlowFailed => return error.FlowFailed,
        };

        // 2. Identity-confirm gate. Existing account_ids are passed so the gate can
        //    block clones (the max-4 lesson).
        const confirmation = self.seams.confirm_identity(
            self.allocator,
            self.seams.confirm_ctx,
            self.provider,
            outcome.email,
            outcome.account_id,
            self.existing_account_ids,
        ) catch |err| switch (err) {
            error.OutOfMemory => {
                self.freeOutcome(outcome);
                return error.OutOfMemory;
            },
            error.Unavailable => {
                self.freeOutcome(outcome);
                return error.ConfirmUnavailable;
            },
        };

        if (confirmation.decision == .reject) {
            self.freeOutcome(outcome);
            return switch (confirmation.reason) {
                .already_enrolled => error.AlreadyEnrolled,
                .identity_mismatch => error.IdentityMismatch,
                // .accepted should never pair with a reject decision; treat as decline.
                .user_declined, .accepted => error.UserDeclined,
            };
        }

        // 3. Confirmed: persist. Only now does any store write happen.
        self.seams.write_store(
            self.allocator,
            self.seams.store_ctx,
            self.provider,
            outcome,
        ) catch |err| {
            self.freeOutcome(outcome);
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.WriteFailed => error.StoreWriteFailed,
            };
        };

        return outcome;
    }
};

/// Convenience: default clone-detection used by real confirm-gate impls. Returns
/// true if `account_id` is already present in `existing_account_ids`. Kept here
/// (not inside `begin`) so redaction/policy stays at the seam, but the dedup
/// comparison logic is shared and testable.
pub fn isAlreadyEnrolled(account_id: []const u8, existing_account_ids: []const []const u8) bool {
    for (existing_account_ids) |existing| {
        if (std.mem.eql(u8, existing, account_id)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS (no network, no browser, no real file writes)
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A test double that records what the orchestrator did to it. Each seam closure
/// recovers this struct from its opaque ctx pointer.
const Recorder = struct {
    /// What the flow seam should hand back.
    flow_email: []const u8 = "user@example.com",
    flow_account_id: []const u8 = "acct_NEW_001",
    /// Confirm seam behavior.
    confirm_decision: IdentityConfirmDecision = .confirm,
    confirm_reason: ConfirmReason = .accepted,
    /// Whether the confirm impl should run real clone detection against existing.
    confirm_uses_clone_check: bool = false,
    existing_for_check: []const []const u8 = &.{},

    // Observations:
    store_called: bool = false,
    stored_account_id: ?[]const u8 = null,
    confirm_saw_existing_len: usize = 0,

    fn runFlow(
        allocator: std.mem.Allocator,
        flow: Flow,
        flow_ctx: *anyopaque,
    ) error{ FlowFailed, OutOfMemory }!FlowOutcome {
        _ = flow;
        const self: *Recorder = @ptrCast(@alignCast(flow_ctx));
        return .{
            .access_token = try allocator.dupe(u8, "ACCESS_TOKEN_VALUE"),
            .refresh_token = try allocator.dupe(u8, "REFRESH_TOKEN_VALUE"),
            .email = try allocator.dupe(u8, self.flow_email),
            .account_id = try allocator.dupe(u8, self.flow_account_id),
        };
    }

    fn confirm(
        allocator: std.mem.Allocator,
        confirm_ctx: *anyopaque,
        provider: []const u8,
        email: []const u8,
        account_id: []const u8,
        existing_account_ids: []const []const u8,
    ) error{ Unavailable, OutOfMemory }!ConfirmResult {
        _ = allocator;
        _ = provider;
        _ = email;
        const self: *Recorder = @ptrCast(@alignCast(confirm_ctx));
        self.confirm_saw_existing_len = existing_account_ids.len;

        if (self.confirm_uses_clone_check and
            isAlreadyEnrolled(account_id, existing_account_ids))
        {
            return .{ .decision = .reject, .reason = .already_enrolled };
        }
        return .{ .decision = self.confirm_decision, .reason = self.confirm_reason };
    }

    fn writeStore(
        allocator: std.mem.Allocator,
        store_ctx: *anyopaque,
        provider: []const u8,
        outcome: FlowOutcome,
    ) error{ WriteFailed, OutOfMemory }!void {
        _ = provider;
        const self: *Recorder = @ptrCast(@alignCast(store_ctx));
        self.store_called = true;
        self.stored_account_id = try allocator.dupe(u8, outcome.account_id);
    }

    fn spawnNoop(
        allocator: std.mem.Allocator,
        spawn_ctx: *anyopaque,
        argv: []const []const u8,
    ) error{ SpawnFailed, OutOfMemory }!?[]const u8 {
        _ = allocator;
        _ = spawn_ctx;
        _ = argv;
        return null;
    }
};

fn seamsFor(rec: *Recorder) Seams {
    return .{
        .run_flow = Recorder.runFlow,
        .confirm_identity = Recorder.confirm,
        .write_store = Recorder.writeStore,
        .process_spawn = Recorder.spawnNoop,
        .flow_ctx = @ptrCast(rec),
        .confirm_ctx = @ptrCast(rec),
        .store_ctx = @ptrCast(rec),
        .spawn_ctx = @ptrCast(rec),
    };
}

test "identity-confirm: confirm -> writeStore called and result owned" {
    const allocator = testing.allocator;
    var rec = Recorder{ .confirm_decision = .confirm, .confirm_reason = .accepted };

    const orch = ReauthOrchestrator.init(allocator, seamsFor(&rec), "codex", &.{});
    const result = try orch.begin(.device_code);
    defer {
        allocator.free(result.access_token);
        if (result.refresh_token) |rt| allocator.free(rt);
        allocator.free(result.email);
        allocator.free(result.account_id);
    }
    defer if (rec.stored_account_id) |s| allocator.free(s);

    try testing.expect(rec.store_called);
    try testing.expectEqualStrings("acct_NEW_001", result.account_id);
    try testing.expectEqualStrings("user@example.com", result.email);
    try testing.expectEqualStrings("ACCESS_TOKEN_VALUE", result.access_token);
    try testing.expectEqualStrings("acct_NEW_001", rec.stored_account_id.?);
}

test "identity-confirm: reject (user declined) -> writeStore NOT called, typed error" {
    const allocator = testing.allocator;
    var rec = Recorder{ .confirm_decision = .reject, .confirm_reason = .user_declined };

    const orch = ReauthOrchestrator.init(allocator, seamsFor(&rec), "codex", &.{});
    const err = orch.begin(.device_code);

    try testing.expectError(error.UserDeclined, err);
    try testing.expect(!rec.store_called);
    // No leak: testing.allocator would fail teardown if the outcome wasn't freed.
}

test "account add clone: account_id matches existing -> flagged (AlreadyEnrolled), no write" {
    const allocator = testing.allocator;
    // The new flow returns an account_id that is ALREADY enrolled.
    const existing = [_][]const u8{ "acct_OLD_A", "acct_CLONE_TARGET", "acct_OLD_B" };
    var rec = Recorder{
        .flow_account_id = "acct_CLONE_TARGET",
        .confirm_uses_clone_check = true,
        .existing_for_check = &existing,
    };

    const orch = ReauthOrchestrator.init(allocator, seamsFor(&rec), "codex", &existing);
    const err = orch.begin(.device_code);

    try testing.expectError(error.AlreadyEnrolled, err);
    try testing.expect(!rec.store_called);
    // The gate must have actually received the existing set (clone-prevention path).
    try testing.expectEqual(@as(usize, 3), rec.confirm_saw_existing_len);
}

test "account add non-clone: distinct account_id passes clone check and writes" {
    const allocator = testing.allocator;
    const existing = [_][]const u8{ "acct_OLD_A", "acct_OLD_B" };
    var rec = Recorder{
        .flow_account_id = "acct_FRESH_999",
        .confirm_uses_clone_check = true,
        .existing_for_check = &existing,
    };

    const orch = ReauthOrchestrator.init(allocator, seamsFor(&rec), "codex", &existing);
    const result = try orch.begin(.device_code);
    defer {
        allocator.free(result.access_token);
        if (result.refresh_token) |rt| allocator.free(rt);
        allocator.free(result.email);
        allocator.free(result.account_id);
    }
    defer if (rec.stored_account_id) |s| allocator.free(s);

    try testing.expect(rec.store_called);
    try testing.expectEqualStrings("acct_FRESH_999", result.account_id);
}

test "identity-confirm: mismatch reason maps to IdentityMismatch error" {
    const allocator = testing.allocator;
    var rec = Recorder{ .confirm_decision = .reject, .confirm_reason = .identity_mismatch };

    const orch = ReauthOrchestrator.init(allocator, seamsFor(&rec), "codex", &.{});
    try testing.expectError(error.IdentityMismatch, orch.begin(.device_code));
    try testing.expect(!rec.store_called);
}

test "isAlreadyEnrolled helper" {
    const existing = [_][]const u8{ "a", "b", "c" };
    try testing.expect(isAlreadyEnrolled("b", &existing));
    try testing.expect(!isAlreadyEnrolled("z", &existing));
    try testing.expect(!isAlreadyEnrolled("a", &.{}));
}
