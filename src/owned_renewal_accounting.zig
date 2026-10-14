//! Fixed-size aggregate of authenticated owned-pair renewal transitions.
//! The actor stages it in the SAME fenced SQLite snapshot transaction. This
//! module never grants issuance, reconstructs an operation or owns credentials.
const std = @import("std");
const domain = @import("domain.zig");
const admission = @import("snapshot_admission.zig");

pub const maximum_snapshot_bytes = 2048;
pub const Outcome = enum { committed_successor, safe_refusal, completion_unknown };
pub const Cause = enum {
    verified_successor_commit,
    transport_admission_refused,
    token_transport_failed,
    token_reply_unusable,
    key_transport_failed,
    verification_failed,
    successor_commit_failed,
    authority_check_failed,
    interrupted_or_stranded,
    source_disconnected,
    consent_withdrawn,
    account_forgotten,
};
pub const cause_count = @typeInfo(Cause).@"enum".field_names.len;
pub const cause_labels: [cause_count]Cause = .{
    .verified_successor_commit,
    .transport_admission_refused,
    .token_transport_failed,
    .token_reply_unusable,
    .key_transport_failed,
    .verification_failed,
    .successor_commit_failed,
    .authority_check_failed,
    .interrupted_or_stranded,
    .source_disconnected,
    .consent_withdrawn,
    .account_forgotten,
};

/// One fixed aggregate window per authenticated Store, since actual optional
/// activation. No rolling sample, slot exhaustion, eviction or per-ID history.
/// The original SQL unique operation and retained pair state/generation fence
/// each admission and terminal transition; this value is never effect authority.
pub const Snapshot = struct {
    schema_version: u32 = 1,
    activated_unix: i64,
    admitted: u64 = 0,
    unresolved: u64 = 0,
    committed_successors: u64 = 0,
    safe_refusals: u64 = 0,
    completion_unknown: u64 = 0,
    causes: [cause_count]u64 = @splat(0),
    counter_saturated: bool = false,

    pub fn init(now: i64) !Snapshot {
        if (now <= 0) return error.InvalidRenewalAccounting;
        return .{ .activated_unix = now };
    }
    fn increment(self: *Snapshot, value: *u64) void {
        if (value.* == std.math.maxInt(u64)) self.counter_saturated = true else value.* += 1;
    }
    /// Called only while staging a new unique, authenticated SQL issuance.
    /// A failed transaction restores the previously committed aggregate.
    pub fn admit(self: *Snapshot) !void {
        try validate(self.*);
        if (self.unresolved >= domain.max_records) return error.InvalidRenewalAccounting;
        self.unresolved += 1;
        self.increment(&self.admitted);
    }
    /// Called only for the exact still-issued pair's one terminal transition.
    /// Idempotence belongs to the operation/state fence, not a counter guess.
    pub fn terminal(self: *Snapshot, outcome: Outcome, cause: Cause) !void {
        try validate(self.*);
        if (self.unresolved == 0) return error.InvalidRenewalAccounting;
        switch (outcome) {
            .committed_successor => if (cause != .verified_successor_commit) return error.InvalidRenewalAccounting,
            .safe_refusal => if (cause != .transport_admission_refused) return error.InvalidRenewalAccounting,
            .completion_unknown => if (cause == .verified_successor_commit or cause == .transport_admission_refused) return error.InvalidRenewalAccounting,
        }
        self.unresolved -= 1;
        switch (outcome) {
            .committed_successor => self.increment(&self.committed_successors),
            .safe_refusal => self.increment(&self.safe_refusals),
            .completion_unknown => self.increment(&self.completion_unknown),
        }
        self.increment(&self.causes[@intFromEnum(cause)]);
    }
};

pub fn validate(saved: Snapshot) !void {
    if (saved.schema_version != 1 or saved.activated_unix <= 0 or saved.unresolved > domain.max_records) return error.InvalidRenewalAccounting;
    if (saved.counter_saturated and saved.admitted != std.math.maxInt(u64)) return error.InvalidRenewalAccounting;
    if (!saved.counter_saturated) {
        const resolved = @as(u128, saved.committed_successors) + saved.safe_refusals + saved.completion_unknown;
        if (@as(u128, saved.admitted) != resolved + saved.unresolved) return error.InvalidRenewalAccounting;
        var cause_total: u128 = 0;
        for (saved.causes) |count| cause_total += count;
        if (cause_total != resolved or saved.causes[@intFromEnum(Cause.verified_successor_commit)] != saved.committed_successors or
            saved.causes[@intFromEnum(Cause.transport_admission_refused)] != saved.safe_refusals) return error.InvalidRenewalAccounting;
    }
    _ = try admission.countJson(saved, maximum_snapshot_bytes);
}
pub fn read(allocator: std.mem.Allocator, raw: std.json.Value) !Snapshot {
    if (raw != .object) return error.InvalidRenewalAccounting;
    inline for (@typeInfo(Snapshot).@"struct".field_names) |name| {
        if (!raw.object.contains(name)) return error.InvalidRenewalAccounting;
    }
    const parsed = try std.json.parseFromValue(Snapshot, allocator, raw, .{});
    defer parsed.deinit();
    try validate(parsed.value);
    return parsed.value;
}

pub const Summary = struct {
    schema_version: u32 = 1,
    scope: enum { authenticated_owned_pair_renewal_admissions } = .authenticated_owned_pair_renewal_admissions,
    window: enum { since_actual_activation_in_this_store_no_reset } = .since_actual_activation_in_this_store_no_reset,
    authority_available: bool = false,
    collection_active: bool = false,
    activation_capacity_unavailable: bool = false,
    // Bounded last-operation diagnostics, separate from aggregate admissions.
    retained_last_capacity_exclusions: u64 = 0,
    complete_capacity_loss_history: bool = false,
    pre_activation_attempt_history_measured: bool = false,
    activated_unix: ?i64 = null,
    admitted: ?u64 = null,
    unresolved: ?u64 = null,
    committed_successors: ?u64 = null,
    safe_refusals: ?u64 = null,
    completion_unknown: ?u64 = null,
    cause_keys: [cause_count]Cause = cause_labels,
    causes: ?[cause_count]u64 = null,
    counter_saturated: bool = false,
    aggregate_counts_exact: bool = false,
    successful_user_journeys_measured: bool = false,
    complete_renewal_opportunity_denominator: bool = false,
    pre_issuance_refusals_measured: bool = false,
    local_elapsed_ns: ?u64 = null,
    user_end_to_end_elapsed_ns: ?u64 = null,
    user_provider_wait_ns: ?u64 = null,
    deployment_provenance_measured: bool = false,
    before_authority_expiry_measured: bool = false,
    achieved_slo: bool = false,
};
pub fn summarize(saved: ?Snapshot, authority: bool, activation_capacity_unavailable: bool) !Summary {
    // Prepared counters after a failed/poisoned commit are not durable facts.
    if (!authority) return .{};
    var result: Summary = .{ .authority_available = true, .activation_capacity_unavailable = activation_capacity_unavailable };
    if (saved) |value| {
        try validate(value);
        result.collection_active = true;
        result.activated_unix = value.activated_unix;
        result.admitted = value.admitted;
        result.unresolved = value.unresolved;
        result.committed_successors = value.committed_successors;
        result.safe_refusals = value.safe_refusals;
        result.completion_unknown = value.completion_unknown;
        result.causes = value.causes;
        result.counter_saturated = value.counter_saturated;
        result.aggregate_counts_exact = !value.counter_saturated;
    }
    return result;
}

test "paired renewal aggregate continues beyond sixty four and partitions admitted outcomes without user success" {
    for (cause_labels, 0..) |cause, index| try std.testing.expectEqual(index, @intFromEnum(cause));
    var value = try Snapshot.init(100);
    for (0..300) |index| {
        try value.admit();
        const outcome: Outcome = switch (index % 3) {
            0 => .committed_successor,
            1 => .safe_refusal,
            else => .completion_unknown,
        };
        const cause: Cause = switch (outcome) {
            .committed_successor => .verified_successor_commit,
            .safe_refusal => .transport_admission_refused,
            .completion_unknown => .token_transport_failed,
        };
        try value.terminal(outcome, cause);
    }
    try validate(value);
    const observed = try summarize(value, true, false);
    try std.testing.expectEqual(@as(?u64, 300), observed.admitted);
    try std.testing.expectEqual(@as(?u64, 100), observed.committed_successors);
    try std.testing.expectEqual(@as(?u64, 100), observed.safe_refusals);
    try std.testing.expectEqual(@as(?u64, 100), observed.completion_unknown);
    try std.testing.expectEqual(@as(?u64, 0), observed.unresolved);
    try std.testing.expect(observed.aggregate_counts_exact);
    try std.testing.expect(!observed.successful_user_journeys_measured and !observed.complete_renewal_opportunity_denominator);
    try std.testing.expect(observed.local_elapsed_ns == null and observed.user_end_to_end_elapsed_ns == null and observed.user_provider_wait_ns == null);
}

test "paired renewal aggregate rejects inconsistent partitions cause promotion and terminal underflow" {
    var value = try Snapshot.init(100);
    try std.testing.expectError(error.InvalidRenewalAccounting, value.terminal(.committed_successor, .verified_successor_commit));
    try value.admit();
    try std.testing.expectError(error.InvalidRenewalAccounting, value.terminal(.safe_refusal, .token_transport_failed));
    try std.testing.expectEqual(@as(u64, 1), value.unresolved);
    var corrupt = value;
    corrupt.committed_successors = 1;
    try std.testing.expectError(error.InvalidRenewalAccounting, validate(corrupt));
    try value.terminal(.completion_unknown, .interrupted_or_stranded);
    const hidden = try summarize(value, false, false);
    try std.testing.expect(!hidden.authority_available and hidden.admitted == null and hidden.causes == null);
    const legacy = try summarize(null, true, true);
    try std.testing.expect(!legacy.collection_active and legacy.admitted == null and legacy.activation_capacity_unavailable);
}

test "paired renewal aggregate numeric saturation preserves transitions and reports inexact lower bounds" {
    var value = try Snapshot.init(100);
    value.admitted = std.math.maxInt(u64);
    value.committed_successors = std.math.maxInt(u64);
    value.causes[@intFromEnum(Cause.verified_successor_commit)] = std.math.maxInt(u64);
    try validate(value);
    try value.admit();
    try value.terminal(.committed_successor, .verified_successor_commit);
    try validate(value);
    const observed = try summarize(value, true, false);
    try std.testing.expect(observed.counter_saturated and !observed.aggregate_counts_exact);
    try std.testing.expectEqual(@as(?u64, 0), observed.unresolved);
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), observed.admitted);
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), observed.committed_successors);
    try std.testing.expect(!observed.achieved_slo);
    // Every fixed cause/counter at maximum still fits the declared promise.
    value.safe_refusals = std.math.maxInt(u64);
    value.completion_unknown = std.math.maxInt(u64);
    value.causes = @splat(std.math.maxInt(u64));
    value.activated_unix = std.math.maxInt(i64);
    try validate(value);
}
