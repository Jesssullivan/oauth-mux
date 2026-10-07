//! Redacted projection of existing immutable mutation completion authority.
//! No new ledger, counters committed elsewhere, clock or removal capability.
//! Engine-owned cached facts are authoritative only for their stated predicate.
const std = @import("std");
const mutation = @import("mutation_authority.zig");

pub const Operation = enum { identity_forget, adapter_removal };
pub const Outcome = enum { completed, pending_safe_removal };
pub const Adapter = enum { git, codex };
pub const PendingReason = enum { native_requests_pending, native_custody_pending };
pub const Fact = struct {
    operation: Operation,
    outcome: Outcome,
    adapter: ?Adapter = null,
    pending_reason: ?PendingReason = null,
};
pub const AdapterCounts = struct { git: u64 = 0, codex: u64 = 0 };
pub const OperationCounts = struct { identity_forget: u64 = 0, adapter_removal: u64 = 0 };
pub const PendingCounts = struct { native_requests_pending: u64 = 0, native_custody_pending: u64 = 0 };
pub const Summary = struct {
    schema_version: u8 = 1,
    scope: enum { retained_mutation_authority_only } = .retained_mutation_authority_only,
    window: enum { all_retained_no_time_window } = .all_retained_no_time_window,
    identity_forget_completed: u64 = 0,
    adapter_removal_completed: AdapterCounts = .{},
    adapter_removal_pending_safe: PendingCounts = .{},
    unresolved_started: OperationCounts = .{},
    unresolved_indeterminate: OperationCounts = .{},
    retained_relevant_records: u64 = 0,
    duration: enum { unknown } = .unknown,
    complete_user_demand_denominator: bool = false,
    complete_lifecycle_coverage: bool = false,
    achieved_slo: bool = false,
    end_to_end_latency_measured: bool = false,
    retirement_supported: bool = false,
};

fn validateIdentity(record: mutation.Record) !void {
    if (record.id_len == 0 or record.id_len > mutation.max_id_bytes or record.method_len == 0 or record.method_len > mutation.max_method_bytes or record.result_len != record.result.len or record.result_len > mutation.max_result_bytes) return error.InvalidTerminalRemovalRecord;
    for (record.id[0..record.id_len]) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return error.InvalidTerminalRemovalRecord;
    for (record.method[0..record.method_len]) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '.') return error.InvalidTerminalRemovalRecord;
    for (record.id[record.id_len..]) |byte| if (byte != 0) return error.InvalidTerminalRemovalRecord;
    for (record.method[record.method_len..]) |byte| if (byte != 0) return error.InvalidTerminalRemovalRecord;
    if (record.state != .completed and record.result_len != 0) return error.InvalidTerminalRemovalRecord;
}
fn operation(record: mutation.Record) !?Operation {
    try validateIdentity(record);
    const name = record.method[0..record.method_len];
    if (std.mem.eql(u8, name, "account.forget")) {
        if (record.kind != .local_atomic) return error.InvalidTerminalRemovalRecord;
        return .identity_forget;
    }
    if (std.mem.eql(u8, name, "integrations.remove")) {
        if (record.kind != .external) return error.InvalidTerminalRemovalRecord;
        return .adapter_removal;
    }
    return null;
}
fn fields(value: std.json.Value, names: []const []const u8) !void {
    if (value != .object or value.object.count() != names.len) return error.InvalidTerminalRemovalResult;
    for (names) |name| if (!value.object.contains(name)) return error.InvalidTerminalRemovalResult;
}
fn boolean(value: std.json.Value, name: []const u8) !bool {
    const member = value.object.get(name) orelse return error.InvalidTerminalRemovalResult;
    if (member != .bool) return error.InvalidTerminalRemovalResult;
    return member.bool;
}
fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    const member = value.object.get(name) orelse return error.InvalidTerminalRemovalResult;
    if (member != .string) return error.InvalidTerminalRemovalResult;
    return member.string;
}

/// Returns typed predicates only; no cached path, ID, error body or label escapes.
/// Caller supplies an authenticated existing mutation record, not arbitrary RPC
/// JSON. A terminal RPC reply is not necessarily completed user removal.
pub fn classifyCompleted(allocator: std.mem.Allocator, record: mutation.Record) !Fact {
    const selected = (try operation(record)) orelse return error.UnsupportedTerminalRemovalMethod;
    if (record.state != .completed or record.result.len == 0) return error.NonterminalRemovalRecord;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record.result, .{ .duplicate_field_behavior = .@"error", .max_value_len = mutation.max_result_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidTerminalRemovalResult,
    };
    defer parsed.deinit();
    const value = parsed.value;
    switch (selected) {
        .identity_forget => {
            try fields(value, &.{"forgotten"});
            if (!try boolean(value, "forgotten")) return error.InvalidTerminalRemovalResult;
            return .{ .operation = selected, .outcome = .completed };
        },
        .adapter_removal => {
            if (value != .object) return error.InvalidTerminalRemovalResult;
            const removed = try boolean(value, "removed");
            if (removed) {
                // Current setup.RemoveResult, including its existing private
                // path field. Validate shape but never copy that path to Fact.
                try fields(value, &.{ "removed", "adapter", "config_path", "changed" });
                _ = try string(value, "config_path");
                _ = try boolean(value, "changed");
                const adapter = std.meta.stringToEnum(Adapter, try string(value, "adapter")) orelse return error.InvalidTerminalRemovalResult;
                return .{ .operation = selected, .outcome = .completed, .adapter = adapter };
            }
            // Current completeNativeRemovalPending result; no generic failure
            // reply or an absent acknowledgment can claim this safe predicate.
            try fields(value, &.{ "removed", "adapter", "installed", "pending_safe_detach", "reason" });
            if (!std.mem.eql(u8, try string(value, "adapter"), "codex") or !try boolean(value, "installed") or !try boolean(value, "pending_safe_detach")) return error.InvalidTerminalRemovalResult;
            const reason = try string(value, "reason");
            const pending: PendingReason = if (std.mem.eql(u8, reason, "NativeRequestsPending")) .native_requests_pending else if (std.mem.eql(u8, reason, "NativeCustodyPending")) .native_custody_pending else return error.InvalidTerminalRemovalResult;
            return .{ .operation = selected, .outcome = .pending_safe_removal, .adapter = .codex, .pending_reason = pending };
        },
    }
}

/// The retained authority set is not all user demand and has no time window.
/// Replay yields the same immutable row; duplicate authority IDs fail closed.
pub fn summarize(allocator: std.mem.Allocator, saved: mutation.Snapshot) !Summary {
    if (saved.version != 1 or saved.capacity == 0 or saved.capacity > mutation.max_records or saved.count > saved.capacity or saved.count != saved.records.len) return error.InvalidTerminalRemovalSnapshot;
    var result: Summary = .{};
    var identities: std.StringHashMap(void) = .init(allocator);
    defer identities.deinit();
    for (saved.records) |*record| {
        const selected = try operation(record.*);
        // Borrow from the stable snapshot row, never a by-value loop copy.
        // The map is ephemeral and bounded by the validated authority capacity.
        const entry = try identities.getOrPut(record.id[0..record.id_len]);
        if (entry.found_existing) return error.InvalidTerminalRemovalSnapshot;
        const relevant = selected orelse continue;
        result.retained_relevant_records += 1;
        switch (record.state) {
            .started => switch (relevant) {
                .identity_forget => result.unresolved_started.identity_forget += 1,
                .adapter_removal => result.unresolved_started.adapter_removal += 1,
            },
            .indeterminate => switch (relevant) {
                .identity_forget => result.unresolved_indeterminate.identity_forget += 1,
                .adapter_removal => result.unresolved_indeterminate.adapter_removal += 1,
            },
            .completed => {
                const fact = try classifyCompleted(allocator, record.*);
                switch (fact.outcome) {
                    .completed => switch (fact.operation) {
                        .identity_forget => result.identity_forget_completed += 1,
                        .adapter_removal => switch (fact.adapter.?) {
                            .git => result.adapter_removal_completed.git += 1,
                            .codex => result.adapter_removal_completed.codex += 1,
                        },
                    },
                    .pending_safe_removal => switch (fact.pending_reason.?) {
                        .native_requests_pending => result.adapter_removal_pending_safe.native_requests_pending += 1,
                        .native_custody_pending => result.adapter_removal_pending_safe.native_custody_pending += 1,
                    },
                }
            },
        }
    }
    return result;
}
