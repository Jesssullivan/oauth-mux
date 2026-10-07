//! Read-only projection of original adapter configuration completion authority.
//! This is neither current installed state nor artifact/service activation.
const std = @import("std");
const mutation = @import("mutation_authority.zig");

pub const method = "integrations.install";
pub const Adapter = enum { git, codex };
pub const Fact = struct { adapter: Adapter, changed: bool };
pub const AdapterCounts = struct { git: u64 = 0, codex: u64 = 0 };
pub const Summary = struct {
    schema_version: u8 = 1,
    scope: enum { retained_adapter_configuration_mutation_authority_only } = .retained_adapter_configuration_mutation_authority_only,
    window: enum { all_retained_no_time_window } = .all_retained_no_time_window,
    setup_completed_changed: AdapterCounts = .{},
    setup_completed_unchanged: AdapterCounts = .{},
    // Adapter is unavailable in unresolved cached authority; do not infer it
    // from current configuration or mutable caller parameters.
    unresolved_started: u64 = 0,
    unresolved_indeterminate: u64 = 0,
    retained_relevant_records: u64 = 0,
    duration: enum { unknown } = .unknown,
    complete_user_demand_denominator: bool = false,
    complete_lifecycle_coverage: bool = false,
    installation_success_measured: bool = false,
    activation_measured: bool = false,
    achieved_slo: bool = false,
    end_to_end_latency_measured: bool = false,
    retirement_supported: bool = false,
};

fn relevant(record: mutation.Record) !bool {
    if (record.id_len == 0 or record.id_len > mutation.max_id_bytes or record.method_len == 0 or record.method_len > mutation.max_method_bytes or record.result_len != record.result.len or record.result_len > mutation.max_result_bytes) return error.InvalidTerminalAdapterSetupRecord;
    for (record.id[0..record.id_len]) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return error.InvalidTerminalAdapterSetupRecord;
    for (record.method[0..record.method_len]) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '.') return error.InvalidTerminalAdapterSetupRecord;
    for (record.id[record.id_len..]) |byte| if (byte != 0) return error.InvalidTerminalAdapterSetupRecord;
    for (record.method[record.method_len..]) |byte| if (byte != 0) return error.InvalidTerminalAdapterSetupRecord;
    if (record.state != .completed and record.result_len != 0) return error.InvalidTerminalAdapterSetupRecord;
    if (!std.mem.eql(u8, record.method[0..record.method_len], method)) return false;
    if (record.kind != .external) return error.InvalidTerminalAdapterSetupRecord;
    return true;
}

/// Caller supplies a retained authenticated mutation record, not an arbitrary
/// reply. Strictly recognize the current setup.InstallResult; redact its path.
pub fn classifyCompleted(allocator: std.mem.Allocator, record: mutation.Record) !Fact {
    if (!try relevant(record)) return error.UnsupportedTerminalAdapterSetupMethod;
    if (record.state != .completed or record.result.len == 0) return error.NonterminalAdapterSetupRecord;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record.result, .{ .duplicate_field_behavior = .@"error", .max_value_len = mutation.max_result_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidTerminalAdapterSetupResult,
    };
    defer parsed.deinit();
    const value = parsed.value;
    if (value != .object or value.object.count() != 4) return error.InvalidTerminalAdapterSetupResult;
    const installed = value.object.get("installed") orelse return error.InvalidTerminalAdapterSetupResult;
    const adapter = value.object.get("adapter") orelse return error.InvalidTerminalAdapterSetupResult;
    const config_path = value.object.get("config_path") orelse return error.InvalidTerminalAdapterSetupResult;
    const changed = value.object.get("changed") orelse return error.InvalidTerminalAdapterSetupResult;
    if (installed != .bool or !installed.bool or adapter != .string or config_path != .string or changed != .bool) return error.InvalidTerminalAdapterSetupResult;
    return .{ .adapter = std.meta.stringToEnum(Adapter, adapter.string) orelse return error.InvalidTerminalAdapterSetupResult, .changed = changed.bool };
}

/// Original IDs survive replay and restart. Historical configuration completion
/// remains counted even after later removal; it is not current readiness.
pub fn summarize(allocator: std.mem.Allocator, saved: mutation.Snapshot) !Summary {
    if (saved.version != 1 or saved.capacity == 0 or saved.capacity > mutation.max_records or saved.count > saved.capacity or saved.count != saved.records.len) return error.InvalidTerminalAdapterSetupSnapshot;
    var result: Summary = .{};
    var identities: std.StringHashMap(void) = .init(allocator);
    defer identities.deinit();
    for (saved.records) |*record| {
        const selected = try relevant(record.*);
        // Borrow stable snapshot rows, never slices of by-value loop copies.
        const identity = try identities.getOrPut(record.id[0..record.id_len]);
        if (identity.found_existing) return error.InvalidTerminalAdapterSetupSnapshot;
        if (!selected) continue;
        result.retained_relevant_records += 1;
        switch (record.state) {
            .started => result.unresolved_started += 1,
            .indeterminate => result.unresolved_indeterminate += 1,
            .completed => {
                const fact = try classifyCompleted(allocator, record.*);
                const counts = if (fact.changed) &result.setup_completed_changed else &result.setup_completed_unchanged;
                switch (fact.adapter) {
                    .git => counts.git += 1,
                    .codex => counts.codex += 1,
                }
            },
        }
    }
    return result;
}
