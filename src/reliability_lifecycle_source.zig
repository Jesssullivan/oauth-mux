//! Read-only partial coverage from original source.disconnect authority.
//! No demand denominator, elapsed-time reconstruction or lifecycle success is
//! inferred from current source absence, deployment labels or passive queries.
const std = @import("std");
const mutation = @import("mutation_authority.zig");
const witness = @import("reliability_lifecycle_witness.zig");

pub const Summary = struct {
    schema_version: u8 = 1,
    scope: enum { actor_admission_to_committed_source_disconnect } = .actor_admission_to_committed_source_disconnect,
    window: enum { all_retained_no_time_window } = .all_retained_no_time_window,
    authority_available: bool = true,
    completed: u64 = 0,
    started: u64 = 0,
    indeterminate: u64 = 0,
    elapsed_measured: u64 = 0,
    elapsed_missing: u64 = 0,
    elapsed_total_ns: ?u64 = null,
    elapsed_min_ns: ?u64 = null,
    elapsed_max_ns: ?u64 = null,
    elapsed_total_saturated: bool = false,
    clock_anomaly: u64 = 0,
    duration_out_of_range: u64 = 0,
    verified_deployment_provenance: u64 = 0,
    unknown_deployment_provenance: u64 = 0,
    local_work: enum { unknown, partial_daemon_owned } = .unknown,
    local_work_measured: u64 = 0,
    daemon_request_elapsed_measured: u64 = 0,
    daemon_request_elapsed_missing: u64 = 0,
    daemon_request_elapsed_total_ns: ?u64 = null,
    daemon_request_elapsed_total_saturated: bool = false,
    daemon_request_scope: enum { control_handler_entry_to_original_commit } = .control_handler_entry_to_original_commit,
    user_provider_wait: enum { unknown } = .unknown,
    complete_user_demand_denominator: bool = false,
    complete_lifecycle_coverage: bool = false,
    user_end_to_end_measured: bool = false,
    application_provenance_measured: bool = false,
    achieved_slo: bool = false,
};

pub fn summarize(allocator: std.mem.Allocator, saved: mutation.Snapshot, current_revision: u64, authority_available: bool) !Summary {
    // A failed optional Store commit can leave an uncommitted in-memory fact.
    // Poisoned custody is unavailable, never optimistic retained evidence.
    if (!authority_available) return .{ .authority_available = false };
    if (saved.version != 1 or saved.count != saved.records.len or saved.count > saved.capacity or saved.capacity > mutation.max_records) return error.InvalidLifecycleSnapshot;
    var result: Summary = .{};
    var seen: std.StringHashMap(void) = .init(allocator);
    defer seen.deinit();
    for (saved.records) |*record| {
        if (record.id_len == 0 or record.id_len > mutation.max_id_bytes or record.method_len > mutation.max_method_bytes) return error.InvalidLifecycleSnapshot;
        const identity = try seen.getOrPut(record.id[0..record.id_len]);
        if (identity.found_existing) return error.InvalidLifecycleSnapshot;
        if (!std.mem.eql(u8, record.method[0..record.method_len], witness.method)) continue;
        _ = try witness.anchor(record.*);
        switch (record.state) {
            .started => result.started += 1,
            .indeterminate => result.indeterminate += 1,
            .completed => {
                try witness.requireTerminal(allocator, record.*);
                result.completed += 1;
                if (record.lifecycle_witness) |fact| {
                    try fact.validateForRecord(allocator, record.*, current_revision);
                    if (fact.elapsed.ns) |ns| {
                        result.elapsed_measured += 1;
                        result.elapsed_min_ns = if (result.elapsed_min_ns) |minimum| @min(minimum, ns) else ns;
                        result.elapsed_max_ns = if (result.elapsed_max_ns) |maximum| @max(maximum, ns) else ns;
                        if (result.elapsed_measured == 1) {
                            result.elapsed_total_ns = ns;
                        } else if (result.elapsed_total_ns) |prior| {
                            if (std.math.add(u64, prior, ns)) |sum| {
                                result.elapsed_total_ns = sum;
                            } else |_| {
                                result.elapsed_total_saturated = true;
                                result.elapsed_total_ns = null;
                            }
                        }
                    } else {
                        result.elapsed_missing += 1;
                        switch (fact.elapsed.missing.?) {
                            .clock_anomaly => result.clock_anomaly += 1,
                            .duration_out_of_range => result.duration_out_of_range += 1,
                            .unobserved, .original_process_lost => {},
                        }
                    }
                    if (fact.local_work.ns != null) {
                        result.local_work = .partial_daemon_owned;
                        result.local_work_measured += 1;
                    }
                    if (fact.daemon_request_elapsed.ns) |total| {
                        result.daemon_request_elapsed_measured += 1;
                        if (result.daemon_request_elapsed_measured == 1) {
                            result.daemon_request_elapsed_total_ns = total;
                        } else if (result.daemon_request_elapsed_total_ns) |prior| {
                            result.daemon_request_elapsed_total_ns = std.math.add(u64, prior, total) catch blk: {
                                result.daemon_request_elapsed_total_saturated = true;
                                break :blk null;
                            };
                        }
                    } else result.daemon_request_elapsed_missing += 1;
                    switch (fact.provenance.status) {
                        .unknown => result.unknown_deployment_provenance += 1,
                        .verified_deployment => result.verified_deployment_provenance += 1,
                    }
                } else {
                    result.elapsed_missing += 1;
                    result.daemon_request_elapsed_missing += 1;
                    result.unknown_deployment_provenance += 1;
                }
            },
        }
    }
    return result;
}
