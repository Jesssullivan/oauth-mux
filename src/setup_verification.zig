//! Explicit setup verification facts cached in existing mutation authority.
//! No parallel ledger, installation success assertion or passive-poll samples.
const std = @import("std");
const onboarding = @import("onboarding.zig");
const mutation = @import("mutation_authority.zig");
const reliability = @import("reliability.zig");

pub const method = "setup.refresh";
pub const maximum_result_bytes = mutation.max_result_bytes;
pub const phase_order = [_]onboarding.Phase{ .artifact, .service, .vault, .source, .identity, .grant, .native };
pub const PhaseOutcome = enum { verified_ready, action_required, unknown };
pub const Outcome = enum { verification_completed, safe_refusal };
pub const Refusal = enum { busy, installation_selection_required, collection_timed_out };
pub const PhaseResult = struct { outcome: PhaseOutcome = .unknown, reason: onboarding.Reason = .observation_unknown };
pub const Result = struct {
    schema_version: u8 = 1,
    operation_id: []const u8,
    generation: u64,
    observed_at: i64,
    outcome: Outcome,
    refusal: ?Refusal = null,
    // Names are implicit in the fixed schema-v1 phase_order, avoiding repeated
    // phase labels in the existing 1024-byte terminal-result reservation.
    phases: [7]PhaseResult = @splat(.{}),
    elapsed_ns: ?u64 = null,
    timing_scope: enum { admission_to_terminal_before_commit_process_local } = .admission_to_terminal_before_commit_process_local,
};

pub fn classify(reason: onboarding.Reason) PhaseOutcome {
    return switch (reason) {
        .ready => .verified_ready,
        .observation_unknown, .observation_stale, .evidence_unobserved, .synthetic_only, .native_evidence_missing, .channel_unknown => .unknown,
        .channel_mismatch, .missing, .pending, .incompatible, .vault_locked, .vault_key_lost, .authority_expired, .browser_required, .native_unsupported => .action_required,
    };
}
pub fn makeCompleted(id: []const u8, generation: u64, observed_at: i64, readiness: onboarding.Readiness, elapsed_ns: ?u64) !Result {
    var result: Result = .{ .operation_id = id, .generation = generation, .observed_at = observed_at, .outcome = .verification_completed, .elapsed_ns = elapsed_ns };
    for (readiness.findings, phase_order, 0..) |finding, phase, index| {
        if (finding.phase != phase) return error.InvalidSetupVerificationResult;
        result.phases[index] = .{ .reason = finding.reason, .outcome = classify(finding.reason) };
    }
    try validate(result);
    return result;
}
pub fn makeRefusal(id: []const u8, generation: u64, observed_at: i64, refusal: Refusal) !Result {
    const result: Result = .{ .operation_id = id, .generation = generation, .observed_at = observed_at, .outcome = .safe_refusal, .refusal = refusal };
    try validate(result);
    return result;
}
/// A real daemon admission-to-terminal observation, never a user/browser start.
pub fn makeTimedRefusal(id: []const u8, generation: u64, observed_at: i64, refusal: Refusal, elapsed_ns: ?u64) !Result {
    var result = try makeRefusal(id, generation, observed_at, refusal);
    result.schema_version = 2;
    result.elapsed_ns = elapsed_ns;
    try validate(result);
    return result;
}
pub fn validate(result: Result) !void {
    if ((result.schema_version != 1 and result.schema_version != 2) or !validId(result.operation_id) or result.observed_at < 0) return error.InvalidSetupVerificationResult;
    switch (result.outcome) {
        .verification_completed => {
            if (result.refusal != null or result.generation == 0) return error.InvalidSetupVerificationResult;
            for (result.phases) |phase| if (phase.outcome != classify(phase.reason)) return error.InvalidSetupVerificationResult;
        },
        .safe_refusal => {
            if (result.refusal == null or (result.schema_version == 1 and result.elapsed_ns != null)) return error.InvalidSetupVerificationResult;
            for (result.phases) |phase| if (phase.outcome != .unknown or phase.reason != .observation_unknown) return error.InvalidSetupVerificationResult;
        },
    }
}
fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > mutation.max_id_bytes) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return false;
    return true;
}
pub fn serialize(allocator: std.mem.Allocator, result: Result) ![]u8 {
    try validate(result);
    const bytes = try std.json.Stringify.valueAlloc(allocator, result, .{});
    if (bytes.len > maximum_result_bytes) {
        allocator.free(bytes);
        return error.ResultTooLarge;
    }
    return bytes;
}
fn validateRecordIdentity(record: mutation.Record) !void {
    if (record.kind != .external or record.id_len == 0 or record.id_len > mutation.max_id_bytes or record.method_len > mutation.max_method_bytes or !validId(record.id[0..record.id_len]) or !std.mem.eql(u8, record.method[0..record.method_len], method)) return error.InvalidSetupVerificationRecord;
    for (record.id[record.id_len..]) |byte| if (byte != 0) return error.InvalidSetupVerificationRecord;
    for (record.method[record.method_len..]) |byte| if (byte != 0) return error.InvalidSetupVerificationRecord;
}
pub fn parseCompletedRecord(allocator: std.mem.Allocator, record: mutation.Record) !std.json.Parsed(Result) {
    try validateRecordIdentity(record);
    if (record.state != .completed or record.result_len != record.result.len or record.result.len == 0 or record.result.len > maximum_result_bytes) return error.InvalidSetupVerificationRecord;
    // Result defaults are convenient constructors, never a migration policy.
    // Cached facts must explicitly contain every schema field and phase fact.
    const shape = std.json.parseFromSlice(std.json.Value, allocator, record.result, .{ .duplicate_field_behavior = .@"error", .max_value_len = maximum_result_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidSetupVerificationRecord,
    };
    defer shape.deinit();
    if (shape.value != .object or shape.value.object.count() != 9) return error.InvalidSetupVerificationRecord;
    inline for (.{ "schema_version", "operation_id", "generation", "observed_at", "outcome", "refusal", "phases", "elapsed_ns", "timing_scope" }) |field| if (!shape.value.object.contains(field)) return error.InvalidSetupVerificationRecord;
    const phases = shape.value.object.get("phases").?;
    if (phases != .array or phases.array.items.len != phase_order.len) return error.InvalidSetupVerificationRecord;
    for (phases.array.items) |phase| if (phase != .object or phase.object.count() != 2 or !phase.object.contains("reason") or !phase.object.contains("outcome")) return error.InvalidSetupVerificationRecord;
    const parsed = std.json.parseFromSlice(Result, allocator, record.result, .{ .duplicate_field_behavior = .@"error", .max_value_len = maximum_result_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidSetupVerificationRecord,
    };
    errdefer parsed.deinit();
    try validate(parsed.value);
    if (!std.mem.eql(u8, parsed.value.operation_id, record.id[0..record.id_len])) return error.InvalidSetupVerificationRecord;
    return parsed;
}

pub const PhaseSummary = struct { verified_ready: u64 = 0, action_required: u64 = 0, unknown: u64 = 0 };
pub const JointReadiness = struct {
    /// Exclusive attempt classifications: a known required action takes
    /// precedence over an unknown phase, then all seven must be verified ready.
    all_ready: u64 = 0,
    action_required: u64 = 0,
    unknown: u64 = 0,
    /// Overlaps the exclusive classes above, preserving uncertainty even when
    /// another phase already establishes that an action is required.
    unknown_phase_present: u64 = 0,
};
pub const Summary = struct {
    schema_version: u8 = 1,
    scope: enum { explicit_setup_verification_not_installation_success } = .explicit_setup_verification_not_installation_success,
    window_start_utc_s: i64,
    phase_names: @TypeOf(phase_order) = phase_order,
    phases: [7]PhaseSummary = @splat(.{}),
    joint_readiness: JointReadiness = .{},
    verification_completed: u64 = 0,
    safe_refusals: u64 = 0,
    busy_refusals: u64 = 0,
    installation_selection_required_refusals: u64 = 0,
    collection_timed_out_refusals: u64 = 0,
    unresolved_started: u64 = 0,
    unresolved_indeterminate: u64 = 0,
    old_window_records: u64 = 0,
    future_clock_records: u64 = 0,
    completed_timing: reliability.LifecycleTiming = .{},
    refusal_timing: reliability.LifecycleTiming = .{},
    achieved_slo: bool = false,
    complete_user_demand_denominator: bool = false,
    installation_success_measured: bool = false,
    end_to_end_latency_measured: bool = false,
    legacy_empty_refresh_measured: bool = false,
    ids_retired: bool = false,
};
/// Facts come only from immutable completed setup.refresh mutation results.
/// Started/indeterminate records are visible uncertainty, not crash successes.
/// UTC placement determines the window; it never manufactures a duration.
pub fn summarize(allocator: std.mem.Allocator, saved: mutation.Snapshot, now_s: i64) !Summary {
    if (now_s < 0 or saved.version != 1 or saved.records.len > mutation.max_records or saved.records.len != saved.count or saved.capacity == 0 or saved.count > saved.capacity or saved.capacity > mutation.max_records) return error.InvalidSetupVerificationSnapshot;
    const start = @max(0, (@divFloor(now_s, 86_400) - 27) * 86_400);
    var result: Summary = .{ .window_start_utc_s = start };
    for (saved.records, 0..) |record, index| {
        if (record.id_len == 0 or record.id_len > mutation.max_id_bytes or record.method_len > mutation.max_method_bytes) return error.InvalidSetupVerificationRecord;
        for (saved.records[0..index]) |previous| if (std.mem.eql(u8, previous.id[0..previous.id_len], record.id[0..record.id_len])) return error.InvalidSetupVerificationSnapshot;
        if (!std.mem.eql(u8, record.method[0..record.method_len], method)) continue;
        try validateRecordIdentity(record);
        switch (record.state) {
            .started => {
                result.unresolved_started += 1;
                continue;
            },
            .indeterminate => {
                result.unresolved_indeterminate += 1;
                continue;
            },
            .completed => {},
        }
        const parsed = try parseCompletedRecord(allocator, record);
        defer parsed.deinit();
        const fact = parsed.value;
        if (fact.observed_at > now_s) {
            result.future_clock_records += 1;
            continue;
        }
        if (fact.observed_at < start) {
            result.old_window_records += 1;
            continue;
        }
        switch (fact.outcome) {
            .verification_completed => {
                result.verification_completed += 1;
                var action_required = false;
                var unknown = false;
                for (&result.phases, fact.phases) |*phase, observed| switch (observed.outcome) {
                    .verified_ready => phase.verified_ready += 1,
                    .action_required => {
                        phase.action_required += 1;
                        action_required = true;
                    },
                    .unknown => {
                        phase.unknown += 1;
                        unknown = true;
                    },
                };
                if (unknown) result.joint_readiness.unknown_phase_present += 1;
                if (action_required) result.joint_readiness.action_required += 1 else if (unknown) result.joint_readiness.unknown += 1 else result.joint_readiness.all_ready += 1;
                if (fact.elapsed_ns) |elapsed| result.completed_timing.latency[reliability.latencyBin(elapsed)] += 1 else result.completed_timing.missing_latency += 1;
            },
            .safe_refusal => {
                result.safe_refusals += 1;
                switch (fact.refusal.?) {
                    .busy => result.busy_refusals += 1,
                    .installation_selection_required => result.installation_selection_required_refusals += 1,
                    .collection_timed_out => result.collection_timed_out_refusals += 1,
                }
                if (fact.elapsed_ns) |elapsed| result.refusal_timing.latency[reliability.latencyBin(elapsed)] += 1 else result.refusal_timing.missing_latency += 1;
            },
        }
    }
    return result;
}

test "verification completion preserves phase reasons without claiming installed product success" {
    var readiness = onboarding.assess(.{});
    readiness.findings[0].reason = .ready;
    readiness.findings[1].reason = .missing;
    const result = try makeCompleted("opaque-attempt", 1, 1, readiness, null);
    try std.testing.expectEqual(PhaseOutcome.verified_ready, result.phases[0].outcome);
    try std.testing.expectEqual(PhaseOutcome.action_required, result.phases[1].outcome);
    try std.testing.expectEqual(PhaseOutcome.unknown, result.phases[6].outcome);
    const refusal = try makeRefusal("opaque-busy", 0, 1, .busy);
    try std.testing.expectEqual(Outcome.safe_refusal, refusal.outcome);
    try std.testing.expectError(error.InvalidSetupVerificationResult, makeCompleted("opaque-attempt", 0, 1, readiness, null));
}

test "worst legal terminal result fits existing immutable 1024 byte reservation" {
    const id: [mutation.max_id_bytes]u8 = @splat('a');
    var longest: onboarding.Reason = .ready;
    inline for (@typeInfo(onboarding.Reason).@"enum".field_names) |name| {
        const reason = std.meta.stringToEnum(onboarding.Reason, name).?;
        if (name.len > @tagName(longest).len) longest = reason;
    }
    const fact: Result = .{ .operation_id = &id, .generation = std.math.maxInt(u64), .observed_at = std.math.maxInt(i64), .outcome = .verification_completed, .phases = @splat(.{ .outcome = classify(longest), .reason = longest }), .elapsed_ns = std.math.maxInt(u64) };
    const bytes = try serialize(std.testing.allocator, fact);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len < maximum_result_bytes);
    const refusal = try makeRefusal(&id, std.math.maxInt(u64), std.math.maxInt(i64), .installation_selection_required);
    const refused = try serialize(std.testing.allocator, refusal);
    defer std.testing.allocator.free(refused);
    try std.testing.expect(refused.len < maximum_result_bytes);
    // The longest reason and longest outcome need not be the same legal pair.
    // Check every valid reason/outcome pairing across all seven phases.
    inline for (@typeInfo(onboarding.Reason).@"enum".field_names) |name| {
        const reason = std.meta.stringToEnum(onboarding.Reason, name).?;
        var candidate = fact;
        candidate.phases = @splat(.{ .outcome = classify(reason), .reason = reason });
        const encoded = try serialize(std.testing.allocator, candidate);
        defer std.testing.allocator.free(encoded);
        try std.testing.expect(encoded.len < maximum_result_bytes);
    }
}

test "missing cached schema fields cannot manufacture completed verification from defaults" {
    var ledger = try mutation.Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    const slot = (try ledger.begin("attempt", method, @splat(1), 0, 0, .external)).execute;
    try ledger.complete(slot, "{\"operation_id\":\"attempt\",\"generation\":1,\"observed_at\":0,\"outcome\":\"verification_completed\"}");
    try std.testing.expectError(error.InvalidSetupVerificationRecord, parseCompletedRecord(std.testing.allocator, ledger.data.records[slot]));
}

test "verification identifiers have the same canonical authority as the existing mutation ledger" {
    var ledger = try mutation.Ledger.init(std.testing.allocator, 1);
    defer ledger.deinit();
    for ([_][]const u8{ "", "not:canonical", "not.canonical", "not/canonical", "not canonical", "not\ncanonical" }) |id| {
        try std.testing.expectError(error.InvalidOperationId, ledger.begin(id, method, @splat(1), 0, 0, .external));
        try std.testing.expectError(error.InvalidSetupVerificationResult, makeRefusal(id, 0, 0, .busy));
    }
    const fact = try makeRefusal("canonical-1_ID", 0, 0, .installation_selection_required);
    const slot = (try ledger.begin(fact.operation_id, method, @splat(1), 0, 0, .external)).execute;
    const bytes = try serialize(std.testing.allocator, fact);
    defer std.testing.allocator.free(bytes);
    try ledger.complete(slot, bytes);
    const parsed = try parseCompletedRecord(std.testing.allocator, ledger.snapshot().records[slot]);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(fact.operation_id, parsed.value.operation_id);
}

test "summary distinguishes immutable terminal results uncertainty clock windows and missing latency" {
    var ledger = try mutation.Ledger.init(std.testing.allocator, 8);
    defer ledger.deinit();
    const now = 30 * 86_400;
    const facts = [_]Result{
        try makeCompleted("complete", 1, now, onboarding.assess(.{}), null),
        try makeRefusal("busy", 1, now, .busy),
        try makeCompleted("old", 1, 0, onboarding.assess(.{}), 10),
        try makeCompleted("future", 1, now + 1, onboarding.assess(.{}), 10),
    };
    for (facts) |fact| {
        const slot = (try ledger.begin(fact.operation_id, method, @splat(1), 0, 0, .external)).execute;
        const bytes = try serialize(std.testing.allocator, fact);
        defer std.testing.allocator.free(bytes);
        try ledger.complete(slot, bytes);
    }
    _ = try ledger.begin("pending", method, @splat(1), 0, 0, .external);
    const unresolved = (try ledger.begin("uncertain", method, @splat(1), 0, 0, .external)).execute;
    try ledger.markIndeterminate(unresolved);
    const summary = try summarize(std.testing.allocator, ledger.snapshot(), now);
    try std.testing.expectEqual(@as(u64, 1), summary.verification_completed);
    try std.testing.expectEqual(@as(u64, 1), summary.safe_refusals);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_started);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_indeterminate);
    try std.testing.expectEqual(@as(u64, 1), summary.old_window_records);
    try std.testing.expectEqual(@as(u64, 1), summary.future_clock_records);
    try std.testing.expectEqual(@as(u64, 1), summary.completed_timing.missing_latency);
    try std.testing.expect(!summary.achieved_slo);
    try std.testing.expect(!summary.end_to_end_latency_measured);
    // Corrupting cached correlation cannot reattribute a verified phase.
    ledger.data.records[0].id[0] = 'x';
    try std.testing.expectError(error.InvalidSetupVerificationRecord, summarize(std.testing.allocator, ledger.snapshot(), now));
}

test "collector timeout is immutable safe refusal without phase or completion latency samples" {
    const allocator = std.testing.allocator;
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const refusal = try makeRefusal("bounded-timeout", 1, 30 * 86_400, .collection_timed_out);
    const bytes = try serialize(allocator, refusal);
    defer allocator.free(bytes);
    const slot = (try ledger.begin(refusal.operation_id, method, @splat(1), 0, 0, .external)).execute;
    try ledger.complete(slot, bytes);
    try std.testing.expectEqualStrings(bytes, (try ledger.begin(refusal.operation_id, method, @splat(1), 0, 1, .external)).replay);
    const summary = try summarize(allocator, ledger.snapshot(), refusal.observed_at);
    try std.testing.expectEqual(@as(u64, 0), summary.verification_completed);
    try std.testing.expectEqual(@as(u64, 1), summary.safe_refusals);
    try std.testing.expectEqual(@as(u64, 1), summary.collection_timed_out_refusals);
    try std.testing.expectEqual(@as(u64, 0), summary.completed_timing.missing_latency);
    for (summary.completed_timing.latency) |count| try std.testing.expectEqual(@as(u64, 0), count);
    for (summary.phases) |phase| try std.testing.expectEqualDeep(PhaseSummary{}, phase);
    try std.testing.expectEqual(@as(u64, 1), summary.refusal_timing.missing_latency);
    try std.testing.expect(!summary.achieved_slo and !summary.end_to_end_latency_measured);
    var forged = refusal;
    forged.elapsed_ns = 1;
    try std.testing.expectError(error.InvalidSetupVerificationResult, validate(forged));
    forged = refusal;
    forged.phases[0] = .{ .outcome = .verified_ready, .reason = .ready };
    try std.testing.expectError(error.InvalidSetupVerificationResult, validate(forged));
}


test "daemon timed refusal retains its distinct population and original result bound" {
    var ledger = try mutation.Ledger.init(std.testing.allocator, 2);
    defer ledger.deinit();
    const slot = (try ledger.begin("owned-refusal", method, @splat(8), 0, 0, .external)).execute;
    const fact = try makeTimedRefusal("owned-refusal", 0, 0, .installation_selection_required, std.math.maxInt(u64));
    const bytes = try serialize(std.testing.allocator, fact);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len <= maximum_result_bytes);
    try ledger.complete(slot, bytes);
    const summary = try summarize(std.testing.allocator, ledger.snapshot(), 0);
    try std.testing.expectEqual(@as(u64, 1), summary.safe_refusals);
    try std.testing.expectEqual(@as(u64, 0), summary.verification_completed);
    try std.testing.expectEqual(@as(u64, 1), summary.refusal_timing.latency[reliability.latencyBin(std.math.maxInt(u64))]);
    try std.testing.expectEqual(@as(u64, 0), summary.refusal_timing.missing_latency);
    try std.testing.expect(!summary.end_to_end_latency_measured and !summary.achieved_slo);
}
