//! Bounded, local diagnostic observations. No identities or arbitrary labels.
//! Caller establishes eligibility: request diagnostics do not establish an SLO.
const std = @import("std");

pub const Metric = enum { control_request, action, health_observation };
pub const Operation = enum { health, metrics_export, snapshot, metadata_read, mutation, adapter, browser, unknown };
pub const Outcome = enum { good, bad, excluded, unobserved };
pub const MeasurementStatus = enum { unmeasured, provisional, observed };
/// Bounds describe only the timed opportunities, never untimed/excluded work.
pub const Percentile = union(enum) {
    unmeasured,
    bounded: u64,
    above_largest_bucket: u64,

    pub fn jsonStringify(self: Percentile, writer: anytype) !void {
        const upper_bound_ns: ?u64 = switch (self) {
            .bounded => |bound| bound,
            .unmeasured, .above_largest_bucket => null,
        };
        const lower_bound_exclusive_ns: ?u64 = switch (self) {
            .above_largest_bucket => |bound| bound,
            .unmeasured, .bounded => null,
        };
        try writer.write(.{ .state = std.meta.activeTag(self), .upper_bound_ns = upper_bound_ns, .lower_bound_exclusive_ns = lower_bound_exclusive_ns });
    }
};
pub const LatencySummary = struct {
    timed_opportunities: u128,
    missing_latency: u64,
    p50: Percentile,
    p95: Percentile,
    p99: Percentile,
};
pub const Cause = enum { none, timeout, busy, custody_unavailable, protocol_mismatch, host_sleep, operator_shutdown, observation_gap, other, local_capacity, result_bound };
pub const Stratum = struct {
    os: enum { linux, macos, other, unknown } = .unknown,
    architecture: enum { x86_64, aarch64, other, unknown } = .unknown,
    adapter: enum { none, codex, git, claude, unknown } = .none,
    evidence: enum { diagnostic, synthetic, native_conformance, live } = .diagnostic,
};
pub const latency_bounds_ns = [_]u64{ 1_000_000, 10_000_000, 50_000_000, 100_000_000, 250_000_000, 500_000_000, 1_000_000_000, 2_000_000_000, 5_000_000_000, 15_000_000_000, 30_000_000_000, 60_000_000_000 };
const metric_count = @typeInfo(Metric).@"enum".field_names.len;
const operation_count = @typeInfo(Operation).@"enum".field_names.len;
const cause_count = @typeInfo(Cause).@"enum".field_names.len;
pub const Cells = [metric_count][operation_count]Cell;

pub const Cell = struct {
    good: u64 = 0,
    bad: u64 = 0,
    excluded: u64 = 0,
    unobserved: u64 = 0,
    causes: [cause_count]u64 = @splat(0),
    /// Exclusive bins for good/bad opportunities only; final bin is > 60 s.
    latency: [latency_bounds_ns.len + 1]u64 = @splat(0),
    missing_latency: u64 = 0,
    pub fn opportunities(self: Cell) u128 {
        return @as(u128, self.good) + self.bad;
    }
    pub fn status(self: Cell) MeasurementStatus {
        const count = self.opportunities();
        return if (count == 0) .unmeasured else if (count < 100) .provisional else .observed;
    }
    /// Budget units are millionths of one opportunity, never rounded successes.
    pub fn budget(self: Cell, target_millionths: u32) !Budget {
        if (target_millionths > 1_000_000) return error.InvalidTarget;
        const allowed = self.opportunities() * (1_000_000 - @as(u128, target_millionths));
        const consumed = @as(u128, self.bad) * 1_000_000;
        return .{ .allowed_microopportunities = allowed, .consumed_microopportunities = consumed, .remaining_microopportunities = if (allowed >= consumed) allowed - consumed else 0, .excess_microopportunities = if (consumed > allowed) consumed - allowed else 0, .unobserved = self.unobserved, .status = self.status() };
    }
    pub fn timedOpportunities(self: Cell) u128 {
        var total: u128 = 0;
        for (self.latency) |count| total += count;
        return total;
    }
    /// Nearest-rank bucket bound, with missing samples reported separately.
    pub fn percentile(self: Cell, requested_percentile: u8) !Percentile {
        if (requested_percentile == 0 or requested_percentile > 100) return error.InvalidPercentile;
        const total = self.timedOpportunities();
        if (total == 0) return .unmeasured;
        const rank = (total * requested_percentile + 99) / 100;
        var cumulative: u128 = 0;
        for (self.latency, 0..) |count, index| {
            cumulative += count;
            if (cumulative >= rank) return if (index < latency_bounds_ns.len) .{ .bounded = latency_bounds_ns[index] } else .{ .above_largest_bucket = latency_bounds_ns[latency_bounds_ns.len - 1] };
        }
        unreachable;
    }
    pub fn latencySummary(self: Cell) LatencySummary {
        return .{ .timed_opportunities = self.timedOpportunities(), .missing_latency = self.missing_latency, .p50 = self.percentile(50) catch unreachable, .p95 = self.percentile(95) catch unreachable, .p99 = self.percentile(99) catch unreachable };
    }
    /// Lossy v1 helper: both unmeasured and overflow return null. New callers
    /// should use percentile() to preserve the distinction.
    pub fn percentileUpperBound(self: Cell, requested_percentile: u8) !?u64 {
        return switch (try self.percentile(requested_percentile)) {
            .unmeasured, .above_largest_bucket => null,
            .bounded => |bound| bound,
        };
    }
};
pub const Budget = struct {
    allowed_microopportunities: u128,
    consumed_microopportunities: u128,
    remaining_microopportunities: u128,
    excess_microopportunities: u128,
    unobserved: u64,
    status: MeasurementStatus,
};
const empty_cells: Cells = @splat(@splat(.{}));
pub const Day = struct { utc_day: ?i64 = null, cells: Cells = empty_cells };
pub const Export = struct {
    /// v2 narrows histogram population to timed good/bad opportunities. v1
    /// mixed excluded/unobserved work; in-memory histories are not migrated.
    schema_version: u32 = 2,
    started_at: i64,
    captured_at: i64,
    window_start: i64,
    window_kind: enum { current_and_previous_27_utc_days } = .current_and_previous_27_utc_days,
    stratum: Stratum,
    storage: enum { in_memory } = .in_memory,
    restart_resets_history: bool = true,
    scheduled_coverage_established: bool = false,
    exact_artifact_and_application_provenance_established: bool = false,
    clock_anomaly: bool,
    saturated: bool,
    recorded_days: u8,
    latency_population: enum { timed_good_and_bad_opportunities } = .timed_good_and_bad_opportunities,
    latency_upper_bounds_ns: @TypeOf(latency_bounds_ns) = latency_bounds_ns,
    metrics: [metric_count]Metric = .{ .control_request, .action, .health_observation },
    operations: [operation_count]Operation = .{ .health, .metrics_export, .snapshot, .metadata_read, .mutation, .adapter, .browser, .unknown },
    /// Additive cause labels preserve existing indices. Consumers map each
    /// counter vector using these ordered names and its current width.
    causes: [cause_count]Cause = .{ .none, .timeout, .busy, .custody_unavailable, .protocol_mismatch, .host_sleep, .operator_shutdown, .observation_gap, .other, .local_capacity, .result_bound },
    cells: Cells,
    latency_summaries: [metric_count][operation_count]LatencySummary,
    /// UTC-day totals support daily review; they are not exact rolling 24 h.
    days: [28]Day,
};
pub const Recorder = struct {
    started_at: i64,
    last_recorded_at: i64,
    stratum: Stratum,
    days: [28]Day = @splat(.{}),
    clock_anomaly: bool = false,
    saturated: bool = false,
    pub fn init(started_at: i64, stratum: Stratum) Recorder {
        return .{ .started_at = started_at, .last_recorded_at = started_at, .stratum = stratum };
    }
    pub fn record(self: *Recorder, utc_s: i64, metric: Metric, operation: Operation, outcome: Outcome, cause: Cause, elapsed_ns: ?u64) !void {
        if (utc_s < 0 or utc_s < self.last_recorded_at) {
            self.clock_anomaly = true;
            return error.ClockAnomaly;
        }
        const day = @divFloor(utc_s, 86_400);
        const slot = &self.days[@intCast(@mod(day, 28))];
        if (slot.utc_day != day) slot.* = .{ .utc_day = day };
        const cell = &slot.cells[@backingInt(metric)][@backingInt(operation)];
        var updated = cell.*;
        const counter = switch (outcome) {
            .good => &updated.good,
            .bad => &updated.bad,
            .excluded => &updated.excluded,
            .unobserved => &updated.unobserved,
        };
        increment(counter) catch {
            self.saturated = true;
            return error.CounterSaturated;
        };
        increment(&updated.causes[@backingInt(cause)]) catch {
            self.saturated = true;
            return error.CounterSaturated;
        };
        switch (outcome) {
            .good, .bad => {
                const latency_counter = if (elapsed_ns) |elapsed| &updated.latency[latencyBin(elapsed)] else &updated.missing_latency;
                increment(latency_counter) catch {
                    self.saturated = true;
                    return error.CounterSaturated;
                };
            },
            .excluded, .unobserved => {},
        }
        cell.* = updated;
        self.last_recorded_at = utc_s;
    }
    pub fn exportSnapshot(self: *Recorder, now_s: i64) !Export {
        if (now_s < 0 or now_s < self.last_recorded_at or now_s < self.started_at) {
            self.clock_anomaly = true;
            return error.ClockAnomaly;
        }
        const day = @divFloor(now_s, 86_400);
        var cells = empty_cells;
        var days: [28]Day = @splat(.{});
        var recorded_days: u8 = 0;
        for (self.days, 0..) |slot, index| {
            const recorded = slot.utc_day orelse continue;
            if (recorded < day - 27 or recorded > day) continue;
            days[index] = slot;
            recorded_days += 1;
            for (slot.cells, 0..) |operations, metric| for (operations, 0..) |cell, operation| {
                merge(&cells[metric][operation], cell) catch {
                    self.saturated = true;
                    return error.CounterSaturated;
                };
            };
        }
        var latency_summaries: [metric_count][operation_count]LatencySummary = undefined;
        for (cells, 0..) |operations, metric| for (operations, 0..) |cell, operation| {
            latency_summaries[metric][operation] = cell.latencySummary();
        };
        self.last_recorded_at = now_s;
        return .{ .started_at = self.started_at, .captured_at = now_s, .window_start = @max(self.started_at, (day - 27) * 86_400), .stratum = self.stratum, .clock_anomaly = self.clock_anomaly, .saturated = self.saturated, .recorded_days = recorded_days, .cells = cells, .latency_summaries = latency_summaries, .days = days };
    }
};
fn increment(value: *u64) !void {
    value.* = std.math.add(u64, value.*, 1) catch return error.CounterSaturated;
}
fn merge(target: *Cell, source: Cell) !void {
    inline for (.{ "good", "bad", "excluded", "unobserved", "missing_latency" }) |field| @field(target.*, field) = std.math.add(u64, @field(target.*, field), @field(source, field)) catch return error.CounterSaturated;
    for (&target.causes, source.causes) |*to, from| to.* = std.math.add(u64, to.*, from) catch return error.CounterSaturated;
    for (&target.latency, source.latency) |*to, from| to.* = std.math.add(u64, to.*, from) catch return error.CounterSaturated;
}
pub fn latencyBin(elapsed_ns: u64) usize {
    for (latency_bounds_ns, 0..) |bound, index| if (elapsed_ns <= bound) return index;
    return latency_bounds_ns.len;
}
pub fn classifyLatency(elapsed_ns: u64, limit_ns: u64) Outcome {
    return if (elapsed_ns <= limit_ns) .good else .bad;
}

/// Companion lifecycle schema: diagnostic Export v2 remains unchanged. A future
/// combined export may add this as a field in v3; v2 history cannot be interpreted
/// as successful lifecycle work. Persistence callers own atomic commit and
/// exactly-once operation correlation; these aggregates alone are not durable.
pub const Phase = enum { install, enroll, renew, @"resume", update, remove };
pub const LifecycleOutcome = enum { success, safe_refusal, failed_admitted, unobserved, cancelled };
const phase_count = @typeInfo(Phase).@"enum".field_names.len;
const lifecycle_outcome_count = @typeInfo(LifecycleOutcome).@"enum".field_names.len;
pub const LifecycleObservation = struct {
    operation_correlation: u64,
    phase: Phase,
    outcome: LifecycleOutcome,
    cause: Cause = .none,
    total_elapsed_ns: ?u64 = null,
    local_elapsed_ns: ?u64 = null,
    user_provider_wait_ns: ?u64 = null,
};
pub const LifecycleTiming = struct {
    latency: [latency_bounds_ns.len + 1]u64 = @splat(0),
    missing_latency: u64 = 0,
    pub fn timedOpportunities(self: LifecycleTiming) u128 {
        var total: u128 = 0;
        for (self.latency) |count| total += count;
        return total;
    }
    pub fn percentile(self: LifecycleTiming, requested_percentile: u8) !Percentile {
        return (@as(Cell, .{ .latency = self.latency, .missing_latency = self.missing_latency })).percentile(requested_percentile);
    }
    pub fn latencySummary(self: LifecycleTiming) LatencySummary {
        return (@as(Cell, .{ .latency = self.latency, .missing_latency = self.missing_latency })).latencySummary();
    }
};
pub const LifecycleCell = struct {
    count: u64 = 0,
    causes: [cause_count]u64 = @splat(0),
    // Separate histograms for each outcome: refusal latency never contributes
    // to the successful-user-outcome distribution.
    total: LifecycleTiming = .{},
    local: LifecycleTiming = .{},
    user_provider_wait: LifecycleTiming = .{},
};
pub const LifecycleCells = [phase_count][lifecycle_outcome_count]LifecycleCell;
const empty_lifecycle_cells: LifecycleCells = @splat(@splat(.{}));
pub const LifecycleDay = struct { utc_day: ?i64 = null, cells: LifecycleCells = empty_lifecycle_cells };
pub const LifecycleRecorder = struct {
    schema_version: u32 = 1,
    started_at: i64,
    last_recorded_at: i64,
    stratum: Stratum,
    days: [28]LifecycleDay = @splat(.{}),
    clock_anomaly: bool = false,
    saturated: bool = false,

    pub fn create(allocator: std.mem.Allocator, started_at: i64, stratum: Stratum) !*LifecycleRecorder {
        const result = try allocator.create(LifecycleRecorder);
        // Initialize in place; do not return a whole ring on the actor stack.
        result.* = .{ .started_at = started_at, .last_recorded_at = started_at, .stratum = stratum };
        return result;
    }
    pub fn clone(self: *const LifecycleRecorder, allocator: std.mem.Allocator) !*LifecycleRecorder {
        const result = try allocator.create(LifecycleRecorder);
        result.* = self.*;
        return result;
    }
    pub fn record(self: *LifecycleRecorder, utc_s: i64, observation: LifecycleObservation) !void {
        if (utc_s < 0 or utc_s < self.last_recorded_at) {
            self.clock_anomaly = true;
            return error.ClockAnomaly;
        }
        if (observation.total_elapsed_ns) |total| {
            if ((observation.local_elapsed_ns orelse 0) > total or (observation.user_provider_wait_ns orelse 0) > total) return error.InvalidDuration;
            const accounted = std.math.add(u64, observation.local_elapsed_ns orelse 0, observation.user_provider_wait_ns orelse 0) catch return error.InvalidDuration;
            if (accounted > total) return error.InvalidDuration;
        }
        const day = @divFloor(utc_s, 86_400);
        const slot = &self.days[@intCast(@mod(day, 28))];
        var updated: LifecycleCell = if (slot.utc_day == day) slot.cells[@backingInt(observation.phase)][@backingInt(observation.outcome)] else .{};
        increment(&updated.count) catch return self.overflow();
        increment(&updated.causes[@backingInt(observation.cause)]) catch return self.overflow();
        addTiming(&updated.total, observation.total_elapsed_ns) catch return self.overflow();
        addTiming(&updated.local, observation.local_elapsed_ns) catch return self.overflow();
        addTiming(&updated.user_provider_wait, observation.user_provider_wait_ns) catch return self.overflow();
        if (slot.utc_day != day) slot.* = .{ .utc_day = day };
        slot.cells[@backingInt(observation.phase)][@backingInt(observation.outcome)] = updated;
        self.last_recorded_at = utc_s;
    }
    fn overflow(self: *LifecycleRecorder) error{CounterSaturated} {
        self.saturated = true;
        return error.CounterSaturated;
    }
    pub fn window(self: *LifecycleRecorder, now_s: i64) !LifecycleCells {
        if (now_s < self.last_recorded_at or now_s < self.started_at or now_s < 0) {
            self.clock_anomaly = true;
            return error.ClockAnomaly;
        }
        const day = @divFloor(now_s, 86_400);
        var cells = empty_lifecycle_cells;
        for (&self.days) |*slot| {
            const recorded = slot.utc_day orelse continue;
            if (recorded < day - 27 or recorded > day) continue;
            for (&slot.cells, 0..) |*outcomes, phase| for (outcomes, 0..) |cell, outcome| {
                const target = &cells[phase][outcome];
                target.count = std.math.add(u64, target.count, cell.count) catch return self.overflow();
                for (&target.causes, cell.causes) |*to, from| to.* = std.math.add(u64, to.*, from) catch return self.overflow();
                mergeTiming(&target.total, cell.total) catch return self.overflow();
                mergeTiming(&target.local, cell.local) catch return self.overflow();
                mergeTiming(&target.user_provider_wait, cell.user_provider_wait) catch return self.overflow();
            };
        }
        return cells;
    }
    /// Encoded bytes must be committed by the storage owner with operation
    /// authority. Serializing is not evidence that restart retention is wired.
    pub fn serialize(self: *const LifecycleRecorder, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try std.json.Stringify.valueAlloc(allocator, self, .{});
        if (bytes.len > max_lifecycle_checkpoint_bytes) {
            allocator.free(bytes);
            return error.CheckpointTooLarge;
        }
        return bytes;
    }
    /// Missing lifecycle data in an older checkpoint means unmeasured, not
    /// success. Reject unknown schemas and malformed ring positions.
    pub fn readAllocated(allocator: std.mem.Allocator, bytes: ?[]const u8, started_at: i64, stratum: Stratum) !*LifecycleRecorder {
        const encoded = bytes orelse return create(allocator, started_at, stratum);
        if (encoded.len > max_lifecycle_checkpoint_bytes) return error.CheckpointTooLarge;
        const parsed = try std.json.parseFromSlice(*LifecycleRecorder, allocator, encoded, .{});
        defer parsed.deinit();
        try parsed.value.validate();
        return parsed.value.clone(allocator);
    }
    pub fn validate(result: *const LifecycleRecorder) !void {
        if (result.schema_version != 1) return error.UnsupportedLifecycleSchema;
        if (result.started_at < 0 or result.last_recorded_at < result.started_at) return error.InvalidCheckpoint;
        for (&result.days, 0..) |*day, index| {
            if (day.utc_day) |utc_day| {
                if (utc_day < 0 or @mod(utc_day, 28) != @as(i64, @intCast(index)) or utc_day > @divFloor(result.last_recorded_at, 86_400)) return error.InvalidCheckpoint;
            }
            for (&day.cells) |*outcomes| for (outcomes) |cell| {
                if (day.utc_day == null and cell.count != 0) return error.InvalidCheckpoint;
                var classified: u128 = 0;
                for (cell.causes) |count| classified += count;
                if (classified != cell.count) return error.InvalidCheckpoint;
                inline for (.{ cell.total, cell.local, cell.user_provider_wait }) |timing| {
                    if (timing.timedOpportunities() + timing.missing_latency != cell.count) return error.InvalidCheckpoint;
                }
            };
        }
    }
};
// Full 28-day matrix with decimal-width-saturated counters remains below this
// prepaid ceiling. Engine admission must reserve the unused portion before IO.
pub const max_lifecycle_checkpoint_bytes = 4 * 1024 * 1024;
fn addTiming(cell: *LifecycleTiming, elapsed_ns: ?u64) !void {
    const counter = if (elapsed_ns) |elapsed| &cell.latency[latencyBin(elapsed)] else &cell.missing_latency;
    try increment(counter);
}
fn mergeTiming(target: *LifecycleTiming, source: LifecycleTiming) !void {
    target.missing_latency = std.math.add(u64, target.missing_latency, source.missing_latency) catch return error.CounterSaturated;
    for (&target.latency, source.latency) |*to, from| to.* = std.math.add(u64, to.*, from) catch return error.CounterSaturated;
}

test "exact latency boundary and bounded percentile" {
    try std.testing.expectEqual(Outcome.good, classifyLatency(2_000_000_000, 2_000_000_000));
    try std.testing.expectEqual(Outcome.bad, classifyLatency(2_000_000_001, 2_000_000_000));
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .control_request, .health, .good, .none, 2_000_000_000);
    const result = try recorder.exportSnapshot(0);
    try std.testing.expectEqual(@as(?u64, 2_000_000_000), try result.cells[0][0].percentileUpperBound(99));
    try std.testing.expect(!result.scheduled_coverage_established);
}
test "denominators budget and gaps remain independent" {
    var cell: Cell = .{ .good = 999, .bad = 1, .excluded = 7, .unobserved = 3 };
    const budget = try cell.budget(999000);
    try std.testing.expectEqual(@as(u128, 1_000_000), budget.allowed_microopportunities);
    try std.testing.expectEqual(@as(u128, 0), budget.remaining_microopportunities);
    try std.testing.expectEqual(@as(u64, 3), budget.unobserved);
    try std.testing.expectEqual(MeasurementStatus.unmeasured, @as(Cell, .{}).status());
    cell = .{ .good = 99 };
    try std.testing.expectEqual(MeasurementStatus.provisional, cell.status());
    try std.testing.expectError(error.InvalidTarget, cell.budget(1000001));
}
test "rolling day retention restart and clock anomalies" {
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .health_observation, .health, .unobserved, .observation_gap, null);
    try recorder.record(27 * 86400, .health_observation, .health, .good, .none, null);
    try std.testing.expectEqual(@as(u8, 2), (try recorder.exportSnapshot(27 * 86400)).recorded_days);
    try std.testing.expectEqual(@as(u64, 0), (try recorder.exportSnapshot(28 * 86400)).cells[2][0].unobserved);
    try std.testing.expectError(error.ClockAnomaly, recorder.record(0, .health_observation, .health, .good, .none, null));
    try std.testing.expect((try recorder.exportSnapshot(28 * 86400)).clock_anomaly);
    var restarted = Recorder.init(28 * 86400, .{});
    try std.testing.expectEqual(@as(u8, 0), (try restarted.exportSnapshot(28 * 86400)).recorded_days);
}
test "counter failure is atomic and overflow percentile is unknown" {
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .action, .mutation, .bad, .timeout, std.math.maxInt(u64));
    const cell = &recorder.days[0].cells[1][4];
    try std.testing.expectEqual(@as(?u64, null), try cell.percentileUpperBound(100));
    cell.causes[@backingInt(Cause.timeout)] = std.math.maxInt(u64);
    try std.testing.expectError(error.CounterSaturated, recorder.record(0, .action, .mutation, .bad, .timeout, 1));
    try std.testing.expectEqual(@as(u64, 1), cell.bad);
    try std.testing.expect(recorder.saturated);
}
test "export contains only bounded typed metadata" {
    var recorder = Recorder.init(100, .{ .os = .linux, .evidence = .synthetic });
    try recorder.record(100, .control_request, .mutation, .bad, .local_capacity, 1);
    try recorder.record(100, .control_request, .mutation, .bad, .result_bound, 1);
    try recorder.record(100, .control_request, .mutation, .bad, .result_bound, 1);
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, try recorder.exportSnapshot(100), .{});
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len < 1024 * 1024);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"latency_population\":\"timed_good_and_bad_opportunities\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"state\":\"unmeasured\"") != null);
    inline for (.{ "account_id", "source_id", "handle", "label", "email", "token", "provider_body", "session_id" }) |forbidden| try std.testing.expect(std.mem.indexOf(u8, bytes, forbidden) == null);
    // Read the public dimensions as a consumer: the appended names must select
    // their distinct counts without requiring a fixed cause-vector width.
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    const labels = parsed.value.object.get("causes").?.array.items;
    const cell = parsed.value.object.get("cells").?.array.items[0].array.items[4];
    const counts = cell.object.get("causes").?.array.items;
    try std.testing.expectEqual(labels.len, counts.len);
    try std.testing.expectEqual(@as(i64, 3), cell.object.get("bad").?.integer);
    var observed_causes: usize = 0;
    for (labels, counts) |label, count| {
        const expected: i64 = if (std.mem.eql(u8, label.string, "local_capacity")) 1 else if (std.mem.eql(u8, label.string, "result_bound")) 2 else 0;
        try std.testing.expectEqual(expected, count.integer);
        if (expected > 0) observed_causes += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), observed_causes);
}

test "serialized percentile preserves finite overflow and absent sample states" {
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .control_request, .health, .good, .none, 2_000_000_000);
    try recorder.record(0, .control_request, .mutation, .bad, .timeout, 60_000_000_001);
    const exported = try recorder.exportSnapshot(0);
    try std.testing.expectEqual(@as(u128, 1), exported.latency_summaries[0][0].timed_opportunities);
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, exported, .{});
    defer std.testing.allocator.free(bytes);
    inline for (.{
        "\"state\":\"bounded\",\"upper_bound_ns\":2000000000,\"lower_bound_exclusive_ns\":null",
        "\"state\":\"above_largest_bucket\",\"upper_bound_ns\":null,\"lower_bound_exclusive_ns\":60000000000",
        "\"state\":\"unmeasured\",\"upper_bound_ns\":null,\"lower_bound_exclusive_ns\":null",
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, bytes, expected) != null);
}

test "export rejects aggregate overflow and budget handles maximum counters" {
    const maximum = std.math.maxInt(u64);
    const budget = try (@as(Cell, .{ .good = maximum, .bad = maximum })).budget(999000);
    try std.testing.expectEqual((@as(u128, maximum) * 2) * 1000, budget.allowed_microopportunities);
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .control_request, .health, .good, .none, null);
    try recorder.record(86400, .control_request, .health, .good, .none, null);
    recorder.days[0].cells[0][0].good = maximum;
    try std.testing.expectError(error.CounterSaturated, recorder.exportSnapshot(86400));
    try std.testing.expect(recorder.saturated);
    try std.testing.expectError(error.InvalidPercentile, (@as(Cell, .{})).percentileUpperBound(0));
}

test "latency population excludes gaps and exclusions and counts untimed opportunities" {
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .control_request, .health, .good, .none, 1_000_000);
    try recorder.record(0, .control_request, .health, .bad, .timeout, 60_000_000_001);
    try recorder.record(0, .control_request, .health, .good, .none, null);
    try recorder.record(0, .control_request, .health, .bad, .timeout, null);
    try recorder.record(0, .control_request, .health, .excluded, .host_sleep, 1);
    try recorder.record(0, .control_request, .health, .excluded, .operator_shutdown, null);
    try recorder.record(0, .control_request, .health, .unobserved, .observation_gap, 1);
    try recorder.record(0, .control_request, .health, .unobserved, .observation_gap, null);
    const cell = (try recorder.exportSnapshot(0)).cells[0][0];
    try std.testing.expectEqual(@as(u128, 4), cell.opportunities());
    try std.testing.expectEqual(@as(u64, 2), cell.excluded);
    try std.testing.expectEqual(@as(u64, 2), cell.unobserved);
    try std.testing.expectEqual(@as(u64, 2), cell.causes[@backingInt(Cause.observation_gap)]);
    const summary = cell.latencySummary();
    try std.testing.expectEqual(@as(u128, 2), summary.timed_opportunities);
    try std.testing.expectEqual(@as(u64, 2), summary.missing_latency);
    try std.testing.expectEqual(@as(u64, 1_000_000), summary.p50.bounded);
    try std.testing.expectEqual(@as(u64, 60_000_000_000), summary.p95.above_largest_bucket);
    try std.testing.expectEqual(@as(u64, 60_000_000_000), summary.p99.above_largest_bucket);
}

test "percentile states distinguish no samples finite bucket and overflow" {
    try std.testing.expect(std.meta.activeTag(try (@as(Cell, .{ .good = 1, .missing_latency = 1 })).percentile(99)) == .unmeasured);
    var cell: Cell = .{};
    cell.latency[latency_bounds_ns.len - 1] = 99;
    cell.latency[latency_bounds_ns.len] = 1;
    try std.testing.expectEqual(@as(u64, 60_000_000_000), (try cell.percentile(99)).bounded);
    try std.testing.expectEqual(@as(u64, 60_000_000_000), (try cell.percentile(100)).above_largest_bucket);
    try std.testing.expectError(error.InvalidPercentile, cell.percentile(101));
    try std.testing.expectEqual(@as(?u64, null), try cell.percentileUpperBound(100));
    try std.testing.expectEqual(latency_bounds_ns.len - 1, latencyBin(60_000_000_000));
    try std.testing.expectEqual(latency_bounds_ns.len, latencyBin(60_000_000_001));
}

test "missing latency saturation remains atomic and retained days merge coverage" {
    var recorder = Recorder.init(0, .{});
    try recorder.record(0, .action, .mutation, .good, .none, null);
    try recorder.record(86_400, .action, .mutation, .bad, .timeout, null);
    const exported = try recorder.exportSnapshot(86_400);
    try std.testing.expectEqual(@as(u64, 2), exported.cells[1][4].missing_latency);
    const cell = &recorder.days[1].cells[1][4];
    cell.missing_latency = std.math.maxInt(u64);
    try std.testing.expectError(error.CounterSaturated, recorder.record(86_400, .action, .mutation, .bad, .timeout, null));
    try std.testing.expectEqual(@as(u64, 1), cell.bad);
    try std.testing.expectEqual(@as(u64, 1), cell.causes[@backingInt(Cause.timeout)]);
    try std.testing.expect(recorder.saturated);
    try std.testing.expectError(error.CounterSaturated, recorder.exportSnapshot(86_400));
    const later = try recorder.exportSnapshot(28 * 86_400);
    try std.testing.expectEqual(std.math.maxInt(u64), later.cells[1][4].missing_latency);
}
