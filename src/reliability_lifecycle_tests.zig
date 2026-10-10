const std = @import("std");
const reliability = @import("reliability.zig");

test "fast refusal does not become successful enrollment" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{ .evidence = .synthetic });
    defer std.testing.allocator.destroy(recorder);
    try recorder.record(0, .{ .operation_correlation = 1, .phase = .enroll, .outcome = .safe_refusal, .cause = .custody_unavailable, .total_elapsed_ns = 100, .local_elapsed_ns = 50, .user_provider_wait_ns = 50 });
    const cells = try recorder.window(0);
    try std.testing.expectEqual(@as(u64, 0), cells[@backingInt(reliability.Phase.enroll)][@backingInt(reliability.LifecycleOutcome.success)].count);
    const refusal = cells[@backingInt(reliability.Phase.enroll)][@backingInt(reliability.LifecycleOutcome.safe_refusal)];
    try std.testing.expectEqual(@as(u64, 1), refusal.count);
    try std.testing.expectEqual(@as(u128, 1), refusal.total.timedOpportunities());
}

test "duration rejection and overflow leave counters unchanged" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(recorder);
    try std.testing.expectError(error.InvalidDuration, recorder.record(0, .{ .operation_correlation = 1, .phase = .install, .outcome = .success, .total_elapsed_ns = 5, .local_elapsed_ns = 4, .user_provider_wait_ns = 2 }));
    try recorder.record(0, .{ .operation_correlation = 1, .phase = .install, .outcome = .success });
    recorder.days[0].cells[0][0].local.missing_latency = std.math.maxInt(u64);
    try std.testing.expectError(error.CounterSaturated, recorder.record(0, .{ .operation_correlation = 2, .phase = .install, .outcome = .success }));
    try std.testing.expectEqual(@as(u64, 1), recorder.days[0].cells[0][0].count);
    try std.testing.expectEqual(@as(u64, 1), recorder.days[0].cells[0][0].total.missing_latency);
}

test "checkpoint roundtrip preserves lifecycle classification and expiry" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{ .os = .linux });
    defer std.testing.allocator.destroy(recorder);
    try recorder.record(0, .{ .operation_correlation = 1, .phase = .renew, .outcome = .failed_admitted, .cause = .timeout, .total_elapsed_ns = 60_000_000_001, .local_elapsed_ns = 10 });
    const bytes = try recorder.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    const restored = try reliability.LifecycleRecorder.readAllocated(std.testing.allocator, bytes, 10, .{});
    defer std.testing.allocator.destroy(restored);
    const cells = try restored.window(0);
    const failure = cells[@backingInt(reliability.Phase.renew)][@backingInt(reliability.LifecycleOutcome.failed_admitted)];
    try std.testing.expectEqual(@as(u64, 1), failure.count);
    try std.testing.expectEqual(reliability.Percentile{ .above_largest_bucket = 60_000_000_000 }, try failure.total.percentile(99));
    try std.testing.expectEqual(@as(u64, 0), (try restored.window(28 * 86_400))[@backingInt(reliability.Phase.renew)][@backingInt(reliability.LifecycleOutcome.failed_admitted)].count);
    const absent = try reliability.LifecycleRecorder.readAllocated(std.testing.allocator, null, 10, .{});
    defer std.testing.allocator.destroy(absent);
    try std.testing.expectEqual(@as(u64, 0), (try absent.window(10))[0][0].count);
}

test "unknown schemas and malformed ring reject checkpoint" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(recorder);
    recorder.schema_version = 99;
    const bytes = try recorder.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.UnsupportedLifecycleSchema, reliability.LifecycleRecorder.readAllocated(std.testing.allocator, bytes, 0, .{}));
    recorder.schema_version = 1;
    recorder.days[1].utc_day = 0;
    const invalid = try recorder.serialize(std.testing.allocator);
    defer std.testing.allocator.free(invalid);
    try std.testing.expectError(error.InvalidCheckpoint, reliability.LifecycleRecorder.readAllocated(std.testing.allocator, invalid, 0, .{}));
}

test "full ring with maximum-width consistent counters fits prepaid checkpoint ceiling" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(recorder);
    recorder.last_recorded_at = 27 * 86_400;
    const maximum = std.math.maxInt(u64);
    var timing: reliability.LifecycleTiming = .{};
    // Spread the maximum population over every bin and missing timing so each
    // decimal counter reaches its largest possible width simultaneously.
    const parts = timing.latency.len + 1;
    @memset(&timing.latency, maximum / parts);
    timing.missing_latency = maximum / parts + maximum % parts;
    for (&recorder.days, 0..) |*day, index| {
        day.utc_day = @intCast(index);
        for (&day.cells) |*outcomes| for (outcomes) |*cell| {
            cell.count = maximum;
            @memset(&cell.causes, maximum / cell.causes.len);
            cell.causes[0] += maximum % cell.causes.len;
            cell.total = timing;
            cell.local = timing;
            cell.user_provider_wait = timing;
        };
    }
    const bytes = try recorder.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len < reliability.max_lifecycle_checkpoint_bytes);
    const restored = try reliability.LifecycleRecorder.readAllocated(std.testing.allocator, bytes, 0, .{});
    defer std.testing.allocator.destroy(restored);
    try std.testing.expectEqual(maximum, restored.days[27].cells[5][4].count);
    // Summing multiple days can legitimately overflow a u64 export cell; it
    // must fail explicitly rather than producing a fabricated good baseline.
    try std.testing.expectError(error.CounterSaturated, restored.window(27 * 86_400));
}


test "durable phase projection preserves refusal latency and unknown readiness across restore" {
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{ .evidence = .synthetic });
    defer std.testing.allocator.destroy(recorder);
    try recorder.record(0, .{ .operation_correlation = 1, .phase = .enroll, .outcome = .safe_refusal, .cause = .custody_unavailable, .local_elapsed_ns = 100 });
    try recorder.record(0, .{ .operation_correlation = 2, .phase = .enroll, .outcome = .success, .total_elapsed_ns = 300 });
    const bytes = try recorder.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    const restored = try reliability.LifecycleRecorder.readAllocated(std.testing.allocator, bytes, 0, .{});
    defer std.testing.allocator.destroy(restored);
    const summary = reliability.lifecycleSummary(try restored.window(0));
    const enroll = summary[@backingInt(reliability.Phase.enroll)];
    try std.testing.expectEqual(@as(u128, 2), enroll.recorded_outcomes);
    try std.testing.expectEqual(@as(u64, 1), enroll.successful_user_outcomes);
    try std.testing.expectEqual(@as(u64, 1), enroll.safe_refusals);
    try std.testing.expectEqual(@as(u128, 0), enroll.outcomes[@backingInt(reliability.LifecycleOutcome.success)].local.timedOpportunities());
    try std.testing.expectEqual(@as(u128, 1), enroll.outcomes[@backingInt(reliability.LifecycleOutcome.safe_refusal)].local.timedOpportunities());
    for (summary) |phase| {
        try std.testing.expect(phase.supported_user_demands == null and phase.ready_supported_user_demands == null);
        try std.testing.expect(!phase.complete_user_demand_denominator and !phase.user_end_to_end_elapsed_measured and !phase.achieved_slo);
    }
    inline for (.{ reliability.Phase.install, reliability.Phase.renew, reliability.Phase.@"resume", reliability.Phase.update }) |phase| {
        try std.testing.expectEqual(reliability.PhaseCoverage.unobserved, summary[@backingInt(phase)].coverage);
        try std.testing.expectEqual(@as(u128, 0), summary[@backingInt(phase)].recorded_outcomes);
    }
}


test "phase export failures preserve the durable recorder and report exact unavailable cause" {
    try std.testing.expectEqual(reliability.PhaseSummaryUnavailable.recorder_unavailable, reliability.lifecycleExport(null, 0).unavailable_reason.?);
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(recorder);
    try recorder.record(1, .{ .operation_correlation = 1, .phase = .enroll, .outcome = .safe_refusal });
    const anomaly = reliability.lifecycleExport(recorder, 0);
    try std.testing.expect(anomaly.phases == null);
    try std.testing.expectEqual(reliability.PhaseSummaryUnavailable.clock_anomaly, anomaly.unavailable_reason.?);
    try std.testing.expectEqual(@as(u64, 1), recorder.days[0].cells[@backingInt(reliability.Phase.enroll)][@backingInt(reliability.LifecycleOutcome.safe_refusal)].count);
    recorder.days[0].cells[0][0].count = std.math.maxInt(u64);
    recorder.days[1].utc_day = 1;
    recorder.days[1].cells[0][0].count = 1;
    const saturated = reliability.lifecycleExport(recorder, 86_400);
    try std.testing.expect(saturated.phases == null);
    try std.testing.expectEqual(reliability.PhaseSummaryUnavailable.counter_saturated, saturated.unavailable_reason.?);
    try std.testing.expectEqual(std.math.maxInt(u64), recorder.days[0].cells[0][0].count);
    try std.testing.expectEqual(@as(u64, 1), recorder.days[1].cells[0][0].count);
}
