//! Prepare lifecycle facts for the SAME authenticated snapshot transaction as
//! terminal operation authority. This module never writes a separate file/table.
//! Callers publish the returned copy only after Store.commit succeeds, or restore
//! the previous authenticated envelope after a failure. A returned job ID is not
//! a verified terminal user outcome and must not call this helper.
const std = @import("std");
const reliability = @import("reliability.zig");
const mutations = @import("mutation_authority.zig");
const domain = @import("domain.zig");

pub const Prepared = struct {
    /// Always allocator-owned, including replay; caller destroys on discard.
    recorder: *reliability.LifecycleRecorder,
    recorded: bool,
};

/// Existing durable mutation authority is the deduplication fence. Do not store
/// a second, expiring ID set that could permit old retries to count again.
pub fn terminalTransition(allocator: std.mem.Allocator, current: *const reliability.LifecycleRecorder, previous: mutations.Record, next: mutations.Record, utc_s: i64, observation: reliability.LifecycleObservation) !Prepared {
    if (previous.id_len == 0 or previous.id_len > mutations.max_id_bytes or next.id_len != previous.id_len or
        previous.method_len > mutations.max_method_bytes or next.method_len != previous.method_len or
        !std.mem.eql(u8, previous.id[0..previous.id_len], next.id[0..next.id_len]) or
        !std.mem.eql(u8, previous.method[0..previous.method_len], next.method[0..next.method_len]) or
        !std.mem.eql(u8, &previous.fingerprint, &next.fingerprint) or
        previous.expected_revision != next.expected_revision or previous.kind != next.kind)
        return error.OperationIdentityMismatch;
    if (previous.state == .completed and next.state == .completed) {
        if (!std.mem.eql(u8, previous.result, next.result)) return error.OperationIdentityMismatch;
        return .{ .recorder = try current.clone(allocator), .recorded = false };
    }
    if (previous.state != .started or next.state != .completed) return error.NonterminalTransition;
    const candidate = try current.clone(allocator);
    errdefer allocator.destroy(candidate);
    try candidate.record(utc_s, observation);
    return .{ .recorder = candidate, .recorded = true };
}

/// Prepay all future aggregate widening BEFORE any external effect. This is
/// conservative: actual serialized bytes + this reserve equals the full ceiling.
/// Add the reserve to engine maintenance headroom, not an independent budget.
pub fn remainingReservation(serialized_bytes: usize) !usize {
    if (serialized_bytes > reliability.max_lifecycle_checkpoint_bytes) return error.CheckpointTooLarge;
    return reliability.max_lifecycle_checkpoint_bytes - serialized_bytes;
}

/// Native-source identity verification has its own durable job generation.
/// Coalesced requests and retired network completions cannot create new samples.
pub fn enrollmentTransition(allocator: std.mem.Allocator, current: *const reliability.LifecycleRecorder, previous: domain.Job, next: domain.Job, utc_s: i64, cause: reliability.Cause, admitted_elapsed_ns: ?u64) !Prepared {
    if (previous.kind != .enrollment or next.kind != .enrollment or previous.operation_generation != next.operation_generation or !std.mem.eql(u8, previous.id, next.id)) return error.OperationIdentityMismatch;
    if (previous.status != .running or (next.status != .completed and next.status != .failed)) return error.NonterminalTransition;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(previous.id, &digest, .{});
    const candidate = try current.clone(allocator);
    errdefer allocator.destroy(candidate);
    try candidate.record(utc_s, .{
        .operation_correlation = std.mem.readInt(u64, digest[0..8], .little) ^ previous.operation_generation,
        .phase = .enroll,
        .outcome = if (next.status == .completed) .success else .failed_admitted,
        .cause = cause,
        // Admission-to-terminal latency includes provider work. Local work and
        // user/provider wait remain unknown; this is not user-request elapsed.
        .total_elapsed_ns = admitted_elapsed_ns,
    });
    return .{ .recorder = candidate, .recorded = true };
}

test "enrollment samples require one exact running job generation terminal transition" {
    const current = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(current);
    const previous: domain.Job = .{ .id = "opaque-attempt", .kind = .enrollment, .status = .running, .operation_generation = 7 };
    var next = previous;
    next.status = .completed;
    const success = try enrollmentTransition(std.testing.allocator, current, previous, next, 0, .none, 100);
    defer std.testing.allocator.destroy(success.recorder);
    try std.testing.expectEqual(@as(u64, 1), (try success.recorder.window(0))[@backingInt(reliability.Phase.enroll)][0].count);
    try std.testing.expectError(error.NonterminalTransition, enrollmentTransition(std.testing.allocator, success.recorder, next, next, 0, .none, 100));
    next.operation_generation += 1;
    try std.testing.expectError(error.OperationIdentityMismatch, enrollmentTransition(std.testing.allocator, current, previous, next, 0, .none, 100));
    next.operation_generation = previous.operation_generation;
    next.status = .failed;
    const failure = try enrollmentTransition(std.testing.allocator, current, previous, next, 0, .timeout, null);
    defer std.testing.allocator.destroy(failure.recorder);
    const failed_cell = (try failure.recorder.window(0))[@backingInt(reliability.Phase.enroll)][@backingInt(reliability.LifecycleOutcome.failed_admitted)];
    try std.testing.expectEqual(@as(u64, 1), failed_cell.count);
    try std.testing.expectEqual(@as(u64, 1), failed_cell.total.missing_latency);
    try std.testing.expectEqual(@as(u64, 0), (try current.window(0))[@backingInt(reliability.Phase.enroll)][0].count);
}

test "terminal authority counts once and replay preserves prior aggregate" {
    const current = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(current);
    var previous: mutations.Record = .{ .id_len = 1, .method_len = 1 };
    previous.id[0] = 'a';
    previous.method[0] = 'm';
    var next = previous;
    next.state = .completed;
    const observation: reliability.LifecycleObservation = .{ .operation_correlation = 1, .phase = .remove, .outcome = .success };
    const prepared = try terminalTransition(std.testing.allocator, current, previous, next, 0, observation);
    defer std.testing.allocator.destroy(prepared.recorder);
    try std.testing.expect(prepared.recorded);
    const replay = try terminalTransition(std.testing.allocator, prepared.recorder, next, next, 0, observation);
    defer std.testing.allocator.destroy(replay.recorder);
    try std.testing.expect(!replay.recorded);
    const restored = replay.recorder;
    try std.testing.expectEqual(@as(u64, 1), (try restored.window(0))[@backingInt(reliability.Phase.remove)][0].count);
    const original = current;
    try std.testing.expectEqual(@as(u64, 0), (try original.window(0))[@backingInt(reliability.Phase.remove)][0].count);
}

test "different operation or unresolved work cannot produce terminal measurement" {
    const current = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{});
    defer std.testing.allocator.destroy(current);
    var previous: mutations.Record = .{ .id_len = 1 };
    previous.id[0] = 'a';
    var next = previous;
    const observation: reliability.LifecycleObservation = .{ .operation_correlation = 1, .phase = .enroll, .outcome = .success };
    try std.testing.expectError(error.NonterminalTransition, terminalTransition(std.testing.allocator, current, previous, next, 0, observation));
    next.state = .completed;
    next.fingerprint[0] = 1;
    try std.testing.expectError(error.OperationIdentityMismatch, terminalTransition(std.testing.allocator, current, previous, next, 0, observation));
    try std.testing.expectError(error.CheckpointTooLarge, remainingReservation(reliability.max_lifecycle_checkpoint_bytes + 1));
}
