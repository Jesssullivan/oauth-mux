const std = @import("std");
const attempts = @import("browser_attempt.zig");

test "refusal replay survives snapshot and changed intent cannot recount" {
    var ledger = try attempts.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    const scope = try attempts.contextKey(@splat(7), .{ "chromium", "extension", "source", "codex" }, 3);
    const intent = try attempts.fingerprint(@splat(7), "bounded exact request bytes");
    try std.testing.expect((try ledger.refuse(scope, "attempt-1", intent, .needs_provider_adapter_proof, .other)) == .fresh);
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(attempts.Snapshot, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    var restored = try attempts.Ledger.fromSnapshot(std.testing.allocator, parsed.value);
    defer restored.deinit();
    const replay = try restored.refuse(scope, "attempt-1", intent, .needs_provider_adapter_proof, .timeout);
    try std.testing.expect(replay == .replay);
    try std.testing.expectEqual(@as(usize, 1), restored.count);
    try std.testing.expectEqual(@import("reliability.zig").Cause.other, replay.replay.cause);
    const changed = try attempts.fingerprint(@splat(7), "different bounded request bytes");
    try std.testing.expectError(error.BrowserAttemptConflict, restored.refuse(scope, "attempt-1", changed, .needs_provider_adapter_proof, .other));
    try std.testing.expectEqual(@as(usize, 1), restored.count);
}

test "full authority never evicts old refusal and maximum snapshot remains bounded" {
    var ledger = try attempts.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    const maximum_id: [attempts.max_id_bytes]u8 = @splat('a');
    for (0..attempts.max_records) |index| {
        var scope: [32]u8 = @splat(255);
        std.mem.writeInt(u64, scope[0..8], @intCast(index), .little);
        _ = try ledger.refuse(scope, &maximum_id, @splat(255), .needs_provider_adapter_proof, .observation_gap);
    }
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, ledger.snapshot(), .{});
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len < attempts.maximum_snapshot_bytes);
    const first = ledger.records[0];
    try std.testing.expect((try ledger.refuse(first.context_key, first.id[0..first.id_len], first.intent_fingerprint, first.refusal, first.cause)) == .replay);
    try std.testing.expectError(error.BrowserAttemptCapacity, ledger.refuse(@splat(2), "new-attempt", @splat(3), .needs_provider_adapter_proof, .other));
}

test "duplicate authority and hidden padding are rejected" {
    var ledger = try attempts.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    _ = try ledger.refuse(@splat(1), "attempt", @splat(2), .needs_provider_adapter_proof, .other);
    const duplicate = [_]attempts.Record{ ledger.records[0], ledger.records[0] };
    try std.testing.expectError(error.InvalidBrowserAttemptSnapshot, attempts.Ledger.fromSnapshot(std.testing.allocator, .{ .records = &duplicate }));
    var invalid = [_]attempts.Record{ledger.records[0]};
    invalid[0].id[63] = 1;
    try std.testing.expectError(error.InvalidBrowserAttemptSnapshot, attempts.Ledger.fromSnapshot(std.testing.allocator, .{ .records = &invalid }));
}
