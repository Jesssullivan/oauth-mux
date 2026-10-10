//! Isolated codec/descriptor models. No provider, vault or native live claim.
const std = @import("std");
const acquisition = @import("native_source_acquisition.zig");
const consent = @import("native_source_consent.zig");
fn request() acquisition.Request {
    const owner: consent.Owner = .{ .id = @splat(1), .nonce = @splat(2), .endpoint_generation = 1,
        .witness = .{ .profile = .linux_pidfs64_v1, .boot_id = @splat(3), .pidfs_device = 4,
            .pidfs_inode = 5, .user_namespace = .{ .device = 6, .inode = 7 },
            .pid_namespace = .{ .device = 8, .inode = 9 }, .uid = 10, .gid = 10 } };
    return .{ .admission = .{ .source_id = @splat(11), .source_generation = 1, .consent_id = @splat(13),
        .consent_generation = 1, .owner = owner, .context = .{ .id = @splat(12), .generation = 1 },
        .forget_epoch = 0, .allow_reenrollment = false, .cutoff = 50 },
        .origin = @splat(14), .operation = @splat('a'), .custody_seconds = 60, .consent_expires_at = 100 };
}
const payload = "{\"tokens\":{\"access_token\":\"fixture-access-placeholder\"},\"expires_at\":90}";
test "selected context requires separate finite copy consent and never accepts a profile locator" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const id = std.fmt.bytesToHex(@as([32]u8, @splat(1)), .lower);
    const nonce = std.fmt.bytesToHex(@as([32]u8, @splat(2)), .lower);
    const context = std.fmt.bytesToHex(@as([32]u8, @splat(12)), .lower);
    const operation: [64]u8 = @splat('a');
    const encoded = try std.json.Stringify.valueAlloc(a, .{ .kind = "native_store", .provider = "codex",
        .operation_id = operation[0..], .expected_revision = 1,
        .native_access_copy = true, .custody_seconds = 60, .consent_seconds = 120,
        .selected_native_context = .{ .owner_id = id[0..], .process_nonce = nonce[0..], .endpoint_generation = "1",
            .source_context_id = context[0..], .source_context_generation = "2" } }, .{});
    var parsed = try std.json.parseFromSlice(std.json.Value, a, encoded, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const selected = try acquisition.controlSelection(parsed.value);
    try std.testing.expectEqual(@as(u64, 2), selected.context.generation);
    try std.testing.expect(!selected.allow_reenrollment);
    inline for (.{ "source_path", "native_context", "owner_endpoint", "capability", "access_token" }) |field| {
        try parsed.value.object.put(a, field, .{ .string = "fixture-untrusted-locator" });
        try std.testing.expectError(error.InvalidParams, acquisition.controlSelection(parsed.value));
        _ = parsed.value.object.swapRemove(field);
    }
    try parsed.value.object.put(a, "native_access_copy", .{ .bool = false });
    try std.testing.expectError(error.NativeSourceConsentRequired, acquisition.controlSelection(parsed.value));
    try parsed.value.object.put(a, "native_access_copy", .{ .bool = true });
    inline for (.{ @as(i64, 0), @as(i64, 3601) }) |seconds| {
        try parsed.value.object.put(a, "custody_seconds", .{ .integer = seconds });
        try std.testing.expectError(error.InvalidParams, acquisition.controlSelection(parsed.value));
    }
    try parsed.value.object.put(a, "custody_seconds", .{ .integer = 60 });
    const selected_value = parsed.value.object.getPtr("selected_native_context").?;
    try selected_value.object.put(a, "source_context_generation", .{ .string = "02" });
    try std.testing.expectError(error.InvalidParams, acquisition.controlSelection(parsed.value));
    try selected_value.object.put(a, "source_context_generation", .{ .integer = 2 });
    try std.testing.expectError(error.InvalidNativeSourcePayload, acquisition.controlSelection(parsed.value));
}
test "signed reply fences payload and every retained operation authority" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const original = request();
    const key: [32]u8 = @splat(31);
    const reply = try acquisition.fixtureReply(a, original, key, payload);
    try acquisition.verifyReply(a, reply, original, key, payload);
    try std.testing.expectError(error.NativeSourceProofInvalid, acquisition.verifyReply(a, reply, original, @splat(32), payload));
    const changed_payload = "{\"tokens\":{\"access_token\":\"fixture-other-placeholder\"},\"expires_at\":90}";
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, original, key, changed_payload));
    inline for (.{ "source_generation", "consent_generation", "forget_epoch" }) |field| {
        var changed = original;
        @field(changed.admission, field) += 1;
        try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    }
    var changed = original;
    changed.admission.context.id = @splat(15);
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    changed = original;
    changed.admission.context.generation += 1;
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    changed = original;
    changed.admission.owner.nonce = @splat(16);
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    changed = original;
    changed.origin = @splat(17);
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    changed = original;
    changed.operation = @splat('b');
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
    changed = original;
    changed.consent_expires_at += 1;
    try std.testing.expectError(error.NativeSourceBindingChanged, acquisition.verifyReply(a, reply, changed, key, payload));
}
test "strict descriptor payload excludes renewal grants selection hints and unexpected schema" {
    const a = std.testing.allocator;
    var candidate = try acquisition.parsePayload(a, "fixture-source", payload, 10, 60);
    defer candidate.deinit();
    try std.testing.expect(!candidate.identity_verified);
    try std.testing.expectEqual(.external, candidate.ownership);
    try std.testing.expect(candidate.provider_account_id == null);
    try std.testing.expectEqual(@as(i64, 70), candidate.custody_expires_at);
    inline for (.{
        "{\"tokens\":{\"access_token\":\"fixture-access-placeholder\",\"refresh_token\":\"fixture-refresh-placeholder\"},\"expires_at\":90}",
        "{\"tokens\":{\"access_token\":\"fixture-access-placeholder\",\"account_id\":\"fixture-selection-placeholder\"},\"expires_at\":90}",
        "{\"tokens\":{\"access_token\":\"fixture-access-placeholder\"},\"expires_at\":90,\"extra\":false}",
        "{\"tokens\":{\"access_token\":\"fixture-access-placeholder\"},\"expires_at\":\"90\"}",
    }) |invalid| try std.testing.expectError(error.InvalidNativeSourcePayload, acquisition.parsePayload(a, "fixture-source", invalid, 10, 60));
    try std.testing.expectError(error.ExpiredCredential, acquisition.parsePayload(a, "fixture-source", payload, 90, 60));
    try std.testing.expectError(error.InvalidNativeSourcePayload, acquisition.parsePayload(a, "fixture-source", payload, 10, 3601));
}
test "descriptor read consumes actual owned fd on success and expired original cutoff" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const file = try directory.dir.createFile(io, "bounded-payload", .{ .read = true, .exclusive = true });
    defer file.close(io);
    try file.writeStreamingAll(io, payload);
    const current = std.c.dup(file.handle);
    if (current < 0) return error.FixtureDescriptorFailed;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(1000) });
    const bytes = try acquisition.readDescriptor(io, std.testing.allocator, current, until);
    defer { std.crypto.secureZero(u8, bytes); std.testing.allocator.free(bytes); }
    try std.testing.expectEqualStrings(payload, bytes);
    try std.testing.expectEqual(@as(c_int, -1), std.c.fcntl(current, std.c.F.GETFD));
    const expired_fd = std.c.dup(file.handle);
    if (expired_fd < 0) return error.FixtureDescriptorFailed;
    const expired: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(0) });
    try std.testing.expectError(error.NativeSourceDeadline, acquisition.readDescriptor(io, std.testing.allocator, expired_fd, expired));
    try std.testing.expectEqual(@as(c_int, -1), std.c.fcntl(expired_fd, std.c.F.GETFD));
}
