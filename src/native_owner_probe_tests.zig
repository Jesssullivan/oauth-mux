//! R-N13: native owner wire and actual private endpoint predicates. Synthetic
//! endpoint ACKs do not establish ordinary-launch or same-process continuity.
const std = @import("std");
const builtin = @import("builtin");
const probe = @import("integrations/native_probe.zig");
const native_owner = @import("native_owner.zig");
const fixture_mod = @import("native_owner_fixture.zig");
const peer = @import("platform/peer.zig");

fn requestFor(identity: probe.OwnerIdentity, operation: native_owner.OperationId) probe.OwnerRequest {
    return .{
        .reference = .{ .owner_id = identity.owner_id, .adapter_epoch = 9, .endpoint_generation = identity.endpoint_generation, .thread_instance_generation = identity.thread_instance_generation, .attachment_generation = 9007199254740993 },
        .thread_id = identity.thread_id,
        .native_nonce = identity.native_nonce,
        .operation_id = operation,
        .broker_socket = "/tmp/fixture-owner/adapter.sock",
        .capability_path = "/tmp/fixture-owner/codex.capability",
    };
}

test "native owner generations are exact nonzero canonical u64 strings" {
    try std.testing.expectEqual(@as(u64, 9007199254740993), try probe.parseOwnerGeneration(.{ .string = "9007199254740993" }));
    try std.testing.expectEqual(std.math.maxInt(u64), try probe.parseOwnerGeneration(.{ .string = "18446744073709551615" }));
    for ([_][]const u8{ "", "0", "00", "01", "+1", "-1", " 1", "1 ", "1.0", "1e3", "18446744073709551616" }) |encoded| {
        try std.testing.expectError(error.InvalidNativeOwnerGeneration, probe.parseOwnerGeneration(.{ .string = encoded }));
    }
    try std.testing.expectError(error.InvalidNativeOwnerGeneration, probe.parseOwnerGeneration(.{ .integer = 1 }));
    try std.testing.expectError(error.InvalidNativeOwnerGeneration, probe.parseOwnerGeneration(.{ .float = 9007199254740992 }));
    try std.testing.expectError(error.InvalidNativeOwnerGeneration, probe.parseOwnerGeneration(.null));
}

test "native owner structural reference never rounds or accepts alternate hex" {
    const allocator = std.testing.allocator;
    const owner_hex = std.fmt.bytesToHex(@as([32]u8, @splat(0xab)), .lower);
    const encoded = try std.json.Stringify.valueAlloc(allocator, .{
        .ownerId = owner_hex[0..],
        .adapterEpoch = "9007199254740993",
        .endpointGeneration = "18446744073709551615",
        .threadInstanceGeneration = "3",
        .attachmentGeneration = "4",
    }, .{});
    defer allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const reference = try probe.decodeOwnerReference(parsed.value);
    try std.testing.expectEqual(@as(u64, 9007199254740993), reference.adapter_epoch);
    try std.testing.expectEqual(std.math.maxInt(u64), reference.endpoint_generation);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xab)), &reference.owner_id);

    // These JSON documents carry no runtime peer context. The public decoder
    // is only a structural boundary, never an attachment admission gate.
    for ([_][]const u8{
        "{\"ownerId\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"adapterEpoch\":\"1\",\"endpointGeneration\":\"1\",\"threadInstanceGeneration\":\"1\",\"attachmentGeneration\":\"1\"}",
        "{\"ownerId\":\"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB\",\"adapterEpoch\":\"1\",\"endpointGeneration\":\"1\",\"threadInstanceGeneration\":\"1\",\"attachmentGeneration\":\"1\"}",
    }) |invalid| {
        var invalid_parsed = try std.json.parseFromSlice(std.json.Value, allocator, invalid, .{});
        defer invalid_parsed.deinit();
        try std.testing.expectError(error.InvalidNativeOwnerHex, probe.decodeOwnerReference(invalid_parsed.value));
    }
}

test "unsupported native owner platform refuses before endpoint or deadline I/O" {
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    const expired = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.UnsupportedPeerProfile, probe.OwnerConnection.open(std.testing.io, std.testing.allocator, "/tmp/../unread-owner", null, expired));
}

test "native owner request rejects invalid thread and operation before effect" {
    const reference: native_owner.NativeRef = .{ .owner_id = @splat(1), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var request: probe.OwnerRequest = .{ .reference = reference, .thread_id = "thread", .native_nonce = @splat(2), .operation_id = @splat('a') };
    try request.validate();
    request.thread_id = "";
    try std.testing.expectError(error.InvalidNativeOwnerThread, request.validate());
    request.thread_id = "thread\x01";
    try std.testing.expectError(error.InvalidNativeOwnerThread, request.validate());
    request.thread_id = "thread";
    request.operation_id = @splat('A');
    try std.testing.expectError(error.InvalidNativeOperation, request.validate());
    request.operation_id = @splat('a');
    request.native_nonce = @splat(0);
    try std.testing.expectError(error.InvalidNativeOwnerNonce, request.validate());
}

test "actual native owner packet channel retains peer across exact register and new-operation detach" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, allocator, .{
        .endpoint_generation = 9007199254740993,
        .thread_instance_generation = std.math.maxInt(u64),
    });
    defer fixture.destroy();
    var connection = try probe.OwnerConnection.open(std.testing.io, allocator, fixture.endpoint, null, null);
    defer connection.deinit();
    const operation: native_owner.OperationId = @splat('a');
    var identity = try connection.identify("existing-native-thread", operation);
    defer identity.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 9007199254740993), identity.endpoint_generation);
    try std.testing.expectEqual(std.math.maxInt(u64), identity.thread_instance_generation);
    try std.testing.expectEqualSlices(u8, &fixture.owner_id, &identity.owner_id);
    try std.testing.expectEqualSlices(u8, &fixture.native_nonce, &identity.native_nonce);
    try std.testing.expect(peer.sameOriginal(identity.witness, try connection.verifiedWitness()));
    var request = requestFor(identity, operation);
    var registered = try connection.register(request, identity.witness);
    defer registered.deinit(allocator);
    try std.testing.expect(registered.reference.same(request.reference));
    try std.testing.expectEqualSlices(u8, &request.native_nonce, &registered.native_nonce);
    try std.testing.expectEqualSlices(u8, &operation, &registered.operation_id);
    try std.testing.expectEqual(probe.OwnerAction.register, registered.action);
    try std.testing.expect(peer.sameOriginal(identity.witness, registered.witness));

    request.operation_id = @splat('b');
    request.broker_socket = null;
    request.capability_path = null;
    var detached = try connection.detach(request, identity.witness);
    defer detached.deinit(allocator);
    try std.testing.expect(detached.reference.same(registered.reference));
    try std.testing.expectEqualSlices(u8, &request.operation_id, &detached.operation_id);
    try std.testing.expectEqual(probe.OwnerAction.detach, detached.action);
    try std.testing.expect(peer.sameOriginal(registered.witness, detached.witness));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.unregister));
}

test "actual native owner packet effects refuse mismatched or ambiguous ACK and poison connection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = .{
        .{ fixture_mod.Mode.wrong_nonce, error.NativeOwnerReferenceMismatch },
        .{ fixture_mod.Mode.wrong_operation, error.NativeOwnerOperationMismatch },
        .{ fixture_mod.Mode.wrong_owner, error.NativeOwnerReferenceMismatch },
        .{ fixture_mod.Mode.wrong_generation, error.NativeOwnerReferenceMismatch },
        .{ fixture_mod.Mode.numeric_generation, error.InvalidNativeOwnerGeneration },
        .{ fixture_mod.Mode.duplicate_keys, error.DuplicateField },
        .{ fixture_mod.Mode.wrong_thread, error.NativeOwnerThreadMismatch },
        .{ fixture_mod.Mode.false_success, error.NativeOwnerRejected },
        .{ fixture_mod.Mode.protocol_v1, error.NativeOwnerProtocolRequired },
        .{ fixture_mod.Mode.ambiguous_envelope, error.InvalidNativeOwnerAck },
        .{ fixture_mod.Mode.server_request, error.InvalidNativeOwnerAck },
        .{ fixture_mod.Mode.noncanonical_generation, error.InvalidNativeOwnerGeneration },
        .{ fixture_mod.Mode.oversized_packet, error.PeerMessageTruncated },
    };
    inline for (cases) |case| {
        for ([_]bool{ false, true }) |detach| {
            const allocator = std.testing.allocator;
            const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, allocator, .{ .mode = case[0] });
            defer fixture.destroy();
            var connection = try probe.OwnerConnection.open(std.testing.io, allocator, fixture.endpoint, null, null);
            defer connection.deinit();
            var identity = try connection.identify("existing-native-thread", @splat('a'));
            defer identity.deinit(allocator);
            const request = requestFor(identity, @splat('b'));
            if (detach) {
                try std.testing.expectError(case[1], connection.detach(request, identity.witness));
            } else {
                try std.testing.expectError(case[1], connection.register(request, identity.witness));
            }
            try std.testing.expectError(error.NativeOwnerConnectionFailed, connection.verifiedWitness());
            try std.testing.expectError(error.NativeOwnerConnectionFailed, connection.register(request, identity.witness));
            try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(if (detach) .unregister else .register));
            try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(if (detach) .register else .unregister));
        }
    }
}

test "native owner saved witness mismatch refuses before first protocol packet" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const fixture = try fixture_mod.Fixture.create(std.testing.io, allocator);
    defer fixture.destroy();
    var initial = try probe.OwnerConnection.open(std.testing.io, allocator, fixture.endpoint, null, null);
    defer initial.deinit();
    var wrong = try initial.verifiedWitness();
    wrong.pidfs_inode = if (wrong.pidfs_inode == std.math.maxInt(u64)) wrong.pidfs_inode - 1 else wrong.pidfs_inode + 1;
    try std.testing.expectError(error.NativeOwnerPeerMismatch, probe.OwnerConnection.open(std.testing.io, allocator, fixture.endpoint, wrong, null));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.announce));
}

test "native owner announce ACK is exact synthetic transport and not actor admission" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, allocator, .{ .endpoint_generation = 9007199254740993 });
    defer fixture.destroy();
    var connection = try probe.OwnerConnection.open(std.testing.io, allocator, fixture.endpoint, null, null);
    defer connection.deinit();
    const operation: native_owner.OperationId = @splat('a');
    var announced = try connection.announce("existing-native-thread", operation, .{
        .broker_socket = "/tmp/fixture-owner/adapter.sock",
        .capability_path = "/tmp/fixture-owner/codex.capability",
    });
    defer announced.deinit(allocator);
    try std.testing.expectEqual(probe.OwnerAction.announce, announced.action);
    try std.testing.expectEqualSlices(u8, &fixture.owner_id, &announced.reference.owner_id);
    try std.testing.expectEqualSlices(u8, &fixture.native_nonce, &announced.native_nonce);
    try std.testing.expectEqualSlices(u8, &operation, &announced.operation_id);
    try std.testing.expectEqual(@as(u64, 9007199254740993), announced.reference.endpoint_generation);
    try std.testing.expectEqualStrings("existing-native-thread", announced.thread_id);
    try std.testing.expect(peer.sameOriginal(try connection.verifiedWitness(), announced.witness));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.announce));
    // The synthetic response has no persisted engine registration row. Actor
    // callback/admission predicates belong to separate integration tests.
}

test "primary owner inspection and thread discovery remain authenticated read-only metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, allocator, .{
        .endpoint_generation = 9007199254740993,
        .thread_instance_generation = std.math.maxInt(u64),
    });
    defer fixture.destroy();
    const info = try probe.inspectOwner(std.testing.io, allocator, fixture.endpoint, "fixture-omux");
    defer info.deinit(allocator);
    try std.testing.expect(info.native_discovery);
    try std.testing.expect(info.native_version.len > 0 and info.native_version.len <= probe.maximum_native_version_bytes);
    try std.testing.expectEqual(@import("integrations/codex.zig").Support.compatible_hook, info.support);
    try std.testing.expectEqualSlices(u8, &fixture.owner_id, &info.owner_id);
    try std.testing.expectEqualSlices(u8, &fixture.native_nonce, &info.native_nonce);
    try std.testing.expectEqual(@as(u64, 9007199254740993), info.endpoint_generation);
    const loaded = try probe.loadedOwnerThreads(std.testing.io, allocator, fixture.endpoint, "fixture-omux");
    defer loaded.deinit(allocator);
    try std.testing.expectEqual(info.support, loaded.support);
    try std.testing.expectEqualStrings(info.native_version, loaded.native_version);
    try std.testing.expectEqualStrings(fixture.endpoint, loaded.socket_path);
    try std.testing.expectEqualSlices(u8, &info.owner_id, &loaded.owner_id);
    try std.testing.expectEqualSlices(u8, &info.native_nonce, &loaded.native_nonce);
    try std.testing.expectEqual(info.endpoint_generation, loaded.endpoint_generation);
    try std.testing.expect(peer.sameOriginal(info.witness, loaded.witness));
    try std.testing.expectEqual(@as(usize, 1), loaded.threads.len);
    try std.testing.expectEqual(loaded.threads.len, loaded.thread_ids.len);
    try std.testing.expectEqualStrings(loaded.threads[0].thread_id, loaded.thread_ids[0]);
    try std.testing.expectEqual(std.math.maxInt(u64), loaded.threads[0].thread_instance_generation);
    try std.testing.expect(loaded.threads[0].attachment_generation != 0);
    try std.testing.expectEqual(@as(usize, 2), fixture.methodCount(.capabilities));
    try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.threads));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.announce));
    // Neither a compatible capability flag nor a reserved attachment
    // generation creates a persisted registration or a live continuity proof.
}

test "owner endpoint availability with absent hooks remains unsupported metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, allocator, .{ .mode = .stock_capabilities });
    defer fixture.destroy();
    const info = try probe.inspectOwner(std.testing.io, allocator, fixture.endpoint, "fixture-omux");
    defer info.deinit(allocator);
    try std.testing.expect(info.native_discovery);
    try std.testing.expectEqual(@import("integrations/codex.zig").Support.native_unsupported, info.support);
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.announce));
}

test "owner read-only capabilities refuse malformed schema before effects" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = .{
        .{ fixture_mod.Mode.capabilities_extra, error.InvalidNativeOwnerAck },
        .{ fixture_mod.Mode.capabilities_missing, error.InvalidNativeOwnerAck },
        .{ fixture_mod.Mode.capabilities_nonboolean, error.InvalidNativeOwnerCapabilities },
        .{ fixture_mod.Mode.native_version_oversized, error.InvalidNativeVersion },
    };
    inline for (cases) |case| {
        const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, std.testing.allocator, .{ .mode = case[0] });
        defer fixture.destroy();
        try std.testing.expectError(case[1], probe.inspectOwner(std.testing.io, std.testing.allocator, fixture.endpoint, "fixture-omux"));
        try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.capabilities));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.threads));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.register));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.unregister));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.announce));
    }
}

test "owner read-only thread discovery refuses invalid or oversized rows before effects" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = .{
        .{ fixture_mod.Mode.threads_extra, error.InvalidNativeOwnerAck },
        .{ fixture_mod.Mode.threads_duplicate, error.InvalidThreadList },
        .{ fixture_mod.Mode.threads_numeric_generation, error.InvalidNativeOwnerGeneration },
        .{ fixture_mod.Mode.threads_zero_generation, error.InvalidNativeOwnerGeneration },
        .{ fixture_mod.Mode.threads_oversized_packet, error.PeerMessageTruncated },
        .{ fixture_mod.Mode.threads_identity_mismatch, error.NativeOwnerIdentityMismatch },
    };
    inline for (cases) |case| {
        const fixture = try fixture_mod.Fixture.createWithOptions(std.testing.io, std.testing.allocator, .{ .mode = case[0], .owner_id = @splat(1), .process_nonce = @splat(2) });
        defer fixture.destroy();
        try std.testing.expectError(case[1], probe.loadedOwnerThreads(std.testing.io, std.testing.allocator, fixture.endpoint, "fixture-omux"));
        try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.capabilities));
        try std.testing.expectEqual(@as(usize, 1), fixture.methodCount(.threads));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.register));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.unregister));
        try std.testing.expectEqual(@as(usize, 0), fixture.methodCount(.announce));
    }
}
