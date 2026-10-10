const std = @import("std");
const consent = @import("native_source_consent.zig");
const domain = @import("domain.zig");

fn fixture() consent.Current {
    const owner: consent.Owner = .{ .id = @splat(1), .nonce = @splat(2), .endpoint_generation = 1,
        .witness = .{ .profile = .linux_pidfs64_v1, .boot_id = @splat(3), .pidfs_device = 4,
            .pidfs_inode = 5, .user_namespace = .{ .device = 6, .inode = 7 },
            .pid_namespace = .{ .device = 8, .inode = 9 }, .uid = 10, .gid = 10 } };
    return .{ .source_id = @splat(11), .source_generation = 1, .status = .connected,
        .owner = owner, .context = .{ .id = @splat(12), .generation = 1 }, .store_present = true,
        .forget_epoch = 0, .consent = .{ .id = @splat(13), .generation = 1, .source_id = @splat(11),
            .source_generation = 1, .owner = owner, .expires_at = 100,
            .purpose = .native_access_copy_for_identity_and_request, .forget_epoch = 0 } };
}
test "available native metadata is not read consent and initial hint cannot select rotated context" {
    var current = fixture();
    current.consent = null;
    try std.testing.expectError(error.NativeSourceConsentRequired, consent.admit(current, 10, 10, 50));
    current = fixture();
    const pending = try consent.admit(current, 10, 10, 50);
    current.context = .{ .id = @splat(14), .generation = 2 };
    try std.testing.expectError(error.NativeSourceContextChanged, consent.check(pending, current, 10, 11));
    const next = try consent.admit(current, 10, 11, 50);
    try std.testing.expectError(error.NativeSourceContextChanged, consent.checkMaterialized(next, current,
        .{ .owner = current.owner, .context = pending.context }, 10, 12));
    try consent.checkMaterialized(next, current, .{ .owner = current.owner, .context = current.context }, 10, 12);
}
test "owner incarnation, consent replacement, source reconnect and expiry fence pending adoption" {
    const original = fixture();
    const pending = try consent.admit(original, 10, 10, 50);
    var current = original;
    current.owner.witness.pidfs_inode += 1;
    try std.testing.expectError(error.NativeSourceUnauthorized, consent.check(pending, current, 10, 11));
    current.consent.?.owner = current.owner; // New explicit grant still cannot revive old operation.
    try std.testing.expectError(error.NativeSourceOwnerChanged, consent.check(pending, current, 10, 11));
    current = original;
    current.consent.?.generation += 1;
    try std.testing.expectError(error.NativeSourceSuperseded, consent.check(pending, current, 10, 11));
    current = original;
    current.status = .disconnected;
    try std.testing.expectError(error.NativeSourceUnauthorized, consent.check(pending, current, 10, 11));
    current.status = .connected;
    current.source_generation += 1;
    current.consent.?.source_generation = current.source_generation;
    try std.testing.expectError(error.NativeSourceSuperseded, consent.check(pending, current, 10, 11));
    try std.testing.expectError(error.NativeSourceDeadline, consent.check(pending, original, 10, 50));
    try std.testing.expectError(error.NativeSourceUnauthorized, consent.check(pending, original, 100, 11));
}
test "forget after admission cannot borrow prior reenrollment permission" {
    var current = fixture();
    const automatic = try consent.admit(current, 10, 10, 50);
    try std.testing.expectError(error.NativeSourceTombstoned, consent.checkEnrollment(automatic, current, true, 10, 11));
    current.consent.?.allow_reenrollment = true;
    current.consent.?.generation += 1;
    const explicit = try consent.admit(current, 10, 11, 50);
    try consent.checkEnrollment(explicit, current, true, 10, 12);
    current.forget_epoch += 1;
    current.consent.?.forget_epoch = current.forget_epoch;
    current.consent.?.generation += 1;
    try std.testing.expectError(error.NativeSourceSuperseded, consent.checkEnrollment(explicit, current, true, 10, 13));
}
test "native source detachment retains grants; disconnect preserves independent grant and external renewal owner" {
    var state = domain.State.init(std.testing.allocator);
    defer state.deinit();
    const identity: domain.Identity = .{ .provider = "codex", .issuer = "https://chatgpt.com",
        .subject = "synthetic-subject", .tenant = "synthetic-tenant", .verified = true };
    _ = try state.connectSource(.{ .id = "native", .kind = .native_store, .provider = "codex" });
    _ = try state.connectSource(.{ .id = "independent", .kind = .explicit, .provider = "codex" });
    _ = try state.enroll(.{ .account_id = "account", .source_id = "native", .identity = identity }, 10);
    _ = try state.enroll(.{ .account_id = "duplicate", .source_id = "independent", .identity = identity }, 10);
    for ([_][]const u8{ "native", "independent" }) |source| {
        _ = try state.addGrant(.{ .id = source, .account_id = "account", .source_id = source,
            .credential_kind = .oauth_access, .ownership = .external, .purposes = &.{.request},
            .audience = "https://chatgpt.com" });
    }
    try state.detachSource("native");
    try std.testing.expectEqual(.ready, state.grant("native").?.status);
    try state.disconnectSource("native");
    try std.testing.expectEqual(.invalid, state.grant("native").?.status);
    try std.testing.expectEqual(.ready, state.grant("independent").?.status);
    try std.testing.expectError(error.OwnershipRequired, state.reconcile(.{ .grant_id = "independent",
        .expected_generation = 1, .next_generation = 2, .status = .refreshing }));
    try std.testing.expectEqual(.external, state.grant("independent").?.ownership);
    try state.forget("account");
    try std.testing.expect(state.grant("native") == null and state.grant("independent") == null);
    const reenroll: domain.Enrollment = .{ .account_id = "reenrolled", .source_id = "independent", .identity = identity };
    try std.testing.expectEqual(.tombstoned, (try state.enroll(reenroll, 11)).status);
    try state.permitReenrollment(identity, "independent", 11);
    try std.testing.expectEqual(.enrolled, (try state.enroll(reenroll, 11)).status);
}
