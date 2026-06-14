const std = @import("std");

/// Stable, non-secret account-id hash: lowercase hex of the first 6 bytes of
/// SHA-256 → 12 hex chars ("sha256_12hex"). Shared by the codex account
/// inventory (src/main.zig) and the muxxing identity guard (the codex adapter,
/// TIN-1851) so both compute the SAME identity key for an upstream account id.
/// Golden vector: sha256_12hex("acct-test") == "660d25a9d7ee".
pub fn sha256_12hex(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const out = try allocator.alloc(u8, 12);
    _ = std.fmt.bufPrint(out, "{x}", .{std.fmt.fmtSliceHexLower(digest[0..6])}) catch unreachable;
    return out;
}

test "sha256_12hex golden vector" {
    const h = try sha256_12hex(std.testing.allocator, "acct-test");
    defer std.testing.allocator.free(h);
    try std.testing.expectEqualStrings("660d25a9d7ee", h);
}

test "sha256_12hex is stable and distinct per input" {
    const a = std.testing.allocator;
    const h1 = try sha256_12hex(a, "account-one");
    defer a.free(h1);
    const h2 = try sha256_12hex(a, "account-one");
    defer a.free(h2);
    const h3 = try sha256_12hex(a, "account-two");
    defer a.free(h3);
    try std.testing.expectEqualStrings(h1, h2);
    try std.testing.expect(!std.mem.eql(u8, h1, h3));
    try std.testing.expectEqual(@as(usize, 12), h1.len);
}
