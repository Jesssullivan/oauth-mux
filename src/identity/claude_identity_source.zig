//! Bounded filesystem source for Claude's stable account identity.
//!
//! This module reads only `<config_dir>/.claude.json` and delegates profile
//! interpretation to `claude_identity.parseClaudeIdentity`. It never consults
//! the account credential backend, keychain, or provider network. Unavailable
//! or unusable profiles stay opaque (`null`); allocator exhaustion propagates.

const std = @import("std");
const claude_identity = @import("claude_identity.zig");
const paths = @import("../paths.zig");

const max_profile_bytes = 1024 * 1024;

/// Read the stable identity hash from an account-scoped Claude profile.
/// Caller owns the returned hash. Missing files, malformed JSON, absent
/// `oauthAccount`, and absent/empty `accountUuid` all return null.
pub fn readAccountIdentityHash(
    allocator: std.mem.Allocator,
    config_dir: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    const raw_dir = config_dir orelse return null;
    const dir = paths.absolutePath(allocator, raw_dir) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer allocator.free(dir);

    const profile_path = try std.fs.path.join(allocator, &.{ dir, ".claude.json" });
    defer allocator.free(profile_path);
    const raw = (try readSmallFileMaybe(allocator, profile_path)) orelse return null;
    defer allocator.free(raw);

    var identity = claude_identity.parseClaudeIdentity(allocator, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer identity.deinit(allocator);
    if (!identity.present) return null;
    const hash = identity.account_id_hash orelse return null;
    if (hash.len == 0) return null;

    // Transfer the parser-owned hash while releasing its diagnostic fields.
    identity.account_id_hash = null;
    return hash;
}

fn readSmallFileMaybe(
    allocator: std.mem.Allocator,
    path: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    return file.readToEndAlloc(allocator, max_profile_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
}

fn writeTestProfile(dir: std.fs.Dir, raw: []const u8) !void {
    const file = try dir.createFile(".claude.json", .{ .truncate = true });
    defer file.close();
    try file.writeAll(raw);
}

test "Claude identity source reads a bounded account-scoped profile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestProfile(tmp.dir,
        \\{"oauthAccount":{"accountUuid":"acct-test"}}
    );
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);

    const hash = (try readAccountIdentityHash(std.testing.allocator, dir)).?;
    defer std.testing.allocator.free(hash);
    try std.testing.expectEqualStrings("660d25a9d7ee", hash);
}

test "Claude identity source keeps unavailable and unusable profiles opaque" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);

    try std.testing.expect((try readAccountIdentityHash(std.testing.allocator, null)) == null);
    try std.testing.expect((try readAccountIdentityHash(std.testing.allocator, dir)) == null);

    const unusable = [_][]const u8{
        "{",
        "{}",
        \\{"oauthAccount":{}}
        ,
        \\{"oauthAccount":{"accountUuid":""}}
        ,
    };
    for (unusable) |raw| {
        try writeTestProfile(tmp.dir, raw);
        try std.testing.expect((try readAccountIdentityHash(std.testing.allocator, dir)) == null);
    }
}

test "Claude identity source rejects profiles above its read bound" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(".claude.json", .{});
    defer file.close();
    try file.setEndPos(max_profile_bytes + 1);
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);

    try std.testing.expect((try readAccountIdentityHash(std.testing.allocator, dir)) == null);
}

test "Claude identity source propagates allocator exhaustion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);

    var storage: [1]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    try std.testing.expectError(
        error.OutOfMemory,
        readAccountIdentityHash(fixed.allocator(), dir),
    );
}
