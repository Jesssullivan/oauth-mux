const std = @import("std");
const builtin = @import("builtin");

pub const AuthorityError = error{
    UnsupportedPlatform,
    AccountAuthorityUnavailable,
    OutOfMemory,
};

const PosixAuthority = if (builtin.os.tag == .macos or builtin.os.tag == .linux) struct {
    extern "c" fn geteuid() std.c.uid_t;
    extern "c" fn getpwuid_r(
        uid: std.c.uid_t,
        record: *std.c.passwd,
        buffer: [*]u8,
        buffer_len: usize,
        result: *?*std.c.passwd,
    ) c_int;
} else struct {};

fn effectiveUid() std.posix.uid_t {
    if (comptime builtin.os.tag == .linux and !builtin.link_libc)
        return std.os.linux.geteuid();
    return @intCast(PosixAuthority.geteuid());
}

fn userNameForUidAlloc(
    allocator: std.mem.Allocator,
    passwd: []const u8,
    uid: std.posix.uid_t,
) AuthorityError![]u8 {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const uid_text = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const candidate = std.fmt.parseInt(std.posix.uid_t, uid_text, 10) catch continue;
        if (candidate != uid or name.len == 0) continue;
        return allocator.dupe(u8, name) catch error.OutOfMemory;
    }
    return error.AccountAuthorityUnavailable;
}

/// Return the effective POSIX account name from kernel/passwd authority.
/// Environment variables are deliberately not inputs: USER and LOGNAME are
/// child presentation values and can be stale or caller-controlled.
pub fn effectiveUserNameAlloc(allocator: std.mem.Allocator) AuthorityError![]u8 {
    if (comptime builtin.os.tag == .macos) {
        var record: std.c.passwd = undefined;
        var result: ?*std.c.passwd = null;
        var buffer: [16 * 1024]u8 = undefined;
        if (PosixAuthority.getpwuid_r(
            PosixAuthority.geteuid(),
            &record,
            &buffer,
            buffer.len,
            &result,
        ) != 0 or result == null) return error.AccountAuthorityUnavailable;
        const name_ptr = record.name orelse return error.AccountAuthorityUnavailable;
        const name = std.mem.span(name_ptr);
        if (name.len == 0) return error.AccountAuthorityUnavailable;
        return allocator.dupe(u8, name) catch error.OutOfMemory;
    }
    if (comptime builtin.os.tag == .linux) {
        const file = std.fs.openFileAbsolute("/etc/passwd", .{}) catch
            return error.AccountAuthorityUnavailable;
        defer file.close();
        const passwd = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.AccountAuthorityUnavailable,
        };
        defer allocator.free(passwd);
        return userNameForUidAlloc(allocator, passwd, effectiveUid());
    }
    return error.UnsupportedPlatform;
}

test "effective POSIX account authority is nonempty" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
        return error.SkipZigTest;
    const account = try effectiveUserNameAlloc(std.testing.allocator);
    defer std.testing.allocator.free(account);
    try std.testing.expect(account.len != 0);
}

test "passwd lookup matches the exact uid and ignores malformed rows" {
    const passwd =
        \\prefix:x:not-a-uid:1::/tmp:/bin/false
        \\truncated:x:420
        \\other:x:42:1::/tmp:/bin/false
        \\target:x:420:1::/tmp:/bin/false
        \\target-suffix:x:4200:1::/tmp:/bin/false
    ;
    const account = try userNameForUidAlloc(std.testing.allocator, passwd, 420);
    defer std.testing.allocator.free(account);
    try std.testing.expectEqualStrings("target", account);
    try std.testing.expectError(
        error.AccountAuthorityUnavailable,
        userNameForUidAlloc(std.testing.allocator, passwd, 7),
    );
}
