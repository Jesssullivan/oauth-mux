const std = @import("std");
const builtin = @import("builtin");

pub const AuthorityError = error{
    UnsupportedPlatform,
    AccountAuthorityUnavailable,
    OutOfMemory,
};

const MacosAuthority = if (builtin.os.tag == .macos) struct {
    extern "c" fn geteuid() std.c.uid_t;
    extern "c" fn getpwuid_r(
        uid: std.c.uid_t,
        record: *std.c.passwd,
        buffer: [*]u8,
        buffer_len: usize,
        result: *?*std.c.passwd,
    ) c_int;
} else struct {};

/// Return the effective macOS account name from kernel/passwd authority.
/// Environment variables are deliberately not inputs: USER and LOGNAME are
/// child presentation values and can be stale or caller-controlled.
pub fn effectiveUserNameAlloc(allocator: std.mem.Allocator) AuthorityError![]u8 {
    if (comptime builtin.os.tag == .macos) {
        var record: std.c.passwd = undefined;
        var result: ?*std.c.passwd = null;
        var buffer: [16 * 1024]u8 = undefined;
        if (MacosAuthority.getpwuid_r(
            MacosAuthority.geteuid(),
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
    return error.UnsupportedPlatform;
}

test "effective macOS account authority is nonempty" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const account = try effectiveUserNameAlloc(std.testing.allocator);
    defer std.testing.allocator.free(account);
    try std.testing.expect(account.len != 0);
}
