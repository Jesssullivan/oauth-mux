//! Normalized descriptor metadata. Zig 0.17 intentionally removed Linux
//! std.c.Stat/fstat wrappers; Linux uses the statx syscall and validates fields.
//! No ABI-shaped Linux struct stat, generated headers, or pathname fallback.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

pub const Metadata = struct {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: i64,
    ino: u64,
    dev: u64,
    mtime_ns: i128,
    ctime_ns: i128,
};

fn linuxMetadata(status: std.os.linux.Statx) !Metadata {
    const required: std.os.linux.STATX = .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true, .GID = true, .MTIME = true, .CTIME = true, .INO = true, .SIZE = true };
    const have: u32 = @bitCast(status.mask);
    const need: u32 = @bitCast(required);
    if (have & need != need) return error.MetadataUnavailable;
    if (status.size > std.math.maxInt(i64) or status.mtime.nsec >= std.time.ns_per_s or status.ctime.nsec >= std.time.ns_per_s) return error.InvalidFileMetadata;
    return .{
        .mode = status.mode,
        .uid = status.uid,
        .gid = status.gid,
        .nlink = status.nlink,
        .size = @intCast(status.size),
        .ino = status.ino,
        .dev = (@as(u64, status.dev_major) << 32) | status.dev_minor,
        .mtime_ns = @as(i128, status.mtime.sec) * std.time.ns_per_s + status.mtime.nsec,
        .ctime_ns = @as(i128, status.ctime.sec) * std.time.ns_per_s + status.ctime.nsec,
    };
}

fn darwinMetadata(status: c.Stat) Metadata {
    const mtime = status.mtime();
    const ctime = status.ctime();
    return .{
        .mode = status.mode,
        .uid = status.uid,
        .gid = status.gid,
        .nlink = status.nlink,
        .size = status.size,
        .ino = status.ino,
        .dev = @as(u32, @bitCast(status.dev)),
        .mtime_ns = @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec,
        .ctime_ns = @as(i128, ctime.sec) * std.time.ns_per_s + ctime.nsec,
    };
}

fn statFailure(result: c_int) anyerror {
    return switch (c.errno(result)) {
        .NOENT => error.FileNotFound,
        .ACCES => error.AccessDenied,
        else => error.PathStatFailed,
    };
}

fn linuxStatFailure(result: usize) anyerror {
    return switch (std.os.linux.errno(result)) {
        .NOENT => error.FileNotFound,
        .ACCES => error.AccessDenied,
        else => error.PathStatFailed,
    };
}

pub fn statFd(descriptor: c.fd_t) !Metadata {
    switch (builtin.os.tag) {
        .linux => {
            var status: std.os.linux.Statx = undefined;
            const result = std.os.linux.statx(descriptor, "", c.AT.EMPTY_PATH, std.os.linux.STATX.BASIC_STATS, &status);
            if (std.os.linux.errno(result) != .SUCCESS) return linuxStatFailure(result);
            return linuxMetadata(status);
        },
        .macos => {
            var status: c.Stat = undefined;
            const result = c.fstat(descriptor, &status);
            if (result != 0) return statFailure(result);
            return darwinMetadata(status);
        },
        else => return error.UnsupportedPlatform,
    }
}

/// Pass std.c.AT.SYMLINK_NOFOLLOW to inspect a directory entry itself.
pub fn statAt(directory: c.fd_t, path: [*:0]const u8, flags: u32) !Metadata {
    switch (builtin.os.tag) {
        .linux => {
            var status: std.os.linux.Statx = undefined;
            const result = std.os.linux.statx(directory, path, flags, std.os.linux.STATX.BASIC_STATS, &status);
            if (std.os.linux.errno(result) != .SUCCESS) return linuxStatFailure(result);
            return linuxMetadata(status);
        },
        .macos => {
            var status: c.Stat = undefined;
            const result = c.fstatat(directory, path, &status, @intCast(flags));
            if (result != 0) return statFailure(result);
            return darwinMetadata(status);
        },
        else => return error.UnsupportedPlatform,
    }
}

test "normalized metadata describes fixture fd and preserves nofollow inspection" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fixture", .data = "metadata" });
    const descriptor = c.openat(tmp.dir.handle, "fixture", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (descriptor < 0) return error.FixtureOpenFailed;
    defer _ = c.close(descriptor);
    const status = try statFd(descriptor);
    try std.testing.expectEqual(@as(u32, c.S.IFREG), status.mode & c.S.IFMT);
    try std.testing.expectEqual(@as(i64, 8), status.size);
    try std.testing.expectEqual(c.getuid(), status.uid);
    if (c.symlinkat("fixture", tmp.dir.handle, "alias") != 0) return error.FixtureSymlinkFailed;
    const alias = try statAt(tmp.dir.handle, "alias", c.AT.SYMLINK_NOFOLLOW);
    try std.testing.expectEqual(@as(u32, c.S.IFLNK), alias.mode & c.S.IFMT);
    const target = try statAt(tmp.dir.handle, "alias", 0);
    try std.testing.expectEqual(status.ino, target.ino);
    try std.testing.expectEqual(status.dev, target.dev);
}

test "missing required statx fields fail closed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var status: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
    try std.testing.expectError(error.MetadataUnavailable, linuxMetadata(status));
    status.mask = std.os.linux.STATX.BASIC_STATS;
    status.mtime.nsec = std.time.ns_per_s;
    try std.testing.expectError(error.InvalidFileMetadata, linuxMetadata(status));
}
