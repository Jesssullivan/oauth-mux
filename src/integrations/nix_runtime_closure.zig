//! Authenticated direct-main Nix closure recheck. Registration and ELF graph
//! qualification belong to the genuine producer; this module never infers them.
const std = @import("std");
const c = std.c;
const metadata = @import("../platform/file_metadata.zig");

pub const maximum_files = 32;
pub const maximum_aliases = 32;
pub const maximum_edges = 64;
pub const maximum_file_bytes = 128 * 1024 * 1024;
pub const maximum_payload_bytes = 256 * 1024 * 1024;
pub const Root = struct { path: []const u8, status: metadata.Metadata };
pub const File = struct { path: []const u8, sha256: [32]u8, bytes: u64, status: metadata.Metadata };
pub const Alias = struct { path: []const u8, target: []const u8, status: metadata.Metadata };
pub const Edge = struct { source_index: u8, needed: []const u8, target_index: u8 };
pub const Record = struct {
    // Static registered ELF graph does not prove actual loader lookup. A later
    // version-bound runtime qualifier must independently establish that proof.
    loader_lookup_qualified: bool = false,
    registration_receipt_sha256: [32]u8,
    original_interpreter: []const u8,
    interpreter_file_index: u8,
    roots: []const Root,
    files: []const File,
    aliases: []const Alias,
    edges: []const Edge,
};

fn check(io: std.Io, until: ?std.Io.Clock.Timestamp) !void {
    try io.checkCancel();
    const deadline = until orelse return error.InvalidDeadline;
    if (deadline.clock != .awake) return error.InvalidDeadline;
    if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
}
fn canonical(path: []const u8) !void {
    if (!std.mem.startsWith(u8, path, "/nix/store/") or path.len > 4096 or path.len <= 44) return error.InvalidNixRuntimeClosure;
    var parts = std.mem.splitScalar(u8, path[11..], '/');
    const root = parts.next() orelse return error.InvalidNixRuntimeClosure;
    if (root.len < 34 or root[32] != '-') return error.InvalidNixRuntimeClosure;
    if (root.len > 255) return error.InvalidNixRuntimeClosure;
    for (root[33..]) |ch| if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "+._-", ch) == null) return error.InvalidNixRuntimeClosure;
    for (root[0..32]) |ch| if (std.mem.indexOfScalar(u8, "0123456789abcdfghijklmnpqrsvwxyz", ch) == null) return error.InvalidNixRuntimeClosure;
    for (path) |ch| if (ch < 32 or ch >= 127 or ch == '\\') return error.InvalidNixRuntimeClosure;
    while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidNixRuntimeClosure;
}
fn immutable(status: metadata.Metadata, kind: u32) !void {
    if (status.uid != 0 or status.mode & c.S.IFMT != kind or
        (kind != c.S.IFLNK and status.mode & 0o222 != 0)) return error.UnsafeNixRuntimeClosure;
}

/// Traverse only explicit selected names. The store parent is root-owned; each
/// selected derivation and nested directory is immutable and no-follow.
fn openParent(io: std.Io, allocator: std.mem.Allocator, until: ?std.Io.Clock.Timestamp, path: []const u8) !struct { fd: c.fd_t, name: [:0]u8 } {
    try canonical(path);
    var fd = c.open("/nix/store", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.NixRuntimeUnavailable;
    errdefer _ = c.close(fd);
    const store = try metadata.statFd(fd);
    if (store.uid != 0 or store.mode & c.S.IFMT != c.S.IFDIR or store.mode & 0o6002 != 0 or
        (store.mode & 0o020 != 0 and store.mode & 0o1000 == 0)) return error.UnsafeNixRuntimeClosure;
    var parts = std.mem.splitScalar(u8, path[11..], '/');
    while (parts.next()) |part| {
        try check(io, until);
        if (parts.peek() == null) return .{ .fd = fd, .name = try allocator.dupeSentinel(u8, part, 0) };
        const name = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(name);
        const next = c.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0) return error.NixRuntimeUnavailable;
        errdefer _ = c.close(next);
        try immutable(try metadata.statFd(next), c.S.IFDIR);
        _ = c.close(fd);
        fd = next;
    }
    return error.InvalidNixRuntimeClosure;
}
fn open(io: std.Io, allocator: std.mem.Allocator, until: ?std.Io.Clock.Timestamp, path: []const u8, directory: bool) !c.fd_t {
    const parent = try openParent(io, allocator, until, path);
    defer _ = c.close(parent.fd);
    defer allocator.free(parent.name);
    const fd = c.openat(parent.fd, parent.name.ptr, .{ .DIRECTORY = directory, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return error.NixRuntimeUnavailable;
    return fd;
}

pub fn openSelectedFile(io: std.Io, allocator: std.mem.Allocator, until: std.Io.Clock.Timestamp, path: []const u8) !c.fd_t {
    return open(io, allocator, until, path, false);
}

pub fn openSelectedDirectory(io: std.Io, allocator: std.mem.Allocator, until: std.Io.Clock.Timestamp, path: []const u8) !c.fd_t {
    const fd = try open(io, allocator, until, path, true);
    errdefer _ = c.close(fd);
    try immutable(try metadata.statFd(fd), c.S.IFDIR);
    try check(io, until);
    return fd;
}

/// Owned immutable selected-file descriptor for the producer's ELF parser.
/// Full bytes are rehashed by recheck around graph validation; this operation
/// pins the exact declared inode without an ambient absolute-path open.
pub fn openVerifiedFile(io: std.Io, allocator: std.mem.Allocator, until: std.Io.Clock.Timestamp, record: Record, index: usize) !c.fd_t {
    try check(io, until);
    if (index >= record.files.len or record.files.len > maximum_files or record.roots.len == 0 or record.roots.len > maximum_files) return error.InvalidNixRuntimeClosure;
    const file = record.files[index];
    var selected_root = false;
    for (record.roots) |root| {
        try canonical(root.path);
        if (file.path.len > root.path.len and std.mem.startsWith(u8,file.path,root.path) and file.path[root.path.len] == '/') selected_root = true;
        const directory = try open(io,allocator,until,root.path,true);
        defer _ = c.close(directory);
        if (!std.meta.eql(root.status,try metadata.statFd(directory))) return error.RuntimeSelectionDrift;
    }
    if (!selected_root) return error.InvalidNixRuntimeClosure;
    const fd = try open(io,allocator,until,file.path,false);
    errdefer _ = c.close(fd);
    const before = try metadata.statFd(fd);
    try immutable(before,c.S.IFREG);
    if (!std.meta.eql(before,file.status) or before.size < 0 or @as(u64,@intCast(before.size)) != file.bytes) return error.RuntimeSelectionDrift;
    const named = try open(io,allocator,until,file.path,false);
    defer _ = c.close(named);
    if (!std.meta.eql(before,try metadata.statFd(named))) return error.RuntimeSelectionDrift;
    try check(io,until);
    return fd;
}
fn requireSorted(comptime T: type, rows: []const T) !void {
    for (rows, 0..) |row, index| {
        try canonical(row.path);
        if (index > 0 and std.mem.order(u8, rows[index - 1].path, row.path) != .lt) return error.InvalidNixRuntimeClosure;
    }
}
fn insideRoots(path: []const u8, roots: []const Root) bool {
    for (roots) |root| if (path.len > root.path.len and std.mem.startsWith(u8,path,root.path) and path[root.path.len] == '/') return true;
    return false;
}

pub fn recheck(io: std.Io, allocator: std.mem.Allocator, until: ?std.Io.Clock.Timestamp, record: Record) !void {
    try check(io, until);
    if (record.roots.len == 0 or record.roots.len > maximum_files or record.files.len == 0 or record.files.len > maximum_files or
        record.aliases.len > maximum_aliases or record.edges.len > maximum_edges or record.interpreter_file_index >= record.files.len or
        std.mem.allEqual(u8, &record.registration_receipt_sha256, 0)) return error.InvalidNixRuntimeClosure;
    try canonical(record.original_interpreter);
    try requireSorted(Root, record.roots);
    try requireSorted(File, record.files);
    try requireSorted(Alias, record.aliases);
    for (record.roots) |root| if (std.mem.indexOfScalar(u8,root.path[11..],'/') != null) return error.InvalidNixRuntimeClosure;
    if (!insideRoots(record.original_interpreter,record.roots)) return error.InvalidNixRuntimeClosure;
    for (record.files) |file| if (!insideRoots(file.path,record.roots)) return error.InvalidNixRuntimeClosure;
    for (record.aliases) |alias| {
        if (!insideRoots(alias.path,record.roots)) return error.InvalidNixRuntimeClosure;
        for (record.files) |file| if (std.mem.eql(u8,file.path,alias.path)) return error.InvalidNixRuntimeClosure;
        if (std.mem.startsWith(u8,alias.target,"/")) {
            try canonical(alias.target);
            if (!insideRoots(alias.target,record.roots)) return error.InvalidNixRuntimeClosure;
        } else {
            var parts = std.mem.splitScalar(u8,alias.target,'/');
            while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8,part,".") or std.mem.eql(u8,part,"..")) return error.InvalidNixRuntimeClosure;
        }
    }
    for (record.roots) |root| {
        const fd = try open(io, allocator, until, root.path, true);
        defer _ = c.close(fd);
        const status = try metadata.statFd(fd);
        try immutable(status, c.S.IFDIR);
        if (!std.meta.eql(status, root.status)) return error.RuntimeSelectionDrift;
    }
    var total: u64 = 0;
    for (record.files) |file| {
        try check(io, until);
        if (file.bytes == 0 or file.bytes > maximum_file_bytes) return error.InvalidNixRuntimeClosure;
        total = try std.math.add(u64, total, file.bytes);
        if (total > maximum_payload_bytes) return error.InvalidNixRuntimeClosure;
        const fd = try open(io, allocator, until, file.path, false);
        defer _ = c.close(fd);
        const before = try metadata.statFd(fd);
        try immutable(before, c.S.IFREG);
        if (!std.meta.eql(before, file.status) or before.size < 0 or @as(u64, @intCast(before.size)) != file.bytes) return error.RuntimeSelectionDrift;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < file.bytes) {
            try check(io, until);
            const count = c.pread(fd, &buffer, @min(buffer.len, file.bytes - offset), @intCast(offset));
            if (count < 0 and c.errno(count) == .INTR) continue;
            if (count <= 0) return error.RuntimeSelectionDrift;
            hash.update(buffer[0..@intCast(count)]);
            offset += @intCast(count);
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        const named = try open(io, allocator, until, file.path, false);
        defer _ = c.close(named);
        if (!std.meta.eql(digest, file.sha256) or !std.meta.eql(before, try metadata.statFd(fd)) or !std.meta.eql(before, try metadata.statFd(named))) return error.RuntimeSelectionDrift;
    }
    for (record.aliases) |alias| {
        const parent = try openParent(io, allocator, until, alias.path);
        defer _ = c.close(parent.fd);
        defer allocator.free(parent.name);
        const before = try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW);
        try immutable(before, c.S.IFLNK);
        if (!std.meta.eql(before, alias.status) or alias.target.len == 0 or alias.target.len > 4096) return error.RuntimeSelectionDrift;
        var target: [4097]u8 = undefined;
        const count = c.readlinkat(parent.fd, parent.name.ptr, &target, target.len);
        if (count <= 0 or !std.mem.eql(u8, target[0..@intCast(count)], alias.target) or
            !std.meta.eql(before, try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW))) return error.RuntimeSelectionDrift;
    }
    // The authenticated producer established ELF resolution; recheck cannot
    // invent or add an edge, and only these immutable bytes can satisfy it.
    for (record.edges) |edge| if ((edge.source_index != 255 and edge.source_index >= record.files.len) or edge.target_index >= record.files.len or
        edge.needed.len == 0 or edge.needed.len > 255 or std.mem.indexOfScalar(u8, edge.needed, '/') != null) return error.InvalidNixRuntimeClosure;
    for (record.roots) |root| {
        const fd = try open(io, allocator, until, root.path, true);
        defer _ = c.close(fd);
        if (!std.meta.eql(root.status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    }
    try check(io, until);
}

test "Nix closure canonical parser rejects escapes and foreign namespaces" {
    try canonical("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc/lib/libc.so.6");
    try std.testing.expectError(error.InvalidNixRuntimeClosure,canonical("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc/../lib/libc.so.6"));
    try std.testing.expectError(error.InvalidNixRuntimeClosure,canonical("/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc/lib/libc.so.6"));
    try std.testing.expectError(error.InvalidNixRuntimeClosure,canonical("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-glibc/lib/libc.so.6"));
}
