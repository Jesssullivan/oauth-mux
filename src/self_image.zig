//! Linux backing-image diagnostics for a known address in Omux's own code.
//! Kernel mapping identity and verified receipt descriptors are authority;
//! argv, mapping pathnames and the process loader are not image authority.
const std = @import("std");
const builtin = @import("builtin");
const metadata = @import("platform/file_metadata.zig");
const c = std.c;

pub const maximum_maps_bytes = 256 * 1024;
pub const maximum_mappings = 4096;
pub const maximum_reads = 64;
pub const Status = enum { unobserved, unsupported, unavailable, read_failed, scan_limit, malformed_mapping, anchor_missing, anchor_not_executable, anchor_anonymous, observed, role_missing, role_identity_mismatch, role_path_changed, mapping_changed, bound, image_bytes_mismatch };
pub const Observation = struct { status: Status, witness: ?Witness = null, records: usize = 0 };

pub const Witness = struct {
    anchor: usize,
    start: usize,
    end: usize,
    permissions: [4]u8,
    offset: u64,
    dev: u64,
    ino: u64,

    pub fn matchesFile(self: Witness, file: metadata.Metadata) bool {
        if (self.start > self.anchor or self.anchor >= self.end or self.permissions[2] != 'x' or self.permissions[1] == 'w' or self.ino == 0 or file.size <= 0 or self.dev != file.dev or self.ino != file.ino) return false;
        const position = std.math.add(u64, self.offset, @intCast(self.anchor - self.start)) catch return false;
        return position < @as(u64, @intCast(file.size));
    }
};

fn number(comptime T: type, bytes: []const u8, base: u8) ?T {
    if (bytes.len == 0) return null;
    for (bytes) |byte| {
        if (base == 16) {
            if (!std.ascii.isHex(byte)) return null;
        } else if (!std.ascii.isDigit(byte)) return null;
    }
    return std.fmt.parseInt(T, bytes, base) catch null;
}

/// Parse only kernel numeric/permission fields. The remainder of each line is
/// never a pathname selector, even when it names a loader or a deleted file.
pub fn parseSnapshot(bytes: []const u8, anchor: usize) ?Witness {
    return parseChunk(bytes, anchor).witness;
}

pub fn parseChunk(bytes: []const u8, anchor: usize) Observation {
    const malformed: Observation = .{ .status = .malformed_mapping };
    if (bytes.len > maximum_maps_bytes) return .{ .status = .scan_limit };
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') return malformed;
    var lines = std.mem.splitScalar(u8, bytes[0 .. bytes.len - 1], '\n');
    var previous_end: usize = 0;
    var count: usize = 0;
    var found: ?Witness = null;
    while (lines.next()) |line| {
        count += 1;
        if (count > maximum_mappings) return .{ .status = .scan_limit };
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const range = fields.next() orelse return malformed;
        const permissions = fields.next() orelse return malformed;
        const offset = number(u64, fields.next() orelse return malformed, 16) orelse return malformed;
        const device = fields.next() orelse return malformed;
        const ino = number(u64, fields.next() orelse return malformed, 10) orelse return malformed;
        var bounds = std.mem.splitScalar(u8, range, '-');
        const start = number(usize, bounds.next() orelse return malformed, 16) orelse return malformed;
        const end = number(usize, bounds.next() orelse return malformed, 16) orelse return malformed;
        if (bounds.next() != null or start >= end or start < previous_end) return malformed;
        previous_end = end;
        if (permissions.len != 4 or (permissions[0] != 'r' and permissions[0] != '-') or (permissions[1] != 'w' and permissions[1] != '-') or (permissions[2] != 'x' and permissions[2] != '-') or (permissions[3] != 'p' and permissions[3] != 's')) return malformed;
        var devices = std.mem.splitScalar(u8, device, ':');
        const major = number(u32, devices.next() orelse return malformed, 16) orelse return malformed;
        const minor = number(u32, devices.next() orelse return malformed, 16) orelse return malformed;
        if (devices.next() != null) return malformed;
        if (start <= anchor and anchor < end) {
            if (found != null) return malformed;
            if (permissions[2] != 'x' or permissions[1] == 'w') return .{ .status = .anchor_not_executable };
            if (ino == 0) return .{ .status = .anchor_anonymous };
            found = .{ .anchor = anchor, .start = start, .end = end, .permissions = permissions[0..4].*, .offset = offset, .dev = (@as(u64, major) << 32) | minor, .ino = ino };
        }
    }
    return .{ .status = if (found != null) .observed else .anchor_missing, .witness = found, .records = count };
}

fn check(io: std.Io, deadline: std.Io.Clock.Timestamp) !void {
    try io.checkCancel();
    if (deadline.clock != .awake) return error.InvalidDeadline;
    if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
}

/// The accepted anchor record comes wholly from one successful kernel read.
/// seq_file may return a page of complete records despite a larger requested
/// buffer. Scan bounded chunks, never concatenate them or claim a full-file
/// atomic snapshot. A second independent scan rechecks the anchor witness.
pub fn observe(io: std.Io, allocator: std.mem.Allocator, deadline: std.Io.Clock.Timestamp, anchor: usize) !?Witness {
    return (try observeDetailed(io, allocator, deadline, anchor)).witness;
}

pub fn observeDetailed(io: std.Io, allocator: std.mem.Allocator, deadline: std.Io.Clock.Timestamp, anchor: usize) !Observation {
    if (builtin.os.tag != .linux or (builtin.cpu.arch != .x86_64 and builtin.cpu.arch != .aarch64)) return .{ .status = .unsupported };
    try check(io, deadline);
    const fd = c.open("/proc/self/maps", .{ .CLOEXEC = true, .NONBLOCK = true, .NOFOLLOW = true });
    if (fd < 0) return .{ .status = .unavailable };
    defer _ = c.close(fd);
    const bytes = try allocator.alloc(u8, maximum_maps_bytes + 1);
    defer allocator.free(bytes);
    var total: usize = 0;
    var records: usize = 0;
    var reads: usize = 0;
    while (reads < maximum_reads and total < maximum_maps_bytes) {
        try check(io, deadline);
        reads += 1;
        const count = c.read(fd, bytes.ptr, maximum_maps_bytes - total + 1);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return .{ .status = .read_failed };
        }
        if (count == 0) return .{ .status = .anchor_missing };
        const length: usize = @intCast(count);
        total += length;
        if (total > maximum_maps_bytes) return .{ .status = .scan_limit };
        const chunk = parseChunk(bytes[0..length], anchor);
        records += chunk.records;
        if (records > maximum_mappings) return .{ .status = .scan_limit };
        if (chunk.status != .anchor_missing) return chunk;
    }
    return .{ .status = .scan_limit };
}

pub fn daemonRole(prefix: []const u8, path: []const u8) bool {
    if (path.len <= prefix.len or !std.mem.startsWith(u8, path, prefix) or path[prefix.len] != '/') return false;
    const relative = path[prefix.len + 1 ..];
    return std.mem.eql(u8, relative, "bin/omuxd") or std.mem.eql(u8, relative, "lib/omux/libexec/omuxd.bin");
}

/// Both the mapping and selected directory entry must still name the verified
/// backing file after hashing. Unrelated map changes do not invalidate it.
pub fn acceptsReceiptImage(prefix: []const u8, path: []const u8, before: Witness, after: Witness, file: metadata.Metadata, hashed: metadata.Metadata, reopened: metadata.Metadata) bool {
    return daemonRole(prefix, path) and std.meta.eql(before, after) and before.matchesFile(file) and std.meta.eql(file, hashed) and std.meta.eql(file, reopened);
}

test "known code mapping selects backend rather than loader or mapping pathname" {
    const maps = "1000-2000 r-xp 00000000 08:01 10 /installed/omuxd.bin\n3000-4000 r-xp 00001000 08:01 20 /misleading/loader (deleted)\n4000-5000 rw-p 00002000 08:01 20 /other-name\n";
    const image = parseSnapshot(maps, 0x3100) orelse return error.MissingFixtureWitness;
    try std.testing.expectEqual(@as(u64, 20), image.ino);
    try std.testing.expectEqual((@as(u64, 8) << 32) | 1, image.dev);
    try std.testing.expect(parseSnapshot(maps, 0x4000) == null);
    try std.testing.expect(parseSnapshot(maps, 0x3000) != null);
    try std.testing.expect(parseSnapshot(maps, 0x5000) == null);
}

test "page chunks remain independent and a later complete anchor record is observable" {
    const first = parseChunk("1000-2000 r-xp 0 08:01 10 /loader\n", 0x3100);
    const second = parseChunk("3000-4000 r-xp 1000 08:01 20 /backend\n", 0x3100);
    try std.testing.expectEqual(Status.anchor_missing, first.status);
    try std.testing.expectEqual(Status.observed, second.status);
    try std.testing.expectEqual(@as(usize, 1), first.records);
    try std.testing.expectEqual(@as(usize, 1), second.records);
    try std.testing.expectEqual(Status.malformed_mapping, parseChunk("3000-4000 r-xp 1000 08:", 0x3100).status);
    try std.testing.expectEqual(Status.malformed_mapping, parseChunk("01 20 /backend\n", 0x3100).status);
    try std.testing.expectEqual(Status.anchor_anonymous, parseChunk("3000-4000 r-xp 0 00:00 0\n", 0x3100).status);
    try std.testing.expectEqual(Status.anchor_not_executable, parseChunk("3000-4000 rw-p 0 08:01 20\n", 0x3100).status);
}

test "live observer binds its own known code to the native test image descriptor" {
    if (builtin.os.tag != .linux or (builtin.cpu.arch != .x86_64 and builtin.cpu.arch != .aarch64)) return error.SkipZigTest;
    const io = std.testing.io;
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    const anchor = @intFromPtr(&parseSnapshot);
    const first = try observeDetailed(io, std.testing.allocator, deadline, anchor);
    try std.testing.expectEqual(Status.observed, first.status);
    // This native unit executable launches directly. The production portable
    // collector never treats /proc/self/exe's loader identity as daemon proof.
    const fd = c.open("/proc/self/exe", .{ .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return error.LiveImageDescriptorUnavailable;
    defer _ = c.close(fd);
    const file = try metadata.statFd(fd);
    try std.testing.expect(first.witness.?.matchesFile(file));
    const second = try observeDetailed(io, std.testing.allocator, deadline, anchor);
    try std.testing.expectEqual(Status.observed, second.status);
    try std.testing.expect(std.meta.eql(first.witness.?, second.witness.?));
    try std.testing.expect(std.meta.eql(file, try metadata.statFd(fd)));
}

test "malformed anonymous writable overlapping and truncated map evidence stays unknown" {
    for ([_][]const u8{
        "1000-2000 r-xp 0 00:00 0\n",
        "1000-2000 rwxp 0 08:01 20\n",
        "1000-2000 r--p 0 08:01 20\n",
        "1000-2000 r-xp 0 08:01 20\n1000-2000 r-xp 0 08:01 20\n",
        "1000-2000 r-xp 0 08:01 20\n1800-3000 r-xp 0 08:01 20\n",
        "2000-1000 r-xp 0 08:01 20\n",
        "1000-2000 r-xp 0 100000000:01 20\n",
        "1000-2000 r-xp 0 08:01 18446744073709551616\n",
        "1000-2000 r-xp +0 08:01 20\n",
        "1000-2000 r-xp 0 08:01 20",
        "1000-2000 r-xp 0 08:01\n",
    }) |maps| try std.testing.expect(parseSnapshot(maps, 0x1100) == null);
    const oversized = try std.testing.allocator.alloc(u8, maximum_maps_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, '\n');
    try std.testing.expect(parseSnapshot(oversized, 0x1100) == null);
}

test "exact daemon role and stable inode metadata mapping are required after hash" {
    const before = parseSnapshot("1000-2000 r-xp 0 08:01 20 /ignored\n", 0x1100).?;
    const churn = parseSnapshot("1000-2000 r-xp 0 08:01 20 /new-label\n3000-4000 rw-p 0 00:00 0\n", 0x1100).?;
    const file: metadata.Metadata = .{ .mode = 0o100755, .uid = 1000, .gid = 1000, .nlink = 1, .size = 8192, .ino = 20, .dev = (@as(u64, 8) << 32) | 1, .mtime_ns = 1, .ctime_ns = 1 };
    for ([_][]const u8{ "/installed/bin/omuxd", "/installed/lib/omux/libexec/omuxd.bin" }) |path| try std.testing.expect(acceptsReceiptImage("/installed", path, before, churn, file, file, file));
    for ([_][]const u8{ "/installed/lib/omux/lib/loader", "/installed/bin/omux", "/installed-other/bin/omuxd", "/installed/bin/omuxd/extra", "/installed/lib/omux/libexec/omux.bin" }) |path| try std.testing.expect(!acceptsReceiptImage("/installed", path, before, churn, file, file, file));
    var loader = file;
    loader.ino = 10;
    try std.testing.expect(!acceptsReceiptImage("/installed", "/installed/bin/omuxd", before, churn, loader, loader, loader));
    var changed = file;
    changed.ino += 1;
    try std.testing.expect(!acceptsReceiptImage("/installed", "/installed/bin/omuxd", before, churn, file, file, changed));
    changed = file;
    changed.dev += 1;
    try std.testing.expect(!before.matchesFile(changed));
    changed = file;
    changed.ctime_ns += 1;
    try std.testing.expect(!acceptsReceiptImage("/installed", "/installed/bin/omuxd", before, churn, file, changed, file));
    var moved = before;
    moved.offset += 1;
    try std.testing.expect(!acceptsReceiptImage("/installed", "/installed/bin/omuxd", before, moved, file, file, file));
    moved = before;
    moved.permissions[1] = 'w';
    try std.testing.expect(!acceptsReceiptImage("/installed", "/installed/bin/omuxd", before, moved, file, file, file));
    changed = file;
    changed.size = 1;
    try std.testing.expect(!before.matchesFile(changed));
}
