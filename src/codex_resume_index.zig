const std = @import("std");
const builtin = @import("builtin");

pub const Lookup = enum {
    match,
    no_match,
    unavailable,
};

pub const max_record_bytes: usize = 1024 * 1024;
pub const max_file_bytes: u64 = 16 * 1024 * 1024;

pub fn lookup(
    allocator: std.mem.Allocator,
    store_dir: []const u8,
    resume_id: []const u8,
) error{OutOfMemory}!Lookup {
    if (resume_id.len == 0 or !std.fs.path.isAbsolute(store_dir)) return .unavailable;
    if (comptime builtin.os.tag == .wasi) return .unavailable;

    // Open the configured authority itself without following its final
    // component. Resolving it first would let a retargetable store symlink
    // authorize one physical store while CODEX_HOME later names another.
    var dir = std.fs.openDirAbsolute(store_dir, .{ .no_follow = true }) catch return .unavailable;
    defer dir.close();

    var file = if (comptime builtin.os.tag == .windows) blk: {
        break :blk dir.openFile("session_index.jsonl", .{}) catch |err| switch (err) {
            error.FileNotFound => return .no_match,
            else => return .unavailable,
        };
    } else blk: {
        const fd = std.posix.openat(dir.fd, "session_index.jsonl", .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
            .NONBLOCK = true,
        }, 0) catch |err| switch (err) {
            error.FileNotFound => return .no_match,
            else => return .unavailable,
        };
        break :blk std.fs.File{ .handle = fd };
    };
    defer file.close();

    const stat = file.stat() catch return .unavailable;
    if (stat.kind != .file or stat.size > max_file_bytes) return .unavailable;

    var line = std.ArrayList(u8).init(allocator);
    defer line.deinit();
    var oversized = false;
    var bytes_read: u64 = 0;
    var buffer: [8192]u8 = undefined;

    while (true) {
        const read_len = file.read(&buffer) catch return .unavailable;
        if (read_len == 0) break;

        bytes_read = std.math.add(u64, bytes_read, read_len) catch return .unavailable;
        if (bytes_read > max_file_bytes) return .unavailable;

        for (buffer[0..read_len]) |byte| {
            if (byte == '\n') {
                if (!oversized and line.items.len != 0 and try lineMatches(allocator, line.items, resume_id)) {
                    return .match;
                }
                line.clearRetainingCapacity();
                oversized = false;
                continue;
            }

            if (oversized) continue;
            if (line.items.len == max_record_bytes) {
                line.clearRetainingCapacity();
                oversized = true;
                continue;
            }
            line.append(byte) catch return error.OutOfMemory;
        }
    }

    if (!oversized and line.items.len != 0 and try lineMatches(allocator, line.items, resume_id)) {
        return .match;
    }
    return .no_match;
}

fn lineMatches(
    allocator: std.mem.Allocator,
    line_raw: []const u8,
    resume_id: []const u8,
) error{OutOfMemory}!bool {
    const line = std.mem.trim(u8, line_raw, " \t\r\n");
    if (line.len == 0) return false;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer parsed.deinit();

    const object = switch (parsed.value) {
        .object => |value| value,
        else => return false,
    };
    const id_value = object.get("id") orelse return false;
    return switch (id_value) {
        .string => |value| std.mem.eql(u8, value, resume_id),
        else => false,
    };
}

test "resume index matching is structural and exact" {
    const allocator = std.testing.allocator;
    const resume_id = "short-valid";

    try std.testing.expect(try lineMatches(
        allocator,
        \\{"id":"short-valid","thread_name":"fixture"}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"id":"short-valid-longer","thread_name":"fixture"}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"id":"different","thread_name":"short-valid"}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"session":{"id":"short-valid"}}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"id":"short-valid","id":"different"}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"id":"different","id":"short-valid"}
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(
        allocator,
        \\{"id":"short-valid"} trailing
    ,
        resume_id,
    ));
    try std.testing.expect(!try lineMatches(allocator, "not-json", resume_id));
}

test "resume index lookup skips oversized records before an exact record" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    const resume_id = "short-valid";
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const index = try tmp.dir.createFile("session_index.jsonl", .{});
    defer index.close();
    const oversized_chunk = [_]u8{'x'} ** 4096;
    var remaining: usize = max_record_bytes + 1;
    while (remaining != 0) {
        const write_len = @min(remaining, oversized_chunk.len);
        try index.writeAll(oversized_chunk[0..write_len]);
        remaining -= write_len;
    }
    try index.writeAll(
        \\
        \\{"id":"short-valid","thread_name":"fixture"}
        \\
    );

    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.match, try lookup(allocator, store_dir, resume_id));
}

test "resume index lookup rejects an oversized target record" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const index = try tmp.dir.createFile("session_index.jsonl", .{});
    defer index.close();
    try index.writeAll("{\"id\":\"short-valid\",\"padding\":\"");
    const padding_chunk = [_]u8{'a'} ** 4096;
    var remaining: usize = max_record_bytes + 1;
    while (remaining != 0) {
        const write_len = @min(remaining, padding_chunk.len);
        try index.writeAll(padding_chunk[0..write_len]);
        remaining -= write_len;
    }
    try index.writeAll("\"}\n");

    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.no_match, try lookup(allocator, store_dir, "short-valid"));
}

test "resume index lookup rejects globally oversized files" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const index = try tmp.dir.createFile("session_index.jsonl", .{});
    defer index.close();
    try index.setEndPos(max_file_bytes + 1);

    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, store_dir, "short-valid"));
}

test "resume index lookup rejects symlink and relative authority" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const target = try tmp.dir.createFile("target.jsonl", .{});
        defer target.close();
        try target.writeAll("{\"id\":\"short-valid\"}\n");
    }
    try tmp.dir.symLink("target.jsonl", "session_index.jsonl", .{});

    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, store_dir, "short-valid"));
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, "relative/store", "short-valid"));
}

test "resume index lookup rejects a symlinked store authority" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("physical-store");
    {
        const index = try tmp.dir.createFile("physical-store/session_index.jsonl", .{});
        defer index.close();
        try index.writeAll("{\"id\":\"short-valid\"}\n");
    }
    try tmp.dir.symLink("physical-store", "configured-store", .{ .is_directory = true });

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const configured_store = try std.fs.path.join(allocator, &.{ root, "configured-store" });
    defer allocator.free(configured_store);
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, configured_store, "short-valid"));
}

test "resume index lookup distinguishes missing index from unavailable store" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.no_match, try lookup(allocator, store_dir, "short-valid"));

    const missing = try std.fs.path.join(allocator, &.{ store_dir, "missing" });
    defer allocator.free(missing);
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, missing, "short-valid"));
}

test "resume index lookup rejects non-regular index entries" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("session_index.jsonl");
    const store_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_dir);
    try std.testing.expectEqual(Lookup.unavailable, try lookup(allocator, store_dir, "short-valid"));
}
