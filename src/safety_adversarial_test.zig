//! Synthetic engine through production daemon sockets. No vault, provider,
//! personal native store, installed application or seamless-handoff claim.
const std = @import("std");
const builtin = @import("builtin");
const Engine = @import("engine.zig").Engine;
const daemon = @import("daemon.zig");
const paths = @import("paths.zig");

const allocator = std.heap.page_allocator;
const io = std.testing.io;
const health = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.health\"}";
extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) c_int;

/// Deliver a complete RPC, then close without consuming any response bytes.
fn loseReply(path: []const u8, bytes: []const u8) !void {
    const fd = socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.FixtureSocketFailed;
    defer _ = std.c.close(fd);
    var address: std.c.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return error.FixtureSocketTooLong;
    @memcpy(address.path[0..path.len], path);
    const length: std.c.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + path.len + 1);
    if (builtin.os.tag == .macos) address.len = @intCast(length);
    if (std.c.connect(fd, @ptrCast(&address), length) != 0) return error.FixtureConnectFailed;
    const framed = try std.fmt.allocPrint(allocator, "{s}\n", .{bytes});
    defer allocator.free(framed);
    var offset: usize = 0;
    while (offset < framed.len) {
        const count = std.c.write(fd, framed[offset..].ptr, framed.len - offset);
        if (count <= 0) return error.FixtureSendFailed;
        offset += @intCast(count);
    }
}

const Server = struct {
    locations: paths.Locations,
    engine: *Engine,
    failure: ?anyerror = null,
    fn run(self: *Server) void {
        daemon.serveWithEngineForTest(io, allocator, self.locations, self.engine) catch |err| {
            self.failure = err;
        };
    }
};

fn ready(socket_path: []const u8) !void {
    for (0..200) |_| {
        const response = daemon.exchange(io, allocator, socket_path, health) catch {
            try io.sleep(.fromMilliseconds(10), .awake);
            continue;
        };
        allocator.free(response);
        return;
    }
    return error.FixtureSocketUnavailable;
}

fn request(socket_path: []const u8, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    const response = try daemon.exchange(io, allocator, socket_path, bytes);
    defer allocator.free(response);
    return std.json.parseFromSlice(std.json.Value, allocator, response, .{});
}

fn result(value: std.json.Value) !std.json.Value {
    return value.object.get("result") orelse error.FixtureRequestRejected;
}

test "socket duplicate mutation survives actor restart with stable result and revision" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var random: [8]u8 = undefined;
    try io.randomSecure(&random);
    const runtime = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-test-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(random, .lower) }, 0);
    defer allocator.free(runtime);
    if (std.c.mkdir(runtime.ptr, 0o700) != 0) return error.FixtureRuntimeUnavailable;
    defer std.Io.Dir.cwd().deleteTree(io, runtime) catch |err| std.log.err("fixture cleanup failed: {s}", .{@errorName(err)});
    const locations = try paths.Locations.fromRuntime(allocator, path, runtime);
    defer {
        allocator.free(locations.state);
        allocator.free(locations.run);
        allocator.free(locations.control);
        allocator.free(locations.browser);
        allocator.free(locations.adapter);
        if (locations.runtime_parent) |parent| allocator.free(parent);
    }
    var expected_result: ?[]u8 = null;
    defer if (expected_result) |bytes| allocator.free(bytes);
    var expected_revision: u64 = 0;
    var submitted_revision: u64 = 0;
    var mutation: ?[]u8 = null;
    defer if (mutation) |bytes| allocator.free(bytes);
    for (0..2) |round| {
        const engine = try Engine.openWithKey(io, allocator, path, @splat(27));
        defer engine.deinit();
        var server: Server = .{ .locations = locations, .engine = engine };
        const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
        defer {
            daemon.stopForTest() catch unreachable;
            thread.join();
            std.testing.expect(server.failure == null) catch @panic("synthetic daemon exited with a failure");
        }
        try ready(locations.control);
        if (round == 0) {
            submitted_revision = engine.revision;
            mutation = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"policy.set\",\"params\":{{\"operation_id\":\"lost-reply-fixture\",\"expected_revision\":{d},\"warm_alternatives\":false}}}}", .{submitted_revision});
        } else expected_revision = engine.revision;
        if (round == 0) {
            try loseReply(locations.control, mutation.?);
            // The server may process the duplicate before the abandoned socket;
            // either order must commit exactly one mutation.
        }
        var first = try request(locations.control, mutation.?);
        defer first.deinit();
        const first_result = try std.json.Stringify.valueAlloc(allocator, try result(first.value), .{});
        defer allocator.free(first_result);
        if (round == 0) {
            expected_result = try allocator.dupe(u8, first_result);
            expected_revision = engine.revision;
            try std.testing.expectEqual(submitted_revision + 1, expected_revision);
        }
        try std.testing.expectEqualStrings(expected_result.?, first_result);
        try std.testing.expectEqual(expected_revision, engine.revision);
        // Different RPC correlation ID and property order preserve operation identity.
        const reordered = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"2.0\",\"id\":78,\"method\":\"policy.set\",\"params\":{{\"warm_alternatives\":false,\"expected_revision\":{d},\"operation_id\":\"lost-reply-fixture\"}}}}", .{submitted_revision});
        defer allocator.free(reordered);
        var duplicate = try request(locations.control, reordered);
        defer duplicate.deinit();
        const duplicate_result = try std.json.Stringify.valueAlloc(allocator, try result(duplicate.value), .{});
        defer allocator.free(duplicate_result);
        try std.testing.expectEqualStrings(expected_result.?, duplicate_result);
        try std.testing.expectEqual(expected_revision, engine.revision);
        const conflicting = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"2.0\",\"id\":79,\"method\":\"policy.set\",\"params\":{{\"operation_id\":\"lost-reply-fixture\",\"expected_revision\":{d},\"warm_alternatives\":true}}}}", .{submitted_revision});
        defer allocator.free(conflicting);
        var rejected = try request(locations.control, conflicting);
        defer rejected.deinit();
        try std.testing.expectEqualStrings("OperationIdConflict", rejected.value.object.get("error").?.object.get("message").?.string);
        try std.testing.expectEqual(expected_revision, engine.revision);
        const before_poll = engine.last_source_poll;
        for (0..4) |_| {
            var checked = try request(locations.control, health);
            defer checked.deinit();
            const metadata = try result(checked.value);
            try std.testing.expectEqual(@as(i64, @intCast(expected_revision)), metadata.object.get("revision").?.integer);
        }
        try std.testing.expectEqual(before_poll, engine.last_source_poll);
        try std.testing.expectEqual(expected_revision, engine.revision);
    }
}
