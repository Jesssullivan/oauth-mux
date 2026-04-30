const std = @import("std");
const paths = @import("paths.zig");
const types = @import("types.zig");

pub const RepairEvent = struct {
    ts: i64 = 0,
    profile: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    action: ?[]const u8 = null,
    outcome: []const u8,
    reason: ?[]const u8 = null,
    ok: bool = false,
    executed: bool = false,
    interactive: bool = false,
    mutating: bool = false,
};

pub const RepairLock = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    file: std.fs.File,

    pub fn release(self: *RepairLock) void {
        self.file.close();
        std.fs.deleteFileAbsolute(self.path) catch {};
        self.allocator.free(self.path);
    }
};

pub fn appendEvent(allocator: std.mem.Allocator, event: RepairEvent) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);
    try ensureParentDir(path);

    const file = try std.fs.createFileAbsolute(path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
    });
    defer file.close();

    try file.seekFromEnd(0);
    try writeEventJson(file.writer(), event);
    try file.writeAll("\n");
}

pub fn writeEvents(allocator: std.mem.Allocator, writer: anytype, json: bool, limit: usize) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            if (json) {
                try writer.writeAll("{\"events\":[]}\n");
            } else {
                try writer.writeAll("no repair events recorded\n");
            }
            return;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    if (!json) {
        try writeLastTextLines(writer, bytes, limit);
        return;
    }

    try writer.writeAll("{\"events\":[");
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len != 0) try lines.append(trimmed);
    }

    const start = if (limit != 0 and lines.items.len > limit) lines.items.len - limit else 0;
    for (lines.items[start..], 0..) |line, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll(line);
    }
    try writer.writeAll("]}\n");
}

pub fn acquireRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !RepairLock {
    const path = try lockPath(allocator, provider, account);
    errdefer allocator.free(path);
    try ensureParentDir(path);

    const file = std.fs.createFileAbsolute(path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
        .lock_nonblocking = true,
    }) catch |e| switch (e) {
        error.WouldBlock => return error.RepairInProgress,
        else => return e,
    };
    errdefer file.close();

    const now = std.time.timestamp();
    try file.setEndPos(0);
    try file.seekTo(0);
    const writer = file.writer();
    try writer.writeAll("{\"provider\":");
    try std.json.stringify(provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(account, .{}, writer);
    try writer.print(",\"started_at\":{d}}}\n", .{now});

    return .{
        .allocator = allocator,
        .path = path,
        .file = file,
    };
}

pub fn probeRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !?types.RuntimeReadiness.RepairProgress {
    const path = try lockPath(allocator, provider, account);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{
        .mode = .read_write,
        .lock = .exclusive,
        .lock_nonblocking = true,
    }) catch |e| switch (e) {
        error.FileNotFound => return null,
        error.WouldBlock => return try readRepairProgress(allocator, path, account),
        else => return e,
    };
    file.close();
    return null;
}

fn eventsPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "repair-events.jsonl" });
}

fn locksDir(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.runtimeDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "repair-locks" });
}

fn lockPath(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    const dir = try locksDir(allocator);
    defer allocator.free(dir);
    const file_name = try sanitizedLockFileName(allocator, provider, account);
    defer allocator.free(file_name);
    return std.fs.path.join(allocator, &.{ dir, file_name });
}

fn sanitizedLockFileName(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try appendLockNamePart(&out, provider);
    try out.append('-');
    try appendLockNamePart(&out, account);
    try out.appendSlice(".lock");
    return try out.toOwnedSlice();
}

fn appendLockNamePart(out: *std.ArrayList(u8), value: []const u8) !void {
    for (value) |c| {
        const safe = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        try out.append(if (safe) c else '_');
    }
}

fn readRepairProgress(
    allocator: std.mem.Allocator,
    path: []const u8,
    fallback_account: []const u8,
) !types.RuntimeReadiness.RepairProgress {
    const file = std.fs.openFileAbsolute(path, .{}) catch return .{
        .account = fallback_account,
        .started_at = 0,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, 16 * 1024) catch return .{
        .account = fallback_account,
        .started_at = 0,
    };
    defer allocator.free(bytes);

    return .{
        .account = fallback_account,
        .started_at = parseStartedAt(bytes) orelse 0,
    };
}

fn parseStartedAt(bytes: []const u8) ?i64 {
    const marker = "\"started_at\":";
    const start = std.mem.indexOf(u8, bytes, marker) orelse return null;
    var idx = start + marker.len;
    while (idx < bytes.len and bytes[idx] == ' ') : (idx += 1) {}
    const value_start = idx;
    while (idx < bytes.len and std.ascii.isDigit(bytes[idx])) : (idx += 1) {}
    if (idx == value_start) return null;
    return std.fmt.parseInt(i64, bytes[value_start..idx], 10) catch null;
}

fn ensureParentDir(path: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }
}

fn writeEventJson(writer: anytype, event: RepairEvent) !void {
    const ts = if (event.ts == 0) std.time.timestamp() else event.ts;
    try writer.print("{{\"ts\":{d},\"kind\":\"repair_run\"", .{ts});
    try writer.writeAll(",\"profile\":");
    if (event.profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"provider\":");
    if (event.provider) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (event.account) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (event.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"action\":");
    if (event.action) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"outcome\":");
    try std.json.stringify(event.outcome, .{}, writer);
    try writer.writeAll(",\"reason\":");
    if (event.reason) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (event.ok) "true" else "false");
    try writer.writeAll(",\"executed\":");
    try writer.writeAll(if (event.executed) "true" else "false");
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (event.interactive) "true" else "false");
    try writer.writeAll(",\"mutating\":");
    try writer.writeAll(if (event.mutating) "true" else "false");
    try writer.writeByte('}');
}

fn writeLastTextLines(writer: anytype, bytes: []const u8, limit: usize) !void {
    var count: usize = 0;
    var it_count = std.mem.splitScalar(u8, bytes, '\n');
    while (it_count.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len != 0) count += 1;
    }

    const skip = if (limit != 0 and count > limit) count - limit else 0;
    var seen: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (seen >= skip) {
            try writer.writeAll(trimmed);
            try writer.writeByte('\n');
        }
        seen += 1;
    }
}

test "parseStartedAt reads lock metadata timestamp" {
    try std.testing.expectEqual(@as(?i64, 42), parseStartedAt("{\"started_at\":42}\n"));
    try std.testing.expectEqual(@as(?i64, null), parseStartedAt("{\"started_at\":\"42\"}\n"));
}

test "repair event json is redacted and structured" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventJson(buf.writer(), .{
        .ts = 42,
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
        .action = "reauth",
        .outcome = "confirmation_required",
        .reason = "missing_session",
        .ok = false,
        .executed = false,
        .interactive = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"provider\":\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"profile\":\"codex-max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"account\":\"max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "token") == null);
}

test "sanitized lock file names do not preserve path separators" {
    const name = try sanitizedLockFileName(std.testing.allocator, "co/dex", "max:1");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("co_dex-max_1.lock", name);
}
