const std = @import("std");
const paths = @import("paths.zig");
const types = @import("types.zig");

pub const RepairEvent = struct {
    ts: i64 = 0,
    kind: []const u8 = "repair_run",
    profile: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    action: ?[]const u8 = null,
    command: ?[]const u8 = null,
    writeback_capability: ?[]const u8 = null,
    automatic_refresh_admitted: ?bool = null,
    outcome: []const u8,
    reason: ?[]const u8 = null,
    ok: bool = false,
    executed: bool = false,
    interactive: bool = false,
    mutating: bool = false,
};

pub const HandoffKey = struct {
    profile: ?[]const u8 = null,
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
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
    try writeEventView(allocator, writer, json, limit, "events", null, "no repair events recorded");
}

pub fn writeHandoffs(allocator: std.mem.Allocator, writer: anytype, json: bool, limit: usize, all: bool) !void {
    if (all) {
        try writeEventView(allocator, writer, json, limit, "handoffs", "daemon_handoff", "no daemon handoffs recorded");
        return;
    }
    try writePendingHandoffView(allocator, writer, json, limit);
}

pub fn writeDaemonSnapshot(allocator: std.mem.Allocator, bytes: []const u8) !void {
    const path = try daemonSnapshotPath(allocator);
    defer allocator.free(path);
    try ensureParentDir(path);

    const file = try std.fs.createFileAbsolute(path, .{
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    try file.writeAll(bytes);
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') try file.writeAll("\n");
}

pub fn readDaemonSnapshotAlloc(allocator: std.mem.Allocator) !?[]const u8 {
    const path = try daemonSnapshotPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, 64 * 1024);
}

pub fn hasPendingHandoff(allocator: std.mem.Allocator, key: HandoffKey) !bool {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var pending = false;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or !eventRouteKeyMatchesHandoffKey(trimmed, key)) continue;
        if (isQueuedHandoffEvent(trimmed)) {
            pending = true;
        } else if (eventResolvesHandoff(trimmed)) {
            pending = false;
        }
    }

    return pending;
}

fn writeEventView(
    allocator: std.mem.Allocator,
    writer: anytype,
    json: bool,
    limit: usize,
    root_key: []const u8,
    filter_kind: ?[]const u8,
    empty_text: []const u8,
) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            if (json) {
                try writeEmptyJsonView(writer, root_key);
            } else {
                try writer.print("{s}\n", .{empty_text});
            }
            return;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len != 0 and eventLineMatchesKind(trimmed, filter_kind)) try lines.append(trimmed);
    }

    if (lines.items.len == 0 and !json) {
        try writer.print("{s}\n", .{empty_text});
        return;
    }

    const start = if (limit != 0 and lines.items.len > limit) lines.items.len - limit else 0;

    if (!json) {
        try writeTextLines(writer, lines.items[start..]);
        return;
    }

    try writer.print("{{\"{s}\":[", .{root_key});
    for (lines.items[start..], 0..) |line, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll(line);
    }
    try writer.writeAll("]}\n");
}

fn writeEmptyJsonView(writer: anytype, root_key: []const u8) !void {
    try writer.print("{{\"{s}\":[]}}\n", .{root_key});
}

fn writePendingHandoffView(
    allocator: std.mem.Allocator,
    writer: anytype,
    json: bool,
    limit: usize,
) !void {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => {
            if (json) {
                try writeEmptyJsonView(writer, "handoffs");
            } else {
                try writer.writeAll("no pending daemon handoffs recorded\n");
            }
            return;
        },
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var pending = std.ArrayList([]const u8).init(allocator);
    defer pending.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (isQueuedHandoffEvent(trimmed)) {
            try upsertPendingHandoff(&pending, trimmed);
        } else {
            removeResolvedHandoffs(&pending, trimmed);
        }
    }

    if (pending.items.len == 0 and !json) {
        try writer.writeAll("no pending daemon handoffs recorded\n");
        return;
    }

    const start = if (limit != 0 and pending.items.len > limit) pending.items.len - limit else 0;
    if (!json) {
        try writeTextLines(writer, pending.items[start..]);
        return;
    }

    try writer.writeAll("{\"handoffs\":[");
    for (pending.items[start..], 0..) |line, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll(line);
    }
    try writer.writeAll("]}\n");
}

fn eventLineMatchesKind(line: []const u8, filter_kind: ?[]const u8) bool {
    const kind = filter_kind orelse return true;
    const marker = "\"kind\":\"";
    const pos = std.mem.indexOf(u8, line, marker) orelse return false;
    const value_start = pos + marker.len;
    const value_end_delta = std.mem.indexOfScalar(u8, line[value_start..], '"') orelse return false;
    return std.mem.eql(u8, line[value_start .. value_start + value_end_delta], kind);
}

fn isQueuedHandoffEvent(line: []const u8) bool {
    return eventLineMatchesKind(line, "daemon_handoff") and eventFieldEquals(line, "outcome", "handoff_queued");
}

fn upsertPendingHandoff(pending: *std.ArrayList([]const u8), line: []const u8) !void {
    var idx: usize = 0;
    while (idx < pending.items.len) {
        if (eventRouteKeyMatches(pending.items[idx], line)) {
            _ = pending.orderedRemove(idx);
            continue;
        }
        idx += 1;
    }
    try pending.append(line);
}

fn removeResolvedHandoffs(pending: *std.ArrayList([]const u8), event_line: []const u8) void {
    if (!eventResolvesHandoff(event_line)) return;
    var idx: usize = 0;
    while (idx < pending.items.len) {
        if (eventRouteKeyMatches(pending.items[idx], event_line)) {
            _ = pending.orderedRemove(idx);
            continue;
        }
        idx += 1;
    }
}

fn eventResolvesHandoff(line: []const u8) bool {
    if (eventFieldEquals(line, "outcome", "route_selectable")) return true;
    if (eventFieldEquals(line, "outcome", "handoff_resolved")) return true;
    if (eventFieldBool(line, "ok") == true and eventFieldEquals(line, "outcome", "executed")) return true;
    if (eventFieldBool(line, "ok") == true and eventFieldEquals(line, "outcome", "noop")) return true;
    return false;
}

fn eventRouteKeyMatches(a: []const u8, b: []const u8) bool {
    return eventOptionalFieldEquals(a, b, "profile") and
        eventOptionalFieldEquals(a, b, "provider") and
        eventOptionalFieldEquals(a, b, "account") and
        eventOptionalFieldEquals(a, b, "capability");
}

fn eventRouteKeyMatchesHandoffKey(line: []const u8, key: HandoffKey) bool {
    return eventOptionalFieldMatches(line, "profile", key.profile) and
        eventFieldEquals(line, "provider", key.provider) and
        eventFieldEquals(line, "account", key.account) and
        eventOptionalFieldMatches(line, "capability", key.capability);
}

fn eventOptionalFieldEquals(a: []const u8, b: []const u8, field: []const u8) bool {
    const av = eventFieldString(a, field);
    const bv = eventFieldString(b, field);
    if (av == null and bv == null) return true;
    if (av == null or bv == null) return false;
    return std.mem.eql(u8, av.?, bv.?);
}

fn eventOptionalFieldMatches(line: []const u8, field: []const u8, expected: ?[]const u8) bool {
    const actual = eventFieldString(line, field);
    if (actual == null and expected == null) return true;
    if (actual == null or expected == null) return false;
    return std.mem.eql(u8, actual.?, expected.?);
}

fn eventFieldEquals(line: []const u8, field: []const u8, expected: []const u8) bool {
    const value = eventFieldString(line, field) orelse return false;
    return std.mem.eql(u8, value, expected);
}

fn eventFieldBool(line: []const u8, field: []const u8) ?bool {
    const start = eventFieldValueStart(line, field) orelse return null;
    if (std.mem.startsWith(u8, line[start..], "true")) return true;
    if (std.mem.startsWith(u8, line[start..], "false")) return false;
    return null;
}

fn eventFieldString(line: []const u8, field: []const u8) ?[]const u8 {
    var idx = eventFieldValueStart(line, field) orelse return null;
    if (std.mem.startsWith(u8, line[idx..], "null")) return null;
    if (idx >= line.len or line[idx] != '"') return null;
    idx += 1;
    const start = idx;
    while (idx < line.len) : (idx += 1) {
        if (line[idx] == '\\') {
            idx += 1;
            continue;
        }
        if (line[idx] == '"') return line[start..idx];
    }
    return null;
}

fn eventFieldValueStart(line: []const u8, field: []const u8) ?usize {
    var search_start: usize = 0;
    while (search_start < line.len) {
        const quote_delta = std.mem.indexOfScalar(u8, line[search_start..], '"') orelse return null;
        const key_start = search_start + quote_delta + 1;
        if (key_start + field.len + 2 <= line.len and
            std.mem.eql(u8, line[key_start .. key_start + field.len], field) and
            line[key_start + field.len] == '"' and
            line[key_start + field.len + 1] == ':')
        {
            return key_start + field.len + 2;
        }
        search_start = key_start;
    }
    return null;
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

fn daemonSnapshotPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try paths.stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "daemon-snapshot.json" });
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
    try writer.print("{{\"ts\":{d},\"kind\":", .{ts});
    try std.json.stringify(event.kind, .{}, writer);
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
    try writer.writeAll(",\"command\":");
    if (event.command) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"writeback_capability\":");
    if (event.writeback_capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"automatic_refresh_admitted\":");
    if (event.automatic_refresh_admitted) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
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

fn writeTextLines(writer: anytype, lines: []const []const u8) !void {
    for (lines) |line| {
        try writer.writeAll(line);
        try writer.writeByte('\n');
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
        .command = "oauth-mux codex login-device max-1",
        .outcome = "confirmation_required",
        .reason = "missing_session",
        .ok = false,
        .executed = false,
        .interactive = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"provider\":\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"repair_run\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"profile\":\"codex-max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"account\":\"max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "token") == null);
}

test "event kind filtering keeps daemon handoffs only" {
    try std.testing.expect(eventLineMatchesKind("{\"kind\":\"daemon_handoff\"}", "daemon_handoff"));
    try std.testing.expect(!eventLineMatchesKind("{\"kind\":\"repair_run\"}", "daemon_handoff"));
    try std.testing.expect(!eventLineMatchesKind("{\"kind\":\"repair_run\",\"reason\":\"daemon_handoff\"}", "daemon_handoff"));
    try std.testing.expect(eventLineMatchesKind("{\"kind\":\"repair_run\"}", null));
}

test "pending handoff queue resolves by later route event" {
    var pending = std.ArrayList([]const u8).init(std.testing.allocator);
    defer pending.deinit();

    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";
    const unrelated =
        "{\"kind\":\"daemon_action\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-2\",\"capability\":\"codex-max\",\"outcome\":\"route_selectable\",\"ok\":true}";
    const resolved =
        "{\"kind\":\"daemon_action\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"route_selectable\",\"ok\":true}";

    try upsertPendingHandoff(&pending, handoff);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, unrelated);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, resolved);
    try std.testing.expectEqual(@as(usize, 0), pending.items.len);
}

test "pending handoff queue resolves by explicit handoff event" {
    var pending = std.ArrayList([]const u8).init(std.testing.allocator);
    defer pending.deinit();

    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";
    const acknowledged =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_acknowledged\",\"ok\":true}";
    const resolved =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_resolved\",\"ok\":true}";

    try upsertPendingHandoff(&pending, handoff);
    removeResolvedHandoffs(&pending, acknowledged);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    removeResolvedHandoffs(&pending, resolved);
    try std.testing.expectEqual(@as(usize, 0), pending.items.len);
}

test "handoff key matching distinguishes pending route" {
    const handoff =
        "{\"kind\":\"daemon_handoff\",\"profile\":\"codex-max\",\"provider\":\"codex\",\"account\":\"max-1\",\"capability\":\"codex-max\",\"outcome\":\"handoff_queued\",\"ok\":false}";

    try std.testing.expect(eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
    }));
    try std.testing.expect(!eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-2",
        .capability = "codex-max",
    }));
    try std.testing.expect(!eventRouteKeyMatchesHandoffKey(handoff, .{
        .profile = "codex-max",
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-mini",
    }));
}

test "refresh event json carries redacted writeback evidence" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventJson(buf.writer(), .{
        .ts = 43,
        .kind = "token_refresh",
        .profile = "work",
        .provider = "figma",
        .account = "design",
        .action = "refresh",
        .writeback_capability = "replace_file",
        .automatic_refresh_admitted = true,
        .outcome = "persisted",
        .reason = "replace_file_writeback_available",
        .ok = true,
        .executed = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"token_refresh\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"writeback_capability\":\"replace_file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"automatic_refresh_admitted\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"outcome\":\"persisted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "access_token") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "refresh_token") == null);
}

test "sanitized lock file names do not preserve path separators" {
    const name = try sanitizedLockFileName(std.testing.allocator, "co/dex", "max:1");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("co_dex-max_1.lock", name);
}
