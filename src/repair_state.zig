const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
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
    engine_run_available: ?bool = null,
    execution: ?[]const u8 = null,
    agent_safe: ?bool = null,
    spends_provider_calls: ?bool = null,
    budget: ?[]const u8 = null,
    repair_owner: ?[]const u8 = null,
    fresh_browser_context_required: ?bool = null,
    browser_context: ?[]const u8 = null,
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

// ── Process-local actor gate (TIN-1851 no-self-deadlock, TIN-2059 no-self-race) ──
// The repair lock is an OS flock (createFileAbsolute .lock=.exclusive), which is
// per-open-file-description. A SECOND acquire of the same (provider,account) key
// from the SAME process — e.g. the in-process proxy materializer thread refreshing
// while the session main thread already holds the account's repair lock — opens a
// new fd and flock() would block on itself: a self-deadlock. We therefore hold
// exactly ONE real flock per key per process; a condition variable serializes the
// first-acquire so two threads never race the real flock for the same key.
// Cross-process serialization is unchanged: the OS flock still blocks (or returns
// RepairInProgress) for a different process.
//
// TIN-2059: plain refcounting made the in-process side re-entrant for EVERYONE —
// a daemon hosting a warm-scheduler tick AND a live session / broker materializer
// for one provider:account re-entered (`entry.count += 1`) and raced itself: two
// logical actors, one process, zero serialization, double-spend of a single-use
// refresh-token chain. The registry therefore tracks the OWNING ACTOR of each
// held key and only the same actor may nest:
//
//   - actor = the acquiring thread, unless the thread acts on behalf of another
//     actor via a cooperative blocking join (below);
//   - same-actor re-acquire → refcount join (one actor is sequential; it cannot
//     race itself);
//   - cross-actor NONBLOCKING acquire → error.RepairInProgress — the same typed
//     lock_busy/deferred contract every nonblocking caller already implements
//     for the cross-process case (pipeline probe/refresh/identity, CLI
//     repair/reauth/daemon-tick, broker + adapter identity guards);
//   - cross-actor BLOCKING acquire of a BLOCKING-held key → cooperative join +
//     actor adoption. The only blocking pair in the tree is the managed codex
//     session (adapters/codex/main.zig, holds across spawn→wait→finalize) and
//     the broker materializer refresh (broker_loader.refreshCodexAccountAuthFile)
//     running mid-session on the proxy thread ON BEHALF OF that session. The
//     joiner adopts the owner's actor for the duration of the hold so its nested
//     identity-lock acquire is recognized as the same actor;
//   - cross-actor BLOCKING acquire of a NONBLOCKING-held key → wait for full
//     release, then take the real flock. A nonblocking holder is a short-hold
//     typed writer (warm tick, probe, CLI repair), never a parent actor: the
//     materializer serializes BEHIND it, and its under-lock revalidation then
//     sees the freshly rotated credential (lock-then-revalidate, TIN-2073).

const ActorId = u64;

const HeldLock = struct {
    count: usize,
    acquiring: bool,
    owner_actor: ActorId,
    owner_blocking: bool,
    file: ?std.fs.File = null,
};

var held_mutex: std.Thread.Mutex = .{};
var held_cond: std.Thread.Condition = .{};
var held_locks: std.StringHashMapUnmanaged(HeldLock) = .{};
const held_gpa = std.heap.page_allocator; // process-global; mutated only under held_mutex

/// Actor identity this thread acts as. Defaults to the thread itself; a
/// cooperative blocking join temporarily adopts the lock owner's actor
/// (materializer-on-behalf-of-session), restored by release() in LIFO order.
threadlocal var adopted_actor: ?ActorId = null;

fn currentActor() ActorId {
    if (adopted_actor) |actor| return actor;
    return @intCast(std.Thread.getCurrentId());
}

pub const RepairLock = struct {
    allocator: std.mem.Allocator,
    key: []const u8, // caller-allocator-owned sanitized lock name
    /// Set on a cooperative blocking join: this hold adopted the owner's actor.
    /// release() restores the previous binding; every caller releases via defer
    /// in the acquiring frame, so restoration runs on the acquiring thread and
    /// unwinds LIFO with any nested holds.
    adopted: bool = false,
    prev_actor: ?ActorId = null,

    pub fn release(self: *RepairLock) void {
        held_mutex.lock();
        if (held_locks.getPtr(self.key)) |entry| {
            if (entry.count > 0) entry.count -= 1;
            if (entry.count == 0) {
                // Real-lock teardown: closing the fd drops the OS flock, and the
                // lock FILE deliberately persists (TIN-2041). Unlinking it here
                // raced waiters: a waiter blocked on the old inode acquires the
                // kernel flock the instant the fd closes, the unlink then orphans
                // the name it holds, and a later acquirer creates a NEW inode at
                // the same path and locks immediately — two concurrent holders.
                // flock(2) state is the only mutual-exclusion authority: stale
                // lock files are simply re-locked on the next acquire, and
                // probeRepairLock reports unlocked files as no repair in
                // progress.
                if (entry.file) |f| f.close();
                if (held_locks.fetchRemove(self.key)) |kv| held_gpa.free(kv.key);
                // Wake cross-actor blocking acquirers serialized behind this
                // hold (TIN-2059): they re-check the registry and take the
                // real flock only after full release.
                held_cond.broadcast();
            }
        }
        held_mutex.unlock();
        if (self.adopted) adopted_actor = self.prev_actor;
        self.allocator.free(self.key);
    }
};

// The append-only repair-events log is read back whole by every reader
// (hasPendingHandoff / writeEvents / writePendingHandoffView), each of which caps
// the read at 1 MiB and FAILS with FileTooBig past that. Bound the file so reads
// stay correct and O(tail): rotate to the most recent ~512 KiB once it grows past
// 768 KiB (kept well under the 1 MiB read cap so a single post-rotation append can
// never exceed it). Repair handoffs resolve within a handful of events, so the
// retained tail covers every realistically-live pending handoff.
const events_soft_cap_bytes: u64 = 768 * 1024;
const events_retain_tail_bytes: usize = 512 * 1024;

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

    // Best-effort: a rotation hiccup must not drop the event we just recorded.
    rotateEventsTailInPlace(allocator, file, events_soft_cap_bytes, events_retain_tail_bytes) catch {};
}

/// If `file` exceeds `soft_cap`, rewrite it in place keeping only the last
/// ~`retain_tail` bytes, trimmed forward to the next line boundary so no JSONL
/// record is split. Operates on the already-exclusively-locked handle. Pure of
/// global state so it is unit-testable with small caps.
fn rotateEventsTailInPlace(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    soft_cap: u64,
    retain_tail: usize,
) !void {
    const size = try file.getEndPos();
    if (size <= soft_cap) return;

    try file.seekTo(0);
    const all = try file.readToEndAlloc(allocator, size + 1);
    defer allocator.free(all);

    var start: usize = if (all.len > retain_tail) all.len - retain_tail else 0;
    if (start > 0) {
        // Advance to just after the next newline so the kept tail starts on a
        // record boundary; if none remains, keep nothing rather than a torn line.
        start = if (std.mem.indexOfScalarPos(u8, all, start, '\n')) |nl| nl + 1 else all.len;
    }

    try file.seekTo(0);
    try file.setEndPos(0);
    try file.writeAll(all[start..]);
}

test "rotateEventsTailInPlace bounds the file to the recent tail on a record boundary" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("ev.jsonl", .{ .read = true, .truncate = true });
    defer f.close();
    var i: usize = 0;
    while (i < 100) : (i += 1) try f.writer().print("rec{d:0>4}\n", .{i}); // 800 bytes total

    try rotateEventsTailInPlace(std.testing.allocator, f, 200, 100);

    try f.seekTo(0);
    const out = try f.readToEndAlloc(std.testing.allocator, 1 << 20);
    defer std.testing.allocator.free(out);
    try std.testing.expect(out.len <= 100); // bounded to the retain tail
    try std.testing.expect(out.len > 0 and out[0] == 'r'); // starts on a record boundary
    try std.testing.expect(out[out.len - 1] == '\n'); // ends clean, no torn line
    try std.testing.expect(std.mem.indexOf(u8, out, "rec0099") != null); // most recent kept
    try std.testing.expect(std.mem.indexOf(u8, out, "rec0000") == null); // oldest dropped
}

test "rotateEventsTailInPlace is a no-op below the cap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("ev2.jsonl", .{ .read = true, .truncate = true });
    defer f.close();
    try f.writeAll("a\nb\nc\n");
    try rotateEventsTailInPlace(std.testing.allocator, f, 1024, 512);
    try f.seekTo(0);
    const out = try f.readToEndAlloc(std.testing.allocator, 1024);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\nb\nc\n", out);
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
    return (try pendingHandoffProgress(allocator, key)) != null;
}

pub fn pendingHandoffProgress(allocator: std.mem.Allocator, key: HandoffKey) !?types.RuntimeReadiness.RepairProgress {
    const path = try eventsPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);

    var pending_started_at: ?i64 = null;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or !eventRouteKeyMatchesHandoffKey(trimmed, key)) continue;
        if (isQueuedHandoffEvent(trimmed)) {
            pending_started_at = eventFieldInt(trimmed, "ts") orelse 0;
        } else if (eventResolvesHandoff(trimmed)) {
            pending_started_at = null;
        }
    }

    if (pending_started_at) |started_at| {
        return .{
            .account = key.account,
            .started_at = started_at,
        };
    }
    return null;
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

fn eventFieldInt(line: []const u8, field: []const u8) ?i64 {
    var idx = eventFieldValueStart(line, field) orelse return null;
    while (idx < line.len and line[idx] == ' ') : (idx += 1) {}
    const start = idx;
    if (idx < line.len and line[idx] == '-') idx += 1;
    while (idx < line.len and std.ascii.isDigit(line[idx])) : (idx += 1) {}
    if (idx == start or (idx == start + 1 and line[start] == '-')) return null;
    return std.fmt.parseInt(i64, line[start..idx], 10) catch null;
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
    return acquireRepairLockWithMode(allocator, provider, account, true);
}

pub fn acquireRepairLockBlocking(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
) !RepairLock {
    return acquireRepairLockWithMode(allocator, provider, account, false);
}

const RealRepairLock = struct { file: std.fs.File, path: []const u8 };

fn acquireRealRepairLock(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    nonblocking: bool,
) !RealRepairLock {
    const path = try lockPath(allocator, provider, account);
    errdefer allocator.free(path);
    try ensureParentDir(path);

    const file = std.fs.createFileAbsolute(path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
        .lock_nonblocking = nonblocking,
    }) catch |e| switch (e) {
        error.WouldBlock => if (nonblocking) return error.RepairInProgress else return e,
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

    return .{ .file = file, .path = path };
}

fn acquireRepairLockWithMode(
    allocator: std.mem.Allocator,
    provider: []const u8,
    account: []const u8,
    nonblocking: bool,
) !RepairLock {
    const key = try sanitizedLockFileName(allocator, provider, account);
    errdefer allocator.free(key);
    const self_actor = currentActor();

    held_mutex.lock();
    while (true) {
        if (held_locks.getPtr(key)) |entry| {
            if (entry.acquiring) {
                if (nonblocking) {
                    // A sibling thread is mid-flock for this key. Waiting
                    // would silently turn the caller's typed
                    // refuse-on-held contract into an unbounded block
                    // behind the sibling's (possibly blocking) acquire.
                    held_mutex.unlock();
                    return error.RepairInProgress;
                }
                // Blocking caller: wait for the sibling's flock to resolve.
                held_cond.wait(&held_mutex);
                continue;
            }
            if (entry.owner_actor == self_actor) {
                // Same logical actor: genuine nesting (a single actor is
                // sequential and cannot race itself). Refcount, no new flock.
                entry.count += 1;
                held_mutex.unlock();
                return .{ .allocator = allocator, .key = key };
            }
            if (nonblocking) {
                // TIN-2059: a DIFFERENT in-process actor holds this key.
                // The old unconditional `entry.count += 1` join here is what
                // let a warm tick race a live session/materializer inside one
                // process. Refuse typed instead — identical contract to the
                // cross-process flock's WouldBlock arm.
                held_mutex.unlock();
                return error.RepairInProgress;
            }
            if (entry.owner_blocking) {
                // Cooperative hierarchical join (TIN-1851): a blocking
                // acquirer joining a blocking hold is the proxy materializer
                // refreshing on behalf of the live session that owns this
                // key. Adopt the owner's actor for the duration of the hold
                // so nested acquires (the identity lock) match the session.
                entry.count += 1;
                const prev = adopted_actor;
                adopted_actor = entry.owner_actor;
                held_mutex.unlock();
                return .{ .allocator = allocator, .key = key, .adopted = true, .prev_actor = prev };
            }
            // Blocking acquirer vs a short-hold typed writer (warm tick,
            // probe, CLI repair): serialize BEHIND it — wait for the full
            // release, then take the real flock and revalidate under it.
            held_cond.wait(&held_mutex);
            continue;
        }
        break;
    }
    // Reserve the key as 'acquiring', then take the (possibly blocking) real
    // flock OUTSIDE the mutex so other threads/keys are not stalled.
    const reg_key = held_gpa.dupe(u8, key) catch {
        held_mutex.unlock();
        return error.OutOfMemory;
    };
    held_locks.put(held_gpa, reg_key, .{
        .count = 1,
        .acquiring = true,
        .owner_actor = self_actor,
        .owner_blocking = !nonblocking,
    }) catch {
        held_gpa.free(reg_key);
        held_mutex.unlock();
        return error.OutOfMemory;
    };
    held_mutex.unlock();

    const real = acquireRealRepairLock(allocator, provider, account, nonblocking) catch |e| {
        held_mutex.lock();
        if (held_locks.fetchRemove(key)) |kv| held_gpa.free(kv.key);
        held_cond.broadcast();
        held_mutex.unlock();
        return e;
    };

    allocator.free(real.path);

    held_mutex.lock();
    if (held_locks.getPtr(key)) |entry| {
        entry.file = real.file;
        entry.acquiring = false;
    } else {
        // Should not happen (we own the 'acquiring' reservation), but stay safe.
        // Close only — the lock file itself persists (see release()).
        real.file.close();
    }
    held_cond.broadcast();
    held_mutex.unlock();

    return .{ .allocator = allocator, .key = key };
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

// TIN-1806: reauth jobs serialize against the same per-account flock domain as
// refresh/session/repair. Exporting this as "reauth" metadata gives child
// processes and probes a stable place to coordinate without inventing a second
// lock namespace that would fail to protect the credential store.
pub fn reauthLocksDir(allocator: std.mem.Allocator) ![]const u8 {
    return locksDir(allocator);
}

pub fn reauthJobAlloc(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ provider, account });
}

pub fn lockPath(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) ![]const u8 {
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
        std.fs.cwd().makePath(dir) catch |e| switch (e) {
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
    try writer.writeAll(",\"engine_run_available\":");
    if (event.engine_run_available) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"execution\":");
    if (event.execution) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"agent_safe\":");
    if (event.agent_safe) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"spends_provider_calls\":");
    if (event.spends_provider_calls) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"budget\":");
    if (event.budget) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"repair_owner\":");
    if (event.repair_owner) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"fresh_browser_context_required\":");
    if (event.fresh_browser_context_required) |value| try writer.writeAll(if (value) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"browser_context\":");
    if (event.browser_context) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
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

/// Test helper: scope lock files to a per-test tmp runtime dir via the
/// OMUX_RUNTIME_DIR seam so unit tests never write into the user's real
/// runtime dir (locks persist after TIN-2041, so stray writes are permanent).
/// Pub so other modules' lock tests (pipeline refresh/probe) reuse it instead
/// of polluting the real repair-locks dir (TIN-2039 review).
pub const TestRuntimeDirScope = struct {
    tmp: std.testing.TmpDir,
    root: []const u8,
    overrides: std.process.EnvMap,

    pub fn init(allocator: std.mem.Allocator) !TestRuntimeDirScope {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(root);
        var overrides = std.process.EnvMap.init(allocator);
        errdefer overrides.deinit();
        try overrides.put("OMUX_RUNTIME_DIR", root);
        return .{ .tmp = tmp, .root = root, .overrides = overrides };
    }

    pub fn activate(self: *TestRuntimeDirScope) void {
        env.test_overrides = &self.overrides;
    }

    pub fn deinit(self: *TestRuntimeDirScope, allocator: std.mem.Allocator) void {
        env.test_overrides = null;
        self.overrides.deinit();
        allocator.free(self.root);
        self.tmp.cleanup();
    }
};

test "repair lock is re-entrant within one actor (TIN-1851 no self-deadlock)" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    // First acquire takes the real OS flock.
    var l1 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    // A second acquire of the SAME key from the SAME actor (this thread) must
    // return immediately (re-entrant) rather than self-deadlock on the per-fd
    // flock.
    var l2 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    // A nonblocking acquire from the same actor is also re-entrant (already
    // serialized by the held lock), NOT RepairInProgress.
    var l3 = try acquireRepairLock(a, "codex", "tin1851-reentrancy-test");
    l3.release();
    l2.release();
    l1.release();
    // Fully released: a fresh acquire succeeds and the registry entry is gone.
    var l4 = try acquireRepairLockBlocking(a, "codex", "tin1851-reentrancy-test");
    l4.release();
}

test "cross-actor in-process nonblocking acquire is refused, not re-entrant (TIN-2059)" {
    // Two logical actors in ONE process contending for one provider:account:
    // the second (warm-tick-shaped, nonblocking) actor must get the typed
    // RepairInProgress busy result while the first holds — never a refcount
    // join. Deterministic: the worker thread is joined BEFORE the holder
    // releases, so the hold provably spans the worker's attempt.
    //
    // FAILS-against-old proof: with the actor gate temporarily reverted to the
    // pre-TIN-2059 unconditional `entry.count += 1` join (removing the
    // owner_actor check so any in-process acquire refcounts), the expect below
    // failed — the worker's acquire SUCCEEDED while the main thread held the
    // key. Verified 2026-07-02 by reverting the gate locally, observing this
    // test fail, then restoring the gate.
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var holder = try acquireRepairLock(a, "codex", "tin2059-cross-actor-nonblocking");

    const Worker = struct {
        fn run(refused: *bool) void {
            // Distinct thread = distinct actor. Must be refused while held.
            if (acquireRepairLock(std.testing.allocator, "codex", "tin2059-cross-actor-nonblocking")) |lock| {
                var l = lock;
                l.release();
                refused.* = false; // joined a cross-actor hold: the TIN-2059 defect
            } else |e| {
                refused.* = (e == error.RepairInProgress);
            }
        }
    };
    var refused = false;
    const worker = try std.Thread.spawn(.{}, Worker.run, .{&refused});
    worker.join();
    try std.testing.expect(refused);

    holder.release();
    // Fully released: the key is free again for any actor.
    var again = try acquireRepairLock(a, "codex", "tin2059-cross-actor-nonblocking");
    again.release();
}

test "blocking join adopts the session actor so materializer nesting works (TIN-1851/TIN-2059)" {
    // The managed-session shape from the real call graph: the session main
    // thread holds the account lock (blocking, adapters/codex/main.zig:1440
    // shape) AND the identity lock (nonblocking, :1452 shape). The proxy
    // materializer thread blocking-joins the account hold
    // (broker_loader.zig:368 shape) and must then be recognized as the SAME
    // actor for its nested identity acquire (:404 shape) — while a third,
    // unrelated actor is still refused on both keys.
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var account_hold = try acquireRepairLockBlocking(a, "codex", "tin2059-adopt-account");
    var identity_hold = try acquireRepairLock(a, "codex-identity", "tin2059-adopt-id");

    const Materializer = struct {
        fn run(ok: *bool) void {
            const ta = std.testing.allocator;
            // Blocking join of the blocking-held account key: immediate (no
            // self-deadlock), adopting the session's actor for the hold.
            var acct = acquireRepairLockBlocking(ta, "codex", "tin2059-adopt-account") catch {
                ok.* = false;
                return;
            };
            defer acct.release();
            // Nested identity acquire is now same-actor: allowed.
            var ident = acquireRepairLock(ta, "codex-identity", "tin2059-adopt-id") catch {
                ok.* = false;
                return;
            };
            ident.release();
            ok.* = true;
        }
    };
    var materializer_ok = false;
    const mt = try std.Thread.spawn(.{}, Materializer.run, .{&materializer_ok});
    mt.join(); // joined while the session still holds both keys
    try std.testing.expect(materializer_ok);

    const Stranger = struct {
        fn run(refused: *bool) void {
            if (acquireRepairLock(std.testing.allocator, "codex-identity", "tin2059-adopt-id")) |lock| {
                var l = lock;
                l.release();
                refused.* = false;
            } else |e| {
                refused.* = (e == error.RepairInProgress);
            }
        }
    };
    var stranger_refused = false;
    const st = try std.Thread.spawn(.{}, Stranger.run, .{&stranger_refused});
    st.join();
    try std.testing.expect(stranger_refused);

    identity_hold.release();
    account_hold.release();
}

test "cross-actor blocking acquire serializes BEHIND a nonblocking hold (TIN-2059)" {
    // The warm-tick-holds / materializer-arrives shape: a blocking acquirer
    // hitting a NONBLOCKING (short-hold typed writer) hold must WAIT for full
    // release — never cooperative-join it — so its under-lock revalidation
    // runs strictly after the holder's rotation. Under the actor gate the
    // waiter can only acquire after release, so `overlapped` stays false by
    // construction. Against the old unconditional join this leg failed
    // whenever the waiter got scheduled inside the yield window (near-always;
    // the deterministic old-behavior witness is the cross-actor nonblocking
    // test above).
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var holder = try acquireRepairLock(a, "codex", "tin2059-serialize-behind");
    var holder_released = std.atomic.Value(bool).init(false);
    var overlapped = std.atomic.Value(bool).init(false);

    const Waiter = struct {
        fn run(released: *std.atomic.Value(bool), ov: *std.atomic.Value(bool)) void {
            var l = acquireRepairLockBlocking(std.testing.allocator, "codex", "tin2059-serialize-behind") catch {
                ov.store(true, .seq_cst); // a blocking acquire must not fail here
                return;
            };
            if (!released.load(.seq_cst)) ov.store(true, .seq_cst);
            l.release();
        }
    };
    const waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &holder_released, &overlapped });
    // Give an (incorrect) instant join every chance to happen before release.
    var i: usize = 0;
    while (i < 200) : (i += 1) std.Thread.yield() catch {};
    holder_released.store(true, .seq_cst);
    holder.release();
    waiter.join();
    try std.testing.expect(!overlapped.load(.seq_cst));
}

test "lock file path persists after acquire+release (TIN-2041 no unlink-on-release)" {
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const path = try lockPath(a, "codex", "tin2041-lockfile-persists");
    defer a.free(path);
    std.fs.deleteFileAbsolute(path) catch {}; // start from a clean slate

    var lock = try acquireRepairLockBlocking(a, "codex", "tin2041-lockfile-persists");
    try std.fs.accessAbsolute(path, .{});
    lock.release();
    // The lock file must STILL exist: release only drops the flock. Unlinking
    // here is what orphaned the inode under a waiter (TIN-2041).
    try std.fs.accessAbsolute(path, .{});
}

test "release hands the SAME inode to the next acquirer under kernel flock conflict (TIN-2041)" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var scope = try TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();
    const provider = "codex";
    const account = "tin2041-ofd-conflict";

    const path = try lockPath(a, provider, account);
    defer a.free(path);
    std.fs.deleteFileAbsolute(path) catch {}; // start from a clean slate

    // A: public-API acquire takes the real OS flock for this process.
    var lock_a = try acquireRepairLock(a, provider, account);

    const ino_before = blk: {
        const f = try std.fs.openFileAbsolute(path, .{});
        defer f.close();
        break :blk (try f.stat()).inode;
    };

    // B: a second, distinct open-file-description on the same path. flock is
    // per-OFD, so this conflicts even within one process; the public API would
    // refcount-share, so go below it to create a real kernel conflict.
    try std.testing.expectError(error.RepairInProgress, acquireRealRepairLock(a, provider, account, true));

    lock_a.release();

    // B now acquires — and must get the SAME inode A held. The old
    // unlink-on-release orphaned A's inode under any blocked waiter and a
    // fresh acquire created a new inode at the path: two concurrent holders.
    const lock_b = try acquireRealRepairLock(a, provider, account, true);
    defer {
        lock_b.file.close();
        a.free(lock_b.path);
    }
    try std.testing.expectEqual(ino_before, (try lock_b.file.stat()).inode);

    // Mutual exclusion holds while B owns the lock: a third distinct-OFD
    // try-acquire fails.
    try std.testing.expectError(error.RepairInProgress, acquireRealRepairLock(a, provider, account, true));
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

test "handoff event json carries redacted consent metadata" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventJson(buf.writer(), .{
        .ts = 44,
        .kind = "daemon_handoff",
        .provider = "codex",
        .account = "max-1",
        .action = "reauth_start",
        .command = "oauth-mux codex login-device max-1",
        .engine_run_available = false,
        .execution = "command_owned",
        .agent_safe = false,
        .spends_provider_calls = false,
        .budget = "1 interactive login",
        .repair_owner = "upstream_cli_login",
        .fresh_browser_context_required = true,
        .browser_context = "fresh_incognito_or_isolated_profile",
        .outcome = "handoff_queued",
        .reason = "reauth_user_mediated",
        .interactive = true,
        .mutating = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"daemon_handoff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"engine_run_available\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"execution\":\"command_owned\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"fresh_browser_context_required\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"browser_context\":\"fresh_incognito_or_isolated_profile\"") != null);
}

test "sanitized lock file names do not preserve path separators" {
    const name = try sanitizedLockFileName(std.testing.allocator, "co/dex", "max:1");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("co_dex-max_1.lock", name);
}
