//! Announced, bounded advisory-lock acquisition (TIN-2049).
//!
//! The repair/account flock (repair_state.zig) is a cross-process OS flock. A
//! second launch of the same account blocks *inside* the kernel flock call with
//! no output until the first holder releases — and a live session holds it for
//! its whole duration, so the second launch reads as a silent, indefinite hang.
//!
//! This wrapper surfaces and bounds that wait WITHOUT changing lock granularity
//! or hold duration:
//!   - fast path: a single non-blocking `flock` attempt — no output, ~one
//!     syscall, when the lock is free;
//!   - on WOULD_BLOCK: emit ONE line naming the lock (and the holder, if the
//!     lock file records it), then poll, emitting a periodic still-waiting line
//!     with elapsed time;
//!   - a bounded overall timeout fails with `error.LockWaitTimeout` naming the
//!     path — never an unbounded silent hang.
//!
//! It operates on an already-open `std.fs.File` and uses standard-library
//! advisory locking (flock(2) / std.os.windows.LockFile) — no FFI, no platform-
//! specific holder digging. The caller keeps the file open for the lock's
//! lifetime and closes it to release (matching flock ownership).

const std = @import("std");
const builtin = @import("builtin");

pub const LockWaitError = error{LockWaitTimeout};

pub const WaitOptions = struct {
    /// How often to retry the non-blocking flock while waiting.
    poll_interval_ns: u64 = 200 * std.time.ns_per_ms,
    /// How often to emit a "still waiting" line while blocked.
    heartbeat_ns: u64 = 15 * std.time.ns_per_s,
    /// Overall bound on the wait. Generous by default; a live session holding
    /// the account lock for longer than this fails loudly rather than hanging.
    timeout_ns: u64 = 120 * std.time.ns_per_s,
};

/// One non-blocking attempt to take the exclusive advisory lock. Returns true if
/// acquired, false if an incompatible lock is already held. The file must stay
/// open for the lock's lifetime; closing it releases the lock.
pub fn tryLockFile(file: std.fs.File) std.fs.File.LockError!bool {
    if (comptime builtin.os.tag == .windows) {
        // Zig 0.14.1's std.fs.File.tryLock currently fails to compile for
        // Windows because its internal `.none => return` prong is analyzed even
        // when callers pass `.exclusive`. Use the same std.os.windows.LockFile
        // primitive directly so the release cross-targets stay buildable.
        const windows = std.os.windows;
        const range_off: windows.LARGE_INTEGER = 0;
        const range_len: windows.LARGE_INTEGER = 1;
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        windows.LockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &range_off,
            &range_len,
            null,
            windows.TRUE, // non-blocking=true
            1, // exclusive=true
        ) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => |e| return e,
        };
        return true;
    }
    return file.tryLock(.exclusive);
}

/// Acquire the exclusive advisory lock on `file`, taking the fast path when the
/// lock is free (no output) and otherwise announcing + bounding the wait.
/// `path` is used only for the log lines; `holder_hint`, when non-null, is
/// rendered as "(held by <hint>)" on the first wait line.
pub fn lockFileAnnounced(
    file: std.fs.File,
    path: []const u8,
    log: anytype,
    holder_hint: ?[]const u8,
    opts: WaitOptions,
) !void {
    if (try tryLockFile(file)) return; // uncontended: one syscall, no wait lines
    try waitForLock(file, path, log, holder_hint, opts);
}

/// Wait for an already-contended lock: emit the initial wait line, then poll
/// until acquired or the overall timeout elapses. Callers that have already
/// consumed the fast-path `tryLockFile` attempt use this directly so the
/// uncontended path pays for neither the announce nor the holder lookup.
pub fn waitForLock(
    file: std.fs.File,
    path: []const u8,
    log: anytype,
    holder_hint: ?[]const u8,
    opts: WaitOptions,
) !void {
    if (holder_hint) |hint| {
        log.print("[INF] waiting on lock {s} (held by {s})\n", .{ path, hint }) catch {};
    } else {
        log.print("[INF] waiting on lock {s}\n", .{path}) catch {};
    }

    var timer = std.time.Timer.start() catch {
        // No monotonic clock: fall back to a single blocking acquire rather
        // than busy-spinning unbounded. Still announced (line above).
        try file.lock(.exclusive);
        return;
    };
    var last_heartbeat_ns: u64 = 0;

    while (true) {
        std.Thread.sleep(opts.poll_interval_ns);
        if (try tryLockFile(file)) return;

        const elapsed_ns = timer.read();
        if (elapsed_ns >= opts.timeout_ns) {
            log.print(
                "[INF] gave up waiting on lock {s} after {d}s\n",
                .{ path, elapsed_ns / std.time.ns_per_s },
            ) catch {};
            return LockWaitError.LockWaitTimeout;
        }
        if (elapsed_ns - last_heartbeat_ns >= opts.heartbeat_ns) {
            last_heartbeat_ns = elapsed_ns;
            log.print(
                "[INF] still waiting on lock {s} ({d}s elapsed)\n",
                .{ path, elapsed_ns / std.time.ns_per_s },
            ) catch {};
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Two distinct open-file-descriptions on one path contend even within a single
/// process (flock is per-OFD), so these tests exercise the real WOULD_BLOCK path
/// with in-process handles.
fn openContender(dir: std.fs.Dir, name: []const u8) !std.fs.File {
    return dir.createFile(name, .{ .read = true, .truncate = false, .mode = 0o600 });
}

test "uncontended acquire takes the fast path and emits no wait lines" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openContender(tmp.dir, "free.lock");
    defer f.close();

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    try lockFileAnnounced(f, "free.lock", buf.writer(), null, .{});
    // Acquired without waiting: not a single announce byte.
    try testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "contended acquire announces the wait then times out with LockWaitTimeout naming the path" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var holder = try openContender(tmp.dir, "busy.lock");
    defer holder.close();
    try testing.expect(try tryLockFile(holder)); // hold it for the whole test

    var waiter = try openContender(tmp.dir, "busy.lock");
    defer waiter.close();

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const opts: WaitOptions = .{
        .poll_interval_ns = 2 * std.time.ns_per_ms,
        .heartbeat_ns = 1 * std.time.ns_per_hour,
        .timeout_ns = 40 * std.time.ns_per_ms,
    };
    try testing.expectError(
        LockWaitError.LockWaitTimeout,
        lockFileAnnounced(waiter, "busy.lock", buf.writer(), "pid 4242", opts),
    );

    // The would-block path emitted an actionable, path-naming wait line...
    try testing.expect(std.mem.indexOf(u8, buf.items, "waiting on lock busy.lock") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "held by pid 4242") != null);
    // ...and the timeout named the lock too.
    try testing.expect(std.mem.indexOf(u8, buf.items, "gave up waiting on lock busy.lock") != null);
}

test "contended acquire eventually succeeds after the holder releases" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var holder = try openContender(tmp.dir, "handoff.lock");
    defer holder.close();
    try testing.expect(try tryLockFile(holder));

    var waiter = try openContender(tmp.dir, "handoff.lock");
    defer waiter.close();

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const Waiter = struct {
        fn run(w: std.fs.File, out: *std.ArrayList(u8), result: *anyerror!void) void {
            const opts: WaitOptions = .{
                .poll_interval_ns = 2 * std.time.ns_per_ms,
                .heartbeat_ns = 1 * std.time.ns_per_hour,
                .timeout_ns = 5 * std.time.ns_per_s, // generous: must acquire, not time out
            };
            result.* = lockFileAnnounced(w, "handoff.lock", out.writer(), null, opts);
        }
    };

    var result: anyerror!void = {};
    const thread = try std.Thread.spawn(.{}, Waiter.run, .{ waiter, &buf, &result });
    // Hold long enough that the waiter provably enters the wait loop first.
    std.Thread.sleep(30 * std.time.ns_per_ms);
    holder.unlock();
    thread.join();

    try result; // acquired (no LockWaitTimeout) after the release
    try testing.expect(std.mem.indexOf(u8, buf.items, "waiting on lock handoff.lock") != null);
}
