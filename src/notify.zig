//! Desktop notification delivery seam (TIN-2061 MVP).
//!
//! A general, opt-in alerting channel: a PURE decision half (what to say, and
//! whether to say it) and an EFFECT half (say it, via a platform subprocess).
//! It is deliberately parallel to `secret.zig`'s keychain shell-out: no FFI, no
//! linked frameworks — macOS shells out to `/usr/bin/osascript` and Linux to
//! `notify-send`, exactly the "shell out for platform services, never FFI" rule
//! in AGENTS.md and the same move the notification survey recommends
//! (`docs/spec/notification-delivery-survey-2026-07-09.md`).
//!
//! CONTENT DISCIPLINE: no title/body string ever carries a token or credential
//! payload. Events are built from config-labels (provider/account names — safe,
//! operator-chosen) and fixed reason strings only. The effect half logs at most
//! a subprocess exit code, never the notification body (mirroring the
//! never-log-the-secret discipline of `secret.zig`).
//!
//! This module has NO knowledge of keepalive: the keepalive wiring lives in
//! `keepalive/notify_adapter.zig`, which translates a scheduler transition into
//! one of these events and applies the opt-in + dedupe policy.

const std = @import("std");
const builtin = @import("builtin");
const log = @import("log.zig");

pub const NotifyError = error{
    /// No notification backend for this OS (e.g. Windows — not built yet).
    UnsupportedPlatform,
    /// Linux `notify-send` is not on PATH (or the macOS binary is missing).
    NotifyUnavailable,
    /// The backend ran but returned a non-zero exit status.
    NotifyFailed,
    IoError,
    OutOfMemory,
};

// ── Pure vocabulary ──────────────────────────────────────────────────────────

/// The operator-relevant transitions worth a desktop alert. Every field is a
/// non-secret: `provider`/`account` are config labels, `reason` is a fixed
/// caller-chosen phrase (NEVER a raw provider error, which could echo a token).
pub const NotifyEvent = union(enum) {
    refresh_failed: struct { provider: []const u8, account: []const u8, reason: []const u8 },
    credential_dead: struct { provider: []const u8, account: []const u8 },
    all_waiting: struct { provider: []const u8, wait_until_ms: i64 },
};

/// Opt-in delivery policy. DEFAULTS OFF — nothing is ever delivered unless the
/// operator turns it on. `min_interval_ms` is a simple per-target dedupe floor
/// (the caller keys "last sent" per event target; see `shouldNotify`).
pub const Policy = struct {
    enabled: bool = false,
    min_interval_ms: u64 = 60_000,
};

/// PURE decision: should this event be delivered now? `last_sent_ms` is the
/// instant this event's target was last notified (null = never). The decision
/// is: opt-in on, AND (never sent, OR at least `min_interval_ms` has elapsed).
/// A backwards clock (now < last) is treated as "elapsed enough" rather than
/// wedging the channel shut forever.
pub fn shouldNotify(policy: Policy, event: NotifyEvent, last_sent_ms: ?i64, now_ms: i64) bool {
    _ = event; // reserved: per-event-kind policy is a future increment (TIN-2061)
    if (!policy.enabled) return false;
    const last = last_sent_ms orelse return true;
    if (now_ms <= last) return true;
    const elapsed: u64 = @intCast(now_ms - last);
    return elapsed >= policy.min_interval_ms;
}

/// A rendered notification. Owns fixed-size buffers so rendering NEVER
/// allocates and NEVER fails (over-long labels truncate cleanly rather than
/// erroring or panicking). Copy-by-value is ~500B, cheap for the tick path.
pub const Rendered = struct {
    title_buf: [96]u8 = undefined,
    title_len: usize = 0,
    body_buf: [400]u8 = undefined,
    body_len: usize = 0,

    pub fn title(self: *const Rendered) []const u8 {
        return self.title_buf[0..self.title_len];
    }
    pub fn body(self: *const Rendered) []const u8 {
        return self.body_buf[0..self.body_len];
    }
};

/// Truncating formatter: write `fmt` into `buf`, returning the (possibly
/// truncated) written slice. Never errors — a too-long value yields the prefix
/// that fit, so no notification-render path can fail or panic.
fn fitInto(buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    fbs.writer().print(fmt, args) catch {};
    return fbs.getWritten();
}

/// PURE: render an event's title + body. Exhaustive over the event union. No
/// string here carries a secret — only the event's non-secret fields appear.
pub fn renderNotification(event: NotifyEvent) Rendered {
    var r = Rendered{};
    switch (event) {
        .refresh_failed => |e| {
            r.title_len = fitInto(&r.title_buf, "oauth-mux: refresh failed", .{}).len;
            r.body_len = fitInto(&r.body_buf, "{s}/{s}: {s}", .{ e.provider, e.account, e.reason }).len;
        },
        .credential_dead => |e| {
            r.title_len = fitInto(&r.title_buf, "oauth-mux: credential dead", .{}).len;
            r.body_len = fitInto(&r.body_buf, "{s}/{s}: repeated refresh failures — re-login needed", .{ e.provider, e.account }).len;
        },
        .all_waiting => |e| {
            r.title_len = fitInto(&r.title_buf, "oauth-mux: all accounts waiting", .{}).len;
            r.body_len = fitInto(&r.body_buf, "{s}: all accounts rate-limited (until {d} ms)", .{ e.provider, e.wait_until_ms }).len;
        },
    }
    return r;
}

// ── AppleScript escaping (pure, adversarial-tested) ──────────────────────────

/// PURE: escape a string so it is safe inside an AppleScript double-quoted
/// literal. A body containing `"` or `\` MUST NOT be able to break out of the
/// string and inject AppleScript; a raw newline MUST NOT split the single-line
/// `-e` script. Caller owns the returned bytes. Non-ASCII (UTF-8) passes
/// through verbatim — `osascript` accepts UTF-8.
pub fn escapeAppleScript(allocator: std.mem.Allocator, in: []const u8) std.mem.Allocator.Error![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    for (in) |c| {
        switch (c) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, c),
        }
    }
    return out.toOwnedSlice(allocator);
}

// ── Effect: post a notification via a platform subprocess ────────────────────

/// Dispatch by OS with an exhaustive-by-branch switch. Every platform without a
/// backend returns a typed error rather than silently no-op'ing.
pub fn post(allocator: std.mem.Allocator, title: []const u8, body: []const u8) NotifyError!void {
    return switch (builtin.os.tag) {
        .macos => postDarwin(allocator, title, body),
        .linux => postLinux(allocator, title, body),
        else => error.UnsupportedPlatform,
    };
}

/// macOS: `/usr/bin/osascript -e 'display notification "<body>" with title
/// "<title>"'`. The whole script is ONE argv element (no shell), and both
/// interpolated strings are AppleScript-escaped so neither can break out.
pub fn postDarwin(allocator: std.mem.Allocator, title: []const u8, body: []const u8) NotifyError!void {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const esc_title = try escapeAppleScript(allocator, title);
    defer allocator.free(esc_title);
    const esc_body = try escapeAppleScript(allocator, body);
    defer allocator.free(esc_body);

    const script = std.fmt.allocPrint(
        allocator,
        "display notification \"{s}\" with title \"{s}\"",
        .{ esc_body, esc_title },
    ) catch return error.OutOfMemory;
    defer allocator.free(script);

    const result = runProcess(allocator, &.{ "/usr/bin/osascript", "-e", script }) catch return error.IoError;
    defer allocator.free(result.stdout);
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            // Exit code only — never the body (which names an account label).
            log.debug("notify: osascript exited {d}", .{code});
            return error.NotifyFailed;
        },
        else => return error.IoError,
    }
}

/// Linux: `notify-send <title> <body>`. PATH-resolved (the binary's location
/// varies by distro), passed as separate argv (no shell, no escaping needed).
/// Absent binary → typed `NotifyUnavailable`, never a panic.
pub fn postLinux(allocator: std.mem.Allocator, title: []const u8, body: []const u8) NotifyError!void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const result = runProcess(allocator, &.{ "notify-send", title, body }) catch |e| switch (e) {
        error.FileNotFound => return error.NotifyUnavailable,
        else => return error.IoError,
    };
    defer allocator.free(result.stdout);
    defer if (result.stderr.len > 0) allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            log.debug("notify: notify-send exited {d}", .{code});
            return error.NotifyFailed;
        },
        else => return error.IoError,
    }
}

const ProcessResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    term: std.process.Child.Term,
};

/// Upper bound on how long we wait for a notification subprocess. A best-effort
/// desktop alert must NEVER stall the keepalive tick: the seam is invoked inline
/// on the scheduler's failure path, and under launchd with no active Aqua
/// session (or a wedged NotificationCenter) `osascript display notification` can
/// block indefinitely. The watchdog SIGKILLs the child at this deadline so
/// `wait()` always returns. Generous (10s) so a merely slow-but-live backend is
/// not false-killed — normal delivery is sub-second.
const default_notify_timeout_ns: u64 = 10 * std.time.ns_per_s;

/// SIGKILL the notification child so a hung subprocess cannot pin the caller's
/// `wait()` open. SIGKILL is uncatchable, so the time bound always holds. Total
/// over `builtin.os.tag` (the off-posix prong is never analyzed there) — notify
/// only ever spawns on macOS/Linux, but the file cross-compiles for all targets.
fn killNotifyChild(child: *std.process.Child) void {
    switch (builtin.os.tag) {
        .macos, .linux => std.posix.kill(child.id, std.posix.SIG.KILL) catch {},
        else => {},
    }
}

/// Watchdog thread: block until the caller signals completion via `done`, or
/// SIGKILL the child once `timeout_ns` elapses first. The caller reaps either
/// way (a normal exit, or the kill it just triggered).
const NotifyWatchdog = struct {
    child: *std.process.Child,
    timeout_ns: u64,
    done: std.Thread.ResetEvent = .{},

    fn run(self: *NotifyWatchdog) void {
        self.done.timedWait(self.timeout_ns) catch killNotifyChild(self.child);
    }
};

/// Spawn `argv`, pipe stdout/stderr, wait — bounded by `default_notify_timeout_ns`.
/// Mirrors `secret.zig`'s `runProcess` (std-only, no shell); a missing binary
/// surfaces as the spawn error (`error.FileNotFound`) so callers can distinguish
/// "not installed" from "ran and failed".
fn runProcess(allocator: std.mem.Allocator, argv: []const []const u8) !ProcessResult {
    return runProcessTimed(allocator, argv, default_notify_timeout_ns);
}

/// Bounded variant of `runProcess`: a watchdog thread SIGKILLs the child if it
/// outlives `timeout_ns`, so a hung subprocess can never block the wait — and
/// therefore never stall the keepalive tick — indefinitely.
fn runProcessTimed(allocator: std.mem.Allocator, argv: []const []const u8, timeout_ns: u64) !ProcessResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // Arm the deadline. If the watchdog thread cannot spawn (resource
    // exhaustion), degrade to an unbounded wait rather than failing delivery.
    var wd = NotifyWatchdog{ .child = &child, .timeout_ns = timeout_ns };
    const wd_thread: ?std.Thread = std.Thread.spawn(.{}, NotifyWatchdog.run, .{&wd}) catch null;
    defer if (wd_thread) |t| {
        wd.done.set(); // release the watchdog (idempotent if it already fired)
        t.join();
    };

    var stdout_buf = std.ArrayListUnmanaged(u8){};
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    errdefer stdout_buf.deinit(allocator);
    errdefer stderr_buf.deinit(allocator);

    child.collectOutput(allocator, &stdout_buf, &stderr_buf, 1024 * 1024) catch {};
    const term = try child.wait();

    return .{
        .stdout = stdout_buf.toOwnedSlice(allocator) catch &.{},
        .stderr = stderr_buf.toOwnedSlice(allocator) catch &.{},
        .term = term,
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

// The same secret-marker vocabulary the fixture-redaction scanner forbids; a
// rendered notification must never contain any of these.
const forbidden_markers = [_][]const u8{
    "access_token", "refresh_token", "id_token",     "client_secret",
    "authorization:", "authorization=", "bearer ",   "bearer%20",
    "set-cookie:",  "cookie:",        "sk-",          "sess-",
};

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

test {
    // Force analysis of BOTH platform backends on every host (CI runs/cross-
    // compiles on Linux too), so a latent error in the non-host backend can't
    // hide behind the comptime `post` dispatch.
    std.testing.refAllDeclsRecursive(@This());
}

test "escapeAppleScript: double quotes cannot break out" {
    const out = try escapeAppleScript(std.testing.allocator, "he said \"hi\"");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("he said \\\"hi\\\"", out);
}

test "escapeAppleScript: backslashes are doubled" {
    const out = try escapeAppleScript(std.testing.allocator, "a\\b\\\\c");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\\\\b\\\\\\\\c", out);
}

test "escapeAppleScript: a trailing backslash cannot escape the closing quote" {
    // Adversarial: `...\` before the literal's closing quote would, unescaped,
    // turn the closing `"` into an escaped quote and swallow the rest of the
    // script. Doubling the backslash defuses it.
    const out = try escapeAppleScript(std.testing.allocator, "payload\\");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("payload\\\\", out);
    // The last two chars are both backslashes → the following `"` in the script
    // template stays a real closing quote.
    try std.testing.expect(out[out.len - 1] == '\\' and out[out.len - 2] == '\\');
}

test "escapeAppleScript: newlines, CR and tabs become escape sequences" {
    const out = try escapeAppleScript(std.testing.allocator, "a\nb\r\tc");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\\nb\\r\\tc", out);
    // No raw control byte survives to split the single-line -e script.
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\n') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\t') == null);
}

test "escapeAppleScript: unicode passes through untouched" {
    const in = "café — naïve 日本語 🔒";
    const out = try escapeAppleScript(std.testing.allocator, in);
    defer std.testing.allocator.free(out);
    // No quote/backslash/control bytes in the input → identical output.
    try std.testing.expectEqualStrings(in, out);
}

test "escapeAppleScript: injection attempt stays inside the literal" {
    // A body that tries to close the string and append its own AppleScript.
    const attack = "\" & (do shell script \"rm -rf ~\") & \"";
    const out = try escapeAppleScript(std.testing.allocator, attack);
    defer std.testing.allocator.free(out);
    // Every double-quote is now backslash-escaped: the string can't be closed.
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        if (out[i] == '"') {
            try std.testing.expect(i > 0 and out[i - 1] == '\\');
        }
    }
}

test "shouldNotify: disabled never notifies" {
    const ev = NotifyEvent{ .credential_dead = .{ .provider = "claude", .account = "work" } };
    try std.testing.expect(!shouldNotify(.{ .enabled = false }, ev, null, 1_000));
    // Even a long-elapsed target stays silent while disabled.
    try std.testing.expect(!shouldNotify(.{ .enabled = false, .min_interval_ms = 10 }, ev, 0, 1_000_000));
}

test "shouldNotify: first send (never sent) always fires when enabled" {
    const ev = NotifyEvent{ .refresh_failed = .{ .provider = "codex", .account = "a", .reason = "x" } };
    try std.testing.expect(shouldNotify(.{ .enabled = true }, ev, null, 0));
}

test "shouldNotify: dedupes within the interval, fires after it" {
    const ev = NotifyEvent{ .refresh_failed = .{ .provider = "codex", .account = "a", .reason = "x" } };
    const policy = Policy{ .enabled = true, .min_interval_ms = 60_000 };
    // sent at t=1000; a re-fire 59_999ms later is suppressed, at 60_000ms allowed.
    try std.testing.expect(!shouldNotify(policy, ev, 1_000, 1_000 + 59_999));
    try std.testing.expect(shouldNotify(policy, ev, 1_000, 1_000 + 60_000));
    try std.testing.expect(shouldNotify(policy, ev, 1_000, 1_000 + 60_001));
}

test "shouldNotify: a backwards clock does not wedge the channel" {
    const ev = NotifyEvent{ .credential_dead = .{ .provider = "claude", .account = "work" } };
    try std.testing.expect(shouldNotify(.{ .enabled = true }, ev, 10_000, 5_000));
}

test "renderNotification: refresh_failed carries the labels, no token markers" {
    const r = renderNotification(.{ .refresh_failed = .{
        .provider = "claude",
        .account = "work-account",
        .reason = "proactive refresh was refused or failed",
    } });
    try std.testing.expect(containsIgnoreCase(r.body(), "claude"));
    try std.testing.expect(containsIgnoreCase(r.body(), "work-account"));
    for (forbidden_markers) |m| {
        try std.testing.expect(!containsIgnoreCase(r.title(), m));
        try std.testing.expect(!containsIgnoreCase(r.body(), m));
    }
}

test "renderNotification: all three variants render non-empty and marker-free" {
    const events = [_]NotifyEvent{
        .{ .refresh_failed = .{ .provider = "codex", .account = "acct", .reason = "refresh failed" } },
        .{ .credential_dead = .{ .provider = "claude", .account = "acct" } },
        .{ .all_waiting = .{ .provider = "claude", .wait_until_ms = 1_720_000_000_000 } },
    };
    for (events) |ev| {
        const r = renderNotification(ev);
        try std.testing.expect(r.title().len > 0);
        try std.testing.expect(r.body().len > 0);
        for (forbidden_markers) |m| {
            try std.testing.expect(!containsIgnoreCase(r.title(), m));
            try std.testing.expect(!containsIgnoreCase(r.body(), m));
        }
    }
}

test "renderNotification: a pathologically long label truncates, never overflows" {
    const long = "x" ** 4096;
    const r = renderNotification(.{ .refresh_failed = .{ .provider = long, .account = long, .reason = long } });
    try std.testing.expect(r.body().len <= r.body_buf.len);
    try std.testing.expect(r.title().len <= r.title_buf.len);
}

test "post: unsupported platform is a typed error, not a panic" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) {
        try std.testing.expectError(error.UnsupportedPlatform, post(std.testing.allocator, "t", "b"));
    }
}

test "runProcessTimed: a hung child is SIGKILLed at the deadline, never blocks forever" {
    // POSIX only — the watchdog kills via std.posix.kill.
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return;

    const start = std.time.milliTimestamp();
    // `sleep 60` asks for 60s (PATH-resolved, no slash); we bound it to 200ms.
    // The BUG (un-timed wait) would pin this test open for ~60_000ms; the fix
    // returns at the deadline with the child SIGKILLed.
    const res = try runProcessTimed(std.testing.allocator, &.{ "sleep", "60" }, 200 * std.time.ns_per_ms);
    defer std.testing.allocator.free(res.stdout);
    defer if (res.stderr.len > 0) std.testing.allocator.free(res.stderr);

    const elapsed = std.time.milliTimestamp() - start;
    try std.testing.expect(elapsed < 5_000); // nowhere near the 60s the child asked for
    const killed = switch (res.term) {
        .Signal => true, // SIGKILL from the watchdog, not a clean exit
        else => false,
    };
    try std.testing.expect(killed);
}

test "runProcessTimed: a fast child completes normally, watchdog never fires" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return;

    // `true` exits 0 immediately; a generous deadline must NOT kill it — the
    // fast path still reports the real exit status (so the adapter's record/
    // retry contract is preserved).
    const res = try runProcessTimed(std.testing.allocator, &.{ "true", }, 10 * std.time.ns_per_s);
    defer std.testing.allocator.free(res.stdout);
    defer if (res.stderr.len > 0) std.testing.allocator.free(res.stderr);

    const exited_zero = switch (res.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    try std.testing.expect(exited_zero);
}
