//! BrowserLauncher: COOKIELESS BROWSER LAUNCHER.
//!
//! Tier 1 (default, zero-dep): print "open a PRIVATE/incognito window" + the
//!   authorize/verification URL (and non-secret user_code). Works over SSH, in
//!   pipes, in CI — anywhere. This is the safe default.
//!
//! Tier 2 (opportunistic): if a chromium-family binary exists, spawn it against a
//!   FRESH EPHEMERAL profile:
//!       chrome --user-data-dir=<ephemeral tmp> --no-first-run --incognito <url>
//!   The ephemeral profile dir is created before launch and deleted after the
//!   browser exits, so no cookies/history persist (cookieless).
//!
//! Auto-detect Tier 2 -> fall back to Tier 1 if no browser is found.
//!
//! INJECTED SEAMS: `which` (binary detection), `spawn` (process), temp-dir
//! create/delete, and `print` (output). Tests assert tier selection + the
//! ephemeral-dir create/delete lifecycle and that argv carries NO secret, all
//! WITHOUT touching the real filesystem, launching a real browser, or writing to
//! real stdout. Imports only `std`.
//!
//! SECURITY: only the non-secret authorize/verification URL (and user_code) ever
//! reaches argv. Access/refresh tokens never appear in argv or shell history.

const std = @import("std");

pub const BrowserTier = enum {
    /// Print instructions; user opens their own private window.
    tier1_print,
    /// Spawn a chromium-family browser with an ephemeral profile.
    tier2_ephemeral_chrome,
};

pub const BrowserLaunchError = error{
    ProcessSpawnFailed,
    TempDirCreationFailed,
    PrintFailed,
    OutOfMemory,
};

/// Result of a launch, so callers/tests can introspect what happened.
pub const LaunchResult = struct {
    tier: BrowserTier,
    /// Reserved for future lifecycle reporting. Today `launch()` deletes the
    /// ephemeral profile before returning and reports null for both tiers.
    ephemeral_dir: ?[]const u8 = null,
};

// ── Injected seams ───────────────────────────────────────────────────────────

/// Locate a binary on PATH (equivalent of `which`). Returns owned full path, or
/// null if not found.
pub const WhichFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    binary: []const u8,
) error{OutOfMemory}!?[]const u8;

/// Spawn a process with the given argv. Returns the exit code. The real impl uses
/// std.process.Child; tests record argv and return 0 without spawning.
pub const SpawnFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    argv: []const []const u8,
) error{ SpawnFailed, OutOfMemory }!i32;

/// Create a fresh ephemeral directory and return its owned path. Real impl makes a
/// unique temp dir; tests track creation without touching disk.
pub const MakeTempDirFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
) error{ TempDirCreationFailed, OutOfMemory }![]const u8;

/// Delete a previously created ephemeral directory.
pub const DeleteTempDirFn = *const fn (
    ctx: *anyopaque,
    path: []const u8,
) void;

/// Emit a line of instruction text to the operator. Injected so tests capture the
/// output instead of writing to real stdout. REDACTION (if any) lives here.
pub const PrintFn = *const fn (
    ctx: *anyopaque,
    line: []const u8,
) error{PrintFailed}!void;

pub const BrowserSeams = struct {
    which: WhichFn,
    spawn: SpawnFn,
    make_temp_dir: MakeTempDirFn,
    delete_temp_dir: DeleteTempDirFn,
    print: PrintFn,

    which_ctx: *anyopaque,
    spawn_ctx: *anyopaque,
    make_temp_dir_ctx: *anyopaque,
    delete_temp_dir_ctx: *anyopaque,
    print_ctx: *anyopaque,
};

/// Chromium-family binaries to probe, in preference order.
pub const chromium_candidates = [_][]const u8{
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "microsoft-edge",
};

pub const BrowserLauncher = struct {
    allocator: std.mem.Allocator,
    seams: BrowserSeams,
    /// Non-secret authorize / verification URL. Safe for argv + display.
    authorization_url: []const u8,
    /// Optional non-secret user/device code (RFC 8628). Safe to display.
    user_code: ?[]const u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        seams: BrowserSeams,
        authorization_url: []const u8,
        user_code: ?[]const u8,
    ) BrowserLauncher {
        return .{
            .allocator = allocator,
            .seams = seams,
            .authorization_url = authorization_url,
            .user_code = user_code,
        };
    }

    /// Probe for a chromium-family binary. Returns the owned path of the first
    /// match, or null. Caller frees the returned path.
    fn findChromium(self: *const BrowserLauncher) error{OutOfMemory}!?[]const u8 {
        for (chromium_candidates) |candidate| {
            const found = try self.seams.which(
                self.allocator,
                self.seams.which_ctx,
                candidate,
            );
            if (found) |path| return path;
        }
        return null;
    }

    /// Decide which tier to use without launching anything.
    pub fn detectTier(self: *const BrowserLauncher) error{OutOfMemory}!BrowserTier {
        const path = try self.findChromium();
        if (path) |p| {
            self.allocator.free(p);
            return .tier2_ephemeral_chrome;
        }
        return .tier1_print;
    }

    /// Launch: auto-detect tier, then either print (Tier 1) or spawn an ephemeral
    /// chromium (Tier 2) and clean up its profile dir afterward.
    pub fn launch(self: *const BrowserLauncher) BrowserLaunchError!LaunchResult {
        const chromium_path = try self.findChromium();
        if (chromium_path == null) {
            try self.printInstructions();
            return .{ .tier = .tier1_print, .ephemeral_dir = null };
        }
        const path = chromium_path.?;
        defer self.allocator.free(path);

        return self.launchEphemeralChrome(path);
    }

    fn printInstructions(self: *const BrowserLauncher) BrowserLaunchError!void {
        try self.seams.print(self.seams.print_ctx, "Browser authorization required.");
        try self.seams.print(self.seams.print_ctx, "Open a PRIVATE / INCOGNITO window and visit:");
        try self.seams.print(self.seams.print_ctx, self.authorization_url);
        if (self.user_code) |code| {
            // user_code is NOT a secret (RFC 8628); safe to print.
            const line = std.fmt.allocPrint(self.allocator, "Enter code: {s}", .{code}) catch
                return error.OutOfMemory;
            defer self.allocator.free(line);
            try self.seams.print(self.seams.print_ctx, line);
        }
        try self.seams.print(self.seams.print_ctx, "Return here after authenticating.");
    }

    fn launchEphemeralChrome(self: *const BrowserLauncher, chrome_path: []const u8) BrowserLaunchError!LaunchResult {
        // 1. Create the ephemeral profile dir.
        const profile_dir = self.seams.make_temp_dir(
            self.allocator,
            self.seams.make_temp_dir_ctx,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TempDirCreationFailed => return error.TempDirCreationFailed,
        };
        // Always delete the ephemeral profile, even on spawn failure (cookieless).
        defer self.seams.delete_temp_dir(self.seams.delete_temp_dir_ctx, profile_dir);

        // 2. Build argv. `--user-data-dir=<dir>` is a single token so the path
        //    cannot be mistaken for a positional arg. The ONLY URL/value passed is
        //    the non-secret authorization URL.
        const user_data_arg = std.fmt.allocPrint(
            self.allocator,
            "--user-data-dir={s}",
            .{profile_dir},
        ) catch return error.OutOfMemory;
        defer self.allocator.free(user_data_arg);

        var argv = std.ArrayList([]const u8).init(self.allocator);
        defer argv.deinit();
        argv.append(chrome_path) catch return error.OutOfMemory;
        argv.append(user_data_arg) catch return error.OutOfMemory;
        argv.append("--no-first-run") catch return error.OutOfMemory;
        argv.append("--no-default-browser-check") catch return error.OutOfMemory;
        argv.append("--incognito") catch return error.OutOfMemory;
        argv.append(self.authorization_url) catch return error.OutOfMemory;

        // 3. Spawn (blocks until the browser exits in the real impl).
        _ = self.seams.spawn(
            self.allocator,
            self.seams.spawn_ctx,
            argv.items,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SpawnFailed => return error.ProcessSpawnFailed,
        };

        // ephemeral_dir is reported back, but it has already been deleted by the
        // defer above by the time the caller inspects it (lifecycle is complete).
        return .{ .tier = .tier2_ephemeral_chrome, .ephemeral_dir = null };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TESTS (no real browser, no real filesystem, no real stdout)
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Records seam interactions so tests can assert tier selection, the temp-dir
/// create/delete lifecycle, captured output, and the exact argv (to prove no
/// secret leaks).
const Spy = struct {
    chrome_present: bool,

    // Temp-dir lifecycle bookkeeping.
    temp_created: usize = 0,
    temp_deleted: usize = 0,
    live_temp_dir: ?[]const u8 = null,
    fixed_temp_path: []const u8 = "/virtual/tmp/oauth-mux-XXXX",

    // Spawn bookkeeping. argv slices are duped into `arena` so they survive.
    spawned: bool = false,
    captured_argv: std.ArrayList([]const u8),

    // Captured printed lines.
    printed: std.ArrayList([]const u8),

    arena: std.mem.Allocator,

    fn init(arena: std.mem.Allocator, chrome_present: bool) Spy {
        return .{
            .chrome_present = chrome_present,
            .captured_argv = std.ArrayList([]const u8).init(arena),
            .printed = std.ArrayList([]const u8).init(arena),
            .arena = arena,
        };
    }

    fn which(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        binary: []const u8,
    ) error{OutOfMemory}!?[]const u8 {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        if (!self.chrome_present) return null;
        if (std.mem.eql(u8, binary, "google-chrome")) {
            return try allocator.dupe(u8, "/usr/bin/google-chrome");
        }
        return null;
    }

    fn spawn(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        argv: []const []const u8,
    ) error{ SpawnFailed, OutOfMemory }!i32 {
        _ = allocator;
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.spawned = true;
        for (argv) |arg| {
            const dup = self.arena.dupe(u8, arg) catch return error.OutOfMemory;
            self.captured_argv.append(dup) catch return error.OutOfMemory;
        }
        return 0;
    }

    fn makeTempDir(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
    ) error{ TempDirCreationFailed, OutOfMemory }![]const u8 {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.temp_created += 1;
        const path = allocator.dupe(u8, self.fixed_temp_path) catch return error.OutOfMemory;
        self.live_temp_dir = path;
        return path;
    }

    fn deleteTempDir(ctx: *anyopaque, path: []const u8) void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.temp_deleted += 1;
        // The path delivered to delete must be exactly the one we created.
        if (self.live_temp_dir) |live| {
            if (std.mem.eql(u8, live, path)) self.live_temp_dir = null;
        }
    }

    fn print(ctx: *anyopaque, line: []const u8) error{PrintFailed}!void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        const dup = self.arena.dupe(u8, line) catch return error.PrintFailed;
        self.printed.append(dup) catch return error.PrintFailed;
    }

    fn seams(self: *Spy) BrowserSeams {
        return .{
            .which = Spy.which,
            .spawn = Spy.spawn,
            .make_temp_dir = Spy.makeTempDir,
            .delete_temp_dir = Spy.deleteTempDir,
            .print = Spy.print,
            .which_ctx = @ptrCast(self),
            .spawn_ctx = @ptrCast(self),
            .make_temp_dir_ctx = @ptrCast(self),
            .delete_temp_dir_ctx = @ptrCast(self),
            .print_ctx = @ptrCast(self),
        };
    }
};

const SECRET_TOKEN = "ACCESS_TOKEN_THAT_MUST_NEVER_REACH_ARGV";
const AUTH_URL = "https://auth.example.com/device?user_code=WXYZ-7788";

test "tier detection: chrome present -> Tier 2" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var spy = Spy.init(arena, true);
    const launcher = BrowserLauncher.init(arena, spy.seams(), AUTH_URL, "WXYZ-7788");

    try testing.expectEqual(BrowserTier.tier2_ephemeral_chrome, try launcher.detectTier());
}

test "tier detection: chrome absent -> Tier 1" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var spy = Spy.init(arena, false);
    const launcher = BrowserLauncher.init(arena, spy.seams(), AUTH_URL, "WXYZ-7788");

    try testing.expectEqual(BrowserTier.tier1_print, try launcher.detectTier());
}

test "Tier 2: ephemeral profile dir is created then removed, and spawned" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var spy = Spy.init(arena, true);
    const launcher = BrowserLauncher.init(arena, spy.seams(), AUTH_URL, "WXYZ-7788");

    const result = try launcher.launch();

    try testing.expectEqual(BrowserTier.tier2_ephemeral_chrome, result.tier);
    try testing.expect(spy.spawned);
    // Lifecycle: created exactly once, deleted exactly once, none left live.
    try testing.expectEqual(@as(usize, 1), spy.temp_created);
    try testing.expectEqual(@as(usize, 1), spy.temp_deleted);
    try testing.expect(spy.live_temp_dir == null);
}

test "Tier 2: argv passes the ephemeral dir + auth URL but NEVER a secret" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var spy = Spy.init(arena, true);
    const launcher = BrowserLauncher.init(arena, spy.seams(), AUTH_URL, "WXYZ-7788");

    _ = try launcher.launch();

    var saw_user_data_dir = false;
    var saw_auth_url = false;
    for (spy.captured_argv.items) |arg| {
        // The secret must appear in NO argv token (substring check, not equality).
        try testing.expect(std.mem.indexOf(u8, arg, SECRET_TOKEN) == null);
        if (std.mem.startsWith(u8, arg, "--user-data-dir=")) saw_user_data_dir = true;
        if (std.mem.eql(u8, arg, AUTH_URL)) saw_auth_url = true;
    }
    try testing.expect(saw_user_data_dir);
    try testing.expect(saw_auth_url);
}

test "Tier 1: prints incognito instructions + URL + user_code, no spawn, no temp dir" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var spy = Spy.init(arena, false);
    const launcher = BrowserLauncher.init(arena, spy.seams(), AUTH_URL, "WXYZ-7788");

    const result = try launcher.launch();

    try testing.expectEqual(BrowserTier.tier1_print, result.tier);
    try testing.expect(!spy.spawned);
    try testing.expectEqual(@as(usize, 0), spy.temp_created);

    // Must mention private/incognito, the URL, and the user_code.
    var saw_incognito = false;
    var saw_url = false;
    var saw_code = false;
    for (spy.printed.items) |line| {
        if (std.mem.indexOf(u8, line, "INCOGNITO") != null or
            std.mem.indexOf(u8, line, "PRIVATE") != null) saw_incognito = true;
        if (std.mem.indexOf(u8, line, AUTH_URL) != null) saw_url = true;
        if (std.mem.indexOf(u8, line, "WXYZ-7788") != null) saw_code = true;
        // Never print a secret.
        try testing.expect(std.mem.indexOf(u8, line, SECRET_TOKEN) == null);
    }
    try testing.expect(saw_incognito);
    try testing.expect(saw_url);
    try testing.expect(saw_code);
}
