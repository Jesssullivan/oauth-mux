const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
const product_identity = @import("product_identity.zig");

pub const app_name = product_identity.storage_namespace;
const unix_socket_path_soft_limit = 100;

pub fn configDir(allocator: std.mem.Allocator) ![]const u8 {
    if (try env.get(allocator, "OMUX_CONFIG_DIR")) |dir| {
        defer allocator.free(dir);
        return absolutePath(allocator, dir);
    }
    return xdgOrMacOS(allocator, "XDG_CONFIG_HOME", ".config", "Application Support");
}

pub fn stateDir(allocator: std.mem.Allocator) ![]const u8 {
    if (try env.get(allocator, "OMUX_STATE_DIR")) |dir| {
        defer allocator.free(dir);
        return absolutePath(allocator, dir);
    }
    return xdgOrMacOS(allocator, "XDG_STATE_HOME", ".local/state", "Application Support");
}

pub fn runtimeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (try env.get(allocator, "OMUX_RUNTIME_DIR")) |dir| {
        defer allocator.free(dir);
        return absolutePath(allocator, dir);
    }
    // TIN-2039: repair-lock files intentionally persist after release
    // (TIN-2041), so test builds must not silently fall through to the
    // operator's real runtime dir. Tests that need cleanup still set
    // OMUX_RUNTIME_DIR via repair_state.TestRuntimeDirScope; this is only the
    // backstop for tests that forgot to scope themselves.
    if (comptime builtin.is_test) return testRuntimeDir(allocator);
    return productionRuntimeDir(allocator);
}

fn testRuntimeDir(allocator: std.mem.Allocator) ![]const u8 {
    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fs.path.join(allocator, &.{ cwd, ".zig-cache", "oauth-mux-test-runtime" });
}

fn productionRuntimeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (try env.get(allocator, "XDG_RUNTIME_DIR")) |dir| {
        defer allocator.free(dir);
        return std.fs.path.join(allocator, &.{ dir, app_name });
    }
    if (comptime builtin.os.tag == .macos) {
        // TIN-2041: the old fallback /tmp/oauth-mux-<uid> was subject to
        // periodic /tmp cleaning, which can unlink HELD repair-lock files and
        // break flock mutual exclusion (the same failure mode as
        // unlink-on-release, OS-triggered). Use a persistent per-user runtime
        // dir instead; it also hosts the daemon unix socket — that move is
        // intended.
        const home = (try env.get(allocator, "HOME")) orelse return error.OutOfMemory;
        defer allocator.free(home);
        return std.fs.path.join(allocator, &.{ home, "Library", "Application Support", app_name, "runtime" });
    }
    const home = (try env.get(allocator, "HOME")) orelse try allocator.dupe(u8, "/tmp");
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".local", "state", app_name });
}

pub fn configFilePath(allocator: std.mem.Allocator) ![]const u8 {
    if (try env.get(allocator, "OMUX_CONFIG")) |path| {
        defer allocator.free(path);
        return absolutePath(allocator, path);
    }
    const dir = try configDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "config.json" });
}

pub fn healthFilePath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try stateDir(allocator);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "health.json" });
}

pub fn socketPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = try runtimeDir(allocator);
    defer allocator.free(dir);
    return socketPathFromRuntimeDir(allocator, dir);
}

fn socketPathFromRuntimeDir(allocator: std.mem.Allocator, dir: []const u8) ![]const u8 {
    const path = try std.fs.path.join(allocator, &.{ dir, "daemon.sock" });
    if (comptime builtin.os.tag == .windows) return path;
    if (path.len < unix_socket_path_soft_limit) return path;

    defer allocator.free(path);
    const uid = (try env.get(allocator, "UID")) orelse try allocator.dupe(u8, "0");
    defer allocator.free(uid);
    const hash = std.hash.Wyhash.hash(0, path);
    return std.fmt.allocPrint(allocator, "/tmp/{s}-{s}/{x}.sock", .{ app_name, uid, hash });
}

fn xdgOrMacOS(
    allocator: std.mem.Allocator,
    xdg_env: []const u8,
    linux_default_suffix: []const u8,
    macos_dir_name: []const u8,
) ![]const u8 {
    if (try env.get(allocator, xdg_env)) |base| {
        defer allocator.free(base);
        const joined = try std.fs.path.join(allocator, &.{ base, app_name });
        defer allocator.free(joined);
        return absolutePath(allocator, joined);
    }
    const home = (try env.get(allocator, "HOME")) orelse return error.OutOfMemory;
    defer allocator.free(home);
    if (comptime builtin.os.tag == .macos) {
        return std.fs.path.join(allocator, &.{ home, "Library", macos_dir_name, app_name });
    }
    return std.fs.path.join(allocator, &.{ home, linux_default_suffix, app_name });
}

pub fn absolutePath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const expanded = try expandTilde(allocator, path);
    defer allocator.free(expanded);
    if (std.fs.path.isAbsolute(expanded)) return try allocator.dupe(u8, expanded);

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fs.path.join(allocator, &.{ cwd, expanded });
}

pub fn expandTilde(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len == 0) return try allocator.dupe(u8, path);
    if (path[0] != '~') return try allocator.dupe(u8, path);
    const home = (try env.get(allocator, "HOME")) orelse return try allocator.dupe(u8, path);
    defer allocator.free(home);
    if (path.len == 1) return try allocator.dupe(u8, home);
    return std.fs.path.join(allocator, &.{ home, path[2..] });
}

test "expandTilde" {
    const allocator = std.testing.allocator;
    {
        const result = try expandTilde(allocator, "/absolute/path");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/absolute/path", result);
    }
    {
        const result = try expandTilde(allocator, "");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("", result);
    }
}

test "absolutePath keeps absolute and expands relative paths" {
    const allocator = std.testing.allocator;
    {
        const result = try absolutePath(allocator, "/absolute/path");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/absolute/path", result);
    }
    {
        const result = try absolutePath(allocator, "relative/path");
        defer allocator.free(result);
        try std.testing.expect(std.fs.path.isAbsolute(result));
        try std.testing.expect(std.mem.endsWith(u8, result, "relative/path"));
    }
}

test "runtimeDir honors OMUX_RUNTIME_DIR override (test seam, 2026-06-12 audit)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var overrides = std.process.EnvMap.init(allocator);
    defer overrides.deinit();
    try overrides.put("OMUX_RUNTIME_DIR", root);
    env.test_overrides = &overrides;
    defer env.test_overrides = null;

    const dir = try runtimeDir(allocator);
    defer allocator.free(dir);
    try std.testing.expectEqualStrings(root, dir);
}

test "runtimeDir macOS fallback avoids periodically-cleaned /tmp (TIN-2041)" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const dir = try productionRuntimeDir(allocator);
    defer allocator.free(dir);
    if (try env.get(allocator, "XDG_RUNTIME_DIR")) |base| {
        defer allocator.free(base);
        // Explicit XDG runtime dir stays honored.
        try std.testing.expect(std.mem.startsWith(u8, dir, base));
        return;
    }
    try std.testing.expect(!std.mem.startsWith(u8, dir, "/tmp/"));
    try std.testing.expect(std.mem.endsWith(u8, dir, "Library/Application Support/oauth-mux/runtime"));
}

test "runtimeDir test fallback stays out of the operator runtime dir (TIN-2039)" {
    if (try env.get(std.testing.allocator, "OMUX_RUNTIME_DIR")) |base| {
        std.testing.allocator.free(base);
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    const dir = try runtimeDir(allocator);
    defer allocator.free(dir);

    try std.testing.expect(std.fs.path.isAbsolute(dir));
    try std.testing.expect(std.mem.indexOf(u8, dir, ".zig-cache") != null);
    try std.testing.expect(std.mem.endsWith(u8, dir, "oauth-mux-test-runtime"));
}

test "socketPathFromRuntimeDir keeps Unix socket paths under the platform limit" {
    if (comptime builtin.os.tag == .windows) return;

    const allocator = std.testing.allocator;
    const result = try socketPathFromRuntimeDir(
        allocator,
        "/tmp/oauth-mux-e2e.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    defer allocator.free(result);

    try std.testing.expect(result.len < unix_socket_path_soft_limit);
    try std.testing.expect(std.mem.startsWith(u8, result, "/tmp/oauth-mux-"));
    try std.testing.expect(std.mem.endsWith(u8, result, ".sock"));
}
