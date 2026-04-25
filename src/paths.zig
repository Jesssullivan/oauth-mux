const std = @import("std");
const builtin = @import("builtin");

pub const app_name = "oauth-mux";

pub fn configDir(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("OMUX_CONFIG_DIR")) |dir| {
        return try allocator.dupe(u8, dir);
    }
    return xdgOrMacOS(allocator, "XDG_CONFIG_HOME", ".config", "Application Support");
}

pub fn stateDir(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("OMUX_STATE_DIR")) |dir| {
        return try allocator.dupe(u8, dir);
    }
    return xdgOrMacOS(allocator, "XDG_STATE_HOME", ".local/state", "Application Support");
}

pub fn runtimeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("XDG_RUNTIME_DIR")) |dir| {
        return std.fs.path.join(allocator, &.{ dir, app_name });
    }
    if (comptime builtin.os.tag == .macos) {
        const uid = std.posix.getenv("UID") orelse "501";
        return std.fmt.allocPrint(allocator, "/tmp/{s}-{s}", .{ app_name, uid });
    }
    const home = std.posix.getenv("HOME") orelse "/tmp";
    return std.fs.path.join(allocator, &.{ home, ".local", "state", app_name });
}

pub fn configFilePath(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("OMUX_CONFIG")) |path| {
        return try allocator.dupe(u8, path);
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
    return std.fs.path.join(allocator, &.{ dir, "daemon.sock" });
}

fn xdgOrMacOS(
    allocator: std.mem.Allocator,
    xdg_env: []const u8,
    linux_default_suffix: []const u8,
    macos_dir_name: []const u8,
) ![]const u8 {
    if (std.posix.getenv(xdg_env)) |base| {
        return std.fs.path.join(allocator, &.{ base, app_name });
    }
    const home = std.posix.getenv("HOME") orelse return error.OutOfMemory;
    if (comptime builtin.os.tag == .macos) {
        return std.fs.path.join(allocator, &.{ home, "Library", macos_dir_name, app_name });
    }
    return std.fs.path.join(allocator, &.{ home, linux_default_suffix, app_name });
}

pub fn expandTilde(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len == 0) return try allocator.dupe(u8, path);
    if (path[0] != '~') return try allocator.dupe(u8, path);
    const home = std.posix.getenv("HOME") orelse return try allocator.dupe(u8, path);
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
