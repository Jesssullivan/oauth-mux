const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const env = @import("env.zig");

pub fn detect() types.ShellKind {
    const allocator = std.heap.page_allocator;
    if (env.get(allocator, "OMUX_SHELL") catch null) |s| {
        defer allocator.free(s);
        return shellFromName(s);
    }
    if (env.has("FISH_VERSION")) return .fish;
    if (env.has("ZSH_VERSION")) return .zsh;
    if (env.has("BASH_VERSION")) return .bash;
    if (env.has("KSH_VERSION")) return .ksh;

    if (env.get(allocator, "SHELL") catch null) |shell| {
        defer allocator.free(shell);
        return shellFromPath(shell);
    }
    return .posix;
}

fn shellFromName(name: []const u8) types.ShellKind {
    const map = std.StaticStringMap(types.ShellKind).initComptime(.{
        .{ "fish", .fish },
        .{ "zsh", .zsh },
        .{ "bash", .bash },
        .{ "ksh", .ksh },
    });
    return map.get(name) orelse .posix;
}

fn shellFromPath(path: []const u8) types.ShellKind {
    const basename = std.fs.path.basename(path);
    return shellFromName(basename);
}

pub fn emitEnv(
    writer: anytype,
    shell: types.ShellKind,
    env_pairs: []const [2][]const u8,
) !void {
    for (env_pairs) |pair| {
        try shell.exportStatement(writer, pair[0], pair[1]);
    }
}

pub fn execTarget(argv: []const []const u8, env_map: *std.process.EnvMap) error{ExecFailed}!noreturn {
    if (argv.len == 0) return error.ExecFailed;

    if (comptime builtin.os.tag == .windows) {
        var child = std.process.Child.init(argv, std.heap.page_allocator);
        child.env_map = env_map;
        const term = child.spawnAndWait() catch return error.ExecFailed;
        switch (term) {
            .Exited => |code| std.process.exit(code),
            else => std.process.exit(1),
        }
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const argv_z = alloc.allocSentinel(?[*:0]const u8, argv.len, null) catch return error.ExecFailed;
    for (argv, 0..) |arg, i| {
        argv_z[i] = alloc.dupeZ(u8, arg) catch return error.ExecFailed;
    }

    const envp = std.process.createNullDelimitedEnvMap(alloc, env_map) catch return error.ExecFailed;

    const err = std.posix.execvpeZ(argv_z[0].?, argv_z, envp);
    return switch (err) {
        error.FileNotFound, error.AccessDenied => error.ExecFailed,
        else => error.ExecFailed,
    };
}

test "detect returns a valid ShellKind" {
    const shell = detect();
    _ = shell;
}

test "shellFromPath" {
    try std.testing.expectEqual(types.ShellKind.fish, shellFromPath("/usr/bin/fish"));
    try std.testing.expectEqual(types.ShellKind.zsh, shellFromPath("/bin/zsh"));
    try std.testing.expectEqual(types.ShellKind.bash, shellFromPath("/usr/local/bin/bash"));
    try std.testing.expectEqual(types.ShellKind.posix, shellFromPath("/bin/sh"));
}

test "emitEnv fish" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const pairs = [_][2][]const u8{
        .{ "CLAUDE_CONFIG_DIR", "/tmp/omux-abc" },
        .{ "OMUX_ACTIVE_PROVIDER", "claude" },
    };
    try emitEnv(fbs.writer(), .fish, &pairs);
    const expected =
        "set -gx CLAUDE_CONFIG_DIR '/tmp/omux-abc';\n" ++
        "set -gx OMUX_ACTIVE_PROVIDER 'claude';\n";
    try std.testing.expectEqualStrings(expected, fbs.getWritten());
}

test "emitEnv bash" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const pairs = [_][2][]const u8{
        .{ "CODEX_HOME", "/tmp/omux-def" },
    };
    try emitEnv(fbs.writer(), .bash, &pairs);
    try std.testing.expectEqualStrings("export CODEX_HOME='/tmp/omux-def'\n", fbs.getWritten());
}
