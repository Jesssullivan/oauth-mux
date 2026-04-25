const std = @import("std");
const types = @import("types.zig");

pub const version = "0.1.0";

pub const Command = union(enum) {
    exec: ExecArgs,
    env: EnvArgs,
    status: StatusArgs,
    health: HealthArgs,
    config_validate,
    config_path,
    init: InitArgs,
    completions: CompletionsArgs,
    daemon_start,
    daemon_stop,
    daemon_status,
    version_cmd,
    help,

    pub const ExecArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        strategy: ?[]const u8 = null,
        target_argv: []const []const u8 = &.{},
    };

    pub const EnvArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        shell: ?[]const u8 = null,
    };

    pub const StatusArgs = struct {
        json: bool = false,
        provider: ?[]const u8 = null,
    };

    pub const HealthArgs = struct {
        json: bool = false,
        provider: ?[]const u8 = null,
        reset: ?[]const u8 = null,
    };

    pub const InitArgs = struct {
        interactive: bool = false,
    };

    pub const CompletionsArgs = struct {
        shell: []const u8 = "fish",
    };
};

pub fn parse(args: []const []const u8) Command {
    if (args.len == 0) return .help;

    const cmd = args[0];
    const rest = if (args.len > 1) args[1..] else &[_][]const u8{};

    if (eql(cmd, "exec")) return parseExec(rest);
    if (eql(cmd, "env")) return parseEnv(rest);
    if (eql(cmd, "status")) return parseStatus(rest);
    if (eql(cmd, "health")) return parseHealth(rest);
    if (eql(cmd, "config")) return parseConfig(rest);
    if (eql(cmd, "init")) return parseInit(rest);
    if (eql(cmd, "version") or eql(cmd, "--version") or eql(cmd, "-v")) return .version_cmd;
    if (eql(cmd, "daemon")) {
        if (rest.len > 0) {
            if (eql(rest[0], "start")) return .daemon_start;
            if (eql(rest[0], "stop")) return .daemon_stop;
            if (eql(rest[0], "status")) return .daemon_status;
        }
        return .daemon_status;
    }
    if (eql(cmd, "completions")) {
        if (rest.len > 0) return .{ .completions = .{ .shell = rest[0] } };
        return .{ .completions = .{} };
    }
    if (eql(cmd, "help") or eql(cmd, "--help") or eql(cmd, "-h")) return .help;

    return .help;
}

fn parseExec(args: []const []const u8) Command {
    var result = Command.ExecArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--")) {
            if (i + 1 < args.len) {
                result.target_argv = args[i + 1 ..];
            }
            break;
        }
        if (eql(args[i], "--profile") or eql(args[i], "-p")) {
            i += 1;
            if (i < args.len) result.profile = args[i];
        } else if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        } else if (eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capability = args[i];
        } else if (eql(args[i], "--strategy")) {
            i += 1;
            if (i < args.len) result.strategy = args[i];
        }
    }
    return .{ .exec = result };
}

fn parseEnv(args: []const []const u8) Command {
    var result = Command.EnvArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--profile") or eql(args[i], "-p")) {
            i += 1;
            if (i < args.len) result.profile = args[i];
        } else if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        } else if (eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capability = args[i];
        } else if (eql(args[i], "--shell")) {
            i += 1;
            if (i < args.len) result.shell = args[i];
        }
    }
    return .{ .env = result };
}

fn parseStatus(args: []const []const u8) Command {
    var result = Command.StatusArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) result.json = true;
    }
    return .{ .status = result };
}

fn parseHealth(args: []const []const u8) Command {
    var result = Command.HealthArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--json")) {
            result.json = true;
        } else if (eql(args[i], "--reset")) {
            i += 1;
            if (i < args.len) result.reset = args[i];
        } else if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        }
    }
    return .{ .health = result };
}

fn parseConfig(args: []const []const u8) Command {
    if (args.len == 0) return .config_path;
    if (eql(args[0], "validate")) return .config_validate;
    if (eql(args[0], "path")) return .config_path;
    return .config_path;
}

fn parseInit(args: []const []const u8) Command {
    var result = Command.InitArgs{};
    for (args) |arg| {
        if (eql(arg, "--interactive") or eql(arg, "-i")) result.interactive = true;
    }
    return .{ .init = result };
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\oauth-mux — OAuth fallback muxing for AI harness subscriptions
        \\
        \\Usage: oauth-mux <command> [options]
        \\
        \\Commands:
        \\  exec [--profile <name>] [--provider <name>] [--capability <name>] -- <cmd> [args...]
        \\      Execute a command with muxed OAuth credentials injected.
        \\
        \\  env [--profile <name>] [--provider <name>] [--capability <name>] [--shell fish|zsh|bash|ksh]
        \\      Print shell export statements for eval.
        \\
        \\  status [--json] [--provider <name>]
        \\      Show active accounts, health scores, and circuit states.
        \\
        \\  health [--json] [--reset <account>] [--provider <name>]
        \\      Show or reset redacted health and liveness tracking data.
        \\
        \\  config validate    Validate the configuration file.
        \\  config path        Print the config file path.
        \\
        \\  daemon start       Start background token refresh daemon.
        \\  daemon stop        Stop the daemon.
        \\  daemon status      Show daemon status.
        \\
        \\  init [--interactive]
        \\      Generate a starter config file.
        \\
        \\  completions <shell> Generate shell completions (fish|zsh|bash).
        \\
        \\  version            Print version.
        \\  help               Print this help.
        \\
        \\Environment:
        \\  OMUX_CONFIG        Override config file path
        \\  OMUX_CONFIG_DIR    Override config directory
        \\  OMUX_STATE_DIR     Override state directory
        \\  OMUX_SHELL         Override shell detection
        \\  OMUX_DEBUG         Enable debug logging
        \\  NO_COLOR           Disable colored output
        \\
        \\Version:
    );
    try writer.writeAll(version);
    try writer.writeAll("\n");
}

test "parse exec with profile and target" {
    const args = [_][]const u8{ "exec", "--profile", "work", "--capability", "gpt-5.1-codex-max", "--", "claude", "chat" };
    const cmd = parse(&args);
    switch (cmd) {
        .exec => |exec| {
            try std.testing.expectEqualStrings("work", exec.profile.?);
            try std.testing.expectEqualStrings("gpt-5.1-codex-max", exec.capability.?);
            try std.testing.expectEqual(@as(usize, 2), exec.target_argv.len);
            try std.testing.expectEqualStrings("claude", exec.target_argv[0]);
            try std.testing.expectEqualStrings("chat", exec.target_argv[1]);
        },
        else => return error.Unexpected,
    }
}

test "parse env with shell" {
    const args = [_][]const u8{ "env", "--shell", "fish", "--capability", "tools/design-context" };
    const cmd = parse(&args);
    switch (cmd) {
        .env => |env_args| {
            try std.testing.expectEqualStrings("fish", env_args.shell.?);
            try std.testing.expectEqualStrings("tools/design-context", env_args.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse status json" {
    const args = [_][]const u8{ "status", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .status => |status| try std.testing.expect(status.json),
        else => return error.Unexpected,
    }
}

test "parse health json provider" {
    const args = [_][]const u8{ "health", "--json", "--provider", "codex" };
    const cmd = parse(&args);
    switch (cmd) {
        .health => |health| {
            try std.testing.expect(health.json);
            try std.testing.expectEqualStrings("codex", health.provider.?);
        },
        else => return error.Unexpected,
    }
}

pub fn printCompletions(writer: anytype, shell_name: []const u8) !void {
    if (eql(shell_name, "fish")) {
        try writer.writeAll(
            \\complete -c oauth-mux -f
            \\complete -c oauth-mux -n __fish_use_subcommand -a exec -d 'Execute with muxed credentials'
            \\complete -c oauth-mux -n __fish_use_subcommand -a env -d 'Print shell exports'
            \\complete -c oauth-mux -n __fish_use_subcommand -a status -d 'Show status'
            \\complete -c oauth-mux -n __fish_use_subcommand -a health -d 'Show health data'
            \\complete -c oauth-mux -n __fish_use_subcommand -a config -d 'Config operations'
            \\complete -c oauth-mux -n __fish_use_subcommand -a init -d 'Generate config'
            \\complete -c oauth-mux -n __fish_use_subcommand -a version -d 'Print version'
            \\complete -c oauth-mux -n __fish_use_subcommand -a completions -d 'Generate completions'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from env' -l shell -d 'Shell type' -r -a 'fish zsh bash ksh'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from status' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from config' -a 'validate path' -d 'Config subcommand'
            \\
        );
    } else if (eql(shell_name, "zsh")) {
        try writer.writeAll(
            \\#compdef oauth-mux
            \\_oauth-mux() {
            \\  local -a commands
            \\  commands=(
            \\    'exec:Execute with muxed credentials'
            \\    'env:Print shell exports'
            \\    'status:Show status'
            \\    'health:Show health data'
            \\    'config:Config operations'
            \\    'init:Generate config'
            \\    'version:Print version'
            \\    'completions:Generate completions'
            \\  )
            \\  _describe 'command' commands
            \\}
            \\compdef _oauth-mux oauth-mux
            \\
        );
    } else if (eql(shell_name, "bash")) {
        try writer.writeAll(
            \\_oauth_mux_completions() {
            \\  local cur="${COMP_WORDS[COMP_CWORD]}"
            \\  COMPREPLY=($(compgen -W "exec env status health config init version completions" -- "$cur"))
            \\}
            \\complete -F _oauth_mux_completions oauth-mux
            \\
        );
    }
}

test "parse version" {
    const args = [_][]const u8{"--version"};
    const cmd = parse(&args);
    try std.testing.expect(cmd == .version_cmd);
}

test "parse empty" {
    const cmd = parse(&[_][]const u8{});
    try std.testing.expect(cmd == .help);
}
