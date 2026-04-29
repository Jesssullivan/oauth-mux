const std = @import("std");
const types = @import("types.zig");

pub const version = "0.1.3";

pub const Command = union(enum) {
    exec: ExecArgs,
    env: EnvArgs,
    probe: ProbeArgs,
    doctor: DoctorArgs,
    report: ReportArgs,
    providers: ProvidersArgs,
    status: StatusArgs,
    health: HealthArgs,
    discover: DiscoverArgs,
    config_validate,
    config_path,
    init: InitArgs,
    codex: CodexArgs,
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

    pub const ProbeArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        json: bool = false,
    };

    pub const DoctorArgs = struct {
        json: bool = false,
    };

    pub const ReportArgs = struct {
        json: bool = false,
        redacted: bool = true,
        include_paths: bool = false,
    };

    pub const ProvidersAction = enum {
        list,
    };

    pub const ProvidersArgs = struct {
        action: ProvidersAction = .list,
        json: bool = false,
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

    pub const DiscoverArgs = struct {
        json: bool = false,
    };

    pub const InitArgs = struct {
        interactive: bool = false,
        codex_max: bool = false,
    };

    pub const CodexAction = enum {
        bootstrap_dirs,
        login,
        login_device,
        login_status,
        login_status_all,
        onboard,
        canary,
        probe_all,
    };

    pub const CodexArgs = struct {
        action: CodexAction = .canary,
        account: ?[]const u8 = null,
        accounts: []const u8 = "max-1,max-2,max-3",
        capabilities: []const u8 = "codex-mini,codex-max",
        store_root: ?[]const u8 = null,
        device: bool = false,
        status_only: bool = false,
        live: bool = false,
        json: bool = false,
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
    if (eql(cmd, "probe")) return parseProbe(rest);
    if (eql(cmd, "doctor")) return parseDoctor(rest);
    if (eql(cmd, "report")) return parseReport(rest);
    if (eql(cmd, "providers")) return parseProviders(rest);
    if (eql(cmd, "status")) return parseStatus(rest);
    if (eql(cmd, "health")) return parseHealth(rest);
    if (eql(cmd, "discover")) return parseDiscover(rest);
    if (eql(cmd, "config")) return parseConfig(rest);
    if (eql(cmd, "init")) return parseInit(rest);
    if (eql(cmd, "setup")) return parseSetup(rest);
    if (eql(cmd, "codex")) return parseCodex(rest);
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

fn parseProbe(args: []const []const u8) Command {
    var result = Command.ProbeArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--profile") or eql(args[i], "-p")) {
            i += 1;
            if (i < args.len) result.profile = args[i];
        } else if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        } else if (eql(args[i], "--account")) {
            i += 1;
            if (i < args.len) result.account = args[i];
        } else if (eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capability = args[i];
        } else if (eql(args[i], "--json")) {
            result.json = true;
        }
    }
    return .{ .probe = result };
}

fn parseDoctor(args: []const []const u8) Command {
    var result = Command.DoctorArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) result.json = true;
    }
    return .{ .doctor = result };
}

fn parseReport(args: []const []const u8) Command {
    var result = Command.ReportArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) {
            result.json = true;
        } else if (eql(arg, "--redacted")) {
            result.redacted = true;
        } else if (eql(arg, "--include-paths")) {
            result.include_paths = true;
        }
    }
    return .{ .report = result };
}

fn parseProviders(args: []const []const u8) Command {
    var result = Command.ProvidersArgs{};
    var i: usize = 0;
    if (args.len > 0 and eql(args[0], "list")) {
        result.action = .list;
        i = 1;
    }
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--json")) result.json = true;
    }
    return .{ .providers = result };
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

fn parseDiscover(args: []const []const u8) Command {
    var result = Command.DiscoverArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) result.json = true;
    }
    return .{ .discover = result };
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
        if (eql(arg, "--codex-max")) result.codex_max = true;
    }
    return .{ .init = result };
}

fn parseSetup(args: []const []const u8) Command {
    if (args.len == 0) return .help;
    if (eql(args[0], "codex")) {
        var result = Command.CodexArgs{ .action = .onboard };
        parseCodexOptions(&result, args, 1);
        return .{ .codex = result };
    }
    return .help;
}

fn parseCodex(args: []const []const u8) Command {
    var result = Command.CodexArgs{};
    var option_start: usize = 0;

    if (args.len > 0 and !std.mem.startsWith(u8, args[0], "-")) {
        option_start = 1;
        if (eql(args[0], "bootstrap-dirs")) {
            result.action = .bootstrap_dirs;
        } else if (eql(args[0], "setup")) {
            result.action = .onboard;
        } else if (eql(args[0], "login")) {
            result.action = .login;
        } else if (eql(args[0], "login-device")) {
            result.action = .login_device;
            result.device = true;
        } else if (eql(args[0], "login-status")) {
            result.action = .login_status;
        } else if (eql(args[0], "login-status-all")) {
            result.action = .login_status_all;
        } else if (eql(args[0], "onboard")) {
            result.action = .onboard;
        } else if (eql(args[0], "canary")) {
            result.action = .canary;
        } else if (eql(args[0], "probe-all")) {
            result.action = .probe_all;
        } else {
            result.action = .canary;
            option_start = 0;
        }
    }

    parseCodexOptions(&result, args, option_start);

    if (result.action == .login_device) result.device = true;
    return .{ .codex = result };
}

fn parseCodexOptions(result: *Command.CodexArgs, args: []const []const u8, option_start: usize) void {
    var i = option_start;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--account")) {
            i += 1;
            if (i < args.len) result.account = args[i];
        } else if (eql(args[i], "--accounts")) {
            i += 1;
            if (i < args.len) result.accounts = args[i];
        } else if (eql(args[i], "--capabilities") or eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capabilities = args[i];
        } else if (eql(args[i], "--store-root")) {
            i += 1;
            if (i < args.len) result.store_root = args[i];
        } else if (eql(args[i], "--device")) {
            result.device = true;
        } else if (eql(args[i], "--status-only")) {
            result.status_only = true;
        } else if (eql(args[i], "--live")) {
            result.live = true;
        } else if (eql(args[i], "--json")) {
            result.json = true;
        } else if (result.account == null and !std.mem.startsWith(u8, args[i], "-")) {
            result.account = args[i];
        }
    }
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
        \\  probe [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Validate a selected account and run its capability probe when configured.
        \\
        \\  doctor [--json]
        \\      Run no-spend readiness checks and print first-run next commands.
        \\
        \\  report [--redacted] [--json] [--include-paths]
        \\      Print a redacted support bundle without reading credential values.
        \\
        \\  providers list [--json]
        \\      Show built-in and configured provider support status.
        \\
        \\  status [--json] [--provider <name>]
        \\      Show active accounts, health scores, and circuit states.
        \\
        \\  health [--json] [--reset <account>] [--provider <name>]
        \\      Show or reset redacted health and liveness tracking data.
        \\
        \\  discover [--json]
        \\      Print redacted provider/profile inventory and agent-safe next commands.
        \\
        \\  config validate    Validate the configuration file.
        \\  config path        Print the config file path.
        \\
        \\  daemon start       Start background token refresh daemon.
        \\  daemon stop        Stop the daemon.
        \\  daemon status      Show daemon status.
        \\
        \\  init [--interactive] [--codex-max]
        \\      Generate a starter config file.
        \\
        \\  setup codex [--accounts a,b,c] [--device|--status-only] [--live]
        \\      First-run Codex setup alias.
        \\
        \\  codex setup|onboard [--accounts a,b,c] [--device|--status-only] [--live]
        \\      Bootstrap isolated Codex account stores and login flow.
        \\
        \\  codex canary [--accounts a,b,c] [--capabilities c1,c2] [--live]
        \\      Run a no-spend Codex Max readiness check; --live runs probes.
        \\
        \\  codex probe-all [--accounts a,b,c] [--capabilities c1,c2] [--json]
        \\      Probe every selected Codex account/capability route.
        \\
        \\  codex login <account> | login-device <account> | login-status [account] | login-status-all
        \\      Codex account login/status helpers using isolated CODEX_HOME dirs.
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
    const args = [_][]const u8{ "exec", "--profile", "work", "--capability", "codex-max", "--", "claude", "chat" };
    const cmd = parse(&args);
    switch (cmd) {
        .exec => |exec| {
            try std.testing.expectEqualStrings("work", exec.profile.?);
            try std.testing.expectEqualStrings("codex-max", exec.capability.?);
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

test "parse probe with account capability and json" {
    const args = [_][]const u8{ "probe", "--provider", "codex", "--account", "max-2", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .probe => |probe| {
            try std.testing.expectEqualStrings("codex", probe.provider.?);
            try std.testing.expectEqualStrings("max-2", probe.account.?);
            try std.testing.expectEqualStrings("codex-max", probe.capability.?);
            try std.testing.expect(probe.json);
        },
        else => return error.Unexpected,
    }
}

test "parse doctor json" {
    const args = [_][]const u8{ "doctor", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .doctor => |doctor| try std.testing.expect(doctor.json),
        else => return error.Unexpected,
    }
}

test "parse report redacted json include paths" {
    const args = [_][]const u8{ "report", "--redacted", "--json", "--include-paths" };
    const cmd = parse(&args);
    switch (cmd) {
        .report => |report| {
            try std.testing.expect(report.redacted);
            try std.testing.expect(report.json);
            try std.testing.expect(report.include_paths);
        },
        else => return error.Unexpected,
    }
}

test "parse providers list json" {
    const args = [_][]const u8{ "providers", "list", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .providers => |providers| {
            try std.testing.expect(providers.action == .list);
            try std.testing.expect(providers.json);
        },
        else => return error.Unexpected,
    }
}

test "parse init codex max" {
    const args = [_][]const u8{ "init", "--codex-max" };
    const cmd = parse(&args);
    switch (cmd) {
        .init => |init| try std.testing.expect(init.codex_max),
        else => return error.Unexpected,
    }
}

test "parse codex canary" {
    const args = [_][]const u8{ "codex", "canary", "--accounts", "max-1,max-2", "--capabilities", "codex-mini", "--live" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .canary);
            try std.testing.expectEqualStrings("max-1,max-2", codex.accounts);
            try std.testing.expectEqualStrings("codex-mini", codex.capabilities);
            try std.testing.expect(codex.live);
        },
        else => return error.Unexpected,
    }
}

test "parse codex setup alias" {
    const args = [_][]const u8{ "codex", "setup", "--accounts", "work,personal" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .onboard);
            try std.testing.expectEqualStrings("work,personal", codex.accounts);
        },
        else => return error.Unexpected,
    }
}

test "parse setup codex alias" {
    const args = [_][]const u8{ "setup", "codex", "--accounts", "work,personal", "--device" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .onboard);
            try std.testing.expectEqualStrings("work,personal", codex.accounts);
            try std.testing.expect(codex.device);
        },
        else => return error.Unexpected,
    }
}

test "parse codex probe-all with capability alias" {
    const args = [_][]const u8{ "codex", "probe-all", "--accounts", "max-1,max-3", "--capability", "codex-mini", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .probe_all);
            try std.testing.expectEqualStrings("max-1,max-3", codex.accounts);
            try std.testing.expectEqualStrings("codex-mini", codex.capabilities);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex login account" {
    const args = [_][]const u8{ "codex", "login-device", "max-2" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .login_device);
            try std.testing.expectEqualStrings("max-2", codex.account.?);
            try std.testing.expect(codex.device);
        },
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

test "parse discover json" {
    const args = [_][]const u8{ "discover", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .discover => |discover| try std.testing.expect(discover.json),
        else => return error.Unexpected,
    }
}

pub fn printCompletions(writer: anytype, shell_name: []const u8) !void {
    if (eql(shell_name, "fish")) {
        try writer.writeAll(
            \\complete -c oauth-mux -f
            \\complete -c oauth-mux -n __fish_use_subcommand -a exec -d 'Execute with muxed credentials'
            \\complete -c oauth-mux -n __fish_use_subcommand -a env -d 'Print shell exports'
            \\complete -c oauth-mux -n __fish_use_subcommand -a probe -d 'Probe account liveness'
            \\complete -c oauth-mux -n __fish_use_subcommand -a doctor -d 'Run readiness checks'
            \\complete -c oauth-mux -n __fish_use_subcommand -a report -d 'Print redacted support report'
            \\complete -c oauth-mux -n __fish_use_subcommand -a providers -d 'List provider support'
            \\complete -c oauth-mux -n __fish_use_subcommand -a status -d 'Show status'
            \\complete -c oauth-mux -n __fish_use_subcommand -a health -d 'Show health data'
            \\complete -c oauth-mux -n __fish_use_subcommand -a discover -d 'Show agent-safe inventory'
            \\complete -c oauth-mux -n __fish_use_subcommand -a config -d 'Config operations'
            \\complete -c oauth-mux -n __fish_use_subcommand -a init -d 'Generate config'
            \\complete -c oauth-mux -n __fish_use_subcommand -a setup -d 'First-run setup'
            \\complete -c oauth-mux -n __fish_use_subcommand -a codex -d 'Codex account onboarding'
            \\complete -c oauth-mux -n __fish_use_subcommand -a version -d 'Print version'
            \\complete -c oauth-mux -n __fish_use_subcommand -a completions -d 'Generate completions'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from probe' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from probe' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report providers' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report' -l redacted -d 'Redact credential paths and values'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report' -l include-paths -d 'Include non-token paths'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from providers' -a 'list' -d 'Provider subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from env' -l shell -d 'Shell type' -r -a 'fish zsh bash ksh'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from status' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from discover' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from init' -l codex-max -d 'Generate Codex Max scaffold'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from setup' -a 'codex' -d 'Setup target'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from config' -a 'validate path' -d 'Config subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex' -a 'setup onboard canary probe-all bootstrap-dirs login login-device login-status login-status-all' -d 'Codex subcommand'
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
            \\    'probe:Probe account liveness'
            \\    'doctor:Run readiness checks'
            \\    'report:Print redacted support report'
            \\    'providers:List provider support'
            \\    'status:Show status'
            \\    'health:Show health data'
            \\    'discover:Show agent-safe inventory'
            \\    'config:Config operations'
            \\    'init:Generate config'
            \\    'setup:First-run setup'
            \\    'codex:Codex account onboarding'
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
            \\  COMPREPLY=($(compgen -W "exec env probe doctor report providers status health discover config init setup codex version completions" -- "$cur"))
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
