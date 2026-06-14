const std = @import("std");
const types = @import("types.zig");
const build_options = @import("build_options");

pub const version = build_options.version;
pub const build_id = build_options.build_id;

pub const Command = union(enum) {
    exec: ExecArgs,
    env: EnvArgs,
    probe: ProbeArgs,
    doctor: DoctorArgs,
    report: ReportArgs,
    providers: ProvidersArgs,
    accounts: AccountsArgs,
    enroll: EnrollArgs,
    status: StatusArgs,
    health: HealthArgs,
    discover: DiscoverArgs,
    repair_plan: RepairPlanArgs,
    repair_run: RepairRunArgs,
    route: RouteArgs,
    stay_afloat_next: RouteArgs,
    stay_afloat_launch: ExecArgs,
    stay_afloat_observe: ObserveArgs,
    stay_afloat: DaemonTickArgs,
    stay_afloat_handoff: HandoffArgs,
    keepalive: KeepaliveArgs,
    config_validate,
    config_path,
    init: InitArgs,
    codex: CodexArgs,
    completions: CompletionsArgs,
    daemon_run: DaemonRunArgs,
    mcp: McpArgs,
    codex_adapter: CodexAdapterArgs,
    daemon_start,
    daemon_stop,
    daemon_status: DaemonStatusArgs,
    daemon_events: DaemonEventsArgs,
    daemon_handoffs: DaemonHandoffsArgs,
    daemon_tick: DaemonTickArgs,
    version_cmd: VersionArgs,
    help,
    codex_help,

    pub const McpArgs = struct {
        profile: ?[]const u8 = null,
        capability: ?[]const u8 = null,
    };

    /// TIN-1851 mux storage model, parsed from --mux-mode. null = not set on the
    /// CLI (the adapter then resolves TINYLAND_CODEX_MUX_MODE, else the default).
    pub const CodexMuxMode = enum { isolated_persistent, shared_canonical };

    pub const CodexAdapterArgs = struct {
        profile: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        account: ?[]const u8 = null,
        session_home: ?[]const u8 = null,
        isolated_session_store: bool = false,
        mux_mode: ?CodexMuxMode = null,
        json_status: bool = false,
        json_status_file: ?[]const u8 = null,
        invalid_option: ?[]const u8 = null,
        /// Args after `--` forwarded to codex unchanged.
        forward_argv: []const []const u8 = &.{},
    };

    pub const ExecArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        strategy: ?[]const u8 = null,
        target_argv: []const []const u8 = &.{},
    };

    pub const ObserveArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        target_argv: []const []const u8 = &.{},
        legacy_max_restarts: u32 = 0,
        legacy_restart_aliases_used: bool = false,
        classify_exit_code: ?u8 = null,
        classify_codex_usage_limit: bool = false,
        stream_capture: bool = false,
        json: bool = false,
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
        // TIN-2073: internal (not CLI-parsed). The daemon's probe phase sets
        // this false so a probe-budget tick can never rotate tokens —
        // rotation belongs to the repair phase under admission + lock.
        allow_refresh_mutation: bool = true,
    };

    pub const DoctorMode = enum {
        summary,
        runtime,
    };

    pub const DoctorArgs = struct {
        mode: DoctorMode = .summary,
        json: bool = false,
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
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

    pub const AccountsAction = enum {
        list,
    };

    pub const AccountsArgs = struct {
        action: AccountsAction = .list,
        provider: ?[]const u8 = null,
        json: bool = false,
    };

    pub const EnrollAction = enum {
        plan,
        codex,
        claude,
        figma,
    };

    pub const EnrollArgs = struct {
        action: EnrollAction = .plan,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        mode: ?[]const u8 = null,
        store_root: ?[]const u8 = null,
        secret_env: ?[]const u8 = null,
        confirm_enroll: bool = false,
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

    pub const RepairPlanArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        json: bool = false,
    };

    pub const RepairRunArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        json: bool = false,
        confirm_repair: bool = false,
    };

    pub const RouteAction = enum {
        select,
        explain,
    };

    pub const RouteArgs = struct {
        action: RouteAction = .select,
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
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
        live_qa,
        revalidate_exhausted,
        probe_all,
        config_candidate,
        config_merge,
        preflight,
        managed_plan,
        managed,
        status_latest,
        broker_plan,
        broker_session_plan,
        broker_session_smoke,
        broker_run,
        broker_fallback_drill,
        broker_smoke,
        broker_refresh_smoke,
        broker_401_smoke,
        broker_quota_smoke,
    };

    pub const CodexArgs = struct {
        action: CodexAction = .canary,
        profile: ?[]const u8 = null,
        account: ?[]const u8 = null,
        accounts: []const u8 = "max-1,max-2,max-3",
        capabilities: []const u8 = "codex-mini,codex-max",
        store_root: ?[]const u8 = null,
        device: bool = false,
        status_only: bool = false,
        live: bool = false,
        confirm_spend: bool = false,
        confirm_broker: bool = false,
        confirm_drill: bool = false,
        json: bool = false,
        prompt: ?[]const u8 = null,
        model: ?[]const u8 = null,
        from_account: ?[]const u8 = null,
        resume_id: ?[]const u8 = null,
        resume_last: bool = false,
        include_non_interactive: bool = false,
        managed_argv: []const []const u8 = &.{},
        stdin_prompts: bool = false,
        continue_on_failure: bool = false,
        output: ?[]const u8 = null,
        candidate: ?[]const u8 = null,
        backup: ?[]const u8 = null,
        status_file: ?[]const u8 = null,
    };

    pub const CompletionsArgs = struct {
        shell: []const u8 = "fish",
    };

    pub const DaemonStatusArgs = struct {
        json: bool = false,
    };

    pub const DaemonRunArgs = struct {
        stay_afloat: bool = false,
        tick: DaemonTickArgs = .{},
    };

    pub const DaemonEventsArgs = struct {
        json: bool = false,
        limit: usize = 50,
    };

    pub const DaemonHandoffsArgs = struct {
        json: bool = false,
        limit: usize = 50,
        all: bool = false,
    };

    pub const DaemonTickArgs = struct {
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        once: bool = true,
        iterations: u32 = 1,
        interval_ms: u64 = 60_000,
        execute: bool = false,
        json: bool = false,
    };

    /// `oauth-mux keepalive` — run the warm-loop scheduler over the configured
    /// accounts. Bounded by `iterations` (default 1 = a single tick) so it always
    /// terminates; `interval_ms` caps the per-tick sleep. Refuses to rotate any
    /// account whose proactive_refresh grant is not admitted (safe over builtins).
    pub const KeepaliveArgs = struct {
        iterations: u32 = 1,
        interval_ms: u64 = 60_000,
        json: bool = false,
    };

    pub const HandoffAction = enum {
        ack,
        clear,
    };

    pub const HandoffArgs = struct {
        action: HandoffAction = .ack,
        profile: ?[]const u8 = null,
        provider: ?[]const u8 = null,
        account: ?[]const u8 = null,
        capability: ?[]const u8 = null,
        json: bool = false,
    };

    pub const VersionArgs = struct {
        json: bool = false,
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
    if (eql(cmd, "accounts")) return parseAccounts(rest);
    if (eql(cmd, "enroll")) return parseEnroll(rest);
    if (eql(cmd, "status")) return parseStatus(rest);
    if (eql(cmd, "health")) return parseHealth(rest);
    if (eql(cmd, "discover")) return parseDiscover(rest);
    if (eql(cmd, "repair")) return parseRepair(rest);
    if (eql(cmd, "repair-plan")) return parseRepairPlan(rest);
    if (eql(cmd, "route")) return parseRoute(rest);
    if (eql(cmd, "stay-afloat")) return parseStayAfloat(rest);
    if (eql(cmd, "keepalive")) return parseKeepalive(rest);
    if (eql(cmd, "config")) return parseConfig(rest);
    if (eql(cmd, "init")) return parseInit(rest);
    if (eql(cmd, "setup")) return parseSetup(rest);
    if (eql(cmd, "codex")) {
        // Broker-mediated session entrypoint. Other `codex ...`
        // subcommands continue through the legacy parser until the
        // adapter path is ready to replace them.
        if (rest.len == 0) return .{ .codex_adapter = .{} };
        if (eql(rest[0], "help") or eql(rest[0], "--help") or eql(rest[0], "-h")) return .codex_help;
        if (eql(rest[0], "run")) return parseCodexAdapter(rest[1..], true);
        if (!isCodexLegacySubcommand(rest[0])) return parseCodexAdapter(rest, false);
        return parseCodex(rest);
    }
    if (eql(cmd, "mcp")) return parseMcp(rest);
    if (eql(cmd, "version") or eql(cmd, "--version") or eql(cmd, "-v")) return parseVersion(rest);
    if (eql(cmd, "daemon")) {
        if (rest.len > 0) {
            if (eql(rest[0], "run")) return parseDaemonRun(rest[1..]);
            if (eql(rest[0], "loop") or eql(rest[0], "supervise")) return parseDaemonLoop(rest[1..]);
            if (eql(rest[0], "repair-plan")) return parseRepairPlan(rest[1..]);
            if (eql(rest[0], "start")) return .daemon_start;
            if (eql(rest[0], "stop")) return .daemon_stop;
            if (eql(rest[0], "status")) return parseDaemonStatus(rest[1..]);
            if (eql(rest[0], "events")) return parseDaemonEvents(rest[1..]);
            if (eql(rest[0], "handoffs")) return parseDaemonHandoffs(rest[1..]);
            if (eql(rest[0], "tick")) return parseDaemonTick(rest[1..]);
        }
        return .{ .daemon_status = .{} };
    }
    if (eql(cmd, "completions")) {
        if (rest.len > 0) return .{ .completions = .{ .shell = rest[0] } };
        return .{ .completions = .{} };
    }
    if (eql(cmd, "help") or eql(cmd, "--help") or eql(cmd, "-h")) return .help;

    return .help;
}

fn parseExec(args: []const []const u8) Command {
    return .{ .exec = parseExecArgs(args) };
}

fn parseVersion(args: []const []const u8) Command {
    var result = Command.VersionArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) result.json = true;
    }
    return .{ .version_cmd = result };
}

fn parseCodexAdapter(args: []const []const u8, strict_run: bool) Command {
    var result = Command.CodexAdapterArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--")) {
            result.forward_argv = args[i + 1 ..];
            break;
        } else if ((eql(args[i], "--profile") or eql(args[i], "-p")) and i + 1 < args.len) {
            i += 1;
            result.profile = args[i];
        } else if (eql(args[i], "--capability") and i + 1 < args.len) {
            i += 1;
            result.capability = args[i];
        } else if (eql(args[i], "--account") and i + 1 < args.len) {
            i += 1;
            result.account = args[i];
        } else if (eql(args[i], "--session-home") and i + 1 < args.len) {
            i += 1;
            result.session_home = args[i];
        } else if (eql(args[i], "--isolated-session-store")) {
            result.isolated_session_store = true;
        } else if (eql(args[i], "--mux-mode") and i + 1 < args.len) {
            i += 1;
            if (eql(args[i], "isolated_persistent")) {
                result.mux_mode = .isolated_persistent;
            } else if (eql(args[i], "shared_canonical")) {
                result.mux_mode = .shared_canonical;
            } else {
                result.invalid_option = args[i];
                result.forward_argv = &.{};
                break;
            }
        } else if (eql(args[i], "--json-status")) {
            result.json_status = true;
        } else if (eql(args[i], "--json-status-file") and i + 1 < args.len) {
            i += 1;
            result.json_status_file = args[i];
            result.json_status = true;
        } else if (strict_run) {
            result.invalid_option = args[i];
            result.forward_argv = &.{};
            break;
        } else {
            result.forward_argv = args[i..];
            break;
        }
    }
    return .{ .codex_adapter = result };
}

fn isCodexLegacySubcommand(arg: []const u8) bool {
    return eql(arg, "bootstrap-dirs") or
        eql(arg, "setup") or
        eql(arg, "login") or
        eql(arg, "login-device") or
        eql(arg, "login-status") or
        eql(arg, "login-status-all") or
        eql(arg, "onboard") or
        eql(arg, "canary") or
        eql(arg, "live-qa") or
        eql(arg, "revalidate-exhausted") or
        eql(arg, "probe-all") or
        eql(arg, "config-candidate") or
        eql(arg, "config-merge") or
        eql(arg, "preflight") or
        eql(arg, "managed-plan") or
        eql(arg, "managed") or
        eql(arg, "status-latest") or
        eql(arg, "broker-plan") or
        eql(arg, "broker-session-plan") or
        eql(arg, "broker-session-smoke") or
        eql(arg, "broker-run") or
        eql(arg, "broker-fallback-drill") or
        eql(arg, "broker-smoke") or
        eql(arg, "broker-refresh-smoke") or
        eql(arg, "broker-401-smoke") or
        eql(arg, "broker-quota-smoke");
}

fn parseMcp(args: []const []const u8) Command {
    var result = Command.McpArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--profile") and i + 1 < args.len) {
            i += 1;
            result.profile = args[i];
        } else if (eql(args[i], "--capability") and i + 1 < args.len) {
            i += 1;
            result.capability = args[i];
        }
    }
    return .{ .mcp = result };
}

fn parseExecArgs(args: []const []const u8) Command.ExecArgs {
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
        } else if (eql(args[i], "--account")) {
            i += 1;
            if (i < args.len) result.account = args[i];
        } else if (eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capability = args[i];
        } else if (eql(args[i], "--strategy")) {
            i += 1;
            if (i < args.len) result.strategy = args[i];
        }
    }
    return result;
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
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "runtime")) {
            result.mode = .runtime;
        } else if (eql(args[i], "--profile") or eql(args[i], "-p")) {
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

fn parseAccounts(args: []const []const u8) Command {
    var result = Command.AccountsArgs{};
    var i: usize = 0;
    if (args.len > 0 and eql(args[0], "list")) {
        result.action = .list;
        i = 1;
    }
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        } else if (eql(args[i], "--json")) {
            result.json = true;
        }
    }
    return .{ .accounts = result };
}

fn parseEnroll(args: []const []const u8) Command {
    var result = Command.EnrollArgs{};
    var i: usize = 0;
    if (args.len > 0 and eql(args[0], "plan")) {
        result.action = .plan;
        i = 1;
    } else if (args.len > 0 and eql(args[0], "codex")) {
        result.action = .codex;
        result.provider = "codex";
        i = 1;
    } else if (args.len > 0 and eql(args[0], "claude")) {
        result.action = .claude;
        result.provider = "claude";
        i = 1;
    } else if (args.len > 0 and eql(args[0], "figma")) {
        result.action = .figma;
        result.provider = "figma";
        i = 1;
    }
    if (i < args.len and !std.mem.startsWith(u8, args[i], "--")) {
        if (result.action == .codex or result.action == .claude or result.action == .figma) {
            result.account = args[i];
        } else {
            result.provider = args[i];
        }
        i += 1;
    }
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--provider")) {
            i += 1;
            if (i < args.len) result.provider = args[i];
        } else if (eql(args[i], "--account")) {
            i += 1;
            if (i < args.len) result.account = args[i];
        } else if (eql(args[i], "--mode")) {
            i += 1;
            if (i < args.len) result.mode = args[i];
        } else if (eql(args[i], "--store-root") or eql(args[i], "--config-root")) {
            i += 1;
            if (i < args.len) result.store_root = args[i];
        } else if (eql(args[i], "--secret-env")) {
            i += 1;
            if (i < args.len) result.secret_env = args[i];
        } else if (eql(args[i], "--confirm-enroll") or eql(args[i], "--confirm")) {
            result.confirm_enroll = true;
        } else if (eql(args[i], "--json")) {
            result.json = true;
        }
    }
    return .{ .enroll = result };
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

fn parseRepairPlan(args: []const []const u8) Command {
    var result = Command.RepairPlanArgs{};
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
    return .{ .repair_plan = result };
}

fn parseRepair(args: []const []const u8) Command {
    if (args.len > 0 and eql(args[0], "run")) {
        return parseRepairRun(args[1..]);
    }
    return .help;
}

fn parseRepairRun(args: []const []const u8) Command {
    var result = Command.RepairRunArgs{};
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
        } else if (eql(args[i], "--confirm-repair")) {
            result.confirm_repair = true;
        }
    }
    return .{ .repair_run = result };
}

fn parseRoute(args: []const []const u8) Command {
    var result = Command.RouteArgs{};
    var i: usize = 0;
    if (args.len > 0) {
        if (eql(args[0], "select")) {
            result.action = .select;
            i = 1;
        } else if (eql(args[0], "explain")) {
            result.action = .explain;
            i = 1;
        }
    }
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
    return .{ .route = result };
}

fn parseDaemonStatus(args: []const []const u8) Command {
    var result = Command.DaemonStatusArgs{};
    for (args) |arg| {
        if (eql(arg, "--json")) result.json = true;
    }
    return .{ .daemon_status = result };
}

fn parseDaemonRun(args: []const []const u8) Command {
    var result = Command.DaemonRunArgs{};
    result.tick = parseDaemonTickArgs(args);
    result.tick.execute = true;
    var bounded = false;
    for (args) |arg| {
        if (eql(arg, "--stay-afloat") or eql(arg, "stay-afloat")) {
            result.stay_afloat = true;
        } else if (eql(arg, "--iterations") or eql(arg, "--once")) {
            bounded = true;
        }
    }
    if (!bounded) {
        result.tick.once = false;
        result.tick.iterations = std.math.maxInt(u32);
    }
    if (!result.stay_afloat) {
        result.tick = .{};
    }
    return .{ .daemon_run = result };
}

fn parseDaemonLoop(args: []const []const u8) Command {
    var result = Command.DaemonRunArgs{
        .stay_afloat = true,
        .tick = parseDaemonTickArgs(args),
    };
    result.tick.execute = true;
    var bounded = false;
    for (args) |arg| {
        if (eql(arg, "--iterations") or eql(arg, "--once")) bounded = true;
    }
    if (!bounded) {
        result.tick.once = false;
        result.tick.iterations = std.math.maxInt(u32);
    }
    return .{ .daemon_run = result };
}

fn parseDaemonEvents(args: []const []const u8) Command {
    var result = Command.DaemonEventsArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--json")) {
            result.json = true;
        } else if (eql(args[i], "--limit")) {
            i += 1;
            if (i < args.len) {
                result.limit = std.fmt.parseInt(usize, args[i], 10) catch result.limit;
            }
        }
    }
    return .{ .daemon_events = result };
}

fn parseDaemonHandoffs(args: []const []const u8) Command {
    var result = Command.DaemonHandoffsArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--json")) {
            result.json = true;
        } else if (eql(args[i], "--all")) {
            result.all = true;
        } else if (eql(args[i], "--limit")) {
            i += 1;
            if (i < args.len) {
                result.limit = std.fmt.parseInt(usize, args[i], 10) catch result.limit;
            }
        }
    }
    return .{ .daemon_handoffs = result };
}

fn parseDaemonTick(args: []const []const u8) Command {
    return .{ .daemon_tick = parseDaemonTickArgs(args) };
}

fn parseStayAfloat(args: []const []const u8) Command {
    if (args.len > 0 and eql(args[0], "launch")) return .{ .stay_afloat_launch = parseExecArgs(args[1..]) };
    if (args.len > 0 and (eql(args[0], "observe") or eql(args[0], "supervise"))) {
        var cmd = parseStayAfloatObserve(args[1..]);
        if (eql(args[0], "supervise")) {
            switch (cmd) {
                .stay_afloat_observe => |*observe| observe.legacy_restart_aliases_used = true,
                else => {},
            }
        }
        return cmd;
    }
    if (args.len > 0 and eql(args[0], "next")) return parseStayAfloatNext(args[1..]);
    if (args.len > 0 and eql(args[0], "handoffs")) return parseDaemonHandoffs(args[1..]);
    if (args.len > 0 and eql(args[0], "handoff")) return parseStayAfloatHandoff(args[1..]);
    if (args.len > 0 and eql(args[0], "refresh")) {
        var tick = parseDaemonTickArgs(args[1..]);
        tick.once = true;
        tick.iterations = 1;
        tick.execute = true;
        return .{ .stay_afloat = tick };
    }
    return .{ .stay_afloat = parseDaemonTickArgs(args) };
}

fn parseKeepalive(args: []const []const u8) Command {
    var result = Command.KeepaliveArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--json")) {
            result.json = true;
        } else if (eql(args[i], "--once")) {
            result.iterations = 1;
        } else if (eql(args[i], "--iterations")) {
            i += 1;
            if (i < args.len) result.iterations = std.fmt.parseInt(u32, args[i], 10) catch result.iterations;
        } else if (eql(args[i], "--interval-ms")) {
            i += 1;
            if (i < args.len) result.interval_ms = std.fmt.parseInt(u64, args[i], 10) catch result.interval_ms;
        }
    }
    return .{ .keepalive = result };
}

fn parseStayAfloatObserve(args: []const []const u8) Command {
    var result = Command.ObserveArgs{};
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
        } else if (eql(args[i], "--account")) {
            i += 1;
            if (i < args.len) result.account = args[i];
        } else if (eql(args[i], "--capability")) {
            i += 1;
            if (i < args.len) result.capability = args[i];
        } else if (eql(args[i], "--max-restarts")) {
            result.legacy_restart_aliases_used = true;
            i += 1;
            if (i < args.len) result.legacy_max_restarts = std.fmt.parseInt(u32, args[i], 10) catch result.legacy_max_restarts;
        } else if (eql(args[i], "--classify-exit-code")) {
            i += 1;
            if (i < args.len) result.classify_exit_code = std.fmt.parseInt(u8, args[i], 10) catch result.classify_exit_code;
        } else if (eql(args[i], "--restart-on-exit-code")) {
            result.legacy_restart_aliases_used = true;
            i += 1;
            if (i < args.len) result.classify_exit_code = std.fmt.parseInt(u8, args[i], 10) catch result.classify_exit_code;
        } else if (eql(args[i], "--classify-codex-usage-limit")) {
            result.classify_codex_usage_limit = true;
        } else if (eql(args[i], "--restart-on-codex-usage-limit")) {
            result.legacy_restart_aliases_used = true;
            result.classify_codex_usage_limit = true;
        } else if (eql(args[i], "--stream-capture")) {
            result.stream_capture = true;
        } else if (eql(args[i], "--json")) {
            result.json = true;
        }
    }
    return .{ .stay_afloat_observe = result };
}

fn parseStayAfloatNext(args: []const []const u8) Command {
    var result = Command.RouteArgs{ .action = .explain };
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
    return .{ .stay_afloat_next = result };
}

fn parseStayAfloatHandoff(args: []const []const u8) Command {
    var result = Command.HandoffArgs{};
    var i: usize = 0;
    if (args.len > 0) {
        if (eql(args[0], "clear") or eql(args[0], "resolve")) {
            result.action = .clear;
            i = 1;
        } else if (eql(args[0], "ack") or eql(args[0], "acknowledge")) {
            result.action = .ack;
            i = 1;
        }
    }
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
    return .{ .stay_afloat_handoff = result };
}

fn parseDaemonTickArgs(args: []const []const u8) Command.DaemonTickArgs {
    var result = Command.DaemonTickArgs{};
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
        } else if (eql(args[i], "--execute")) {
            result.execute = true;
        } else if (eql(args[i], "--once")) {
            result.once = true;
            result.iterations = 1;
        } else if (eql(args[i], "--loop")) {
            result.once = false;
        } else if (eql(args[i], "--iterations")) {
            i += 1;
            if (i < args.len) {
                result.iterations = std.fmt.parseInt(u32, args[i], 10) catch result.iterations;
                if (result.iterations > 1) result.once = false;
            }
        } else if (eql(args[i], "--interval-ms")) {
            i += 1;
            if (i < args.len) {
                result.interval_ms = std.fmt.parseInt(u64, args[i], 10) catch result.interval_ms;
            }
        }
    }
    return result;
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
        if (hasHelpFlag(args[1..])) return .codex_help;
        var result = Command.CodexArgs{ .action = .onboard };
        parseCodexOptions(&result, args, 1);
        return .{ .codex = result };
    }
    if (eql(args[0], "help") or hasHelpFlag(args)) return .help;
    return .help;
}

fn parseCodex(args: []const []const u8) Command {
    if (hasHelpFlag(args) or (args.len > 0 and eql(args[0], "help"))) return .codex_help;

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
        } else if (eql(args[0], "live-qa")) {
            result.action = .live_qa;
        } else if (eql(args[0], "revalidate-exhausted")) {
            result.action = .revalidate_exhausted;
        } else if (eql(args[0], "probe-all")) {
            result.action = .probe_all;
        } else if (eql(args[0], "config-candidate")) {
            result.action = .config_candidate;
        } else if (eql(args[0], "config-merge")) {
            result.action = .config_merge;
        } else if (eql(args[0], "preflight")) {
            result.action = .preflight;
        } else if (eql(args[0], "managed-plan")) {
            result.action = .managed_plan;
        } else if (eql(args[0], "managed")) {
            result.action = .managed;
        } else if (eql(args[0], "status-latest")) {
            result.action = .status_latest;
        } else if (eql(args[0], "broker-plan")) {
            result.action = .broker_plan;
        } else if (eql(args[0], "broker-session-plan")) {
            result.action = .broker_session_plan;
        } else if (eql(args[0], "broker-session-smoke")) {
            result.action = .broker_session_smoke;
        } else if (eql(args[0], "broker-run")) {
            result.action = .broker_run;
        } else if (eql(args[0], "broker-fallback-drill")) {
            result.action = .broker_fallback_drill;
        } else if (eql(args[0], "broker-smoke")) {
            result.action = .broker_smoke;
        } else if (eql(args[0], "broker-refresh-smoke")) {
            result.action = .broker_refresh_smoke;
        } else if (eql(args[0], "broker-401-smoke")) {
            result.action = .broker_401_smoke;
        } else if (eql(args[0], "broker-quota-smoke")) {
            result.action = .broker_quota_smoke;
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
        if (eql(args[i], "--")) {
            result.managed_argv = args[i + 1 ..];
            break;
        } else if (eql(args[i], "--profile") or eql(args[i], "-p")) {
            i += 1;
            if (i < args.len) result.profile = args[i];
        } else if (eql(args[i], "--account")) {
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
        } else if (eql(args[i], "--output")) {
            i += 1;
            if (i < args.len) result.output = args[i];
        } else if (eql(args[i], "--candidate")) {
            i += 1;
            if (i < args.len) result.candidate = args[i];
        } else if (eql(args[i], "--backup")) {
            i += 1;
            if (i < args.len) result.backup = args[i];
        } else if (eql(args[i], "--status-file")) {
            i += 1;
            if (i < args.len) result.status_file = args[i];
        } else if (eql(args[i], "--prompt")) {
            i += 1;
            if (i < args.len) result.prompt = args[i];
        } else if (eql(args[i], "--model")) {
            i += 1;
            if (i < args.len) result.model = args[i];
        } else if (eql(args[i], "--from-account")) {
            i += 1;
            if (i < args.len) result.from_account = args[i];
        } else if (eql(args[i], "--resume")) {
            i += 1;
            if (i < args.len) result.resume_id = args[i];
        } else if (eql(args[i], "--resume-last")) {
            result.resume_last = true;
        } else if (eql(args[i], "--include-non-interactive")) {
            result.include_non_interactive = true;
        } else if (eql(args[i], "--stdin")) {
            result.stdin_prompts = true;
        } else if (eql(args[i], "--continue-on-failure")) {
            result.continue_on_failure = true;
        } else if (eql(args[i], "--device")) {
            result.device = true;
        } else if (eql(args[i], "--status-only")) {
            result.status_only = true;
        } else if (eql(args[i], "--live")) {
            result.live = true;
        } else if (eql(args[i], "--confirm-spend")) {
            result.confirm_spend = true;
        } else if (eql(args[i], "--confirm-broker")) {
            result.confirm_broker = true;
        } else if (eql(args[i], "--confirm-drill")) {
            result.confirm_drill = true;
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

fn hasHelpFlag(args: []const []const u8) bool {
    for (args) |arg| {
        if (eql(arg, "--help") or eql(arg, "-h")) return true;
    }
    return false;
}

pub fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\oauth-mux — OAuth fallback muxing for AI harness subscriptions
        \\
        \\Usage: oauth-mux <command> [options]
        \\
        \\Commands:
        \\  exec [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] -- <cmd> [args...]
        \\      Execute a command with muxed OAuth credentials injected.
        \\
        \\  env [--profile <name>] [--provider <name>] [--capability <name>] [--shell fish|zsh|bash|ksh]
        \\      Print shell export statements for eval.
        \\
        \\  probe [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Validate a selected account and run its capability probe when configured.
        \\
        \\  doctor [--json]
        \\      Run local config readiness checks and print first-run next commands.
        \\
        \\  doctor runtime [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Check local runtime readiness without reading token values.
        \\
        \\  report [--redacted] [--json] [--include-paths]
        \\      Print a redacted support bundle without reading credential values.
        \\
        \\  providers list [--json]
        \\      Show built-in and configured provider support status.
        \\
        \\  accounts list [--provider <name>] [--json]
        \\      Show configured accounts, runtime readiness, liveness evidence, and safe next commands.
        \\
        \\  enroll plan <provider> [--account <name>] [--mode <mode>] [--json]
        \\      Show provider-specific enrollment steps without mutating auth state.
        \\
        \\  enroll codex --account <name> [--store-root <path>] [--confirm-enroll] [--json]
        \\      Add a Codex account to oauth-mux config; does not run Codex login.
        \\
        \\  enroll claude --account <name> [--config-root <path>] [--confirm-enroll] [--json]
        \\      Add a Claude account config dir; does not run Claude login.
        \\
        \\  enroll figma --account <name> [--mode oauth|pat|plan] [--secret-env <name>] [--confirm-enroll] [--json]
        \\      Add a Figma account secret route; does not create or validate token material.
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
        \\  repair-plan [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Explain non-mutating repair actions from runtime and liveness state.
        \\
        \\  repair run [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--confirm-repair] [--json]
        \\      Run one admitted repair action; refuses mutation without confirmation.
        \\
        \\  route select|explain [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Select or explain a route from recorded liveness without probing.
        \\
        \\  stay-afloat [--once|--loop] [--execute] [--iterations <n>] [--interval-ms <ms>] [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Run the portable stay-afloat planner/executor without service-manager assumptions.
        \\  stay-afloat next [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Show the next mediated action: exec argv when afloat, otherwise typed repair/handoff.
        \\  stay-afloat launch [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] -- <cmd> [args...]
        \\      Launch a target only when route evidence selects an exact account; otherwise print mediation and exit nonzero.
        \\  stay-afloat observe [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--classify-exit-code <code>] [--classify-codex-usage-limit] [--stream-capture] [--json] -- <cmd> [args...]
        \\      Run a diagnostic child capture; does not relaunch or claim seamless stay-afloat.
        \\  stay-afloat refresh [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Run one execute tick to refresh route evidence after user-mediated auth.
        \\  stay-afloat handoffs [--json] [--limit <n>] [--all]
        \\      Show pending user-mediated stay-afloat handoffs; --all includes history.
        \\  stay-afloat handoff ack|clear --provider <name> --account <name> [--profile <name>] [--capability <name>] [--json]
        \\      Acknowledge or clear a pending user-mediated handoff.
        \\
        \\  config validate    Validate the configuration file.
        \\  config path        Print the config file path.
        \\
        \\  daemon run [--stay-afloat] [stay-afloat options]
        \\      Run the daemon in the foreground; --stay-afloat hosts the foreground tick loop.
        \\  daemon loop [stay-afloat options]
        \\      Alias for daemon run --stay-afloat. `daemon supervise` remains a legacy alias.
        \\  daemon start       Start experimental daemon stub; no automatic repair.
        \\  daemon stop        Stop the daemon.
        \\  daemon status [--json]
        \\      Show daemon status.
        \\
        \\  daemon events [--json] [--limit <n>]
        \\      Show recent redacted repair events.
        \\
        \\  daemon handoffs [--json] [--limit <n>] [--all]
        \\      Show pending user-mediated daemon handoffs; --all includes history.
        \\
        \\  daemon tick [--once|--loop] [--execute] [--iterations <n>] [--interval-ms <ms>] [--profile <name>] [--provider <name>] [--account <name>] [--capability <name>] [--json]
        \\      Plan daemon ticks; --execute runs at most one admitted non-interactive action per tick.
        \\
        \\  mcp [--profile <name>] [--capability <name>]
        \\      Run the broker MCP/JSON-RPC server on stdio for harness adapters.
        \\
        \\  codex [--profile name] [--account provider:account] [--session-home path] [--isolated-session-store] [--json-status] [--json-status-file path] [-- codex-args...]
        \\      Run a broker-mediated Codex adapter session with a local wire proxy.
        \\  codex resume [id|--last]
        \\      Resume Codex inside the broker-mediated adapter frame.
        \\  codex run [adapter options] -- [codex-args...]
        \\      Advanced/testing spelling for the broker-mediated Codex adapter.
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
        \\      Run Codex Max readiness checks; --live contacts provider endpoints.
        \\
        \\  codex live-qa [--accounts a,b,c] [--capabilities c1,c2] [--confirm-spend] [--json]
        \\      Run confirmed Codex route probes and record route evidence.
        \\
        \\  codex revalidate-exhausted [--profile name] [--capability c] [--account a] --confirm-spend [--json]
        \\      Re-probe exhausted Codex routes after external billing or credit changes.
        \\
        \\  codex probe-all [--accounts a,b,c] [--capabilities c1,c2] [--json]
        \\      Probe every selected Codex account/capability route.
        \\
        \\  codex preflight [--profile name] [--capability c] [--account a] [--json]
        \\      Managed Codex readiness snapshot: install, policy, routes, and next actions.
        \\
        \\  codex managed-plan [--profile name] [--capability c] [--json]
        \\      Plan a legacy route-local native Codex launch diagnostic.
        \\
        \\  codex managed [--profile name] [--capability c] [--resume id|--resume-last] [--include-non-interactive] [-- codex-args...]
        \\      Launch native Codex through stay-afloat route selection and selected CODEX_HOME.
        \\
        \\  codex status-latest [--status-file path] [--json]
        \\      Summarize a Codex managed status artifact; defaults to the latest state artifact.
        \\
        \\  codex broker-plan [--profile name] [--capability c] [--json]
        \\      Inspect local app-server auth material only; use broker-session-plan for route-aware selection.
        \\
        \\  codex broker-session-plan [--profile name] [--capability c] [--json]
        \\      Plan a broker-owned Codex session from route liveness and auth-broker readiness.
        \\
        \\  codex broker-session-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\      Run a local multi-turn broker-owned Codex session smoke from the session plan.
        \\
        \\  codex broker-run [--profile name] [--capability c] (--prompt text|--stdin) --confirm-spend [--model m] [--continue-on-failure] [--json]
        \\      Run live broker-owned Codex app-server turns from the session plan.
        \\
        \\  codex broker-fallback-drill [--profile name] [--capability c] --from-account name --confirm-drill [--json]
        \\      Mark one Codex route quota-exhausted locally and prove the next broker-owned route selection.
        \\
        \\  codex broker-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\      Start a broker-owned Codex app-server stdio session and verify external auth login.
        \\
        \\  codex broker-refresh-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\      Verify a broker-owned Codex app-server auth-refresh response path.
        \\
        \\  codex broker-401-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\      Verify a broker-owned Codex app-server 401 retry with fallback auth.
        \\
        \\  codex broker-quota-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\      Verify a broker-owned Codex app-server next-turn quota fallback.
        \\
        \\  codex config-candidate [--output path] [--store-root path] [--json]
        \\      Write a non-overwriting Codex Max config candidate.
        \\
        \\  codex config-merge [--candidate path] [--backup path] [--json]
        \\      Merge a reviewed Codex Max candidate into the active config with backup.
        \\
        \\  codex login <account> | login-device <account> | login-status [account] | login-status-all
        \\      Codex account login/status helpers using isolated CODEX_HOME dirs.
        \\
        \\  completions <shell> Generate shell completions (fish|zsh|bash).
        \\
        \\  version [--json]   Print version; --json includes runtime binary identity.
        \\  help               Print this help.
        \\
        \\Environment:
        \\  OMUX_CONFIG        Override config file path
        \\  OMUX_CONFIG_DIR    Override config directory
        \\  OMUX_STATE_DIR     Override state directory
        \\  OMUX_RUNTIME_DIR   Override runtime directory (locks, daemon socket)
        \\  OMUX_SHELL         Override shell detection
        \\  OMUX_DEBUG         Enable debug logging
        \\  NO_COLOR           Disable colored output
        \\
        \\Version:
    );
    try writer.writeAll(version);
    try writer.writeAll("\n");
}

pub fn printCodexUsage(writer: anytype) !void {
    try writer.writeAll(
        \\oauth-mux codex — broker-mediated Codex sessions, setup, and probes
        \\
        \\Usage:
        \\  oauth-mux codex [--profile name] [--capability c] [--account provider:account] [--session-home path] [--isolated-session-store] [--json-status] [--json-status-file path] [-- codex-args...]
        \\  oauth-mux codex resume [id|--last]
        \\  oauth-mux codex run [adapter options] -- [codex-args...]
        \\  oauth-mux setup codex [--accounts a,b,c] [--device|--status-only] [--live]
        \\  oauth-mux codex setup|onboard [--accounts a,b,c] [--device|--status-only] [--live]
        \\  oauth-mux codex canary [--accounts a,b,c] [--capabilities c1,c2] [--live]
        \\  oauth-mux codex live-qa [--accounts a,b,c] [--capabilities c1,c2] [--confirm-spend] [--json]
        \\  oauth-mux codex revalidate-exhausted [--profile name] [--capability c] [--account a] --confirm-spend [--json]
        \\  oauth-mux codex probe-all [--accounts a,b,c] [--capability c] [--json]
        \\  oauth-mux codex preflight [--profile name] [--capability c] [--account a] [--json]
        \\  oauth-mux codex managed-plan [--profile name] [--capability c] [--json]
        \\  oauth-mux codex managed [--profile name] [--capability c] [--resume id|--resume-last] [--include-non-interactive] [-- codex-args...]
        \\  oauth-mux codex status-latest [--status-file path] [--json]
        \\  oauth-mux codex broker-plan [--profile name] [--capability c] [--json]
        \\  oauth-mux codex broker-session-plan [--profile name] [--capability c] [--json]
        \\  oauth-mux codex broker-session-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\  oauth-mux codex broker-run [--profile name] [--capability c] (--prompt text|--stdin) --confirm-spend [--model m] [--continue-on-failure] [--json]
        \\  oauth-mux codex broker-fallback-drill [--profile name] [--capability c] --from-account name --confirm-drill [--json]
        \\  oauth-mux codex broker-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\  oauth-mux codex broker-refresh-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\  oauth-mux codex broker-401-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\  oauth-mux codex broker-quota-smoke [--profile name] [--capability c] --confirm-broker [--json]
        \\  oauth-mux codex config-candidate [--output path] [--store-root path] [--json]
        \\  oauth-mux codex config-merge [--candidate path] [--backup path] [--json]
        \\  oauth-mux codex bootstrap-dirs [--accounts a,b,c] [--store-root path]
        \\  oauth-mux codex login <account> [--store-root path]
        \\  oauth-mux codex login-device <account> [--store-root path]
        \\  oauth-mux codex login-status [account] [--store-root path]
        \\  oauth-mux codex login-status-all [--accounts a,b,c] [--store-root path]
        \\
        \\Safety:
        \\  canary reads local readiness by default; --live contacts provider endpoints.
        \\  live-qa, revalidate-exhausted, probe-all, and canary --live run real provider probes.
        \\  managed-plan only inspects route-local launch readiness. managed launches
        \\  native Codex under the selected route-local CODEX_HOME, so provider calls
        \\  depend on the Codex child process and are not made during planning.
        \\  For canonical Codex resume authority, use oauth-mux codex resume.
        \\  broker-smoke, broker-refresh-smoke, broker-401-smoke,
        \\  broker-quota-smoke, broker-session-smoke, and broker-run read a
        \\  selected Codex route secret and send it only to a broker-owned
        \\  Codex app-server child process; they do not print token or
        \\  account-id values.
        \\  broker-run may persist live quota/rate-limit evidence to route health
        \\  and, with --continue-on-failure, start a fresh broker-owned session on
        \\  the next selected route.
        \\  broker-fallback-drill mutates only oauth-mux route health; it does
        \\  not contact provider endpoints or print secrets.
        \\  live-qa, revalidate-exhausted, and broker-run require --confirm-spend or
        \\  OMUX_LIVE_QA_CONFIRM=spend-real-calls.
        \\  --help and -h are non-mutating for every Codex subcommand.
        \\
        \\Defaults:
        \\  accounts:     max-1,max-2,max-3 (starter; pass --accounts for max-4)
        \\  capabilities: codex-mini,codex-max
        \\  store root:   $XDG_DATA_HOME/oauth-mux/codex or ~/.local/share/oauth-mux/codex
        \\
    );
}

test "parse exec with profile and target" {
    const args = [_][]const u8{ "exec", "--profile", "work", "--provider", "codex", "--account", "max-2", "--capability", "codex-max", "--", "claude", "chat" };
    const cmd = parse(&args);
    switch (cmd) {
        .exec => |exec| {
            try std.testing.expectEqualStrings("work", exec.profile.?);
            try std.testing.expectEqualStrings("codex", exec.provider.?);
            try std.testing.expectEqualStrings("max-2", exec.account.?);
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

test "parse keepalive defaults and flags" {
    switch (parse(&[_][]const u8{"keepalive"})) {
        .keepalive => |k| {
            try std.testing.expectEqual(@as(u32, 1), k.iterations);
            try std.testing.expectEqual(@as(u64, 60_000), k.interval_ms);
            try std.testing.expect(!k.json);
        },
        else => return error.Unexpected,
    }
    switch (parse(&[_][]const u8{ "keepalive", "--iterations", "5", "--interval-ms", "1000", "--json" })) {
        .keepalive => |k| {
            try std.testing.expectEqual(@as(u32, 5), k.iterations);
            try std.testing.expectEqual(@as(u64, 1000), k.interval_ms);
            try std.testing.expect(k.json);
        },
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
        .doctor => |doctor| {
            try std.testing.expect(doctor.mode == .summary);
            try std.testing.expect(doctor.json);
        },
        else => return error.Unexpected,
    }
}

test "parse doctor runtime json" {
    const args = [_][]const u8{ "doctor", "runtime", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .doctor => |doctor| {
            try std.testing.expect(doctor.mode == .runtime);
            try std.testing.expect(doctor.json);
        },
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

test "parse codex live qa confirmation" {
    const args = [_][]const u8{ "codex", "live-qa", "--accounts", "max-1,max-3", "--capabilities", "codex-mini", "--confirm-spend", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .live_qa);
            try std.testing.expectEqualStrings("max-1,max-3", codex.accounts);
            try std.testing.expectEqualStrings("codex-mini", codex.capabilities);
            try std.testing.expect(codex.confirm_spend);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex revalidate exhausted" {
    const args = [_][]const u8{ "codex", "revalidate-exhausted", "--profile", "codex-max", "--capability", "codex-max", "--account", "max-3", "--confirm-spend", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .revalidate_exhausted);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expectEqualStrings("max-3", codex.account.?);
            try std.testing.expect(codex.confirm_spend);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex subcommand help as non-mutating help" {
    const canary_args = [_][]const u8{ "codex", "canary", "--help" };
    try std.testing.expect(parse(&canary_args) == .codex_help);

    const probe_args = [_][]const u8{ "codex", "probe-all", "-h" };
    try std.testing.expect(parse(&probe_args) == .codex_help);

    const setup_args = [_][]const u8{ "setup", "codex", "--help" };
    try std.testing.expect(parse(&setup_args) == .codex_help);
}

test "parse codex config candidate" {
    const args = [_][]const u8{ "codex", "config-candidate", "--output", "/tmp/codex-max.config.json", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .config_candidate);
            try std.testing.expectEqualStrings("/tmp/codex-max.config.json", codex.output.?);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex config merge" {
    const args = [_][]const u8{ "codex", "config-merge", "--candidate", "/tmp/candidate.json", "--backup", "/tmp/config.backup.json", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .config_merge);
            try std.testing.expectEqualStrings("/tmp/candidate.json", codex.candidate.?);
            try std.testing.expectEqualStrings("/tmp/config.backup.json", codex.backup.?);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker plan" {
    const args = [_][]const u8{ "codex", "broker-plan", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_plan);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker session plan" {
    const args = [_][]const u8{ "codex", "broker-session-plan", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_session_plan);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex managed plan" {
    const args = [_][]const u8{ "codex", "managed-plan", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .managed_plan);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex preflight" {
    const args = [_][]const u8{ "codex", "preflight", "--profile", "codex-max", "--capability", "codex-max", "--account", "max-2", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .preflight);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expectEqualStrings("max-2", codex.account.?);
            try std.testing.expect(codex.json);
        },
        else => return error.TestUnexpectedCommand,
    }
}

test "parse codex status latest" {
    const args = [_][]const u8{ "codex", "status-latest", "--status-file", "/tmp/status.ndjson", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .status_latest);
            try std.testing.expectEqualStrings("/tmp/status.ndjson", codex.status_file.?);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex managed resume last passthrough" {
    const args = [_][]const u8{ "codex", "managed", "--profile", "codex-max", "--capability", "codex-max", "--resume-last", "--include-non-interactive", "--", "--model", "gpt-5.5", "--no-alt-screen" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .managed);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.resume_last);
            try std.testing.expect(codex.include_non_interactive);
            try std.testing.expectEqual(@as(usize, 3), codex.managed_argv.len);
            try std.testing.expectEqualStrings("--model", codex.managed_argv[0]);
            try std.testing.expectEqualStrings("gpt-5.5", codex.managed_argv[1]);
            try std.testing.expectEqualStrings("--no-alt-screen", codex.managed_argv[2]);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker session smoke" {
    const args = [_][]const u8{ "codex", "broker-session-smoke", "--profile", "codex-max", "--capability", "codex-max", "--confirm-broker", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_session_smoke);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.confirm_broker);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker run" {
    const args = [_][]const u8{ "codex", "broker-run", "--profile", "codex-max", "--capability", "codex-max", "--prompt", "hello", "--model", "gpt-5.5", "--confirm-spend", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_run);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expectEqualStrings("hello", codex.prompt.?);
            try std.testing.expectEqualStrings("gpt-5.5", codex.model.?);
            try std.testing.expect(codex.confirm_spend);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker run stdin" {
    const args = [_][]const u8{ "codex", "broker-run", "--profile", "codex-max", "--capability", "codex-max", "--stdin", "--continue-on-failure", "--confirm-spend", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_run);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.stdin_prompts);
            try std.testing.expect(codex.continue_on_failure);
            try std.testing.expect(codex.confirm_spend);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker fallback drill" {
    const args = [_][]const u8{ "codex", "broker-fallback-drill", "--profile", "codex-max", "--capability", "codex-max", "--from-account", "max-3", "--confirm-drill", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_fallback_drill);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expectEqualStrings("max-3", codex.from_account.?);
            try std.testing.expect(codex.confirm_drill);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker smoke" {
    const args = [_][]const u8{ "codex", "broker-smoke", "--profile", "codex-max", "--capability", "codex-max", "--confirm-broker", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_smoke);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.confirm_broker);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker refresh smoke" {
    const args = [_][]const u8{ "codex", "broker-refresh-smoke", "--profile", "codex-max", "--capability", "codex-max", "--confirm-broker", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_refresh_smoke);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.confirm_broker);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker 401 smoke" {
    const args = [_][]const u8{ "codex", "broker-401-smoke", "--profile", "codex-max", "--capability", "codex-max", "--confirm-broker", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_401_smoke);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.confirm_broker);
            try std.testing.expect(codex.json);
        },
        else => return error.Unexpected,
    }
}

test "parse codex broker quota smoke" {
    const args = [_][]const u8{ "codex", "broker-quota-smoke", "--profile", "codex-max", "--capability", "codex-max", "--confirm-broker", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .broker_quota_smoke);
            try std.testing.expectEqualStrings("codex-max", codex.profile.?);
            try std.testing.expectEqualStrings("codex-max", codex.capabilities);
            try std.testing.expect(codex.confirm_broker);
            try std.testing.expect(codex.json);
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
    const login_args = [_][]const u8{ "codex", "login", "max-2" };
    const login_cmd = parse(&login_args);
    switch (login_cmd) {
        .codex => |codex| {
            try std.testing.expect(codex.action == .login);
            try std.testing.expectEqualStrings("max-2", codex.account.?);
        },
        else => return error.Unexpected,
    }

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

test "parse accounts list provider json" {
    const args = [_][]const u8{ "accounts", "list", "--provider", "codex", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .accounts => |accounts| {
            try std.testing.expect(accounts.action == .list);
            try std.testing.expectEqualStrings("codex", accounts.provider.?);
            try std.testing.expect(accounts.json);
        },
        else => return error.Unexpected,
    }
}

test "parse enroll plan provider account mode json" {
    const args = [_][]const u8{ "enroll", "plan", "figma", "--account", "work", "--mode", "pat", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .enroll => |enroll| {
            try std.testing.expect(enroll.action == .plan);
            try std.testing.expectEqualStrings("figma", enroll.provider.?);
            try std.testing.expectEqualStrings("work", enroll.account.?);
            try std.testing.expectEqualStrings("pat", enroll.mode.?);
            try std.testing.expect(enroll.json);
        },
        else => return error.Unexpected,
    }
}

test "parse enroll codex account confirmation" {
    const args = [_][]const u8{ "enroll", "codex", "--account", "max-4", "--store-root", "/tmp/codex", "--confirm-enroll", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .enroll => |enroll| {
            try std.testing.expect(enroll.action == .codex);
            try std.testing.expectEqualStrings("codex", enroll.provider.?);
            try std.testing.expectEqualStrings("max-4", enroll.account.?);
            try std.testing.expectEqualStrings("/tmp/codex", enroll.store_root.?);
            try std.testing.expect(enroll.confirm_enroll);
            try std.testing.expect(enroll.json);
        },
        else => return error.Unexpected,
    }
}

test "parse enroll claude account confirmation" {
    const args = [_][]const u8{ "enroll", "claude", "work", "--config-root", "/tmp/claude", "--confirm", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .enroll => |enroll| {
            try std.testing.expect(enroll.action == .claude);
            try std.testing.expectEqualStrings("claude", enroll.provider.?);
            try std.testing.expectEqualStrings("work", enroll.account.?);
            try std.testing.expectEqualStrings("/tmp/claude", enroll.store_root.?);
            try std.testing.expect(enroll.confirm_enroll);
            try std.testing.expect(enroll.json);
        },
        else => return error.Unexpected,
    }
}

test "parse enroll figma account mode secret env confirmation" {
    const args = [_][]const u8{ "enroll", "figma", "service", "--mode", "pat", "--secret-env", "OMUX_FIGMA_SERVICE_PAT", "--confirm", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .enroll => |enroll| {
            try std.testing.expect(enroll.action == .figma);
            try std.testing.expectEqualStrings("figma", enroll.provider.?);
            try std.testing.expectEqualStrings("service", enroll.account.?);
            try std.testing.expectEqualStrings("pat", enroll.mode.?);
            try std.testing.expectEqualStrings("OMUX_FIGMA_SERVICE_PAT", enroll.secret_env.?);
            try std.testing.expect(enroll.confirm_enroll);
            try std.testing.expect(enroll.json);
        },
        else => return error.Unexpected,
    }
}

test "parse repair plan with profile" {
    const args = [_][]const u8{ "repair-plan", "--profile", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .repair_plan => |repair| {
            try std.testing.expectEqualStrings("codex-max", repair.profile.?);
            try std.testing.expect(repair.json);
        },
        else => return error.Unexpected,
    }
}

test "parse runtime doctor with route scope" {
    const args = [_][]const u8{ "doctor", "runtime", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .doctor => |doctor| {
            try std.testing.expect(doctor.mode == .runtime);
            try std.testing.expectEqualStrings("codex-max", doctor.profile.?);
            try std.testing.expectEqualStrings("codex-max", doctor.capability.?);
            try std.testing.expect(doctor.json);
        },
        else => return error.Unexpected,
    }
}

test "parse repair run requires explicit confirmation flag" {
    const args = [_][]const u8{ "repair", "run", "--profile", "codex-max", "--capability", "codex-max", "--confirm-repair", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .repair_run => |repair| {
            try std.testing.expectEqualStrings("codex-max", repair.profile.?);
            try std.testing.expectEqualStrings("codex-max", repair.capability.?);
            try std.testing.expect(repair.confirm_repair);
            try std.testing.expect(repair.json);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon repair plan alias" {
    const args = [_][]const u8{ "daemon", "repair-plan", "--provider", "codex", "--account", "max-1", "--capability", "codex-max" };
    const cmd = parse(&args);
    switch (cmd) {
        .repair_plan => |repair| {
            try std.testing.expectEqualStrings("codex", repair.provider.?);
            try std.testing.expectEqualStrings("max-1", repair.account.?);
            try std.testing.expectEqualStrings("codex-max", repair.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse route explain with profile" {
    const args = [_][]const u8{ "route", "explain", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .route => |route| {
            try std.testing.expect(route.action == .explain);
            try std.testing.expectEqualStrings("codex-max", route.profile.?);
            try std.testing.expectEqualStrings("codex-max", route.capability.?);
            try std.testing.expect(route.json);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon run" {
    const args = [_][]const u8{ "daemon", "run" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_run => |run| try std.testing.expect(!run.stay_afloat),
        else => return error.Unexpected,
    }
}

test "parse daemon events json limit" {
    const args = [_][]const u8{ "daemon", "events", "--json", "--limit", "5" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_events => |events| {
            try std.testing.expect(events.json);
            try std.testing.expectEqual(@as(usize, 5), events.limit);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon handoffs json limit" {
    const args = [_][]const u8{ "daemon", "handoffs", "--json", "--limit", "3", "--all" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_handoffs => |events| {
            try std.testing.expect(events.json);
            try std.testing.expectEqual(@as(usize, 3), events.limit);
            try std.testing.expect(events.all);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon tick once json selector" {
    const args = [_][]const u8{ "daemon", "tick", "--once", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_tick => |tick| {
            try std.testing.expect(tick.once);
            try std.testing.expect(tick.json);
            try std.testing.expectEqualStrings("codex-max", tick.profile.?);
            try std.testing.expectEqualStrings("codex-max", tick.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat once json selector" {
    const args = [_][]const u8{ "stay-afloat", "--once", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat => |tick| {
            try std.testing.expect(tick.once);
            try std.testing.expect(tick.json);
            try std.testing.expectEqualStrings("codex-max", tick.profile.?);
            try std.testing.expectEqualStrings("codex-max", tick.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat next json selector" {
    const args = [_][]const u8{ "stay-afloat", "next", "--profile", "codex-max", "--account", "max-2", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_next => |route| {
            try std.testing.expect(route.action == .explain);
            try std.testing.expectEqualStrings("codex-max", route.profile.?);
            try std.testing.expectEqualStrings("max-2", route.account.?);
            try std.testing.expectEqualStrings("codex-max", route.capability.?);
            try std.testing.expect(route.json);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat launch selector and target" {
    const args = [_][]const u8{ "stay-afloat", "launch", "--profile", "codex-max", "--provider", "codex", "--account", "max-2", "--capability", "codex-max", "--", "codex", "--ask-for-approval=never" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_launch => |launch| {
            try std.testing.expectEqualStrings("codex-max", launch.profile.?);
            try std.testing.expectEqualStrings("codex", launch.provider.?);
            try std.testing.expectEqualStrings("max-2", launch.account.?);
            try std.testing.expectEqualStrings("codex-max", launch.capability.?);
            try std.testing.expectEqual(@as(usize, 2), launch.target_argv.len);
            try std.testing.expectEqualStrings("codex", launch.target_argv[0]);
            try std.testing.expectEqualStrings("--ask-for-approval=never", launch.target_argv[1]);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat observe selector diagnostic policy and target" {
    const args = [_][]const u8{ "stay-afloat", "observe", "--profile", "codex-max", "--provider", "codex", "--account", "max-2", "--capability", "codex-max", "--classify-exit-code", "42", "--classify-codex-usage-limit", "--stream-capture", "--json", "--", "codex", "--ask-for-approval=never" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_observe => |observe| {
            try std.testing.expectEqualStrings("codex-max", observe.profile.?);
            try std.testing.expectEqualStrings("codex", observe.provider.?);
            try std.testing.expectEqualStrings("max-2", observe.account.?);
            try std.testing.expectEqualStrings("codex-max", observe.capability.?);
            try std.testing.expectEqual(@as(u8, 42), observe.classify_exit_code.?);
            try std.testing.expect(observe.classify_codex_usage_limit);
            try std.testing.expect(observe.stream_capture);
            try std.testing.expect(observe.json);
            try std.testing.expect(!observe.legacy_restart_aliases_used);
            try std.testing.expectEqual(@as(usize, 2), observe.target_argv.len);
            try std.testing.expectEqualStrings("codex", observe.target_argv[0]);
            try std.testing.expectEqualStrings("--ask-for-approval=never", observe.target_argv[1]);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon run stay-afloat foreground loop" {
    const args = [_][]const u8{ "daemon", "run", "--stay-afloat", "--profile", "codex-max", "--capability", "codex-max", "--iterations", "2", "--interval-ms", "0" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_run => |run| {
            try std.testing.expect(run.stay_afloat);
            try std.testing.expect(!run.tick.once);
            try std.testing.expect(run.tick.execute);
            try std.testing.expectEqual(@as(u32, 2), run.tick.iterations);
            try std.testing.expectEqual(@as(u64, 0), run.tick.interval_ms);
            try std.testing.expectEqualStrings("codex-max", run.tick.profile.?);
            try std.testing.expectEqualStrings("codex-max", run.tick.capability.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse legacy stay-afloat supervise as observe" {
    const args = [_][]const u8{ "stay-afloat", "supervise", "--max-restarts", "2", "--restart-on-exit-code", "42", "--restart-on-codex-usage-limit", "--", "codex" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_observe => |observe| {
            try std.testing.expectEqual(@as(u32, 2), observe.legacy_max_restarts);
            try std.testing.expect(observe.legacy_restart_aliases_used);
            try std.testing.expectEqual(@as(u8, 42), observe.classify_exit_code.?);
            try std.testing.expect(observe.classify_codex_usage_limit);
            try std.testing.expectEqualStrings("codex", observe.target_argv[0]);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat handoffs json limit" {
    const args = [_][]const u8{ "stay-afloat", "handoffs", "--json", "--limit", "2", "--all" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_handoffs => |events| {
            try std.testing.expect(events.json);
            try std.testing.expectEqual(@as(usize, 2), events.limit);
            try std.testing.expect(events.all);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat refresh enables execute tick" {
    const args = [_][]const u8{ "stay-afloat", "refresh", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat => |tick| {
            try std.testing.expect(tick.once);
            try std.testing.expect(tick.execute);
            try std.testing.expect(tick.json);
            try std.testing.expectEqualStrings("codex-max", tick.profile.?);
            try std.testing.expectEqualStrings("codex-max", tick.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat handoff acknowledgement" {
    const args = [_][]const u8{ "stay-afloat", "handoff", "ack", "--profile", "codex-max", "--provider", "codex", "--account", "max-1", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_handoff => |handoff| {
            try std.testing.expectEqual(Command.HandoffAction.ack, handoff.action);
            try std.testing.expectEqualStrings("codex-max", handoff.profile.?);
            try std.testing.expectEqualStrings("codex", handoff.provider.?);
            try std.testing.expectEqualStrings("max-1", handoff.account.?);
            try std.testing.expectEqualStrings("codex-max", handoff.capability.?);
            try std.testing.expect(handoff.json);
        },
        else => return error.Unexpected,
    }
}

test "parse stay-afloat handoff clear" {
    const args = [_][]const u8{ "stay-afloat", "handoff", "clear", "--provider", "codex", "--account", "max-1", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .stay_afloat_handoff => |handoff| {
            try std.testing.expectEqual(Command.HandoffAction.clear, handoff.action);
            try std.testing.expectEqualStrings("codex", handoff.provider.?);
            try std.testing.expectEqualStrings("max-1", handoff.account.?);
            try std.testing.expect(handoff.json);
        },
        else => return error.Unexpected,
    }
}

test "parse daemon tick bounded loop" {
    const args = [_][]const u8{ "daemon", "tick", "--loop", "--execute", "--iterations", "3", "--interval-ms", "250", "--profile", "codex-max", "--capability", "codex-max", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .daemon_tick => |tick| {
            try std.testing.expect(!tick.once);
            try std.testing.expect(tick.execute);
            try std.testing.expectEqual(@as(u32, 3), tick.iterations);
            try std.testing.expectEqual(@as(u64, 250), tick.interval_ms);
            try std.testing.expect(tick.json);
            try std.testing.expectEqualStrings("codex-max", tick.profile.?);
            try std.testing.expectEqualStrings("codex-max", tick.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse mcp broker server profile" {
    const args = [_][]const u8{ "mcp", "--profile", "codex-max", "--capability", "codex-max" };
    const cmd = parse(&args);
    switch (cmd) {
        .mcp => |mcp| {
            try std.testing.expectEqualStrings("codex-max", mcp.profile.?);
            try std.testing.expectEqualStrings("codex-max", mcp.capability.?);
        },
        else => return error.Unexpected,
    }
}

test "parse codex run adapter args" {
    const args = [_][]const u8{ "codex", "run", "--profile", "codex-max", "--capability", "codex-max", "--account", "codex:max-1", "--session-home", "/tmp/codex-sessions", "--isolated-session-store", "--json-status-file", "/tmp/omux-status.ndjson", "--", "--model", "gpt-5.5" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex_adapter => |adapter| {
            try std.testing.expectEqualStrings("codex-max", adapter.profile.?);
            try std.testing.expectEqualStrings("codex-max", adapter.capability.?);
            try std.testing.expectEqualStrings("codex:max-1", adapter.account.?);
            try std.testing.expectEqualStrings("/tmp/codex-sessions", adapter.session_home.?);
            try std.testing.expect(adapter.isolated_session_store);
            try std.testing.expect(adapter.json_status);
            try std.testing.expectEqualStrings("/tmp/omux-status.ndjson", adapter.json_status_file.?);
            try std.testing.expect(adapter.invalid_option == null);
            try std.testing.expectEqual(@as(usize, 2), adapter.forward_argv.len);
            try std.testing.expectEqualStrings("--model", adapter.forward_argv[0]);
            try std.testing.expectEqualStrings("gpt-5.5", adapter.forward_argv[1]);
        },
        else => return error.Unexpected,
    }
}

test "parse codex top-level resume aliases route to adapter" {
    const resume_last_args = [_][]const u8{ "codex", "--profile", "codex-max", "--json-status-file", "/tmp/omux.ndjson", "resume", "--last" };
    const resume_last = parse(&resume_last_args);
    switch (resume_last) {
        .codex_adapter => |adapter| {
            try std.testing.expectEqualStrings("codex-max", adapter.profile.?);
            try std.testing.expectEqualStrings("/tmp/omux.ndjson", adapter.json_status_file.?);
            try std.testing.expectEqual(@as(usize, 2), adapter.forward_argv.len);
            try std.testing.expectEqualStrings("resume", adapter.forward_argv[0]);
            try std.testing.expectEqualStrings("--last", adapter.forward_argv[1]);
        },
        else => return error.Unexpected,
    }

    const resume_id_args = [_][]const u8{ "codex", "resume", "session-123" };
    const resume_id = parse(&resume_id_args);
    switch (resume_id) {
        .codex_adapter => |adapter| {
            try std.testing.expectEqual(@as(usize, 2), adapter.forward_argv.len);
            try std.testing.expectEqualStrings("resume", adapter.forward_argv[0]);
            try std.testing.expectEqualStrings("session-123", adapter.forward_argv[1]);
        },
        else => return error.Unexpected,
    }

    const resume_chooser_args = [_][]const u8{ "codex", "resume" };
    const resume_chooser = parse(&resume_chooser_args);
    switch (resume_chooser) {
        .codex_adapter => |adapter| {
            try std.testing.expectEqual(@as(usize, 1), adapter.forward_argv.len);
            try std.testing.expectEqualStrings("resume", adapter.forward_argv[0]);
        },
        else => return error.Unexpected,
    }
}

test "parse codex top-level adapter preserves explicit separator" {
    const args = [_][]const u8{ "codex", "--profile", "codex-max", "--", "--help" };
    const cmd = parse(&args);
    switch (cmd) {
        .codex_adapter => |adapter| {
            try std.testing.expectEqualStrings("codex-max", adapter.profile.?);
            try std.testing.expectEqual(@as(usize, 1), adapter.forward_argv.len);
            try std.testing.expectEqualStrings("--help", adapter.forward_argv[0]);
        },
        else => return error.Unexpected,
    }
}

test "parse codex run property: args after separator are preserved exactly" {
    const cases = [_][]const []const u8{
        &.{ "resume", "--last" },
        &.{ "resume", "019dea53-49a0-7890-9580-e88decb97af0" },
        &.{ "--no-alt-screen", "resume", "--last" },
        &.{ "exec", "--json", "hello" },
    };

    for (cases) |forward| {
        var argv: [12][]const u8 = undefined;
        argv[0] = "codex";
        argv[1] = "run";
        argv[2] = "--";
        for (forward, 0..) |arg, i| argv[3 + i] = arg;
        const parsed = parse(argv[0 .. 3 + forward.len]);
        switch (parsed) {
            .codex_adapter => |adapter| {
                try std.testing.expectEqual(forward.len, adapter.forward_argv.len);
                for (forward, 0..) |arg, i| {
                    try std.testing.expectEqualStrings(arg, adapter.forward_argv[i]);
                }
                try std.testing.expect(adapter.invalid_option == null);
            },
            else => return error.Unexpected,
        }
    }
}

test "parse codex run property: unknown pre-separator args are never dropped" {
    const invalid = [_][]const u8{ "resume", "--model", "codex", "--no-alt-screen" };
    for (invalid) |arg| {
        const args = [_][]const u8{ "codex", "run", arg, "ignored" };
        const cmd = parse(&args);
        switch (cmd) {
            .codex_adapter => |adapter| {
                try std.testing.expectEqualStrings(arg, adapter.invalid_option.?);
                try std.testing.expectEqual(@as(usize, 0), adapter.forward_argv.len);
            },
            else => return error.Unexpected,
        }
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
            \\complete -c oauth-mux -n __fish_use_subcommand -a accounts -d 'List configured accounts'
            \\complete -c oauth-mux -n __fish_use_subcommand -a enroll -d 'Plan account enrollment'
            \\complete -c oauth-mux -n __fish_use_subcommand -a status -d 'Show status'
            \\complete -c oauth-mux -n __fish_use_subcommand -a health -d 'Show health data'
            \\complete -c oauth-mux -n __fish_use_subcommand -a discover -d 'Show agent-safe inventory'
            \\complete -c oauth-mux -n __fish_use_subcommand -a repair-plan -d 'Show non-mutating repair plan'
            \\complete -c oauth-mux -n __fish_use_subcommand -a repair -d 'Run admitted repair actions'
            \\complete -c oauth-mux -n __fish_use_subcommand -a route -d 'Select or explain routes'
            \\complete -c oauth-mux -n __fish_use_subcommand -a stay-afloat -d 'Run stay-afloat planner'
            \\complete -c oauth-mux -n __fish_use_subcommand -a config -d 'Config operations'
            \\complete -c oauth-mux -n __fish_use_subcommand -a init -d 'Generate config'
            \\complete -c oauth-mux -n __fish_use_subcommand -a setup -d 'First-run setup'
            \\complete -c oauth-mux -n __fish_use_subcommand -a codex -d 'Codex account onboarding'
            \\complete -c oauth-mux -n __fish_use_subcommand -a daemon -d 'Daemon operations'
            \\complete -c oauth-mux -n __fish_use_subcommand -a mcp -d 'Run broker MCP server'
            \\complete -c oauth-mux -n __fish_use_subcommand -a version -d 'Print version'
            \\complete -c oauth-mux -n __fish_use_subcommand -a completions -d 'Generate completions'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe route stay-afloat' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe route stay-afloat' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec probe route stay-afloat' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from exec env probe route stay-afloat' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from probe' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -a runtime -d 'Runtime readiness checks'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from doctor' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report providers accounts' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report' -l redacted -d 'Redact credential paths and values'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from report' -l include-paths -d 'Include non-token paths'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from providers' -a 'list' -d 'Provider subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from accounts' -a 'list' -d 'Accounts subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from accounts' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -a 'plan codex claude figma' -d 'Enrollment subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l mode -d 'Enrollment mode' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l store-root -d 'Codex store root' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l config-root -d 'Provider config root' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l secret-env -d 'Secret env var name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l confirm-enroll -d 'Confirm config/store mutation'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from enroll' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from env' -l shell -d 'Shell type' -r -a 'fish zsh bash ksh'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from status' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from discover' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair-plan' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair-plan' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair-plan' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair-plan' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair-plan' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -a 'run' -d 'Repair subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from repair' -l confirm-repair -d 'Confirm mutating repair'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from route' -a 'select explain' -d 'Route subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from route' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -a 'next launch observe handoffs handoff refresh' -d 'Stay-afloat subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from handoff' -a 'ack clear' -d 'Handoff action'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l once -d 'Run one stay-afloat tick'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l loop -d 'Run bounded foreground stay-afloat ticks'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l execute -d 'Execute one admitted non-interactive action'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l iterations -d 'Number of stay-afloat ticks' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l interval-ms -d 'Milliseconds between ticks' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l limit -d 'Limit handoff count' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l all -d 'Include historical handoff events'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l classify-exit-code -d 'Exit code to classify in observe diagnostics' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l classify-codex-usage-limit -d 'Classify captured Codex usage-limit text'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from stay-afloat' -l stream-capture -d 'Tee captured child output while retaining classifier buffers'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from init' -l codex-max -d 'Generate Codex Max scaffold'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from setup' -a 'codex' -d 'Setup target'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from config' -a 'validate path' -d 'Config subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex' -a 'resume run setup onboard canary live-qa revalidate-exhausted probe-all preflight managed-plan managed status-latest broker-plan broker-session-plan broker-session-smoke broker-run broker-fallback-drill broker-smoke broker-refresh-smoke broker-401-smoke broker-quota-smoke config-candidate config-merge bootstrap-dirs login login-device login-status login-status-all' -d 'Codex subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l account -d 'Route account id' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l session-home -d 'Canonical Codex session authority home' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l isolated-session-store -d 'Use isolated session authority for this run'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l json-status -d 'Emit redacted adapter status frames'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from codex run' -l json-status-file -d 'Write redacted adapter status frames to a file' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -a 'run loop start stop status events handoffs tick' -d 'Daemon subcommand'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l stay-afloat -d 'Host foreground stay-afloat tick loop'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l json -d 'JSON output'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l limit -d 'Limit event count' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l all -d 'Include historical handoff events'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l once -d 'Run one planning tick'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l loop -d 'Run bounded foreground planning ticks'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l execute -d 'Execute one admitted non-interactive tick action'
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l iterations -d 'Number of planning ticks' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l interval-ms -d 'Milliseconds between ticks' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l provider -d 'Provider name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l account -d 'Account name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from daemon' -l capability -d 'Route capability' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from mcp' -l profile -s p -d 'Profile name' -r
            \\complete -c oauth-mux -n '__fish_seen_subcommand_from mcp' -l capability -d 'Route capability' -r
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
            \\    'accounts:List configured accounts'
            \\    'enroll:Plan account enrollment'
            \\    'status:Show status'
            \\    'health:Show health data'
            \\    'discover:Show agent-safe inventory'
            \\    'repair-plan:Show non-mutating repair plan'
            \\    'repair:Run admitted repair actions'
            \\    'route:Select or explain routes'
            \\    'stay-afloat:Run stay-afloat planner'
            \\    'config:Config operations'
            \\    'init:Generate config'
            \\    'setup:First-run setup'
            \\    'codex:Codex account onboarding'
            \\    'daemon:Daemon operations'
            \\    'mcp:Run broker MCP server'
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
            \\  COMPREPLY=($(compgen -W "exec env probe doctor report providers accounts enroll status health discover repair-plan repair route stay-afloat config init setup codex daemon mcp version completions" -- "$cur"))
            \\}
            \\complete -F _oauth_mux_completions oauth-mux
            \\
        );
    }
}

test "parse version" {
    const args = [_][]const u8{"--version"};
    const cmd = parse(&args);
    switch (cmd) {
        .version_cmd => |parsed| try std.testing.expect(!parsed.json),
        else => return error.UnexpectedCommand,
    }
}

test "parse version json" {
    const args = [_][]const u8{ "version", "--json" };
    const cmd = parse(&args);
    switch (cmd) {
        .version_cmd => |parsed| try std.testing.expect(parsed.json),
        else => return error.UnexpectedCommand,
    }
}

test "parse empty" {
    const cmd = parse(&[_][]const u8{});
    try std.testing.expect(cmd == .help);
}
