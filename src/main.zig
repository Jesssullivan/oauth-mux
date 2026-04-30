const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli.zig");
const config = @import("config.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const shell = @import("shell.zig");
const types = @import("types.zig");
const pipeline = @import("pipeline.zig");
const health_mod = @import("health.zig");
const provider = @import("provider.zig");
const provider_schema = @import("provider_schema.zig");
const daemon = @import("daemon.zig");

pub fn main() !void {
    log.init();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const all_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, all_args);

    const args = if (all_args.len > 1) all_args[1..] else &[_][]const u8{};
    const cmd = cli.parse(args);

    const stdout = std.io.getStdOut().writer();

    switch (cmd) {
        .version_cmd => try stdout.print("oauth-mux {s}\n", .{cli.version}),
        .help => try cli.printUsage(stdout),
        .codex_help => try cli.printCodexUsage(stdout),

        .config_path => {
            const path = try paths.configFilePath(allocator);
            defer allocator.free(path);
            try stdout.print("{s}\n", .{path});
        },

        .config_validate => {
            const parsed = config.load(allocator) catch |e| {
                log.err("config: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.config_error.int());
            };
            defer parsed.deinit();
            config.validate(parsed.value, stdout) catch |e| {
                log.err("config: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.config_error.int());
            };
            try stdout.writeAll("config: valid\n");
        },

        .status => |status_args| {
            try runStatus(allocator, stdout, status_args);
        },

        .env => |env_args| {
            runEnv(allocator, stdout, env_args) catch |e| {
                log.err("env: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .probe => |probe_args| {
            runProbe(allocator, stdout, probe_args) catch |e| {
                log.err("probe: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .doctor => |doctor_args| {
            try runDoctor(allocator, stdout, doctor_args);
        },

        .report => |report_args| {
            try runReport(allocator, stdout, report_args);
        },

        .providers => |providers_args| {
            try runProviders(allocator, stdout, providers_args);
        },

        .exec => |exec_args| {
            runExec(allocator, exec_args) catch |e| {
                log.err("exec: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .init => |init_args| {
            try runInit(allocator, stdout, init_args);
        },

        .codex => |codex_args| {
            runCodex(allocator, stdout, codex_args) catch |e| {
                log.err("codex: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .health => |health_args| {
            try runHealth(allocator, stdout, health_args);
        },

        .discover => |discover_args| {
            try runDiscover(allocator, stdout, discover_args);
        },

        .repair_plan => |repair_args| {
            runRepairPlan(allocator, stdout, repair_args) catch |e| {
                log.err("repair-plan: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .completions => |comp_args| {
            try cli.printCompletions(stdout, comp_args.shell);
        },

        .daemon_run => {
            daemon.run(allocator) catch |e| {
                log.err("daemon: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },
        .daemon_start => {
            daemon.start(allocator) catch |e| {
                log.err("daemon: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },
        .daemon_stop => {
            daemon.stop(allocator) catch |e| {
                log.err("daemon: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },
        .daemon_status => {
            try daemon.status(allocator, stdout);
        },
    }
}

fn exitCodeFromPipelineError(e: anyerror) u8 {
    return switch (e) {
        error.ConfigNotFound, error.ConfigParseError, error.ConfigValidationError => types.ExitCode.config_error.int(),
        error.AllAccountsExhausted => types.ExitCode.all_accounts_exhausted.int(),
        error.SecretReadFailed, error.SecretDecryptFailed => types.ExitCode.secret_read_failed.int(),
        error.TokenRefreshFailed => types.ExitCode.token_refresh_failed.int(),
        error.NetworkError => types.ExitCode.network_error.int(),
        else => types.ExitCode.general_error.int(),
    };
}

fn runStatus(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.StatusArgs) !void {
    const parsed = config.load(allocator) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"error\":\"config not found\"}\n");
        } else {
            log.err("config: {s}", .{@errorName(e)});
        }
        return;
    };
    defer parsed.deinit();
    const cfg = parsed.value;

    if (args.json) {
        try writer.writeAll("{\n");
        try writer.print("  \"version\": \"{s}\",\n", .{cli.version});
        try writer.writeAll("  \"providers\": {\n");
        var first = true;
        var it = cfg.providers.map.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeAll(",\n");
            first = false;
            try writer.print("    \"{s}\": {{\"kind\": \"{s}\", \"accounts\": {d}}}", .{
                entry.key_ptr.*,
                entry.value_ptr.kind,
                entry.value_ptr.accounts.map.count(),
            });
        }
        try writer.writeAll("\n  }\n}\n");
    } else {
        try writer.print("oauth-mux v{s}\n\n", .{cli.version});
        var it = cfg.providers.map.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const prov = entry.value_ptr.*;
            try writer.print("  {s} ({s})\n", .{ name, prov.kind });
            var acct_it = prov.accounts.map.iterator();
            while (acct_it.next()) |acct_entry| {
                try writer.print("    {s}  priority={d}  secret={s}\n", .{
                    acct_entry.key_ptr.*,
                    acct_entry.value_ptr.priority,
                    acct_entry.value_ptr.secret.backend,
                });
            }
        }
    }
}

fn runDiscover(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.DiscoverArgs) !void {
    const config_path = try paths.configFilePath(allocator);
    defer allocator.free(config_path);
    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);

    const parsed = config.load(allocator) catch {
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"configured\":false,\"config_path\":");
            try std.json.stringify(config_path, .{}, writer);
            try writer.writeAll(",\"state_dir\":");
            try std.json.stringify(state_dir, .{}, writer);
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux init");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux init --codex-max");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux doctor");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux providers list");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux report --redacted");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux discover\n\n");
            try writer.print("  config: missing at {s}\n", .{config_path});
            try writer.print("  state:  {s}\n\n", .{state_dir});
            try writer.writeAll("  next:\n");
            try writer.writeAll("    oauth-mux init\n");
            try writer.writeAll("    oauth-mux init --codex-max\n");
            try writer.writeAll("    oauth-mux doctor\n");
            try writer.writeAll("    oauth-mux providers list\n");
            try writer.writeAll("    oauth-mux report --redacted\n");
            try writer.writeAll("    oauth-mux config validate\n");
        }
        return;
    };
    defer parsed.deinit();

    if (args.json) {
        try writeDiscoverJson(writer, parsed.value, config_path, state_dir);
    } else {
        try writeDiscoverText(writer, parsed.value, config_path, state_dir);
    }
}

fn writeDiscoverText(writer: anytype, cfg: config.Config, config_path: []const u8, state_dir: []const u8) !void {
    const codex_configured = codexConfigured(cfg);
    const codex_max_configured = codexMaxShapeConfigured(cfg);

    try writer.writeAll("oauth-mux discover\n\n");
    try writer.print("  config: {s}\n", .{config_path});
    try writer.print("  state:  {s}\n\n", .{state_dir});

    try writer.writeAll("  providers:\n");
    if (cfg.providers.map.count() == 0) {
        try writer.writeAll("    none configured\n");
    } else {
        var provider_it = cfg.providers.map.iterator();
        while (provider_it.next()) |entry| {
            const provider_name = entry.key_ptr.*;
            const prov = entry.value_ptr.*;
            try writer.print("    {s} ({s})\n", .{ provider_name, prov.kind });
            var account_it = prov.accounts.map.iterator();
            while (account_it.next()) |acct_entry| {
                const account_name = acct_entry.key_ptr.*;
                const account = acct_entry.value_ptr.*;
                try writer.print("      {s} priority={d} secret={s}", .{
                    account_name,
                    account.priority,
                    account.secret.backend,
                });
                if (account.config_dir != null) try writer.writeAll(" config_dir=yes");
                if (account.tags) |tags| {
                    try writer.writeAll(" tags=");
                    for (tags, 0..) |tag, idx| {
                        if (idx > 0) try writer.writeByte(',');
                        try writer.writeAll(tag);
                    }
                }
                try writer.writeByte('\n');
            }
        }
    }

    try writer.writeAll("\n  profiles:\n");
    if (cfg.profiles.map.count() == 0) {
        try writer.writeAll("    none configured\n");
    } else {
        var profile_it = cfg.profiles.map.iterator();
        while (profile_it.next()) |entry| {
            const profile_name = entry.key_ptr.*;
            const profile = entry.value_ptr.*;
            try writer.print("    {s}", .{profile_name});
            if (profile.strategy) |strategy| try writer.print(" strategy={s}", .{strategy});
            try writer.writeByte('\n');
            for (profile.providers) |provider_ref| {
                try writer.print("      {s}\n", .{provider_ref});
            }
        }
    }

    if (codex_configured) {
        try writer.writeAll("\n  codex:\n");
        try writer.print("    codex-max shape: {s}\n", .{if (codex_max_configured) "configured" else "missing"});
        if (!codex_max_configured) {
            try writer.writeAll("    next: oauth-mux codex config-candidate\n");
        }
    }

    try writer.writeAll("\n  agent-safe commands:\n");
    try writer.writeAll("    oauth-mux config validate\n");
    try writer.writeAll("    oauth-mux doctor --json\n");
    try writer.writeAll("    oauth-mux report --redacted --json\n");
    try writer.writeAll("    oauth-mux providers list --json\n");
    try writer.writeAll("    oauth-mux status --json\n");
    try writer.writeAll("    oauth-mux health --json\n");
    try writer.writeAll("    oauth-mux probe --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux repair-plan --profile <profile> --capability <capability> --json\n");
    if (codex_configured and !codex_max_configured) {
        try writer.writeAll("    oauth-mux codex config-candidate --json\n");
    }
    try writer.writeAll("    oauth-mux env --profile <profile> --capability <capability> --shell <shell>\n");
    try writer.writeAll("    oauth-mux exec --profile <profile> --capability <capability> -- <command>\n");
}

fn writeDiscoverJson(writer: anytype, cfg: config.Config, config_path: []const u8, state_dir: []const u8) !void {
    const codex_configured = codexConfigured(cfg);
    const codex_max_configured = codexMaxShapeConfigured(cfg);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"configured\":true,\"config_path\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"state_dir\":");
    try std.json.stringify(state_dir, .{}, writer);
    try writer.writeAll(",\"codex_configured\":");
    try writer.writeAll(if (codex_configured) "true" else "false");
    try writer.writeAll(",\"codex_max_configured\":");
    try writer.writeAll(if (codex_max_configured) "true" else "false");
    try writer.writeAll(",\"providers\":[");

    var provider_first = true;
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!provider_first) try writer.writeByte(',');
        provider_first = false;
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        try writer.writeAll("{\"name\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"kind\":");
        try std.json.stringify(prov.kind, .{}, writer);
        try writer.writeAll(",\"config_dir_env\":");
        if (prov.config_dir_env) |config_dir_env| {
            try std.json.stringify(config_dir_env, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"accounts\":[");
        var account_first = true;
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            if (!account_first) try writer.writeByte(',');
            account_first = false;
            const account_name = acct_entry.key_ptr.*;
            const account = acct_entry.value_ptr.*;
            try writer.writeAll("{\"name\":");
            try std.json.stringify(account_name, .{}, writer);
            try writer.print(",\"priority\":{d},\"secret_backend\":", .{account.priority});
            try std.json.stringify(account.secret.backend, .{}, writer);
            try writer.writeAll(",\"config_dir_set\":");
            try writer.writeAll(if (account.config_dir != null) "true" else "false");
            try writer.writeAll(",\"tags\":[");
            if (account.tags) |tags| {
                for (tags, 0..) |tag, idx| {
                    if (idx > 0) try writer.writeByte(',');
                    try std.json.stringify(tag, .{}, writer);
                }
            }
            try writer.writeAll("]}");
        }
        try writer.writeAll("]}");
    }

    try writer.writeAll("],\"profiles\":[");
    var profile_first = true;
    var profile_it = cfg.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        if (!profile_first) try writer.writeByte(',');
        profile_first = false;
        const profile_name = entry.key_ptr.*;
        const profile = entry.value_ptr.*;
        try writer.writeAll("{\"name\":");
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeAll(",\"strategy\":");
        if (profile.strategy) |strategy| {
            try std.json.stringify(strategy, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.print(",\"affinity_ttl_minutes\":{d},\"providers\":[", .{profile.affinity_ttl_minutes});
        for (profile.providers, 0..) |provider_ref, idx| {
            if (idx > 0) try writer.writeByte(',');
            try std.json.stringify(provider_ref, .{}, writer);
        }
        try writer.writeAll("]}");
    }

    try writer.writeAll("],\"agent_safe_commands\":[");
    var command_first = true;
    const commands = [_][]const u8{
        "oauth-mux config validate",
        "oauth-mux doctor --json",
        "oauth-mux report --redacted --json",
        "oauth-mux providers list --json",
        "oauth-mux status --json",
        "oauth-mux health --json",
        "oauth-mux probe --profile <profile> --capability <capability> --json",
        "oauth-mux repair-plan --profile <profile> --capability <capability> --json",
        "oauth-mux env --profile <profile> --capability <capability> --shell <shell>",
        "oauth-mux exec --profile <profile> --capability <capability> -- <command>",
    };
    for (commands) |command| {
        try writeDoctorCommandJson(writer, &command_first, command);
    }
    if (codex_configured and !codex_max_configured) {
        try writeDoctorCommandJson(writer, &command_first, "oauth-mux codex config-candidate --json");
    }
    try writer.writeAll("]}\n");
}

fn writeCommandJson(writer: anytype, command: []const u8) !void {
    try std.json.stringify(command, .{}, writer);
}

const RepairPlanRoute = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

const RepairCommandKind = enum {
    none,
    probe,
    codex_login_device,
};

const RepairAction = struct {
    kind: []const u8,
    severity: []const u8,
    message: []const u8,
    command: RepairCommandKind = .none,
    interactive: bool = false,
    mutating: bool = false,
    retry_after_s: ?u32 = null,
    wait_until: ?i64 = null,
};

fn runRepairPlan(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.RepairPlanArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, args);
    defer routes.deinit();

    if (args.json) {
        try writeRepairPlanJson(writer, allocator, parsed.value, &store, routes.items, args);
    } else {
        try writeRepairPlanText(writer, allocator, parsed.value, &store, routes.items, args);
    }
}

fn collectRepairPlanRoutes(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    args: cli.Command.RepairPlanArgs,
) !std.ArrayList(RepairPlanRoute) {
    var routes = std.ArrayList(RepairPlanRoute).init(allocator);
    errdefer routes.deinit();

    if (args.profile) |profile_name| {
        const profile = cfg.profiles.map.get(profile_name) orelse return error.ConfigValidationError;
        for (profile.providers) |provider_ref| {
            const parsed = parseRepairRouteSpec(provider_ref) orelse return error.ConfigValidationError;
            try routes.append(.{
                .provider = parsed.provider,
                .account = parsed.account,
                .capability = args.capability orelse parsed.capability,
            });
        }
        return routes;
    }

    if (args.provider) |provider_name| {
        const prov = cfg.providers.map.get(provider_name) orelse return error.ConfigValidationError;
        if (args.account) |account_name| {
            if (prov.accounts.map.get(account_name) == null) return error.ConfigValidationError;
            try routes.append(.{
                .provider = provider_name,
                .account = account_name,
                .capability = args.capability,
            });
            return routes;
        }

        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |entry| {
            try routes.append(.{
                .provider = provider_name,
                .account = entry.key_ptr.*,
                .capability = args.capability,
            });
        }
        return routes;
    }

    if (args.account != null) return error.ConfigValidationError;

    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |provider_entry| {
        const provider_name = provider_entry.key_ptr.*;
        var account_it = provider_entry.value_ptr.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            try routes.append(.{
                .provider = provider_name,
                .account = account_entry.key_ptr.*,
                .capability = args.capability,
            });
        }
    }
    return routes;
}

fn parseRepairRouteSpec(spec: []const u8) ?RepairPlanRoute {
    const colon = std.mem.indexOf(u8, spec, ":") orelse return null;
    if (colon == 0 or colon + 1 >= spec.len) return null;

    const rest = spec[colon + 1 ..];
    if (std.mem.indexOf(u8, rest, "#")) |hash| {
        if (hash == 0 or hash + 1 >= rest.len) return null;
        return .{
            .provider = spec[0..colon],
            .account = rest[0..hash],
            .capability = rest[hash + 1 ..],
        };
    }

    return .{
        .provider = spec[0..colon],
        .account = rest,
    };
}

fn writeRepairPlanText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    routes: []const RepairPlanRoute,
    args: cli.Command.RepairPlanArgs,
) !void {
    try writer.writeAll("oauth-mux repair-plan\n\n");
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (routes.len == 0) {
        try writer.writeAll("  no matching configured accounts\n");
        return;
    }

    for (routes) |route| {
        const def = config.resolveProviderDefinition(cfg, route.provider);
        const runtime = try providerRuntimeReadiness(allocator, def, route.capability);
        const health = routeHealth(store, route);
        const budget = routeProbeBudget(def, route.capability);
        const action = repairActionFor(route, def, runtime, health, budget);

        try writer.print("  {s}:{s}", .{ route.provider, route.account });
        if (route.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.print(" runtime={s} repair={s}", .{
            runtimeReadinessSummary(runtime),
            @tagName(def.repair.owner),
        });
        if (budget) |probe_budget| try writer.print(" probe_budget={s}", .{@tagName(probe_budget)});
        try writer.writeAll(" liveness=");
        if (health) |h| {
            try health_mod.writeLivenessSummary(writer, h.liveness);
        } else {
            try writer.writeAll("unrecorded");
        }
        try writer.print("\n    action={s} severity={s} {s}\n", .{ action.kind, action.severity, action.message });
        if (try repairCommandAlloc(allocator, action.command, route)) |command| {
            defer allocator.free(command);
            try writer.print("    command: {s}\n", .{command});
        }
    }
}

fn writeRepairPlanJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    routes: []const RepairPlanRoute,
    args: cli.Command.RepairPlanArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"profile\":");
    if (args.profile) |profile_name| {
        try std.json.stringify(profile_name, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"routes\":[");
    for (routes, 0..) |route, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeRepairPlanRouteJson(writer, allocator, cfg, store, route);
    }
    try writer.writeAll("]}\n");
}

fn writeRepairPlanRouteJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    route: RepairPlanRoute,
) !void {
    const def = config.resolveProviderDefinition(cfg, route.provider);
    const runtime = try providerRuntimeReadiness(allocator, def, route.capability);
    const health = routeHealth(store, route);
    const budget = routeProbeBudget(def, route.capability);
    const action = repairActionFor(route, def, runtime, health, budget);

    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (route.capability) |capability| {
        try std.json.stringify(capability, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"extension_mode\":");
    try std.json.stringify(@tagName(def.extension_mode), .{}, writer);
    try writer.writeAll(",\"repair_owner\":");
    try std.json.stringify(@tagName(def.repair.owner), .{}, writer);
    try writer.writeAll(",\"probe_budget\":");
    if (budget) |probe_budget| {
        try std.json.stringify(@tagName(probe_budget), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessJson(writer, runtime);
    try writer.writeAll(",\"liveness\":");
    if (health) |h| {
        try writeLivenessJson(writer, h.liveness);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"last_probe\":");
    if (health) |h| {
        try writeProbeEvidenceJson(writer, h);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"action\":");
    try writeRepairActionJson(writer, allocator, action, route);
    try writer.writeByte('}');
}

fn writeRepairActionJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    action: RepairAction,
    route: RepairPlanRoute,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try std.json.stringify(action.kind, .{}, writer);
    try writer.writeAll(",\"severity\":");
    try std.json.stringify(action.severity, .{}, writer);
    try writer.writeAll(",\"message\":");
    try std.json.stringify(action.message, .{}, writer);
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (action.interactive) "true" else "false");
    try writer.writeAll(",\"mutating\":");
    try writer.writeAll(if (action.mutating) "true" else "false");
    try writer.writeAll(",\"retry_after_s\":");
    if (action.retry_after_s) |retry_after| {
        try writer.print("{d}", .{retry_after});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"wait_until\":");
    if (action.wait_until) |wait_until| {
        try writer.print("{d}", .{wait_until});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"command\":");
    if (try repairCommandAlloc(allocator, action.command, route)) |command| {
        defer allocator.free(command);
        try std.json.stringify(command, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn routeHealth(store: *health_mod.HealthStore, route: RepairPlanRoute) ?health_mod.AccountHealth {
    const account_key = health_mod.accountKey(route.provider, route.account);
    const account_health = store.accounts.get(account_key.slice());
    if (account_health) |health| {
        if (accountLivenessBlocksRoute(health.liveness)) return health;
    }

    if (route.capability) |capability| {
        const capability_key = health_mod.capabilityKey(route.provider, route.account, capability);
        if (store.accounts.get(capability_key.slice())) |health| return health;
    }

    return account_health;
}

fn routeProbeBudget(def: provider_schema.ProviderDefinition, capability: ?[]const u8) ?types.ActionBudget {
    const capability_name = capability orelse return null;
    const plan = provider_schema.probePlanForCapability(def, capability_name) orelse return null;
    return plan.budget;
}

fn repairActionFor(
    route: RepairPlanRoute,
    def: provider_schema.ProviderDefinition,
    runtime: types.RuntimeReadiness,
    health: ?health_mod.AccountHealth,
    budget: ?types.ActionBudget,
) RepairAction {
    switch (runtime) {
        .ready => {},
        .missing_binary => return .{
            .kind = "fix_runtime",
            .severity = "error",
            .message = "required upstream CLI is missing",
        },
        .permission_denied, .unwritable_store, .session_unavailable, .sandbox_blocked => return .{
            .kind = "fix_runtime",
            .severity = "error",
            .message = "runtime is not ready; fix local permissions, store, session, or sandbox access",
        },
        .needs_reauth => return reauthAction(route, def),
        .repair_in_progress => return .{
            .kind = "wait_for_repair",
            .severity = "info",
            .message = "repair is already in progress",
        },
    }

    const current = health orelse return .{
        .kind = "probe_needed",
        .severity = if (budget == .spend_provider) "warning" else "info",
        .message = if (budget == .spend_provider)
            "no health evidence recorded; explicit live probe may spend provider quota"
        else
            "no health evidence recorded; run a probe to classify this route",
        .command = .probe,
    };

    return switch (current.liveness) {
        .live => |live| switch (live.availability) {
            .available => .{
                .kind = "none",
                .severity = "ok",
                .message = "route is selectable",
            },
            .rate_limited => |rl| .{
                .kind = "wait_and_retry",
                .severity = "warning",
                .message = "short rate-limit window is active; try another route until retry",
                .retry_after_s = rl.retry_after_s,
            },
            .quota_exhausted => |quota| .{
                .kind = "wait_for_quota",
                .severity = "warning",
                .message = "quota window is exhausted; use another account until reset",
                .wait_until = quota.window_resets_at,
            },
            .cooldown => |cooldown| .{
                .kind = "wait_for_cooldown",
                .severity = "warning",
                .message = "local cooldown is active",
                .wait_until = cooldown.until,
            },
        },
        .degraded => |degraded| degradedAction(route, def, degraded.reason),
        .dead => reauthAction(route, def),
    };
}

fn degradedAction(route: RepairPlanRoute, def: provider_schema.ProviderDefinition, reason: types.DegradedReason) RepairAction {
    return switch (reason) {
        .step_up_required, .pending_verification, .terms_required => reauthAction(route, def),
        .scope_insufficient => .{
            .kind = "scope_or_permission",
            .severity = "warning",
            .message = "credential is valid but lacks required scope or route permission",
            .command = .probe,
        },
        .tier_insufficient, .subscription_paused => .{
            .kind = "provider_plan",
            .severity = "warning",
            .message = "account is authenticated but not operable for this capability",
        },
        .provider_degraded => .{
            .kind = "try_next_provider",
            .severity = "warning",
            .message = "provider appears degraded; try another provider route",
        },
        .schema_invalid, .unknown_4xx => .{
            .kind = "inspect_provider_schema",
            .severity = "warning",
            .message = "provider returned a route/schema error; inspect provider definition and probe evidence",
            .command = .probe,
        },
    };
}

fn reauthAction(route: RepairPlanRoute, def: provider_schema.ProviderDefinition) RepairAction {
    return switch (def.repair.owner) {
        .upstream_cli_login => .{
            .kind = "reauth",
            .severity = "error",
            .message = "reauth is owned by the upstream CLI",
            .command = if (std.mem.eql(u8, route.provider, "codex")) .codex_login_device else .none,
            .interactive = true,
            .mutating = true,
        },
        .oauth_mux_refresh => .{
            .kind = "refresh",
            .severity = "warning",
            .message = "oauth-mux owns refresh for this provider; automatic repair is not enabled by repair-plan",
            .mutating = true,
        },
        .external_secret_owner => .{
            .kind = "external_secret_rotation",
            .severity = "error",
            .message = "credential repair is owned by an external secret backend",
        },
        .manual_only => .{
            .kind = "manual_repair",
            .severity = "error",
            .message = "manual operator repair is required for this provider",
        },
    };
}

fn repairCommandAlloc(
    allocator: std.mem.Allocator,
    command: RepairCommandKind,
    route: RepairPlanRoute,
) !?[]const u8 {
    return switch (command) {
        .none => null,
        .probe => if (route.capability) |capability|
            try std.fmt.allocPrint(allocator, "oauth-mux probe --provider {s} --account {s} --capability {s} --json", .{ route.provider, route.account, capability })
        else
            try std.fmt.allocPrint(allocator, "oauth-mux probe --provider {s} --account {s} --json", .{ route.provider, route.account }),
        .codex_login_device => try std.fmt.allocPrint(allocator, "oauth-mux codex login-device {s}", .{route.account}),
    };
}

const DoctorStats = struct {
    configured: bool = false,
    config_valid: bool = false,
    config_error: ?[]const u8 = null,
    provider_count: usize = 0,
    account_count: usize = 0,
    profile_count: usize = 0,
    strategy_count: usize = 0,
    codex_configured: bool = false,
    codex_max_configured: bool = false,
    health_file_exists: bool = false,
    health_entries: usize = 0,

    fn ok(self: DoctorStats) bool {
        return self.configured and self.config_valid and self.provider_count > 0 and self.account_count > 0;
    }
};

fn runDoctor(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.DoctorArgs) !void {
    const config_path = try paths.configFilePath(allocator);
    defer allocator.free(config_path);
    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const health_path = try paths.healthFilePath(allocator);
    defer allocator.free(health_path);

    var stats = DoctorStats{
        .health_file_exists = fileExistsAbsolute(health_path),
    };

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();

    if (config.load(allocator)) |parsed| {
        defer parsed.deinit();
        stats.configured = true;
        stats.provider_count = parsed.value.providers.map.count();
        stats.account_count = countConfiguredAccounts(parsed.value);
        stats.profile_count = parsed.value.profiles.map.count();
        stats.strategy_count = parsed.value.strategies.map.count();
        stats.codex_configured = codexConfigured(parsed.value);
        stats.codex_max_configured = codexMaxShapeConfigured(parsed.value);

        config.validate(parsed.value, validation_messages.writer()) catch |e| {
            stats.config_error = @errorName(e);
        };
        stats.config_valid = stats.config_error == null;
    } else |e| {
        stats.config_error = @errorName(e);
    }

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();
    stats.health_entries = store.accounts.count();

    if (args.json) {
        try writeDoctorJson(writer, stats, config_path, state_dir, health_path, validation_messages.items);
    } else {
        try writeDoctorText(writer, stats, config_path, state_dir, health_path, validation_messages.items);
    }
}

fn writeDoctorText(
    writer: anytype,
    stats: DoctorStats,
    config_path: []const u8,
    state_dir: []const u8,
    health_path: []const u8,
    validation_messages: []const u8,
) !void {
    try writer.writeAll("oauth-mux doctor\n\n");
    try writer.print("  config: {s}\n", .{config_path});
    if (!stats.configured) {
        try writer.print("    status: missing ({s})\n", .{stats.config_error orelse "not_found"});
    } else if (!stats.config_valid) {
        try writer.print("    status: invalid ({s})\n", .{stats.config_error orelse "validation_failed"});
    } else {
        try writer.writeAll("    status: valid\n");
    }
    try writer.print("    providers={d} accounts={d} profiles={d} strategies={d}\n", .{
        stats.provider_count,
        stats.account_count,
        stats.profile_count,
        stats.strategy_count,
    });
    try writer.print("  state:  {s}\n", .{state_dir});
    try writer.print("  health: {s} ({s}, entries={d})\n", .{
        health_path,
        if (stats.health_file_exists) "present" else "not recorded",
        stats.health_entries,
    });
    try writer.print("  readiness: {s}\n", .{if (stats.ok()) "ready" else "action_needed"});

    if (validation_messages.len != 0) {
        try writer.writeAll("\n  validation:\n");
        var lines = std.mem.splitScalar(u8, validation_messages, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try writer.print("    {s}\n", .{line});
        }
    }

    try writer.writeAll("\n  next:\n");
    try writeDoctorNextCommandsText(writer, stats);
}

fn writeDoctorJson(
    writer: anytype,
    stats: DoctorStats,
    config_path: []const u8,
    state_dir: []const u8,
    health_path: []const u8,
    validation_messages: []const u8,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (stats.ok()) "true" else "false");
    try writer.writeAll(",\"configured\":");
    try writer.writeAll(if (stats.configured) "true" else "false");
    try writer.writeAll(",\"config_path\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"state_dir\":");
    try std.json.stringify(state_dir, .{}, writer);
    try writer.writeAll(",\"health_path\":");
    try std.json.stringify(health_path, .{}, writer);
    try writer.writeAll(",\"config_valid\":");
    try writer.writeAll(if (stats.config_valid) "true" else "false");
    try writer.writeAll(",\"config_error\":");
    if (stats.config_error) |err| {
        try std.json.stringify(err, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.print(
        ",\"providers\":{d},\"accounts\":{d},\"profiles\":{d},\"strategies\":{d},\"health_file_exists\":{s},\"health_entries\":{d},\"codex_configured\":{s},\"codex_max_configured\":{s}",
        .{
            stats.provider_count,
            stats.account_count,
            stats.profile_count,
            stats.strategy_count,
            if (stats.health_file_exists) "true" else "false",
            stats.health_entries,
            if (stats.codex_configured) "true" else "false",
            if (stats.codex_max_configured) "true" else "false",
        },
    );
    try writer.writeAll(",\"checks\":[");
    try writeDoctorChecksJson(writer, stats, validation_messages);
    try writer.writeAll("],\"next_commands\":[");
    try writeDoctorNextCommandsJson(writer, stats);
    try writer.writeAll("]}\n");
}

fn writeDoctorChecksJson(writer: anytype, stats: DoctorStats, validation_messages: []const u8) !void {
    var first = true;
    try writeDoctorCheckJson(writer, &first, "config_found", stats.configured, if (stats.configured) "ok" else "error", if (stats.configured) "config file found" else "config file missing");
    const valid_message = if (validation_messages.len == 0)
        if (stats.config_valid) "config validates" else "config could not be loaded"
    else
        validation_messages;
    try writeDoctorCheckJson(writer, &first, "config_valid", stats.config_valid, if (stats.config_valid) "ok" else "error", valid_message);
    try writeDoctorCheckJson(writer, &first, "accounts_configured", stats.account_count > 0, if (stats.account_count > 0) "ok" else "error", if (stats.account_count > 0) "one or more accounts configured" else "no muxable accounts configured");
    try writeDoctorCheckJson(writer, &first, "profiles_configured", stats.profile_count > 0, if (stats.profile_count > 0) "ok" else "warning", if (stats.profile_count > 0) "one or more profiles configured" else "no profiles configured");
    if (stats.codex_configured) {
        try writeDoctorCheckJson(
            writer,
            &first,
            "codex_max_configured",
            stats.codex_max_configured,
            if (stats.codex_max_configured) "ok" else "warning",
            if (stats.codex_max_configured)
                "three-account Codex Max mux shape configured"
            else
                "Codex is configured but the three-account Codex Max mux shape is missing; run oauth-mux codex config-candidate",
        );
    }
    try writeDoctorCheckJson(writer, &first, "health_recorded", stats.health_entries > 0, if (stats.health_entries > 0) "ok" else "info", if (stats.health_entries > 0) "health state recorded" else "no health state recorded yet");
}

fn writeDoctorCheckJson(
    writer: anytype,
    first: *bool,
    name: []const u8,
    ok: bool,
    severity: []const u8,
    message: []const u8,
) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writer.writeAll("{\"name\":");
    try std.json.stringify(name, .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"severity\":");
    try std.json.stringify(severity, .{}, writer);
    try writer.writeAll(",\"message\":");
    try std.json.stringify(message, .{}, writer);
    try writer.writeByte('}');
}

fn writeDoctorNextCommandsText(writer: anytype, stats: DoctorStats) !void {
    if (!stats.configured) {
        try writer.writeAll("    oauth-mux init\n");
        try writer.writeAll("    oauth-mux init --codex-max\n");
        try writer.writeAll("    oauth-mux doctor\n");
        return;
    }

    if (!stats.config_valid) {
        try writer.writeAll("    oauth-mux config validate\n");
        try writer.writeAll("    oauth-mux doctor\n");
        return;
    }

    try writer.writeAll("    oauth-mux discover --json\n");
    try writer.writeAll("    oauth-mux report --redacted --json\n");
    try writer.writeAll("    oauth-mux providers list --json\n");
    try writer.writeAll("    oauth-mux status --json\n");
    try writer.writeAll("    oauth-mux health --json\n");
    if (stats.codex_configured) {
        if (!stats.codex_max_configured) {
            try writer.writeAll("    oauth-mux codex config-candidate\n");
        }
        try writer.writeAll("    oauth-mux setup codex\n");
        try writer.writeAll("    oauth-mux codex canary\n");
        try writer.writeAll("    oauth-mux codex canary --live\n");
    }
}

fn writeDoctorNextCommandsJson(writer: anytype, stats: DoctorStats) !void {
    var first = true;
    if (!stats.configured) {
        try writeDoctorCommandJson(writer, &first, "oauth-mux init");
        try writeDoctorCommandJson(writer, &first, "oauth-mux init --codex-max");
        try writeDoctorCommandJson(writer, &first, "oauth-mux doctor");
        return;
    }

    if (!stats.config_valid) {
        try writeDoctorCommandJson(writer, &first, "oauth-mux config validate");
        try writeDoctorCommandJson(writer, &first, "oauth-mux doctor");
        return;
    }

    try writeDoctorCommandJson(writer, &first, "oauth-mux discover --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux report --redacted --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux providers list --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux status --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux health --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux repair-plan --json");
    if (stats.codex_configured) {
        if (!stats.codex_max_configured) {
            try writeDoctorCommandJson(writer, &first, "oauth-mux codex config-candidate --json");
        }
        try writeDoctorCommandJson(writer, &first, "oauth-mux setup codex");
        try writeDoctorCommandJson(writer, &first, "oauth-mux codex canary");
        try writeDoctorCommandJson(writer, &first, "oauth-mux codex canary --live");
    }
}

fn writeDoctorCommandJson(writer: anytype, first: *bool, command: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writeCommandJson(writer, command);
}

fn codexConfigured(cfg: config.Config) bool {
    return cfg.providers.map.get("codex") != null;
}

fn codexMaxShapeConfigured(cfg: config.Config) bool {
    const prov = cfg.providers.map.get("codex") orelse return false;
    if (!std.mem.eql(u8, prov.kind, "codex")) return false;

    const expected_accounts = [_][]const u8{ "max-1", "max-2", "max-3" };
    for (expected_accounts) |account| {
        if (prov.accounts.map.get(account) == null) return false;
    }

    return profileContainsProviderRef(cfg, "codex-max", "codex:max-1#codex-max") and
        profileContainsProviderRef(cfg, "codex-max", "codex:max-2#codex-max") and
        profileContainsProviderRef(cfg, "codex-max", "codex:max-3#codex-max") and
        profileContainsProviderRef(cfg, "codex-mini", "codex:max-1#codex-mini") and
        profileContainsProviderRef(cfg, "codex-mini", "codex:max-2#codex-mini") and
        profileContainsProviderRef(cfg, "codex-mini", "codex:max-3#codex-mini");
}

fn profileContainsProviderRef(cfg: config.Config, profile_name: []const u8, provider_ref: []const u8) bool {
    const profile = cfg.profiles.map.get(profile_name) orelse return false;
    for (profile.providers) |candidate| {
        if (std.mem.eql(u8, candidate, provider_ref)) return true;
    }
    return false;
}

fn runReport(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.ReportArgs) !void {
    const config_path = try paths.configFilePath(allocator);
    defer allocator.free(config_path);
    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const health_path = try paths.healthFilePath(allocator);
    defer allocator.free(health_path);

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    if (config.load(allocator)) |parsed| {
        defer parsed.deinit();
        var config_error: ?[]const u8 = null;
        config.validate(parsed.value, validation_messages.writer()) catch |e| {
            config_error = @errorName(e);
        };
        const config_valid = config_error == null;
        if (args.json) {
            try writeReportJson(writer, allocator, args, config_path, state_dir, health_path, parsed.value, true, config_valid, config_error, validation_messages.items, &store);
        } else {
            try writeReportText(writer, allocator, args, config_path, state_dir, health_path, parsed.value, true, config_valid, config_error, validation_messages.items, &store);
        }
    } else |e| {
        const config_error = @errorName(e);
        if (args.json) {
            try writeReportJson(writer, allocator, args, config_path, state_dir, health_path, null, false, false, config_error, validation_messages.items, &store);
        } else {
            try writeReportText(writer, allocator, args, config_path, state_dir, health_path, null, false, false, config_error, validation_messages.items, &store);
        }
    }
}

fn writeReportText(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.ReportArgs,
    config_path: []const u8,
    state_dir: []const u8,
    health_path: []const u8,
    cfg: ?config.Config,
    configured: bool,
    config_valid: bool,
    config_error: ?[]const u8,
    validation_messages: []const u8,
    store: *health_mod.HealthStore,
) !void {
    try writer.writeAll("oauth-mux report\n\n");
    try writer.print("  version:  {s}\n", .{cli.version});
    try writer.print("  platform: {s}/{s}\n", .{ @tagName(builtin.os.tag), @tagName(builtin.cpu.arch) });
    try writer.print("  redacted: {s}\n", .{if (args.redacted) "true" else "false"});
    try writer.print("  config:   {s}\n", .{config_path});
    try writer.print("  state:    {s}\n", .{state_dir});
    try writer.print("  health:   {s}\n", .{health_path});

    try writer.writeAll("\n  config status:\n");
    if (!configured) {
        try writer.print("    missing ({s})\n", .{config_error orelse "not_found"});
    } else if (!config_valid) {
        try writer.print("    invalid ({s})\n", .{config_error orelse "validation_failed"});
    } else {
        try writer.writeAll("    valid\n");
    }

    if (cfg) |loaded| {
        try writer.print("    providers={d} accounts={d} profiles={d} strategies={d} provider_definitions={d}\n", .{
            loaded.providers.map.count(),
            countConfiguredAccounts(loaded),
            loaded.profiles.map.count(),
            loaded.strategies.map.count(),
            loaded.provider_definitions.map.count(),
        });
    }

    if (validation_messages.len != 0) {
        try writer.writeAll("\n  validation:\n");
        try writeIndentedLines(writer, validation_messages, "    ");
    }

    try writer.writeAll("\n  providers:\n");
    if (cfg) |loaded| {
        if (loaded.providers.map.count() == 0) {
            try writer.writeAll("    none configured\n");
        } else {
            var provider_it = loaded.providers.map.iterator();
            while (provider_it.next()) |entry| {
                const provider_name = entry.key_ptr.*;
                const prov = entry.value_ptr.*;
                try writer.print("    {s} kind={s} accounts={d}\n", .{ provider_name, prov.kind, prov.accounts.map.count() });
                var account_it = prov.accounts.map.iterator();
                while (account_it.next()) |acct_entry| {
                    const account_name = acct_entry.key_ptr.*;
                    const account = acct_entry.value_ptr.*;
                    try writer.print("      {s} priority={d} secret={s}", .{ account_name, account.priority, account.secret.backend });
                    if (account.config_dir != null) try writer.writeAll(" config_dir=set");
                    if (args.include_paths) try writeAccountPathHintsText(writer, account);
                    if (account.tags) |tags| {
                        try writer.writeAll(" tags=");
                        for (tags, 0..) |tag, idx| {
                            if (idx > 0) try writer.writeByte(',');
                            try writer.writeAll(tag);
                        }
                    }
                    try writer.writeByte('\n');
                }
            }
        }
    } else {
        try writer.writeAll("    unavailable until config loads\n");
    }

    try writer.writeAll("\n  health:\n");
    if (store.accounts.count() == 0) {
        try writer.writeAll("    no health data recorded yet\n");
    } else {
        var health_it = store.accounts.iterator();
        while (health_it.next()) |entry| {
            const health = entry.value_ptr.*;
            try writer.print("    {s} score={d} circuit={s} http=", .{
                entry.key_ptr.*,
                health.score.score,
                circuitName(health.circuit),
            });
            if (health.last_http_status) |status| {
                try writer.print("{d}", .{status});
            } else {
                try writer.writeByte('-');
            }
            try writer.writeAll(" liveness=");
            try health_mod.writeLivenessSummary(writer, health.liveness);
            try writer.writeByte('\n');
        }
    }

    try writer.writeAll("\n  command availability:\n");
    try writeCommandAvailabilityText(writer, allocator);

    try writer.writeAll("\n  next:\n");
    try writer.writeAll("    oauth-mux doctor --json\n");
    try writer.writeAll("    oauth-mux providers list --json\n");
    try writer.writeAll("    oauth-mux health --json\n");
}

fn writeReportJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.ReportArgs,
    config_path: []const u8,
    state_dir: []const u8,
    health_path: []const u8,
    cfg: ?config.Config,
    configured: bool,
    config_valid: bool,
    config_error: ?[]const u8,
    validation_messages: []const u8,
    store: *health_mod.HealthStore,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"os\":");
    try std.json.stringify(@tagName(builtin.os.tag), .{}, writer);
    try writer.writeAll(",\"arch\":");
    try std.json.stringify(@tagName(builtin.cpu.arch), .{}, writer);
    try writer.writeAll(",\"redacted\":");
    try writer.writeAll(if (args.redacted) "true" else "false");
    try writer.writeAll(",\"include_paths\":");
    try writer.writeAll(if (args.include_paths) "true" else "false");
    try writer.writeAll(",\"paths\":{\"config\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"state\":");
    try std.json.stringify(state_dir, .{}, writer);
    try writer.writeAll(",\"health\":");
    try std.json.stringify(health_path, .{}, writer);
    try writer.writeAll("},\"config\":{\"configured\":");
    try writer.writeAll(if (configured) "true" else "false");
    try writer.writeAll(",\"valid\":");
    try writer.writeAll(if (config_valid) "true" else "false");
    try writer.writeAll(",\"error\":");
    if (config_error) |err| {
        try std.json.stringify(err, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    if (cfg) |loaded| {
        try writer.print(",\"providers\":{d},\"accounts\":{d},\"profiles\":{d},\"strategies\":{d},\"provider_definitions\":{d}", .{
            loaded.providers.map.count(),
            countConfiguredAccounts(loaded),
            loaded.profiles.map.count(),
            loaded.strategies.map.count(),
            loaded.provider_definitions.map.count(),
        });
    } else {
        try writer.writeAll(",\"providers\":0,\"accounts\":0,\"profiles\":0,\"strategies\":0,\"provider_definitions\":0");
    }
    try writer.writeAll(",\"validation_messages\":");
    try writeLineArrayJson(writer, validation_messages);
    try writer.writeAll("},\"providers\":");
    if (cfg) |loaded| {
        try writeConfiguredProvidersReportJson(writer, args, loaded);
    } else {
        try writer.writeAll("[]");
    }
    try writer.writeAll(",\"health\":");
    try writeHealthEntriesJson(writer, store);
    try writer.writeAll(",\"command_availability\":");
    try writeCommandAvailabilityJson(writer, allocator);
    try writer.writeAll(",\"next_commands\":[");
    try writeCommandJson(writer, "oauth-mux doctor --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux providers list --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux health --json");
    try writer.writeAll("]}\n");
}

fn runProviders(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.ProvidersArgs) !void {
    switch (args.action) {
        .list => {},
    }

    if (config.load(allocator)) |parsed| {
        defer parsed.deinit();
        if (args.json) {
            try writeProvidersListJson(writer, allocator, parsed.value, true, null);
        } else {
            try writeProvidersListText(writer, allocator, parsed.value, true, null);
        }
    } else |e| {
        if (args.json) {
            try writeProvidersListJson(writer, allocator, null, false, @errorName(e));
        } else {
            try writeProvidersListText(writer, allocator, null, false, @errorName(e));
        }
    }
}

fn writeProvidersListText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: ?config.Config,
    config_loaded: bool,
    config_error: ?[]const u8,
) !void {
    try writer.writeAll("oauth-mux providers\n\n");
    if (!config_loaded) {
        try writer.print("  config: unavailable ({s}); showing built-ins\n\n", .{config_error orelse "not_found"});
    }

    try writer.print("  {s:<12} {s:<14} {s:<20} {s:>8} {s:>5} {s:>6}\n", .{
        "Provider", "Support", "Proof", "Accounts", "Caps", "Probes",
    });
    try writer.print("  {s:-<12} {s:-<14} {s:-<20} {s:->8} {s:->5} {s:->6}\n", .{ "", "", "", "", "", "" });

    for (provider_schema.builtin_providers) |def| {
        try writeProviderListTextRow(writer, cfg, def.name, def, true);
    }

    if (cfg) |loaded| {
        var def_it = loaded.provider_definitions.map.iterator();
        while (def_it.next()) |entry| {
            const def_key = entry.key_ptr.*;
            const def = entry.value_ptr.*;
            if (isBuiltinDefinition(def_key, def.name)) continue;
            try writeProviderListTextRow(writer, cfg, def_key, def, false);
        }
    }

    try writer.writeAll("\n  support: live_proven means hosted secret-scoped QA has proved a real route.\n");
    try writer.writeAll("  proof: needs_operator_proof means the schema exists but needs live provider evidence.\n");
    _ = allocator;
}

fn writeProviderListTextRow(writer: anytype, cfg: ?config.Config, def_key: []const u8, def: provider_schema.ProviderDefinition, built_in: bool) !void {
    const accounts = configuredAccountCountForDefinition(cfg, def_key, def.name);
    try writer.print("  {s:<12} {s:<14} {s:<20} {d:>8} {d:>5} {d:>6}\n", .{
        def.name,
        supportStatus(def.name, built_in),
        proofStatus(def.name),
        accounts,
        def.capabilities.len,
        countProviderProbes(def),
    });
    try writer.print("    mode={s} repair={s}\n", .{ @tagName(def.extension_mode), @tagName(def.repair.owner) });
}

fn writeProvidersListJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: ?config.Config,
    config_loaded: bool,
    config_error: ?[]const u8,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"config_loaded\":");
    try writer.writeAll(if (config_loaded) "true" else "false");
    try writer.writeAll(",\"config_error\":");
    if (config_error) |err| {
        try std.json.stringify(err, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"providers\":[");

    var first = true;
    for (provider_schema.builtin_providers) |def| {
        try writeProviderListJsonEntry(writer, allocator, &first, cfg, def.name, def, true);
    }

    if (cfg) |loaded| {
        var def_it = loaded.provider_definitions.map.iterator();
        while (def_it.next()) |entry| {
            const def_key = entry.key_ptr.*;
            const def = entry.value_ptr.*;
            if (isBuiltinDefinition(def_key, def.name)) continue;
            try writeProviderListJsonEntry(writer, allocator, &first, cfg, def_key, def, false);
        }
    }

    try writer.writeAll("]}\n");
}

fn writeProviderListJsonEntry(
    writer: anytype,
    allocator: std.mem.Allocator,
    first: *bool,
    cfg: ?config.Config,
    def_key: []const u8,
    def: provider_schema.ProviderDefinition,
    built_in: bool,
) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;

    const accounts = configuredAccountCountForDefinition(cfg, def_key, def.name);
    try writer.writeByte('{');
    try writer.writeAll("\"definition_key\":");
    try std.json.stringify(def_key, .{}, writer);
    try writer.writeByte(',');
    try writer.writeAll("\"name\":");
    try std.json.stringify(def.name, .{}, writer);
    try writer.writeAll(",\"display_name\":");
    try std.json.stringify(providerDisplayName(def), .{}, writer);
    try writer.writeAll(",\"support_status\":");
    try std.json.stringify(supportStatus(def.name, built_in), .{}, writer);
    try writer.writeAll(",\"proof_status\":");
    try std.json.stringify(proofStatus(def.name), .{}, writer);
    try writer.writeAll(",\"extension_mode\":");
    try std.json.stringify(@tagName(def.extension_mode), .{}, writer);
    try writer.writeAll(",\"repair_owner\":");
    try std.json.stringify(@tagName(def.repair.owner), .{}, writer);
    try writer.writeAll(",\"built_in\":");
    try writer.writeAll(if (built_in) "true" else "false");
    try writer.writeAll(",\"configured\":");
    try writer.writeAll(if (accounts > 0) "true" else "false");
    try writer.print(",\"configured_accounts\":{d},\"capabilities\":{d},\"probes\":{d},\"failure_rules\":{d}", .{
        accounts,
        def.capabilities.len,
        countProviderProbes(def),
        def.failure_rules.len,
    });
    try writer.writeAll(",\"detection_binaries\":");
    try writeStringArrayJson(writer, def.detection.binary_names);
    try writer.writeAll(",\"env_markers\":");
    try writeStringArrayJson(writer, def.detection.env_markers);
    try writer.writeAll(",\"runtime\":");
    try writeProviderRuntimeJson(writer, allocator, def, null);
    try writer.writeAll(",\"capability_budgets\":");
    try writeCapabilityBudgetsJson(writer, def);
    try writer.writeAll(",\"command_availability\":[");
    for (def.detection.binary_names, 0..) |binary_name, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try std.json.stringify(binary_name, .{}, writer);
        try writer.writeAll(",\"available\":");
        try writer.writeAll(if (try commandAvailable(allocator, binary_name)) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
    try writer.writeByte('}');
}

fn writeProviderRuntimeJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    def: provider_schema.ProviderDefinition,
    capability: ?[]const u8,
) !void {
    const readiness = try providerRuntimeReadiness(allocator, def, capability);
    try writer.writeByte('{');
    try writer.writeAll("\"readiness\":");
    try writeRuntimeReadinessJson(writer, readiness);
    try writer.writeAll(",\"required_binaries\":");
    try writeStringArrayJson(writer, def.runtime.required_binaries);
    try writer.writeAll(",\"env_vars\":");
    try writeStringArrayJson(writer, def.runtime.env_vars);
    try writer.writeAll(",\"writable_paths\":");
    try writeStringArrayJson(writer, def.runtime.writable_paths);
    try writer.writeAll(",\"session_paths\":");
    try writeStringArrayJson(writer, def.runtime.session_paths);
    try writer.writeByte('}');
}

fn writeCapabilityBudgetsJson(writer: anytype, def: provider_schema.ProviderDefinition) !void {
    try writer.writeByte('[');
    for (def.capabilities, 0..) |capability, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"name\":");
        try std.json.stringify(capability.name, .{}, writer);
        try writer.writeAll(",\"budget\":");
        if (capability.probe) |probe_def| {
            try std.json.stringify(@tagName(probe_def.budget orelse provider_schema.defaultProbeBudget(probe_def.transport)), .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn writeConfiguredProvidersReportJson(writer: anytype, args: cli.Command.ReportArgs, cfg: config.Config) !void {
    try writer.writeByte('[');
    var provider_first = true;
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!provider_first) try writer.writeByte(',');
        provider_first = false;
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        try writer.writeByte('{');
        try writer.writeAll("\"name\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"kind\":");
        try std.json.stringify(prov.kind, .{}, writer);
        try writer.writeAll(",\"support_status\":");
        try std.json.stringify(supportStatusForConfig(cfg, provider_name, prov.kind), .{}, writer);
        try writer.writeAll(",\"proof_status\":");
        try std.json.stringify(proofStatus(prov.kind), .{}, writer);
        try writer.writeAll(",\"config_dir_env\":");
        if (prov.config_dir_env) |config_dir_env| {
            try std.json.stringify(config_dir_env, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"accounts\":[");
        var account_first = true;
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            if (!account_first) try writer.writeByte(',');
            account_first = false;
            try writeAccountReportJson(writer, args, acct_entry.key_ptr.*, acct_entry.value_ptr.*);
        }
        try writer.writeAll("]}");
    }
    try writer.writeByte(']');
}

fn writeAccountReportJson(writer: anytype, args: cli.Command.ReportArgs, account_name: []const u8, account: config.AccountConfig) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"name\":");
    try std.json.stringify(account_name, .{}, writer);
    try writer.print(",\"priority\":{d},\"secret_backend\":", .{account.priority});
    try std.json.stringify(account.secret.backend, .{}, writer);
    try writer.writeAll(",\"secret_location\":");
    if (args.include_paths) {
        try writeSecretLocationJson(writer, account.secret);
    } else {
        try std.json.stringify("redacted", .{}, writer);
    }
    try writer.writeAll(",\"config_dir_set\":");
    try writer.writeAll(if (account.config_dir != null) "true" else "false");
    try writer.writeAll(",\"config_dir\":");
    if (args.include_paths) {
        if (account.config_dir) |config_dir| {
            try std.json.stringify(config_dir, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"tags\":[");
    if (account.tags) |tags| {
        for (tags, 0..) |tag, idx| {
            if (idx > 0) try writer.writeByte(',');
            try std.json.stringify(tag, .{}, writer);
        }
    }
    try writer.writeAll("]}");
}

fn writeSecretLocationJson(writer: anytype, secret: config.SecretConfig) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"backend\":");
    try std.json.stringify(secret.backend, .{}, writer);

    if (std.mem.eql(u8, secret.backend, "env")) {
        try writer.writeAll(",\"variable\":");
        if (secret.variable) |variable| try std.json.stringify(variable, .{}, writer) else try writer.writeAll("null");
    } else if (std.mem.eql(u8, secret.backend, "file") or std.mem.eql(u8, secret.backend, "sops")) {
        try writer.writeAll(",\"path\":");
        if (secret.path) |path_value| try std.json.stringify(path_value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"key_path\":");
        if (secret.key_path) |key_path| try std.json.stringify(key_path, .{}, writer) else try writer.writeAll("null");
    } else if (std.mem.eql(u8, secret.backend, "age")) {
        try writer.writeAll(",\"path\":");
        if (secret.path) |path_value| try std.json.stringify(path_value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"identity_set\":");
        try writer.writeAll(if (secret.identity != null) "true" else "false");
    } else if (std.mem.eql(u8, secret.backend, "keychain")) {
        try writer.writeAll(",\"service\":");
        if (secret.service) |service| try std.json.stringify(service, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"account\":");
        if (secret.account) |account| try std.json.stringify(account, .{}, writer) else try writer.writeAll("null");
    } else if (std.mem.eql(u8, secret.backend, "command")) {
        try writer.writeAll(",\"command\":");
        if (secret.command) |argv| {
            if (argv.len > 0) {
                try std.json.stringify(argv[0], .{}, writer);
            } else {
                try writer.writeAll("null");
            }
            try writer.print(",\"arg_count\":{d}", .{argv.len});
        } else {
            try writer.writeAll("null,\"arg_count\":0");
        }
    }
    try writer.writeByte('}');
}

fn writeHealthEntriesJson(writer: anytype, store: *health_mod.HealthStore) !void {
    try writer.writeByte('[');
    var first = true;
    var it = store.accounts.iterator();
    while (it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        const h = entry.value_ptr.*;
        try writer.writeByte('{');
        try writer.writeAll("\"key\":");
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        if (health_mod.parseHealthKey(entry.key_ptr.*)) |parts| {
            try writer.writeAll(",\"provider\":");
            try std.json.stringify(parts.provider, .{}, writer);
            try writer.writeAll(",\"account\":");
            try std.json.stringify(parts.account, .{}, writer);
            try writer.writeAll(",\"capability\":");
            if (parts.capability) |capability| {
                try std.json.stringify(capability, .{}, writer);
            } else {
                try writer.writeAll("null");
            }
        }
        try writer.print(",\"score\":{d},\"successes\":{d},\"failures\":{d},\"rate_limits\":{d},\"circuit\":", .{
            h.score.score,
            h.score.successes,
            h.score.failures,
            h.score.rate_limits,
        });
        try std.json.stringify(circuitName(h.circuit), .{}, writer);
        try writer.writeAll(",\"last_http_status\":");
        if (h.last_http_status) |status| {
            try writer.print("{d}", .{status});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"liveness\":");
        try writeLivenessJson(writer, h.liveness);
        try writer.writeAll(",\"last_probe\":");
        try writeProbeEvidenceJson(writer, h);
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn writeCommandAvailabilityText(writer: anytype, allocator: std.mem.Allocator) !void {
    var any = false;
    for (provider_schema.builtin_providers) |def| {
        for (def.detection.binary_names) |binary_name| {
            any = true;
            try writer.print("    {s}:{s} {s}\n", .{
                def.name,
                binary_name,
                if (try commandAvailable(allocator, binary_name)) "available" else "missing",
            });
        }
    }
    if (!any) try writer.writeAll("    no command detectors declared\n");
}

fn writeCommandAvailabilityJson(writer: anytype, allocator: std.mem.Allocator) !void {
    try writer.writeByte('[');
    var first = true;
    for (provider_schema.builtin_providers) |def| {
        for (def.detection.binary_names) |binary_name| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeAll("{\"provider\":");
            try std.json.stringify(def.name, .{}, writer);
            try writer.writeAll(",\"command\":");
            try std.json.stringify(binary_name, .{}, writer);
            try writer.writeAll(",\"available\":");
            try writer.writeAll(if (try commandAvailable(allocator, binary_name)) "true" else "false");
            try writer.writeByte('}');
        }
    }
    try writer.writeByte(']');
}

fn writeAccountPathHintsText(writer: anytype, account: config.AccountConfig) !void {
    if (account.config_dir) |config_dir| try writer.print(" config_dir={s}", .{config_dir});

    const secret = account.secret;
    if (std.mem.eql(u8, secret.backend, "env")) {
        if (secret.variable) |variable| try writer.print(" env={s}", .{variable});
    } else if (std.mem.eql(u8, secret.backend, "file") or std.mem.eql(u8, secret.backend, "sops") or std.mem.eql(u8, secret.backend, "age")) {
        if (secret.path) |path_value| try writer.print(" path={s}", .{path_value});
    } else if (std.mem.eql(u8, secret.backend, "keychain")) {
        if (secret.service) |service| try writer.print(" keychain_service={s}", .{service});
        if (secret.account) |account_name| try writer.print(" keychain_account={s}", .{account_name});
    } else if (std.mem.eql(u8, secret.backend, "command")) {
        if (secret.command) |argv| {
            if (argv.len > 0) try writer.print(" command={s} argc={d}", .{ argv[0], argv.len });
        }
    }
}

fn writeIndentedLines(writer: anytype, value: []const u8, indent: []const u8) !void {
    var lines = std.mem.splitScalar(u8, value, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try writer.print("{s}{s}\n", .{ indent, line });
    }
}

fn writeLineArrayJson(writer: anytype, value: []const u8) !void {
    try writer.writeByte('[');
    var first = true;
    var lines = std.mem.splitScalar(u8, value, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(line, .{}, writer);
    }
    try writer.writeByte(']');
}

fn writeStringArrayJson(writer: anytype, values: []const []const u8) !void {
    try writer.writeByte('[');
    for (values, 0..) |value, idx| {
        if (idx > 0) try writer.writeByte(',');
        try std.json.stringify(value, .{}, writer);
    }
    try writer.writeByte(']');
}

fn configuredAccountCountForDefinition(cfg: ?config.Config, def_key: []const u8, def_name: []const u8) usize {
    const loaded = cfg orelse return 0;
    var count: usize = 0;
    var provider_it = loaded.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        if (std.mem.eql(u8, provider_name, def_key) or
            std.mem.eql(u8, provider_name, def_name) or
            std.mem.eql(u8, prov.kind, def_key) or
            std.mem.eql(u8, prov.kind, def_name))
        {
            count += prov.accounts.map.count();
        }
    }
    return count;
}

fn supportStatusForConfig(cfg: config.Config, provider_name: []const u8, provider_kind: []const u8) []const u8 {
    if (provider_schema.findBuiltin(provider_kind) != null) {
        return supportStatus(provider_kind, true);
    }
    if (provider_schema.findBuiltin(provider_name) != null) {
        return supportStatus(provider_name, true);
    }
    if (cfg.provider_definitions.map.get(provider_kind) != null or cfg.provider_definitions.map.get(provider_name) != null) {
        return "schema_modeled";
    }
    return "needs_operator_proof";
}

fn supportStatus(def_name: []const u8, built_in: bool) []const u8 {
    if (std.mem.eql(u8, def_name, "codex")) return "live_proven";
    if (built_in) return "built_in";
    return "schema_modeled";
}

fn proofStatus(def_name: []const u8) []const u8 {
    if (std.mem.eql(u8, def_name, "codex")) return "live_proven";
    return "needs_operator_proof";
}

fn providerDisplayName(def: provider_schema.ProviderDefinition) []const u8 {
    if (def.display_name.len != 0) return def.display_name;
    return def.name;
}

fn countProviderProbes(def: provider_schema.ProviderDefinition) usize {
    var count: usize = 0;
    for (def.capabilities) |capability| {
        if (capability.probe != null) count += 1;
    }
    return count;
}

fn providerRuntimeReadiness(
    allocator: std.mem.Allocator,
    def: provider_schema.ProviderDefinition,
    capability: ?[]const u8,
) !types.RuntimeReadiness {
    for (def.runtime.required_binaries) |binary_name| {
        if (!try commandAvailable(allocator, binary_name)) {
            return .{ .missing_binary = binary_name };
        }
    }

    if (capability) |capability_name| {
        if (provider_schema.probePlanForCapability(def, capability_name)) |plan| {
            if (plan.transport == .command) {
                const argv = plan.command orelse return .{ .session_unavailable = "probe command missing" };
                if (argv.len == 0) return .{ .session_unavailable = "probe command empty" };
                if (!try commandAvailable(allocator, argv[0])) {
                    return .{ .missing_binary = argv[0] };
                }
            }
        }
    }

    return .ready;
}

fn runtimeReadinessSummary(readiness: types.RuntimeReadiness) []const u8 {
    return switch (readiness) {
        .ready => "ready",
        .missing_binary => "missing_binary",
        .permission_denied => "permission_denied",
        .unwritable_store => "unwritable_store",
        .session_unavailable => "session_unavailable",
        .sandbox_blocked => "sandbox_blocked",
        .needs_reauth => "needs_reauth",
        .repair_in_progress => "repair_in_progress",
    };
}

fn writeRuntimeReadinessJson(writer: anytype, readiness: types.RuntimeReadiness) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"state\":");
    try std.json.stringify(runtimeReadinessSummary(readiness), .{}, writer);
    switch (readiness) {
        .ready => {},
        .missing_binary => |binary| {
            try writer.writeAll(",\"binary\":");
            try std.json.stringify(binary, .{}, writer);
        },
        .permission_denied => |info| {
            try writer.writeAll(",\"path\":");
            try std.json.stringify(info.path, .{}, writer);
            try writer.writeAll(",\"operation\":");
            try std.json.stringify(info.operation, .{}, writer);
        },
        .unwritable_store, .session_unavailable, .sandbox_blocked => |value| {
            try writer.writeAll(",\"detail\":");
            try std.json.stringify(value, .{}, writer);
        },
        .needs_reauth => |info| {
            try writer.writeAll(",\"methods\":");
            try writeStringArrayJson(writer, info.methods);
            try writer.writeAll(",\"reason\":");
            try std.json.stringify(info.reason, .{}, writer);
        },
        .repair_in_progress => |info| {
            try writer.writeAll(",\"account\":");
            try std.json.stringify(info.account, .{}, writer);
            try writer.print(",\"started_at\":{d}", .{info.started_at});
        },
    }
    try writer.writeByte('}');
}

fn isBuiltinDefinition(def_key: []const u8, def_name: []const u8) bool {
    return provider_schema.findBuiltin(def_key) != null or provider_schema.findBuiltin(def_name) != null;
}

fn circuitName(circuit: types.CircuitState) []const u8 {
    return switch (circuit) {
        .closed => "closed",
        .open => "open",
        .half_open => "half_open",
    };
}

fn commandAvailable(allocator: std.mem.Allocator, binary_name: []const u8) !bool {
    if (binary_name.len == 0) return false;

    const path_env = std.process.getEnvVarOwned(allocator, "PATH") catch return false;
    defer allocator.free(path_env);

    var dirs = std.mem.splitScalar(u8, path_env, pathDelimiter());
    while (dirs.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, binary_name });
        defer allocator.free(candidate);
        if (fileExists(candidate)) return true;

        if (comptime builtin.os.tag == .windows) {
            if (!std.ascii.endsWithIgnoreCase(binary_name, ".exe")) {
                const exe_name = try std.fmt.allocPrint(allocator, "{s}.exe", .{binary_name});
                defer allocator.free(exe_name);
                const exe_candidate = try std.fs.path.join(allocator, &.{ dir, exe_name });
                defer allocator.free(exe_candidate);
                if (fileExists(exe_candidate)) return true;
            }
        }
    }

    return false;
}

fn pathDelimiter() u8 {
    return if (builtin.os.tag == .windows) ';' else ':';
}

fn fileExists(path_value: []const u8) bool {
    const file = if (std.fs.path.isAbsolute(path_value))
        std.fs.openFileAbsolute(path_value, .{}) catch return false
    else
        std.fs.cwd().openFile(path_value, .{}) catch return false;
    file.close();
    return true;
}

fn countConfiguredAccounts(cfg: config.Config) usize {
    var count: usize = 0;
    var it = cfg.providers.map.iterator();
    while (it.next()) |entry| {
        count += entry.value_ptr.accounts.map.count();
    }
    return count;
}

fn fileExistsAbsolute(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn runEnv(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.EnvArgs) !void {
    const parsed = config.load(allocator) catch {
        return error.ConfigNotFound;
    };
    defer parsed.deinit();

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var ctx = pipeline.Context.init(allocator, parsed.value, &store);
    defer ctx.deinit();

    ctx.profile_name = args.profile;
    ctx.provider_name = args.provider;
    ctx.capability_name = args.capability;
    ctx.shell = if (args.shell) |s| blk: {
        const map = std.StaticStringMap(types.ShellKind).initComptime(.{
            .{ "fish", .fish },
            .{ "zsh", .zsh },
            .{ "bash", .bash },
            .{ "ksh", .ksh },
        });
        break :blk map.get(s) orelse shell.detect();
    } else shell.detect();

    pipeline.runEnv(&ctx) catch |e| {
        store.persist();
        return e;
    };

    try shell.emitEnv(writer, ctx.shell, ctx.env_pairs.items);

    store.persist();
}

fn runProbe(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.ProbeArgs) !void {
    const parsed = config.load(allocator) catch {
        return error.ConfigNotFound;
    };
    defer parsed.deinit();

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var ctx = pipeline.Context.init(allocator, parsed.value, &store);
    defer ctx.deinit();

    ctx.profile_name = args.profile;
    ctx.provider_name = args.provider;
    ctx.account_name = args.account;
    ctx.capability_name = args.capability;

    const result = pipeline.runProbe(&ctx);
    store.persist();

    var probe_error: ?types.PipelineError = null;
    if (result) |_| {} else |e| {
        probe_error = e;
    }

    if (args.json) {
        try writeProbeJson(writer, allocator, &store, &ctx, probe_error);
    } else {
        try writeProbeText(writer, allocator, &store, &ctx);
    }
    try result;
}

fn runExec(allocator: std.mem.Allocator, args: cli.Command.ExecArgs) !void {
    if (args.target_argv.len == 0) {
        log.err("exec: no target command specified (use -- before the command)", .{});
        std.process.exit(types.ExitCode.general_error.int());
    }

    const parsed = config.load(allocator) catch {
        return error.ConfigNotFound;
    };
    defer parsed.deinit();

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var ctx = pipeline.Context.init(allocator, parsed.value, &store);
    defer ctx.deinit();

    ctx.profile_name = args.profile;
    ctx.provider_name = args.provider;
    ctx.capability_name = args.capability;
    ctx.target_argv = args.target_argv;

    pipeline.runExec(&ctx) catch |e| {
        store.persist();
        return e;
    };

    // Build env map from current env + pipeline injections
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    for (ctx.env_pairs.items) |pair| {
        try env_map.put(pair[0], pair[1]);
    }
    try env_map.put("OMUX_VERSION", cli.version);

    store.persist();

    // execve replaces the process — does not return on success
    shell.execTarget(args.target_argv, &env_map) catch {
        log.err("exec: failed to execute {s}", .{args.target_argv[0]});
        std.process.exit(types.ExitCode.general_error.int());
    };
}

const HealthSelection = struct {
    key: health_mod.KeyBuf,
    health: ?health_mod.AccountHealth,
};

fn selectedHealth(store: *health_mod.HealthStore, ctx: *const pipeline.Context) HealthSelection {
    const prov = ctx.provider_name orelse "";
    const acct = ctx.account_name orelse "";
    const account_key = health_mod.accountKey(prov, acct);
    const account_health = store.accounts.get(account_key.slice());
    if (account_health) |health| {
        if (accountLivenessBlocksRoute(health.liveness)) {
            return .{ .key = account_key, .health = health };
        }
    }

    if (ctx.capability_name) |capability| {
        const route_key = health_mod.capabilityKey(prov, acct, capability);
        if (store.accounts.get(route_key.slice())) |health| {
            return .{ .key = route_key, .health = health };
        }
    }

    return .{ .key = account_key, .health = account_health };
}

fn accountLivenessBlocksRoute(liveness: types.CredentialLiveness) bool {
    return switch (liveness) {
        .dead, .degraded => true,
        .live => |live| switch (live.availability) {
            .available => false,
            .rate_limited, .quota_exhausted, .cooldown => true,
        },
    };
}

fn probeDecision(ctx: *const pipeline.Context, probe_error: ?types.PipelineError) types.MuxDecision {
    if (probe_error) |err| {
        return switch (err) {
            error.NetworkError => .try_next_provider,
            error.AllAccountsExhausted => ctx.last_probe_decision orelse .give_up,
            else => .try_next_account,
        };
    }
    return ctx.last_probe_decision orelse .use_this;
}

fn writeProbeText(writer: anytype, allocator: std.mem.Allocator, store: *health_mod.HealthStore, ctx: *const pipeline.Context) !void {
    const provider_name = ctx.provider_name orelse "-";
    const account_name = ctx.account_name orelse "-";
    try writer.writeAll("oauth-mux probe\n\n");
    try writer.print("  selected: {s}:{s}", .{ provider_name, account_name });
    if (ctx.capability_name) |capability| {
        try writer.print("#{s}", .{capability});
    }
    try writer.writeByte('\n');

    if (ctx.last_probe_executed) {
        try writer.writeAll("  probe:    executed status=");
        if (ctx.last_probe_status) |status| {
            try writer.print("{d}", .{status});
        } else {
            try writer.writeAll("-");
        }
        try writer.print(" decision={s}\n", .{@tagName(ctx.last_probe_decision orelse .use_this)});
    } else if (ctx.capability_name != null) {
        try writer.writeAll("  probe:    no configured probe plan for capability\n");
    } else {
        try writer.writeAll("  probe:    no capability requested; credential parse/expiry validation only\n");
    }

    if (ctx.provider_name) |selected_provider| {
        const def = config.resolveProviderDefinition(ctx.cfg, selected_provider);
        const readiness = try providerRuntimeReadiness(allocator, def, ctx.capability_name);
        try writer.print("  runtime:  {s}\n", .{runtimeReadinessSummary(readiness)});
    }

    const selection = selectedHealth(store, ctx);
    try writer.print("  health:   {s} ", .{selection.key.slice()});
    if (selection.health) |health| {
        try health_mod.writeLivenessSummary(writer, health.liveness);
        if (health.last_http_status) |status| {
            try writer.print(" http={d}", .{status});
        }
        if (health.last_probe_source) |source| {
            try writer.print("\n  evidence: source={s}", .{@tagName(source)});
            if (health.last_probe_observed_at) |observed_at| {
                try writer.print(" observed_at={d}", .{observed_at});
            }
            if (health.last_probe_retry_after_s) |retry_after| {
                try writer.print(" retry_after_s={d}", .{retry_after});
            }
            if (health.last_probe_hint_class) |hint_class| {
                try writer.print(" hint={s}", .{@tagName(hint_class)});
            }
            if (health.last_probe_decision) |decision| {
                try writer.print(" decision={s}", .{@tagName(decision)});
            }
        }
    } else {
        try writer.writeAll("unrecorded");
    }
    try writer.writeByte('\n');
}

fn writeProbeJson(writer: anytype, allocator: std.mem.Allocator, store: *health_mod.HealthStore, ctx: *const pipeline.Context, probe_error: ?types.PipelineError) !void {
    const selection = selectedHealth(store, ctx);
    const decision = probeDecision(ctx, probe_error);
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(ctx.provider_name orelse "", .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(ctx.account_name orelse "", .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (ctx.capability_name) |capability| {
        try std.json.stringify(capability, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (probe_error == null) "true" else "false");
    try writer.writeAll(",\"error\":");
    if (probe_error) |err| {
        try std.json.stringify(@errorName(err), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"exit_code\":");
    if (probe_error) |err| {
        try writer.print("{d}", .{exitCodeFromPipelineError(err)});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"probe_executed\":");
    try writer.writeAll(if (ctx.last_probe_executed) "true" else "false");
    try writer.writeAll(",\"probe_status\":");
    if (ctx.last_probe_status) |status| {
        try writer.print("{d}", .{status});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"decision\":");
    try std.json.stringify(@tagName(decision), .{}, writer);
    try writer.writeAll(",\"runtime\":");
    if (ctx.provider_name) |provider_name| {
        const def = config.resolveProviderDefinition(ctx.cfg, provider_name);
        try writeProviderRuntimeJson(writer, allocator, def, ctx.capability_name);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"health_key\":");
    try std.json.stringify(selection.key.slice(), .{}, writer);
    try writer.writeAll(",\"liveness\":");
    if (selection.health) |health| {
        try writeLivenessJson(writer, health.liveness);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"last_probe\":");
    if (selection.health) |health| {
        try writeProbeEvidenceJson(writer, health);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

fn runHealth(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.HealthArgs) !void {
    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    if (args.reset) |key| {
        if (store.accounts.fetchRemove(key)) |kv| {
            allocator.free(kv.key);
            try writer.print("reset health for {s}\n", .{key});
        } else {
            try writer.print("no health data for {s}\n", .{key});
        }
        store.persist();
        return;
    }

    if (args.json) {
        try writeHealthJson(writer, &store, args.provider);
        return;
    }

    try writeHealthText(writer, &store, args.provider);
}

fn writeHealthText(writer: anytype, store: *health_mod.HealthStore, provider_filter: ?[]const u8) !void {
    try writer.print("oauth-mux health\n\n", .{});
    if (matchingHealthCount(store, provider_filter) == 0) {
        try writer.writeAll("  no health data recorded yet\n");
    } else {
        try writer.print("  {s:<30} {s:>6} {s:>5} {s:>5} {s:>5}  {s:<9} {s:>5}  {s}\n", .{
            "Account", "Score", "OK", "Fail", "Rate", "Circuit", "HTTP", "Liveness",
        });
        try writer.print("  {s:-<30} {s:->6} {s:->5} {s:->5} {s:->5}  {s:-<9} {s:->5}  {s:-<24}\n", .{
            "", "", "", "", "", "", "", "",
        });
        var it = store.accounts.iterator();
        while (it.next()) |entry| {
            if (!matchesProvider(entry.key_ptr.*, provider_filter)) continue;
            const h = entry.value_ptr.*;
            try writer.print("  {s:<30} {d:>5}% {d:>5} {d:>5} {d:>5}  {s:<9} ", .{
                entry.key_ptr.*,
                h.score.score,
                h.score.successes,
                h.score.failures,
                h.score.rate_limits,
                switch (h.circuit) {
                    .closed => "closed",
                    .open => "OPEN",
                    .half_open => "half-open",
                },
            });
            if (h.last_http_status) |status| {
                try writer.print("{d:>5}  ", .{status});
            } else {
                try writer.writeAll("    -  ");
            }
            try health_mod.writeLivenessSummary(writer, h.liveness);
            try writer.writeByte('\n');
        }
    }
}

fn writeHealthJson(writer: anytype, store: *health_mod.HealthStore, provider_filter: ?[]const u8) !void {
    try writer.writeAll("{\"accounts\":[");
    var first = true;
    var it = store.accounts.iterator();
    while (it.next()) |entry| {
        if (!matchesProvider(entry.key_ptr.*, provider_filter)) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        const h = entry.value_ptr.*;
        try writer.writeByte('{');
        try writer.writeAll("\"key\":");
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        if (health_mod.parseHealthKey(entry.key_ptr.*)) |parts| {
            try writer.writeAll(",\"provider\":");
            try std.json.stringify(parts.provider, .{}, writer);
            try writer.writeAll(",\"account\":");
            try std.json.stringify(parts.account, .{}, writer);
            try writer.writeAll(",\"capability\":");
            if (parts.capability) |capability| {
                try std.json.stringify(capability, .{}, writer);
            } else {
                try writer.writeAll("null");
            }
        }
        try writer.print(
            ",\"score\":{d},\"successes\":{d},\"failures\":{d},\"rate_limits\":{d},\"circuit\":\"{s}\"",
            .{
                h.score.score,
                h.score.successes,
                h.score.failures,
                h.score.rate_limits,
                switch (h.circuit) {
                    .closed => "closed",
                    .open => "open",
                    .half_open => "half_open",
                },
            },
        );
        try writer.writeAll(",\"last_http_status\":");
        if (h.last_http_status) |status| {
            try writer.print("{d}", .{status});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"liveness\":");
        try writeLivenessJson(writer, h.liveness);
        try writer.writeAll(",\"last_probe\":");
        try writeProbeEvidenceJson(writer, h);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}\n");
}

fn writeProbeEvidenceJson(writer: anytype, health: health_mod.AccountHealth) !void {
    if (health.last_probe_source == null and
        health.last_probe_observed_at == null and
        health.last_probe_retry_after_s == null and
        health.last_probe_hint_class == null and
        health.last_probe_decision == null)
    {
        try writer.writeAll("null");
        return;
    }

    try writer.writeByte('{');
    try writer.writeAll("\"source\":");
    if (health.last_probe_source) |source| {
        try std.json.stringify(@tagName(source), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"observed_at\":");
    if (health.last_probe_observed_at) |observed_at| {
        try writer.print("{d}", .{observed_at});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"retry_after_s\":");
    if (health.last_probe_retry_after_s) |retry_after| {
        try writer.print("{d}", .{retry_after});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"hint_class\":");
    if (health.last_probe_hint_class) |hint_class| {
        try std.json.stringify(@tagName(hint_class), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"decision\":");
    if (health.last_probe_decision) |decision| {
        try std.json.stringify(@tagName(decision), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeLivenessJson(writer: anytype, liveness: types.CredentialLiveness) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"summary\":");
    try writer.writeByte('"');
    try health_mod.writeLivenessSummary(writer, liveness);
    try writer.writeByte('"');

    switch (liveness) {
        .live => |live| {
            try writer.writeAll(",\"state\":\"live\"");
            switch (live.availability) {
                .available => try writer.writeAll(",\"availability\":\"available\""),
                .rate_limited => |rl| try writer.print(
                    ",\"availability\":\"rate_limited\",\"retry_after_s\":{d},\"window\":\"{s}\"",
                    .{ rl.retry_after_s, @tagName(rl.window) },
                ),
                .quota_exhausted => |q| {
                    try writer.writeAll(",\"availability\":\"quota_exhausted\",\"window_resets_at\":");
                    if (q.window_resets_at) |reset| {
                        try writer.print("{d}", .{reset});
                    } else {
                        try writer.writeAll("null");
                    }
                },
                .cooldown => |c| try writer.print(",\"availability\":\"cooldown\",\"until\":{d}", .{c.until}),
            }
        },
        .degraded => |d| try writer.print(",\"state\":\"degraded\",\"reason\":\"{s}\"", .{@tagName(d.reason)}),
        .dead => |d| try writer.print(",\"state\":\"dead\",\"reason\":\"{s}\"", .{@tagName(d.reason)}),
    }
    try writer.writeByte('}');
}

fn matchingHealthCount(store: *health_mod.HealthStore, provider_filter: ?[]const u8) usize {
    var count: usize = 0;
    var it = store.accounts.iterator();
    while (it.next()) |entry| {
        if (matchesProvider(entry.key_ptr.*, provider_filter)) count += 1;
    }
    return count;
}

fn matchesProvider(key: []const u8, provider_filter: ?[]const u8) bool {
    const filter = provider_filter orelse return true;
    if (std.mem.eql(u8, key, filter)) return true;
    if (!std.mem.startsWith(u8, key, filter)) return false;
    return key.len > filter.len and key[filter.len] == ':';
}

fn runInit(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.InitArgs) !void {
    const path = try paths.configFilePath(allocator);
    defer allocator.free(path);

    if (std.fs.openFileAbsolute(path, .{})) |file| {
        file.close();
        try writer.print("config already exists at {s}\n", .{path});
        return;
    } else |_| {}

    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    const generic_starter_config =
        \\{
        \\  "version": 1,
        \\  "defaults": {
        \\    "provider": "claude",
        \\    "strategy": "health-weighted",
        \\    "shell": "fish"
        \\  },
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "config_dir_env": "CLAUDE_CONFIG_DIR",
        \\      "accounts": {
        \\        "default": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "keychain",
        \\            "service": "Claude Code-credentials",
        \\            "account": "default"
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "codex": {
        \\      "kind": "codex",
        \\      "config_dir_env": "CODEX_HOME",
        \\      "accounts": {
        \\        "default": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "keychain",
        \\            "service": "Codex Auth",
        \\            "account": "default"
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "gemini": {
        \\      "kind": "gemini",
        \\      "config_dir_env": "GEMINI_CLI_HOME",
        \\      "accounts": {
        \\        "default": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "file",
        \\            "path": "~/.gemini/oauth_creds.json"
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "vercel": {
        \\      "kind": "vercel",
        \\      "accounts": {
        \\        "default": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "file",
        \\            "path": "~/Library/Application Support/com.vercel.cli/auth.json"
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "github": {
        \\      "kind": "github",
        \\      "accounts": {
        \\        "default": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "command",
        \\            "command": ["gh", "auth", "token"]
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "mcp": {
        \\      "kind": "mcp",
        \\      "accounts": {}
        \\    }
        \\  },
        \\  "profiles": {
        \\    "default": {
        \\      "providers": ["claude:default", "codex:default", "gemini:default"],
        \\      "strategy": "health-weighted"
        \\    }
        \\  },
        \\  "strategies": {
        \\    "failover": {
        \\      "kind": "priority-failover",
        \\      "max_retries": 2
        \\    },
        \\    "health-weighted": {
        \\      "kind": "health-weighted",
        \\      "rate_limit_penalty": -10,
        \\      "failure_penalty": -20,
        \\      "success_bonus": 1
        \\    }
        \\  }
        \\}
    ;
    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();

    if (args.codex_max) {
        const store_root = try codexStoreRoot(allocator, .{});
        defer allocator.free(store_root);
        try writeCodexMaxStarterConfig(allocator, file.writer(), store_root);
    } else {
        try file.writeAll(generic_starter_config);
    }

    try writer.print("created {s}\n", .{path});
}

fn writeCodexMaxStarterConfig(allocator: std.mem.Allocator, writer: anytype, store_root: []const u8) !void {
    try writer.writeAll(
        \\{
        \\  "version": 1,
        \\  "defaults": {
        \\    "provider": "codex",
        \\    "strategy": "health-weighted",
        \\    "shell": "fish"
        \\  },
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "config_dir_env": "CODEX_HOME",
        \\      "accounts": {
        \\
    );

    try writeCodexMaxStarterAccount(allocator, writer, store_root, "max-1", 30, true);
    try writeCodexMaxStarterAccount(allocator, writer, store_root, "max-2", 20, false);
    try writeCodexMaxStarterAccount(allocator, writer, store_root, "max-3", 10, false);

    try writer.writeAll(
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": [
        \\        "codex:max-1#codex-max",
        \\        "codex:max-2#codex-max",
        \\        "codex:max-3#codex-max"
        \\      ],
        \\      "strategy": "health-weighted",
        \\      "affinity_ttl_minutes": 20
        \\    },
        \\    "codex-mini": {
        \\      "providers": [
        \\        "codex:max-1#codex-mini",
        \\        "codex:max-2#codex-mini",
        \\        "codex:max-3#codex-mini"
        \\      ],
        \\      "strategy": "health-weighted",
        \\      "affinity_ttl_minutes": 20
        \\    }
        \\  },
        \\  "strategies": {
        \\    "health-weighted": {
        \\      "kind": "health-weighted",
        \\      "rate_limit_penalty": -10,
        \\      "failure_penalty": -20,
        \\      "success_bonus": 1
        \\    }
        \\  }
        \\}
    );
}

fn writeCodexMaxStarterAccount(
    allocator: std.mem.Allocator,
    writer: anytype,
    store_root: []const u8,
    account: []const u8,
    priority: i32,
    first: bool,
) !void {
    const account_dir = try std.fs.path.join(allocator, &.{ store_root, account });
    defer allocator.free(account_dir);
    const auth_path = try std.fs.path.join(allocator, &.{ account_dir, "auth.json" });
    defer allocator.free(auth_path);

    if (!first) try writer.writeAll(",\n");
    try writer.print("        \"{s}\": {{\n", .{account});
    try writer.print("          \"priority\": {d},\n", .{priority});
    try writer.writeAll("          \"config_dir\": ");
    try std.json.stringify(account_dir, .{}, writer);
    try writer.writeAll(",\n");
    try writer.writeAll(
        \\          "secret": {
        \\            "backend": "file",
        \\            "path":
    );
    try writer.writeByte(' ');
    try std.json.stringify(auth_path, .{}, writer);
    try writer.writeAll(
        \\
        \\          },
        \\          "tags": ["subscription", "codex-max"]
        \\        }
    );
}

fn runCodex(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const root = try codexStoreRoot(allocator, args);
    defer allocator.free(root);

    switch (args.action) {
        .bootstrap_dirs => try bootstrapCodexDirs(allocator, writer, args, root),
        .login => {
            const account = singleCodexAccount(args) orelse return error.MissingAccount;
            try bootstrapOneCodexDir(allocator, writer, root, account);
            const dir = try codexAccountDir(allocator, root, account);
            defer allocator.free(dir);
            if (!try runCodexCli(allocator, dir, &.{ "codex", "login" })) return error.CodexCommandFailed;
        },
        .login_device => {
            const account = singleCodexAccount(args) orelse return error.MissingAccount;
            try bootstrapOneCodexDir(allocator, writer, root, account);
            const dir = try codexAccountDir(allocator, root, account);
            defer allocator.free(dir);
            if (!try runCodexCli(allocator, dir, &.{ "codex", "login", "--device-auth" })) return error.CodexCommandFailed;
        },
        .login_status => {
            const account = singleCodexAccount(args) orelse return error.MissingAccount;
            const dir = try codexAccountDir(allocator, root, account);
            defer allocator.free(dir);
            try writer.print("=== {s} ===\nCODEX_HOME={s}\n", .{ account, dir });
            if (!try runCodexCli(allocator, dir, &.{ "codex", "login", "status" })) return error.CodexCommandFailed;
        },
        .login_status_all => try runCodexLoginStatusAll(allocator, writer, args, root),
        .onboard => try runCodexOnboard(allocator, writer, args, root),
        .canary => try runCodexCanary(allocator, writer, args, root),
        .probe_all => try runCodexProbeAll(allocator, writer, args),
        .config_candidate => try runCodexConfigCandidate(allocator, writer, args, root),
    }
}

fn runCodexOnboard(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    try writer.writeAll("oauth-mux Codex Max onboarding\n\n");
    try writer.print("store root: {s}\n", .{root});
    try writer.print("accounts:   {s}\n", .{args.accounts});
    try writer.print("mode:       {s}\n\n", .{if (args.status_only) "status-only" else if (args.device) "device" else "browser"});

    try bootstrapCodexDirs(allocator, writer, args, root);
    try validateCurrentConfig(allocator, writer);

    var failures: usize = 0;
    var it = std.mem.splitScalar(u8, args.accounts, ',');
    while (it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        const dir = try codexAccountDir(allocator, root, account);
        defer allocator.free(dir);

        try writer.print("\n=== {s} ===\nCODEX_HOME={s}\n", .{ account, dir });
        if (try runCodexCli(allocator, dir, &.{ "codex", "login", "status" })) continue;
        if (args.status_only) {
            failures += 1;
            continue;
        }

        const login_argv = if (args.device)
            &[_][]const u8{ "codex", "login", "--device-auth" }
        else
            &[_][]const u8{ "codex", "login" };
        if (!try runCodexCli(allocator, dir, login_argv)) {
            failures += 1;
            continue;
        }
        if (!try runCodexCli(allocator, dir, &.{ "codex", "login", "status" })) failures += 1;
    }

    try writer.writeAll("\n=== oauth-mux discovery ===\n");
    try runDiscover(allocator, writer, .{ .json = false });

    if (args.live) {
        try runCodexLiveProbes(allocator, writer, args, true);
    } else {
        try writer.writeAll("\nLive probes not run. Add --live only when real provider calls are intended.\n");
    }

    if (failures != 0) return error.CodexCommandFailed;
}

fn runCodexCanary(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    try writer.writeAll("oauth-mux Codex Max canary\n\n");
    try writer.print("store root:   {s}\n", .{root});
    try writer.print("accounts:     {s}\n", .{args.accounts});
    try writer.print("capabilities: {s}\n\n", .{args.capabilities});

    try bootstrapCodexDirs(allocator, writer, args, root);

    try writer.writeAll("\n=== config validate ===\n");
    try validateCurrentConfig(allocator, writer);

    try writer.writeAll("\n=== agent discovery ===\n");
    try runDiscover(allocator, writer, .{ .json = args.json });

    try writer.writeAll("\n=== codex login status ===\n");
    try runCodexLoginStatusAll(allocator, writer, args, root);

    try writer.writeAll("\n=== route liveness snapshot ===\n");
    try writer.writeAll("Existing oauth-mux health state; add --live to refresh with real provider probes.\n");
    try writeCodexRouteSnapshot(allocator, writer, args);

    try writer.writeAll("\n=== repair plan ===\n");
    try writer.writeAll("Non-mutating next actions from runtime readiness and recorded route liveness.\n");
    try writeCodexRepairPlanSnapshot(allocator, writer, args);

    if (args.live) {
        try writer.writeAll("\n=== live probes ===\n");
        try runCodexLiveProbes(allocator, writer, args, true);
    } else {
        try writer.writeAll("\nLive probes not run. Add --live only when real provider calls are intended.\n");
    }
}

fn runCodexProbeAll(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    if (!args.json) {
        try writer.writeAll("oauth-mux Codex probe-all\n\n");
        try writer.print("accounts:     {s}\n", .{args.accounts});
        try writer.print("capabilities: {s}\n\n", .{args.capabilities});
        try writer.writeAll("=== config validate ===\n");
        try validateCurrentConfig(allocator, writer);
        try writer.writeAll("\n=== live probes ===\n");
    }
    try runCodexLiveProbes(allocator, writer, args, !args.json);
}

fn runCodexConfigCandidate(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
    root: []const u8,
) !void {
    const active_config_path = try paths.configFilePath(allocator);
    defer allocator.free(active_config_path);

    const candidate_path = if (args.output) |output|
        try paths.expandTilde(allocator, output)
    else
        try defaultCodexConfigCandidatePath(allocator, active_config_path);
    defer allocator.free(candidate_path);

    var config_buf = std.ArrayList(u8).init(allocator);
    defer config_buf.deinit();
    try writeCodexMaxStarterConfig(allocator, config_buf.writer(), root);

    const parsed = try config.loadFromBytes(allocator, config_buf.items);
    defer parsed.deinit();
    try config.validate(parsed.value, std.io.null_writer);

    if (std.fs.openFileAbsolute(candidate_path, .{})) |file| {
        file.close();
        try writeCodexConfigCandidateResult(writer, allocator, active_config_path, candidate_path, false, args.json);
        return;
    } else |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    }

    if (std.fs.path.dirname(candidate_path)) |dir| try std.fs.cwd().makePath(dir);

    const file = std.fs.createFileAbsolute(candidate_path, .{ .exclusive = true, .mode = 0o600 }) catch |e| switch (e) {
        error.PathAlreadyExists => {
            try writeCodexConfigCandidateResult(writer, allocator, active_config_path, candidate_path, false, args.json);
            return;
        },
        else => return e,
    };
    defer file.close();
    try file.writeAll(config_buf.items);

    try writeCodexConfigCandidateResult(writer, allocator, active_config_path, candidate_path, true, args.json);
}

fn defaultCodexConfigCandidatePath(allocator: std.mem.Allocator, active_config_path: []const u8) ![]const u8 {
    if (std.fs.path.dirname(active_config_path)) |dir| {
        return try std.fs.path.join(allocator, &.{ dir, "codex-max.config.json" });
    }
    return try allocator.dupe(u8, "codex-max.config.json");
}

fn writeCodexConfigCandidateResult(
    writer: anytype,
    allocator: std.mem.Allocator,
    active_config_path: []const u8,
    candidate_path: []const u8,
    created: bool,
    json: bool,
) !void {
    const quoted_candidate_path = try shellQuoteAlloc(allocator, candidate_path);
    defer allocator.free(quoted_candidate_path);

    const validate_cmd = try std.fmt.allocPrint(allocator, "OMUX_CONFIG={s} oauth-mux config validate", .{quoted_candidate_path});
    defer allocator.free(validate_cmd);
    const status_cmd = try std.fmt.allocPrint(allocator, "OMUX_CONFIG={s} oauth-mux setup codex --status-only", .{quoted_candidate_path});
    defer allocator.free(status_cmd);
    const repair_cmd = try std.fmt.allocPrint(allocator, "OMUX_CONFIG={s} oauth-mux repair-plan --profile codex-max --capability codex-max --json", .{quoted_candidate_path});
    defer allocator.free(repair_cmd);
    const canary_cmd = try std.fmt.allocPrint(allocator, "OMUX_CONFIG={s} oauth-mux codex canary", .{quoted_candidate_path});
    defer allocator.free(canary_cmd);

    if (json) {
        try writer.writeAll("{\"created\":");
        try writer.writeAll(if (created) "true" else "false");
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(active_config_path, .{}, writer);
        try writer.writeAll(",\"candidate_config\":");
        try std.json.stringify(candidate_path, .{}, writer);
        try writer.writeAll(",\"next_commands\":[");
        try writeCommandJson(writer, validate_cmd);
        try writer.writeByte(',');
        try writeCommandJson(writer, status_cmd);
        try writer.writeByte(',');
        try writeCommandJson(writer, repair_cmd);
        try writer.writeByte(',');
        try writeCommandJson(writer, canary_cmd);
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux Codex Max config candidate\n\n");
    try writer.print("active config:    {s}\n", .{active_config_path});
    try writer.print("candidate config: {s}\n", .{candidate_path});
    try writer.print("created:          {s}\n\n", .{if (created) "yes" else "no, already exists"});
    try writer.writeAll("The active config was not modified.\n\n");
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{validate_cmd});
    try writer.print("  {s}\n", .{status_cmd});
    try writer.print("  {s}\n", .{repair_cmd});
    try writer.print("  {s}\n", .{canary_cmd});
}

fn shellQuoteAlloc(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    try out.append('\'');
    for (value) |c| {
        if (c == '\'') {
            try out.appendSlice("'\\''");
        } else {
            try out.append(c);
        }
    }
    try out.append('\'');
    return out.toOwnedSlice();
}

fn validateCurrentConfig(allocator: std.mem.Allocator, writer: anytype) !void {
    const parsed = config.load(allocator) catch return error.ConfigNotFound;
    defer parsed.deinit();
    try config.validate(parsed.value, writer);
    try writer.writeAll("config: valid\n");
}

fn runCodexLoginStatusAll(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    var failures: usize = 0;
    var it = std.mem.splitScalar(u8, args.accounts, ',');
    while (it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        const dir = try codexAccountDir(allocator, root, account);
        defer allocator.free(dir);
        try writer.print("=== {s} ===\nCODEX_HOME={s}\n", .{ account, dir });
        if (!try runCodexCli(allocator, dir, &.{ "codex", "login", "status" })) failures += 1;
    }
    if (failures != 0) return error.CodexCommandFailed;
}

fn runCodexLiveProbes(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, emit_headers: bool) !void {
    var account_it = std.mem.splitScalar(u8, args.accounts, ',');
    while (account_it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        var capability_it = std.mem.splitScalar(u8, args.capabilities, ',');
        while (capability_it.next()) |raw_capability| {
            const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
            if (capability.len == 0) continue;
            if (emit_headers) try writer.print("\n--- codex:{s}#{s} ---\n", .{ account, capability });
            runProbe(allocator, writer, .{
                .provider = "codex",
                .account = account,
                .capability = capability,
                .json = args.json,
            }) catch |e| switch (e) {
                error.AllAccountsExhausted => {},
                else => return e,
            };
        }
    }
}

fn writeCodexRouteSnapshot(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var account_it = std.mem.splitScalar(u8, args.accounts, ',');
    while (account_it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        var capability_it = std.mem.splitScalar(u8, args.capabilities, ',');
        while (capability_it.next()) |raw_capability| {
            const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
            if (capability.len == 0) continue;
            const key = try std.fmt.allocPrint(allocator, "codex:{s}#{s}", .{ account, capability });
            defer allocator.free(key);
            try writer.print("{s}: ", .{key});
            if (store.accounts.get(key)) |health| {
                try health_mod.writeLivenessSummary(writer, health.liveness);
                if (health.last_http_status) |status| try writer.print(" http={d}", .{status});
                if (health.last_probe_decision) |decision| try writer.print(" decision={s}", .{@tagName(decision)});
                if (health.last_probe_observed_at) |observed_at| try writer.print(" observed_at={d}", .{observed_at});
            } else {
                try writer.writeAll("no recorded health yet");
            }
            try writer.writeByte('\n');
        }
    }
}

fn writeCodexRepairPlanSnapshot(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    var capability_it = std.mem.splitScalar(u8, args.capabilities, ',');
    while (capability_it.next()) |raw_capability| {
        const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
        if (capability.len == 0) continue;

        if (!args.json) try writer.print("\n--- profile {s} ---\n", .{capability});
        runRepairPlan(allocator, writer, .{
            .profile = capability,
            .capability = capability,
            .json = args.json,
        }) catch |e| switch (e) {
            error.ConfigValidationError => {
                if (args.json) {
                    try writer.writeAll("{\"profile\":");
                    try std.json.stringify(capability, .{}, writer);
                    try writer.writeAll(",\"skipped\":true,\"error\":\"ConfigValidationError\"}\n");
                } else {
                    try writer.print("repair-plan skipped for profile {s}: current config does not define that Codex profile\n", .{capability});
                }
            },
            else => return e,
        };
    }
}

fn bootstrapCodexDirs(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    var it = std.mem.splitScalar(u8, args.accounts, ',');
    while (it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        try bootstrapOneCodexDir(allocator, writer, root, account);
    }
}

fn bootstrapOneCodexDir(allocator: std.mem.Allocator, writer: anytype, root: []const u8, account: []const u8) !void {
    const dir = try codexAccountDir(allocator, root, account);
    defer allocator.free(dir);
    try std.fs.cwd().makePath(dir);
    try writer.print("created/verified {s}\n", .{dir});
}

fn codexStoreRoot(allocator: std.mem.Allocator, args: cli.Command.CodexArgs) ![]const u8 {
    if (args.store_root) |root| return try paths.expandTilde(allocator, root);
    if (try getEnvOwnedOrNull(allocator, "OMUX_CODEX_STORE_ROOT")) |root| {
        defer allocator.free(root);
        return try paths.expandTilde(allocator, root);
    }
    if (try getEnvOwnedOrNull(allocator, "XDG_DATA_HOME")) |xdg| {
        defer allocator.free(xdg);
        return try std.fs.path.join(allocator, &.{ xdg, "oauth-mux", "codex" });
    }
    const home = (try getEnvOwnedOrNull(allocator, "HOME")) orelse return error.ConfigNotFound;
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".local", "share", "oauth-mux", "codex" });
}

fn codexAccountDir(allocator: std.mem.Allocator, root: []const u8, account: []const u8) ![]const u8 {
    return try std.fs.path.join(allocator, &.{ root, account });
}

fn singleCodexAccount(args: cli.Command.CodexArgs) ?[]const u8 {
    if (args.account) |account| return account;
    var it = std.mem.splitScalar(u8, args.accounts, ',');
    while (it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len != 0) return account;
    }
    return null;
}

fn getEnvOwnedOrNull(allocator: std.mem.Allocator, name: []const u8) !?[]const u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        else => return e,
    };
}

fn runCodexCli(allocator: std.mem.Allocator, account_dir: []const u8, argv: []const []const u8) !bool {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", account_dir);

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;

    const term = child.spawnAndWait() catch return error.CodexCommandFailed;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

test "matchesProvider filters account keys" {
    try std.testing.expect(matchesProvider("codex:max-1", "codex"));
    try std.testing.expect(matchesProvider("codex:max-1#codex-max", "codex"));
    try std.testing.expect(matchesProvider("codex", "codex"));
    try std.testing.expect(!matchesProvider("codexish:max-1", "codex"));
    try std.testing.expect(!matchesProvider("claude:work", "codex"));
}

test "Codex Max starter config uses resolved store root" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeCodexMaxStarterConfig(std.testing.allocator, buf.writer(), "/tmp/omux-codex");

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"config_dir\": \"/tmp/omux-codex/max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"path\": \"/tmp/omux-codex/max-1/auth.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "~/.local/share/oauth-mux/codex") == null);

    const parsed = try config.loadFromBytes(std.testing.allocator, buf.items);
    defer parsed.deinit();
    try config.validate(parsed.value, std.io.null_writer);
    try std.testing.expect(codexMaxShapeConfigured(parsed.value));
}

test "codexMaxShapeConfigured rejects single-account Codex config" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "CODEX_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "default": {
        \\      "providers": ["codex:default"],
        \\      "strategy": "health-weighted"
        \\    }
        \\  },
        \\  "strategies": {
        \\    "health-weighted": {
        \\      "kind": "health-weighted"
        \\    }
        \\  }
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expect(codexConfigured(parsed.value));
    try std.testing.expect(!codexMaxShapeConfigured(parsed.value));
}

test "doctor json recommends Codex Max candidate for single-account drift" {
    const stats = DoctorStats{
        .configured = true,
        .config_valid = true,
        .provider_count = 1,
        .account_count = 1,
        .profile_count = 1,
        .strategy_count = 1,
        .codex_configured = true,
        .codex_max_configured = false,
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeDoctorJson(buf.writer(), stats, "/tmp/config.json", "/tmp/state", "/tmp/health.json", "");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"codex_configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"codex_max_configured\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"codex_max_configured\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"severity\":\"warning\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux codex config-candidate --json") != null);
}

test "writeHealthJson includes redacted liveness" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordHttpStatus("codex:max-1", 429, 30);
    store.recordHttpStatus("claude:work", 401, null);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeHealthJson(buf.writer(), &store, "codex");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"key\":\"codex:max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"provider\":\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"account\":\"max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"availability\":\"rate_limited\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"last_probe\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"hint_class\":\"rate_limit\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "claude:work") == null);
}

test "writeHealthJson includes capability routes" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeHealthJson(buf.writer(), &store, "codex");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"key\":\"codex:max-1#codex-max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"capability\":\"codex-max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"availability\":\"quota_exhausted\"") != null);
}

test "writeDiscoverJson includes repair-plan as agent-safe command" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeDiscoverJson(buf.writer(), parsed.value, "/tmp/config.json", "/tmp/state");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux repair-plan --profile <profile> --capability <capability> --json") != null);
}

test "writeDiscoverJson exposes Codex Max drift command" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "CODEX_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "default": {
        \\      "providers": ["codex:default"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeDiscoverJson(buf.writer(), parsed.value, "/tmp/config.json", "/tmp/state");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"codex_configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"codex_max_configured\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux codex config-candidate --json") != null);
}

test "writeProvidersListJson exposes extension and budget metadata" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeProvidersListJson(buf.writer(), std.testing.allocator, null, false, "FileNotFound");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"extension_mode\":\"command_adapter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"repair_owner\":\"upstream_cli_login\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"runtime\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"capability_budgets\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"budget\":\"spend_provider\"") != null);
}

test "collectRepairPlanRoutes expands profile capability routes" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "secret": { "backend": "file", "path": "/tmp/omux/max-1/auth.json" }
        \\        },
        \\        "max-2": {
        \\          "secret": { "backend": "file", "path": "/tmp/omux/max-2/auth.json" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "codex-max" });
    defer routes.deinit();

    try std.testing.expectEqual(@as(usize, 2), routes.items.len);
    try std.testing.expectEqualStrings("codex", routes.items[0].provider);
    try std.testing.expectEqualStrings("max-1", routes.items[0].account);
    try std.testing.expectEqualStrings("codex-max", routes.items[0].capability.?);
    try std.testing.expectEqualStrings("max-2", routes.items[1].account);
}

test "repairActionFor warns before spending provider quota without health evidence" {
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .display_name = "Toy Provider",
        .repair = .{ .owner = .manual_only },
    };
    const action = repairActionFor(
        .{ .provider = "toy", .account = "default", .capability = "expensive" },
        def,
        .ready,
        null,
        .spend_provider,
    );

    try std.testing.expectEqualStrings("probe_needed", action.kind);
    try std.testing.expectEqualStrings("warning", action.severity);
    try std.testing.expect(action.command == .probe);
    try std.testing.expect(std.mem.indexOf(u8, action.message, "spend provider quota") != null);
}

test "repairActionFor classifies quota exhaustion as wait action" {
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .display_name = "Toy Provider",
        .repair = .{ .owner = .manual_only },
    };
    const health = health_mod.AccountHealth{
        .liveness = .{ .live = .{
            .availability = .{ .quota_exhausted = .{
                .window_resets_at = 1_777_777,
                .exhausted_at = 1_700_000,
            } },
        } },
    };
    const action = repairActionFor(
        .{ .provider = "toy", .account = "default", .capability = "chat" },
        def,
        .ready,
        health,
        .spend_provider,
    );

    try std.testing.expectEqualStrings("wait_for_quota", action.kind);
    try std.testing.expectEqualStrings("warning", action.severity);
    try std.testing.expectEqual(@as(?i64, 1_777_777), action.wait_until);
    try std.testing.expect(action.command == .none);
}

test "writeRepairActionJson emits codex reauth command without running it" {
    const def = provider_schema.ProviderDefinition{
        .name = "codex",
        .display_name = "Codex",
        .repair = .{ .owner = .upstream_cli_login },
    };
    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const action = reauthAction(route, def);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeRepairActionJson(buf.writer(), std.testing.allocator, action, route);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"reauth\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"interactive\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mutating\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
}

test "shellQuoteAlloc protects config paths with spaces" {
    const quoted = try shellQuoteAlloc(std.testing.allocator, "/Users/me/Library/Application Support/oauth-mux/codex-max.config.json");
    defer std.testing.allocator.free(quoted);
    try std.testing.expectEqualStrings("'/Users/me/Library/Application Support/oauth-mux/codex-max.config.json'", quoted);

    const with_quote = try shellQuoteAlloc(std.testing.allocator, "/tmp/it's-here.json");
    defer std.testing.allocator.free(with_quote);
    try std.testing.expectEqualStrings("'/tmp/it'\\''s-here.json'", with_quote);
}

test "writeProbeJson includes terminal pipeline error" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("codex:max-1", .auth_failure);
    _ = try store.getOrCreate("codex:max-1#codex-mini");

    var ctx = pipeline.Context.init(std.testing.allocator, .{}, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "max-1";
    ctx.capability_name = "codex-mini";

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeProbeJson(buf.writer(), std.testing.allocator, &store, &ctx, error.SecretReadFailed);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"error\":\"SecretReadFailed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"exit_code\":202") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"decision\":\"try_next_account\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"runtime\":{\"readiness\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"health_key\":\"codex:max-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"dead\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"hint_class\":\"auth_dead\"") != null);
}

// Pull in all module tests
comptime {
    _ = @import("types.zig");
    _ = @import("cli.zig");
    _ = @import("config.zig");
    _ = @import("paths.zig");
    _ = @import("shell.zig");
    _ = @import("log.zig");
    _ = @import("secret.zig");
    _ = @import("health.zig");
    _ = @import("provider.zig");
    _ = @import("pipeline.zig");
    _ = @import("oauth.zig");
    _ = @import("probe.zig");
    _ = @import("age.zig");
    _ = @import("daemon.zig");
    _ = @import("provider_schema.zig");
    _ = @import("fixture_redaction.zig");
}
