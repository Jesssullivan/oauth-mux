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
const repair_state = @import("repair_state.zig");
const runtime_mod = @import("runtime.zig");
const secret_mod = @import("secret.zig");

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
            if (doctor_args.mode == .runtime) {
                try runDoctorRuntime(allocator, stdout, doctor_args);
            } else {
                try runDoctor(allocator, stdout, doctor_args);
            }
        },

        .report => |report_args| {
            try runReport(allocator, stdout, report_args);
        },

        .providers => |providers_args| {
            try runProviders(allocator, stdout, providers_args);
        },

        .accounts => |accounts_args| {
            try runAccounts(allocator, stdout, accounts_args);
        },

        .enroll => |enroll_args| {
            try runEnroll(allocator, stdout, enroll_args);
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

        .repair_run => |repair_args| {
            runRepairRun(allocator, stdout, repair_args) catch |e| {
                log.err("repair run: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .route => |route_args| {
            runRoute(allocator, stdout, route_args) catch |e| {
                log.err("route: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .stay_afloat_next => |route_args| {
            runStayAfloatNext(allocator, stdout, route_args) catch |e| {
                log.err("stay-afloat next: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .stay_afloat_launch => |launch_args| {
            runStayAfloatLaunch(allocator, stdout, launch_args) catch |e| {
                log.err("stay-afloat launch: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .stay_afloat_supervise => |supervise_args| {
            runStayAfloatSupervise(allocator, stdout, supervise_args) catch |e| {
                log.err("stay-afloat supervise: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .stay_afloat => |tick_args| {
            runDaemonTick(allocator, stdout, tick_args, "oauth-mux stay-afloat") catch |e| {
                log.err("stay-afloat: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .stay_afloat_handoff => |handoff_args| {
            runStayAfloatHandoff(allocator, stdout, handoff_args) catch |e| {
                log.err("stay-afloat handoff: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .completions => |comp_args| {
            try cli.printCompletions(stdout, comp_args.shell);
        },

        .daemon_run => |run_args| {
            if (run_args.stay_afloat) {
                runSupervisedStayAfloat(allocator, stdout, run_args.tick) catch |e| {
                    log.err("daemon stay-afloat: {s}", .{@errorName(e)});
                    std.process.exit(types.ExitCode.general_error.int());
                };
                return;
            }
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
        .daemon_status => |daemon_args| {
            try daemon.status(allocator, stdout, daemon_args.json);
        },
        .daemon_events => |events_args| {
            try repair_state.writeEvents(allocator, stdout, events_args.json, events_args.limit);
        },
        .daemon_handoffs => |events_args| {
            try repair_state.writeHandoffs(allocator, stdout, events_args.json, events_args.limit, events_args.all);
        },
        .daemon_tick => |tick_args| {
            runDaemonTick(allocator, stdout, tick_args, "oauth-mux daemon tick") catch |e| {
                log.err("daemon tick: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
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

fn runAccounts(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.AccountsArgs) !void {
    switch (args.action) {
        .list => {},
    }

    const parsed = config.load(allocator) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"configured\":false,\"config_error\":");
            try std.json.stringify(@errorName(e), .{}, writer);
            try writer.writeAll(",\"accounts\":[],\"agent_safe_commands\":[");
            try writeCommandJson(writer, "oauth-mux init");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux init --codex-max");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux accounts list --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux accounts\n\n");
            try writer.print("  config: unavailable ({s})\n", .{@errorName(e)});
            try writer.writeAll("  next: oauth-mux init\n");
        }
        return;
    };
    defer parsed.deinit();

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    if (args.json) {
        try writeAccountsListJson(writer, allocator, parsed.value, &store, args);
    } else {
        try writeAccountsListText(writer, allocator, parsed.value, &store, args);
    }
}

fn writeAccountsListText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    args: cli.Command.AccountsArgs,
) !void {
    try writer.writeAll("oauth-mux accounts\n\n");
    if (args.provider) |provider_filter| try writer.print("  provider: {s}\n\n", .{provider_filter});

    var count: usize = 0;
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        if (!accountsProviderMatches(args, provider_name, prov.kind)) continue;

        const def = config.resolveProviderDefinition(cfg, provider_name);
        const kind = config.resolveProviderKind(cfg, provider_name);
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            count += 1;
            const account_name = acct_entry.key_ptr.*;
            const account = acct_entry.value_ptr.*;
            const info = try runtime_mod.accountInfo(allocator, prov, account, def, kind);
            const state = accountEnrollmentState(store, provider_name, account_name, def, info.readiness);
            try writer.print("  {s}:{s} state={s} runtime={s} secret={s}", .{
                provider_name,
                account_name,
                state,
                runtimeReadinessSummary(info.readiness),
                account.secret.backend,
            });
            if (account.config_dir != null) try writer.writeAll(" config_dir=set");
            try writer.writeByte('\n');

            for (def.capabilities) |capability| {
                const route = RepairPlanRoute{ .provider = provider_name, .account = account_name, .capability = capability.name };
                const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
                const health = routeHealth(store, route);
                const selectable = routeSelectable(runtime, health);
                try writer.print("    {s} proof={s} selectable={s} runtime={s}", .{
                    capability.name,
                    capability.proof_status,
                    if (selectable) "true" else "false",
                    runtimeReadinessSummary(runtime),
                });
                if (health) |h| {
                    try writer.writeAll(" liveness=");
                    try health_mod.writeLivenessSummary(writer, h.liveness);
                } else {
                    try writer.writeAll(" liveness=unrecorded");
                }
                try writer.writeByte('\n');
            }
        }
    }

    if (count == 0) try writer.writeAll("  no configured accounts\n");
    try writer.writeAll("\n  agent-safe next:\n");
    try writer.writeAll("    oauth-mux accounts list --json\n");
    try writer.writeAll("    oauth-mux doctor runtime --provider <provider> --account <account> --json\n");
    try writer.writeAll("    oauth-mux repair-plan --provider <provider> --account <account> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json\n");
}

fn writeAccountsListJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    args: cli.Command.AccountsArgs,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"configured\":true,\"filter_provider\":");
    if (args.provider) |provider_filter| try std.json.stringify(provider_filter, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"accounts\":[");

    var first = true;
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        if (!accountsProviderMatches(args, provider_name, prov.kind)) continue;

        const def = config.resolveProviderDefinition(cfg, provider_name);
        const kind = config.resolveProviderKind(cfg, provider_name);
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writeAccountListJsonEntry(writer, allocator, cfg, store, provider_name, prov, acct_entry.key_ptr.*, acct_entry.value_ptr.*, def, kind);
        }
    }

    try writer.writeAll("],\"agent_safe_commands\":[");
    try writeCommandJson(writer, "oauth-mux accounts list --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux doctor runtime --provider <provider> --account <account> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux repair-plan --provider <provider> --account <account> --capability <capability> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json");
    try writer.writeAll("]}\n");
}

fn writeAccountListJsonEntry(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    provider_name: []const u8,
    prov: config.ProviderConfig,
    account_name: []const u8,
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) !void {
    const info = try runtime_mod.accountInfo(allocator, prov, account, def, kind);
    const state = accountEnrollmentState(store, provider_name, account_name, def, info.readiness);

    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(provider_name, .{}, writer);
    try writer.writeAll(",\"kind\":");
    try std.json.stringify(prov.kind, .{}, writer);
    try writer.writeAll(",\"display_name\":");
    try std.json.stringify(providerDisplayName(def), .{}, writer);
    try writer.writeAll(",\"support_status\":");
    try std.json.stringify(supportStatusForConfig(cfg, provider_name, prov.kind), .{}, writer);
    try writer.writeAll(",\"provider_proof_status\":");
    try std.json.stringify(proofStatus(prov.kind), .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(account_name, .{}, writer);
    try writer.writeAll(",\"state\":");
    try std.json.stringify(state, .{}, writer);
    try writer.print(",\"priority\":{d}", .{account.priority});
    try writer.writeAll(",\"secret_backend\":");
    try std.json.stringify(account.secret.backend, .{}, writer);
    try writer.writeAll(",\"config_dir_set\":");
    try writer.writeAll(if (account.config_dir != null) "true" else "false");
    try writer.writeAll(",\"config_dir_env\":");
    if (runtime_mod.configDirEnv(prov, def, kind)) |env_var| try std.json.stringify(env_var, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"tags\":[");
    if (account.tags) |tags| {
        for (tags, 0..) |tag, idx| {
            if (idx > 0) try writer.writeByte(',');
            try std.json.stringify(tag, .{}, writer);
        }
    }
    try writer.writeAll("],\"runtime\":");
    try writeRuntimeReadinessJson(writer, info.readiness);
    try writer.writeAll(",\"writeback\":");
    try writeAccountWritebackJson(writer, account, def);
    try writer.writeAll(",\"capabilities\":[");
    for (def.capabilities, 0..) |capability, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeAccountCapabilityJson(writer, allocator, cfg, store, provider_name, account_name, def, capability);
    }
    try writer.writeAll("]}");
}

fn writeAccountCapabilityJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    provider_name: []const u8,
    account_name: []const u8,
    def: provider_schema.ProviderDefinition,
    capability: provider_schema.CapabilityDefinition,
) !void {
    const route = RepairPlanRoute{ .provider = provider_name, .account = account_name, .capability = capability.name };
    const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
    const health = routeHealth(store, route);
    const budget = routeProbeBudget(def, capability.name);
    const action = repairActionFor(route, def, runtime, health, budget);
    const selectable = routeSelectable(runtime, health);

    try writer.writeByte('{');
    try writer.writeAll("\"name\":");
    try std.json.stringify(capability.name, .{}, writer);
    try writer.writeAll(",\"proof_status\":");
    try std.json.stringify(capability.proof_status, .{}, writer);
    try writer.writeAll(",\"proof_requirements\":");
    try writeStringArrayJson(writer, capability.proof_requirements);
    try writer.writeAll(",\"budget\":");
    if (budget) |probe_budget| try std.json.stringify(@tagName(probe_budget), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessJson(writer, runtime);
    try writer.writeAll(",\"health_recorded\":");
    try writer.writeAll(if (health != null) "true" else "false");
    try writer.writeAll(",\"liveness\":");
    if (health) |h| try writeLivenessJson(writer, h.liveness) else try writer.writeAll("null");
    try writer.writeAll(",\"selectable\":");
    try writer.writeAll(if (selectable) "true" else "false");
    try writer.writeAll(",\"action\":");
    try writeRepairActionJson(writer, allocator, action, route);
    try writer.writeByte('}');
}

fn accountsProviderMatches(args: cli.Command.AccountsArgs, provider_name: []const u8, provider_kind: []const u8) bool {
    const provider_filter = args.provider orelse return true;
    return std.mem.eql(u8, provider_filter, provider_name) or std.mem.eql(u8, provider_filter, provider_kind);
}

fn accountEnrollmentState(
    store: *health_mod.HealthStore,
    provider_name: []const u8,
    account_name: []const u8,
    def: provider_schema.ProviderDefinition,
    runtime: types.RuntimeReadiness,
) []const u8 {
    if (!runtime.isReady()) return "action_needed";
    var has_evidence = false;

    const account_key = health_mod.accountKey(provider_name, account_name);
    if (store.accounts.get(account_key.slice())) |health| {
        has_evidence = true;
        if (livenessIsAvailable(health.liveness)) return "available";
    }

    for (def.capabilities) |capability| {
        const capability_key = health_mod.capabilityKey(provider_name, account_name, capability.name);
        if (store.accounts.get(capability_key.slice())) |health| {
            has_evidence = true;
            if (livenessIsAvailable(health.liveness)) return "available";
        }
    }

    return if (has_evidence) "has_evidence" else "configured";
}

fn livenessIsAvailable(liveness: types.CredentialLiveness) bool {
    return switch (liveness) {
        .live => |live| live.availability == .available,
        .degraded, .dead => false,
    };
}

fn runEnroll(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.EnrollArgs) !void {
    switch (args.action) {
        .plan => {
            var parsed_config: ?std.json.Parsed(config.Config) = config.load(allocator) catch null;
            defer if (parsed_config) |*parsed| parsed.deinit();
            const cfg: ?config.Config = if (parsed_config) |parsed| parsed.value else null;

            if (args.json) {
                try writeEnrollPlanJson(writer, allocator, cfg, args);
            } else {
                try writeEnrollPlanText(writer, allocator, cfg, args);
            }
        },
        .codex => try runEnrollCodex(allocator, writer, args),
        .claude => try runEnrollClaude(allocator, writer, args),
        .figma => try runEnrollFigma(allocator, writer, args),
    }
}

const EnrollCodexResult = struct {
    ok: bool,
    reason: []const u8,
    account: []const u8,
    store_root: []const u8,
    account_dir: []const u8,
    active_config: []const u8,
    backup_config: ?[]const u8 = null,
    config_changed: bool = false,
    store_bootstrapped: bool = false,
};

fn runEnrollCodex(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.EnrollArgs) !void {
    const account = args.account orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"missing_account\",\"mutates\":true,\"requires\":\"--account <name>\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux enroll plan codex --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll codex\n\n");
            try writer.writeAll("  missing required --account <name>\n");
            try writer.writeAll("  next: oauth-mux enroll plan codex --json\n");
        }
        return;
    };

    const store_root = try codexStoreRoot(allocator, .{ .store_root = args.store_root });
    defer allocator.free(store_root);
    const account_dir = try codexAccountDir(allocator, store_root, account);
    defer allocator.free(account_dir);
    const active_config_path = try paths.configFilePath(allocator);
    defer allocator.free(active_config_path);

    if (!args.confirm_enroll) {
        try writeEnrollCodexConfirmationRequired(writer, allocator, args, active_config_path, store_root, account_dir);
        return;
    }

    var active = config.loadFromPath(allocator, active_config_path) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":");
            try std.json.stringify(@errorName(e), .{}, writer);
            try writer.writeAll(",\"message\":\"active config is required before confirmed Codex enrollment\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux init --codex-max");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll codex\n\n");
            try writer.print("  config unavailable: {s}\n", .{@errorName(e)});
            try writer.writeAll("  next: oauth-mux init --codex-max\n");
        }
        return;
    };
    defer active.deinit();
    try config.validate(active.value, std.io.null_writer);

    if (!codexMaxShapeConfigured(active.value)) {
        try writeEnrollCodexRequiresCodexMax(writer, args.json);
        return;
    }

    var result = EnrollCodexResult{
        .ok = true,
        .reason = "enrolled_codex_account",
        .account = account,
        .store_root = store_root,
        .account_dir = account_dir,
        .active_config = active_config_path,
    };

    var backup_config: ?[]const u8 = null;
    defer if (backup_config) |backup| allocator.free(backup);

    const config_changed = !codexEnrollmentShapeConfigured(active.value, account);
    if (config_changed) {
        var config_buf = std.ArrayList(u8).init(allocator);
        defer config_buf.deinit();
        try writeCodexEnrollConfigJson(allocator, config_buf.writer(), active.value, store_root, account);

        const parsed = try config.loadFromBytes(allocator, config_buf.items);
        defer parsed.deinit();
        try config.validate(parsed.value, std.io.null_writer);
        if (!codexEnrollmentShapeConfigured(parsed.value, account)) return error.ConfigValidationError;

        backup_config = try defaultCodexConfigBackupPath(allocator, active_config_path);
        try writeActiveConfigAtomically(allocator, active_config_path, backup_config.?, config_buf.items);

        result.backup_config = backup_config.?;
        result.config_changed = true;
    } else {
        result.reason = "codex_account_already_configured";
    }

    if (args.json) {
        try bootstrapOneCodexDir(allocator, std.io.null_writer, store_root, account);
    } else {
        try bootstrapOneCodexDir(allocator, writer, store_root, account);
    }
    result.store_bootstrapped = true;

    try writeEnrollCodexResult(writer, allocator, result, args.json);
}

const EnrollClaudeResult = struct {
    ok: bool,
    reason: []const u8,
    account: []const u8,
    config_root: []const u8,
    account_dir: []const u8,
    active_config: []const u8,
    backup_config: ?[]const u8 = null,
    config_changed: bool = false,
    config_bootstrapped: bool = false,
};

fn runEnrollClaude(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.EnrollArgs) !void {
    const account = args.account orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"missing_account\",\"mutates\":true,\"requires\":\"--account <name>\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux enroll plan claude --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll claude\n\n");
            try writer.writeAll("  missing required --account <name>\n");
            try writer.writeAll("  next: oauth-mux enroll plan claude --json\n");
        }
        return;
    };

    const config_root = try claudeConfigRoot(allocator, args.store_root);
    defer allocator.free(config_root);
    const account_dir = try claudeAccountDir(allocator, config_root, account);
    defer allocator.free(account_dir);
    const active_config_path = try paths.configFilePath(allocator);
    defer allocator.free(active_config_path);

    if (!args.confirm_enroll) {
        try writeEnrollClaudeConfirmationRequired(writer, allocator, args, active_config_path, config_root, account_dir);
        return;
    }

    var active = config.loadFromPath(allocator, active_config_path) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":");
            try std.json.stringify(@errorName(e), .{}, writer);
            try writer.writeAll(",\"message\":\"active config is required before confirmed Claude enrollment\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux init");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll claude\n\n");
            try writer.print("  config unavailable: {s}\n", .{@errorName(e)});
            try writer.writeAll("  next: oauth-mux init\n");
        }
        return;
    };
    defer active.deinit();
    try config.validate(active.value, std.io.null_writer);

    var result = EnrollClaudeResult{
        .ok = true,
        .reason = "enrolled_claude_account",
        .account = account,
        .config_root = config_root,
        .account_dir = account_dir,
        .active_config = active_config_path,
    };

    var backup_config: ?[]const u8 = null;
    defer if (backup_config) |backup| allocator.free(backup);

    const config_changed = !claudeEnrollmentShapeConfigured(active.value, account);
    if (config_changed) {
        var config_buf = std.ArrayList(u8).init(allocator);
        defer config_buf.deinit();
        try writeClaudeEnrollConfigJson(allocator, config_buf.writer(), active.value, config_root, account);

        const parsed = try config.loadFromBytes(allocator, config_buf.items);
        defer parsed.deinit();
        try config.validate(parsed.value, std.io.null_writer);
        if (!claudeEnrollmentShapeConfigured(parsed.value, account)) return error.ConfigValidationError;

        backup_config = try defaultCodexConfigBackupPath(allocator, active_config_path);
        try writeActiveConfigAtomically(allocator, active_config_path, backup_config.?, config_buf.items);

        result.backup_config = backup_config.?;
        result.config_changed = true;
    } else {
        result.reason = "claude_account_already_configured";
    }

    if (args.json) {
        try bootstrapOneClaudeDir(allocator, std.io.null_writer, config_root, account);
    } else {
        try bootstrapOneClaudeDir(allocator, writer, config_root, account);
    }
    result.config_bootstrapped = true;

    try writeEnrollClaudeResult(writer, allocator, result, args.json);
}

const EnrollFigmaResult = struct {
    ok: bool,
    reason: []const u8,
    account: []const u8,
    mode: []const u8,
    provider: []const u8,
    profile: []const u8,
    capability: []const u8,
    secret_env: []const u8,
    active_config: []const u8,
    backup_config: ?[]const u8 = null,
    config_changed: bool = false,
};

fn runEnrollFigma(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.EnrollArgs) !void {
    const account = args.account orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"missing_account\",\"mutates\":true,\"requires\":\"--account <name>\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux enroll plan figma --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll figma\n\n");
            try writer.writeAll("  missing required --account <name>\n");
            try writer.writeAll("  next: oauth-mux enroll plan figma --json\n");
        }
        return;
    };

    const mode = figmaEnrollmentMode(args.mode);
    const provider_name = figmaProviderForMode(mode);
    const profile_name = provider_name;
    const capability = figmaCapabilityForMode(mode);
    const secret_env = if (args.secret_env) |value|
        try allocator.dupe(u8, value)
    else
        try figmaDefaultSecretEnv(allocator, account, mode);
    defer allocator.free(secret_env);

    const active_config_path = try paths.configFilePath(allocator);
    defer allocator.free(active_config_path);

    if (!args.confirm_enroll) {
        try writeEnrollFigmaConfirmationRequired(writer, allocator, args, active_config_path, provider_name, profile_name, capability, secret_env);
        return;
    }

    var active = config.loadFromPath(allocator, active_config_path) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":");
            try std.json.stringify(@errorName(e), .{}, writer);
            try writer.writeAll(",\"message\":\"active config is required before confirmed Figma enrollment\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux init");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux enroll figma\n\n");
            try writer.print("  config unavailable: {s}\n", .{@errorName(e)});
            try writer.writeAll("  next: oauth-mux init\n");
        }
        return;
    };
    defer active.deinit();
    try config.validate(active.value, std.io.null_writer);

    var result = EnrollFigmaResult{
        .ok = true,
        .reason = "enrolled_figma_account",
        .account = account,
        .mode = mode,
        .provider = provider_name,
        .profile = profile_name,
        .capability = capability,
        .secret_env = secret_env,
        .active_config = active_config_path,
    };

    var backup_config: ?[]const u8 = null;
    defer if (backup_config) |backup| allocator.free(backup);

    const config_changed = !figmaEnrollmentShapeConfigured(active.value, provider_name, profile_name, account, capability);
    if (config_changed) {
        var config_buf = std.ArrayList(u8).init(allocator);
        defer config_buf.deinit();
        try writeFigmaEnrollConfigJson(config_buf.writer(), active.value, provider_name, profile_name, account, mode, capability, secret_env);

        const parsed = try config.loadFromBytes(allocator, config_buf.items);
        defer parsed.deinit();
        try config.validate(parsed.value, std.io.null_writer);
        if (!figmaEnrollmentShapeConfigured(parsed.value, provider_name, profile_name, account, capability)) return error.ConfigValidationError;

        backup_config = try defaultCodexConfigBackupPath(allocator, active_config_path);
        try writeActiveConfigAtomically(allocator, active_config_path, backup_config.?, config_buf.items);

        result.backup_config = backup_config.?;
        result.config_changed = true;
    } else {
        result.reason = "figma_account_already_configured";
    }

    try writeEnrollFigmaResult(writer, allocator, result, args.json);
}

fn writeEnrollCodexConfirmationRequired(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.EnrollArgs,
    active_config_path: []const u8,
    store_root: []const u8,
    account_dir: []const u8,
) !void {
    const account = args.account orelse "<account>";
    const confirm_command = try enrollCodexConfirmCommand(allocator, account, args.store_root, args.json);
    defer allocator.free(confirm_command);

    if (args.json) {
        try writer.writeAll("{\"ok\":false,\"executed\":false,\"confirmation_required\":true,\"requires\":\"--confirm-enroll\",\"mutates\":true,\"interactive\":false,\"spends_provider_calls\":false,\"provider\":\"codex\",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(active_config_path, .{}, writer);
        try writer.writeAll(",\"store_root\":");
        try std.json.stringify(store_root, .{}, writer);
        try writer.writeAll(",\"account_dir\":");
        try std.json.stringify(account_dir, .{}, writer);
        try writer.writeAll(",\"confirm_command\":");
        try std.json.stringify(confirm_command, .{}, writer);
        try writer.writeAll(",\"plan\":");
        try writeEnrollPlanJsonInline(writer, allocator, args);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll codex\n\n");
    try writer.writeAll("  confirmation required: --confirm-enroll\n");
    try writer.writeAll("  mutates: active oauth-mux config and local Codex account directory\n");
    try writer.writeAll("  does not run: codex login, provider probes, browser/device auth\n\n");
    try writer.print("  active config: {s}\n", .{active_config_path});
    try writer.print("  store root:    {s}\n", .{store_root});
    try writer.print("  account dir:   {s}\n\n", .{account_dir});
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{confirm_command});
}

fn writeEnrollClaudeConfirmationRequired(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.EnrollArgs,
    active_config_path: []const u8,
    config_root: []const u8,
    account_dir: []const u8,
) !void {
    const account = args.account orelse "<account>";
    const confirm_command = try enrollClaudeConfirmCommand(allocator, account, args.store_root, args.json);
    defer allocator.free(confirm_command);

    if (args.json) {
        try writer.writeAll("{\"ok\":false,\"executed\":false,\"confirmation_required\":true,\"requires\":\"--confirm-enroll\",\"mutates\":true,\"interactive\":false,\"spends_provider_calls\":false,\"provider\":\"claude\",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(active_config_path, .{}, writer);
        try writer.writeAll(",\"config_root\":");
        try std.json.stringify(config_root, .{}, writer);
        try writer.writeAll(",\"account_dir\":");
        try std.json.stringify(account_dir, .{}, writer);
        try writer.writeAll(",\"confirm_command\":");
        try std.json.stringify(confirm_command, .{}, writer);
        try writer.writeAll(",\"plan\":");
        try writeEnrollPlanJsonInline(writer, allocator, args);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll claude\n\n");
    try writer.writeAll("  confirmation required: --confirm-enroll\n");
    try writer.writeAll("  mutates: active oauth-mux config and local Claude config directory\n");
    try writer.writeAll("  does not run: claude auth login, provider probes, browser/device auth\n\n");
    try writer.print("  active config: {s}\n", .{active_config_path});
    try writer.print("  config root:   {s}\n", .{config_root});
    try writer.print("  account dir:   {s}\n\n", .{account_dir});
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{confirm_command});
}

fn writeEnrollFigmaConfirmationRequired(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.EnrollArgs,
    active_config_path: []const u8,
    provider_name: []const u8,
    profile_name: []const u8,
    capability: []const u8,
    secret_env: []const u8,
) !void {
    const account = args.account orelse "<account>";
    const confirm_command = try enrollFigmaConfirmCommand(allocator, account, args.mode, args.secret_env, args.json);
    defer allocator.free(confirm_command);
    const probe_command = try enrollProbeCommand(allocator, provider_name, args.account, capability);
    defer allocator.free(probe_command);

    if (args.json) {
        try writer.writeAll("{\"ok\":false,\"executed\":false,\"confirmation_required\":true,\"requires\":\"--confirm-enroll\",\"mutates\":true,\"interactive\":false,\"spends_provider_calls\":false,\"provider\":\"figma\",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"mode\":");
        try std.json.stringify(figmaEnrollmentMode(args.mode), .{}, writer);
        try writer.writeAll(",\"config_provider\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"profile\":");
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeAll(",\"capability\":");
        try std.json.stringify(capability, .{}, writer);
        try writer.writeAll(",\"secret_backend\":\"env\",\"secret_env\":");
        try std.json.stringify(secret_env, .{}, writer);
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(active_config_path, .{}, writer);
        try writer.writeAll(",\"confirm_command\":");
        try std.json.stringify(confirm_command, .{}, writer);
        try writer.writeAll(",\"proof_command\":");
        try std.json.stringify(probe_command, .{}, writer);
        try writer.writeAll(",\"plan\":");
        try writeEnrollPlanJsonInline(writer, allocator, args);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll figma\n\n");
    try writer.writeAll("  confirmation required: --confirm-enroll\n");
    try writer.writeAll("  mutates: active oauth-mux config only\n");
    try writer.writeAll("  does not create: Figma token material, OAuth browser auth, provider probes\n\n");
    try writer.print("  active config: {s}\n", .{active_config_path});
    try writer.print("  provider:      {s}\n", .{provider_name});
    try writer.print("  profile:       {s}\n", .{profile_name});
    try writer.print("  capability:    {s}\n", .{capability});
    try writer.print("  secret env:    {s}\n\n", .{secret_env});
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{confirm_command});
}

fn writeEnrollPlanJsonInline(writer: anytype, allocator: std.mem.Allocator, args: cli.Command.EnrollArgs) !void {
    var parsed_config: ?std.json.Parsed(config.Config) = config.load(allocator) catch null;
    defer if (parsed_config) |*parsed| parsed.deinit();
    const cfg: ?config.Config = if (parsed_config) |parsed| parsed.value else null;
    const provider_name = args.provider orelse "codex";

    const plan_args = cli.Command.EnrollArgs{
        .action = .plan,
        .provider = provider_name,
        .account = args.account,
        .mode = args.mode,
        .store_root = args.store_root,
        .secret_env = args.secret_env,
        .json = true,
    };

    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"action\":\"plan\",\"mutates\":false,\"provider\":");
    try std.json.stringify(provider_name, .{}, writer);
    try writer.writeAll(",\"account\":");
    if (plan_args.account) |account| try std.json.stringify(account, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"mode\":");
    if (plan_args.mode) |mode| try std.json.stringify(mode, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"configured\":");
    try writer.writeAll(if (cfg != null) "true" else "false");
    try writer.writeAll(",\"provider_configured\":");
    try writer.writeAll(if (enrollProviderConfigured(cfg, provider_name)) "true" else "false");
    try writer.writeAll(",\"provider_neutral_mutation_supported\":");
    try writer.writeAll(if (enrollMutationSupported(provider_name)) "true" else "false");
    try writer.writeAll(",\"existing_accounts\":[");
    try writeEnrollExistingAccountsJson(writer, cfg, provider_name);
    try writer.writeAll("],\"steps\":[");
    try writeEnrollPlanStepsJson(writer, allocator, plan_args);
    try writer.writeAll("]}");
}

fn writeEnrollCodexRequiresCodexMax(writer: anytype, json: bool) !void {
    if (json) {
        try writer.writeAll("{\"ok\":false,\"executed\":false,\"error\":\"requires_codex_max_config\",\"message\":\"confirmed Codex enrollment requires the active config to already have codex-max and codex-mini profiles\",\"next_commands\":[");
        try writeCommandJson(writer, "oauth-mux codex config-candidate --json");
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux codex config-merge --candidate ~/.config/oauth-mux/codex-max.config.json --json");
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll codex\n\n");
    try writer.writeAll("  active config is not a Codex Max mux shape yet.\n");
    try writer.writeAll("  next:\n");
    try writer.writeAll("    oauth-mux codex config-candidate --json\n");
    try writer.writeAll("    oauth-mux codex config-merge --candidate ~/.config/oauth-mux/codex-max.config.json --json\n");
}

fn writeEnrollCodexResult(writer: anytype, allocator: std.mem.Allocator, result: EnrollCodexResult, json: bool) !void {
    const login_command = try enrollCodexLoginCommand(allocator, result.account);
    defer allocator.free(login_command);
    const runtime_command = try enrollRuntimeCommand(allocator, "codex", result.account, "codex-max");
    defer allocator.free(runtime_command);
    const accounts_command = try enrollAccountsCommand(allocator, "codex");
    defer allocator.free(accounts_command);

    if (json) {
        try writer.writeAll("{\"ok\":");
        try writer.writeAll(if (result.ok) "true" else "false");
        try writer.writeAll(",\"executed\":true,\"provider\":\"codex\",\"account\":");
        try std.json.stringify(result.account, .{}, writer);
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(result.reason, .{}, writer);
        try writer.writeAll(",\"config_changed\":");
        try writer.writeAll(if (result.config_changed) "true" else "false");
        try writer.writeAll(",\"store_bootstrapped\":");
        try writer.writeAll(if (result.store_bootstrapped) "true" else "false");
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(result.active_config, .{}, writer);
        try writer.writeAll(",\"backup_config\":");
        if (result.backup_config) |backup| try std.json.stringify(backup, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"store_root\":");
        try std.json.stringify(result.store_root, .{}, writer);
        try writer.writeAll(",\"account_dir\":");
        try std.json.stringify(result.account_dir, .{}, writer);
        try writer.writeAll(",\"ran_provider_login\":false,\"spends_provider_calls\":false,\"next_commands\":[");
        try writeCommandJson(writer, login_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, runtime_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, accounts_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json");
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll codex\n\n");
    try writer.print("  account:             {s}\n", .{result.account});
    try writer.print("  config changed:      {s}\n", .{if (result.config_changed) "yes" else "no"});
    if (result.backup_config) |backup| try writer.print("  backup config:       {s}\n", .{backup});
    try writer.print("  account dir:         {s}\n", .{result.account_dir});
    try writer.writeAll("  provider login run:  no\n\n");
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{login_command});
    try writer.print("  {s}\n", .{runtime_command});
    try writer.print("  {s}\n", .{accounts_command});
    try writer.writeAll("  oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json\n");
}

fn writeEnrollClaudeResult(writer: anytype, allocator: std.mem.Allocator, result: EnrollClaudeResult, json: bool) !void {
    const login_command = try enrollClaudeLoginCommand(allocator, result.account_dir);
    defer allocator.free(login_command);
    const runtime_command = try enrollRuntimeCommand(allocator, "claude", result.account, "auth-status");
    defer allocator.free(runtime_command);
    const accounts_command = try enrollAccountsCommand(allocator, "claude");
    defer allocator.free(accounts_command);

    if (json) {
        try writer.writeAll("{\"ok\":");
        try writer.writeAll(if (result.ok) "true" else "false");
        try writer.writeAll(",\"executed\":true,\"provider\":\"claude\",\"account\":");
        try std.json.stringify(result.account, .{}, writer);
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(result.reason, .{}, writer);
        try writer.writeAll(",\"config_changed\":");
        try writer.writeAll(if (result.config_changed) "true" else "false");
        try writer.writeAll(",\"config_bootstrapped\":");
        try writer.writeAll(if (result.config_bootstrapped) "true" else "false");
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(result.active_config, .{}, writer);
        try writer.writeAll(",\"backup_config\":");
        if (result.backup_config) |backup| try std.json.stringify(backup, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"config_root\":");
        try std.json.stringify(result.config_root, .{}, writer);
        try writer.writeAll(",\"account_dir\":");
        try std.json.stringify(result.account_dir, .{}, writer);
        try writer.writeAll(",\"ran_provider_login\":false,\"spends_provider_calls\":false,\"next_commands\":[");
        try writeCommandJson(writer, login_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, runtime_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, accounts_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux stay-afloat refresh --profile claude --capability auth-status --json");
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll claude\n\n");
    try writer.print("  account:             {s}\n", .{result.account});
    try writer.print("  config changed:      {s}\n", .{if (result.config_changed) "yes" else "no"});
    if (result.backup_config) |backup| try writer.print("  backup config:       {s}\n", .{backup});
    try writer.print("  account dir:         {s}\n", .{result.account_dir});
    try writer.writeAll("  provider login run:  no\n\n");
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{login_command});
    try writer.print("  {s}\n", .{runtime_command});
    try writer.print("  {s}\n", .{accounts_command});
    try writer.writeAll("  oauth-mux stay-afloat refresh --profile claude --capability auth-status --json\n");
}

fn writeEnrollFigmaResult(writer: anytype, allocator: std.mem.Allocator, result: EnrollFigmaResult, json: bool) !void {
    const accounts_command = try enrollAccountsCommand(allocator, "figma");
    defer allocator.free(accounts_command);
    const probe_command = try enrollProbeCommand(allocator, result.provider, result.account, result.capability);
    defer allocator.free(probe_command);
    const export_command = try figmaSecretExportCommand(allocator, result.secret_env);
    defer allocator.free(export_command);

    if (json) {
        try writer.writeAll("{\"ok\":");
        try writer.writeAll(if (result.ok) "true" else "false");
        try writer.writeAll(",\"executed\":true,\"provider\":\"figma\",\"account\":");
        try std.json.stringify(result.account, .{}, writer);
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(result.reason, .{}, writer);
        try writer.writeAll(",\"mode\":");
        try std.json.stringify(result.mode, .{}, writer);
        try writer.writeAll(",\"config_provider\":");
        try std.json.stringify(result.provider, .{}, writer);
        try writer.writeAll(",\"profile\":");
        try std.json.stringify(result.profile, .{}, writer);
        try writer.writeAll(",\"capability\":");
        try std.json.stringify(result.capability, .{}, writer);
        try writer.writeAll(",\"secret_backend\":\"env\",\"secret_env\":");
        try std.json.stringify(result.secret_env, .{}, writer);
        try writer.writeAll(",\"config_changed\":");
        try writer.writeAll(if (result.config_changed) "true" else "false");
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(result.active_config, .{}, writer);
        try writer.writeAll(",\"backup_config\":");
        if (result.backup_config) |backup| try std.json.stringify(backup, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"created_secret\":false,\"ran_provider_login\":false,\"spends_provider_calls\":false,\"next_commands\":[");
        try writeCommandJson(writer, export_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux config validate");
        try writer.writeByte(',');
        try writeCommandJson(writer, accounts_command);
        try writer.writeByte(',');
        try writeCommandJson(writer, probe_command);
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux enroll figma\n\n");
    try writer.print("  account:             {s}\n", .{result.account});
    try writer.print("  mode:                {s}\n", .{result.mode});
    try writer.print("  provider/profile:    {s} / {s}\n", .{ result.provider, result.profile });
    try writer.print("  capability:          {s}\n", .{result.capability});
    try writer.print("  secret env:          {s}\n", .{result.secret_env});
    try writer.print("  config changed:      {s}\n", .{if (result.config_changed) "yes" else "no"});
    if (result.backup_config) |backup| try writer.print("  backup config:       {s}\n", .{backup});
    try writer.writeAll("  provider login run:  no\n\n");
    try writer.writeAll("next:\n");
    try writer.print("  {s}\n", .{export_command});
    try writer.writeAll("  oauth-mux config validate\n");
    try writer.print("  {s}\n", .{accounts_command});
    try writer.print("  {s}\n", .{probe_command});
}

fn enrollCodexConfirmCommand(allocator: std.mem.Allocator, account: []const u8, store_root: ?[]const u8, json: bool) ![]const u8 {
    if (store_root) |root| {
        return try std.fmt.allocPrint(allocator, "oauth-mux enroll codex --account {s} --store-root {s} --confirm-enroll{s}", .{
            account,
            root,
            if (json) " --json" else "",
        });
    }
    return try std.fmt.allocPrint(allocator, "oauth-mux enroll codex --account {s} --confirm-enroll{s}", .{
        account,
        if (json) " --json" else "",
    });
}

fn enrollClaudeConfirmCommand(allocator: std.mem.Allocator, account: []const u8, config_root: ?[]const u8, json: bool) ![]const u8 {
    if (config_root) |root| {
        return try std.fmt.allocPrint(allocator, "oauth-mux enroll claude --account {s} --config-root {s} --confirm-enroll{s}", .{
            account,
            root,
            if (json) " --json" else "",
        });
    }
    return try std.fmt.allocPrint(allocator, "oauth-mux enroll claude --account {s} --confirm-enroll{s}", .{
        account,
        if (json) " --json" else "",
    });
}

fn enrollClaudeLoginCommand(allocator: std.mem.Allocator, account_dir: []const u8) ![]const u8 {
    const quoted_dir = try shellQuoteAlloc(allocator, account_dir);
    defer allocator.free(quoted_dir);
    return try std.fmt.allocPrint(allocator, "env CLAUDE_CONFIG_DIR={s} claude auth login", .{quoted_dir});
}

fn enrollFigmaConfirmCommand(
    allocator: std.mem.Allocator,
    account: []const u8,
    mode: ?[]const u8,
    secret_env: ?[]const u8,
    json: bool,
) ![]const u8 {
    var command = std.ArrayList(u8).init(allocator);
    errdefer command.deinit();
    try command.appendSlice("oauth-mux enroll figma --account ");
    try command.appendSlice(account);
    if (mode) |value| {
        try command.appendSlice(" --mode ");
        try command.appendSlice(value);
    }
    if (secret_env) |value| {
        try command.appendSlice(" --secret-env ");
        try command.appendSlice(value);
    }
    try command.appendSlice(" --confirm-enroll");
    if (json) try command.appendSlice(" --json");
    return command.toOwnedSlice();
}

fn figmaSecretExportCommand(allocator: std.mem.Allocator, secret_env: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "export {s}=<figma-token>", .{secret_env});
}

fn codexEnrollmentShapeConfigured(cfg: config.Config, account: []const u8) bool {
    const codex_provider = cfg.providers.map.get("codex") orelse return false;
    if (codex_provider.accounts.map.get(account) == null) return false;

    const max_route = health_mod.capabilityKey("codex", account, "codex-max");
    const mini_route = health_mod.capabilityKey("codex", account, "codex-mini");
    return profileContainsProvider(cfg, "codex-max", max_route.slice()) and
        profileContainsProvider(cfg, "codex-mini", mini_route.slice());
}

fn claudeEnrollmentShapeConfigured(cfg: config.Config, account: []const u8) bool {
    const claude_provider = cfg.providers.map.get("claude") orelse return false;
    if (claude_provider.accounts.map.get(account) == null) return false;

    const route = health_mod.capabilityKey("claude", account, "auth-status");
    return profileContainsProvider(cfg, "claude", route.slice());
}

fn figmaEnrollmentShapeConfigured(
    cfg: config.Config,
    provider_name: []const u8,
    profile_name: []const u8,
    account: []const u8,
    capability: []const u8,
) bool {
    const figma_provider = cfg.providers.map.get(provider_name) orelse return false;
    if (figma_provider.accounts.map.get(account) == null) return false;

    const route = health_mod.capabilityKey(provider_name, account, capability);
    return profileContainsProvider(cfg, profile_name, route.slice());
}

fn profileContainsProvider(cfg: config.Config, profile_name: []const u8, provider_ref: []const u8) bool {
    const profile = cfg.profiles.map.get(profile_name) orelse return false;
    for (profile.providers) |existing| {
        if (std.mem.eql(u8, existing, provider_ref)) return true;
    }
    return false;
}

fn writeCodexEnrollConfigJson(
    allocator: std.mem.Allocator,
    writer: anytype,
    active: config.Config,
    store_root: []const u8,
    account: []const u8,
) !void {
    try writer.writeAll("{\"version\":");
    try writer.print("{d}", .{active.version});
    try writer.writeAll(",\"defaults\":");
    try std.json.stringify(active.defaults, .{}, writer);
    try writer.writeAll(",\"policy\":");
    try std.json.stringify(active.policy, .{}, writer);
    try writer.writeAll(",\"provider_definitions\":");
    try std.json.stringify(active.provider_definitions, .{}, writer);
    try writer.writeAll(",\"providers\":{");

    var first = true;
    var provider_it = active.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, entry.key_ptr.*, "codex")) {
            try writeCodexProviderWithEnrollment(allocator, writer, entry.value_ptr.*, store_root, account);
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }

    try writer.writeAll("},\"profiles\":{");
    first = true;
    var profile_it = active.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        const profile_name = entry.key_ptr.*;
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, profile_name, "codex-max")) {
            const route = health_mod.capabilityKey("codex", account, "codex-max");
            try writeProfileWithAddedProvider(writer, entry.value_ptr.*, route.slice());
        } else if (std.mem.eql(u8, profile_name, "codex-mini")) {
            const route = health_mod.capabilityKey("codex", account, "codex-mini");
            try writeProfileWithAddedProvider(writer, entry.value_ptr.*, route.slice());
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }

    try writer.writeAll("},\"strategies\":");
    try std.json.stringify(active.strategies, .{}, writer);
    try writer.writeAll("}\n");
}

fn writeClaudeEnrollConfigJson(
    allocator: std.mem.Allocator,
    writer: anytype,
    active: config.Config,
    config_root: []const u8,
    account: []const u8,
) !void {
    try writer.writeAll("{\"version\":");
    try writer.print("{d}", .{active.version});
    try writer.writeAll(",\"defaults\":");
    try std.json.stringify(active.defaults, .{}, writer);
    try writer.writeAll(",\"policy\":");
    try std.json.stringify(active.policy, .{}, writer);
    try writer.writeAll(",\"provider_definitions\":");
    try std.json.stringify(active.provider_definitions, .{}, writer);
    try writer.writeAll(",\"providers\":{");

    var first = true;
    var wrote_claude = false;
    var provider_it = active.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, entry.key_ptr.*, "claude")) {
            try writeClaudeProviderWithEnrollment(allocator, writer, entry.value_ptr.*, config_root, account);
            wrote_claude = true;
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }
    if (!wrote_claude) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify("claude", .{}, writer);
        try writer.writeByte(':');
        try writeClaudeProviderWithEnrollment(allocator, writer, null, config_root, account);
    }

    const route = health_mod.capabilityKey("claude", account, "auth-status");
    const profile_strategy = enrollmentProfileStrategy(active);

    try writer.writeAll("},\"profiles\":{");
    first = true;
    var wrote_claude_profile = false;
    var profile_it = active.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        const profile_name = entry.key_ptr.*;
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, profile_name, "claude")) {
            try writeProfileWithAddedProvider(writer, entry.value_ptr.*, route.slice());
            wrote_claude_profile = true;
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }
    if (!wrote_claude_profile) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify("claude", .{}, writer);
        try writer.writeByte(':');
        try writeSingleRouteProfile(writer, route.slice(), profile_strategy);
    }

    try writer.writeAll("},\"strategies\":");
    try std.json.stringify(active.strategies, .{}, writer);
    try writer.writeAll("}\n");
}

fn writeFigmaEnrollConfigJson(
    writer: anytype,
    active: config.Config,
    provider_name: []const u8,
    profile_name: []const u8,
    account: []const u8,
    mode: []const u8,
    capability: []const u8,
    secret_env: []const u8,
) !void {
    try writer.writeAll("{\"version\":");
    try writer.print("{d}", .{active.version});
    try writer.writeAll(",\"defaults\":");
    try std.json.stringify(active.defaults, .{}, writer);
    try writer.writeAll(",\"policy\":");
    try std.json.stringify(active.policy, .{}, writer);
    try writer.writeAll(",\"provider_definitions\":");
    try std.json.stringify(active.provider_definitions, .{}, writer);
    try writer.writeAll(",\"providers\":{");

    var first = true;
    var wrote_figma = false;
    var provider_it = active.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, entry.key_ptr.*, provider_name)) {
            try writeFigmaProviderWithEnrollment(writer, entry.value_ptr.*, account, mode, secret_env);
            wrote_figma = true;
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }
    if (!wrote_figma) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeByte(':');
        try writeFigmaProviderWithEnrollment(writer, null, account, mode, secret_env);
    }

    const route = health_mod.capabilityKey(provider_name, account, capability);
    const profile_strategy = enrollmentProfileStrategy(active);

    try writer.writeAll("},\"profiles\":{");
    first = true;
    var wrote_figma_profile = false;
    var profile_it = active.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        const current_profile_name = entry.key_ptr.*;
        try std.json.stringify(current_profile_name, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, current_profile_name, profile_name)) {
            try writeProfileWithAddedProvider(writer, entry.value_ptr.*, route.slice());
            wrote_figma_profile = true;
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }
    if (!wrote_figma_profile) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeByte(':');
        try writeSingleRouteProfile(writer, route.slice(), profile_strategy);
    }

    try writer.writeAll("},\"strategies\":");
    try std.json.stringify(active.strategies, .{}, writer);
    try writer.writeAll("}\n");
}

fn writeCodexProviderWithEnrollment(
    allocator: std.mem.Allocator,
    writer: anytype,
    active_provider: config.ProviderConfig,
    store_root: []const u8,
    account: []const u8,
) !void {
    try writer.writeAll("{\"kind\":");
    try std.json.stringify(active_provider.kind, .{}, writer);
    try writer.writeAll(",\"config_dir_env\":");
    if (active_provider.config_dir_env) |config_dir_env| {
        try std.json.stringify(config_dir_env, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"accounts\":{");

    var first = true;
    var next_priority: i32 = 10;
    var account_it = active_provider.accounts.map.iterator();
    while (account_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.writeByte(':');
        try std.json.stringify(entry.value_ptr.*, .{}, writer);
        if (entry.value_ptr.priority <= next_priority) next_priority = entry.value_ptr.priority - 10;
    }

    if (active_provider.accounts.map.get(account) == null) {
        if (!first) try writer.writeByte(',');
        try writeCodexMaxStarterAccount(allocator, writer, store_root, account, next_priority, true);
    }

    try writer.writeAll("}}");
}

fn writeClaudeProviderWithEnrollment(
    allocator: std.mem.Allocator,
    writer: anytype,
    active_provider: ?config.ProviderConfig,
    config_root: []const u8,
    account: []const u8,
) !void {
    try writer.writeAll("{\"kind\":");
    if (active_provider) |provider_cfg| {
        try std.json.stringify(provider_cfg.kind, .{}, writer);
    } else {
        try std.json.stringify("claude", .{}, writer);
    }
    try writer.writeAll(",\"config_dir_env\":");
    if (active_provider) |provider_cfg| {
        if (provider_cfg.config_dir_env) |config_dir_env| {
            try std.json.stringify(config_dir_env, .{}, writer);
        } else {
            try std.json.stringify("CLAUDE_CONFIG_DIR", .{}, writer);
        }
    } else {
        try std.json.stringify("CLAUDE_CONFIG_DIR", .{}, writer);
    }
    try writer.writeAll(",\"accounts\":{");

    var first = true;
    var next_priority: i32 = 10;
    var account_present = false;
    if (active_provider) |provider_cfg| {
        var account_it = provider_cfg.accounts.map.iterator();
        while (account_it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try std.json.stringify(entry.key_ptr.*, .{}, writer);
            try writer.writeByte(':');
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
            if (entry.value_ptr.priority <= next_priority) next_priority = entry.value_ptr.priority - 10;
            if (std.mem.eql(u8, entry.key_ptr.*, account)) account_present = true;
        }
    }

    if (!account_present) {
        if (!first) try writer.writeByte(',');
        try writeClaudeStarterAccount(allocator, writer, config_root, account, next_priority);
    }

    try writer.writeAll("}}");
}

fn writeClaudeStarterAccount(
    allocator: std.mem.Allocator,
    writer: anytype,
    config_root: []const u8,
    account: []const u8,
    priority: i32,
) !void {
    const account_dir = try std.fs.path.join(allocator, &.{ config_root, account });
    defer allocator.free(account_dir);
    const credentials_path = try std.fs.path.join(allocator, &.{ account_dir, ".credentials.json" });
    defer allocator.free(credentials_path);

    try std.json.stringify(account, .{}, writer);
    try writer.writeAll(":{\"priority\":");
    try writer.print("{d}", .{priority});
    try writer.writeAll(",\"config_dir\":");
    try std.json.stringify(account_dir, .{}, writer);
    try writer.writeAll(",\"secret\":{\"backend\":\"file\",\"path\":");
    try std.json.stringify(credentials_path, .{}, writer);
    try writer.writeAll("},\"tags\":[\"oauth\",\"claude\"]}");
}

fn writeFigmaProviderWithEnrollment(
    writer: anytype,
    active_provider: ?config.ProviderConfig,
    account: []const u8,
    mode: []const u8,
    secret_env: []const u8,
) !void {
    try writer.writeAll("{\"kind\":");
    if (active_provider) |provider_cfg| {
        try std.json.stringify(provider_cfg.kind, .{}, writer);
    } else {
        try std.json.stringify("figma", .{}, writer);
    }
    try writer.writeAll(",\"config_dir_env\":");
    if (active_provider) |provider_cfg| {
        if (provider_cfg.config_dir_env) |config_dir_env| {
            try std.json.stringify(config_dir_env, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"accounts\":{");

    var first = true;
    var next_priority: i32 = 10;
    var account_present = false;
    if (active_provider) |provider_cfg| {
        var account_it = provider_cfg.accounts.map.iterator();
        while (account_it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try std.json.stringify(entry.key_ptr.*, .{}, writer);
            try writer.writeByte(':');
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
            if (entry.value_ptr.priority <= next_priority) next_priority = entry.value_ptr.priority - 10;
            if (std.mem.eql(u8, entry.key_ptr.*, account)) account_present = true;
        }
    }

    if (!account_present) {
        if (!first) try writer.writeByte(',');
        try writeFigmaStarterAccount(writer, account, mode, secret_env, next_priority);
    }

    try writer.writeAll("}}");
}

fn writeFigmaStarterAccount(
    writer: anytype,
    account: []const u8,
    mode: []const u8,
    secret_env: []const u8,
    priority: i32,
) !void {
    try std.json.stringify(account, .{}, writer);
    try writer.writeAll(":{\"priority\":");
    try writer.print("{d}", .{priority});
    try writer.writeAll(",\"secret\":{\"backend\":\"env\",\"variable\":");
    try std.json.stringify(secret_env, .{}, writer);
    try writer.writeAll("},\"tags\":[");
    try std.json.stringify(mode, .{}, writer);
    try writer.writeAll(",\"figma\"]}");
}

fn writeProfileWithAddedProvider(writer: anytype, profile: config.ProfileConfig, provider_ref: []const u8) !void {
    try writer.writeAll("{\"providers\":[");
    var first = true;
    var already_present = false;
    for (profile.providers) |existing| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(existing, .{}, writer);
        if (std.mem.eql(u8, existing, provider_ref)) already_present = true;
    }
    if (!already_present) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify(provider_ref, .{}, writer);
    }
    try writer.writeAll("],\"strategy\":");
    if (profile.strategy) |strategy| {
        try std.json.stringify(strategy, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"affinity_ttl_minutes\":{d}}}", .{profile.affinity_ttl_minutes});
}

fn writeSingleRouteProfile(writer: anytype, provider_ref: []const u8, strategy: ?[]const u8) !void {
    try writer.writeAll("{\"providers\":[");
    try std.json.stringify(provider_ref, .{}, writer);
    try writer.writeAll("],\"strategy\":");
    if (strategy) |strategy_name| {
        try std.json.stringify(strategy_name, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"affinity_ttl_minutes\":20}");
}

fn enrollmentProfileStrategy(cfg: config.Config) ?[]const u8 {
    const strategy = cfg.defaults.strategy orelse return null;
    if (cfg.strategies.map.get(strategy) == null) return null;
    return strategy;
}

fn writeActiveConfigAtomically(allocator: std.mem.Allocator, active_config_path: []const u8, backup_path: []const u8, bytes: []const u8) !void {
    if (fileExistsAbsolute(backup_path)) return error.PathAlreadyExists;
    if (std.fs.path.dirname(active_config_path)) |dir| try std.fs.cwd().makePath(dir);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ active_config_path, std.crypto.random.int(u64) });
    defer allocator.free(tmp_path);

    const tmp_file = try std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 });
    errdefer std.fs.deleteFileAbsolute(tmp_path) catch {};
    {
        defer tmp_file.close();
        try tmp_file.writeAll(bytes);
    }

    try std.fs.renameAbsolute(active_config_path, backup_path);
    std.fs.renameAbsolute(tmp_path, active_config_path) catch |e| {
        std.fs.renameAbsolute(backup_path, active_config_path) catch {};
        return e;
    };
}

fn writeEnrollPlanText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: ?config.Config,
    args: cli.Command.EnrollArgs,
) !void {
    const provider_label = args.provider orelse "<provider>";
    try writer.writeAll("oauth-mux enroll plan\n\n");
    try writer.print("  provider: {s}\n", .{provider_label});
    if (args.account) |account| try writer.print("  account: {s}\n", .{account});
    if (args.mode) |mode| try writer.print("  mode: {s}\n", .{mode});
    try writer.writeAll("  mutates: false\n");
    try writer.print("  provider-neutral enrollment mutation: {s}\n\n", .{
        if (args.provider != null and enrollMutationSupported(args.provider.?)) "available with --confirm-enroll" else "not shipped yet",
    });

    try writer.writeAll("  existing accounts:\n");
    try writeEnrollExistingAccountsText(writer, cfg, args.provider);

    try writer.writeAll("\n  plan:\n");
    try writeEnrollPlanStepsText(writer, allocator, args);

    try writer.writeAll("\n  agent-safe next:\n");
    try writer.writeAll("    oauth-mux providers list --json\n");
    if (args.provider) |provider_name| {
        try writer.print("    oauth-mux accounts list --provider {s} --json\n", .{provider_name});
    } else {
        try writer.writeAll("    oauth-mux accounts list --json\n");
    }
    try writer.writeAll("    oauth-mux config validate\n");
}

fn writeEnrollPlanJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: ?config.Config,
    args: cli.Command.EnrollArgs,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"action\":\"plan\",\"mutates\":false,\"provider\":");
    if (args.provider) |provider_name| try std.json.stringify(provider_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (args.account) |account| try std.json.stringify(account, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"mode\":");
    if (args.mode) |mode| try std.json.stringify(mode, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"configured\":");
    try writer.writeAll(if (cfg != null) "true" else "false");
    try writer.writeAll(",\"provider_configured\":");
    try writer.writeAll(if (enrollProviderConfigured(cfg, args.provider)) "true" else "false");
    try writer.writeAll(",\"provider_neutral_mutation_supported\":");
    try writer.writeAll(if (args.provider != null and enrollMutationSupported(args.provider.?)) "true" else "false");
    try writer.writeAll(",\"existing_accounts\":[");
    try writeEnrollExistingAccountsJson(writer, cfg, args.provider);
    try writer.writeAll("],\"steps\":[");
    try writeEnrollPlanStepsJson(writer, allocator, args);
    try writer.writeAll("],\"agent_safe_commands\":[");
    try writeCommandJson(writer, "oauth-mux providers list --json");
    try writer.writeByte(',');
    const accounts_command = try enrollAccountsCommand(allocator, args.provider);
    defer allocator.free(accounts_command);
    try writeCommandJson(writer, accounts_command);
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux config validate");
    try writer.writeAll("],\"future_provider_neutral_command\":");
    try writeEnrollFutureCommandJson(writer, allocator, args);
    try writer.writeAll("}\n");
}

fn writeEnrollExistingAccountsText(writer: anytype, cfg: ?config.Config, provider_filter: ?[]const u8) !void {
    const config_value = cfg orelse {
        try writer.writeAll("    config unavailable\n");
        return;
    };

    var count: usize = 0;
    var provider_it = config_value.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        if (!enrollProviderMatches(provider_filter, provider_name, prov.kind)) continue;
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            count += 1;
            try writer.print("    {s}:{s} secret={s}\n", .{
                provider_name,
                acct_entry.key_ptr.*,
                acct_entry.value_ptr.secret.backend,
            });
        }
    }

    if (count == 0) try writer.writeAll("    none configured\n");
}

fn writeEnrollExistingAccountsJson(writer: anytype, cfg: ?config.Config, provider_filter: ?[]const u8) !void {
    const config_value = cfg orelse return;

    var first = true;
    var provider_it = config_value.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        if (!enrollProviderMatches(provider_filter, provider_name, prov.kind)) continue;
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |acct_entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeByte('{');
            try writer.writeAll("\"provider\":");
            try std.json.stringify(provider_name, .{}, writer);
            try writer.writeAll(",\"kind\":");
            try std.json.stringify(prov.kind, .{}, writer);
            try writer.writeAll(",\"account\":");
            try std.json.stringify(acct_entry.key_ptr.*, .{}, writer);
            try writer.writeAll(",\"secret_backend\":");
            try std.json.stringify(acct_entry.value_ptr.secret.backend, .{}, writer);
            try writer.writeAll("}");
        }
    }
}

fn writeEnrollPlanStepsText(writer: anytype, allocator: std.mem.Allocator, args: cli.Command.EnrollArgs) !void {
    const provider_name = args.provider orelse {
        try writer.writeAll("    1. Pick a provider after inspecting provider support.\n");
        try writer.writeAll("       command: oauth-mux providers list --json\n");
        try writer.writeAll("    2. Inspect already configured accounts.\n");
        try writer.writeAll("       command: oauth-mux accounts list --json\n");
        try writer.writeAll("    3. Re-run this plan with a provider.\n");
        try writer.writeAll("       command: oauth-mux enroll plan <provider> --json\n");
        return;
    };

    if (isProvider(provider_name, "codex")) {
        const accounts_command = try enrollAccountsCommand(allocator, provider_name);
        defer allocator.free(accounts_command);
        try writeEnrollPlanStepText(writer, 1, "Inspect configured Codex accounts.", accounts_command, false, false, false);
        try writeEnrollPlanStepText(writer, 2, "Generate or review the Codex Max config sidecar when the active config is not already N-account.", "oauth-mux codex config-candidate --json", true, false, false);
        const login_command = try enrollCodexLoginCommand(allocator, args.account);
        defer allocator.free(login_command);
        try writeEnrollPlanStepText(writer, 3, "Run provider-owned Codex login for the target account.", login_command, true, true, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, "codex-max");
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepText(writer, 4, "Recheck local runtime readiness for that account.", runtime_command, false, false, false);
        try writeEnrollPlanStepText(writer, 5, "Refresh recorded route evidence after user-mediated login.", "oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json", true, false, false);
    } else if (isProvider(provider_name, "claude")) {
        const accounts_command = try enrollAccountsCommand(allocator, provider_name);
        defer allocator.free(accounts_command);
        try writeEnrollPlanStepText(writer, 1, "Inspect configured Claude accounts.", accounts_command, false, false, false);
        try writeEnrollPlanStepText(writer, 2, "Create or review an account-scoped CLAUDE_CONFIG_DIR config entry.", null, true, false, false);
        const login_command = try enrollClaudePlanLoginCommand(allocator, args);
        defer allocator.free(login_command);
        try writeEnrollPlanStepText(writer, 3, "Run Claude CLI-owned login in the selected config directory.", login_command, true, true, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, "auth-status");
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepText(writer, 4, "Prove low-impact auth status before broader quota/repair claims.", runtime_command, false, false, false);
    } else if (isProvider(provider_name, "figma")) {
        const capability = figmaCapabilityForMode(args.mode);
        const accounts_command = try enrollAccountsCommand(allocator, provider_name);
        defer allocator.free(accounts_command);
        try writeEnrollPlanStepText(writer, 1, "Inspect configured Figma identities.", accounts_command, false, false, false);
        try writeEnrollPlanStepText(writer, 2, "Configure OAuth/PAT/plan-token mode explicitly in the account secret backend.", null, true, false, false);
        try writeEnrollPlanStepText(writer, 3, "Validate config before any provider call.", "oauth-mux config validate", false, false, false);
        const probe_command = try enrollProbeCommand(allocator, provider_name, args.account, capability);
        defer allocator.free(probe_command);
        try writeEnrollPlanStepText(writer, 4, "Run the chosen low-impact Figma proof only with user consent.", probe_command, false, false, true);
    } else if (isProvider(provider_name, "mcp")) {
        const accounts_command = try enrollAccountsCommand(allocator, provider_name);
        defer allocator.free(accounts_command);
        try writeEnrollPlanStepText(writer, 1, "Inspect configured MCP resource-server accounts.", accounts_command, false, false, false);
        try writeEnrollPlanStepText(writer, 2, "Probe protected-resource metadata before assuming OAuth server details.", "oauth-mux probe --provider mcp --capability resource-metadata --json", false, false, false);
        try writeEnrollPlanStepText(writer, 3, "Only then attach a bearer resource token and prove audience/resource matching.", null, true, false, true);
    } else {
        const accounts_command = try enrollAccountsCommand(allocator, provider_name);
        defer allocator.free(accounts_command);
        try writeEnrollPlanStepText(writer, 1, "Inspect provider support and configured accounts.", accounts_command, false, false, false);
        try writeEnrollPlanStepText(writer, 2, "Validate config after adding a named account and secret backend.", "oauth-mux config validate", false, false, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, null);
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepText(writer, 3, "Run runtime diagnostics before provider calls.", runtime_command, false, false, false);
    }
}

fn writeEnrollPlanStepsJson(writer: anytype, allocator: std.mem.Allocator, args: cli.Command.EnrollArgs) !void {
    var first = true;
    const provider_name = args.provider orelse {
        try writeEnrollPlanStepJson(writer, &first, "choose_provider", "Pick a provider after inspecting provider support.", "oauth-mux providers list --json", false, false, false);
        try writeEnrollPlanStepJson(writer, &first, "inspect_accounts", "Inspect already configured accounts.", "oauth-mux accounts list --json", false, false, false);
        try writeEnrollPlanStepJson(writer, &first, "rerun_plan", "Re-run this plan with a provider.", "oauth-mux enroll plan <provider> --json", false, false, false);
        return;
    };

    const accounts_command = try enrollAccountsCommand(allocator, provider_name);
    defer allocator.free(accounts_command);
    try writeEnrollPlanStepJson(writer, &first, "inspect_accounts", "Inspect configured accounts for this provider.", accounts_command, false, false, false);

    if (isProvider(provider_name, "codex")) {
        try writeEnrollPlanStepJson(writer, &first, "config_candidate", "Generate or review the Codex Max config sidecar when the active config is not already N-account.", "oauth-mux codex config-candidate --json", true, false, false);
        const login_command = try enrollCodexLoginCommand(allocator, args.account);
        defer allocator.free(login_command);
        try writeEnrollPlanStepJson(writer, &first, "provider_login", "Run provider-owned Codex login for the target account.", login_command, true, true, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, "codex-max");
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepJson(writer, &first, "runtime_proof", "Recheck local runtime readiness for that account.", runtime_command, false, false, false);
        try writeEnrollPlanStepJson(writer, &first, "refresh_evidence", "Refresh recorded route evidence after user-mediated login.", "oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json", true, false, false);
    } else if (isProvider(provider_name, "claude")) {
        try writeEnrollPlanStepJson(writer, &first, "config_entry", "Create or review an account-scoped CLAUDE_CONFIG_DIR config entry.", null, true, false, false);
        const login_command = try enrollClaudePlanLoginCommand(allocator, args);
        defer allocator.free(login_command);
        try writeEnrollPlanStepJson(writer, &first, "provider_login", "Run Claude CLI-owned login in the selected config directory.", login_command, true, true, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, "auth-status");
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepJson(writer, &first, "runtime_proof", "Prove low-impact auth status before broader quota/repair claims.", runtime_command, false, false, false);
    } else if (isProvider(provider_name, "figma")) {
        const capability = figmaCapabilityForMode(args.mode);
        try writeEnrollPlanStepJson(writer, &first, "secret_backend", "Configure OAuth/PAT/plan-token mode explicitly in the account secret backend.", null, true, false, false);
        try writeEnrollPlanStepJson(writer, &first, "validate_config", "Validate config before any provider call.", "oauth-mux config validate", false, false, false);
        const probe_command = try enrollProbeCommand(allocator, provider_name, args.account, capability);
        defer allocator.free(probe_command);
        try writeEnrollPlanStepJson(writer, &first, "provider_proof", "Run the chosen low-impact Figma proof only with user consent.", probe_command, false, false, true);
    } else if (isProvider(provider_name, "mcp")) {
        try writeEnrollPlanStepJson(writer, &first, "resource_metadata", "Probe protected-resource metadata before assuming OAuth server details.", "oauth-mux probe --provider mcp --capability resource-metadata --json", false, false, false);
        try writeEnrollPlanStepJson(writer, &first, "bearer_resource", "Only then attach a bearer resource token and prove audience/resource matching.", null, true, false, true);
    } else {
        try writeEnrollPlanStepJson(writer, &first, "validate_config", "Validate config after adding a named account and secret backend.", "oauth-mux config validate", false, false, false);
        const runtime_command = try enrollRuntimeCommand(allocator, provider_name, args.account, null);
        defer allocator.free(runtime_command);
        try writeEnrollPlanStepJson(writer, &first, "runtime_proof", "Run runtime diagnostics before provider calls.", runtime_command, false, false, false);
    }
}

fn writeEnrollPlanStepText(
    writer: anytype,
    index: usize,
    description: []const u8,
    command: ?[]const u8,
    mutating: bool,
    interactive: bool,
    spends_provider_calls: bool,
) !void {
    try writer.print("    {d}. {s}\n", .{ index, description });
    if (command) |cmd| try writer.print("       command: {s}\n", .{cmd});
    try writer.print("       mutating={s} interactive={s} spends_provider_calls={s}\n", .{
        if (mutating) "true" else "false",
        if (interactive) "true" else "false",
        if (spends_provider_calls) "true" else "false",
    });
}

fn writeEnrollPlanStepJson(
    writer: anytype,
    first: *bool,
    kind: []const u8,
    description: []const u8,
    command: ?[]const u8,
    mutating: bool,
    interactive: bool,
    spends_provider_calls: bool,
) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try std.json.stringify(kind, .{}, writer);
    try writer.writeAll(",\"description\":");
    try std.json.stringify(description, .{}, writer);
    try writer.writeAll(",\"command\":");
    if (command) |cmd| try std.json.stringify(cmd, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"mutating\":");
    try writer.writeAll(if (mutating) "true" else "false");
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (interactive) "true" else "false");
    try writer.writeAll(",\"spends_provider_calls\":");
    try writer.writeAll(if (spends_provider_calls) "true" else "false");
    try writer.writeAll(",\"agent_safe\":");
    try writer.writeAll(if (!mutating and !interactive and !spends_provider_calls) "true" else "false");
    try writer.writeByte('}');
}

fn writeEnrollFutureCommandJson(writer: anytype, allocator: std.mem.Allocator, args: cli.Command.EnrollArgs) !void {
    try writer.writeByte('{');
    const provider_name = args.provider orelse {
        try writer.writeAll("\"available\":false,\"command\":");
        try writer.writeAll("null,\"reason\":\"provider_required\"}");
        return;
    };
    const account = args.account orelse "<account>";
    const available = enrollMutationSupported(provider_name);
    try writer.writeAll("\"available\":");
    try writer.writeAll(if (available) "true" else "false");
    try writer.writeAll(",\"command\":");
    const command = if (available and isProvider(provider_name, "figma"))
        try enrollFigmaConfirmCommand(allocator, account, args.mode, args.secret_env, false)
    else if (available)
        try std.fmt.allocPrint(allocator, "oauth-mux enroll {s} --account {s} --confirm-enroll", .{ provider_name, account })
    else
        try std.fmt.allocPrint(allocator, "oauth-mux enroll {s} --account {s}", .{ provider_name, account });
    defer allocator.free(command);
    try std.json.stringify(command, .{}, writer);
    if (available) {
        try writer.writeAll(",\"reason\":\"available_for_config_and_store_scaffolding; provider login remains a user-run handoff\"}");
    } else {
        try writer.writeAll(",\"reason\":\"not_implemented; use enroll plan and provider-owned setup commands\"}");
    }
}

fn enrollProviderConfigured(cfg: ?config.Config, provider_filter: ?[]const u8) bool {
    const config_value = cfg orelse return false;
    const filter = provider_filter orelse return config_value.providers.map.count() > 0;
    var provider_it = config_value.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (enrollProviderMatches(filter, entry.key_ptr.*, entry.value_ptr.kind)) return true;
    }
    return false;
}

fn enrollProviderMatches(provider_filter: ?[]const u8, provider_name: []const u8, provider_kind: []const u8) bool {
    const filter = provider_filter orelse return true;
    return std.mem.eql(u8, filter, provider_name) or std.mem.eql(u8, filter, provider_kind);
}

fn isProvider(provider_name: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(provider_name, expected);
}

fn enrollMutationSupported(provider_name: []const u8) bool {
    return isProvider(provider_name, "codex") or isProvider(provider_name, "claude") or isProvider(provider_name, "figma");
}

fn figmaEnrollmentMode(mode: ?[]const u8) []const u8 {
    const value = mode orelse return "oauth";
    if (isProvider(value, "pat")) return "pat";
    if (isProvider(value, "plan") or isProvider(value, "file") or isProvider(value, "file-metadata")) return "plan";
    return "oauth";
}

fn figmaProviderForMode(mode: []const u8) []const u8 {
    if (isProvider(mode, "pat")) return "figma-pat";
    if (isProvider(mode, "plan")) return "figma-plan";
    return "figma";
}

fn figmaCapabilityForMode(mode: ?[]const u8) []const u8 {
    const value = mode orelse return "identity";
    if (isProvider(value, "pat")) return "identity-pat";
    if (isProvider(value, "plan") or isProvider(value, "file") or isProvider(value, "file-metadata")) return "file-metadata-plan";
    return "identity";
}

fn figmaDefaultSecretEnv(allocator: std.mem.Allocator, account: []const u8, mode: []const u8) ![]const u8 {
    var normalized_account = std.ArrayList(u8).init(allocator);
    defer normalized_account.deinit();
    for (account) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            try normalized_account.append(std.ascii.toUpper(c));
        } else {
            try normalized_account.append('_');
        }
    }
    const suffix = if (isProvider(mode, "pat"))
        "PAT"
    else if (isProvider(mode, "plan"))
        "PLAN_TOKEN"
    else
        "TOKEN";
    return try std.fmt.allocPrint(allocator, "OMUX_FIGMA_{s}_{s}", .{ normalized_account.items, suffix });
}

fn enrollAccountsCommand(allocator: std.mem.Allocator, provider_name: ?[]const u8) ![]const u8 {
    if (provider_name) |name| return std.fmt.allocPrint(allocator, "oauth-mux accounts list --provider {s} --json", .{name});
    return allocator.dupe(u8, "oauth-mux accounts list --json");
}

fn enrollCodexLoginCommand(allocator: std.mem.Allocator, account: ?[]const u8) ![]const u8 {
    if (account) |name| return std.fmt.allocPrint(allocator, "oauth-mux codex login-device {s}", .{name});
    return allocator.dupe(u8, "oauth-mux setup codex --status-only");
}

fn enrollClaudePlanLoginCommand(allocator: std.mem.Allocator, args: cli.Command.EnrollArgs) ![]const u8 {
    const account = args.account orelse return allocator.dupe(u8, "env CLAUDE_CONFIG_DIR=<account-dir> claude auth login");
    const config_root = try claudeConfigRoot(allocator, args.store_root);
    defer allocator.free(config_root);
    const account_dir = try claudeAccountDir(allocator, config_root, account);
    defer allocator.free(account_dir);
    return enrollClaudeLoginCommand(allocator, account_dir);
}

fn enrollRuntimeCommand(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    account: ?[]const u8,
    capability: ?[]const u8,
) ![]const u8 {
    if (account) |account_name| {
        if (capability) |capability_name| {
            return std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --account {s} --capability {s} --json", .{ provider_name, account_name, capability_name });
        }
        return std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --account {s} --json", .{ provider_name, account_name });
    }
    if (capability) |capability_name| {
        return std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --capability {s} --json", .{ provider_name, capability_name });
    }
    return std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --json", .{provider_name});
}

fn enrollProbeCommand(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    account: ?[]const u8,
    capability: []const u8,
) ![]const u8 {
    if (account) |account_name| {
        return std.fmt.allocPrint(allocator, "oauth-mux probe --provider {s} --account {s} --capability {s} --json", .{ provider_name, account_name, capability });
    }
    return std.fmt.allocPrint(allocator, "oauth-mux probe --provider {s} --capability {s} --json", .{ provider_name, capability });
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
            try writeCommandJson(writer, "oauth-mux accounts list");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux enroll plan <provider>");
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
            try writer.writeAll("    oauth-mux accounts list\n");
            try writer.writeAll("    oauth-mux enroll plan <provider>\n");
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
    try writer.writeAll("    oauth-mux accounts list --json\n");
    try writer.writeAll("    oauth-mux enroll plan <provider> --json\n");
    try writer.writeAll("    oauth-mux status --json\n");
    try writer.writeAll("    oauth-mux health --json\n");
    try writer.writeAll("    oauth-mux doctor runtime --json\n");
    try writer.writeAll("    oauth-mux probe --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux route explain --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux route select --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux repair-plan --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux repair run --profile <profile> --capability <capability> --json\n");
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
        "oauth-mux accounts list --json",
        "oauth-mux enroll plan <provider> --json",
        "oauth-mux status --json",
        "oauth-mux health --json",
        "oauth-mux doctor runtime --json",
        "oauth-mux probe --profile <profile> --capability <capability> --json",
        "oauth-mux route explain --profile <profile> --capability <capability> --json",
        "oauth-mux route select --profile <profile> --capability <capability> --json",
        "oauth-mux stay-afloat next --profile <profile> --capability <capability> --json",
        "oauth-mux repair-plan --profile <profile> --capability <capability> --json",
        "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json",
        "oauth-mux repair run --profile <profile> --capability <capability> --json",
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

const RepairActionKind = enum {
    none,
    probe_needed,
    fix_runtime,
    wait_for_repair,
    wait_and_retry,
    wait_for_quota,
    wait_for_cooldown,
    scope_or_permission,
    resource_or_audience,
    provider_plan,
    try_next_provider,
    inspect_provider_schema,
    reauth,
    refresh,
    external_secret_rotation,
    manual_repair,
};

const RepairMediation = enum {
    none,
    probe,
    local_runtime,
    wait,
    user_handoff,
    oauth_mux_refresh,
    external_secret_owner,
    manual_operator,
    provider_scope,
    provider_plan,
    provider_degraded,
    schema_inspection,
};

const RepairAction = struct {
    kind: RepairActionKind,
    severity: []const u8,
    message: []const u8,
    mediation: RepairMediation = .none,
    owner: ?types.RepairOwner = null,
    command: RepairCommandKind = .none,
    budget: ?types.ActionBudget = null,
    interactive: bool = false,
    mutating: bool = false,
    retry_after_s: ?u32 = null,
    wait_until: ?i64 = null,
};

const AdmissionDecision = struct {
    admitted: bool,
    reason: []const u8,
    budget: ?types.ActionBudget = null,
};

const DaemonTickSchedule = struct {
    next_tick_after: ?i64 = null,
    reason: []const u8 = "none",
};

const daemon_repair_poll_s: i64 = 30;
const daemon_runtime_recheck_s: i64 = 300;
const daemon_handoff_recheck_s: i64 = 300;
const daemon_quota_unknown_recheck_s: i64 = 3600;
const daemon_provider_plan_recheck_s: i64 = 3600;

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

fn runRepairRun(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.RepairRunArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, repairRunArgsToPlanArgs(args));
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);
    const candidate_index = repairRunCandidate(evaluations.items, selected_index, args);

    if (candidate_index == null) {
        if (selected_index) |idx| {
            recordRepairRunEvent(allocator, args, evaluations.items[idx], "noop", "route_selectable", true, false);
        } else {
            recordRepairRunEvent(allocator, args, null, "no_admitted_repair", "no_admitted_repair", true, false);
        }
        if (args.json) {
            try writeRepairRunNoopJson(writer, evaluations.items, selected_index, args);
        } else {
            try writeRepairRunNoopText(writer, evaluations.items, selected_index, args);
        }
        return;
    }

    const evaluation = evaluations.items[candidate_index.?];
    if (!args.confirm_repair) {
        recordRepairRunEvent(allocator, args, evaluation, "confirmation_required", "missing_confirm_repair", false, false);
        if (args.json) {
            try writeRepairRunConfirmationJson(writer, allocator, parsed.value, evaluation, args);
        } else {
            try writeRepairRunConfirmationText(writer, allocator, evaluation);
        }
        return error.RepairConfirmationRequired;
    }

    if (args.json and evaluation.action.interactive) {
        recordRepairRunEvent(allocator, args, evaluation, "interactive_json_unsupported", "json_mode", false, false);
        try writeRepairRunJsonInteractiveUnsupported(writer, allocator, parsed.value, evaluation, args);
        return error.RepairConfirmationRequired;
    }

    var lock = repair_state.acquireRepairLock(allocator, evaluation.route.provider, evaluation.route.account) catch |e| switch (e) {
        error.RepairInProgress => {
            recordRepairRunEvent(allocator, args, evaluation, "repair_in_progress", "lock_busy", false, false);
            if (args.json) {
                try writeRepairRunLockBusyJson(writer, allocator, parsed.value, evaluation, args);
            } else {
                try writeRepairRunLockBusyText(writer, evaluation);
            }
            return error.RepairAlreadyInProgress;
        },
        else => return e,
    };
    defer lock.release();

    const command = try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route);
    defer if (command) |value| allocator.free(value);

    try repair_state.appendEvent(allocator, repairRunEvent(evaluation, args.profile, "started", "confirmed_repair", false, false));
    const ok = try executeRepairCommand(allocator, parsed.value, evaluation);
    recordRepairRunEvent(allocator, args, evaluation, if (ok) "executed" else "failed", if (ok) "command_success" else "command_failed", ok, true);
    if (args.json) {
        try writeRepairRunExecutedJson(writer, allocator, parsed.value, evaluation, command, ok);
    } else {
        try writeRepairRunExecutedText(writer, evaluation, command, ok);
    }
    if (!ok) return error.CodexCommandFailed;
}

fn repairRunArgsToPlanArgs(args: cli.Command.RepairRunArgs) cli.Command.RepairPlanArgs {
    return .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
        .json = args.json,
    };
}

fn repairRunCandidate(
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RepairRunArgs,
) ?usize {
    if (args.account == null and selected_index != null) return null;

    for (evaluations, 0..) |evaluation, idx| {
        if (evaluation.action.mutating and evaluation.action.command != .none) return idx;
    }
    return null;
}

fn recordRepairRunEvent(
    allocator: std.mem.Allocator,
    args: cli.Command.RepairRunArgs,
    evaluation: ?RouteEvaluation,
    outcome: []const u8,
    reason: []const u8,
    ok: bool,
    executed: bool,
) void {
    const event = if (evaluation) |value|
        repairRunEvent(value, args.profile, outcome, reason, ok, executed)
    else
        repair_state.RepairEvent{
            .profile = args.profile,
            .capability = args.capability,
            .outcome = outcome,
            .reason = reason,
            .ok = ok,
            .executed = executed,
        };
    repair_state.appendEvent(allocator, event) catch {};
}

fn repairRunEvent(
    evaluation: RouteEvaluation,
    profile: ?[]const u8,
    outcome: []const u8,
    reason: []const u8,
    ok: bool,
    executed: bool,
) repair_state.RepairEvent {
    return .{
        .profile = profile,
        .provider = evaluation.route.provider,
        .account = evaluation.route.account,
        .capability = evaluation.route.capability,
        .action = @tagName(evaluation.action.kind),
        .outcome = outcome,
        .reason = reason,
        .ok = ok,
        .executed = executed,
        .interactive = evaluation.action.interactive,
        .mutating = evaluation.action.mutating,
    };
}

fn writeRepairRunNoopText(
    writer: anytype,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RepairRunArgs,
) !void {
    try writer.writeAll("oauth-mux repair run\n\n");
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    if (selected_index) |idx| {
        const route = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ route.provider, route.account });
        if (route.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.writeAll("\n  executed: no\n  reason: route is already selectable; no repair needed for stay-afloat\n");
    } else {
        try writer.writeAll("  executed: no\n  reason: no admitted mutating repair action found\n");
    }
}

fn writeRepairRunNoopJson(
    writer: anytype,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RepairRunArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":true,\"executed\":false,\"confirmation_required\":false,\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"reason\":");
    if (selected_index != null) {
        try std.json.stringify("route_selectable", .{}, writer);
    } else {
        try std.json.stringify("no_admitted_repair", .{}, writer);
    }
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

fn writeRepairRunConfirmationText(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluation: RouteEvaluation,
) !void {
    try writer.writeAll("oauth-mux repair run\n\n");
    try writer.writeAll("  executed: no\n");
    try writer.writeAll("  confirmation_required: --confirm-repair\n");
    try writer.print("  route: {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
    if (evaluation.route.capability) |capability| try writer.print("#{s}", .{capability});
    try writer.print("\n  action: {s}\n", .{@tagName(evaluation.action.kind)});
    if (try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route)) |command| {
        defer allocator.free(command);
        try writer.print("  command: {s}\n", .{command});
    }
}

fn writeRepairRunConfirmationJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    args: cli.Command.RepairRunArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":false,\"executed\":false,\"confirmation_required\":true,\"requires\":\"--confirm-repair\",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"route\":");
    try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, false);
    try writer.writeAll("}\n");
}

fn writeRepairRunJsonInteractiveUnsupported(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    args: cli.Command.RepairRunArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":false,\"executed\":false,\"confirmation_required\":false,\"error\":\"interactive_json_unsupported\",\"message\":\"interactive repair may write upstream CLI output; rerun without --json after reviewing repair-plan\",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"route\":");
    try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, false);
    try writer.writeAll("}\n");
}

fn writeRepairRunLockBusyText(
    writer: anytype,
    evaluation: RouteEvaluation,
) !void {
    try writer.writeAll("oauth-mux repair run\n\n");
    try writer.writeAll("  executed: no\n");
    try writer.writeAll("  reason: repair already in progress for this account\n");
    try writer.print("  route: {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
    if (evaluation.route.capability) |capability| try writer.print("#{s}", .{capability});
    try writer.writeByte('\n');
}

fn writeRepairRunLockBusyJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    args: cli.Command.RepairRunArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":false,\"executed\":false,\"confirmation_required\":false,\"error\":\"repair_in_progress\",\"message\":\"another oauth-mux repair process holds this account lock\",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"route\":");
    try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, false);
    try writer.writeAll("}\n");
}

fn writeRepairRunExecutedText(
    writer: anytype,
    evaluation: RouteEvaluation,
    command: ?[]const u8,
    ok: bool,
) !void {
    try writer.writeAll("oauth-mux repair run\n\n");
    try writer.print("  executed: {s}\n", .{if (ok) "yes" else "failed"});
    try writer.print("  route: {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
    if (evaluation.route.capability) |capability| try writer.print("#{s}", .{capability});
    try writer.print("\n  action: {s}\n", .{@tagName(evaluation.action.kind)});
    if (command) |value| try writer.print("  command: {s}\n", .{value});
}

fn writeRepairRunExecutedJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    command: ?[]const u8,
    ok: bool,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"executed\":true,\"confirmation_required\":false,\"command\":");
    if (command) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"route\":");
    try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, false);
    try writer.writeAll("}\n");
}

fn executeRepairCommand(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
) !bool {
    return switch (evaluation.action.command) {
        .none, .probe => false,
        .codex_login_device => try executeCodexLoginDeviceRepair(allocator, cfg, evaluation.route),
    };
}

fn executeCodexLoginDeviceRepair(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
) !bool {
    const prov = cfg.providers.map.get(route.provider) orelse return false;
    const account = prov.accounts.map.get(route.account) orelse return false;
    const config_dir = account.config_dir orelse return false;
    const expanded = try paths.expandTilde(allocator, config_dir);
    defer allocator.free(expanded);
    return try runCodexCli(allocator, expanded, &.{ "codex", "login", "--device-auth" });
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
        const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
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
        try writer.print("\n    action={s} severity={s} {s}\n", .{ @tagName(action.kind), action.severity, action.message });
        if (try repairCommandAlloc(allocator, action.command, route)) |command| {
            defer allocator.free(command);
            try writer.print("    command: {s}\n", .{command});
        }
        if (try runtimeDiagnosticCommandAlloc(allocator, action, route)) |command| {
            defer allocator.free(command);
            try writer.print("    diagnostic: {s}\n", .{command});
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
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
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
    const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
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
    try writer.writeAll(",\"writeback\":");
    try writeRouteWritebackJson(writer, cfg, route, def);
    try writer.writeAll(",\"probe_budget\":");
    if (budget) |probe_budget| {
        try std.json.stringify(@tagName(probe_budget), .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"admission\":");
    try writeRouteAdmissionJson(writer, cfg.policy, action, budget);
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
    try std.json.stringify(@tagName(action.kind), .{}, writer);
    try writer.writeAll(",\"mediation\":");
    try std.json.stringify(@tagName(action.mediation), .{}, writer);
    try writer.writeAll(",\"repair_owner\":");
    if (action.owner) |owner| try std.json.stringify(@tagName(owner), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"severity\":");
    try std.json.stringify(action.severity, .{}, writer);
    try writer.writeAll(",\"message\":");
    try std.json.stringify(action.message, .{}, writer);
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (action.interactive) "true" else "false");
    try writer.writeAll(",\"mutating\":");
    try writer.writeAll(if (action.mutating) "true" else "false");
    try writer.writeAll(",\"budget\":");
    if (action.budget) |budget| try std.json.stringify(@tagName(budget), .{}, writer) else try writer.writeAll("null");
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
    try writer.writeAll(",\"diagnostic_command\":");
    if (try runtimeDiagnosticCommandAlloc(allocator, action, route)) |command| {
        defer allocator.free(command);
        try std.json.stringify(command, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writePolicyJson(writer: anytype, policy: config.PolicyConfig) !void {
    try writer.writeAll("{\"daemon\":{");
    try writer.writeAll("\"allowed_budgets\":");
    try writeBudgetArrayJson(writer, policy.daemon.allowed_budgets);
    try writer.writeAll(",\"allow_interactive\":");
    try writer.writeAll(if (policy.daemon.allow_interactive) "true" else "false");
    try writer.writeAll(",\"allow_mutating\":");
    try writer.writeAll(if (policy.daemon.allow_mutating) "true" else "false");
    try writer.writeAll("}}");
}

fn writeBudgetArrayJson(writer: anytype, budgets: []const types.ActionBudget) !void {
    try writer.writeByte('[');
    for (budgets, 0..) |budget, idx| {
        if (idx > 0) try writer.writeByte(',');
        try std.json.stringify(@tagName(budget), .{}, writer);
    }
    try writer.writeByte(']');
}

fn writeRouteAdmissionJson(
    writer: anytype,
    policy: config.PolicyConfig,
    action: RepairAction,
    probe_budget: ?types.ActionBudget,
) !void {
    const probe = daemonProbeAdmission(policy.daemon, probe_budget);
    const repair = daemonRepairAdmission(policy.daemon, action);

    try writer.writeByte('{');
    try writer.writeAll("\"daemon_probe\":");
    try writeAdmissionDecisionJson(writer, probe);
    try writer.writeAll(",\"daemon_repair\":");
    try writeAdmissionDecisionJson(writer, repair);
    try writer.writeByte('}');
}

fn writeAdmissionDecisionJson(writer: anytype, decision: AdmissionDecision) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"admitted\":");
    try writer.writeAll(if (decision.admitted) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(decision.reason, .{}, writer);
    try writer.writeAll(",\"budget\":");
    if (decision.budget) |budget| try std.json.stringify(@tagName(budget), .{}, writer) else try writer.writeAll("null");
    try writer.writeByte('}');
}

fn writeRouteWritebackJson(
    writer: anytype,
    cfg: config.Config,
    route: RepairPlanRoute,
    def: provider_schema.ProviderDefinition,
) !void {
    const plan = routeWritebackPlan(cfg, route, def);
    try writer.writeByte('{');
    try writer.writeAll("\"capability\":");
    try std.json.stringify(@tagName(plan.capability), .{}, writer);
    try writer.writeAll(",\"automatic_refresh_admitted\":");
    try writer.writeAll(if (plan.automatic_refresh_admitted) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(plan.reason, .{}, writer);
    try writer.writeByte('}');
}

fn routeWritebackPlan(
    cfg: config.Config,
    route: RepairPlanRoute,
    def: provider_schema.ProviderDefinition,
) secret_mod.WritebackPlan {
    const prov = cfg.providers.map.get(route.provider) orelse return .{
        .capability = .unsupported,
        .automatic_refresh_admitted = false,
        .reason = "provider_not_configured",
    };
    const account = prov.accounts.map.get(route.account) orelse return .{
        .capability = .unsupported,
        .automatic_refresh_admitted = false,
        .reason = "account_not_configured",
    };
    const backend = config.resolveSecretBackend(account.secret) catch return .{
        .capability = .unsupported,
        .automatic_refresh_admitted = false,
        .reason = "secret_backend_invalid",
    };
    return secret_mod.writebackPlan(backend, def.repair.owner);
}

fn daemonProbeAdmission(policy: config.DaemonPolicyConfig, budget: ?types.ActionBudget) AdmissionDecision {
    const value = budget orelse return .{
        .admitted = false,
        .reason = "no_probe_budget",
    };
    if (!config.daemonPolicyAllowsBudget(policy, value)) {
        return .{
            .admitted = false,
            .reason = "budget_not_allowed",
            .budget = value,
        };
    }
    return .{
        .admitted = true,
        .reason = "allowed_by_policy",
        .budget = value,
    };
}

fn daemonRepairAdmission(policy: config.DaemonPolicyConfig, action: RepairAction) AdmissionDecision {
    if (action.command == .probe) {
        return .{
            .admitted = true,
            .reason = "no_repair_action",
        };
    }
    const budget = action.budget orelse return .{
        .admitted = true,
        .reason = "no_repair_action",
    };
    if (action.interactive and !policy.allow_interactive) {
        return .{
            .admitted = false,
            .reason = "interactive_not_allowed",
            .budget = budget,
        };
    }
    if (action.mutating and !policy.allow_mutating) {
        return .{
            .admitted = false,
            .reason = "mutating_not_allowed",
            .budget = budget,
        };
    }
    if (!config.daemonPolicyAllowsBudget(policy, budget)) {
        return .{
            .admitted = false,
            .reason = "budget_not_allowed",
            .budget = budget,
        };
    }
    return .{
        .admitted = true,
        .reason = "allowed_by_policy",
        .budget = budget,
    };
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
            .kind = .fix_runtime,
            .severity = "error",
            .message = "required upstream CLI is missing",
            .mediation = .local_runtime,
            .budget = .free_local,
        },
        .permission_denied, .unwritable_store, .session_unavailable, .sandbox_blocked => return .{
            .kind = .fix_runtime,
            .severity = "error",
            .message = "runtime is not ready; fix local permissions, store, session, or sandbox access",
            .mediation = .local_runtime,
            .budget = .free_local,
        },
        .needs_reauth => return reauthAction(route, def),
        .repair_in_progress => return .{
            .kind = .wait_for_repair,
            .severity = "info",
            .message = "repair is already in progress",
            .mediation = .wait,
            .budget = .free_local,
        },
    }

    const current = health orelse return .{
        .kind = .probe_needed,
        .severity = if (budget == .spend_provider) "warning" else "info",
        .message = if (budget == .spend_provider)
            "no health evidence recorded; explicit live probe may spend provider quota"
        else
            "no health evidence recorded; run a probe to classify this route",
        .mediation = .probe,
        .command = .probe,
        .budget = budget,
    };

    return switch (current.liveness) {
        .live => |live| switch (live.availability) {
            .available => .{
                .kind = .none,
                .severity = "ok",
                .message = "route is selectable",
            },
            .rate_limited => |rl| .{
                .kind = .wait_and_retry,
                .severity = "warning",
                .message = "short rate-limit window is active; try another route until retry",
                .mediation = .wait,
                .budget = .free_local,
                .retry_after_s = rl.retry_after_s,
            },
            .quota_exhausted => |quota| .{
                .kind = .wait_for_quota,
                .severity = "warning",
                .message = "quota window is exhausted; use another account until reset",
                .mediation = .wait,
                .budget = .free_local,
                .wait_until = quota.window_resets_at,
            },
            .cooldown => |cooldown| .{
                .kind = .wait_for_cooldown,
                .severity = "warning",
                .message = "local cooldown is active",
                .mediation = .wait,
                .budget = .free_local,
                .wait_until = cooldown.until,
            },
        },
        .degraded => |degraded| degradedAction(route, def, degraded.reason, budget),
        .dead => reauthAction(route, def),
    };
}

fn degradedAction(
    route: RepairPlanRoute,
    def: provider_schema.ProviderDefinition,
    reason: types.DegradedReason,
    budget: ?types.ActionBudget,
) RepairAction {
    return switch (reason) {
        .step_up_required, .pending_verification, .terms_required => reauthAction(route, def),
        .scope_insufficient => .{
            .kind = .scope_or_permission,
            .severity = "warning",
            .message = "credential is valid but lacks required scope or route permission",
            .mediation = .provider_scope,
            .command = .probe,
            .budget = budget,
        },
        .audience_mismatch => .{
            .kind = .resource_or_audience,
            .severity = "warning",
            .message = "credential is valid but was minted for a different resource or audience",
            .mediation = .provider_scope,
            .command = .probe,
            .budget = budget,
        },
        .tier_insufficient, .subscription_paused => .{
            .kind = .provider_plan,
            .severity = "warning",
            .message = "account is authenticated but not operable for this capability",
            .mediation = .provider_plan,
        },
        .provider_degraded => .{
            .kind = .try_next_provider,
            .severity = "warning",
            .message = "provider appears degraded; try another provider route",
            .mediation = .provider_degraded,
        },
        .schema_invalid, .unknown_4xx => .{
            .kind = .inspect_provider_schema,
            .severity = "warning",
            .message = "provider returned a route/schema error; inspect provider definition and probe evidence",
            .mediation = .schema_inspection,
            .command = .probe,
            .budget = budget,
        },
    };
}

fn reauthAction(route: RepairPlanRoute, def: provider_schema.ProviderDefinition) RepairAction {
    return switch (def.repair.owner) {
        .upstream_cli_login => .{
            .kind = .reauth,
            .severity = "error",
            .message = "reauth is owned by the upstream CLI",
            .mediation = .user_handoff,
            .owner = .upstream_cli_login,
            .command = if (std.mem.eql(u8, route.provider, "codex")) .codex_login_device else .none,
            .budget = .interactive,
            .interactive = true,
            .mutating = true,
        },
        .oauth_mux_refresh => .{
            .kind = .refresh,
            .severity = "warning",
            .message = "oauth-mux owns refresh for this provider; automatic repair is not enabled by repair-plan",
            .mediation = .oauth_mux_refresh,
            .owner = .oauth_mux_refresh,
            .budget = .mutating,
            .mutating = true,
        },
        .external_secret_owner => .{
            .kind = .external_secret_rotation,
            .severity = "error",
            .message = "credential repair is owned by an external secret backend",
            .mediation = .external_secret_owner,
            .owner = .external_secret_owner,
        },
        .manual_only => .{
            .kind = .manual_repair,
            .severity = "error",
            .message = "manual operator repair is required for this provider",
            .mediation = .manual_operator,
            .owner = .manual_only,
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

fn runtimeDiagnosticCommandAlloc(
    allocator: std.mem.Allocator,
    action: RepairAction,
    route: RepairPlanRoute,
) !?[]const u8 {
    if (action.kind != .fix_runtime) return null;
    return if (route.capability) |capability|
        try std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --account {s} --capability {s} --json", .{ route.provider, route.account, capability })
    else
        try std.fmt.allocPrint(allocator, "oauth-mux doctor runtime --provider {s} --account {s} --json", .{ route.provider, route.account });
}

const RouteEvaluation = struct {
    route: RepairPlanRoute,
    runtime: types.RuntimeReadiness,
    health: ?health_mod.AccountHealth,
    budget: ?types.ActionBudget,
    action: RepairAction,
    selectable: bool,
    skip_reason: []const u8,
};

fn runRoute(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.RouteArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);

    if (args.json) {
        try writeRouteJson(writer, allocator, parsed.value, evaluations.items, selected_index, args);
    } else {
        try writeRouteText(writer, allocator, evaluations.items, selected_index, args);
    }

    if (args.action == .select and selected_index == null) return error.AllAccountsExhausted;
}

fn runStayAfloatNext(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.RouteArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
        .json = args.json,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);
    const candidate_index = if (selected_index == null) firstActionableRoute(evaluations.items) else null;

    if (args.json) {
        try writeStayAfloatNextJson(writer, allocator, parsed.value, evaluations.items, selected_index, candidate_index, args);
    } else {
        try writeStayAfloatNextText(writer, allocator, evaluations.items, selected_index, candidate_index, args);
    }
}

fn runStayAfloatLaunch(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.ExecArgs) !void {
    if (args.target_argv.len == 0) {
        log.err("stay-afloat launch: no target command specified (use -- before the command)", .{});
        return error.ConfigValidationError;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const selector = cli.Command.RouteArgs{
        .action = .explain,
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
    };
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = selector.profile,
        .provider = selector.provider,
        .account = selector.account,
        .capability = selector.capability,
    });
    defer routes.deinit();

    var attempted_routes = std.ArrayList(RepairPlanRoute).init(allocator);
    defer attempted_routes.deinit();

    var last_exec_error: ?anyerror = null;
    while (attempted_routes.items.len < routes.items.len) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer evaluations.deinit();
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

        const selected_index = firstSelectableRouteNotAttempted(evaluations.items, attempted_routes.items);
        if (selected_index == null) {
            const candidate_index = firstActionableRoute(evaluations.items);
            try writeStayAfloatMediationText(writer, allocator, evaluations.items, null, candidate_index, selector, "oauth-mux stay-afloat launch");
            if (last_exec_error) |err| return err;
            return error.AllAccountsExhausted;
        }

        const selected = evaluations.items[selected_index.?].route;
        try attempted_routes.append(selected);

        var exec_args = args;
        exec_args.profile = null;
        exec_args.provider = selected.provider;
        exec_args.account = selected.account;
        exec_args.capability = selected.capability orelse args.capability;
        runExec(allocator, exec_args) catch |e| {
            last_exec_error = e;
            continue;
        };
    }

    try writeStayAfloatLaunchMediationFromCurrentState(
        allocator,
        writer,
        parsed.value,
        routes.items,
        selector,
    );
    if (last_exec_error) |err| return err;
    return error.AllAccountsExhausted;
}

const SuperviseAttempt = struct {
    route: RepairPlanRoute,
    term: std.process.Child.Term,
    output_classification: ?[]const u8 = null,
    restart_admitted: bool,
    route_health_recorded: bool = false,
    event_recorded: bool = false,
    captured_stdout_bytes: usize = 0,
    captured_stderr_bytes: usize = 0,
};

const SuperviseChildResult = struct {
    term: std.process.Child.Term,
    output_classification: ?[]const u8 = null,
    captured_stdout_bytes: usize = 0,
    captured_stderr_bytes: usize = 0,
};

const SuperviseCaptureLimit = 512 * 1024;

const SuperviseStreamCapture = struct {
    buffer: []u8,
    len: usize = 0,
    read_error: ?anyerror = null,
};

fn runStayAfloatSupervise(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.SuperviseArgs,
) !void {
    if (args.target_argv.len == 0) {
        log.err("stay-afloat supervise: no target command specified (use -- before the command)", .{});
        return error.ConfigValidationError;
    }
    if (args.stream_capture and !args.restart_on_codex_usage_limit) {
        log.err("stay-afloat supervise: --stream-capture requires --restart-on-codex-usage-limit", .{});
        return error.ConfigValidationError;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const selector = cli.Command.RouteArgs{
        .action = .explain,
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
    };
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = selector.profile,
        .provider = selector.provider,
        .account = selector.account,
        .capability = selector.capability,
    });
    defer routes.deinit();

    var attempted_routes = std.ArrayList(RepairPlanRoute).init(allocator);
    defer attempted_routes.deinit();
    var attempts = std.ArrayList(SuperviseAttempt).init(allocator);
    defer attempts.deinit();

    var restart_count: u32 = 0;
    var reason: []const u8 = "no_attempt";

    while (true) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer evaluations.deinit();
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

        const selected_index = firstSelectableRouteNotAttempted(evaluations.items, attempted_routes.items);
        if (selected_index == null) {
            reason = if (attempts.items.len == 0) "no_selectable_route" else "no_fallback_route";
            break;
        }

        const selected = evaluations.items[selected_index.?].route;
        try attempted_routes.append(selected);

        var env_map = buildPinnedExecEnvMap(allocator, parsed.value, &store, selected, args) catch {
            reason = "preflight_reclassified_route";
            continue;
        };
        defer env_map.deinit();

        const child_result = runSupervisedChild(allocator, &env_map, args) catch return error.ExecFailed;
        const route_health_recorded = if (superviseOutputClassificationIsCodexUsageLimit(child_result.output_classification))
            recordStayAfloatSuperviseRouteHealth(&store, selected)
        else
            false;
        if (route_health_recorded) store.persist();

        const restart_admitted = superviseRestartAdmitted(args, child_result.term, child_result.output_classification, restart_count);
        const event_recorded = recordStayAfloatSuperviseEvent(allocator, args, selected, child_result.term, child_result.output_classification, route_health_recorded, restart_admitted);
        try attempts.append(.{
            .route = selected,
            .term = child_result.term,
            .output_classification = child_result.output_classification,
            .restart_admitted = restart_admitted,
            .route_health_recorded = route_health_recorded,
            .event_recorded = event_recorded,
            .captured_stdout_bytes = child_result.captured_stdout_bytes,
            .captured_stderr_bytes = child_result.captured_stderr_bytes,
        });

        if (restart_admitted) {
            restart_count += 1;
            reason = "restart_admitted";
            continue;
        }

        reason = if (superviseTermSucceeded(child_result.term)) "target_completed" else "target_failed";
        break;
    }

    if (args.json) {
        try writeStayAfloatSuperviseJson(writer, args, attempts.items, restart_count, reason);
    } else {
        try writeStayAfloatSuperviseText(writer, args, attempts.items, restart_count, reason);
    }
}

fn runSupervisedChild(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    args: cli.Command.SuperviseArgs,
) !SuperviseChildResult {
    var child = std.process.Child.init(args.target_argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = if (args.restart_on_codex_usage_limit) .Pipe else if (args.json) .Ignore else .Inherit;
    child.stderr_behavior = if (args.restart_on_codex_usage_limit) .Pipe else if (args.json) .Ignore else .Inherit;
    child.env_map = env_map;

    if (!args.restart_on_codex_usage_limit) {
        return .{ .term = try child.spawnAndWait() };
    }

    if (args.stream_capture) {
        return runSupervisedChildStreamingPipe(allocator, &child, args);
    }

    try child.spawn();

    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);

    child.collectOutput(allocator, &stdout_buf, &stderr_buf, SuperviseCaptureLimit) catch |e| {
        _ = child.kill() catch null;
        return e;
    };
    const term = try child.wait();
    const classification: ?[]const u8 = if (superviseOutputLooksLikeCodexUsageLimit(stdout_buf.items) or superviseOutputLooksLikeCodexUsageLimit(stderr_buf.items))
        "codex_usage_limit"
    else
        null;
    return .{
        .term = term,
        .output_classification = classification,
        .captured_stdout_bytes = stdout_buf.items.len,
        .captured_stderr_bytes = stderr_buf.items.len,
    };
}

fn runSupervisedChildStreamingPipe(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    args: cli.Command.SuperviseArgs,
) !SuperviseChildResult {
    try child.spawn();

    const stdout_storage = try allocator.alloc(u8, SuperviseCaptureLimit);
    defer allocator.free(stdout_storage);
    const stderr_storage = try allocator.alloc(u8, SuperviseCaptureLimit);
    defer allocator.free(stderr_storage);

    var stdout_capture = SuperviseStreamCapture{ .buffer = stdout_storage };
    var stderr_capture = SuperviseStreamCapture{ .buffer = stderr_storage };

    const stdout_file = child.stdout.?;
    const stderr_file = child.stderr.?;

    const parent_stdout = std.io.getStdOut();
    const parent_stderr = std.io.getStdErr();
    const stdout_target = if (args.json) parent_stderr else parent_stdout;

    const stdout_thread = try std.Thread.spawn(.{}, readSupervisedChildStream, .{ stdout_file, &stdout_capture, stdout_target });
    const stderr_thread = try std.Thread.spawn(.{}, readSupervisedChildStream, .{ stderr_file, &stderr_capture, parent_stderr });

    stdout_thread.join();
    stderr_thread.join();
    const term = try child.wait();

    if (stdout_capture.read_error) |err| return err;
    if (stderr_capture.read_error) |err| return err;

    const stdout_items = stdout_capture.buffer[0..stdout_capture.len];
    const stderr_items = stderr_capture.buffer[0..stderr_capture.len];
    const classification: ?[]const u8 = if (superviseOutputLooksLikeCodexUsageLimit(stdout_items) or superviseOutputLooksLikeCodexUsageLimit(stderr_items))
        "codex_usage_limit"
    else
        null;
    return .{
        .term = term,
        .output_classification = classification,
        .captured_stdout_bytes = stdout_capture.len,
        .captured_stderr_bytes = stderr_capture.len,
    };
}

fn readSupervisedChildStream(
    input: std.fs.File,
    capture: *SuperviseStreamCapture,
    output: std.fs.File,
) void {
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = input.read(&chunk) catch |err| {
            capture.read_error = err;
            return;
        };
        if (n == 0) return;
        const remaining = capture.buffer.len - capture.len;
        const copy_len = @min(n, remaining);
        if (copy_len > 0) {
            @memcpy(capture.buffer[capture.len..][0..copy_len], chunk[0..copy_len]);
            capture.len += copy_len;
        }
        output.writeAll(chunk[0..n]) catch {};
    }
}

fn buildPinnedExecEnvMap(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    route: RepairPlanRoute,
    args: cli.Command.SuperviseArgs,
) !std.process.EnvMap {
    var ctx = pipeline.Context.init(allocator, cfg, store);
    defer ctx.deinit();

    ctx.provider_name = route.provider;
    ctx.account_name = route.account;
    ctx.capability_name = route.capability orelse args.capability;
    ctx.target_argv = args.target_argv;

    pipeline.runExec(&ctx) catch |e| {
        store.persist();
        return e;
    };

    var env_map = try std.process.getEnvMap(allocator);
    errdefer env_map.deinit();
    for (ctx.env_pairs.items) |pair| {
        try env_map.put(pair[0], pair[1]);
    }
    try env_map.put("OMUX_VERSION", cli.version);
    store.persist();
    return env_map;
}

fn superviseRestartAdmitted(
    args: cli.Command.SuperviseArgs,
    term: std.process.Child.Term,
    output_classification: ?[]const u8,
    restart_count: u32,
) bool {
    if (restart_count >= args.max_restarts) return false;
    if (args.restart_on_codex_usage_limit and superviseOutputClassificationIsCodexUsageLimit(output_classification)) return true;
    const expected = args.restart_on_exit_code orelse return false;
    return switch (term) {
        .Exited => |code| code == expected,
        else => false,
    };
}

fn superviseOutputClassificationIsCodexUsageLimit(classification: ?[]const u8) bool {
    return if (classification) |value| std.mem.eql(u8, value, "codex_usage_limit") else false;
}

fn superviseOutputLooksLikeCodexUsageLimit(output: []const u8) bool {
    return containsAsciiIgnoreCase(output, "you've hit your usage limit") or
        containsAsciiIgnoreCase(output, "usage limit has been reached") or
        containsAsciiIgnoreCase(output, "usage_limit_reached") or
        containsAsciiIgnoreCase(output, "UsageLimitReached") or
        containsAsciiIgnoreCase(output, "UsageLimitExceeded");
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var idx: usize = 0;
    while (idx + needle.len <= haystack.len) : (idx += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[idx .. idx + needle.len], needle)) return true;
    }
    return false;
}

fn recordStayAfloatSuperviseRouteHealth(store: *health_mod.HealthStore, route: RepairPlanRoute) bool {
    const key = repairPlanRouteHealthKey(route);
    const classification = types.HttpClassification{ .quota_exhausted = .{ .retry_after_s = 7200 } };
    store.recordHttpClassification(key.slice(), 429, classification);
    store.recordProbeEvidence(
        key.slice(),
        .supervised_child_output,
        health_mod.retryAfterFromClassification(classification),
        health_mod.hintClassFromClassification(classification),
        health_mod.decisionFromClassification(classification),
    );
    return true;
}

fn recordStayAfloatSuperviseEvent(
    allocator: std.mem.Allocator,
    args: cli.Command.SuperviseArgs,
    route: RepairPlanRoute,
    term: std.process.Child.Term,
    output_classification: ?[]const u8,
    route_health_recorded: bool,
    restart_admitted: bool,
) bool {
    const outcome = if (restart_admitted)
        "restart_admitted"
    else if (superviseTermSucceeded(term))
        "target_completed"
    else
        "target_failed";
    const reason = output_classification orelse if (args.restart_on_exit_code != null) "operator_exit_code" else "child_exit";
    repair_state.appendEvent(allocator, .{
        .kind = "stay_afloat_supervise",
        .profile = args.profile,
        .provider = route.provider,
        .account = route.account,
        .capability = route.capability orelse args.capability,
        .action = "supervise",
        .outcome = outcome,
        .reason = reason,
        .ok = superviseTermSucceeded(term),
        .executed = true,
        .interactive = args.stream_capture,
        .mutating = route_health_recorded,
    }) catch return false;
    return true;
}

fn superviseRestartClassificationSource(args: cli.Command.SuperviseArgs) []const u8 {
    if (args.restart_on_exit_code != null and args.restart_on_codex_usage_limit) return "operator_exit_code_or_codex_usage_limit_output";
    if (args.restart_on_codex_usage_limit) return "codex_usage_limit_output";
    if (args.restart_on_exit_code != null) return "operator_exit_code";
    return "none";
}

fn superviseCaptureTransport(args: cli.Command.SuperviseArgs) []const u8 {
    if (!args.restart_on_codex_usage_limit) return if (args.json) "none" else "inherit";
    return if (args.stream_capture) "streaming_pipe" else "buffered_pipe";
}

fn superviseTermSucceeded(term: std.process.Child.Term) bool {
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn superviseTermKind(term: std.process.Child.Term) []const u8 {
    return switch (term) {
        .Exited => "exited",
        .Signal => "signal",
        .Stopped => "stopped",
        .Unknown => "unknown",
    };
}

fn superviseTermCode(term: std.process.Child.Term) u32 {
    return switch (term) {
        .Exited => |code| code,
        .Signal => |signal| signal,
        .Stopped => |signal| signal,
        .Unknown => |code| code,
    };
}

fn writeStayAfloatSuperviseJson(
    writer: anytype,
    args: cli.Command.SuperviseArgs,
    attempts: []const SuperviseAttempt,
    restart_count: u32,
    reason: []const u8,
) !void {
    const ok = attempts.len > 0 and superviseTermSucceeded(attempts[attempts.len - 1].term);
    const prepared_fallback = attempts.len > 0;
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"stay_afloat_supervise\",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(reason, .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":");
    try std.json.stringify(if (restart_count > 0) "supervised_restart" else "supervised_process", .{}, writer);
    try writer.writeAll(",\"prepared_fallback\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"supervised_restart\":");
    try writer.writeAll(if (restart_count > 0) "true" else "false");
    try writer.writeAll(",\"wrapper_owned_process\":true,\"restart_classification_source\":");
    try std.json.stringify(superviseRestartClassificationSource(args), .{}, writer);
    try writer.writeAll(",\"route_health_recorded\":");
    try writer.writeAll(if (superviseAttemptsRecordedRouteHealth(attempts)) "true" else "false");
    try writer.writeAll(",\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"max_restarts\":");
    try writer.print("{d}", .{args.max_restarts});
    try writer.writeAll(",\"restart_on_exit_code\":");
    if (args.restart_on_exit_code) |code| try writer.print("{d}", .{code}) else try writer.writeAll("null");
    try writer.writeAll(",\"restart_on_codex_usage_limit\":");
    try writer.writeAll(if (args.restart_on_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"capture_transport\":");
    try std.json.stringify(superviseCaptureTransport(args), .{}, writer);
    try writer.writeAll(",\"live_child_output_streamed\":");
    try writer.writeAll(if (args.stream_capture and args.restart_on_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"restart_count\":");
    try writer.print("{d}", .{restart_count});
    try writer.writeAll(",\"attempts\":[");
    for (attempts, 0..) |attempt, idx| {
        if (idx != 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"selected\":");
        try writeRouteSelectionJson(writer, attempt.route);
        try writer.writeAll(",\"term\":{\"kind\":");
        try std.json.stringify(superviseTermKind(attempt.term), .{}, writer);
        try writer.writeAll(",\"code\":");
        try writer.print("{d}", .{superviseTermCode(attempt.term)});
        try writer.writeAll("},\"output_classification\":");
        if (attempt.output_classification) |classification| try std.json.stringify(classification, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"captured_stdout_bytes\":");
        try writer.print("{d}", .{attempt.captured_stdout_bytes});
        try writer.writeAll(",\"captured_stderr_bytes\":");
        try writer.print("{d}", .{attempt.captured_stderr_bytes});
        try writer.writeAll(",\"route_health_recorded\":");
        try writer.writeAll(if (attempt.route_health_recorded) "true" else "false");
        try writer.writeAll(",\"event_recorded\":");
        try writer.writeAll(if (attempt.event_recorded) "true" else "false");
        try writer.writeAll(",\"restart_admitted\":");
        try writer.writeAll(if (attempt.restart_admitted) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"redaction\":{\"tokens_printed\":false,\"captured_output_in_json\":false,\"captured_output_printed\":false,\"live_child_output_streamed\":");
    try writer.writeAll(if (args.stream_capture and args.restart_on_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"raw_protocol_printed\":false}}\n");
}

fn writeStayAfloatSuperviseText(
    writer: anytype,
    args: cli.Command.SuperviseArgs,
    attempts: []const SuperviseAttempt,
    restart_count: u32,
    reason: []const u8,
) !void {
    const ok = attempts.len > 0 and superviseTermSucceeded(attempts[attempts.len - 1].term);
    try writer.writeAll("oauth-mux stay-afloat supervise\n\n");
    try writer.print("  ok: {s}\n", .{if (ok) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
    try writer.print("  max restarts: {d}\n", .{args.max_restarts});
    try writer.writeAll("  restart on exit code: ");
    if (args.restart_on_exit_code) |code| try writer.print("{d}\n", .{code}) else try writer.writeAll("not configured\n");
    try writer.print("  restart on Codex usage limit: {s}\n", .{if (args.restart_on_codex_usage_limit) "true" else "false"});
    try writer.print("  capture transport: {s}\n", .{superviseCaptureTransport(args)});
    try writer.print("  live child output streamed: {s}\n", .{if (args.stream_capture and args.restart_on_codex_usage_limit) "true" else "false"});
    try writer.print("  restart count: {d}\n", .{restart_count});
    for (attempts, 0..) |attempt, idx| {
        try writer.print("  attempt {d}: {s}:{s}", .{ idx + 1, attempt.route.provider, attempt.route.account });
        if (attempt.route.capability) |cap| try writer.print("#{s}", .{cap});
        try writer.print(" {s}:{d} restart_admitted={s}", .{
            superviseTermKind(attempt.term),
            superviseTermCode(attempt.term),
            if (attempt.restart_admitted) "true" else "false",
        });
        if (attempt.output_classification) |classification| try writer.print(" classification={s}", .{classification});
        if (attempt.route_health_recorded) try writer.writeAll(" route_health_recorded=true");
        if (attempt.event_recorded) try writer.writeAll(" event_recorded=true");
        try writer.writeByte('\n');
    }
    try writer.writeAll("  boundary: wrapper-owned child restart only; no current-process hot-swap or per-request muxing\n");
}

fn superviseAttemptsRecordedRouteHealth(attempts: []const SuperviseAttempt) bool {
    for (attempts) |attempt| {
        if (attempt.route_health_recorded) return true;
    }
    return false;
}

fn firstSelectableRouteNotAttempted(
    evaluations: []const RouteEvaluation,
    attempted_routes: []const RepairPlanRoute,
) ?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (!evaluation.selectable) continue;
        if (routeWasAttempted(evaluation.route, attempted_routes)) continue;
        return idx;
    }
    return null;
}

fn routeWasAttempted(route: RepairPlanRoute, attempted_routes: []const RepairPlanRoute) bool {
    for (attempted_routes) |attempted| {
        if (routesEqual(route, attempted)) return true;
    }
    return false;
}

fn routesEqual(a: RepairPlanRoute, b: RepairPlanRoute) bool {
    return std.mem.eql(u8, a.provider, b.provider) and
        std.mem.eql(u8, a.account, b.account) and
        optionalStringsEqual(a.capability, b.capability);
}

fn optionalStringsEqual(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |a_value| {
        const b_value = b orelse return false;
        return std.mem.eql(u8, a_value, b_value);
    }
    return b == null;
}

fn writeStayAfloatLaunchMediationFromCurrentState(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: config.Config,
    routes: []const RepairPlanRoute,
    selector: cli.Command.RouteArgs,
) !void {
    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, cfg, &store, routes, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);
    const candidate_index = if (selected_index == null) firstActionableRoute(evaluations.items) else null;
    try writeStayAfloatMediationText(
        writer,
        allocator,
        evaluations.items,
        selected_index,
        candidate_index,
        selector,
        "oauth-mux stay-afloat launch",
    );
}

fn runDaemonTick(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.DaemonTickArgs,
    command_name: []const u8,
) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, daemonTickArgsToPlanArgs(args));
    defer routes.deinit();

    const iterations = normalizedDaemonTickIterations(args);
    if (args.json and iterations > 1) {
        try writer.writeAll("{\"version\":");
        try std.json.stringify(cli.version, .{}, writer);
        try writer.writeAll(",\"mode\":\"loop\",\"execution_mode\":");
        try std.json.stringify(if (args.execute) "execute" else "plan", .{}, writer);
        try writer.writeAll(",\"executed\":false,\"message\":");
        try std.json.stringify(daemonTickMessage(args), .{}, writer);
        try writer.writeAll(",\"iterations_requested\":");
        try writer.print("{d}", .{iterations});
        try writer.writeAll(",\"interval_ms\":");
        try writer.print("{d}", .{args.interval_ms});
        try writer.writeAll(",\"ticks\":[");
    }

    var idx: u32 = 0;
    while (idx < iterations) : (idx += 1) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer evaluations.deinit();
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

        var selected_index = firstSelectableRoute(evaluations.items);
        const observed_at = std.time.timestamp();
        var executions = std.ArrayList(DaemonTickExecution).init(allocator);
        defer executions.deinit();

        const state_changed = if (args.execute)
            try executeDaemonTickActions(allocator, parsed.value, args, evaluations.items, selected_index, &executions)
        else
            false;
        if (state_changed) {
            store.deinit();
            store = health_mod.HealthStore.load(allocator, .{});
            evaluations.clearRetainingCapacity();
            try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);
            selected_index = firstSelectableRoute(evaluations.items);
        }

        writeDaemonTickSnapshot(allocator, parsed.value, evaluations.items, selected_index, executions.items, args, observed_at) catch {};

        if (args.json) {
            if (iterations > 1) {
                if (idx > 0) try writer.writeByte(',');
                try writeDaemonTickJsonObject(writer, allocator, parsed.value, evaluations.items, selected_index, executions.items, args, idx, observed_at, false);
            } else {
                try writeDaemonTickJsonObject(writer, allocator, parsed.value, evaluations.items, selected_index, executions.items, args, idx, observed_at, true);
                try writer.writeByte('\n');
            }
        } else {
            if (iterations > 1) try writer.print("tick {d}/{d}\n", .{ idx + 1, iterations });
            try writeDaemonTickText(writer, allocator, parsed.value, evaluations.items, selected_index, executions.items, args, observed_at, command_name);
            if (iterations > 1 and idx + 1 < iterations) try writer.writeByte('\n');
        }

        const stats = daemonTickStats(parsed.value.policy.daemon, evaluations.items, observed_at);
        sleepBetweenDaemonTicks(args, idx, iterations, stats, observed_at);
    }

    if (args.json and iterations > 1) {
        try writer.writeAll("]}\n");
    }
}

fn runSupervisedStayAfloat(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.DaemonTickArgs,
) !void {
    var tick_args = args;
    tick_args.execute = true;
    tick_args.json = false;

    var guard = try daemon.acquireStayAfloatRunGuard(allocator, .{
        .profile = tick_args.profile,
        .provider = tick_args.provider,
        .account = tick_args.account,
        .capability = tick_args.capability,
        .once = tick_args.once,
        .iterations = normalizedDaemonTickIterations(tick_args),
        .interval_ms = tick_args.interval_ms,
        .execute = tick_args.execute,
    });
    defer guard.release();

    try runDaemonTick(allocator, writer, tick_args, "oauth-mux daemon run --stay-afloat");
}

fn writeDaemonTickSnapshot(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    executions: []const DaemonTickExecution,
    args: cli.Command.DaemonTickArgs,
    observed_at: i64,
) !void {
    var snapshot = std.ArrayList(u8).init(allocator);
    defer snapshot.deinit();
    const writer = snapshot.writer();
    const stats = daemonTickStats(cfg.policy.daemon, evaluations, observed_at);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"contract\":\"foreground_tick_snapshot\"");
    try writer.writeAll(",\"last_tick_at\":");
    try writer.print("{d}", .{observed_at});
    try writer.writeAll(",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"mode\":");
    try std.json.stringify(if (args.once) "once" else "loop", .{}, writer);
    try writer.writeAll(",\"execution_mode\":");
    try std.json.stringify(if (args.execute) "execute" else "plan", .{}, writer);
    try writer.writeAll(",\"executed\":");
    try writer.writeAll(if (daemonTickExecutionsRan(executions)) "true" else "false");
    try writer.writeAll(",\"handoff_queued\":");
    try writer.writeAll(if (daemonTickHandoffQueued(executions)) "true" else "false");
    try writer.writeAll(",\"handoff_pending\":");
    try writer.writeAll(if (daemonTickHandoffPending(executions)) "true" else "false");
    try writer.writeAll(",\"afloat\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJson(writer, evaluations, selected_index);
    try writer.writeAll(",\"claim\":");
    try writeStayAfloatClaimJson(writer, selectorFromDaemonTickArgs(args), selectedRoute(evaluations, selected_index), selectableFallbackRouteCount(evaluations, selected_index));
    try writer.writeAll(",\"summary\":");
    try writeDaemonTickStatsJson(writer, stats);
    try writer.writeByte('}');

    try repair_state.writeDaemonSnapshot(allocator, snapshot.items);
}

fn selectedRoute(evaluations: []const RouteEvaluation, selected_index: ?usize) ?RepairPlanRoute {
    if (selected_index) |idx| {
        if (idx < evaluations.len) return evaluations[idx].route;
    }
    return null;
}

fn selectableFallbackRouteCount(evaluations: []const RouteEvaluation, selected_index: ?usize) usize {
    var count: usize = 0;
    for (evaluations, 0..) |evaluation, idx| {
        if (!evaluation.selectable) continue;
        if (selected_index) |selected| {
            if (idx == selected) continue;
        }
        count += 1;
    }
    return count;
}

fn writeRouteResilienceJson(
    writer: anytype,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    const selected = selected_index != null;
    try writer.writeByte('{');
    try writer.writeAll("\"selected_route_ready\":");
    try writer.writeAll(if (selected) "true" else "false");
    try writer.print(",\"selectable_fallback_routes\":{d}", .{fallback_count});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (selected and fallback_count > 0) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (selected and fallback_count == 0) "true" else "false");
    try writer.writeAll(",\"state\":");
    try std.json.stringify(if (!selected) "not_afloat" else if (fallback_count > 0) "afloat_with_spare_fallback" else "afloat_without_spare_fallback", .{}, writer);
    try writer.writeByte('}');
}

fn writeRouteResilienceActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: ?[]const u8,
) !void {
    const selected = selected_index orelse {
        try writer.writeAll("[]");
        return;
    };
    if (selected >= evaluations.len or !std.mem.eql(u8, evaluations[selected].route.provider, "codex")) {
        try writer.writeAll("[]");
        return;
    }

    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    const action_capability = capability orelse evaluations[selected].route.capability;
    try writeCodexBrokerSessionRiskActionsJson(writer, allocator, profile, action_capability, true, fallback_count);
}

fn writeRouteResilienceActionsText(
    writer: anytype,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    const selected = selected_index orelse return;
    if (selected >= evaluations.len) return;
    const route = evaluations[selected].route;
    if (!std.mem.eql(u8, route.provider, "codex")) return;
    if (!codexBrokerSessionSingleRouteAtRisk(true, selectableFallbackRouteCount(evaluations, selected_index))) return;

    try writer.writeAll("  next: revalidate exhausted routes, enroll another Codex account, or wait for quota reset\n");
}

const StayAfloatSelector = struct {
    profile: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    capability: ?[]const u8 = null,
};

fn selectorFromDaemonTickArgs(args: cli.Command.DaemonTickArgs) StayAfloatSelector {
    return .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
    };
}

fn selectorFromRouteArgs(args: cli.Command.RouteArgs) StayAfloatSelector {
    return .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
    };
}

fn writeStayAfloatClaimJson(
    writer: anytype,
    selector: StayAfloatSelector,
    route: ?RepairPlanRoute,
    selectable_fallback_routes: usize,
) !void {
    const prepared = route != null;
    try writer.writeAll("{\"claim_version\":1");
    try writer.writeAll(",\"level\":");
    try std.json.stringify(if (prepared) "prepared_fallback" else "mediation_required", .{}, writer);
    try writer.writeAll(",\"max_supported_level\":\"prepared_fallback\"");
    try writer.writeAll(",\"prepared_fallback\":");
    try writer.writeAll(if (prepared) "true" else "false");
    try writer.print(",\"selectable_fallback_routes\":{d}", .{selectable_fallback_routes});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (prepared and selectable_fallback_routes > 0) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (prepared and selectable_fallback_routes == 0) "true" else "false");
    try writer.writeAll(",\"requires_mediation\":true");
    try writer.writeAll(",\"mediation_point\":\"stay-afloat launch\"");
    try writer.writeAll(",\"target_boundary\":\"process_start\"");
    try writer.writeAll(",\"current_process_hotswap\":false");
    try writer.writeAll(",\"supervised_restart\":false");
    try writer.writeAll(",\"per_request_muxing\":false");
    try writer.writeAll(",\"launch_argv\":");
    try writeStayAfloatLaunchArgvJson(writer, selector);
    try writer.writeByte('}');
}

fn writeStayAfloatLaunchArgvJson(writer: anytype, selector: StayAfloatSelector) !void {
    var first = true;
    try writer.writeByte('[');
    try writeJsonArrayString(writer, &first, "oauth-mux");
    try writeJsonArrayString(writer, &first, "stay-afloat");
    try writeJsonArrayString(writer, &first, "launch");
    if (selector.profile) |profile_name| {
        try writeJsonArrayString(writer, &first, "--profile");
        try writeJsonArrayString(writer, &first, profile_name);
    }
    if (selector.provider) |provider_name| {
        try writeJsonArrayString(writer, &first, "--provider");
        try writeJsonArrayString(writer, &first, provider_name);
    }
    if (selector.account) |account| {
        try writeJsonArrayString(writer, &first, "--account");
        try writeJsonArrayString(writer, &first, account);
    }
    if (selector.capability) |capability| {
        try writeJsonArrayString(writer, &first, "--capability");
        try writeJsonArrayString(writer, &first, capability);
    }
    try writeJsonArrayString(writer, &first, "--");
    try writeJsonArrayString(writer, &first, "<command>");
    try writer.writeByte(']');
}

fn daemonTickArgsToPlanArgs(args: cli.Command.DaemonTickArgs) cli.Command.RepairPlanArgs {
    return .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
        .json = args.json,
    };
}

fn normalizedDaemonTickIterations(args: cli.Command.DaemonTickArgs) u32 {
    if (args.once) return 1;
    return @max(args.iterations, 1);
}

fn sleepBetweenDaemonTicks(args: cli.Command.DaemonTickArgs, idx: u32, iterations: u32, stats: DaemonTickStats, observed_at: i64) void {
    const sleep_ms = daemonTickSleepMs(args, idx, iterations, stats, observed_at);
    if (sleep_ms == 0) return;
    std.time.sleep(sleep_ms * std.time.ns_per_ms);
}

fn daemonTickSleepMs(args: cli.Command.DaemonTickArgs, idx: u32, iterations: u32, stats: DaemonTickStats, observed_at: i64) u64 {
    if (idx + 1 >= iterations) return 0;
    if (args.interval_ms == 0) return 0;
    const max_ms = std.math.maxInt(u64) / std.time.ns_per_ms;
    var sleep_ms = @min(args.interval_ms, max_ms);

    if (stats.next_tick_after) |next_tick_after| {
        if (next_tick_after <= observed_at) return 0;
        const seconds_until: u64 = @intCast(next_tick_after - observed_at);
        const hint_ms = if (seconds_until > max_ms / 1000)
            max_ms
        else
            seconds_until * 1000;
        sleep_ms = @min(sleep_ms, hint_ms);
    }

    return sleep_ms;
}

fn runStayAfloatHandoff(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.HandoffArgs,
) !void {
    const provider_name = args.provider orelse return error.ConfigValidationError;
    const account = args.account orelse return error.ConfigValidationError;
    const key = repair_state.HandoffKey{
        .profile = args.profile,
        .provider = provider_name,
        .account = account,
        .capability = args.capability,
    };
    const pending_before = try repair_state.hasPendingHandoff(allocator, key);

    var event_recorded = false;
    const outcome = switch (args.action) {
        .ack => "handoff_acknowledged",
        .clear => "handoff_resolved",
    };
    const reason = switch (args.action) {
        .ack => if (pending_before) "user_acknowledged" else "no_pending_handoff",
        .clear => if (pending_before) "manual_clear" else "no_pending_handoff",
    };

    if (pending_before) {
        try repair_state.appendEvent(allocator, .{
            .kind = "daemon_handoff",
            .profile = args.profile,
            .provider = provider_name,
            .account = account,
            .capability = args.capability,
            .action = @tagName(args.action),
            .outcome = outcome,
            .reason = reason,
            .ok = true,
            .executed = false,
            .interactive = true,
            .mutating = false,
        });
        event_recorded = true;
    }

    const pending_after = try repair_state.hasPendingHandoff(allocator, key);

    if (args.json) {
        try writer.writeAll("{\"ok\":true,\"action\":");
        try std.json.stringify(@tagName(args.action), .{}, writer);
        try writer.writeAll(",\"profile\":");
        if (args.profile) |profile| try std.json.stringify(profile, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"provider\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"capability\":");
        if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"handoff_pending\":");
        try writer.writeAll(if (pending_after) "true" else "false");
        try writer.writeAll(",\"handoff_acknowledged\":");
        try writer.writeAll(if (args.action == .ack and event_recorded) "true" else "false");
        try writer.writeAll(",\"handoff_resolved\":");
        try writer.writeAll(if (args.action == .clear and event_recorded and !pending_after) "true" else "false");
        try writer.writeAll(",\"event_recorded\":");
        try writer.writeAll(if (event_recorded) "true" else "false");
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(reason, .{}, writer);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux stay-afloat handoff\n\n");
    try writer.print("  action: {s}\n", .{@tagName(args.action)});
    try writer.print("  provider: {s}\n", .{provider_name});
    try writer.print("  account: {s}\n", .{account});
    if (args.profile) |profile| try writer.print("  profile: {s}\n", .{profile});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    try writer.print("  handoff_pending: {s}\n", .{if (pending_after) "true" else "false"});
    try writer.print("  handoff_acknowledged: {s}\n", .{if (args.action == .ack and event_recorded) "true" else "false"});
    try writer.print("  handoff_resolved: {s}\n", .{if (args.action == .clear and event_recorded and !pending_after) "true" else "false"});
    try writer.print("  event_recorded: {s}\n", .{if (event_recorded) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
}

fn daemonTickMessage(args: cli.Command.DaemonTickArgs) []const u8 {
    return if (args.execute)
        "execute mode; at most one admitted non-interactive action runs per tick"
    else
        "planning only; no probes or repair commands executed";
}

fn executeDaemonTickActions(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    args: cli.Command.DaemonTickArgs,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    executions: *std.ArrayList(DaemonTickExecution),
) !bool {
    if (selected_index) |idx| {
        recordDaemonActionEvent(allocator, args, evaluations[idx], .none, "none", "route_selectable", "route_selectable", true, false, false);
        return false;
    }

    for (evaluations) |evaluation| {
        const decision = daemonTickDecision(cfg.policy.daemon, evaluation, std.time.timestamp());
        if (std.mem.eql(u8, decision.phase, "repair") and evaluation.action.interactive) {
            try queueDaemonHandoff(allocator, args, evaluation, decision, executions);
            return false;
        }
        if (!decision.admitted) continue;

        if (std.mem.eql(u8, decision.phase, "probe")) {
            return try executeDaemonProbe(allocator, args, evaluation, decision, executions);
        }

        if (std.mem.eql(u8, decision.phase, "repair") and
            evaluation.action.command != .none and
            !evaluation.action.interactive)
        {
            return try executeDaemonRepairCommand(allocator, cfg, args, evaluation, decision, executions);
        }
    }

    return false;
}

fn executeDaemonProbe(
    allocator: std.mem.Allocator,
    args: cli.Command.DaemonTickArgs,
    evaluation: RouteEvaluation,
    decision: DaemonTickDecision,
    executions: *std.ArrayList(DaemonTickExecution),
) !bool {
    var scratch = std.ArrayList(u8).init(allocator);
    defer scratch.deinit();

    var ok = true;
    var reason: []const u8 = "probe_completed";
    runProbe(allocator, scratch.writer(), .{
        .provider = evaluation.route.provider,
        .account = evaluation.route.account,
        .capability = evaluation.route.capability,
        .json = true,
    }) catch |e| {
        ok = false;
        reason = @errorName(e);
    };

    try executions.append(.{
        .route = evaluation.route,
        .phase = "probe",
        .action = "probe",
        .admitted = true,
        .executed = true,
        .ok = ok,
        .reason = reason,
        .budget = decision.budget,
        .command = .probe,
    });
    recordDaemonActionEvent(allocator, args, evaluation, .probe, "probe", if (ok) "executed" else "failed", reason, ok, true, false);
    return true;
}

fn executeDaemonRepairCommand(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    args: cli.Command.DaemonTickArgs,
    evaluation: RouteEvaluation,
    decision: DaemonTickDecision,
    executions: *std.ArrayList(DaemonTickExecution),
) !bool {
    var lock = repair_state.acquireRepairLock(allocator, evaluation.route.provider, evaluation.route.account) catch |e| switch (e) {
        error.RepairInProgress => {
            try executions.append(.{
                .route = evaluation.route,
                .phase = "repair",
                .action = @tagName(evaluation.action.kind),
                .admitted = true,
                .executed = false,
                .ok = false,
                .reason = "repair_in_progress",
                .budget = decision.budget,
                .command = evaluation.action.command,
            });
            recordDaemonActionEvent(allocator, args, evaluation, evaluation.action.command, @tagName(evaluation.action.kind), "repair_in_progress", "lock_busy", false, false, false);
            return false;
        },
        else => return e,
    };
    defer lock.release();

    const ok = try executeRepairCommand(allocator, cfg, evaluation);
    try executions.append(.{
        .route = evaluation.route,
        .phase = "repair",
        .action = @tagName(evaluation.action.kind),
        .admitted = true,
        .executed = true,
        .ok = ok,
        .reason = if (ok) "command_success" else "command_failed",
        .budget = decision.budget,
        .command = evaluation.action.command,
    });
    recordDaemonActionEvent(allocator, args, evaluation, evaluation.action.command, @tagName(evaluation.action.kind), if (ok) "executed" else "failed", if (ok) "command_success" else "command_failed", ok, true, false);
    return ok;
}

fn queueDaemonHandoff(
    allocator: std.mem.Allocator,
    args: cli.Command.DaemonTickArgs,
    evaluation: RouteEvaluation,
    decision: DaemonTickDecision,
    executions: *std.ArrayList(DaemonTickExecution),
) !void {
    const pending = try repair_state.hasPendingHandoff(allocator, .{
        .profile = args.profile,
        .provider = evaluation.route.provider,
        .account = evaluation.route.account,
        .capability = evaluation.route.capability,
    });
    if (pending) {
        try executions.append(.{
            .route = evaluation.route,
            .phase = "handoff",
            .action = @tagName(evaluation.action.kind),
            .admitted = decision.admitted,
            .executed = false,
            .ok = false,
            .handoff = true,
            .handoff_queued = false,
            .reason = "handoff_pending",
            .budget = decision.budget,
            .command = evaluation.action.command,
        });
        return;
    }

    try executions.append(.{
        .route = evaluation.route,
        .phase = "handoff",
        .action = @tagName(evaluation.action.kind),
        .admitted = decision.admitted,
        .executed = false,
        .ok = false,
        .handoff = true,
        .handoff_queued = true,
        .reason = "interactive_user_handoff",
        .budget = decision.budget,
        .command = evaluation.action.command,
    });
    recordDaemonActionEvent(allocator, args, evaluation, evaluation.action.command, @tagName(evaluation.action.kind), "handoff_queued", "interactive_user_handoff", false, false, true);
}

fn recordDaemonActionEvent(
    allocator: std.mem.Allocator,
    args: cli.Command.DaemonTickArgs,
    evaluation: RouteEvaluation,
    command_kind: RepairCommandKind,
    action: []const u8,
    outcome: []const u8,
    reason: []const u8,
    ok: bool,
    executed: bool,
    handoff: bool,
) void {
    const command = repairCommandAlloc(allocator, command_kind, evaluation.route) catch null;
    defer if (command) |value| allocator.free(value);
    repair_state.appendEvent(allocator, .{
        .kind = if (handoff) "daemon_handoff" else "daemon_action",
        .profile = args.profile,
        .provider = evaluation.route.provider,
        .account = evaluation.route.account,
        .capability = evaluation.route.capability,
        .action = action,
        .command = command,
        .outcome = outcome,
        .reason = reason,
        .ok = ok,
        .executed = executed,
        .interactive = evaluation.action.interactive,
        .mutating = evaluation.action.mutating,
    }) catch {};
}

fn collectRouteEvaluations(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    routes: []const RepairPlanRoute,
    evaluations: *std.ArrayList(RouteEvaluation),
) !void {
    for (routes) |route| {
        const def = config.resolveProviderDefinition(cfg, route.provider);
        const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
        const health = routeHealth(store, route);
        const budget = routeProbeBudget(def, route.capability);
        const action = repairActionFor(route, def, runtime, health, budget);
        const selectable = routeSelectable(runtime, health);
        try evaluations.append(.{
            .route = route,
            .runtime = runtime,
            .health = health,
            .budget = budget,
            .action = action,
            .selectable = selectable,
            .skip_reason = if (selectable) "available" else routeSkipReason(runtime, health),
        });
    }
}

fn firstSelectableRoute(evaluations: []const RouteEvaluation) ?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (evaluation.selectable) return idx;
    }
    return null;
}

fn firstActionableRoute(evaluations: []const RouteEvaluation) ?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (evaluation.action.kind != .none) return idx;
    }
    if (evaluations.len > 0) return 0;
    return null;
}

fn routeSelectable(runtime: types.RuntimeReadiness, health: ?health_mod.AccountHealth) bool {
    const current = health orelse return false;
    return types.selectable(current.liveness, runtime);
}

fn routeSkipReason(runtime: types.RuntimeReadiness, health: ?health_mod.AccountHealth) []const u8 {
    if (!runtime.isReady()) return runtimeReadinessSummary(runtime);
    const current = health orelse return "unrecorded";
    return switch (current.liveness) {
        .live => |live| switch (live.availability) {
            .available => "available",
            .rate_limited => "rate_limited",
            .quota_exhausted => "quota_exhausted",
            .cooldown => "cooldown",
        },
        .degraded => |degraded| @tagName(degraded.reason),
        .dead => |dead| @tagName(dead.reason),
    };
}

fn writeRouteText(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RouteArgs,
) !void {
    try writer.print("oauth-mux route {s}\n\n", .{@tagName(args.action)});
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    if (selected_index) |idx| {
        const selected = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ selected.provider, selected.account });
        if (selected.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.writeByte('\n');
        try writeRouteResilienceActionsText(writer, evaluations, selected_index);
    } else {
        try writer.writeAll("  selected: none\n");
    }

    if (evaluations.len == 0) {
        try writer.writeAll("  no matching configured routes\n");
        return;
    }

    try writer.writeAll("\n  routes:\n");
    for (evaluations) |evaluation| {
        try writer.print("    {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
        if (evaluation.route.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.print(" selectable={s} runtime={s}", .{
            if (evaluation.selectable) "true" else "false",
            runtimeReadinessSummary(evaluation.runtime),
        });
        if (evaluation.budget) |budget| try writer.print(" probe_budget={s}", .{@tagName(budget)});
        try writer.writeAll(" liveness=");
        if (evaluation.health) |health| {
            try health_mod.writeLivenessSummary(writer, health.liveness);
        } else {
            try writer.writeAll("unrecorded");
        }
        try writer.print(" reason={s}", .{evaluation.skip_reason});
        if (args.action == .explain) {
            try writer.print(" action={s}", .{@tagName(evaluation.action.kind)});
            if (try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route)) |command| {
                defer allocator.free(command);
                try writer.print(" command={s}", .{command});
            }
            if (try runtimeDiagnosticCommandAlloc(allocator, evaluation.action, evaluation.route)) |command| {
                defer allocator.free(command);
                try writer.print(" diagnostic={s}", .{command});
            }
        }
        try writer.writeByte('\n');
    }
}

fn writeStayAfloatNextText(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    candidate_index: ?usize,
    args: cli.Command.RouteArgs,
) !void {
    try writeStayAfloatMediationText(writer, allocator, evaluations, selected_index, candidate_index, args, "oauth-mux stay-afloat next");
}

fn writeStayAfloatMediationText(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    candidate_index: ?usize,
    args: cli.Command.RouteArgs,
    command_name: []const u8,
) !void {
    try writer.print("{s}\n\n", .{command_name});
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (args.provider) |provider_name| try writer.print("  provider: {s}\n", .{provider_name});
    if (args.account) |account| try writer.print("  account: {s}\n", .{account});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});

    if (selected_index) |idx| {
        const selected = evaluations[idx].route;
        try writer.writeAll("  ready_for_exec: true\n");
        try writer.print("  selected: {s}:{s}", .{ selected.provider, selected.account });
        if (selected.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.writeByte('\n');
        try writeRouteResilienceActionsText(writer, evaluations, selected_index);
        try writer.writeAll("  exec: ");
        try writeStayAfloatExecCommandText(writer, selected);
        try writer.writeByte('\n');
        return;
    }

    try writer.writeAll("  ready_for_exec: false\n");
    if (candidate_index) |idx| {
        const candidate = evaluations[idx];
        try writer.print("  next_action: {s} {s}\n", .{ @tagName(candidate.action.kind), candidate.action.message });
        if (try repairCommandAlloc(allocator, candidate.action.command, candidate.route)) |command| {
            defer allocator.free(command);
            try writer.print("  command: {s}\n", .{command});
        }
        if (try runtimeDiagnosticCommandAlloc(allocator, candidate.action, candidate.route)) |command| {
            defer allocator.free(command);
            try writer.print("  diagnostic: {s}\n", .{command});
        }
    } else {
        try writer.writeAll("  next_action: none no matching routes\n");
    }
}

fn writeRouteJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RouteArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"action\":");
    try std.json.stringify(@tagName(args.action), .{}, writer);
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
    try writer.writeAll(",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJson(writer, evaluations, selected_index);
    try writer.writeAll(",\"resilience_actions\":");
    try writeRouteResilienceActionsJson(writer, allocator, evaluations, selected_index, args.profile, args.capability);
    try writer.writeAll(",\"routes\":[");
    for (evaluations, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected| idx == selected else false;
        try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, selected);
    }
    try writer.writeAll("]}\n");
}

fn writeStayAfloatNextJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    candidate_index: ?usize,
    args: cli.Command.RouteArgs,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"action\":\"next\"");
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
    try writer.writeAll(",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"provider\":");
    if (args.provider) |provider_name| try std.json.stringify(provider_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (args.account) |account| try std.json.stringify(account, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"ready_for_exec\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJson(writer, evaluations, selected_index);
    try writer.writeAll(",\"resilience_actions\":");
    try writeRouteResilienceActionsJson(writer, allocator, evaluations, selected_index, args.profile, args.capability);
    try writer.writeAll(",\"claim\":");
    try writeStayAfloatClaimJson(writer, selectorFromRouteArgs(args), selectedRoute(evaluations, selected_index), selectableFallbackRouteCount(evaluations, selected_index));
    try writer.writeAll(",\"next_action\":");
    try writeStayAfloatNextActionJson(writer, allocator, evaluations, selected_index, candidate_index);
    try writer.writeAll(",\"routes\":[");
    for (evaluations, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected| idx == selected else false;
        try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, selected);
    }
    try writer.writeAll("]}\n");
}

fn writeStayAfloatNextActionJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    candidate_index: ?usize,
) !void {
    if (selected_index) |idx| {
        const route = evaluations[idx].route;
        try writer.writeAll("{\"kind\":\"exec\",\"reason\":\"route_selectable\",\"agent_safe\":true,\"runs_target\":false,\"route\":");
        try writeRouteSelectionJson(writer, route);
        try writer.writeAll(",\"exec_argv\":");
        try writeStayAfloatExecArgvJson(writer, route);
        try writer.writeAll(",\"target_placeholder\":\"<command>\"}");
        return;
    }

    if (candidate_index) |idx| {
        const evaluation = evaluations[idx];
        try writer.writeAll("{\"kind\":\"repair\",\"reason\":\"no_selectable_route\",\"agent_safe\":true,\"runs_target\":false,\"route\":");
        try writeRouteSelectionJson(writer, evaluation.route);
        try writer.writeAll(",\"action\":");
        try writeRepairActionJson(writer, allocator, evaluation.action, evaluation.route);
        try writer.writeByte('}');
        return;
    }

    try writer.writeAll("{\"kind\":\"none\",\"reason\":\"no_matching_routes\",\"agent_safe\":true,\"runs_target\":false}");
}

fn writeStayAfloatExecArgvJson(writer: anytype, route: RepairPlanRoute) !void {
    var first = true;
    try writer.writeByte('[');
    try writeJsonArrayString(writer, &first, "oauth-mux");
    try writeJsonArrayString(writer, &first, "exec");
    try writeJsonArrayString(writer, &first, "--provider");
    try writeJsonArrayString(writer, &first, route.provider);
    try writeJsonArrayString(writer, &first, "--account");
    try writeJsonArrayString(writer, &first, route.account);
    if (route.capability) |capability| {
        try writeJsonArrayString(writer, &first, "--capability");
        try writeJsonArrayString(writer, &first, capability);
    }
    try writeJsonArrayString(writer, &first, "--");
    try writeJsonArrayString(writer, &first, "<command>");
    try writer.writeByte(']');
}

fn writeJsonArrayString(writer: anytype, first: *bool, value: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try std.json.stringify(value, .{}, writer);
}

fn writeStayAfloatExecCommandText(writer: anytype, route: RepairPlanRoute) !void {
    try writer.print("oauth-mux exec --provider {s} --account {s}", .{ route.provider, route.account });
    if (route.capability) |capability| try writer.print(" --capability {s}", .{capability});
    try writer.writeAll(" -- <command>");
}

fn writeRouteSelectionJson(writer: anytype, route: RepairPlanRoute) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (route.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"health_key\":");
    if (route.capability) |capability| {
        const key = health_mod.capabilityKey(route.provider, route.account, capability);
        try std.json.stringify(key.slice(), .{}, writer);
    } else {
        const key = health_mod.accountKey(route.provider, route.account);
        try std.json.stringify(key.slice(), .{}, writer);
    }
    try writer.writeByte('}');
}

fn writeRouteEvaluationJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    selected: bool,
) !void {
    const def = config.resolveProviderDefinition(cfg, evaluation.route.provider);
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(evaluation.route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(evaluation.route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (evaluation.route.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"selected\":");
    try writer.writeAll(if (selected) "true" else "false");
    try writer.writeAll(",\"selectable\":");
    try writer.writeAll(if (evaluation.selectable) "true" else "false");
    try writer.writeAll(",\"skip_reason\":");
    try std.json.stringify(evaluation.skip_reason, .{}, writer);
    try writer.writeAll(",\"extension_mode\":");
    try std.json.stringify(@tagName(def.extension_mode), .{}, writer);
    try writer.writeAll(",\"repair_owner\":");
    try std.json.stringify(@tagName(def.repair.owner), .{}, writer);
    try writer.writeAll(",\"writeback\":");
    try writeRouteWritebackJson(writer, cfg, evaluation.route, def);
    try writer.writeAll(",\"probe_budget\":");
    if (evaluation.budget) |budget| try std.json.stringify(@tagName(budget), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"admission\":");
    try writeRouteAdmissionJson(writer, cfg.policy, evaluation.action, evaluation.budget);
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessJson(writer, evaluation.runtime);
    try writer.writeAll(",\"liveness\":");
    if (evaluation.health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
    try writer.writeAll(",\"last_probe\":");
    if (evaluation.health) |health| try writeProbeEvidenceJson(writer, health) else try writer.writeAll("null");
    try writer.writeAll(",\"action\":");
    try writeRepairActionJson(writer, allocator, evaluation.action, evaluation.route);
    try writer.writeByte('}');
}

const DaemonTickDecision = struct {
    phase: []const u8,
    action: []const u8,
    admitted: bool,
    reason: []const u8,
    budget: ?types.ActionBudget = null,
    executed: bool = false,
    handoff: bool = false,
    next_tick_after: ?i64 = null,
    schedule_reason: []const u8 = "none",
};

const DaemonTickExecution = struct {
    route: RepairPlanRoute,
    phase: []const u8,
    action: []const u8,
    admitted: bool,
    executed: bool,
    ok: bool,
    handoff: bool = false,
    handoff_queued: bool = false,
    reason: []const u8,
    budget: ?types.ActionBudget = null,
    command: RepairCommandKind = .none,
};

const DaemonTickStats = struct {
    routes: usize = 0,
    selectable: usize = 0,
    admitted_probes: usize = 0,
    blocked_probes: usize = 0,
    admitted_repairs: usize = 0,
    blocked_repairs: usize = 0,
    no_action: usize = 0,
    next_tick_after: ?i64 = null,
    next_tick_reason: ?[]const u8 = null,
};

fn writeDaemonTickText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    executions: []const DaemonTickExecution,
    args: cli.Command.DaemonTickArgs,
    observed_at: i64,
    command_name: []const u8,
) !void {
    try writer.print("{s}\n\n", .{command_name});
    try writer.print("  mode: {s}\n", .{if (args.once) "once" else "loop"});
    try writer.print("  execution_mode: {s}\n", .{if (args.execute) "execute" else "plan"});
    try writer.print("  executed: {s}\n", .{if (daemonTickExecutionsRan(executions)) "yes" else "no"});
    try writer.print("  boundary: {s}\n", .{daemonTickMessage(args)});
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    if (selected_index) |idx| {
        const selected = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ selected.provider, selected.account });
        if (selected.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.writeByte('\n');
        try writeRouteResilienceActionsText(writer, evaluations, selected_index);
    } else {
        try writer.writeAll("  selected: none\n");
    }

    if (evaluations.len == 0) {
        try writer.writeAll("  no matching configured routes\n");
        return;
    }

    try writer.writeAll("\n  routes:\n");
    for (evaluations) |evaluation| {
        const decision = daemonTickDecision(cfg.policy.daemon, evaluation, observed_at);
        try writer.print("    {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
        if (evaluation.route.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.print(" selectable={s} runtime={s} tick={s} admitted={s} reason={s}", .{
            if (evaluation.selectable) "true" else "false",
            runtimeReadinessSummary(evaluation.runtime),
            decision.action,
            if (decision.admitted) "true" else "false",
            decision.reason,
        });
        if (decision.budget) |budget| try writer.print(" budget={s}", .{@tagName(budget)});
        try writer.print(" schedule={s}", .{decision.schedule_reason});
        if (decision.next_tick_after) |next| try writer.print(" next_tick_after={d}", .{next});
        if (try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route)) |command| {
            defer allocator.free(command);
            try writer.print(" command={s}", .{command});
        }
        if (try runtimeDiagnosticCommandAlloc(allocator, evaluation.action, evaluation.route)) |command| {
            defer allocator.free(command);
            try writer.print(" diagnostic={s}", .{command});
        }
        try writer.writeByte('\n');
    }

    if (executions.len != 0) {
        try writer.writeAll("\n  executions:\n");
        for (executions) |execution| {
            try writer.print("    {s}:{s}", .{ execution.route.provider, execution.route.account });
            if (execution.route.capability) |capability| try writer.print("#{s}", .{capability});
            try writer.print(" phase={s} action={s} executed={s} ok={s} reason={s}", .{
                execution.phase,
                execution.action,
                if (execution.executed) "true" else "false",
                if (execution.ok) "true" else "false",
                execution.reason,
            });
            if (execution.handoff) {
                try writer.writeAll(" handoff=true");
                try writer.print(" handoff_queued={s}", .{if (execution.handoff_queued) "true" else "false"});
            }
            try writer.writeByte('\n');
        }
    }
}

fn writeDaemonTickJsonObject(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    executions: []const DaemonTickExecution,
    args: cli.Command.DaemonTickArgs,
    tick_index: u32,
    observed_at: i64,
    include_version: bool,
) !void {
    const stats = daemonTickStats(cfg.policy.daemon, evaluations, observed_at);

    try writer.writeByte('{');
    if (include_version) {
        try writer.writeAll("\"version\":");
        try std.json.stringify(cli.version, .{}, writer);
        try writer.writeByte(',');
    }
    try writer.writeAll("\"tick_index\":");
    try writer.print("{d}", .{tick_index});
    try writer.writeAll(",\"observed_at\":");
    try writer.print("{d}", .{observed_at});
    try writer.writeAll(",\"mode\":");
    try std.json.stringify(if (args.once) "once" else "loop", .{}, writer);
    try writer.writeAll(",\"execution_mode\":");
    try std.json.stringify(if (args.execute) "execute" else "plan", .{}, writer);
    try writer.writeAll(",\"executed\":");
    try writer.writeAll(if (daemonTickExecutionsRan(executions)) "true" else "false");
    try writer.writeAll(",\"handoff_queued\":");
    try writer.writeAll(if (daemonTickHandoffQueued(executions)) "true" else "false");
    try writer.writeAll(",\"handoff_pending\":");
    try writer.writeAll(if (daemonTickHandoffPending(executions)) "true" else "false");
    try writer.writeAll(",\"message\":");
    try std.json.stringify(daemonTickMessage(args), .{}, writer);
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
    try writer.writeAll(",\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"afloat\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJson(writer, evaluations, selected_index);
    try writer.writeAll(",\"resilience_actions\":");
    try writeRouteResilienceActionsJson(writer, allocator, evaluations, selected_index, args.profile, args.capability);
    try writer.writeAll(",\"claim\":");
    try writeStayAfloatClaimJson(writer, selectorFromDaemonTickArgs(args), selectedRoute(evaluations, selected_index), selectableFallbackRouteCount(evaluations, selected_index));
    try writer.writeAll(",\"summary\":");
    try writeDaemonTickStatsJson(writer, stats);
    try writer.writeAll(",\"executions\":");
    try writeDaemonTickExecutionsJson(writer, allocator, executions);
    try writer.writeAll(",\"routes\":[");
    for (evaluations, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected| idx == selected else false;
        try writer.writeByte('{');
        try writer.writeAll("\"route\":");
        try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, selected);
        try writer.writeAll(",\"tick\":");
        try writeDaemonTickDecisionJson(writer, daemonTickDecision(cfg.policy.daemon, evaluation, observed_at));
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

fn writeDaemonTickStatsJson(writer: anytype, stats: DaemonTickStats) !void {
    try writer.print(
        "{{\"routes\":{d},\"selectable\":{d},\"admitted_probes\":{d},\"blocked_probes\":{d},\"admitted_repairs\":{d},\"blocked_repairs\":{d},\"no_action\":{d},\"next_tick_after\":",
        .{
            stats.routes,
            stats.selectable,
            stats.admitted_probes,
            stats.blocked_probes,
            stats.admitted_repairs,
            stats.blocked_repairs,
            stats.no_action,
        },
    );
    if (stats.next_tick_after) |next| {
        try writer.print("{d}", .{next});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"next_tick_reason\":");
    if (stats.next_tick_reason) |reason| {
        try std.json.stringify(reason, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeDaemonTickExecutionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    executions: []const DaemonTickExecution,
) !void {
    try writer.writeByte('[');
    for (executions, 0..) |execution, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"provider\":");
        try std.json.stringify(execution.route.provider, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(execution.route.account, .{}, writer);
        try writer.writeAll(",\"capability\":");
        if (execution.route.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"phase\":");
        try std.json.stringify(execution.phase, .{}, writer);
        try writer.writeAll(",\"action\":");
        try std.json.stringify(execution.action, .{}, writer);
        try writer.writeAll(",\"admitted\":");
        try writer.writeAll(if (execution.admitted) "true" else "false");
        try writer.writeAll(",\"executed\":");
        try writer.writeAll(if (execution.executed) "true" else "false");
        try writer.writeAll(",\"ok\":");
        try writer.writeAll(if (execution.ok) "true" else "false");
        try writer.writeAll(",\"handoff\":");
        try writer.writeAll(if (execution.handoff) "true" else "false");
        try writer.writeAll(",\"handoff_queued\":");
        try writer.writeAll(if (execution.handoff_queued) "true" else "false");
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(execution.reason, .{}, writer);
        try writer.writeAll(",\"budget\":");
        if (execution.budget) |budget| try std.json.stringify(@tagName(budget), .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"command\":");
        if (try repairCommandAlloc(allocator, execution.command, execution.route)) |command| {
            defer allocator.free(command);
            try std.json.stringify(command, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn daemonTickExecutionsRan(executions: []const DaemonTickExecution) bool {
    for (executions) |execution| {
        if (execution.executed) return true;
    }
    return false;
}

fn daemonTickHandoffQueued(executions: []const DaemonTickExecution) bool {
    for (executions) |execution| {
        if (execution.handoff_queued) return true;
    }
    return false;
}

fn daemonTickHandoffPending(executions: []const DaemonTickExecution) bool {
    for (executions) |execution| {
        if (execution.handoff) return true;
    }
    return false;
}

fn writeDaemonTickDecisionJson(writer: anytype, decision: DaemonTickDecision) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"phase\":");
    try std.json.stringify(decision.phase, .{}, writer);
    try writer.writeAll(",\"action\":");
    try std.json.stringify(decision.action, .{}, writer);
    try writer.writeAll(",\"admitted\":");
    try writer.writeAll(if (decision.admitted) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(decision.reason, .{}, writer);
    try writer.writeAll(",\"budget\":");
    if (decision.budget) |budget| try std.json.stringify(@tagName(budget), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"executed\":");
    try writer.writeAll(if (decision.executed) "true" else "false");
    try writer.writeAll(",\"handoff\":");
    try writer.writeAll(if (decision.handoff) "true" else "false");
    try writer.writeAll(",\"next_tick_after\":");
    if (decision.next_tick_after) |next| try writer.print("{d}", .{next}) else try writer.writeAll("null");
    try writer.writeAll(",\"schedule_reason\":");
    try std.json.stringify(decision.schedule_reason, .{}, writer);
    try writer.writeByte('}');
}

fn daemonTickStats(policy: config.DaemonPolicyConfig, evaluations: []const RouteEvaluation, observed_at: i64) DaemonTickStats {
    var stats = DaemonTickStats{ .routes = evaluations.len };
    for (evaluations) |evaluation| {
        if (evaluation.selectable) stats.selectable += 1;
        const decision = daemonTickDecision(policy, evaluation, observed_at);
        if (std.mem.eql(u8, decision.phase, "probe")) {
            if (decision.admitted) stats.admitted_probes += 1 else stats.blocked_probes += 1;
        } else if (std.mem.eql(u8, decision.phase, "repair")) {
            if (decision.admitted) stats.admitted_repairs += 1 else stats.blocked_repairs += 1;
        } else if (std.mem.eql(u8, decision.phase, "none") or std.mem.eql(u8, decision.phase, "observe")) {
            stats.no_action += 1;
        }
        if (decision.next_tick_after) |next| {
            if (stats.next_tick_after == null or next < stats.next_tick_after.?) {
                stats.next_tick_after = next;
                stats.next_tick_reason = decision.schedule_reason;
            }
        }
    }
    return stats;
}

fn daemonTickDecision(policy: config.DaemonPolicyConfig, evaluation: RouteEvaluation, observed_at: i64) DaemonTickDecision {
    if (evaluation.selectable) {
        return .{
            .phase = "none",
            .action = "none",
            .admitted = true,
            .reason = "route_selectable",
            .schedule_reason = "route_selectable",
        };
    }

    const schedule = daemonTickSchedule(evaluation.action, observed_at);

    if (evaluation.action.command == .probe) {
        const admission = daemonProbeAdmission(policy, evaluation.budget);
        return .{
            .phase = "probe",
            .action = "probe",
            .admitted = admission.admitted,
            .reason = admission.reason,
            .budget = admission.budget,
            .next_tick_after = schedule.next_tick_after,
            .schedule_reason = schedule.reason,
        };
    }

    if (evaluation.action.command != .none or evaluation.action.mutating or evaluation.action.interactive) {
        const admission = daemonRepairAdmission(policy, evaluation.action);
        return .{
            .phase = "repair",
            .action = @tagName(evaluation.action.kind),
            .admitted = admission.admitted,
            .reason = admission.reason,
            .budget = admission.budget,
            .handoff = evaluation.action.interactive,
            .next_tick_after = schedule.next_tick_after,
            .schedule_reason = schedule.reason,
        };
    }

    const admission = daemonRepairAdmission(policy, evaluation.action);
    return .{
        .phase = "observe",
        .action = @tagName(evaluation.action.kind),
        .admitted = admission.admitted,
        .reason = if (admission.admitted) "observe_only" else admission.reason,
        .budget = admission.budget,
        .next_tick_after = schedule.next_tick_after,
        .schedule_reason = schedule.reason,
    };
}

fn daemonTickSchedule(action: RepairAction, observed_at: i64) DaemonTickSchedule {
    if (action.retry_after_s) |retry_after| return .{
        .next_tick_after = observed_at + @as(i64, retry_after),
        .reason = "retry_after",
    };
    if (action.wait_until) |wait_until| return .{
        .next_tick_after = wait_until,
        .reason = "wait_until",
    };
    if (action.kind == .wait_for_repair) return .{
        .next_tick_after = observed_at + daemon_repair_poll_s,
        .reason = "repair_poll",
    };
    if (action.command == .probe) return .{
        .next_tick_after = observed_at,
        .reason = "probe_due",
    };
    if (action.interactive) return .{
        .next_tick_after = observed_at + daemon_handoff_recheck_s,
        .reason = "handoff_recheck",
    };
    if (action.kind == .fix_runtime) return .{
        .next_tick_after = observed_at + daemon_runtime_recheck_s,
        .reason = "runtime_recheck",
    };
    if (action.kind == .wait_for_quota) return .{
        .next_tick_after = observed_at + daemon_quota_unknown_recheck_s,
        .reason = "quota_poll",
    };
    if (action.kind == .provider_plan or action.kind == .try_next_provider) {
        return .{
            .next_tick_after = observed_at + daemon_provider_plan_recheck_s,
            .reason = "provider_recheck",
        };
    }
    if (action.kind == .none) return .{ .reason = "no_action" };
    return .{};
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
                "Codex Max mux shape configured"
            else
                "Codex is configured but the Codex Max mux shape is missing; run oauth-mux codex config-candidate",
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
    try writer.writeAll("    oauth-mux doctor runtime --json\n");
    try writer.writeAll("    oauth-mux route explain --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux route select --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json\n");
    try writer.writeAll("    oauth-mux repair run --profile <profile> --capability <capability> --json\n");
    if (stats.codex_configured) {
        if (!stats.codex_max_configured) {
            try writer.writeAll("    oauth-mux codex config-candidate\n");
        }
        try writer.writeAll("    oauth-mux setup codex\n");
        try writer.writeAll("    oauth-mux codex canary\n");
        try writer.writeAll("    oauth-mux codex live-qa\n");
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
    try writeDoctorCommandJson(writer, &first, "oauth-mux doctor runtime --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux route explain --profile <profile> --capability <capability> --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux route select --profile <profile> --capability <capability> --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux repair-plan --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json");
    try writeDoctorCommandJson(writer, &first, "oauth-mux repair run --profile <profile> --capability <capability> --json");
    if (stats.codex_configured) {
        if (!stats.codex_max_configured) {
            try writeDoctorCommandJson(writer, &first, "oauth-mux codex config-candidate --json");
        }
        try writeDoctorCommandJson(writer, &first, "oauth-mux setup codex");
        try writeDoctorCommandJson(writer, &first, "oauth-mux codex canary");
        try writeDoctorCommandJson(writer, &first, "oauth-mux codex live-qa");
    }
}

fn writeDoctorCommandJson(writer: anytype, first: *bool, command: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writeCommandJson(writer, command);
}

const RuntimeDoctorStats = struct {
    configured: bool = false,
    config_valid: bool = false,
    providers: usize = 0,
    accounts: usize = 0,
    ready_accounts: usize = 0,
    action_needed_accounts: usize = 0,
    missing_binaries: usize = 0,

    fn ok(self: RuntimeDoctorStats) bool {
        return self.configured and self.config_valid and self.accounts > 0 and self.action_needed_accounts == 0 and self.missing_binaries == 0;
    }
};

const RuntimeAccountInfo = runtime_mod.AccountInfo;

fn runDoctorRuntime(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.DoctorArgs) !void {
    const config_path = try paths.configFilePath(allocator);
    defer allocator.free(config_path);

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();

    const parsed = config.load(allocator) catch |e| {
        const stats = RuntimeDoctorStats{
            .configured = false,
            .config_valid = false,
        };
        if (args.json) {
            try writeDoctorRuntimeJsonNoConfig(writer, stats, config_path, @errorName(e));
        } else {
            try writeDoctorRuntimeTextNoConfig(writer, config_path, @errorName(e));
        }
        return;
    };
    defer parsed.deinit();

    const config_valid = blk: {
        config.validate(parsed.value, validation_messages.writer()) catch break :blk false;
        break :blk true;
    };

    if (doctorRuntimeScoped(args)) {
        var routes = try collectRepairPlanRoutes(allocator, parsed.value, doctorArgsToRepairPlanArgs(args));
        defer routes.deinit();
        const stats = try collectRuntimeDoctorRouteStats(allocator, parsed.value, config_valid, routes.items);
        if (args.json) {
            try writeDoctorRuntimeScopedJson(writer, allocator, parsed.value, stats, config_path, validation_messages.items, routes.items, args);
        } else {
            try writeDoctorRuntimeScopedText(writer, allocator, parsed.value, stats, config_path, validation_messages.items, routes.items, args);
        }
        return;
    }

    const stats = try collectRuntimeDoctorStats(allocator, parsed.value, config_valid);
    if (args.json) {
        try writeDoctorRuntimeJson(writer, allocator, parsed.value, stats, config_path, validation_messages.items);
    } else {
        try writeDoctorRuntimeText(writer, allocator, parsed.value, stats, config_path, validation_messages.items);
    }
}

fn doctorRuntimeScoped(args: cli.Command.DoctorArgs) bool {
    return args.profile != null or args.provider != null or args.account != null or args.capability != null;
}

fn doctorArgsToRepairPlanArgs(args: cli.Command.DoctorArgs) cli.Command.RepairPlanArgs {
    return .{
        .profile = args.profile,
        .provider = args.provider,
        .account = args.account,
        .capability = args.capability,
        .json = args.json,
    };
}

fn collectRuntimeDoctorStats(allocator: std.mem.Allocator, cfg: config.Config, config_valid: bool) !RuntimeDoctorStats {
    var stats = RuntimeDoctorStats{
        .configured = true,
        .config_valid = config_valid,
        .providers = cfg.providers.map.count(),
    };

    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        const def = config.resolveProviderDefinition(cfg, provider_name);
        stats.missing_binaries += try countMissingRuntimeBinaries(allocator, def);

        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            stats.accounts += 1;
            const info = try runtimeAccountInfo(allocator, prov, account_entry.value_ptr.*, def, config.resolveProviderKind(cfg, provider_name));
            if (info.ready()) {
                stats.ready_accounts += 1;
            } else {
                stats.action_needed_accounts += 1;
            }
        }
    }

    return stats;
}

fn collectRuntimeDoctorRouteStats(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    config_valid: bool,
    routes: []const RepairPlanRoute,
) !RuntimeDoctorStats {
    var stats = RuntimeDoctorStats{
        .configured = true,
        .config_valid = config_valid,
    };

    var seen_providers = std.StringHashMap(void).init(allocator);
    defer seen_providers.deinit();

    for (routes) |route| {
        if (!seen_providers.contains(route.provider)) {
            try seen_providers.put(route.provider, {});
            stats.providers += 1;
        }

        stats.accounts += 1;
        const def = config.resolveProviderDefinition(cfg, route.provider);
        const readiness = try routeRuntimeReadiness(allocator, cfg, route, def);
        if (readiness.isReady()) {
            stats.ready_accounts += 1;
        } else {
            stats.action_needed_accounts += 1;
            switch (readiness) {
                .missing_binary => stats.missing_binaries += 1,
                else => {},
            }
        }
    }

    return stats;
}

fn writeDoctorRuntimeTextNoConfig(writer: anytype, config_path: []const u8, err: []const u8) !void {
    try writer.writeAll("oauth-mux doctor runtime\n\n");
    try writer.print("  config: {s}\n", .{config_path});
    try writer.print("  readiness: action_needed ({s})\n\n", .{err});
    try writer.writeAll("  next:\n");
    try writer.writeAll("    oauth-mux init\n");
    try writer.writeAll("    oauth-mux init --codex-max\n");
}

fn writeDoctorRuntimeJsonNoConfig(writer: anytype, stats: RuntimeDoctorStats, config_path: []const u8, err: []const u8) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":false,\"configured\":false,\"config_valid\":false,\"config_path\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"config_error\":");
    try std.json.stringify(err, .{}, writer);
    try writer.print(",\"providers\":{d},\"accounts\":{d},\"ready_accounts\":{d},\"action_needed_accounts\":{d},\"missing_binaries\":{d}", .{
        stats.providers,
        stats.accounts,
        stats.ready_accounts,
        stats.action_needed_accounts,
        stats.missing_binaries,
    });
    try writer.writeAll(",\"provider_reports\":[],\"next_commands\":[");
    try writeCommandJson(writer, "oauth-mux init --codex-max");
    try writer.writeAll("]}\n");
}

fn writeDoctorRuntimeText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    stats: RuntimeDoctorStats,
    config_path: []const u8,
    validation_messages: []const u8,
) !void {
    try writer.writeAll("oauth-mux doctor runtime\n\n");
    try writer.print("  config: {s}\n", .{config_path});
    try writer.print("  readiness: {s}\n", .{if (stats.ok()) "ready" else "action_needed"});
    try writer.print("  providers: {d}  accounts: {d}  ready: {d}  action_needed: {d}\n", .{
        stats.providers,
        stats.accounts,
        stats.ready_accounts,
        stats.action_needed_accounts,
    });
    if (validation_messages.len != 0) {
        try writer.writeAll("\n  validation:\n");
        var lines = std.mem.splitScalar(u8, validation_messages, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try writer.print("    {s}\n", .{line});
        }
    }

    try writer.writeAll("\n  runtime:\n");
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        const def = config.resolveProviderDefinition(cfg, provider_name);
        try writer.print("    {s} kind={s}\n", .{ provider_name, prov.kind });
        for (def.runtime.required_binaries) |binary_name| {
            try writer.print("      binary {s}: {s}\n", .{ binary_name, if (try commandAvailable(allocator, binary_name)) "available" else "missing" });
        }
        var account_it = prov.accounts.map.iterator();
        while (account_it.next()) |account_entry| {
            const info = try runtimeAccountInfo(allocator, prov, account_entry.value_ptr.*, def, config.resolveProviderKind(cfg, provider_name));
            try writer.print("      account {s}: {s} config_dir={s} exists={s} writable={s} sessions={d}/{d}\n", .{
                account_entry.key_ptr.*,
                runtimeReadinessSummary(info.readiness),
                if (info.config_dir_set) "set" else "missing",
                if (info.config_dir_exists) "true" else "false",
                if (info.config_dir_writable) "true" else "false",
                info.session_paths_present,
                info.session_paths_total,
            });
        }
    }
}

fn writeDoctorRuntimeScopedText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    stats: RuntimeDoctorStats,
    config_path: []const u8,
    validation_messages: []const u8,
    routes: []const RepairPlanRoute,
    args: cli.Command.DoctorArgs,
) !void {
    try writer.writeAll("oauth-mux doctor runtime\n\n");
    try writer.print("  config: {s}\n", .{config_path});
    try writer.print("  readiness: {s}\n", .{if (stats.ok()) "ready" else "action_needed"});
    try writer.print("  scope: {s}\n", .{if (doctorRuntimeScoped(args)) "route" else "all"});
    if (args.profile) |profile_name| try writer.print("    profile: {s}\n", .{profile_name});
    if (args.provider) |provider_name| try writer.print("    provider: {s}\n", .{provider_name});
    if (args.account) |account_name| try writer.print("    account: {s}\n", .{account_name});
    if (args.capability) |capability| try writer.print("    capability: {s}\n", .{capability});
    try writer.print("  providers: {d}  routes: {d}  ready: {d}  action_needed: {d}\n", .{
        stats.providers,
        stats.accounts,
        stats.ready_accounts,
        stats.action_needed_accounts,
    });
    if (validation_messages.len != 0) {
        try writer.writeAll("\n  validation:\n");
        var lines = std.mem.splitScalar(u8, validation_messages, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try writer.print("    {s}\n", .{line});
        }
    }

    try writer.writeAll("\n  routes:\n");
    for (routes) |route| {
        const def = config.resolveProviderDefinition(cfg, route.provider);
        const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
        try writer.print("    {s}:{s}", .{ route.provider, route.account });
        if (route.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.print(" runtime={s}\n", .{runtimeReadinessSummary(runtime)});
    }
}

fn writeDoctorRuntimeJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    stats: RuntimeDoctorStats,
    config_path: []const u8,
    validation_messages: []const u8,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (stats.ok()) "true" else "false");
    try writer.writeAll(",\"configured\":true,\"config_valid\":");
    try writer.writeAll(if (stats.config_valid) "true" else "false");
    try writer.writeAll(",\"config_path\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"validation_messages\":");
    try std.json.stringify(validation_messages, .{}, writer);
    try writer.print(",\"providers\":{d},\"accounts\":{d},\"ready_accounts\":{d},\"action_needed_accounts\":{d},\"missing_binaries\":{d}", .{
        stats.providers,
        stats.accounts,
        stats.ready_accounts,
        stats.action_needed_accounts,
        stats.missing_binaries,
    });
    try writer.writeAll(",\"provider_reports\":[");
    var first_provider = true;
    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!first_provider) try writer.writeByte(',');
        first_provider = false;
        try writeRuntimeProviderJson(writer, allocator, cfg, entry.key_ptr.*, entry.value_ptr.*);
    }
    try writer.writeAll("],\"next_commands\":[");
    try writeCommandJson(writer, "oauth-mux route explain --profile <profile> --capability <capability> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux repair-plan --profile <profile> --capability <capability> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json");
    try writer.writeAll("]}\n");
}

fn writeDoctorRuntimeScopedJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    stats: RuntimeDoctorStats,
    config_path: []const u8,
    validation_messages: []const u8,
    routes: []const RepairPlanRoute,
    args: cli.Command.DoctorArgs,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (stats.ok()) "true" else "false");
    try writer.writeAll(",\"configured\":true,\"config_valid\":");
    try writer.writeAll(if (stats.config_valid) "true" else "false");
    try writer.writeAll(",\"config_path\":");
    try std.json.stringify(config_path, .{}, writer);
    try writer.writeAll(",\"scope\":");
    try writeDoctorRuntimeScopeJson(writer, args);
    try writer.writeAll(",\"validation_messages\":");
    try std.json.stringify(validation_messages, .{}, writer);
    try writer.print(",\"providers\":{d},\"accounts\":{d},\"ready_accounts\":{d},\"action_needed_accounts\":{d},\"missing_binaries\":{d}", .{
        stats.providers,
        stats.accounts,
        stats.ready_accounts,
        stats.action_needed_accounts,
        stats.missing_binaries,
    });
    try writer.writeAll(",\"route_reports\":[");
    for (routes, 0..) |route, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeRuntimeRouteJson(writer, allocator, cfg, route);
    }
    try writer.writeAll("],\"provider_reports\":[],\"next_commands\":[");
    try writeCommandJson(writer, "oauth-mux route explain --profile <profile> --capability <capability> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux repair-plan --profile <profile> --capability <capability> --json");
    try writer.writeByte(',');
    try writeCommandJson(writer, "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json");
    try writer.writeAll("]}\n");
}

fn writeDoctorRuntimeScopeJson(writer: anytype, args: cli.Command.DoctorArgs) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"profile\":");
    if (args.profile) |profile_name| try std.json.stringify(profile_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"provider\":");
    if (args.provider) |provider_name| try std.json.stringify(provider_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (args.account) |account_name| try std.json.stringify(account_name, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (args.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeByte('}');
}

fn writeRuntimeRouteJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
) !void {
    const def = config.resolveProviderDefinition(cfg, route.provider);
    const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
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
    try writer.writeAll(",\"ready\":");
    try writer.writeAll(if (runtime.isReady()) "true" else "false");
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessRedactedJson(writer, runtime);
    try writer.writeByte('}');
}

fn writeRuntimeProviderJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    provider_name: []const u8,
    prov: config.ProviderConfig,
) !void {
    const def = config.resolveProviderDefinition(cfg, provider_name);
    const kind = config.resolveProviderKind(cfg, provider_name);
    try writer.writeByte('{');
    try writer.writeAll("\"name\":");
    try std.json.stringify(provider_name, .{}, writer);
    try writer.writeAll(",\"kind\":");
    try std.json.stringify(prov.kind, .{}, writer);
    try writer.writeAll(",\"required_binaries\":[");
    for (def.runtime.required_binaries, 0..) |binary_name, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try std.json.stringify(binary_name, .{}, writer);
        try writer.writeAll(",\"available\":");
        try writer.writeAll(if (try commandAvailable(allocator, binary_name)) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"accounts\":[");
    var first_account = true;
    var account_it = prov.accounts.map.iterator();
    while (account_it.next()) |account_entry| {
        if (!first_account) try writer.writeByte(',');
        first_account = false;
        try writeRuntimeAccountJson(writer, allocator, prov, account_entry.key_ptr.*, account_entry.value_ptr.*, def, kind);
    }
    try writer.writeAll("]}");
}

fn writeRuntimeAccountJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    prov: config.ProviderConfig,
    account_name: []const u8,
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) !void {
    const info = try runtimeAccountInfo(allocator, prov, account, def, kind);
    const env_var = runtimeConfigDirEnv(prov, def, kind);
    try writer.writeByte('{');
    try writer.writeAll("\"name\":");
    try std.json.stringify(account_name, .{}, writer);
    try writer.writeAll(",\"ready\":");
    try writer.writeAll(if (info.ready()) "true" else "false");
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessRedactedJson(writer, info.readiness);
    try writer.writeAll(",\"writeback\":");
    try writeAccountWritebackJson(writer, account, def);
    try writer.writeAll(",\"config_dir_env\":");
    if (env_var) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"config_dir_set\":");
    try writer.writeAll(if (info.config_dir_set) "true" else "false");
    try writer.writeAll(",\"config_dir_exists\":");
    try writer.writeAll(if (info.config_dir_exists) "true" else "false");
    try writer.writeAll(",\"config_dir_writable\":");
    try writer.writeAll(if (info.config_dir_writable) "true" else "false");
    try writer.writeAll(",\"session_paths\":[");
    if (account.config_dir) |config_dir| {
        const expanded = try paths.expandTilde(allocator, config_dir);
        defer allocator.free(expanded);
        for (def.runtime.session_paths, 0..) |session_spec, idx| {
            if (idx > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":");
            try std.json.stringify(session_spec, .{}, writer);
            try writer.writeAll(",\"exists\":");
            const exists = if (try resolveRuntimePath(allocator, session_spec, env_var, expanded)) |session_path| blk: {
                defer allocator.free(session_path);
                break :blk fileExists(session_path);
            } else false;
            try writer.writeAll(if (exists) "true" else "false");
            try writer.writeByte('}');
        }
    }
    try writer.writeAll("]}");
}

fn writeRuntimeReadinessRedactedJson(writer: anytype, readiness: types.RuntimeReadiness) !void {
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
            try writer.writeAll(",\"path_ref\":");
            try std.json.stringify(info.path, .{}, writer);
            try writer.writeAll(",\"operation\":");
            try std.json.stringify(info.operation, .{}, writer);
        },
        .unwritable_store, .session_unavailable, .sandbox_blocked => |detail| {
            try writer.writeAll(",\"detail\":");
            try std.json.stringify(detail, .{}, writer);
        },
        .needs_reauth => |info| {
            try writer.writeAll(",\"reason\":");
            try std.json.stringify(info.reason, .{}, writer);
            try writer.writeAll(",\"methods\":");
            try writeStringArrayJson(writer, info.methods);
        },
        .repair_in_progress => |info| {
            try writer.writeAll(",\"account\":");
            try std.json.stringify(info.account, .{}, writer);
            try writer.print(",\"started_at\":{d}", .{info.started_at});
        },
    }
    try writer.writeByte('}');
}

fn writeAccountWritebackJson(
    writer: anytype,
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
) !void {
    const plan = accountWritebackPlan(account, def);
    try writer.writeByte('{');
    try writer.writeAll("\"capability\":");
    try std.json.stringify(@tagName(plan.capability), .{}, writer);
    try writer.writeAll(",\"automatic_refresh_admitted\":");
    try writer.writeAll(if (plan.automatic_refresh_admitted) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(plan.reason, .{}, writer);
    try writer.writeByte('}');
}

fn accountWritebackPlan(
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
) secret_mod.WritebackPlan {
    const backend = config.resolveSecretBackend(account.secret) catch return .{
        .capability = .unsupported,
        .automatic_refresh_admitted = false,
        .reason = "secret_backend_invalid",
    };
    return secret_mod.writebackPlan(backend, def.repair.owner);
}

fn runtimeAccountInfo(
    allocator: std.mem.Allocator,
    prov: config.ProviderConfig,
    account: config.AccountConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) !RuntimeAccountInfo {
    return runtime_mod.accountInfo(allocator, prov, account, def, kind);
}

fn resolveRuntimePath(
    allocator: std.mem.Allocator,
    spec: []const u8,
    env_var: ?[]const u8,
    config_dir: []const u8,
) !?[]const u8 {
    return runtime_mod.resolvePath(allocator, spec, env_var, config_dir);
}

fn runtimeConfigDirEnv(prov: config.ProviderConfig, def: provider_schema.ProviderDefinition, kind: ?types.ProviderKind) ?[]const u8 {
    return runtime_mod.configDirEnv(prov, def, kind);
}

fn countMissingRuntimeBinaries(allocator: std.mem.Allocator, def: provider_schema.ProviderDefinition) !usize {
    return runtime_mod.countMissingBinaries(allocator, def);
}

fn fileExists(path_value: []const u8) bool {
    return runtime_mod.fileExists(path_value);
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

    try writer.writeAll("\n  support: live_proven means hosted secret-scoped QA has proved a real provider route.\n");
    try writer.writeAll("  proof: provider proof remains conservative; capability proof details are in --json.\n");
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
        try writer.writeAll(",\"proof_status\":");
        try std.json.stringify(capability.proof_status, .{}, writer);
        try writer.writeAll(",\"proof_requirements\":");
        try writeStringArrayJson(writer, capability.proof_requirements);
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
    if (std.mem.eql(u8, def_name, "codex")) return provider_schema.proof_live;
    if (built_in) return "built_in";
    return "schema_modeled";
}

fn proofStatus(def_name: []const u8) []const u8 {
    if (std.mem.eql(u8, def_name, "codex")) return provider_schema.proof_live;
    return provider_schema.proof_needs_operator;
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
    return runtime_mod.providerReadiness(allocator, def, capability);
}

fn routeRuntimeReadiness(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
    def: provider_schema.ProviderDefinition,
) !types.RuntimeReadiness {
    return runtime_mod.routeReadiness(allocator, cfg, .{
        .provider = route.provider,
        .account = route.account,
        .capability = route.capability,
    }, def);
}

fn runtimeReadinessSummary(readiness: types.RuntimeReadiness) []const u8 {
    return runtime_mod.summary(readiness);
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
    return runtime_mod.commandAvailable(allocator, binary_name);
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
    ctx.account_name = args.account;
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

    if (try probeRuntimeReadiness(allocator, ctx)) |readiness| {
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
    try writeProbeRuntimeJson(writer, allocator, ctx);
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

fn probeRuntimeReadiness(allocator: std.mem.Allocator, ctx: *const pipeline.Context) !?types.RuntimeReadiness {
    const provider_name = ctx.provider_name orelse return null;
    const def = config.resolveProviderDefinition(ctx.cfg, provider_name);
    if (ctx.account_name) |account_name| {
        return try routeRuntimeReadiness(allocator, ctx.cfg, .{
            .provider = provider_name,
            .account = account_name,
            .capability = ctx.capability_name,
        }, def);
    }
    return try providerRuntimeReadiness(allocator, def, ctx.capability_name);
}

fn writeProbeRuntimeJson(writer: anytype, allocator: std.mem.Allocator, ctx: *const pipeline.Context) !void {
    const provider_name = ctx.provider_name orelse {
        try writer.writeAll("null");
        return;
    };
    const def = config.resolveProviderDefinition(ctx.cfg, provider_name);
    const readiness = (try probeRuntimeReadiness(allocator, ctx)) orelse .ready;
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
        .live_qa => try runCodexLiveQa(allocator, writer, args, root),
        .revalidate_exhausted => try runCodexRevalidateExhausted(allocator, writer, args),
        .probe_all => try runCodexProbeAll(allocator, writer, args),
        .config_candidate => try runCodexConfigCandidate(allocator, writer, args, root),
        .config_merge => try runCodexConfigMerge(allocator, writer, args),
        .managed_plan => try runCodexManagedPlan(allocator, writer, args),
        .managed => try runCodexManaged(allocator, writer, args),
        .broker_plan => try runCodexBrokerPlan(allocator, writer, args),
        .broker_session_plan => try runCodexBrokerSessionPlan(allocator, writer, args),
        .broker_session_smoke => try runCodexBrokerSessionSmoke(allocator, writer, args),
        .broker_run => try runCodexBrokerRun(allocator, writer, args),
        .broker_fallback_drill => try runCodexBrokerFallbackDrill(allocator, writer, args),
        .broker_smoke => try runCodexBrokerSmoke(allocator, writer, args, .login),
        .broker_refresh_smoke => try runCodexBrokerSmoke(allocator, writer, args, .refresh),
        .broker_401_smoke => try runCodexBroker401Smoke(allocator, writer, args),
        .broker_quota_smoke => try runCodexBrokerQuotaSmoke(allocator, writer, args),
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

    try writer.writeAll("\n=== scoped runtime readiness ===\n");
    try writer.writeAll("Local profile readiness without reading token values or probing providers.\n");
    try writeCodexRuntimeDoctorSnapshot(allocator, writer, args);

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

const CodexRevalidateExhaustedSummary = struct {
    routes_total: usize = 0,
    candidates: usize = 0,
    routes_probed: usize = 0,
    provider_evidence_routes: usize = 0,
    routes_available_after: usize = 0,
    routes_blocked_after: usize = 0,
    probe_errors: usize = 0,
};

fn runCodexRevalidateExhausted(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!codexLiveQaConfirmed(args)) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"confirmation_required\",\"confirmation_required\":true,\"requires\":\"--confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls\",\"spends_provider_calls\":true,\"mutates_user_config\":false,\"mutates_route_health\":true,\"mode\":\"codex_exhausted_route_revalidation\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex revalidate-exhausted --profile <profile> --capability <capability> --confirm-spend --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex exhausted route revalidation is disabled.\n\n");
            try writer.writeAll("This command re-probes exhausted Codex routes and can spend subscription quota.\n");
            try writer.writeAll("Re-run with --confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls.\n");
        }
        return error.CodexLiveQaConfirmationRequired;
    }

    const capability = firstCommaValue(args.capabilities) orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"capability_required\",\"requires\":\"--capability <capability>\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"mode\":\"codex_exhausted_route_revalidation\"}\n");
        } else {
            try writer.writeAll("oauth-mux Codex exhausted route revalidation\n\n");
            try writer.writeAll("  capability required: --capability <capability>\n");
        }
        return;
    };

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = if (args.profile == null) args.account else null,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var before = std.ArrayList(RouteEvaluation).init(allocator);
    defer before.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &before);

    const before_selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, before.items);

    var summary = CodexRevalidateExhaustedSummary{
        .routes_total = before.items.len,
    };

    var route_results = std.ArrayList(u8).init(allocator);
    defer route_results.deinit();
    var first_result = true;

    for (before.items) |evaluation| {
        if (!isCodexExhaustedRevalidationCandidate(evaluation, capability, args.account)) continue;
        summary.candidates += 1;
        summary.routes_probed += 1;

        const route = evaluation.route;
        const key = repairPlanRouteHealthKey(route);
        const previous_health = takeHealthEntry(&store, key.slice());
        var restored_previous = false;

        var ctx = pipeline.Context.init(allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = route.provider;
        ctx.account_name = route.account;
        ctx.capability_name = route.capability;

        const probe_result = pipeline.runProbe(&ctx);
        var probe_error: ?types.PipelineError = null;
        if (probe_result) |_| {} else |e| {
            probe_error = e;
        }

        const recorded_provider_evidence = probe_error == null or liveQaErrorIsRecordedEvidence(probe_error.?);
        if (!recorded_provider_evidence) {
            summary.probe_errors += 1;
            if (store.accounts.get(key.slice()) == null) {
                if (previous_health) |health| {
                    try putHealthEntryCopy(&store, key.slice(), health);
                    restored_previous = true;
                }
            }
        } else {
            summary.provider_evidence_routes += 1;
        }

        const after_health = store.accounts.get(key.slice());
        if (after_health) |health| {
            if (livenessIsAvailable(health.liveness)) {
                summary.routes_available_after += 1;
            } else if (accountLivenessBlocksRoute(health.liveness)) {
                summary.routes_blocked_after += 1;
            }
        }

        var probe_json = std.ArrayList(u8).init(allocator);
        defer probe_json.deinit();
        try writeProbeJson(probe_json.writer(), allocator, &store, &ctx, probe_error);

        if (!first_result) try route_results.append(',');
        first_result = false;
        try writeCodexRevalidateRouteJson(
            route_results.writer(),
            route,
            key.slice(),
            previous_health,
            after_health,
            probe_json.items,
            probe_error,
            recorded_provider_evidence,
            restored_previous,
        );
    }

    store.persist();

    var after = std.ArrayList(RouteEvaluation).init(allocator);
    defer after.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &after);

    const selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, after.items);
    const ok = summary.candidates > 0 and summary.probe_errors == 0;
    const reason = if (summary.candidates == 0)
        "no_exhausted_routes_to_revalidate"
    else if (summary.probe_errors != 0)
        "revalidation_probe_errors"
    else if (summary.routes_available_after != 0)
        "revalidation_found_available_route"
    else
        "provider_evidence_still_blocked";

    if (args.json) {
        try writeCodexRevalidateExhaustedJson(
            writer,
            allocator,
            parsed.value,
            before.items,
            after.items,
            before_selected_index,
            selected_index,
            args.profile,
            capability,
            summary,
            ok,
            reason,
            route_results.items,
        );
    } else {
        try writeCodexRevalidateExhaustedText(writer, before.items, after.items, before_selected_index, selected_index, capability, summary, ok, reason);
    }
}

fn isCodexExhaustedRevalidationCandidate(
    evaluation: RouteEvaluation,
    capability: []const u8,
    account_filter: ?[]const u8,
) bool {
    if (!std.mem.eql(u8, evaluation.route.provider, "codex")) return false;
    if (!evaluation.runtime.isReady()) return false;
    if (account_filter) |account| {
        if (!std.mem.eql(u8, evaluation.route.account, account)) return false;
    }
    const route_capability = evaluation.route.capability orelse return false;
    if (!std.mem.eql(u8, route_capability, capability)) return false;
    return std.mem.eql(u8, evaluation.skip_reason, "quota_exhausted") or
        std.mem.eql(u8, evaluation.skip_reason, "rate_limited");
}

fn repairPlanRouteHealthKey(route: RepairPlanRoute) health_mod.KeyBuf {
    if (route.capability) |capability| {
        return health_mod.capabilityKey(route.provider, route.account, capability);
    }
    return health_mod.accountKey(route.provider, route.account);
}

fn takeHealthEntry(store: *health_mod.HealthStore, key: []const u8) ?health_mod.AccountHealth {
    if (store.accounts.fetchRemove(key)) |kv| {
        defer store.allocator.free(kv.key);
        return kv.value;
    }
    return null;
}

fn putHealthEntryCopy(store: *health_mod.HealthStore, key: []const u8, health: health_mod.AccountHealth) !void {
    const result = try store.accounts.getOrPut(key);
    if (!result.found_existing) {
        result.key_ptr.* = try store.allocator.dupe(u8, key);
    }
    result.value_ptr.* = health;
}

fn writeCodexRevalidateRouteJson(
    writer: anytype,
    route: RepairPlanRoute,
    health_key: []const u8,
    before_health: ?health_mod.AccountHealth,
    after_health: ?health_mod.AccountHealth,
    probe_json: []const u8,
    probe_error: ?types.PipelineError,
    provider_evidence_recorded: bool,
    restored_previous: bool,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (route.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"health_key\":");
    try std.json.stringify(health_key, .{}, writer);
    try writer.writeAll(",\"before_liveness\":");
    if (before_health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
    try writer.writeAll(",\"after_liveness\":");
    if (after_health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
    try writer.writeAll(",\"after_probe\":");
    if (after_health) |health| try writeProbeEvidenceJson(writer, health) else try writer.writeAll("null");
    try writer.writeAll(",\"provider_evidence_recorded\":");
    try writer.writeAll(if (provider_evidence_recorded) "true" else "false");
    try writer.writeAll(",\"restored_previous_health\":");
    try writer.writeAll(if (restored_previous) "true" else "false");
    try writer.writeAll(",\"probe_error\":");
    if (probe_error) |err| try std.json.stringify(@errorName(err), .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"probe\":");
    const trimmed_probe_json = std.mem.trim(u8, probe_json, " \t\r\n");
    if (trimmed_probe_json.len == 0) try writer.writeAll("null") else try writer.writeAll(trimmed_probe_json);
    try writer.writeByte('}');
}

fn writeCodexRevalidateExhaustedJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    before: []const RouteEvaluation,
    after: []const RouteEvaluation,
    before_selected_index: ?usize,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: []const u8,
    summary: CodexRevalidateExhaustedSummary,
    ok: bool,
    reason: []const u8,
    route_results: []const u8,
) !void {
    const session_summary = try summarizeCodexBrokerSessionPlan(allocator, cfg, after, selected_index);
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_exhausted_route_revalidation\",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":true,\"mutates_user_config\":false,\"mutates_route_health\":true");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(reason, .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"route_health_revalidation\",\"proof_status\":\"spend_gated_exhausted_route_revalidation\",\"provider_originated_evidence\":");
    try writer.writeAll(if (summary.provider_evidence_routes > 0) "true" else "false");
    try writer.writeAll(",\"manual_health_reset_required\":false,\"next_turn_route_selection_refreshed\":");
    try writer.writeAll(if (selected_index != null) "true" else "false");
    try writer.writeAll(",\"next_turn_route_state_fallback\":false,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    try std.json.stringify(capability, .{}, writer);
    try writer.writeAll(",\"previous_selected\":");
    if (before_selected_index) |idx| try writeRouteSelectionJson(writer, before[idx].route) else try writer.writeAll("null");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| try writeRouteSelectionJson(writer, after[idx].route) else try writer.writeAll("null");
    try writer.print(",\"summary\":{{\"routes_total\":{d},\"candidates\":{d},\"routes_probed\":{d},\"provider_evidence_routes\":{d},\"routes_available_after\":{d},\"routes_blocked_after\":{d},\"probe_errors\":{d},\"broker_ready_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d}}}", .{
        summary.routes_total,
        summary.candidates,
        summary.routes_probed,
        summary.provider_evidence_routes,
        summary.routes_available_after,
        summary.routes_blocked_after,
        summary.probe_errors,
        session_summary.broker_ready_routes,
        session_summary.selectable_broker_routes,
        session_summary.selectable_fallback_routes,
        session_summary.blocked_broker_routes,
    });
    try writer.writeAll(",\"revalidated_routes\":[");
    try writer.writeAll(route_results);
    try writer.writeAll("],\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexRevalidateExhaustedText(
    writer: anytype,
    before: []const RouteEvaluation,
    after: []const RouteEvaluation,
    before_selected_index: ?usize,
    selected_index: ?usize,
    capability: []const u8,
    summary: CodexRevalidateExhaustedSummary,
    ok: bool,
    reason: []const u8,
) !void {
    try writer.writeAll("oauth-mux Codex exhausted route revalidation\n\n");
    try writer.print("  capability: {s}\n", .{capability});
    try writer.print("  candidates: {d}\n", .{summary.candidates});
    try writer.print("  probed: {d}\n", .{summary.routes_probed});
    try writer.print("  provider evidence: {d}\n", .{summary.provider_evidence_routes});
    try writer.print("  available after: {d}\n", .{summary.routes_available_after});
    try writer.print("  blocked after: {d}\n", .{summary.routes_blocked_after});
    try writer.print("  probe errors: {d}\n", .{summary.probe_errors});
    try writer.writeAll("  previous selected: ");
    if (before_selected_index) |idx| {
        const route = before[idx].route;
        try writer.print("{s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("none\n");
    }
    try writer.writeAll("  selected after: ");
    if (selected_index) |idx| {
        const route = after[idx].route;
        try writer.print("{s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("none\n");
    }
    try writer.print("  ok: {s}\n", .{if (ok) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
    try writer.writeAll("  boundary: spend-gated provider revalidation; same-turn and same-thread quota recovery remain unproven\n");
}

const CodexBrokerTokenPlan = struct {
    can_supply: bool = false,
    reason: []const u8 = "unknown",
    secret_readable: bool = false,
    access_token_present: bool = false,
    access_token_jwt_parseable: bool = false,
    chatgpt_account_id_present: bool = false,
    chatgpt_account_id_source: ?[]const u8 = null,
    chatgpt_plan_type_present: bool = false,
    chatgpt_plan_type_source: ?[]const u8 = null,
};

const CodexBrokerSummary = struct {
    routes_total: usize = 0,
    ready_routes: usize = 0,
    unreadable_routes: usize = 0,
};

const CodexBrokerAuthJson = struct {
    auth_mode: ?[]const u8 = null,
    OPENAI_API_KEY: ?[]const u8 = null,
    tokens: ?CodexBrokerTokensJson = null,
};

const CodexBrokerTokensJson = struct {
    id_token: ?[]const u8 = null,
    access_token: ?[]const u8 = null,
    refresh_token: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
};

const CodexBrokerCredentials = struct {
    access_token: []u8,
    chatgpt_account_id: []u8,
    chatgpt_plan_type: ?[]u8 = null,

    fn deinit(self: CodexBrokerCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.chatgpt_account_id);
        if (self.chatgpt_plan_type) |plan| allocator.free(plan);
    }
};

const CodexBrokerSmokeMode = enum {
    login,
    refresh,

    fn jsonMode(self: CodexBrokerSmokeMode) []const u8 {
        return switch (self) {
            .login => "codex_app_server_stdio_broker_smoke",
            .refresh => "codex_app_server_stdio_broker_refresh_smoke",
        };
    }

    fn commandName(self: CodexBrokerSmokeMode) []const u8 {
        return switch (self) {
            .login => "broker-smoke",
            .refresh => "broker-refresh-smoke",
        };
    }

    fn title(self: CodexBrokerSmokeMode) []const u8 {
        return switch (self) {
            .login => "oauth-mux Codex app-server broker smoke",
            .refresh => "oauth-mux Codex app-server broker refresh smoke",
        };
    }

    fn proofStatus(self: CodexBrokerSmokeMode) []const u8 {
        return switch (self) {
            .login => "local_protocol_smoke",
            .refresh => "local_refresh_protocol_smoke",
        };
    }
};

const CodexBrokerProtocolObservation = struct {
    initialized: bool = false,
    login_response: bool = false,
    login_completed: bool = false,
    login_completed_count: usize = 0,
    account_updated: bool = false,
    account_updates: usize = 0,
    thread_started: bool = false,
    turn_started: bool = false,
    turn_completed: bool = false,
    turn_completed_count: usize = 0,
    refresh_request_seen: bool = false,
    refresh_reason_unauthorized: bool = false,
    experimental_api_required_error: bool = false,
};

const CodexBrokerSmokeResult = struct {
    ok: bool = false,
    reason: []const u8 = "unknown",
    spawned: bool = false,
    stdin_closed: bool = false,
    exited: bool = false,
    exit_code: ?u8 = null,
    stdout_bytes: usize = 0,
    stderr_bytes: usize = 0,
    refresh_response_sent: bool = false,
    protocol: CodexBrokerProtocolObservation = .{},
    live_provider_failure: ?types.HttpClassification = null,
    live_provider_failure_source: ?[]const u8 = null,
    route_health_recorded: bool = false,
};

const CodexBrokerRunContinuation = struct {
    route: RepairPlanRoute,
    prompt_start_index: usize = 0,
    prompt_count: usize = 0,
    result: CodexBrokerSmokeResult = .{},
};

const CodexBroker401HttpObservation = struct {
    request_count: usize = 0,
    responses_request_count: usize = 0,
    pre_turn_responses_count: usize = 0,
    turn_request_seen: bool = false,
    models_request_seen: bool = false,
    backend_request_seen: bool = false,
    unauthorized_response_sent: bool = false,
    sse_response_sent: bool = false,
    initial_authorization_seen: bool = false,
    fallback_authorization_seen: bool = false,
    retried_with_fallback: bool = false,
    server_error: ?[]const u8 = null,
};

const CodexBroker401SmokeResult = struct {
    broker: CodexBrokerSmokeResult = .{},
    http: CodexBroker401HttpObservation = .{},
};

const CodexBrokerQuotaHttpObservation = struct {
    request_count: usize = 0,
    responses_request_count: usize = 0,
    pre_turn_responses_count: usize = 0,
    first_turn_request_seen: bool = false,
    second_turn_request_seen: bool = false,
    backend_request_seen: bool = false,
    quota_response_sent: bool = false,
    second_turn_sse_response_sent: bool = false,
    initial_authorization_seen: bool = false,
    fallback_authorization_seen: bool = false,
    next_turn_used_fallback: bool = false,
    server_error: ?[]const u8 = null,
};

const CodexBrokerQuotaSmokeResult = struct {
    broker: CodexBrokerSmokeResult = .{},
    http: CodexBrokerQuotaHttpObservation = .{},
};

const CodexBrokerRouteCredentials = struct {
    route: RepairPlanRoute,
    credentials: CodexBrokerCredentials,

    fn deinit(self: *CodexBrokerRouteCredentials, allocator: std.mem.Allocator) void {
        self.credentials.deinit(allocator);
    }
};

fn cloneCodexBrokerCredentials(
    allocator: std.mem.Allocator,
    credentials: CodexBrokerCredentials,
) !CodexBrokerCredentials {
    const access_token = try allocator.dupe(u8, credentials.access_token);
    errdefer allocator.free(access_token);
    const chatgpt_account_id = try allocator.dupe(u8, credentials.chatgpt_account_id);
    errdefer allocator.free(chatgpt_account_id);
    const chatgpt_plan_type = if (credentials.chatgpt_plan_type) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (chatgpt_plan_type) |value| allocator.free(value);

    return .{
        .access_token = access_token,
        .chatgpt_account_id = chatgpt_account_id,
        .chatgpt_plan_type = chatgpt_plan_type,
    };
}

fn sameRepairPlanRouteIdentity(a: RepairPlanRoute, b: RepairPlanRoute) bool {
    if (!std.mem.eql(u8, a.provider, b.provider)) return false;
    if (!std.mem.eql(u8, a.account, b.account)) return false;
    if (a.capability == null and b.capability == null) return true;
    if (a.capability == null or b.capability == null) return false;
    return std.mem.eql(u8, a.capability.?, b.capability.?);
}

fn runCodexBrokerPlan(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    if (args.json) {
        try writeCodexBrokerPlanJson(writer, allocator, parsed.value, routes.items, args.profile, capability);
    } else {
        try writeCodexBrokerPlanText(writer, allocator, parsed.value, routes.items, args.profile, capability);
    }
}

fn writeCodexBrokerPlanJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    routes: []const RepairPlanRoute,
    profile: ?[]const u8,
    capability: ?[]const u8,
) !void {
    var route_buf = std.ArrayList(u8).init(allocator);
    defer route_buf.deinit();

    var summary = CodexBrokerSummary{};
    var selected: ?RepairPlanRoute = null;
    var first = true;
    for (routes) |route| {
        const plan = try inspectCodexBrokerRoute(allocator, cfg, route);
        summary.routes_total += 1;
        if (plan.can_supply) {
            summary.ready_routes += 1;
            if (selected == null) selected = route;
        } else if (!plan.secret_readable) {
            summary.unreadable_routes += 1;
        }

        if (!first) try route_buf.append(',');
        first = false;
        try writeCodexBrokerRouteJson(route_buf.writer(), route, cfg, plan);
    }

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_app_server_auth_broker_plan\"");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"refresh_method\":\"account/chatgptAuthTokens/refresh\"}");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (summary.ready_routes > 0) "true" else "false");
    try writer.writeAll(",\"route_liveness_considered\":false");
    try writer.writeAll(",\"selected_basis\":\"auth_material_only\"");
    try writer.writeAll(",\"superseded_by\":\"codex broker-session-plan\"");
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"auth_material_readiness\",\"auth_broker_ready\":");
    try writer.writeAll(if (summary.ready_routes > 0) "true" else "false");
    try writer.writeAll(",\"route_liveness_considered\":false,\"prepared_fallback\":false,\"broker_owned_session\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false,\"proof_status\":\"auth_material_planning_only\",\"superseded_by\":\"codex broker-session-plan\"}");
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.print(",\"routes_total\":{d},\"ready_routes\":{d},\"unreadable_routes\":{d}", .{
        summary.routes_total,
        summary.ready_routes,
        summary.unreadable_routes,
    });
    try writer.writeAll(",\"selected\":");
    if (selected) |route| {
        try writeRouteSelectionJson(writer, route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"routes\":[");
    try writer.writeAll(route_buf.items);
    try writer.writeAll("]}\n");
}

fn writeCodexBrokerPlanText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    routes: []const RepairPlanRoute,
    profile: ?[]const u8,
    capability: ?[]const u8,
) !void {
    try writer.writeAll("oauth-mux Codex app-server broker plan\n\n");
    if (profile) |value| try writer.print("  profile: {s}\n", .{value});
    if (capability) |value| try writer.print("  capability: {s}\n", .{value});
    try writer.writeAll("  claim: auth material readiness only; route liveness is not considered\n");
    try writer.writeAll("  superseded by: oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json\n\n");

    if (routes.len == 0) {
        try writer.writeAll("  no matching Codex routes\n");
        return;
    }

    for (routes) |route| {
        const plan = try inspectCodexBrokerRoute(allocator, cfg, route);
        try writer.print("  {s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.print("  ready={s} reason={s}", .{ if (plan.can_supply) "yes" else "no", plan.reason });
        try writer.print(" access_token={s}", .{if (plan.access_token_present) "yes" else "no"});
        try writer.print(" account_id={s}", .{if (plan.chatgpt_account_id_present) "yes" else "no"});
        try writer.print(" plan_type={s}\n", .{if (plan.chatgpt_plan_type_present) "yes" else "no"});
    }
}

fn runCodexBrokerSessionPlan(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, evaluations.items);

    if (args.json) {
        try writeCodexBrokerSessionPlanJson(writer, allocator, parsed.value, evaluations.items, selected_index, args.profile, capability);
    } else {
        try writeCodexBrokerSessionPlanText(writer, allocator, parsed.value, evaluations.items, selected_index, args.profile, capability);
    }
}

fn runCodexManagedPlan(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);

    if (args.json) {
        try writeCodexManagedPlanJson(writer, allocator, parsed.value, evaluations.items, selected_index, args.profile, capability, args);
    } else {
        try writeCodexManagedPlanText(writer, allocator, parsed.value, evaluations.items, selected_index, args.profile, capability, args);
    }
}

fn runCodexManaged(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    if (args.json) {
        try runCodexManagedPlan(allocator, writer, args);
        return;
    }

    if (args.resume_id != null) {
        const resume_inspection = try inspectCodexManagedResumeForArgs(allocator, args);
        if (!codexManagedResumeAllowsLaunch(resume_inspection)) {
            try writeCodexManagedResumeRefusalText(writer, resume_inspection);
            return error.ConfigValidationError;
        }
    }

    const target_argv = try buildCodexManagedTargetArgv(allocator, args);
    defer allocator.free(target_argv);

    const capability = firstCommaValue(args.capabilities);
    try runStayAfloatLaunch(allocator, writer, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .target_argv = target_argv,
    });
}

fn buildCodexManagedTargetArgv(allocator: std.mem.Allocator, args: cli.Command.CodexArgs) ![]const []const u8 {
    if (args.resume_id != null and args.resume_last) {
        log.err("codex managed: use either --resume <id> or --resume-last, not both", .{});
        return error.ConfigValidationError;
    }
    if (args.include_non_interactive and args.resume_id == null and !args.resume_last) {
        log.err("codex managed: --include-non-interactive only applies to --resume or --resume-last", .{});
        return error.ConfigValidationError;
    }

    var argv = std.ArrayList([]const u8).init(allocator);
    errdefer argv.deinit();
    try argv.append("codex");

    if (args.resume_id != null or args.resume_last) {
        try argv.append("resume");
        if (args.resume_last) {
            try argv.append("--last");
        } else if (args.resume_id) |resume_id| {
            try argv.append(resume_id);
        }
        if (args.include_non_interactive) try argv.append("--include-non-interactive");
    }

    for (args.managed_argv) |arg| try argv.append(arg);
    return try argv.toOwnedSlice();
}

const CodexManagedResumeInspection = struct {
    requested: bool = false,
    explicit_id: bool = false,
    resume_last: bool = false,
    include_non_interactive: bool = false,
    checked: bool = false,
    found: bool = false,
    selected_route_available: bool = false,
    store_available: bool = false,
    session_index_checked: bool = false,
    session_index_match: bool = false,
    rollout_filenames_checked: bool = false,
    rollout_filename_match: bool = false,
    state_store_checked: bool = false,
    state_store_match: bool = false,
    path_printed: bool = false,
    status: []const u8 = "not_requested",
    diagnostic: []const u8 = "no resume id requested",
};

fn inspectCodexManagedResumeForArgs(allocator: std.mem.Allocator, args: cli.Command.CodexArgs) !CodexManagedResumeInspection {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = firstSelectableRoute(evaluations.items);
    const selected_route = if (selected_index) |idx| evaluations.items[idx].route else null;
    return try inspectCodexManagedResume(allocator, parsed.value, selected_route, args);
}

fn inspectCodexManagedResume(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    selected_route: ?RepairPlanRoute,
    args: cli.Command.CodexArgs,
) !CodexManagedResumeInspection {
    var result = CodexManagedResumeInspection{
        .requested = args.resume_id != null or args.resume_last,
        .explicit_id = args.resume_id != null,
        .resume_last = args.resume_last,
        .include_non_interactive = args.include_non_interactive,
    };

    if (!result.requested) return result;
    if (args.resume_last and args.resume_id == null) {
        result.status = "resume_last_unchecked";
        result.diagnostic = "resume --last is resolved by native Codex inside the selected route-local CODEX_HOME";
        result.selected_route_available = selected_route != null;
        return result;
    }

    const resume_id = args.resume_id orelse return result;
    result.checked = true;

    const route = selected_route orelse {
        result.status = "selected_route_unavailable";
        result.diagnostic = "no selectable route is available, so oauth-mux cannot check a route-local Codex resume id";
        return result;
    };
    result.selected_route_available = true;

    const store_dir = try codexManagedRouteConfigDir(allocator, cfg, route) orelse {
        result.status = "selected_route_missing_store";
        result.diagnostic = "selected Codex route does not define a CODEX_HOME store for resume lookup";
        return result;
    };
    defer allocator.free(store_dir);
    result.store_available = true;

    const index_path = try std.fs.path.join(allocator, &.{ store_dir, "session_index.jsonl" });
    defer allocator.free(index_path);
    result.session_index_checked = true;
    result.session_index_match = fileContainsNeedle(allocator, index_path, resume_id) catch false;

    const sessions_dir = try std.fs.path.join(allocator, &.{ store_dir, "sessions" });
    defer allocator.free(sessions_dir);
    result.rollout_filenames_checked = true;
    result.rollout_filename_match = directoryFileNameContainsNeedle(allocator, sessions_dir, resume_id) catch false;

    result.state_store_checked = true;
    result.state_store_match =
        (try codexManagedStateFileContainsNeedle(allocator, store_dir, "state_5.sqlite", resume_id)) or
        (try codexManagedStateFileContainsNeedle(allocator, store_dir, "state_5.sqlite-wal", resume_id));

    result.found = result.session_index_match or result.rollout_filename_match or result.state_store_match;
    if (result.found) {
        result.status = "found_in_selected_store";
        result.diagnostic = "resume id was found in the selected route-local Codex store";
    } else {
        result.status = "not_found_in_selected_store";
        result.diagnostic = "resume id was not found in the selected route-local Codex store; choose the route that owns it or start a new managed session";
    }
    return result;
}

fn codexManagedRouteConfigDir(allocator: std.mem.Allocator, cfg: config.Config, route: RepairPlanRoute) !?[]const u8 {
    const provider_cfg = cfg.providers.map.get(route.provider) orelse return null;
    const account = provider_cfg.accounts.map.get(route.account) orelse return null;
    const config_dir = account.config_dir orelse return null;
    return try paths.expandTilde(allocator, config_dir);
}

fn codexManagedStateFileContainsNeedle(
    allocator: std.mem.Allocator,
    store_dir: []const u8,
    filename: []const u8,
    needle: []const u8,
) !bool {
    const path = try std.fs.path.join(allocator, &.{ store_dir, filename });
    defer allocator.free(path);
    return fileContainsNeedle(allocator, path, needle) catch false;
}

fn fileContainsNeedle(allocator: std.mem.Allocator, path: []const u8, needle: []const u8) !bool {
    if (needle.len == 0) return false;
    var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.NotDir => return false,
        else => return err,
    };
    defer file.close();

    var previous = std.ArrayList(u8).init(allocator);
    defer previous.deinit();

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;

        var haystack = std.ArrayList(u8).init(allocator);
        defer haystack.deinit();
        try haystack.appendSlice(previous.items);
        try haystack.appendSlice(buf[0..n]);
        if (std.mem.indexOf(u8, haystack.items, needle) != null) return true;

        previous.clearRetainingCapacity();
        const keep = @min(needle.len - 1, haystack.items.len);
        if (keep != 0) try previous.appendSlice(haystack.items[haystack.items.len - keep ..]);
    }
    return false;
}

fn directoryFileNameContainsNeedle(allocator: std.mem.Allocator, root: []const u8, needle: []const u8) !bool {
    if (needle.len == 0) return false;
    var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.NotDir => return false,
        else => return err,
    };
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var inspected: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        inspected += 1;
        if (inspected > 20000) return false;
        if (std.mem.indexOf(u8, entry.basename, needle) != null) return true;
    }
    return false;
}

fn codexManagedResumeAllowsLaunch(inspection: CodexManagedResumeInspection) bool {
    if (!inspection.requested) return true;
    if (!inspection.explicit_id) return true;
    return inspection.found;
}

fn writeCodexManagedResumeJson(writer: anytype, inspection: CodexManagedResumeInspection) !void {
    try writer.writeAll("{\"scope\":\"route_local_codex_home\",\"requested\":");
    try writer.writeAll(if (inspection.requested) "true" else "false");
    try writer.writeAll(",\"resume_last\":");
    try writer.writeAll(if (inspection.resume_last) "true" else "false");
    try writer.writeAll(",\"resume_id_provided\":");
    try writer.writeAll(if (inspection.explicit_id) "true" else "false");
    try writer.writeAll(",\"checked\":");
    try writer.writeAll(if (inspection.checked) "true" else "false");
    try writer.writeAll(",\"found_in_selected_store\":");
    try writer.writeAll(if (inspection.found) "true" else "false");
    try writer.writeAll(",\"selected_route_available\":");
    try writer.writeAll(if (inspection.selected_route_available) "true" else "false");
    try writer.writeAll(",\"store_available\":");
    try writer.writeAll(if (inspection.store_available) "true" else "false");
    try writer.writeAll(",\"status\":");
    try std.json.stringify(inspection.status, .{}, writer);
    try writer.writeAll(",\"include_non_interactive\":");
    try writer.writeAll(if (inspection.include_non_interactive) "true" else "false");
    try writer.writeAll(",\"resume_id_printed\":false,\"path_printed\":false,\"unmanaged_cross_route_resume\":false");
    try writer.writeAll(",\"evidence\":{\"session_index_checked\":");
    try writer.writeAll(if (inspection.session_index_checked) "true" else "false");
    try writer.writeAll(",\"session_index_match\":");
    try writer.writeAll(if (inspection.session_index_match) "true" else "false");
    try writer.writeAll(",\"rollout_filenames_checked\":");
    try writer.writeAll(if (inspection.rollout_filenames_checked) "true" else "false");
    try writer.writeAll(",\"rollout_filename_match\":");
    try writer.writeAll(if (inspection.rollout_filename_match) "true" else "false");
    try writer.writeAll(",\"state_store_checked\":");
    try writer.writeAll(if (inspection.state_store_checked) "true" else "false");
    try writer.writeAll(",\"state_store_match\":");
    try writer.writeAll(if (inspection.state_store_match) "true" else "false");
    try writer.writeAll("},\"diagnostic\":");
    try std.json.stringify(inspection.diagnostic, .{}, writer);
    try writer.writeByte('}');
}

fn writeCodexManagedResumeRefusalText(writer: anytype, inspection: CodexManagedResumeInspection) !void {
    try writer.writeAll("oauth-mux Codex managed resume diagnostic\n\n");
    try writer.print("  ok: false\n  status: {s}\n", .{inspection.status});
    try writer.print("  selected_route_available: {s}\n", .{if (inspection.selected_route_available) "true" else "false"});
    try writer.writeAll("  resume_id_printed: false\n");
    try writer.writeAll("  path_printed: false\n");
    try writer.print("  diagnostic: {s}\n", .{inspection.diagnostic});
    try writer.writeAll("  next: start a new managed session, or select the account whose route-local CODEX_HOME owns that session id\n");
}

fn writeCodexManagedPlanJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: ?[]const u8,
    args: cli.Command.CodexArgs,
) !void {
    const session_start_ready = selected_index != null;
    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    const prepared_fallback = session_start_ready and fallback_count > 0;
    const selected_route = if (selected_index) |idx| evaluations[idx].route else null;
    const resume_inspection = try inspectCodexManagedResume(allocator, cfg, selected_route, args);
    const ok = session_start_ready and codexManagedResumeAllowsLaunch(resume_inspection);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_managed_session_plan\"");
    try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"executes_child\":false");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"managed_codex_process\",\"proof_status\":\"managed_launch_planning_only\",\"managed_process_launch\":true,\"mediation_point\":\"stay-afloat launch\",\"route_local_resume\":true,\"resume_namespace\":\"selected_route_codex_home\",\"prepared_fallback\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"selectable_fallback_routes\":");
    try writer.print("{d}", .{fallback_count});
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_auth_broker\":false,\"broker_owned_app_server\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"codex_home\":{\"env\":\"CODEX_HOME\",\"namespace\":\"selected_route_store\",\"path_printed\":false}");
    try writer.writeAll(",\"resume\":");
    try writeCodexManagedResumeJson(writer, resume_inspection);
    try writer.writeAll(",\"target\":{\"program\":\"codex\",\"passthrough_arg_count\":");
    try writer.print("{d}", .{args.managed_argv.len});
    try writer.writeAll(",\"argv_printed\":false}");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resilience\":");
    try writeCodexBrokerSessionResilienceJson(writer, session_start_ready, fallback_count);
    try writer.writeAll(",\"resilience_actions\":");
    try writeCodexBrokerSessionRiskActionsJson(writer, allocator, profile, capability, session_start_ready, fallback_count);
    try writer.writeAll(",\"routes\":[");
    for (evaluations, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        try writeRouteEvaluationJson(writer, allocator, cfg, evaluation, selected);
    }
    try writer.writeAll("]}\n");
}

fn writeCodexManagedPlanText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: ?[]const u8,
    args: cli.Command.CodexArgs,
) !void {
    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    const selected_route = if (selected_index) |idx| evaluations[idx].route else null;
    const resume_inspection = try inspectCodexManagedResume(allocator, cfg, selected_route, args);
    try writer.writeAll("oauth-mux Codex managed session plan\n\n");
    if (profile) |value| try writer.print("  profile: {s}\n", .{value});
    if (capability) |value| try writer.print("  capability: {s}\n", .{value});
    try writer.writeAll("  claim: planning-only managed_codex_process launch with route-local CODEX_HOME resume namespace\n");
    try writer.print("  session_start_ready: {s}\n", .{if (selected_index != null) "true" else "false"});
    try writer.print("  selectable_fallback_routes: {d}\n", .{fallback_count});
    try writer.print("  resume_requested: {s}\n", .{if (args.resume_id != null or args.resume_last) "true" else "false"});
    try writer.print("  resume_status: {s}\n", .{resume_inspection.status});
    try writer.print("  resume_found_in_selected_store: {s}\n", .{if (resume_inspection.found) "true" else "false"});
    if (selected_index) |idx| {
        const route = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("  selected: none\n");
    }
    try writer.writeAll("  codex_home: selected route store; path not printed\n");
    try writer.writeAll("  boundary: this plans/launches native Codex under oauth-mux mediation; it does not import unmanaged sessions or prove same-thread quota handoff\n");
}

const CodexBrokerSessionSummary = struct {
    routes_total: usize = 0,
    broker_ready_routes: usize = 0,
    unreadable_routes: usize = 0,
    selectable_routes: usize = 0,
    selectable_broker_routes: usize = 0,
    selectable_fallback_routes: usize = 0,
    blocked_broker_routes: usize = 0,
    auth_unready_routes: usize = 0,
};

fn codexBrokerSessionSpareFallbackReady(session_start_ready: bool, selectable_fallback_routes: usize) bool {
    return session_start_ready and selectable_fallback_routes > 0;
}

fn codexBrokerSessionSingleRouteAtRisk(session_start_ready: bool, selectable_fallback_routes: usize) bool {
    return session_start_ready and selectable_fallback_routes == 0;
}

fn codexBrokerSessionResilienceState(session_start_ready: bool, selectable_fallback_routes: usize) []const u8 {
    if (!session_start_ready) return "not_ready";
    if (selectable_fallback_routes > 0) return "ready_with_spare_fallback";
    return "ready_without_spare_fallback";
}

fn writeCodexBrokerSessionResilienceJson(
    writer: anytype,
    session_start_ready: bool,
    selectable_fallback_routes: usize,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"session_start_ready\":");
    try writer.writeAll(if (session_start_ready) "true" else "false");
    try writer.writeAll(",\"selectable_fallback_routes\":");
    try writer.print("{d}", .{selectable_fallback_routes});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (codexBrokerSessionSpareFallbackReady(session_start_ready, selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (codexBrokerSessionSingleRouteAtRisk(session_start_ready, selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"state\":");
    try std.json.stringify(codexBrokerSessionResilienceState(session_start_ready, selectable_fallback_routes), .{}, writer);
    try writer.writeByte('}');
}

fn writeCodexBrokerProfileCapabilityCommandJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    base: []const u8,
    profile: ?[]const u8,
    capability: ?[]const u8,
    suffix: []const u8,
) !void {
    var command = std.ArrayList(u8).init(allocator);
    defer command.deinit();
    try command.writer().writeAll(base);
    try command.writer().writeAll(" --profile ");
    try command.writer().writeAll(profile orelse "<profile>");
    try command.writer().writeAll(" --capability ");
    try command.writer().writeAll(capability orelse "<capability>");
    if (suffix.len != 0) {
        try command.writer().writeByte(' ');
        try command.writer().writeAll(suffix);
    }
    try std.json.stringify(command.items, .{}, writer);
}

fn writeCodexBrokerSessionRiskActionJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    kind: []const u8,
    reason: []const u8,
    spends_provider_calls: bool,
    mutates_route_health: bool,
    mutates_user_config: bool,
    confirmation_required: bool,
    include_profile_capability: bool,
    command_base: ?[]const u8,
    profile: ?[]const u8,
    capability: ?[]const u8,
    command_suffix: []const u8,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try std.json.stringify(kind, .{}, writer);
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(reason, .{}, writer);
    try writer.writeAll(",\"agent_safe\":");
    try writer.writeAll(if (!spends_provider_calls and !mutates_route_health and !mutates_user_config) "true" else "false");
    try writer.writeAll(",\"spends_provider_calls\":");
    try writer.writeAll(if (spends_provider_calls) "true" else "false");
    try writer.writeAll(",\"mutates_route_health\":");
    try writer.writeAll(if (mutates_route_health) "true" else "false");
    try writer.writeAll(",\"mutates_user_config\":");
    try writer.writeAll(if (mutates_user_config) "true" else "false");
    try writer.writeAll(",\"confirmation_required\":");
    try writer.writeAll(if (confirmation_required) "true" else "false");
    try writer.writeAll(",\"command\":");
    if (command_base) |base| {
        if (include_profile_capability) {
            try writeCodexBrokerProfileCapabilityCommandJson(writer, allocator, base, profile, capability, command_suffix);
        } else {
            var command = std.ArrayList(u8).init(allocator);
            defer command.deinit();
            try command.writer().writeAll(base);
            if (command_suffix.len != 0) {
                try command.writer().writeByte(' ');
                try command.writer().writeAll(command_suffix);
            }
            try std.json.stringify(command.items, .{}, writer);
        }
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeCodexBrokerSessionRiskActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    selectable_fallback_routes: usize,
) !void {
    try writer.writeByte('[');
    if (codexBrokerSessionSingleRouteAtRisk(session_start_ready, selectable_fallback_routes)) {
        try writeCodexBrokerSessionRiskActionJson(
            writer,
            allocator,
            "revalidate_exhausted_routes",
            "selected_route_has_no_spare_fallback",
            true,
            true,
            false,
            true,
            true,
            "oauth-mux codex revalidate-exhausted",
            profile,
            capability,
            "--confirm-spend --json",
        );
        try writer.writeByte(',');
        try writeCodexBrokerSessionRiskActionJson(
            writer,
            allocator,
            "enroll_codex_account",
            "no_spare_fallback_route_ready",
            false,
            false,
            true,
            true,
            false,
            "oauth-mux enroll codex --account <name> --confirm-enroll --json",
            null,
            null,
            "",
        );
        try writer.writeByte(',');
        try writeCodexBrokerSessionRiskActionJson(
            writer,
            allocator,
            "wait_for_quota_reset",
            "blocked_routes_may_become_available_after_reset",
            false,
            false,
            false,
            false,
            false,
            null,
            null,
            null,
            "",
        );
    }
    try writer.writeByte(']');
}

const codex_fallback_drill_retry_after_s: u32 = 7200;

fn runCodexBrokerFallbackDrill(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!args.confirm_drill) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"confirmation_required\":true,\"requires\":\"--confirm-drill\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":true,\"mode\":\"codex_broker_fallback_drill\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux codex broker-fallback-drill --profile <profile> --capability <capability> --from-account <account> --confirm-drill --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker fallback drill\n\n");
            try writer.writeAll("  confirmation required: --confirm-drill\n");
            try writer.writeAll("  this marks one local route-health entry quota-exhausted and proves the next broker-owned route selection\n");
        }
        return;
    }

    const from_account = nonEmpty(args.from_account) orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"from_account_required\",\"requires\":\"--from-account <account>\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"mode\":\"codex_broker_fallback_drill\"}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker fallback drill\n\n");
            try writer.writeAll("  from account required: --from-account <account>\n");
        }
        return;
    };

    const capability = firstCommaValue(args.capabilities) orelse {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"capability_required\",\"requires\":\"--capability <capability>\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"mode\":\"codex_broker_fallback_drill\"}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker fallback drill\n\n");
            try writer.writeAll("  capability required: --capability <capability>\n");
        }
        return;
    };

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = null,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var before = std.ArrayList(RouteEvaluation).init(allocator);
    defer before.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &before);

    const target_index = findCodexBrokerRouteIndexForAccount(before.items, from_account, capability) orelse {
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":\"codex_broker_fallback_drill\",\"ok\":false,\"confirmed\":true,\"reason\":\"from_account_not_in_route_set\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"from_account\":");
            try std.json.stringify(from_account, .{}, writer);
            try writer.writeAll(",\"profile\":");
            if (args.profile) |profile| try std.json.stringify(profile, .{}, writer) else try writer.writeAll("null");
            try writer.writeAll(",\"capability\":");
            try std.json.stringify(capability, .{}, writer);
            try writer.writeAll("}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker fallback drill\n\n");
            try writer.print("  no matching Codex route for account {s}\n", .{from_account});
        }
        return;
    };

    const previous_selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, before.items);
    const target_route = before.items[target_index].route;
    const target_was_selected_before = if (previous_selected_index) |idx|
        sameRepairPlanRouteIdentity(before.items[idx].route, target_route)
    else
        false;

    const def = config.resolveProviderDefinition(parsed.value, target_route.provider);
    if (target_route.capability) |route_capability| {
        store.recordCapabilityHttpStatusForProvider(
            target_route.provider,
            target_route.account,
            route_capability,
            def,
            429,
            codex_fallback_drill_retry_after_s,
            "controlled codex broker fallback drill",
        );
    } else {
        const key = health_mod.accountKey(target_route.provider, target_route.account);
        store.recordHttpStatusForProvider(
            key.slice(),
            def,
            429,
            codex_fallback_drill_retry_after_s,
            "controlled codex broker fallback drill",
        );
    }
    store.persist();

    var after = std.ArrayList(RouteEvaluation).init(allocator);
    defer after.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &after);

    const selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, after.items);
    const fallback_route_is_distinct = if (selected_index) |idx|
        !sameRepairPlanRouteIdentity(after.items[idx].route, target_route)
    else
        false;
    const ok = target_was_selected_before and fallback_route_is_distinct;
    const reason = if (ok)
        "controlled_fallback_selected_distinct_route"
    else if (!target_was_selected_before)
        "drilled_route_was_not_selected_before"
    else if (selected_index == null)
        "no_fallback_route_after_drill"
    else
        "drill_selected_same_route";

    if (args.json) {
        try writeCodexBrokerFallbackDrillJson(
            writer,
            allocator,
            parsed.value,
            before.items,
            after.items,
            target_route,
            previous_selected_index,
            selected_index,
            args.profile,
            capability,
            ok,
            reason,
            target_was_selected_before,
            fallback_route_is_distinct,
        );
    } else {
        try writeCodexBrokerFallbackDrillText(
            writer,
            target_route,
            before.items,
            after.items,
            previous_selected_index,
            selected_index,
            capability,
            ok,
            reason,
            target_was_selected_before,
            fallback_route_is_distinct,
        );
    }
}

fn findCodexBrokerRouteIndexForAccount(
    evaluations: []const RouteEvaluation,
    account: []const u8,
    capability: []const u8,
) ?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (!std.mem.eql(u8, evaluation.route.provider, "codex")) continue;
        if (!std.mem.eql(u8, evaluation.route.account, account)) continue;
        const route_capability = evaluation.route.capability orelse continue;
        if (!std.mem.eql(u8, route_capability, capability)) continue;
        return idx;
    }
    return null;
}

fn writeCodexBrokerFallbackDrillJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    before: []const RouteEvaluation,
    after: []const RouteEvaluation,
    target_route: RepairPlanRoute,
    previous_selected_index: ?usize,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: []const u8,
    ok: bool,
    reason: []const u8,
    target_was_selected_before: bool,
    fallback_route_is_distinct: bool,
) !void {
    const summary = try summarizeCodexBrokerSessionPlan(allocator, cfg, after, selected_index);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_broker_fallback_drill\",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":true");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(reason, .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"controlled_route_health_drill\",\"proof_status\":\"controlled_route_state_fallback_drill\",\"broker_owned_session\":true,\"route_selection_source\":\"route_health_after_controlled_mutation\",\"provider_originated_quota\":false,\"next_turn_route_state_fallback\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    try std.json.stringify(capability, .{}, writer);
    try writer.writeAll(",\"drilled\":{\"provider\":");
    try std.json.stringify(target_route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(target_route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (target_route.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"health_key\":");
    if (target_route.capability) |route_capability| {
        const key = health_mod.capabilityKey(target_route.provider, target_route.account, route_capability);
        try std.json.stringify(key.slice(), .{}, writer);
    } else {
        const key = health_mod.accountKey(target_route.provider, target_route.account);
        try std.json.stringify(key.slice(), .{}, writer);
    }
    try writer.print(",\"http_status\":429,\"retry_after_s\":{d}", .{codex_fallback_drill_retry_after_s});
    try writer.writeAll(",\"classification\":\"quota_exhausted\",\"decision\":\"try_next_account\",\"previously_selected\":");
    try writer.writeAll(if (target_was_selected_before) "true" else "false");
    try writer.writeByte('}');
    try writer.writeAll(",\"previous_selected\":");
    if (previous_selected_index) |idx| try writeRouteSelectionJson(writer, before[idx].route) else try writer.writeAll("null");
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| try writeRouteSelectionJson(writer, after[idx].route) else try writer.writeAll("null");
    try writer.writeAll(",\"fallback_route_is_distinct\":");
    try writer.writeAll(if (fallback_route_is_distinct) "true" else "false");
    try writer.print(",\"summary\":{{\"routes_total\":{d},\"broker_ready_routes\":{d},\"unreadable_routes\":{d},\"selectable_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d},\"auth_unready_routes\":{d}}}", .{
        summary.routes_total,
        summary.broker_ready_routes,
        summary.unreadable_routes,
        summary.selectable_routes,
        summary.selectable_broker_routes,
        summary.selectable_fallback_routes,
        summary.blocked_broker_routes,
        summary.auth_unready_routes,
    });
    try writer.writeAll(",\"routes\":[");
    for (after, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        try writeCodexBrokerSessionRouteJson(writer, allocator, cfg, evaluation, selected, plan);
    }
    try writer.writeAll("],\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBrokerFallbackDrillText(
    writer: anytype,
    target_route: RepairPlanRoute,
    before: []const RouteEvaluation,
    after: []const RouteEvaluation,
    previous_selected_index: ?usize,
    selected_index: ?usize,
    capability: []const u8,
    ok: bool,
    reason: []const u8,
    target_was_selected_before: bool,
    fallback_route_is_distinct: bool,
) !void {
    try writer.writeAll("oauth-mux Codex broker fallback drill\n\n");
    try writer.print("  capability: {s}\n", .{capability});
    try writer.print("  drilled: {s}:{s}", .{ target_route.provider, target_route.account });
    if (target_route.capability) |value| try writer.print("#{s}", .{value});
    try writer.print(" -> quota_exhausted retry_after_s={d}\n", .{codex_fallback_drill_retry_after_s});
    try writer.writeAll("  previous selected: ");
    if (previous_selected_index) |idx| {
        const route = before[idx].route;
        try writer.print("{s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("none\n");
    }
    try writer.writeAll("  selected after drill: ");
    if (selected_index) |idx| {
        const route = after[idx].route;
        try writer.print("{s}:{s}", .{ route.provider, route.account });
        if (route.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("none\n");
    }
    try writer.print("  previously_selected={s} distinct_fallback={s}\n", .{
        if (target_was_selected_before) "true" else "false",
        if (fallback_route_is_distinct) "true" else "false",
    });
    try writer.print("  ok: {s}\n", .{if (ok) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
    try writer.writeAll("  boundary: controlled route-health mutation; provider-originated quota is not proven by this drill\n");
}

fn firstSelectableCodexBrokerRouteIndex(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
) !?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (!evaluation.selectable) continue;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (plan.can_supply) return idx;
    }
    return null;
}

fn summarizeCodexBrokerSessionPlan(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !CodexBrokerSessionSummary {
    var summary = CodexBrokerSessionSummary{};
    for (evaluations, 0..) |evaluation, idx| {
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        summary.routes_total += 1;
        if (evaluation.selectable) summary.selectable_routes += 1;
        if (plan.can_supply) {
            summary.broker_ready_routes += 1;
            if (evaluation.selectable) {
                summary.selectable_broker_routes += 1;
                if (selected_index == null or idx != selected_index.?) summary.selectable_fallback_routes += 1;
            } else {
                summary.blocked_broker_routes += 1;
            }
        } else {
            summary.auth_unready_routes += 1;
            if (!plan.secret_readable) summary.unreadable_routes += 1;
        }
    }
    return summary;
}

fn writeCodexBrokerSessionPlanJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: ?[]const u8,
) !void {
    const summary = try summarizeCodexBrokerSessionPlan(allocator, cfg, evaluations, selected_index);
    const session_start_ready = selected_index != null;
    const prepared_fallback = codexBrokerSessionSpareFallbackReady(session_start_ready, summary.selectable_fallback_routes);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_broker_owned_session_plan\"");
    try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"refresh_method\":\"account/chatgptAuthTokens/refresh\"}");
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (session_start_ready) "true" else "false");
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":\"session_planning_only\",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"session_start_ready\":");
    try writer.writeAll(if (session_start_ready) "true" else "false");
    try writer.writeAll(",\"prepared_fallback\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"next_thread_quota_fallback_ready\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"selectable_fallback_routes\":");
    try writer.print("{d}", .{summary.selectable_fallback_routes});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (codexBrokerSessionSpareFallbackReady(session_start_ready, summary.selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (codexBrokerSessionSingleRouteAtRisk(session_start_ready, summary.selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"resilience\":");
    try writeCodexBrokerSessionResilienceJson(writer, session_start_ready, summary.selectable_fallback_routes);
    try writer.writeAll(",\"resilience_actions\":");
    try writeCodexBrokerSessionRiskActionsJson(writer, allocator, profile, capability, session_start_ready, summary.selectable_fallback_routes);
    try writer.print(",\"summary\":{{\"routes_total\":{d},\"broker_ready_routes\":{d},\"unreadable_routes\":{d},\"selectable_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d},\"auth_unready_routes\":{d}}}", .{
        summary.routes_total,
        summary.broker_ready_routes,
        summary.unreadable_routes,
        summary.selectable_routes,
        summary.selectable_broker_routes,
        summary.selectable_fallback_routes,
        summary.blocked_broker_routes,
        summary.auth_unready_routes,
    });
    try writer.writeAll(",\"selected\":");
    if (selected_index) |idx| {
        try writeRouteSelectionJson(writer, evaluations[idx].route);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"routes\":[");
    for (evaluations, 0..) |evaluation, idx| {
        if (idx > 0) try writer.writeByte(',');
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        try writeCodexBrokerSessionRouteJson(writer, allocator, cfg, evaluation, selected, plan);
    }
    try writer.writeAll("]}\n");
}

fn writeCodexBrokerSessionPlanText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    profile: ?[]const u8,
    capability: ?[]const u8,
) !void {
    const summary = try summarizeCodexBrokerSessionPlan(allocator, cfg, evaluations, selected_index);
    try writer.writeAll("oauth-mux Codex broker-owned session plan\n\n");
    if (profile) |value| try writer.print("  profile: {s}\n", .{value});
    if (capability) |value| try writer.print("  capability: {s}\n", .{value});
    try writer.writeAll("  claim: planning-only broker_owned_app_server for broker-owned app-server sessions\n");
    try writer.print("  broker_ready_routes: {d}\n", .{summary.broker_ready_routes});
    try writer.print("  selectable_broker_routes: {d}\n", .{summary.selectable_broker_routes});
    try writer.print("  selectable_fallback_routes: {d}\n", .{summary.selectable_fallback_routes});
    try writer.print("  spare_fallback_ready: {s}\n", .{if (codexBrokerSessionSpareFallbackReady(selected_index != null, summary.selectable_fallback_routes)) "true" else "false"});
    try writer.print("  single_route_at_risk: {s}\n", .{if (codexBrokerSessionSingleRouteAtRisk(selected_index != null, summary.selectable_fallback_routes)) "true" else "false"});
    if (codexBrokerSessionSingleRouteAtRisk(selected_index != null, summary.selectable_fallback_routes)) {
        try writer.writeAll("  next: revalidate exhausted routes, wait for reset, or enroll another Codex account\n");
    }

    if (selected_index) |idx| {
        const selected = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ selected.provider, selected.account });
        if (selected.capability) |value| try writer.print("#{s}", .{value});
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("  selected: none\n");
    }

    if (evaluations.len == 0) {
        try writer.writeAll("\n  no matching Codex routes\n");
        return;
    }

    try writer.writeAll("\n  routes:\n");
    for (evaluations, 0..) |evaluation, idx| {
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        const role = codexBrokerSessionRouteRole(evaluation, selected, plan);
        try writer.print("    {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
        if (evaluation.route.capability) |value| try writer.print("#{s}", .{value});
        try writer.print(" role={s} selectable={s} broker_ready={s} reason={s} broker_reason={s}\n", .{
            role,
            if (evaluation.selectable) "true" else "false",
            if (plan.can_supply) "true" else "false",
            evaluation.skip_reason,
            plan.reason,
        });
    }
}

fn writeCodexBrokerSessionRouteJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    selected: bool,
    plan: CodexBrokerTokenPlan,
) !void {
    const fallback_candidate = plan.can_supply and evaluation.selectable and !selected;
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(evaluation.route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(evaluation.route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (evaluation.route.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"selected\":");
    try writer.writeAll(if (selected) "true" else "false");
    try writer.writeAll(",\"selectable\":");
    try writer.writeAll(if (evaluation.selectable) "true" else "false");
    try writer.writeAll(",\"broker_ready\":");
    try writer.writeAll(if (plan.can_supply) "true" else "false");
    try writer.writeAll(",\"session_ready\":");
    try writer.writeAll(if (plan.can_supply and evaluation.selectable) "true" else "false");
    try writer.writeAll(",\"fallback_candidate\":");
    try writer.writeAll(if (fallback_candidate) "true" else "false");
    try writer.writeAll(",\"route_role\":");
    try std.json.stringify(codexBrokerSessionRouteRole(evaluation, selected, plan), .{}, writer);
    try writer.writeAll(",\"skip_reason\":");
    try std.json.stringify(evaluation.skip_reason, .{}, writer);
    try writer.writeAll(",\"runtime\":");
    try writeRuntimeReadinessJson(writer, evaluation.runtime);
    try writer.writeAll(",\"liveness\":");
    if (evaluation.health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
    try writer.writeAll(",\"last_probe\":");
    if (evaluation.health) |health| try writeProbeEvidenceJson(writer, health) else try writer.writeAll("null");
    try writer.writeAll(",\"action\":");
    try writeRepairActionJson(writer, allocator, evaluation.action, evaluation.route);
    try writer.writeAll(",\"auth_broker\":");
    try writeCodexBrokerRouteJson(writer, evaluation.route, cfg, plan);
    try writer.writeByte('}');
}

fn codexBrokerSessionRouteRole(evaluation: RouteEvaluation, selected: bool, plan: CodexBrokerTokenPlan) []const u8 {
    if (!plan.can_supply) return "auth_broker_unready";
    if (selected) return "selected";
    if (evaluation.selectable) return "selectable_fallback";
    if (std.mem.eql(u8, evaluation.skip_reason, "quota_exhausted")) return "quota_blocked";
    if (std.mem.eql(u8, evaluation.skip_reason, "rate_limited")) return "rate_limited";
    if (std.mem.eql(u8, evaluation.skip_reason, "unrecorded")) return "probe_needed";
    return "not_selectable";
}

fn runCodexBrokerSessionSmoke(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!args.confirm_broker) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"confirmation_required\":true,\"requires\":\"--confirm-broker\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_broker_owned_session_smoke\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux codex broker-session-smoke --profile <profile> --capability <capability> --confirm-broker --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned session smoke\n\n");
            try writer.writeAll("  confirmation required: --confirm-broker\n");
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local no-spend Responses mock using broker-session-plan route semantics\n");
        }
        return;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, evaluations.items);
    var selected: ?CodexBrokerRouteCredentials = null;
    defer if (selected) |*value| value.deinit(allocator);
    var fallback_selected: ?CodexBrokerRouteCredentials = null;
    defer if (fallback_selected) |*value| value.deinit(allocator);

    if (selected_index) |idx| {
        const route = evaluations.items[idx].route;
        selected = .{
            .route = route,
            .credentials = try loadCodexBrokerCredentialsForRoute(allocator, parsed.value, route),
        };

        for (evaluations.items, 0..) |evaluation, fallback_idx| {
            if (fallback_idx == idx or !evaluation.selectable) continue;
            const plan = try inspectCodexBrokerRoute(allocator, parsed.value, evaluation.route);
            if (!plan.can_supply) continue;
            fallback_selected = .{
                .route = evaluation.route,
                .credentials = try loadCodexBrokerCredentialsForRoute(allocator, parsed.value, evaluation.route),
            };
            break;
        }
    }

    if (selected == null or fallback_selected == null) {
        const reason = if (selected == null) "no_session_start_ready_route" else "no_selectable_broker_fallback_route";
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":\"codex_broker_owned_session_smoke\",\"ok\":false,\"confirmed\":true,\"reason\":");
            try std.json.stringify(reason, .{}, writer);
            try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"routes_total\":");
            try writer.print("{d}", .{evaluations.items.len});
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned session smoke\n\n");
            try writer.print("  {s}\n", .{reason});
            try writer.writeAll("  next: oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json\n");
        }
        return;
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const run_dir = try std.fmt.allocPrint(allocator, "{s}/codex-broker-session-smoke-{d}", .{ state_dir, std.time.milliTimestamp() });
    defer allocator.free(run_dir);
    try std.fs.cwd().makePath(run_dir);

    var mock_server = try startCodexBrokerQuotaMockServer(allocator, selected.?.credentials.access_token, fallback_selected.?.credentials.access_token);
    defer mock_server.destroy();

    const mock_origin = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{mock_server.port});
    defer allocator.free(mock_origin);
    const base_url = try std.fmt.allocPrint(allocator, "{s}/v1", .{mock_origin});
    defer allocator.free(base_url);
    const chatgpt_base_url = try std.fmt.allocPrint(allocator, "{s}/backend-api", .{mock_origin});
    defer allocator.free(chatgpt_base_url);
    try writeCodexBroker401AppServerFiles(allocator, run_dir, base_url, chatgpt_base_url);

    var result = CodexBrokerQuotaSmokeResult{
        .broker = try runCodexAppServerQuotaBrokerSmoke(
            allocator,
            selected.?.credentials,
            fallback_selected.?.credentials,
            run_dir,
        ),
    };
    result.http = mock_server.finish();

    if (args.json) {
        try writeCodexBrokerSessionSmokeJson(writer, selected.?.route, fallback_selected.?.route, capability, result);
    } else {
        try writeCodexBrokerSessionSmokeText(writer, selected.?.route, fallback_selected.?.route, capability, result);
    }
}

fn codexBrokerSessionSmokeReason(result: CodexBrokerQuotaSmokeResult) []const u8 {
    if (codexBrokerQuotaSmokeOk(result)) return "broker_session_next_thread_fallback_completed";
    return codexBrokerQuotaSmokeReason(result);
}

fn writeCodexBrokerSessionSmokeJson(
    writer: anytype,
    route: RepairPlanRoute,
    fallback_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerQuotaSmokeResult,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_broker_owned_session_smoke\",\"ok\":");
    try writer.writeAll(if (codexBrokerQuotaSmokeOk(result)) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(codexBrokerSessionSmokeReason(result), .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":\"local_broker_owned_session_smoke\",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"route_selection_source\":\"broker_session_plan\",\"session_start_ready\":true,\"prepared_fallback\":true,\"next_thread_quota_fallback_proven\":true,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"selected\":");
    try writeRouteSelectionJson(writer, route);
    try writer.writeAll(",\"fallback_selected\":");
    try writeRouteSelectionJson(writer, fallback_route);
    try writer.writeAll(",\"fallback_route_is_distinct\":");
    try writer.writeAll(if (!sameRepairPlanRouteIdentity(route, fallback_route)) "true" else "false");
    try writer.writeAll(",\"simulated_route_state\":{\"first_turn_classification\":\"quota_exhausted\",\"decision\":\"try_next_account\",\"retry_after_s\":7200}");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"mock_provider\":\"local_responses_429_then_new_thread_fallback_sse\"}");
    try writer.writeAll(",\"protocol\":");
    try writeCodexBrokerProtocolJson(writer, result.broker);
    try writer.writeAll(",\"http_mock\":");
    try writeCodexBrokerQuotaHttpJson(writer, result.http);
    try writer.writeAll(",\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBrokerSessionSmokeText(
    writer: anytype,
    route: RepairPlanRoute,
    fallback_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerQuotaSmokeResult,
) !void {
    try writer.writeAll("oauth-mux Codex broker-owned session smoke\n\n");
    try writer.print("  route: {s}:{s}", .{ route.provider, route.account });
    if (capability) |value| try writer.print("#{s}", .{value});
    try writer.writeByte('\n');
    try writer.print("  fallback route: {s}:{s}", .{ fallback_route.provider, fallback_route.account });
    if (fallback_route.capability) |route_capability| try writer.print("#{s}", .{route_capability});
    try writer.print(" distinct={s}\n", .{if (sameRepairPlanRouteIdentity(route, fallback_route)) "false" else "true"});
    try writer.print("  ok: {s}\n", .{if (codexBrokerQuotaSmokeOk(result)) "true" else "false"});
    try writer.print("  reason: {s}\n", .{codexBrokerSessionSmokeReason(result)});
    try writer.print("  quota_response_sent: {s}\n", .{if (result.http.quota_response_sent) "true" else "false"});
    try writer.print("  next_turn_used_fallback: {s}\n", .{if (result.http.next_turn_used_fallback) "true" else "false"});
    try writer.print("  same_turn_refresh_request_seen: {s}\n", .{if (result.broker.protocol.refresh_request_seen) "true" else "false"});
    try writer.writeAll("  redaction: tokens/account ids/raw protocol not printed\n");
}

fn runCodexBrokerRun(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!codexLiveQaConfirmed(args)) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"confirmation_required\",\"confirmation_required\":true,\"requires\":\"--confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls\",\"spends_provider_calls\":true,\"mutates_user_config\":false,\"mutates_route_health\":true,\"mode\":\"codex_broker_owned_session_live_run\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux codex broker-run --profile <profile> --capability <capability> --prompt <prompt> --confirm-spend --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned live run is disabled.\n\n");
            try writer.writeAll("This command starts a broker-owned Codex app-server and sends live Codex turns.\n");
            try writer.writeAll("Re-run with --confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls.\n");
        }
        return error.CodexLiveQaConfirmationRequired;
    }

    if (args.prompt != null and args.stdin_prompts) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"prompt_source_conflict\",\"requires\":\"exactly one of --prompt or --stdin\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_broker_owned_session_live_run\"}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned live run\n\n");
            try writer.writeAll("  choose exactly one prompt source: --prompt <text> or --stdin\n");
        }
        return;
    }

    var stdin_prompt_input: ?[]u8 = null;
    defer if (stdin_prompt_input) |value| allocator.free(value);
    var prompts = std.ArrayList([]const u8).init(allocator);
    defer prompts.deinit();
    const max_broker_run_prompts: usize = 8;

    if (args.stdin_prompts) {
        stdin_prompt_input = try std.io.getStdIn().reader().readAllAlloc(allocator, 64 * 1024);
        var lines = std.mem.splitScalar(u8, stdin_prompt_input.?, '\n');
        while (lines.next()) |line| {
            const prompt = std.mem.trim(u8, line, " \t\r\n");
            if (prompt.len == 0) continue;
            try prompts.append(prompt);
        }
    } else if (args.prompt) |prompt| {
        try prompts.append(prompt);
    }

    if (prompts.items.len == 0) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"prompt_required\",\"requires\":\"--prompt or --stdin\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_broker_owned_session_live_run\"}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned live run\n\n");
            try writer.writeAll("  prompt required: --prompt <text> or line-delimited --stdin\n");
        }
        return;
    }
    if (prompts.items.len > max_broker_run_prompts) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"prompt_count_limit_exceeded\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_broker_owned_session_live_run\",\"max_prompts\":");
            try writer.print("{d}", .{max_broker_run_prompts});
            try writer.print(",\"prompt_count\":{d}", .{prompts.items.len});
            try writer.writeAll("}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned live run\n\n");
            try writer.print("  too many prompts: max {d}, got {d}\n", .{ max_broker_run_prompts, prompts.items.len });
        }
        return;
    }

    const model = try codexBrokerRunModel(allocator, args);
    defer allocator.free(model);

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

    const selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, evaluations.items);
    const summary = try summarizeCodexBrokerSessionPlan(allocator, parsed.value, evaluations.items, selected_index);

    var selected: ?CodexBrokerRouteCredentials = null;
    defer if (selected) |*value| value.deinit(allocator);

    if (selected_index) |idx| {
        const route = evaluations.items[idx].route;
        selected = .{
            .route = route,
            .credentials = try loadCodexBrokerCredentialsForRoute(allocator, parsed.value, route),
        };
    }

    if (selected == null) {
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":\"codex_broker_owned_session_live_run\",\"ok\":false,\"confirmed\":true,\"reason\":\"no_session_start_ready_route\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false,\"routes_total\":");
            try writer.print("{d}", .{evaluations.items.len});
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex broker-owned live run\n\n");
            try writer.writeAll("  no session-start-ready Codex route found\n");
            try writer.writeAll("  next: oauth-mux codex broker-session-plan --profile <profile> --capability <capability> --json\n");
        }
        return;
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const run_dir = try std.fmt.allocPrint(allocator, "{s}/codex-broker-run-{d}", .{ state_dir, std.time.milliTimestamp() });
    defer allocator.free(run_dir);
    try std.fs.cwd().makePath(run_dir);
    try writeCodexBrokerLiveAppServerFiles(allocator, run_dir, model);

    var result = try runCodexAppServerLiveBrokerRun(
        allocator,
        selected.?.credentials,
        run_dir,
        model,
        prompts.items,
    );

    if (result.live_provider_failure) |classification| {
        recordCodexBrokerRunRouteHealth(&store, selected.?.route, classification);
        result.route_health_recorded = true;
        store.persist();
    }

    var after_failure_evaluations = std.ArrayList(RouteEvaluation).init(allocator);
    defer after_failure_evaluations.deinit();
    var after_failure_selected_index: ?usize = null;
    var after_failure_summary: ?CodexBrokerSessionSummary = null;
    if (result.route_health_recorded) {
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &after_failure_evaluations);
        after_failure_selected_index = try firstSelectableCodexBrokerRouteIndex(allocator, parsed.value, after_failure_evaluations.items);
        after_failure_summary = try summarizeCodexBrokerSessionPlan(allocator, parsed.value, after_failure_evaluations.items, after_failure_selected_index);
    }

    var continuation: ?CodexBrokerRunContinuation = null;
    if (args.continue_on_failure and result.route_health_recorded) {
        if (after_failure_selected_index) |idx| {
            const continuation_route = after_failure_evaluations.items[idx].route;
            if (!sameRepairPlanRouteIdentity(selected.?.route, continuation_route)) {
                const prompt_start_index = codexBrokerRunContinuationPromptStart(result, prompts.items.len);
                if (prompt_start_index < prompts.items.len) {
                    var continuation_credentials = CodexBrokerRouteCredentials{
                        .route = continuation_route,
                        .credentials = try loadCodexBrokerCredentialsForRoute(allocator, parsed.value, continuation_route),
                    };
                    defer continuation_credentials.deinit(allocator);

                    const continuation_dir = try std.fmt.allocPrint(allocator, "{s}/codex-broker-run-{d}-continue", .{ state_dir, std.time.milliTimestamp() });
                    defer allocator.free(continuation_dir);
                    try std.fs.cwd().makePath(continuation_dir);
                    try writeCodexBrokerLiveAppServerFiles(allocator, continuation_dir, model);

                    var continuation_result = try runCodexAppServerLiveBrokerRun(
                        allocator,
                        continuation_credentials.credentials,
                        continuation_dir,
                        model,
                        prompts.items[prompt_start_index..],
                    );
                    if (continuation_result.live_provider_failure) |classification| {
                        recordCodexBrokerRunRouteHealth(&store, continuation_route, classification);
                        continuation_result.route_health_recorded = true;
                        store.persist();
                    }
                    continuation = .{
                        .route = continuation_route,
                        .prompt_start_index = prompt_start_index,
                        .prompt_count = prompts.items.len - prompt_start_index,
                        .result = continuation_result,
                    };
                }
            }
        }
    }

    if (args.json) {
        try writeCodexBrokerRunJson(writer, allocator, selected.?.route, args.profile, capability, model, if (args.stdin_prompts) "stdin" else "prompt", prompts.items, summary, result, after_failure_evaluations.items, after_failure_selected_index, after_failure_summary, args.continue_on_failure, continuation);
    } else {
        try writeCodexBrokerRunText(writer, selected.?.route, capability, model, if (args.stdin_prompts) "stdin" else "prompt", prompts.items, summary, result, after_failure_evaluations.items, after_failure_selected_index, args.continue_on_failure, continuation);
    }
}

fn recordCodexBrokerRunRouteHealth(
    store: *health_mod.HealthStore,
    route: RepairPlanRoute,
    classification: types.HttpClassification,
) void {
    const key = repairPlanRouteHealthKey(route);
    store.recordHttpClassification(key.slice(), 429, classification);
    store.recordProbeEvidence(
        key.slice(),
        .broker_run_live,
        health_mod.retryAfterFromClassification(classification),
        health_mod.hintClassFromClassification(classification),
        health_mod.decisionFromClassification(classification),
    );
}

fn codexBrokerRunModel(allocator: std.mem.Allocator, args: cli.Command.CodexArgs) ![]const u8 {
    if (args.model) |model| return try allocator.dupe(u8, model);
    if (try getEnvOwnedOrNull(allocator, "OMUX_CODEX_BROKER_MODEL")) |model| return model;
    return try allocator.dupe(u8, "gpt-5.5");
}

fn codexBrokerRunOk(result: CodexBrokerSmokeResult, expected_turns: usize) bool {
    return result.protocol.initialized and
        result.protocol.login_response and
        result.protocol.login_completed and
        result.protocol.account_updated and
        result.protocol.thread_started and
        result.protocol.turn_started and
        result.protocol.turn_completed and
        result.protocol.turn_completed_count >= expected_turns and
        result.exit_code != null and
        result.exit_code.? == 0 and
        result.live_provider_failure == null and
        !result.protocol.experimental_api_required_error;
}

fn codexBrokerRunContinuationPromptStart(result: CodexBrokerSmokeResult, prompt_count: usize) usize {
    if (prompt_count == 0) return 0;
    const completed = @min(result.protocol.turn_completed_count, prompt_count);
    if (result.live_provider_failure != null and completed > 0) return completed - 1;
    return completed;
}

fn codexBrokerRunOverallOk(
    result: CodexBrokerSmokeResult,
    expected_turns: usize,
    continuation: ?CodexBrokerRunContinuation,
) bool {
    if (codexBrokerRunOk(result, expected_turns)) return true;
    if (continuation) |value| return codexBrokerRunOk(value.result, value.prompt_count);
    return false;
}

fn codexBrokerRunProviderFailureReason(classification: types.HttpClassification) []const u8 {
    return switch (classification) {
        .quota_exhausted => "live_quota_exhausted",
        .rate_limited => "live_rate_limited",
        .dead => "live_auth_failed",
        .degraded => "live_route_degraded",
        .provider_degraded => "live_provider_degraded",
        .failure => "live_provider_failure",
        .success => "live_turn_completed",
    };
}

fn codexBrokerRunReason(result: CodexBrokerSmokeResult, expected_turns: usize) []const u8 {
    if (codexBrokerRunOk(result, expected_turns)) {
        return if (expected_turns == 1) "live_turn_completed" else "live_session_turns_completed";
    }
    return result.reason;
}

fn codexBrokerRunOverallReason(
    result: CodexBrokerSmokeResult,
    expected_turns: usize,
    continuation: ?CodexBrokerRunContinuation,
) []const u8 {
    if (codexBrokerRunOk(result, expected_turns)) return codexBrokerRunReason(result, expected_turns);
    if (continuation) |value| {
        if (codexBrokerRunOk(value.result, value.prompt_count)) return "live_session_continued_after_route_failure";
    }
    return codexBrokerRunReason(result, expected_turns);
}

fn codexBrokerPromptsTotalChars(prompts: []const []const u8) usize {
    var total: usize = 0;
    for (prompts) |prompt| total += prompt.len;
    return total;
}

fn writeCodexBrokerRunJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    route: RepairPlanRoute,
    profile: ?[]const u8,
    capability: ?[]const u8,
    model: []const u8,
    prompt_source: []const u8,
    prompts: []const []const u8,
    summary: CodexBrokerSessionSummary,
    result: CodexBrokerSmokeResult,
    after_failure_evaluations: []const RouteEvaluation,
    after_failure_selected_index: ?usize,
    after_failure_summary: ?CodexBrokerSessionSummary,
    continue_on_failure: bool,
    continuation: ?CodexBrokerRunContinuation,
) !void {
    const session_start_ready = true;
    const prepared_fallback = codexBrokerSessionSpareFallbackReady(session_start_ready, summary.selectable_fallback_routes);
    const prompt_chars_total = codexBrokerPromptsTotalChars(prompts);
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_broker_owned_session_live_run\",\"ok\":");
    try writer.writeAll(if (codexBrokerRunOverallOk(result, prompts.len, continuation)) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":true,\"mutates_user_config\":false,\"mutates_route_health\":");
    try writer.writeAll(if (result.route_health_recorded) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(codexBrokerRunOverallReason(result, prompts.len, continuation), .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":");
    try std.json.stringify(if (continuation != null) "live_broker_owned_next_session_continuation" else if (prompts.len == 1) "live_broker_owned_session_one_turn" else "live_broker_owned_session_loop", .{}, writer);
    try writer.writeAll(",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"route_selection_source\":\"broker_session_plan\",\"session_start_ready\":true,\"live_provider_turn\":true,\"session_loop\":");
    try writer.writeAll(if (prompts.len > 1) "true" else "false");
    try writer.writeAll(",\"prepared_fallback\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"selectable_fallback_routes\":");
    try writer.print("{d}", .{summary.selectable_fallback_routes});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (codexBrokerSessionSpareFallbackReady(session_start_ready, summary.selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (codexBrokerSessionSingleRouteAtRisk(session_start_ready, summary.selectable_fallback_routes)) "true" else "false");
    try writer.writeAll(",\"next_session_continuation\":");
    try writer.writeAll(if (continuation != null) "true" else "false");
    try writer.writeAll(",\"next_thread_quota_fallback_proven\":false,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"supervised_restart\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"selected\":");
    try writeRouteSelectionJson(writer, route);
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"model\":");
    try std.json.stringify(model, .{}, writer);
    try writer.writeAll(",\"prompt_source\":");
    try std.json.stringify(prompt_source, .{}, writer);
    try writer.print(",\"prompt_count\":{d},\"prompt_chars_total\":{d}", .{ prompts.len, prompt_chars_total });
    try writer.writeAll(",\"resilience\":");
    try writeCodexBrokerSessionResilienceJson(writer, session_start_ready, summary.selectable_fallback_routes);
    try writer.writeAll(",\"resilience_actions\":");
    try writeCodexBrokerSessionRiskActionsJson(writer, allocator, profile, capability, session_start_ready, summary.selectable_fallback_routes);
    try writer.print(",\"summary\":{{\"routes_total\":{d},\"broker_ready_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d},\"auth_unready_routes\":{d}}}", .{
        summary.routes_total,
        summary.broker_ready_routes,
        summary.selectable_broker_routes,
        summary.selectable_fallback_routes,
        summary.blocked_broker_routes,
        summary.auth_unready_routes,
    });
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"provider\":\"default_codex_provider\"}");
    try writer.writeAll(",\"live\":{\"turns_requested\":");
    try writer.print("{d}", .{prompts.len});
    try writer.writeAll(",\"turns_completed\":");
    try writer.print("{d}", .{result.protocol.turn_completed_count});
    try writer.writeAll(",\"transcript_printed\":false}");
    try writer.writeAll(",\"live_failure\":");
    if (result.live_provider_failure) |classification| {
        try writeCodexBrokerRunFailureJson(writer, classification, result.live_provider_failure_source, result.route_health_recorded);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"route_health_after_failure\":");
    if (result.route_health_recorded) {
        var recorded_health: ?health_mod.AccountHealth = null;
        for (after_failure_evaluations) |evaluation| {
            if (sameRepairPlanRouteIdentity(route, evaluation.route)) {
                recorded_health = evaluation.health;
                break;
            }
        }
        try writer.writeByte('{');
        try writer.writeAll("\"recorded\":true,\"health_key\":");
        const key = repairPlanRouteHealthKey(route);
        try std.json.stringify(key.slice(), .{}, writer);
        try writer.writeAll(",\"recorded_probe\":");
        if (recorded_health) |health| try writeProbeEvidenceJson(writer, health) else try writer.writeAll("null");
        try writer.writeAll(",\"recorded_liveness\":");
        if (recorded_health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
        try writer.writeAll(",\"selected\":");
        if (after_failure_selected_index) |idx| try writeRouteSelectionJson(writer, after_failure_evaluations[idx].route) else try writer.writeAll("null");
        if (after_failure_summary) |after_summary| {
            try writer.writeAll(",\"resilience\":");
            try writeCodexBrokerSessionResilienceJson(writer, after_failure_selected_index != null, after_summary.selectable_fallback_routes);
            try writer.writeAll(",\"resilience_actions\":");
            try writeCodexBrokerSessionRiskActionsJson(writer, allocator, profile, capability, after_failure_selected_index != null, after_summary.selectable_fallback_routes);
            try writer.print(",\"summary\":{{\"routes_total\":{d},\"broker_ready_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d},\"auth_unready_routes\":{d}}}", .{
                after_summary.routes_total,
                after_summary.broker_ready_routes,
                after_summary.selectable_broker_routes,
                after_summary.selectable_fallback_routes,
                after_summary.blocked_broker_routes,
                after_summary.auth_unready_routes,
            });
        }
        try writer.writeByte('}');
    } else {
        try writer.writeAll("{\"recorded\":false}");
    }
    try writer.writeAll(",\"continuation\":");
    try writeCodexBrokerRunContinuationJson(writer, continue_on_failure, continuation);
    try writer.writeAll(",\"protocol\":");
    try writeCodexBrokerProtocolJson(writer, result);
    try writer.writeAll(",\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false,\"prompt_printed\":false,\"assistant_output_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBrokerRunContinuationJson(
    writer: anytype,
    continue_on_failure: bool,
    continuation: ?CodexBrokerRunContinuation,
) !void {
    if (continuation) |value| {
        try writer.writeByte('{');
        try writer.writeAll("\"requested\":true,\"attempted\":true,\"mode\":\"new_broker_owned_session\",\"same_thread\":false,\"same_turn\":false,\"selected\":");
        try writeRouteSelectionJson(writer, value.route);
        try writer.print(",\"prompt_start_index\":{d},\"prompt_count\":{d},\"replays_failed_prompt\":true", .{ value.prompt_start_index, value.prompt_count });
        try writer.writeAll(",\"ok\":");
        try writer.writeAll(if (codexBrokerRunOk(value.result, value.prompt_count)) "true" else "false");
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(codexBrokerRunReason(value.result, value.prompt_count), .{}, writer);
        try writer.writeAll(",\"turns_completed\":");
        try writer.print("{d}", .{value.result.protocol.turn_completed_count});
        try writer.writeAll(",\"live_failure\":");
        if (value.result.live_provider_failure) |classification| {
            try writeCodexBrokerRunFailureJson(writer, classification, value.result.live_provider_failure_source, value.result.route_health_recorded);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"protocol\":");
        try writeCodexBrokerProtocolJson(writer, value.result);
        try writer.writeByte('}');
    } else {
        try writer.writeAll("{\"requested\":");
        try writer.writeAll(if (continue_on_failure) "true" else "false");
        try writer.writeAll(",\"attempted\":false}");
    }
}

fn writeCodexBrokerRunFailureJson(
    writer: anytype,
    classification: types.HttpClassification,
    source: ?[]const u8,
    route_health_recorded: bool,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"source\":");
    if (source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"route_health_recorded\":");
    try writer.writeAll(if (route_health_recorded) "true" else "false");
    try writer.writeAll(",\"classification\":");
    try std.json.stringify(codexBrokerRunProviderFailureReason(classification), .{}, writer);
    try writer.writeAll(",\"retry_after_s\":");
    if (health_mod.retryAfterFromClassification(classification)) |retry_after| try writer.print("{d}", .{retry_after}) else try writer.writeAll("null");
    try writer.writeAll(",\"decision\":");
    try std.json.stringify(@tagName(health_mod.decisionFromClassification(classification)), .{}, writer);
    try writer.writeByte('}');
}

fn writeCodexBrokerRunText(
    writer: anytype,
    route: RepairPlanRoute,
    capability: ?[]const u8,
    model: []const u8,
    prompt_source: []const u8,
    prompts: []const []const u8,
    summary: CodexBrokerSessionSummary,
    result: CodexBrokerSmokeResult,
    after_failure_evaluations: []const RouteEvaluation,
    after_failure_selected_index: ?usize,
    continue_on_failure: bool,
    continuation: ?CodexBrokerRunContinuation,
) !void {
    const prompt_chars_total = codexBrokerPromptsTotalChars(prompts);
    try writer.writeAll("oauth-mux Codex broker-owned live run\n\n");
    try writer.print("  route: {s}:{s}", .{ route.provider, route.account });
    if (capability) |value| try writer.print("#{s}", .{value});
    try writer.writeByte('\n');
    try writer.print("  model: {s}\n", .{model});
    try writer.print("  prompt source: {s}\n", .{prompt_source});
    try writer.print("  prompt count: {d}\n", .{prompts.len});
    try writer.print("  prompt chars total: {d}\n", .{prompt_chars_total});
    try writer.print("  prepared fallback: {s}\n", .{if (codexBrokerSessionSpareFallbackReady(true, summary.selectable_fallback_routes)) "true" else "false"});
    try writer.print("  spare fallback ready: {s}\n", .{if (codexBrokerSessionSpareFallbackReady(true, summary.selectable_fallback_routes)) "true" else "false"});
    try writer.print("  single route at risk: {s}\n", .{if (codexBrokerSessionSingleRouteAtRisk(true, summary.selectable_fallback_routes)) "true" else "false"});
    if (codexBrokerSessionSingleRouteAtRisk(true, summary.selectable_fallback_routes)) {
        try writer.writeAll("  next: revalidate exhausted routes, wait for reset, or enroll another Codex account\n");
    }
    try writer.print("  continue on failure: {s}\n", .{if (continue_on_failure) "true" else "false"});
    try writer.print("  ok: {s}\n", .{if (codexBrokerRunOverallOk(result, prompts.len, continuation)) "true" else "false"});
    try writer.print("  reason: {s}\n", .{codexBrokerRunOverallReason(result, prompts.len, continuation)});
    if (result.live_provider_failure) |classification| {
        try writer.print("  live failure: {s}", .{codexBrokerRunProviderFailureReason(classification)});
        if (health_mod.retryAfterFromClassification(classification)) |retry_after| try writer.print(" retry_after_s={d}", .{retry_after});
        try writer.print(" route_health_recorded={s}\n", .{if (result.route_health_recorded) "true" else "false"});
        try writer.writeAll("  selected after failure: ");
        if (after_failure_selected_index) |idx| {
            const next_route = after_failure_evaluations[idx].route;
            try writer.print("{s}:{s}", .{ next_route.provider, next_route.account });
            if (next_route.capability) |value| try writer.print("#{s}", .{value});
            try writer.writeByte('\n');
        } else {
            try writer.writeAll("none\n");
        }
    }
    if (continuation) |value| {
        try writer.writeAll("  continuation: new broker-owned session ");
        try writer.print("{s}:{s}", .{ value.route.provider, value.route.account });
        if (value.route.capability) |cap| try writer.print("#{s}", .{cap});
        try writer.print(" prompt_start_index={d} prompt_count={d} ok={s} reason={s}\n", .{
            value.prompt_start_index,
            value.prompt_count,
            if (codexBrokerRunOk(value.result, value.prompt_count)) "true" else "false",
            codexBrokerRunReason(value.result, value.prompt_count),
        });
    }
    try writer.print("  turn_completed: {s}\n", .{if (result.protocol.turn_completed) "true" else "false"});
    try writer.writeAll("  redaction: tokens/account ids/raw protocol/prompt/assistant output not printed\n");
}

fn runCodexBrokerSmoke(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
    mode: CodexBrokerSmokeMode,
) !void {
    if (!args.confirm_broker) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"confirmation_required\":true,\"requires\":\"--confirm-broker\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":");
            try std.json.stringify(mode.jsonMode(), .{}, writer);
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            const command = try std.fmt.allocPrint(allocator, "oauth-mux codex {s} --profile <profile> --capability <capability> --confirm-broker --json", .{mode.commandName()});
            defer allocator.free(command);
            try writeCommandJson(writer, command);
            try writer.writeAll("]}\n");
        } else {
            try writer.print("{s}\n\n", .{mode.title()});
            try writer.writeAll("  confirmation required: --confirm-broker\n");
            try writer.writeAll("  this starts a broker-owned Codex app-server child and sends the selected route's ChatGPT auth token to that child only\n");
        }
        return;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var selected: ?CodexBrokerRouteCredentials = null;
    defer if (selected) |*value| value.deinit(allocator);
    var refresh_selected: ?CodexBrokerRouteCredentials = null;
    defer if (refresh_selected) |*value| value.deinit(allocator);
    for (routes.items) |route| {
        const plan = try inspectCodexBrokerRoute(allocator, parsed.value, route);
        if (!plan.can_supply) continue;
        const credentials = loadCodexBrokerCredentialsForRoute(allocator, parsed.value, route) catch continue;
        if (selected == null) {
            selected = .{
                .route = route,
                .credentials = credentials,
            };
            continue;
        }
        if (mode == .refresh and refresh_selected == null and !sameRepairPlanRouteIdentity(selected.?.route, route)) {
            refresh_selected = .{
                .route = route,
                .credentials = credentials,
            };
            break;
        }
        credentials.deinit(allocator);
    }

    if (selected == null) {
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":");
            try std.json.stringify(mode.jsonMode(), .{}, writer);
            try writer.writeAll(",\"ok\":false,\"confirmed\":true,\"reason\":\"no_broker_ready_route\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"routes_total\":");
            try writer.print("{d}", .{routes.items.len});
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.print("{s}\n\n", .{mode.title()});
            try writer.writeAll("  no broker-ready Codex route found\n");
            try writer.writeAll("  next: oauth-mux codex broker-plan --profile <profile> --capability <capability> --json\n");
        }
        return;
    }

    if (mode == .refresh and refresh_selected == null) {
        refresh_selected = .{
            .route = selected.?.route,
            .credentials = try cloneCodexBrokerCredentials(allocator, selected.?.credentials),
        };
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const run_dir = try std.fmt.allocPrint(allocator, "{s}/codex-{s}-{d}", .{ state_dir, mode.commandName(), std.time.milliTimestamp() });
    defer allocator.free(run_dir);
    try std.fs.cwd().makePath(run_dir);

    const refresh_route = if (refresh_selected) |value| value.route else null;
    const refresh_credentials = if (refresh_selected) |value| value.credentials else selected.?.credentials;
    const result = try runCodexAppServerBrokerSmoke(allocator, selected.?.credentials, refresh_credentials, run_dir, mode);

    if (args.json) {
        try writeCodexBrokerSmokeJson(writer, selected.?.route, refresh_route, capability, result, mode);
    } else {
        try writeCodexBrokerSmokeText(writer, selected.?.route, refresh_route, capability, result, mode);
    }
}

fn runCodexBroker401Smoke(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!args.confirm_broker) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"confirmation_required\":true,\"requires\":\"--confirm-broker\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_app_server_401_broker_smoke\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux codex broker-401-smoke --profile <profile> --capability <capability> --confirm-broker --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex app-server 401 broker smoke\n\n");
            try writer.writeAll("  confirmation required: --confirm-broker\n");
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local no-spend Responses mock and verifies 401 retry fallback\n");
        }
        return;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var selected: ?CodexBrokerRouteCredentials = null;
    defer if (selected) |*value| value.deinit(allocator);
    var refresh_selected: ?CodexBrokerRouteCredentials = null;
    defer if (refresh_selected) |*value| value.deinit(allocator);
    for (routes.items) |route| {
        const plan = try inspectCodexBrokerRoute(allocator, parsed.value, route);
        if (!plan.can_supply) continue;
        const credentials = loadCodexBrokerCredentialsForRoute(allocator, parsed.value, route) catch continue;
        if (selected == null) {
            selected = .{
                .route = route,
                .credentials = credentials,
            };
            continue;
        }
        if (!sameRepairPlanRouteIdentity(selected.?.route, route)) {
            refresh_selected = .{
                .route = route,
                .credentials = credentials,
            };
            break;
        }
        credentials.deinit(allocator);
    }

    if (selected == null or refresh_selected == null) {
        const reason = if (selected == null) "no_broker_ready_route" else "no_distinct_fallback_broker_ready_route";
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":\"codex_app_server_401_broker_smoke\",\"ok\":false,\"confirmed\":true,\"reason\":");
            try std.json.stringify(reason, .{}, writer);
            try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"routes_total\":");
            try writer.print("{d}", .{routes.items.len});
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex app-server 401 broker smoke\n\n");
            try writer.print("  {s}\n", .{reason});
            try writer.writeAll("  next: oauth-mux codex broker-plan --profile <profile> --capability <capability> --json\n");
        }
        return;
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const run_dir = try std.fmt.allocPrint(allocator, "{s}/codex-broker-401-smoke-{d}", .{ state_dir, std.time.milliTimestamp() });
    defer allocator.free(run_dir);
    try std.fs.cwd().makePath(run_dir);

    var mock_server = try startCodexBroker401MockServer(allocator, selected.?.credentials.access_token, refresh_selected.?.credentials.access_token);
    defer mock_server.destroy();

    const mock_origin = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{mock_server.port});
    defer allocator.free(mock_origin);
    const base_url = try std.fmt.allocPrint(allocator, "{s}/v1", .{mock_origin});
    defer allocator.free(base_url);
    const chatgpt_base_url = try std.fmt.allocPrint(allocator, "{s}/backend-api", .{mock_origin});
    defer allocator.free(chatgpt_base_url);
    try writeCodexBroker401AppServerFiles(allocator, run_dir, base_url, chatgpt_base_url);

    var result = CodexBroker401SmokeResult{
        .broker = try runCodexAppServer401BrokerSmoke(
            allocator,
            selected.?.credentials,
            refresh_selected.?.credentials,
            run_dir,
        ),
    };
    result.http = mock_server.finish();

    if (args.json) {
        try writeCodexBroker401SmokeJson(writer, selected.?.route, refresh_selected.?.route, capability, result);
    } else {
        try writeCodexBroker401SmokeText(writer, selected.?.route, refresh_selected.?.route, capability, result);
    }
}

fn codexBroker401SmokeOk(result: CodexBroker401SmokeResult) bool {
    return result.broker.protocol.initialized and
        result.broker.protocol.login_response and
        result.broker.protocol.login_completed and
        result.broker.protocol.account_updated and
        result.broker.protocol.thread_started and
        result.broker.protocol.turn_started and
        result.broker.protocol.refresh_request_seen and
        result.broker.protocol.refresh_reason_unauthorized and
        result.broker.refresh_response_sent and
        result.broker.protocol.turn_completed and
        result.http.retried_with_fallback and
        result.broker.exit_code != null and
        result.broker.exit_code.? == 0 and
        !result.broker.protocol.experimental_api_required_error;
}

fn codexBroker401SmokeReason(result: CodexBroker401SmokeResult) []const u8 {
    if (codexBroker401SmokeOk(result)) return "protocol_401_retry_completed";
    if (result.http.server_error) |value| return value;
    if (!result.http.turn_request_seen) return "turn_request_not_seen";
    if (!result.http.initial_authorization_seen) return "initial_authorization_not_seen";
    if (!result.http.fallback_authorization_seen) return "fallback_authorization_not_seen";
    if (!result.http.retried_with_fallback) return "retry_did_not_use_fallback";
    return result.broker.reason;
}

fn writeCodexBroker401SmokeJson(
    writer: anytype,
    route: RepairPlanRoute,
    refresh_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBroker401SmokeResult,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_app_server_401_broker_smoke\",\"ok\":");
    try writer.writeAll(if (codexBroker401SmokeOk(result)) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":false,\"mutates_user_config\":false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(codexBroker401SmokeReason(result), .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":\"local_401_retry_smoke\",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"broker_owned_same_process_auth_refresh\":true,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"selected\":");
    try writeRouteSelectionJson(writer, route);
    try writer.writeAll(",\"refresh_selected\":");
    try writeRouteSelectionJson(writer, refresh_route);
    try writer.writeAll(",\"refresh_route_is_fallback\":");
    try writer.writeAll(if (!sameRepairPlanRouteIdentity(route, refresh_route)) "true" else "false");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"refresh_method\":\"account/chatgptAuthTokens/refresh\",\"mock_provider\":\"local_responses_401_then_sse\"}");
    try writer.writeAll(",\"protocol\":");
    try writeCodexBrokerProtocolJson(writer, result.broker);
    try writer.writeAll(",\"http_mock\":");
    try writeCodexBroker401HttpJson(writer, result.http);
    try writer.writeAll(",\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBroker401HttpJson(writer: anytype, http: CodexBroker401HttpObservation) !void {
    try writer.writeByte('{');
    try writer.print("\"request_count\":{d}", .{http.request_count});
    try writer.print(",\"responses_request_count\":{d}", .{http.responses_request_count});
    try writer.print(",\"pre_turn_responses_count\":{d}", .{http.pre_turn_responses_count});
    try writer.writeAll(",\"turn_request_seen\":");
    try writer.writeAll(if (http.turn_request_seen) "true" else "false");
    try writer.writeAll(",\"models_request_seen\":");
    try writer.writeAll(if (http.models_request_seen) "true" else "false");
    try writer.writeAll(",\"backend_request_seen\":");
    try writer.writeAll(if (http.backend_request_seen) "true" else "false");
    try writer.writeAll(",\"unauthorized_response_sent\":");
    try writer.writeAll(if (http.unauthorized_response_sent) "true" else "false");
    try writer.writeAll(",\"sse_response_sent\":");
    try writer.writeAll(if (http.sse_response_sent) "true" else "false");
    try writer.writeAll(",\"initial_authorization_seen\":");
    try writer.writeAll(if (http.initial_authorization_seen) "true" else "false");
    try writer.writeAll(",\"fallback_authorization_seen\":");
    try writer.writeAll(if (http.fallback_authorization_seen) "true" else "false");
    try writer.writeAll(",\"retried_with_fallback\":");
    try writer.writeAll(if (http.retried_with_fallback) "true" else "false");
    try writer.writeAll(",\"server_error\":");
    if (http.server_error) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeByte('}');
}

fn writeCodexBroker401SmokeText(
    writer: anytype,
    route: RepairPlanRoute,
    refresh_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBroker401SmokeResult,
) !void {
    try writer.writeAll("oauth-mux Codex app-server 401 broker smoke\n\n");
    try writer.print("  route: {s}:{s}", .{ route.provider, route.account });
    if (capability) |value| try writer.print("#{s}", .{value});
    try writer.writeByte('\n');
    try writer.print("  refresh route: {s}:{s}", .{ refresh_route.provider, refresh_route.account });
    if (refresh_route.capability) |route_capability| try writer.print("#{s}", .{route_capability});
    try writer.print(" fallback={s}\n", .{if (sameRepairPlanRouteIdentity(route, refresh_route)) "false" else "true"});
    try writer.print("  ok: {s}\n", .{if (codexBroker401SmokeOk(result)) "true" else "false"});
    try writer.print("  reason: {s}\n", .{codexBroker401SmokeReason(result)});
    try writer.print("  refresh_request_seen: {s}\n", .{if (result.broker.protocol.refresh_request_seen) "true" else "false"});
    try writer.print("  refresh_response_sent: {s}\n", .{if (result.broker.refresh_response_sent) "true" else "false"});
    try writer.print("  turn_completed: {s}\n", .{if (result.broker.protocol.turn_completed) "true" else "false"});
    try writer.print("  retried_with_fallback: {s}\n", .{if (result.http.retried_with_fallback) "true" else "false"});
    try writer.writeAll("  redaction: tokens/account ids/raw protocol not printed\n");
}

fn runCodexBrokerQuotaSmoke(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
) !void {
    if (!args.confirm_broker) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"confirmation_required\":true,\"requires\":\"--confirm-broker\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mode\":\"codex_app_server_quota_broker_smoke\",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeByte(',');
            try writeCommandJson(writer, "oauth-mux codex broker-quota-smoke --profile <profile> --capability <capability> --confirm-broker --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex app-server quota broker smoke\n\n");
            try writer.writeAll("  confirmation required: --confirm-broker\n");
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local no-spend Responses mock and verifies next-turn quota fallback\n");
        }
        return;
    }

    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());

    const capability = firstCommaValue(args.capabilities);
    var routes = try collectRepairPlanRoutes(allocator, parsed.value, .{
        .profile = args.profile,
        .provider = if (args.profile == null) "codex" else null,
        .account = args.account,
        .capability = capability,
        .json = args.json,
    });
    defer routes.deinit();

    var selected: ?CodexBrokerRouteCredentials = null;
    defer if (selected) |*value| value.deinit(allocator);
    var fallback_selected: ?CodexBrokerRouteCredentials = null;
    defer if (fallback_selected) |*value| value.deinit(allocator);
    for (routes.items) |route| {
        const plan = try inspectCodexBrokerRoute(allocator, parsed.value, route);
        if (!plan.can_supply) continue;
        const credentials = loadCodexBrokerCredentialsForRoute(allocator, parsed.value, route) catch continue;
        if (selected == null) {
            selected = .{
                .route = route,
                .credentials = credentials,
            };
            continue;
        }
        if (!sameRepairPlanRouteIdentity(selected.?.route, route)) {
            fallback_selected = .{
                .route = route,
                .credentials = credentials,
            };
            break;
        }
        credentials.deinit(allocator);
    }

    if (selected == null or fallback_selected == null) {
        const reason = if (selected == null) "no_broker_ready_route" else "no_distinct_fallback_broker_ready_route";
        if (args.json) {
            try writer.writeAll("{\"version\":");
            try std.json.stringify(cli.version, .{}, writer);
            try writer.writeAll(",\"mode\":\"codex_app_server_quota_broker_smoke\",\"ok\":false,\"confirmed\":true,\"reason\":");
            try std.json.stringify(reason, .{}, writer);
            try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"routes_total\":");
            try writer.print("{d}", .{routes.items.len});
            try writer.writeAll(",\"next_commands\":[");
            try writeCommandJson(writer, "oauth-mux codex broker-plan --profile <profile> --capability <capability> --json");
            try writer.writeAll("]}\n");
        } else {
            try writer.writeAll("oauth-mux Codex app-server quota broker smoke\n\n");
            try writer.print("  {s}\n", .{reason});
        }
        return;
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const run_dir = try std.fmt.allocPrint(allocator, "{s}/codex-broker-quota-smoke-{d}", .{ state_dir, std.time.milliTimestamp() });
    defer allocator.free(run_dir);
    try std.fs.cwd().makePath(run_dir);

    var mock_server = try startCodexBrokerQuotaMockServer(allocator, selected.?.credentials.access_token, fallback_selected.?.credentials.access_token);
    defer mock_server.destroy();

    const mock_origin = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{mock_server.port});
    defer allocator.free(mock_origin);
    const base_url = try std.fmt.allocPrint(allocator, "{s}/v1", .{mock_origin});
    defer allocator.free(base_url);
    const chatgpt_base_url = try std.fmt.allocPrint(allocator, "{s}/backend-api", .{mock_origin});
    defer allocator.free(chatgpt_base_url);
    try writeCodexBroker401AppServerFiles(allocator, run_dir, base_url, chatgpt_base_url);

    var result = CodexBrokerQuotaSmokeResult{
        .broker = try runCodexAppServerQuotaBrokerSmoke(
            allocator,
            selected.?.credentials,
            fallback_selected.?.credentials,
            run_dir,
        ),
    };
    result.http = mock_server.finish();

    if (args.json) {
        try writeCodexBrokerQuotaSmokeJson(writer, selected.?.route, fallback_selected.?.route, capability, result);
    } else {
        try writeCodexBrokerQuotaSmokeText(writer, selected.?.route, fallback_selected.?.route, capability, result);
    }
}

fn codexBrokerQuotaSmokeOk(result: CodexBrokerQuotaSmokeResult) bool {
    return result.broker.protocol.initialized and
        result.broker.protocol.login_response and
        result.broker.protocol.login_completed_count >= 2 and
        result.broker.protocol.account_updates >= 2 and
        result.broker.protocol.thread_started and
        result.broker.protocol.turn_completed_count >= 2 and
        result.http.quota_response_sent and
        result.http.next_turn_used_fallback and
        result.broker.exit_code != null and
        result.broker.exit_code.? == 0 and
        !result.broker.protocol.experimental_api_required_error;
}

fn codexBrokerQuotaSmokeReason(result: CodexBrokerQuotaSmokeResult) []const u8 {
    if (codexBrokerQuotaSmokeOk(result)) return "next_thread_quota_fallback_completed";
    if (result.http.server_error) |value| return value;
    if (!result.http.first_turn_request_seen) return "first_turn_request_not_seen";
    if (!result.http.quota_response_sent) return "quota_response_not_sent";
    if (result.broker.protocol.login_completed_count < 2) return "fallback_login_not_completed";
    if (!result.http.second_turn_request_seen) return "second_turn_request_not_seen";
    if (!result.http.fallback_authorization_seen) return "fallback_authorization_not_seen";
    if (!result.http.next_turn_used_fallback) return "next_turn_did_not_use_fallback";
    return result.broker.reason;
}

fn writeCodexBrokerQuotaSmokeJson(
    writer: anytype,
    route: RepairPlanRoute,
    fallback_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerQuotaSmokeResult,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"codex_app_server_quota_broker_smoke\",\"ok\":");
    try writer.writeAll(if (codexBrokerQuotaSmokeOk(result)) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(codexBrokerQuotaSmokeReason(result), .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":\"local_quota_next_thread_smoke\",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"next_thread_quota_fallback_proven\":true,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"selected\":");
    try writeRouteSelectionJson(writer, route);
    try writer.writeAll(",\"fallback_selected\":");
    try writeRouteSelectionJson(writer, fallback_route);
    try writer.writeAll(",\"fallback_route_is_distinct\":");
    try writer.writeAll(if (!sameRepairPlanRouteIdentity(route, fallback_route)) "true" else "false");
    try writer.writeAll(",\"simulated_route_state\":{\"first_turn_classification\":\"quota_exhausted\",\"decision\":\"try_next_account\",\"retry_after_s\":7200}");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"mock_provider\":\"local_responses_429_then_new_thread_fallback_sse\"}");
    try writer.writeAll(",\"protocol\":");
    try writeCodexBrokerProtocolJson(writer, result.broker);
    try writer.writeAll(",\"http_mock\":");
    try writeCodexBrokerQuotaHttpJson(writer, result.http);
    try writer.writeAll(",\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBrokerQuotaHttpJson(writer: anytype, http: CodexBrokerQuotaHttpObservation) !void {
    try writer.writeByte('{');
    try writer.print("\"request_count\":{d}", .{http.request_count});
    try writer.print(",\"responses_request_count\":{d}", .{http.responses_request_count});
    try writer.print(",\"pre_turn_responses_count\":{d}", .{http.pre_turn_responses_count});
    try writer.writeAll(",\"first_turn_request_seen\":");
    try writer.writeAll(if (http.first_turn_request_seen) "true" else "false");
    try writer.writeAll(",\"second_turn_request_seen\":");
    try writer.writeAll(if (http.second_turn_request_seen) "true" else "false");
    try writer.writeAll(",\"backend_request_seen\":");
    try writer.writeAll(if (http.backend_request_seen) "true" else "false");
    try writer.writeAll(",\"quota_response_sent\":");
    try writer.writeAll(if (http.quota_response_sent) "true" else "false");
    try writer.writeAll(",\"second_turn_sse_response_sent\":");
    try writer.writeAll(if (http.second_turn_sse_response_sent) "true" else "false");
    try writer.writeAll(",\"initial_authorization_seen\":");
    try writer.writeAll(if (http.initial_authorization_seen) "true" else "false");
    try writer.writeAll(",\"fallback_authorization_seen\":");
    try writer.writeAll(if (http.fallback_authorization_seen) "true" else "false");
    try writer.writeAll(",\"next_turn_used_fallback\":");
    try writer.writeAll(if (http.next_turn_used_fallback) "true" else "false");
    try writer.writeAll(",\"server_error\":");
    if (http.server_error) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeByte('}');
}

fn writeCodexBrokerQuotaSmokeText(
    writer: anytype,
    route: RepairPlanRoute,
    fallback_route: RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerQuotaSmokeResult,
) !void {
    try writer.writeAll("oauth-mux Codex app-server quota broker smoke\n\n");
    try writer.print("  route: {s}:{s}", .{ route.provider, route.account });
    if (capability) |value| try writer.print("#{s}", .{value});
    try writer.writeByte('\n');
    try writer.print("  fallback route: {s}:{s}", .{ fallback_route.provider, fallback_route.account });
    if (fallback_route.capability) |route_capability| try writer.print("#{s}", .{route_capability});
    try writer.print(" distinct={s}\n", .{if (sameRepairPlanRouteIdentity(route, fallback_route)) "false" else "true"});
    try writer.print("  ok: {s}\n", .{if (codexBrokerQuotaSmokeOk(result)) "true" else "false"});
    try writer.print("  reason: {s}\n", .{codexBrokerQuotaSmokeReason(result)});
    try writer.print("  quota_response_sent: {s}\n", .{if (result.http.quota_response_sent) "true" else "false"});
    try writer.print("  next_turn_used_fallback: {s}\n", .{if (result.http.next_turn_used_fallback) "true" else "false"});
    try writer.print("  same_turn_refresh_request_seen: {s}\n", .{if (result.broker.protocol.refresh_request_seen) "true" else "false"});
    try writer.writeAll("  redaction: tokens/account ids/raw protocol not printed\n");
}

fn writeCodexBrokerSmokeJson(
    writer: anytype,
    route: RepairPlanRoute,
    refresh_route: ?RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerSmokeResult,
    mode: CodexBrokerSmokeMode,
) !void {
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":");
    try std.json.stringify(mode.jsonMode(), .{}, writer);
    try writer.writeAll(",\"ok\":");
    try writer.writeAll(if (result.ok) "true" else "false");
    try writer.writeAll(",\"confirmed\":true,\"spends_provider_calls\":false,\"mutates_user_config\":false");
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":");
    try std.json.stringify(mode.proofStatus(), .{}, writer);
    try writer.writeAll(",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"selected\":");
    try writeRouteSelectionJson(writer, route);
    try writer.writeAll(",\"refresh_selected\":");
    if (refresh_route) |value| try writeRouteSelectionJson(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"refresh_route_is_fallback\":");
    try writer.writeAll(if (refresh_route != null and !sameRepairPlanRouteIdentity(route, refresh_route.?)) "true" else "false");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"app_server\":{\"transport\":\"stdio\",\"requires_experimental_api\":true,\"login_method\":\"account/login/start.chatgptAuthTokens\",\"refresh_method\":\"account/chatgptAuthTokens/refresh\"}");
    try writer.writeAll(",\"protocol\":");
    try writeCodexBrokerProtocolJson(writer, result);
    try writer.writeAll(",\"redaction\":{\"tokens_printed\":false,\"account_id_printed\":false,\"raw_protocol_printed\":false}");
    try writer.writeAll("}\n");
}

fn writeCodexBrokerProtocolJson(writer: anytype, result: CodexBrokerSmokeResult) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"reason\":");
    try std.json.stringify(result.reason, .{}, writer);
    try writer.writeAll(",\"spawned\":");
    try writer.writeAll(if (result.spawned) "true" else "false");
    try writer.writeAll(",\"stdin_closed\":");
    try writer.writeAll(if (result.stdin_closed) "true" else "false");
    try writer.writeAll(",\"exited\":");
    try writer.writeAll(if (result.exited) "true" else "false");
    try writer.writeAll(",\"exit_code\":");
    if (result.exit_code) |code| try writer.print("{d}", .{code}) else try writer.writeAll("null");
    try writer.writeAll(",\"initialized\":");
    try writer.writeAll(if (result.protocol.initialized) "true" else "false");
    try writer.writeAll(",\"login_response\":");
    try writer.writeAll(if (result.protocol.login_response) "true" else "false");
    try writer.writeAll(",\"login_completed\":");
    try writer.writeAll(if (result.protocol.login_completed) "true" else "false");
    try writer.print(",\"login_completed_count\":{d}", .{result.protocol.login_completed_count});
    try writer.writeAll(",\"account_updated\":");
    try writer.writeAll(if (result.protocol.account_updated) "true" else "false");
    try writer.print(",\"account_updates\":{d}", .{result.protocol.account_updates});
    try writer.writeAll(",\"thread_started\":");
    try writer.writeAll(if (result.protocol.thread_started) "true" else "false");
    try writer.writeAll(",\"turn_started\":");
    try writer.writeAll(if (result.protocol.turn_started) "true" else "false");
    try writer.writeAll(",\"turn_completed\":");
    try writer.writeAll(if (result.protocol.turn_completed) "true" else "false");
    try writer.print(",\"turn_completed_count\":{d}", .{result.protocol.turn_completed_count});
    try writer.writeAll(",\"refresh_request_seen\":");
    try writer.writeAll(if (result.protocol.refresh_request_seen) "true" else "false");
    try writer.writeAll(",\"refresh_reason_unauthorized\":");
    try writer.writeAll(if (result.protocol.refresh_reason_unauthorized) "true" else "false");
    try writer.writeAll(",\"refresh_response_sent\":");
    try writer.writeAll(if (result.refresh_response_sent) "true" else "false");
    try writer.writeAll(",\"experimental_api_required_error\":");
    try writer.writeAll(if (result.protocol.experimental_api_required_error) "true" else "false");
    try writer.print(",\"stdout_bytes\":{d},\"stderr_bytes\":{d}", .{ result.stdout_bytes, result.stderr_bytes });
    try writer.writeByte('}');
}

fn writeCodexBrokerSmokeText(
    writer: anytype,
    route: RepairPlanRoute,
    refresh_route: ?RepairPlanRoute,
    capability: ?[]const u8,
    result: CodexBrokerSmokeResult,
    mode: CodexBrokerSmokeMode,
) !void {
    try writer.print("{s}\n\n", .{mode.title()});
    try writer.print("  route: {s}:{s}", .{ route.provider, route.account });
    if (capability) |value| try writer.print("#{s}", .{value});
    try writer.writeByte('\n');
    if (refresh_route) |value| {
        try writer.print("  refresh route: {s}:{s}", .{ value.provider, value.account });
        if (value.capability) |route_capability| try writer.print("#{s}", .{route_capability});
        try writer.print(" fallback={s}\n", .{if (sameRepairPlanRouteIdentity(route, value)) "false" else "true"});
    }
    try writer.print("  ok: {s}\n", .{if (result.ok) "true" else "false"});
    try writer.print("  reason: {s}\n", .{result.reason});
    try writer.print("  initialized: {s}\n", .{if (result.protocol.initialized) "true" else "false"});
    try writer.print("  login_response: {s}\n", .{if (result.protocol.login_response) "true" else "false"});
    try writer.print("  login_completed: {s}\n", .{if (result.protocol.login_completed) "true" else "false"});
    try writer.print("  account_updated: {s}\n", .{if (result.protocol.account_updated) "true" else "false"});
    if (mode == .refresh) {
        try writer.print("  refresh_request_seen: {s}\n", .{if (result.protocol.refresh_request_seen) "true" else "false"});
        try writer.print("  refresh_reason_unauthorized: {s}\n", .{if (result.protocol.refresh_reason_unauthorized) "true" else "false"});
        try writer.print("  refresh_response_sent: {s}\n", .{if (result.refresh_response_sent) "true" else "false"});
    }
    try writer.writeAll("  redaction: tokens/account ids/raw protocol not printed\n");
}

fn runCodexAppServerBrokerSmoke(
    allocator: std.mem.Allocator,
    login_credentials: CodexBrokerCredentials,
    refresh_credentials: CodexBrokerCredentials,
    codex_home: []const u8,
    mode: CodexBrokerSmokeMode,
) !CodexBrokerSmokeResult {
    const app_server_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_APP_SERVER") catch try allocator.dupe(u8, "codex");
    defer allocator.free(app_server_bin);

    var initialize_request = std.ArrayList(u8).init(allocator);
    defer initialize_request.deinit();
    try writeCodexAppServerInitializeRequest(initialize_request.writer());
    try initialize_request.append('\n');

    var login_request = std.ArrayList(u8).init(allocator);
    defer login_request.deinit();
    try writeCodexAppServerLoginRequest(login_request.writer(), login_credentials);
    try login_request.append('\n');

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home);

    const argv = [_][]const u8{ app_server_bin, "app-server", "--listen", "stdio://" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = &env_map;

    child.spawn() catch |e| {
        return .{ .ok = false, .reason = @errorName(e), .spawned = false };
    };

    var result = CodexBrokerSmokeResult{ .spawned = true };
    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);

    if (child.stdin) |stdin_file| {
        try stdin_file.writeAll(initialize_request.items);
    }

    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    var term: ?std.process.Child.Term = null;
    var login_sent = false;
    const max_output_bytes: usize = 1024 * 1024;
    const deadline_ns = std.time.nanoTimestamp() + (10 * std.time.ns_per_s);
    while (true) {
        if (poller.fifo(.stdout).readableLength() > max_output_bytes or
            poller.fifo(.stderr).readableLength() > max_output_bytes)
        {
            term = child.kill() catch null;
            result.reason = "output_too_large";
            break;
        }

        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) {
            try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
            try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));
            term = child.kill() catch null;
            result.reason = "timeout";
            break;
        }

        const remaining_ns = deadline_ns - now;
        const poll_ns_i = @min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms));
        const keep_polling = poller.pollTimeout(@intCast(poll_ns_i)) catch |e| {
            term = child.kill() catch null;
            result.reason = @errorName(e);
            break;
        };
        try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
        try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));

        const observation = inspectCodexBrokerProtocolOutput(stdout_buf.items);
        if (!login_sent and observation.initialized) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(login_request.items);
                login_sent = true;
            }
        }

        if (mode == .refresh and !result.refresh_response_sent) {
            var refresh_request = try findCodexBrokerRefreshRequest(allocator, stdout_buf.items);
            defer if (refresh_request) |*request| {
                request.deinit(allocator);
            };
            if (refresh_request) |request| {
                if (!request.reason_unauthorized) {
                    result.reason = "unsupported_refresh_reason";
                } else if (child.stdin) |stdin_file| {
                    try writeCodexAppServerRefreshResponse(stdin_file.writer(), request.id, refresh_credentials);
                    try stdin_file.writeAll("\n");
                    result.refresh_response_sent = true;
                    stdin_file.close();
                    child.stdin = null;
                    result.stdin_closed = true;
                }
            }
        }

        if (mode == .login and observation.login_completed and observation.account_updated and !result.stdin_closed) {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
                result.stdin_closed = true;
            }
        }

        if (!keep_polling) break;
    }

    if (!result.stdin_closed) {
        if (child.stdin) |stdin_file| {
            stdin_file.close();
            child.stdin = null;
            result.stdin_closed = true;
        }
    }

    if (term == null) {
        term = child.wait() catch |e| {
            result.reason = @errorName(e);
            return result;
        };
    }

    result.exited = true;
    result.exit_code = switch (term.?) {
        .Exited => |code| code,
        else => null,
    };
    result.stdout_bytes = stdout_buf.items.len;
    result.stderr_bytes = stderr_buf.items.len;
    result.protocol = inspectCodexBrokerProtocolOutput(stdout_buf.items);
    const child_exit_ok = result.exit_code != null and result.exit_code.? == 0;
    result.ok = switch (mode) {
        .login => result.protocol.initialized and
            result.protocol.login_response and
            result.protocol.login_completed and
            result.protocol.account_updated and
            child_exit_ok and
            !result.protocol.experimental_api_required_error,
        .refresh => result.protocol.initialized and
            result.protocol.login_response and
            result.protocol.login_completed and
            result.protocol.account_updated and
            result.protocol.refresh_request_seen and
            result.protocol.refresh_reason_unauthorized and
            result.refresh_response_sent and
            child_exit_ok and
            !result.protocol.experimental_api_required_error,
    };
    if (result.ok) {
        result.reason = switch (mode) {
            .login => "protocol_login_completed",
            .refresh => "protocol_refresh_response_sent",
        };
    } else if (std.mem.eql(u8, result.reason, "unknown")) {
        result.reason = "protocol_incomplete";
    }
    return result;
}

fn runCodexAppServer401BrokerSmoke(
    allocator: std.mem.Allocator,
    login_credentials: CodexBrokerCredentials,
    refresh_credentials: CodexBrokerCredentials,
    codex_home: []const u8,
) !CodexBrokerSmokeResult {
    const app_server_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_APP_SERVER") catch try allocator.dupe(u8, "codex");
    defer allocator.free(app_server_bin);

    var initialize_request = std.ArrayList(u8).init(allocator);
    defer initialize_request.deinit();
    try writeCodexAppServerInitializeRequest(initialize_request.writer());
    try initialize_request.append('\n');

    var login_request = std.ArrayList(u8).init(allocator);
    defer login_request.deinit();
    try writeCodexAppServerLoginRequest(login_request.writer(), login_credentials);
    try login_request.append('\n');

    var thread_request = std.ArrayList(u8).init(allocator);
    defer thread_request.deinit();
    try writeCodexAppServerThreadStartRequest(thread_request.writer());
    try thread_request.append('\n');

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home);
    env_map.remove("OPENAI_API_KEY");

    const argv = [_][]const u8{ app_server_bin, "app-server", "--listen", "stdio://" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = &env_map;

    child.spawn() catch |e| {
        return .{ .ok = false, .reason = @errorName(e), .spawned = false };
    };

    var result = CodexBrokerSmokeResult{ .spawned = true };
    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);
    var turn_request_sent = false;
    var thread_request_sent = false;
    var login_sent = false;

    if (child.stdin) |stdin_file| {
        try stdin_file.writeAll(initialize_request.items);
    }

    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    var term: ?std.process.Child.Term = null;
    const max_output_bytes: usize = 1024 * 1024;
    const deadline_ns = std.time.nanoTimestamp() + (20 * std.time.ns_per_s);
    while (true) {
        if (poller.fifo(.stdout).readableLength() > max_output_bytes or
            poller.fifo(.stderr).readableLength() > max_output_bytes)
        {
            term = child.kill() catch null;
            result.reason = "output_too_large";
            break;
        }

        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) {
            try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
            try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));
            term = child.kill() catch null;
            result.reason = "timeout";
            break;
        }

        const remaining_ns = deadline_ns - now;
        const poll_ns_i = @min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms));
        const keep_polling = poller.pollTimeout(@intCast(poll_ns_i)) catch |e| {
            term = child.kill() catch null;
            result.reason = @errorName(e);
            break;
        };
        try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
        try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));

        const observation = inspectCodexBrokerProtocolOutput(stdout_buf.items);
        if (!login_sent and observation.initialized) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(login_request.items);
                login_sent = true;
            }
        }

        if (!thread_request_sent and observation.login_completed and observation.account_updated) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(thread_request.items);
                thread_request_sent = true;
            }
        }

        if (!turn_request_sent) {
            const thread_id = try findCodexBrokerThreadId(allocator, stdout_buf.items);
            if (thread_id) |id| {
                defer allocator.free(id);
                if (child.stdin) |stdin_file| {
                    try writeCodexAppServerTurnStartRequest(stdin_file.writer(), id);
                    try stdin_file.writeAll("\n");
                    turn_request_sent = true;
                }
            }
        }

        if (!result.refresh_response_sent) {
            var refresh_request = try findCodexBrokerRefreshRequest(allocator, stdout_buf.items);
            defer if (refresh_request) |*request| {
                request.deinit(allocator);
            };
            if (refresh_request) |request| {
                if (!request.reason_unauthorized) {
                    result.reason = "unsupported_refresh_reason";
                } else if (child.stdin) |stdin_file| {
                    try writeCodexAppServerRefreshResponse(stdin_file.writer(), request.id, refresh_credentials);
                    try stdin_file.writeAll("\n");
                    result.refresh_response_sent = true;
                }
            }
        }

        if (observation.turn_completed and !result.stdin_closed) {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
                result.stdin_closed = true;
            }
        }

        if (!keep_polling) break;
    }

    if (!result.stdin_closed) {
        if (child.stdin) |stdin_file| {
            stdin_file.close();
            child.stdin = null;
            result.stdin_closed = true;
        }
    }

    if (term == null) {
        term = child.wait() catch |e| {
            result.reason = @errorName(e);
            return result;
        };
    }

    result.exited = true;
    result.exit_code = switch (term.?) {
        .Exited => |code| code,
        else => null,
    };
    result.stdout_bytes = stdout_buf.items.len;
    result.stderr_bytes = stderr_buf.items.len;
    result.protocol = inspectCodexBrokerProtocolOutput(stdout_buf.items);
    result.ok = result.protocol.initialized and
        result.protocol.login_response and
        result.protocol.login_completed and
        result.protocol.account_updated and
        result.protocol.thread_started and
        result.protocol.turn_started and
        result.protocol.refresh_request_seen and
        result.protocol.refresh_reason_unauthorized and
        result.refresh_response_sent and
        result.protocol.turn_completed and
        result.exit_code != null and
        result.exit_code.? == 0 and
        !result.protocol.experimental_api_required_error;
    if (result.ok) {
        result.reason = "protocol_401_retry_completed";
    } else if (std.mem.eql(u8, result.reason, "unknown")) {
        result.reason = "protocol_incomplete";
    }
    return result;
}

fn runCodexAppServerQuotaBrokerSmoke(
    allocator: std.mem.Allocator,
    login_credentials: CodexBrokerCredentials,
    fallback_credentials: CodexBrokerCredentials,
    codex_home: []const u8,
) !CodexBrokerSmokeResult {
    const app_server_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_APP_SERVER") catch try allocator.dupe(u8, "codex");
    defer allocator.free(app_server_bin);

    var initialize_request = std.ArrayList(u8).init(allocator);
    defer initialize_request.deinit();
    try writeCodexAppServerInitializeRequest(initialize_request.writer());
    try initialize_request.append('\n');

    var login_request = std.ArrayList(u8).init(allocator);
    defer login_request.deinit();
    try writeCodexAppServerLoginRequest(login_request.writer(), login_credentials);
    try login_request.append('\n');

    var fallback_login_request = std.ArrayList(u8).init(allocator);
    defer fallback_login_request.deinit();
    try writeCodexAppServerLoginRequestWithId(fallback_login_request.writer(), 5, fallback_credentials);
    try fallback_login_request.append('\n');

    var thread_request = std.ArrayList(u8).init(allocator);
    defer thread_request.deinit();
    try writeCodexAppServerThreadStartRequest(thread_request.writer());
    try thread_request.append('\n');

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home);
    env_map.remove("OPENAI_API_KEY");

    const argv = [_][]const u8{ app_server_bin, "app-server", "--listen", "stdio://" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = &env_map;

    child.spawn() catch |e| {
        return .{ .ok = false, .reason = @errorName(e), .spawned = false };
    };

    var result = CodexBrokerSmokeResult{ .spawned = true };
    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);
    var first_turn_sent = false;
    var second_thread_request_sent = false;
    var second_turn_sent = false;
    var thread_request_sent = false;
    var login_sent = false;
    var fallback_login_sent = false;

    if (child.stdin) |stdin_file| {
        try stdin_file.writeAll(initialize_request.items);
    }

    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    var term: ?std.process.Child.Term = null;
    const max_output_bytes: usize = 1024 * 1024;
    const deadline_ns = std.time.nanoTimestamp() + (20 * std.time.ns_per_s);
    while (true) {
        if (poller.fifo(.stdout).readableLength() > max_output_bytes or
            poller.fifo(.stderr).readableLength() > max_output_bytes)
        {
            term = child.kill() catch null;
            result.reason = "output_too_large";
            break;
        }

        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) {
            try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
            try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));
            term = child.kill() catch null;
            result.reason = "timeout";
            break;
        }

        const remaining_ns = deadline_ns - now;
        const poll_ns_i = @min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms));
        const keep_polling = poller.pollTimeout(@intCast(poll_ns_i)) catch |e| {
            term = child.kill() catch null;
            result.reason = @errorName(e);
            break;
        };
        try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
        try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));

        const observation = inspectCodexBrokerProtocolOutput(stdout_buf.items);
        if (!login_sent and observation.initialized) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(login_request.items);
                login_sent = true;
            }
        }

        if (!thread_request_sent and observation.login_completed and observation.account_updated) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(thread_request.items);
                thread_request_sent = true;
            }
        }

        const thread_id = try findCodexBrokerThreadId(allocator, stdout_buf.items);
        defer if (thread_id) |id| allocator.free(id);
        if (!first_turn_sent) {
            if (thread_id) |id| {
                if (child.stdin) |stdin_file| {
                    try writeCodexAppServerTurnStartRequestWithId(stdin_file.writer(), 4, id, "Quota one");
                    try stdin_file.writeAll("\n");
                    first_turn_sent = true;
                }
            }
        }

        if (first_turn_sent and !fallback_login_sent and observation.turn_completed_count >= 1) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(fallback_login_request.items);
                fallback_login_sent = true;
            }
        }

        if (fallback_login_sent and !second_thread_request_sent and observation.login_completed_count >= 2 and observation.account_updates >= 2) {
            if (child.stdin) |stdin_file| {
                try writeCodexAppServerThreadStartRequestWithId(stdin_file.writer(), 6);
                try stdin_file.writeAll("\n");
                second_thread_request_sent = true;
            }
        }

        if (second_thread_request_sent and !second_turn_sent) {
            const second_thread_id = try findCodexBrokerThreadIdForRequest(allocator, stdout_buf.items, 6);
            defer if (second_thread_id) |id| allocator.free(id);
            if (second_thread_id) |id| {
                if (child.stdin) |stdin_file| {
                    try writeCodexAppServerTurnStartRequestWithId(stdin_file.writer(), 7, id, "Quota two");
                    try stdin_file.writeAll("\n");
                    second_turn_sent = true;
                }
            }
        }

        if (second_turn_sent and observation.turn_completed_count >= 2 and !result.stdin_closed) {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
                result.stdin_closed = true;
            }
        }

        if (!keep_polling) break;
    }

    if (!result.stdin_closed) {
        if (child.stdin) |stdin_file| {
            stdin_file.close();
            child.stdin = null;
            result.stdin_closed = true;
        }
    }

    if (term == null) {
        term = child.wait() catch |e| {
            result.reason = @errorName(e);
            return result;
        };
    }

    result.exited = true;
    result.exit_code = switch (term.?) {
        .Exited => |code| code,
        else => null,
    };
    result.stdout_bytes = stdout_buf.items.len;
    result.stderr_bytes = stderr_buf.items.len;
    result.protocol = inspectCodexBrokerProtocolOutput(stdout_buf.items);
    result.ok = result.protocol.initialized and
        result.protocol.login_completed_count >= 2 and
        result.protocol.account_updates >= 2 and
        result.protocol.thread_started and
        result.protocol.turn_completed_count >= 2 and
        result.exit_code != null and
        result.exit_code.? == 0 and
        !result.protocol.experimental_api_required_error;
    if (result.ok) {
        result.reason = "next_thread_quota_fallback_completed";
    } else if (std.mem.eql(u8, result.reason, "unknown")) {
        result.reason = "protocol_incomplete";
    }
    return result;
}

fn runCodexAppServerLiveBrokerRun(
    allocator: std.mem.Allocator,
    login_credentials: CodexBrokerCredentials,
    codex_home: []const u8,
    model: []const u8,
    prompts: []const []const u8,
) !CodexBrokerSmokeResult {
    const app_server_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_APP_SERVER") catch try allocator.dupe(u8, "codex");
    defer allocator.free(app_server_bin);

    var initialize_request = std.ArrayList(u8).init(allocator);
    defer initialize_request.deinit();
    try writeCodexAppServerInitializeRequest(initialize_request.writer());
    try initialize_request.append('\n');

    var login_request = std.ArrayList(u8).init(allocator);
    defer login_request.deinit();
    try writeCodexAppServerLoginRequest(login_request.writer(), login_credentials);
    try login_request.append('\n');

    var thread_request = std.ArrayList(u8).init(allocator);
    defer thread_request.deinit();
    try writeCodexAppServerThreadStartRequestWithModel(thread_request.writer(), model);
    try thread_request.append('\n');

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home);
    env_map.remove("OPENAI_API_KEY");

    const argv = [_][]const u8{ app_server_bin, "app-server", "--listen", "stdio://" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = &env_map;

    child.spawn() catch |e| {
        return .{ .ok = false, .reason = @errorName(e), .spawned = false };
    };

    var result = CodexBrokerSmokeResult{ .spawned = true };
    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);
    var thread_request_sent = false;
    var login_sent = false;
    var turns_sent: usize = 0;

    if (child.stdin) |stdin_file| {
        try stdin_file.writeAll(initialize_request.items);
    }

    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    var term: ?std.process.Child.Term = null;
    const max_output_bytes: usize = 2 * 1024 * 1024;
    const deadline_ns = std.time.nanoTimestamp() + (90 * std.time.ns_per_s);
    while (true) {
        if (poller.fifo(.stdout).readableLength() > max_output_bytes or
            poller.fifo(.stderr).readableLength() > max_output_bytes)
        {
            term = child.kill() catch null;
            result.reason = "output_too_large";
            break;
        }

        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) {
            try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
            try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));
            term = child.kill() catch null;
            result.reason = "timeout";
            break;
        }

        const remaining_ns = deadline_ns - now;
        const poll_ns_i = @min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms));
        const keep_polling = poller.pollTimeout(@intCast(poll_ns_i)) catch |e| {
            term = child.kill() catch null;
            result.reason = @errorName(e);
            break;
        };
        try appendCodexBrokerPollFifo(allocator, &stdout_buf, poller.fifo(.stdout));
        try appendCodexBrokerPollFifo(allocator, &stderr_buf, poller.fifo(.stderr));

        const observation = inspectCodexBrokerProtocolOutput(stdout_buf.items);
        if (result.live_provider_failure == null) {
            if (provider_schema.classifyCodexAppServerJsonRpc(allocator, stdout_buf.items)) |classification| {
                result.live_provider_failure = classification;
                result.live_provider_failure_source = "app_server_protocol";
            } else if (provider_schema.classifyCodexAppServerJsonRpc(allocator, stderr_buf.items)) |classification| {
                result.live_provider_failure = classification;
                result.live_provider_failure_source = "app_server_stderr";
            }
        }
        if (result.live_provider_failure != null and !result.stdin_closed) {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
                result.stdin_closed = true;
            }
        }
        if (!login_sent and observation.initialized) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(login_request.items);
                login_sent = true;
            }
        }

        if (!thread_request_sent and observation.login_completed and observation.account_updated) {
            if (child.stdin) |stdin_file| {
                try stdin_file.writeAll(thread_request.items);
                thread_request_sent = true;
            }
        }

        const thread_id = try findCodexBrokerThreadId(allocator, stdout_buf.items);
        defer if (thread_id) |id| allocator.free(id);
        if (result.live_provider_failure == null and turns_sent < prompts.len and observation.turn_completed_count >= turns_sent) {
            if (thread_id) |id| {
                if (child.stdin) |stdin_file| {
                    try writeCodexAppServerTurnStartRequestWithId(stdin_file.writer(), @intCast(4 + turns_sent), id, prompts[turns_sent]);
                    try stdin_file.writeAll("\n");
                    turns_sent += 1;
                }
            }
        }

        if (turns_sent >= prompts.len and observation.turn_completed_count >= prompts.len and !result.stdin_closed) {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
                result.stdin_closed = true;
            }
        }

        if (!keep_polling) break;
    }

    if (!result.stdin_closed) {
        if (child.stdin) |stdin_file| {
            stdin_file.close();
            child.stdin = null;
            result.stdin_closed = true;
        }
    }

    if (term == null) {
        term = child.wait() catch |e| {
            result.reason = @errorName(e);
            return result;
        };
    }

    result.exited = true;
    result.exit_code = switch (term.?) {
        .Exited => |code| code,
        else => null,
    };
    result.stdout_bytes = stdout_buf.items.len;
    result.stderr_bytes = stderr_buf.items.len;
    result.protocol = inspectCodexBrokerProtocolOutput(stdout_buf.items);
    if (result.live_provider_failure == null) {
        if (provider_schema.classifyCodexAppServerJsonRpc(allocator, stdout_buf.items)) |classification| {
            result.live_provider_failure = classification;
            result.live_provider_failure_source = "app_server_protocol";
        } else if (provider_schema.classifyCodexAppServerJsonRpc(allocator, stderr_buf.items)) |classification| {
            result.live_provider_failure = classification;
            result.live_provider_failure_source = "app_server_stderr";
        }
    }
    result.ok = codexBrokerRunOk(result, prompts.len);
    if (result.ok) {
        result.reason = if (prompts.len == 1) "live_turn_completed" else "live_session_turns_completed";
    } else if (result.live_provider_failure) |classification| {
        result.reason = codexBrokerRunProviderFailureReason(classification);
    } else if (std.mem.eql(u8, result.reason, "unknown")) {
        result.reason = "protocol_incomplete";
    }
    return result;
}

const CodexBroker401MockServerState = struct {
    mutex: std.Thread.Mutex = .{},
    observation: CodexBroker401HttpObservation = .{},

    fn snapshot(self: *CodexBroker401MockServerState) CodexBroker401HttpObservation {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.observation;
    }

    fn recordModelsRequest(self: *CodexBroker401MockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.models_request_seen = true;
    }

    fn recordOtherRequest(self: *CodexBroker401MockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
    }

    fn recordBackendRequest(self: *CodexBroker401MockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.backend_request_seen = true;
    }

    fn recordResponsesRequest(self: *CodexBroker401MockServerState, response_index: usize, initial_seen: bool, fallback_seen: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.responses_request_count = @max(self.observation.responses_request_count, response_index);
        self.observation.turn_request_seen = true;
        if (response_index == 1) {
            self.observation.initial_authorization_seen = initial_seen;
            self.observation.unauthorized_response_sent = true;
        } else if (response_index == 2) {
            self.observation.fallback_authorization_seen = fallback_seen;
            self.observation.sse_response_sent = true;
            self.observation.retried_with_fallback = fallback_seen;
        }
    }

    fn recordPreTurnResponsesRequest(self: *CodexBroker401MockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.pre_turn_responses_count += 1;
    }

    fn setError(self: *CodexBroker401MockServerState, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.observation.server_error == null) self.observation.server_error = reason;
    }
};

const CodexBroker401MockServerArgs = struct {
    server: std.net.Server,
    initial_access_token: []const u8,
    fallback_access_token: []const u8,
    state: CodexBroker401MockServerState = .{},
};

const CodexBroker401MockServer = struct {
    allocator: std.mem.Allocator,
    args: *CodexBroker401MockServerArgs,
    thread: std.Thread,
    port: u16,
    joined: bool = false,

    fn finish(self: *CodexBroker401MockServer) CodexBroker401HttpObservation {
        self.deinit();
        return self.args.state.snapshot();
    }

    fn snapshot(self: *CodexBroker401MockServer) CodexBroker401HttpObservation {
        return self.args.state.snapshot();
    }

    fn deinit(self: *CodexBroker401MockServer) void {
        if (!self.joined) {
            self.thread.join();
            self.joined = true;
        }
    }

    fn destroy(self: *CodexBroker401MockServer) void {
        self.deinit();
        self.allocator.destroy(self.args);
    }
};

fn startCodexBroker401MockServer(
    allocator: std.mem.Allocator,
    initial_access_token: []const u8,
    fallback_access_token: []const u8,
) !CodexBroker401MockServer {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    errdefer server.deinit();

    const args = try allocator.create(CodexBroker401MockServerArgs);
    errdefer allocator.destroy(args);
    args.* = .{
        .server = server,
        .initial_access_token = initial_access_token,
        .fallback_access_token = fallback_access_token,
    };

    const thread = try std.Thread.spawn(.{}, runCodexBroker401MockServer, .{args});
    return .{
        .allocator = allocator,
        .args = args,
        .thread = thread,
        .port = server.listen_address.getPort(),
    };
}

fn runCodexBroker401MockServer(args: *CodexBroker401MockServerArgs) void {
    defer args.server.deinit();
    runCodexBroker401MockServerInner(args) catch |e| {
        args.state.setError(@errorName(e));
    };
}

fn runCodexBroker401MockServerInner(args: *CodexBroker401MockServerArgs) !void {
    const deadline_ns = std.time.nanoTimestamp() + (20 * std.time.ns_per_s);
    while (args.state.snapshot().responses_request_count < 2) {
        if (std.time.nanoTimestamp() >= deadline_ns) {
            args.state.setError("mock_server_timeout");
            return;
        }

        var fds = [_]std.posix.pollfd{.{
            .fd = args.server.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&fds, 50);
        if (ready == 0) continue;

        const conn = args.server.accept() catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        defer conn.stream.close();
        try handleCodexBroker401MockConnection(args, conn.stream);
    }
}

fn handleCodexBroker401MockConnection(args: *CodexBroker401MockServerArgs, stream: std.net.Stream) !void {
    var request_buf: [64 * 1024]u8 = undefined;
    const request = try readHttpRequest(stream, &request_buf);
    const path = findHttpRequestPath(request) orelse "/";
    const auth_header = findHttpHeaderValue(request, "authorization");
    const initial_seen = if (auth_header) |value| authHeaderMatchesBearer(value, args.initial_access_token) else false;
    const fallback_seen = if (auth_header) |value| authHeaderMatchesBearer(value, args.fallback_access_token) else false;

    if (std.mem.endsWith(u8, path, "/models")) {
        try writeHttpJsonResponse(stream, 200, "OK", "{\"object\":\"list\",\"data\":[{\"id\":\"mock-model\",\"object\":\"model\",\"created\":0,\"owned_by\":\"oauth-mux\"}]}");
        args.state.recordModelsRequest();
        return;
    }

    if (std.mem.indexOf(u8, path, "/backend-api/") != null) {
        try writeHttpJsonResponse(stream, 200, "OK", "{}");
        args.state.recordBackendRequest();
        return;
    }

    if (!std.mem.endsWith(u8, path, "/responses")) {
        try writeHttpJsonResponse(stream, 404, "Not Found", "{\"error\":{\"message\":\"not found\"}}");
        args.state.recordOtherRequest();
        return;
    }

    if (!isCodexBroker401TurnRequest(request)) {
        try writeCodexBroker401SseSuccess(stream);
        args.state.recordPreTurnResponsesRequest();
        return;
    }

    const response_index = args.state.snapshot().responses_request_count + 1;
    if (response_index == 1) {
        try writeHttpJsonResponse(stream, 401, "Unauthorized", "{\"error\":{\"message\":\"unauthorized\"}}");
        args.state.recordResponsesRequest(response_index, initial_seen, false);
    } else {
        try writeCodexBroker401SseSuccess(stream);
        args.state.recordResponsesRequest(response_index, false, fallback_seen);
    }
}

const CodexBrokerQuotaMockServerState = struct {
    mutex: std.Thread.Mutex = .{},
    observation: CodexBrokerQuotaHttpObservation = .{},

    fn snapshot(self: *CodexBrokerQuotaMockServerState) CodexBrokerQuotaHttpObservation {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.observation;
    }

    fn recordOtherRequest(self: *CodexBrokerQuotaMockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
    }

    fn recordBackendRequest(self: *CodexBrokerQuotaMockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.backend_request_seen = true;
    }

    fn recordPreTurnResponsesRequest(self: *CodexBrokerQuotaMockServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.pre_turn_responses_count += 1;
    }

    fn recordFirstTurnRequest(self: *CodexBrokerQuotaMockServerState, initial_seen: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.responses_request_count = @max(self.observation.responses_request_count, 1);
        self.observation.first_turn_request_seen = true;
        self.observation.quota_response_sent = true;
        self.observation.initial_authorization_seen = initial_seen;
    }

    fn recordSecondTurnRequest(self: *CodexBrokerQuotaMockServerState, fallback_seen: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observation.request_count += 1;
        self.observation.responses_request_count = @max(self.observation.responses_request_count, 2);
        self.observation.second_turn_request_seen = true;
        self.observation.second_turn_sse_response_sent = true;
        self.observation.fallback_authorization_seen = fallback_seen;
        self.observation.next_turn_used_fallback = fallback_seen;
    }

    fn setError(self: *CodexBrokerQuotaMockServerState, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.observation.server_error == null) self.observation.server_error = reason;
    }
};

const CodexBrokerQuotaMockServerArgs = struct {
    server: std.net.Server,
    initial_access_token: []const u8,
    fallback_access_token: []const u8,
    state: CodexBrokerQuotaMockServerState = .{},
};

const CodexBrokerQuotaMockServer = struct {
    allocator: std.mem.Allocator,
    args: *CodexBrokerQuotaMockServerArgs,
    thread: std.Thread,
    port: u16,
    joined: bool = false,

    fn finish(self: *CodexBrokerQuotaMockServer) CodexBrokerQuotaHttpObservation {
        self.deinit();
        return self.args.state.snapshot();
    }

    fn deinit(self: *CodexBrokerQuotaMockServer) void {
        if (!self.joined) {
            self.thread.join();
            self.joined = true;
        }
    }

    fn destroy(self: *CodexBrokerQuotaMockServer) void {
        self.deinit();
        self.allocator.destroy(self.args);
    }
};

fn startCodexBrokerQuotaMockServer(
    allocator: std.mem.Allocator,
    initial_access_token: []const u8,
    fallback_access_token: []const u8,
) !CodexBrokerQuotaMockServer {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    errdefer server.deinit();

    const args = try allocator.create(CodexBrokerQuotaMockServerArgs);
    errdefer allocator.destroy(args);
    args.* = .{
        .server = server,
        .initial_access_token = initial_access_token,
        .fallback_access_token = fallback_access_token,
    };

    const thread = try std.Thread.spawn(.{}, runCodexBrokerQuotaMockServer, .{args});
    return .{
        .allocator = allocator,
        .args = args,
        .thread = thread,
        .port = server.listen_address.getPort(),
    };
}

fn runCodexBrokerQuotaMockServer(args: *CodexBrokerQuotaMockServerArgs) void {
    defer args.server.deinit();
    runCodexBrokerQuotaMockServerInner(args) catch |e| {
        args.state.setError(@errorName(e));
    };
}

fn runCodexBrokerQuotaMockServerInner(args: *CodexBrokerQuotaMockServerArgs) !void {
    const deadline_ns = std.time.nanoTimestamp() + (20 * std.time.ns_per_s);
    while (!args.state.snapshot().next_turn_used_fallback) {
        if (std.time.nanoTimestamp() >= deadline_ns) {
            args.state.setError("mock_server_timeout");
            return;
        }

        var fds = [_]std.posix.pollfd{.{
            .fd = args.server.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&fds, 50);
        if (ready == 0) continue;

        const conn = args.server.accept() catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        defer conn.stream.close();
        try handleCodexBrokerQuotaMockConnection(args, conn.stream);
    }
}

fn handleCodexBrokerQuotaMockConnection(args: *CodexBrokerQuotaMockServerArgs, stream: std.net.Stream) !void {
    var request_buf: [64 * 1024]u8 = undefined;
    const request = try readHttpRequest(stream, &request_buf);
    const path = findHttpRequestPath(request) orelse "/";
    const auth_header = findHttpHeaderValue(request, "authorization");
    const initial_seen = if (auth_header) |value| authHeaderMatchesBearer(value, args.initial_access_token) else false;
    const fallback_seen = if (auth_header) |value| authHeaderMatchesBearer(value, args.fallback_access_token) else false;

    if (std.mem.indexOf(u8, path, "/backend-api/") != null) {
        try writeHttpJsonResponse(stream, 200, "OK", "{}");
        args.state.recordBackendRequest();
        return;
    }

    if (!std.mem.endsWith(u8, path, "/responses")) {
        try writeHttpJsonResponse(stream, 404, "Not Found", "{\"error\":{\"message\":\"not found\"}}");
        args.state.recordOtherRequest();
        return;
    }

    if (std.mem.indexOf(u8, request, "\"Quota one\"") != null or
        std.mem.indexOf(u8, request, "\\\"Quota one\\\"") != null)
    {
        try writeCodexBrokerQuota429Response(stream);
        args.state.recordFirstTurnRequest(initial_seen);
        return;
    }

    if (std.mem.indexOf(u8, request, "\"Quota two\"") != null or
        std.mem.indexOf(u8, request, "\\\"Quota two\\\"") != null)
    {
        try writeCodexBroker401SseSuccess(stream);
        args.state.recordSecondTurnRequest(fallback_seen);
        return;
    }

    try writeCodexBroker401SseSuccess(stream);
    args.state.recordPreTurnResponsesRequest();
}

fn readHttpRequest(stream: std.net.Stream, buf: []u8) ![]const u8 {
    var used: usize = 0;
    var header_end: ?usize = null;
    while (used < buf.len) {
        const n = try stream.read(buf[used..]);
        if (n == 0) break;
        used += n;
        if (findHttpHeaderEnd(buf[0..used])) |end| {
            header_end = end;
            break;
        }
    }
    const end = header_end orelse return buf[0..used];
    const content_length = parseHttpContentLength(buf[0..end]) orelse 0;
    const target_len = end + 4 + content_length;
    if (target_len > buf.len) return error.HttpRequestTooLarge;
    while (used < target_len) {
        const n = try stream.read(buf[used..target_len]);
        if (n == 0) break;
        used += n;
    }
    return buf[0..used];
}

fn findHttpHeaderEnd(request: []const u8) ?usize {
    return std.mem.indexOf(u8, request, "\r\n\r\n");
}

fn parseHttpContentLength(headers: []const u8) ?usize {
    const value = findHttpHeaderValue(headers, "content-length") orelse return null;
    return std.fmt.parseInt(usize, value, 10) catch null;
}

fn authHeaderMatchesBearer(value: []const u8, access_token: []const u8) bool {
    const prefix = "Bearer ";
    if (value.len != prefix.len + access_token.len) return false;
    if (!std.ascii.eqlIgnoreCase(value[0.."Bearer".len], "Bearer")) return false;
    if (value["Bearer".len] != ' ') return false;
    return std.mem.eql(u8, value[prefix.len..], access_token);
}

fn isCodexBroker401TurnRequest(request: []const u8) bool {
    return std.mem.indexOf(u8, request, "\"Hello\"") != null or
        std.mem.indexOf(u8, request, "\\\"Hello\\\"") != null;
}

fn findHttpHeaderValue(request: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, request, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(key, name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

fn findHttpRequestPath(request: []const u8) ?[]const u8 {
    const first_line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const first_line = request[0..first_line_end];
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = parts.next() orelse return null;
    return parts.next();
}

fn writeHttpJsonResponse(stream: std.net.Stream, status: u16, reason: []const u8, body: []const u8) !void {
    try stream.writer().print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}",
        .{ status, reason, body.len, body },
    );
}

fn writeHttpSseResponse(stream: std.net.Stream, body: []const u8) !void {
    try stream.writer().print(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
}

fn writeCodexBroker401SseSuccess(stream: std.net.Stream) !void {
    const body =
        "event: response.created\n" ++
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-turn\"}}\n\n" ++
        "event: response.output_item.done\n" ++
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg-turn\",\"content\":[{\"type\":\"output_text\",\"text\":\"turn ok\"}]}}\n\n" ++
        "event: response.completed\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-turn\",\"usage\":{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}\n\n";
    try writeHttpSseResponse(stream, body);
}

fn writeCodexBrokerQuota429Response(stream: std.net.Stream) !void {
    const body = "{\"error\":{\"type\":\"usage_limit_reached\",\"message\":\"limit reached\",\"resets_at\":1777987200,\"plan_type\":\"pro\"}}";
    try stream.writer().print(
        "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nretry-after: 7200\r\nx-codex-primary-used-percent: 100.0\r\nx-codex-primary-window-minutes: 120\r\nconnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
}

fn appendCodexBrokerPollFifo(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    fifo: *std.io.PollFifo,
) !void {
    var offset: usize = 0;
    const total = fifo.readableLength();
    while (offset < total) {
        const chunk = fifo.readableSlice(offset);
        if (chunk.len == 0) break;
        try list.appendSlice(allocator, chunk);
        offset += chunk.len;
    }
    fifo.discard(total);
}

fn writeCodexAppServerInitializeRequest(writer: anytype) !void {
    try writer.writeAll("{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"oauth-mux\",\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll("},\"capabilities\":{\"experimentalApi\":true}}}");
}

fn writeCodexAppServerLoginRequest(writer: anytype, credentials: CodexBrokerCredentials) !void {
    try writeCodexAppServerLoginRequestWithId(writer, 2, credentials);
}

fn writeCodexAppServerLoginRequestWithId(writer: anytype, id: i64, credentials: CodexBrokerCredentials) !void {
    try writer.print("{{\"id\":{d},\"method\":\"account/login/start\",\"params\":{{\"type\":\"chatgptAuthTokens\",\"accessToken\":", .{id});
    try std.json.stringify(credentials.access_token, .{}, writer);
    try writer.writeAll(",\"chatgptAccountId\":");
    try std.json.stringify(credentials.chatgpt_account_id, .{}, writer);
    try writer.writeAll(",\"chatgptPlanType\":");
    if (credentials.chatgpt_plan_type) |plan| try std.json.stringify(plan, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll("}}");
}

fn writeCodexAppServerThreadStartRequest(writer: anytype) !void {
    try writeCodexAppServerThreadStartRequestWithId(writer, 3);
}

fn writeCodexAppServerThreadStartRequestWithId(writer: anytype, id: i64) !void {
    try writeCodexAppServerThreadStartRequestWithIdAndModel(writer, id, "mock-model");
}

fn writeCodexAppServerThreadStartRequestWithModel(writer: anytype, model: []const u8) !void {
    try writeCodexAppServerThreadStartRequestWithIdAndModel(writer, 3, model);
}

fn writeCodexAppServerThreadStartRequestWithIdAndModel(writer: anytype, id: i64, model: []const u8) !void {
    try writer.print("{{\"id\":{d},\"method\":\"thread/start\",\"params\":{{\"model\":", .{id});
    try std.json.stringify(model, .{}, writer);
    try writer.writeAll("}}");
}

fn writeCodexAppServerTurnStartRequest(writer: anytype, thread_id: []const u8) !void {
    try writeCodexAppServerTurnStartRequestWithId(writer, 4, thread_id, "Hello");
}

fn writeCodexAppServerTurnStartRequestWithId(writer: anytype, id: i64, thread_id: []const u8, text: []const u8) !void {
    try writer.print("{{\"id\":{d},\"method\":\"turn/start\",\"params\":{{\"threadId\":", .{id});
    try std.json.stringify(thread_id, .{}, writer);
    try writer.writeAll(",\"input\":[{\"type\":\"text\",\"text\":");
    try std.json.stringify(text, .{}, writer);
    try writer.writeAll(",\"text_elements\":[]}]}}");
}

fn writeCodexBroker401AppServerFiles(
    allocator: std.mem.Allocator,
    codex_home: []const u8,
    base_url: []const u8,
    chatgpt_base_url: []const u8,
) !void {
    const config_path = try std.fs.path.join(allocator, &.{ codex_home, "config.toml" });
    defer allocator.free(config_path);
    const config_file = try std.fs.createFileAbsolute(config_path, .{ .truncate = true, .mode = 0o600 });
    defer config_file.close();
    try config_file.writer().print(
        \\
        \\model = "mock-model"
        \\approval_policy = "never"
        \\sandbox_mode = "danger-full-access"
        \\chatgpt_base_url = "{s}"
        \\model_provider = "mock_provider"
        \\
        \\[features]
        \\shell_snapshot = false
        \\
        \\[model_providers.mock_provider]
        \\name = "Mock provider for oauth-mux broker smoke"
        \\base_url = "{s}"
        \\wire_api = "responses"
        \\request_max_retries = 0
        \\stream_max_retries = 0
        \\requires_openai_auth = true
        \\
    , .{ chatgpt_base_url, base_url });

    const cache_path = try std.fs.path.join(allocator, &.{ codex_home, "models_cache.json" });
    defer allocator.free(cache_path);
    const cache_file = try std.fs.createFileAbsolute(cache_path, .{ .truncate = true, .mode = 0o600 });
    defer cache_file.close();
    try cache_file.writer().writeAll(
        \\{
        \\  "fetched_at": "2999-01-01T00:00:00Z",
        \\  "etag": null,
        \\  "client_version": "oauth-mux",
        \\  "models": [
        \\    {
        \\      "slug": "mock-model",
        \\      "display_name": "mock-model",
        \\      "description": "oauth-mux local broker smoke model",
        \\      "default_reasoning_level": "medium",
        \\      "supported_reasoning_levels": [
        \\        {"effort": "low", "description": "low"},
        \\        {"effort": "medium", "description": "medium"}
        \\      ],
        \\      "shell_type": "shell_command",
        \\      "visibility": "list",
        \\      "supported_in_api": true,
        \\      "priority": 0,
        \\      "additional_speed_tiers": [],
        \\      "availability_nux": null,
        \\      "upgrade": null,
        \\      "base_instructions": "base instructions",
        \\      "model_messages": null,
        \\      "supports_reasoning_summaries": false,
        \\      "default_reasoning_summary": "auto",
        \\      "support_verbosity": false,
        \\      "default_verbosity": null,
        \\      "apply_patch_tool_type": null,
        \\      "web_search_tool_type": "text",
        \\      "truncation_policy": {"mode": "bytes", "limit": 10000},
        \\      "supports_parallel_tool_calls": false,
        \\      "supports_image_detail_original": false,
        \\      "context_window": 272000,
        \\      "max_context_window": 272000,
        \\      "auto_compact_token_limit": null,
        \\      "effective_context_window_percent": 95,
        \\      "experimental_supported_tools": [],
        \\      "input_modalities": ["text"],
        \\      "supports_search_tool": false
        \\    }
        \\  ]
        \\}
    );
}

fn writeCodexBrokerLiveAppServerFiles(
    allocator: std.mem.Allocator,
    codex_home: []const u8,
    model: []const u8,
) !void {
    const config_path = try std.fs.path.join(allocator, &.{ codex_home, "config.toml" });
    defer allocator.free(config_path);
    const config_file = try std.fs.createFileAbsolute(config_path, .{ .truncate = true, .mode = 0o600 });
    defer config_file.close();
    try config_file.writer().writeAll("model = ");
    try std.json.stringify(model, .{}, config_file.writer());
    try config_file.writer().writeAll(
        \\
        \\approval_policy = "never"
        \\sandbox_mode = "read-only"
        \\model_reasoning_effort = "low"
        \\
        \\[features]
        \\shell_snapshot = false
        \\
    );
}

const CodexBrokerJsonRpcId = union(enum) {
    integer: i64,
    string: []u8,

    fn deinit(self: CodexBrokerJsonRpcId, allocator: std.mem.Allocator) void {
        switch (self) {
            .integer => {},
            .string => |value| allocator.free(value),
        }
    }
};

const CodexBrokerRefreshRequest = struct {
    id: CodexBrokerJsonRpcId,
    reason_unauthorized: bool = false,

    fn deinit(self: *CodexBrokerRefreshRequest, allocator: std.mem.Allocator) void {
        self.id.deinit(allocator);
    }
};

fn writeCodexAppServerRefreshResponse(
    writer: anytype,
    id: CodexBrokerJsonRpcId,
    credentials: CodexBrokerCredentials,
) !void {
    try writer.writeAll("{\"id\":");
    try writeCodexBrokerJsonRpcId(writer, id);
    try writer.writeAll(",\"result\":{\"accessToken\":");
    try std.json.stringify(credentials.access_token, .{}, writer);
    try writer.writeAll(",\"chatgptAccountId\":");
    try std.json.stringify(credentials.chatgpt_account_id, .{}, writer);
    try writer.writeAll(",\"chatgptPlanType\":");
    if (credentials.chatgpt_plan_type) |plan| try std.json.stringify(plan, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll("}}");
}

fn writeCodexBrokerJsonRpcId(writer: anytype, id: CodexBrokerJsonRpcId) !void {
    switch (id) {
        .integer => |value| try writer.print("{d}", .{value}),
        .string => |value| try std.json.stringify(value, .{}, writer),
    }
}

fn findCodexBrokerRefreshRequest(allocator: std.mem.Allocator, stdout: []const u8) !?CodexBrokerRefreshRequest {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line_raw| {
        if (std.mem.indexOf(u8, line_raw, "account/chatgptAuthTokens/refresh") == null) continue;
        const line = std.mem.trim(u8, line_raw, " \t\r\n");
        if (line.len == 0) continue;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{
            .allocate = .alloc_always,
        }) catch continue;
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |object| object,
            else => continue,
        };
        const method_value = root.get("method") orelse continue;
        const method = switch (method_value) {
            .string => |value| value,
            else => continue,
        };
        if (!std.mem.eql(u8, method, "account/chatgptAuthTokens/refresh")) continue;

        const id_value = root.get("id") orelse continue;
        const id: CodexBrokerJsonRpcId = switch (id_value) {
            .integer => |value| .{ .integer = value },
            .string => |value| .{ .string = try allocator.dupe(u8, value) },
            else => continue,
        };
        errdefer id.deinit(allocator);

        var reason_unauthorized = false;
        if (root.get("params")) |params_value| {
            const params = switch (params_value) {
                .object => |object| object,
                else => null,
            };
            if (params) |object| {
                if (object.get("reason")) |reason_value| {
                    const reason = switch (reason_value) {
                        .string => |value| value,
                        else => null,
                    };
                    if (reason) |value| reason_unauthorized = std.ascii.eqlIgnoreCase(value, "unauthorized");
                }
            }
        }

        return .{
            .id = id,
            .reason_unauthorized = reason_unauthorized,
        };
    }

    return null;
}

fn findCodexBrokerThreadId(allocator: std.mem.Allocator, stdout: []const u8) !?[]u8 {
    return findCodexBrokerThreadIdForRequest(allocator, stdout, 3);
}

fn findCodexBrokerThreadIdForRequest(allocator: std.mem.Allocator, stdout: []const u8, request_id: i64) !?[]u8 {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line_raw| {
        var id_buf: [32]u8 = undefined;
        const id_needle = std.fmt.bufPrint(&id_buf, "\"id\":{d}", .{request_id}) catch continue;
        if (std.mem.indexOf(u8, line_raw, id_needle) == null) continue;
        const line = std.mem.trim(u8, line_raw, " \t\r\n");
        if (line.len == 0) continue;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{
            .allocate = .alloc_always,
        }) catch continue;
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |object| object,
            else => continue,
        };
        const id_value = root.get("id") orelse continue;
        const id_matches = switch (id_value) {
            .integer => |value| value == request_id,
            else => false,
        };
        if (!id_matches) continue;

        const result_value = root.get("result") orelse continue;
        const result = switch (result_value) {
            .object => |object| object,
            else => continue,
        };
        const thread_value = result.get("thread") orelse continue;
        const thread = switch (thread_value) {
            .object => |object| object,
            else => continue,
        };
        const thread_id_value = thread.get("id") orelse continue;
        const thread_id = switch (thread_id_value) {
            .string => |value| value,
            else => continue,
        };
        return try allocator.dupe(u8, thread_id);
    }

    return null;
}

fn inspectCodexBrokerProtocolOutput(stdout: []const u8) CodexBrokerProtocolObservation {
    const account_updates = countNeedle(stdout, "\"account/updated\"");
    const login_completed_count = countNeedle(stdout, "\"account/login/completed\"");
    const turn_completed_count = countNeedle(stdout, "\"turn/completed\"");
    return .{
        .initialized = std.mem.indexOf(u8, stdout, "\"id\":1") != null and std.mem.indexOf(u8, stdout, "\"result\"") != null,
        .login_response = std.mem.indexOf(u8, stdout, "\"id\":2") != null and std.mem.indexOf(u8, stdout, "\"type\":\"chatgptAuthTokens\"") != null,
        .login_completed = login_completed_count != 0 and std.mem.indexOf(u8, stdout, "\"success\":true") != null,
        .login_completed_count = login_completed_count,
        .account_updated = account_updates != 0 and std.mem.indexOf(u8, stdout, "\"authMode\":\"chatgptAuthTokens\"") != null,
        .account_updates = account_updates,
        .thread_started = std.mem.indexOf(u8, stdout, "\"id\":3") != null and std.mem.indexOf(u8, stdout, "\"thread\"") != null,
        .turn_started = std.mem.indexOf(u8, stdout, "\"id\":4") != null and std.mem.indexOf(u8, stdout, "\"result\"") != null,
        .turn_completed = turn_completed_count != 0,
        .turn_completed_count = turn_completed_count,
        .refresh_request_seen = std.mem.indexOf(u8, stdout, "\"account/chatgptAuthTokens/refresh\"") != null,
        .refresh_reason_unauthorized = std.mem.indexOf(u8, stdout, "\"reason\":\"unauthorized\"") != null or
            std.mem.indexOf(u8, stdout, "\"reason\":\"Unauthorized\"") != null,
        .experimental_api_required_error = std.mem.indexOf(u8, stdout, "requires experimentalApi capability") != null,
    };
}

fn countNeedle(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, start, needle)) |idx| {
        count += 1;
        start = idx + needle.len;
    }
    return count;
}

fn writeCodexBrokerRouteJson(
    writer: anytype,
    route: RepairPlanRoute,
    cfg: config.Config,
    plan: CodexBrokerTokenPlan,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try std.json.stringify(route.provider, .{}, writer);
    try writer.writeAll(",\"account\":");
    try std.json.stringify(route.account, .{}, writer);
    try writer.writeAll(",\"capability\":");
    if (route.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"secret_backend\":");
    if (cfg.providers.map.get(route.provider)) |prov| {
        if (prov.accounts.map.get(route.account)) |account| {
            try std.json.stringify(account.secret.backend, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"can_supply\":");
    try writer.writeAll(if (plan.can_supply) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(plan.reason, .{}, writer);
    try writer.writeAll(",\"fields\":{\"access_token\":");
    try writer.writeAll(if (plan.access_token_present) "true" else "false");
    try writer.writeAll(",\"access_token_jwt_parseable\":");
    try writer.writeAll(if (plan.access_token_jwt_parseable) "true" else "false");
    try writer.writeAll(",\"chatgpt_account_id\":");
    try writer.writeAll(if (plan.chatgpt_account_id_present) "true" else "false");
    try writer.writeAll(",\"chatgpt_account_id_source\":");
    if (plan.chatgpt_account_id_source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"chatgpt_plan_type\":");
    try writer.writeAll(if (plan.chatgpt_plan_type_present) "true" else "false");
    try writer.writeAll(",\"chatgpt_plan_type_source\":");
    if (plan.chatgpt_plan_type_source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll("}}");
}

fn inspectCodexBrokerRoute(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
) !CodexBrokerTokenPlan {
    if (!std.mem.eql(u8, route.provider, "codex")) {
        return .{ .reason = "non_codex_route" };
    }

    const prov = cfg.providers.map.get(route.provider) orelse return .{ .reason = "provider_missing" };
    if (!std.mem.eql(u8, prov.kind, "codex")) return .{ .reason = "provider_kind_not_codex" };
    const account = prov.accounts.map.get(route.account) orelse return .{ .reason = "account_missing" };
    const backend = config.resolveSecretBackend(account.secret) catch return .{ .reason = "secret_backend_invalid" };
    const raw = secret_mod.read(backend, allocator) catch |e| {
        return .{
            .reason = codexBrokerSecretReadReason(e),
        };
    };
    defer allocator.free(raw);

    var plan = inspectCodexBrokerAuthJson(allocator, raw);
    plan.secret_readable = true;
    return plan;
}

fn loadCodexBrokerCredentialsForRoute(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
) !CodexBrokerCredentials {
    if (!std.mem.eql(u8, route.provider, "codex")) return error.NonCodexRoute;
    const prov = cfg.providers.map.get(route.provider) orelse return error.ProviderMissing;
    if (!std.mem.eql(u8, prov.kind, "codex")) return error.ProviderKindNotCodex;
    const account = prov.accounts.map.get(route.account) orelse return error.AccountMissing;
    const backend = try config.resolveSecretBackend(account.secret);
    const raw = try secret_mod.read(backend, allocator);
    defer allocator.free(raw);
    return try loadCodexBrokerCredentialsFromAuthJson(allocator, raw);
}

fn inspectCodexBrokerAuthJson(allocator: std.mem.Allocator, raw: []const u8) CodexBrokerTokenPlan {
    const parsed = std.json.parseFromSlice(CodexBrokerAuthJson, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return .{ .secret_readable = true, .reason = "auth_json_invalid" };
    defer parsed.deinit();

    if (parsed.value.OPENAI_API_KEY != null and parsed.value.tokens == null) {
        return .{
            .secret_readable = true,
            .reason = "api_key_mode_not_supported_for_chatgpt_auth_broker",
        };
    }

    const tokens = parsed.value.tokens orelse return .{ .secret_readable = true, .reason = "tokens_missing" };
    const access_token = nonEmpty(tokens.access_token) orelse return .{ .secret_readable = true, .reason = "access_token_missing" };
    const access_token_jwt_parseable = jwtPayloadParses(allocator, access_token);
    const account_id_source = codexAccountIdSource(allocator, tokens);
    const plan_type_source = codexPlanTypeSource(allocator, tokens);
    const can_supply = access_token_jwt_parseable and account_id_source != null;

    return .{
        .secret_readable = true,
        .can_supply = can_supply,
        .reason = if (can_supply) "ready" else if (!access_token_jwt_parseable) "access_token_not_jwt" else "chatgpt_account_id_missing",
        .access_token_present = true,
        .access_token_jwt_parseable = access_token_jwt_parseable,
        .chatgpt_account_id_present = account_id_source != null,
        .chatgpt_account_id_source = account_id_source,
        .chatgpt_plan_type_present = plan_type_source != null,
        .chatgpt_plan_type_source = plan_type_source,
    };
}

fn loadCodexBrokerCredentialsFromAuthJson(allocator: std.mem.Allocator, raw: []const u8) !CodexBrokerCredentials {
    const parsed = try std.json.parseFromSlice(CodexBrokerAuthJson, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    const tokens = parsed.value.tokens orelse return error.TokensMissing;
    const access_token = nonEmpty(tokens.access_token) orelse return error.AccessTokenMissing;
    if (!jwtPayloadParses(allocator, access_token)) return error.AccessTokenNotJwt;

    const account_id = try codexAccountIdValueAlloc(allocator, tokens) orelse return error.ChatgptAccountIdMissing;
    errdefer allocator.free(account_id);
    const access_token_dup = try allocator.dupe(u8, access_token);
    errdefer allocator.free(access_token_dup);
    const plan_type = try codexPlanTypeValueAlloc(allocator, tokens);
    errdefer if (plan_type) |value| allocator.free(value);

    return .{
        .access_token = access_token_dup,
        .chatgpt_account_id = account_id,
        .chatgpt_plan_type = plan_type,
    };
}

fn codexBrokerSecretReadReason(e: secret_mod.ReadError) []const u8 {
    return switch (e) {
        error.NotFound => "secret_not_found",
        error.AccessDenied => "secret_access_denied",
        error.DecryptFailed => "secret_decrypt_failed",
        error.CommandFailed => "secret_command_failed",
        error.Timeout => "secret_timeout",
        error.OutOfMemory => "out_of_memory",
        error.IoError => "secret_io_error",
    };
}

fn codexAccountIdSource(allocator: std.mem.Allocator, tokens: CodexBrokerTokensJson) ?[]const u8 {
    if (nonEmpty(tokens.account_id) != null) return "tokens.account_id";
    if (jwtAuthStringClaimPresent(allocator, tokens.id_token, "chatgpt_account_id")) return "tokens.id_token.auth.chatgpt_account_id";
    if (jwtAuthStringClaimPresent(allocator, tokens.access_token, "chatgpt_account_id")) return "tokens.access_token.auth.chatgpt_account_id";
    return null;
}

fn codexAccountIdValueAlloc(allocator: std.mem.Allocator, tokens: CodexBrokerTokensJson) !?[]u8 {
    if (nonEmpty(tokens.account_id)) |value| return try allocator.dupe(u8, value);
    if (try jwtAuthStringClaimAlloc(allocator, tokens.id_token, "chatgpt_account_id")) |value| return value;
    if (try jwtAuthStringClaimAlloc(allocator, tokens.access_token, "chatgpt_account_id")) |value| return value;
    return null;
}

fn codexPlanTypeSource(allocator: std.mem.Allocator, tokens: CodexBrokerTokensJson) ?[]const u8 {
    if (jwtAuthStringClaimPresent(allocator, tokens.id_token, "chatgpt_plan_type")) return "tokens.id_token.auth.chatgpt_plan_type";
    if (jwtAuthStringClaimPresent(allocator, tokens.access_token, "chatgpt_plan_type")) return "tokens.access_token.auth.chatgpt_plan_type";
    return null;
}

fn codexPlanTypeValueAlloc(allocator: std.mem.Allocator, tokens: CodexBrokerTokensJson) !?[]u8 {
    if (try jwtAuthStringClaimAlloc(allocator, tokens.id_token, "chatgpt_plan_type")) |value| return value;
    if (try jwtAuthStringClaimAlloc(allocator, tokens.access_token, "chatgpt_plan_type")) |value| return value;
    return null;
}

fn jwtAuthStringClaimPresent(allocator: std.mem.Allocator, maybe_jwt: ?[]const u8, field: []const u8) bool {
    const jwt = nonEmpty(maybe_jwt) orelse return false;
    const payload = jwtPayloadJsonAlloc(allocator, jwt) catch return false;
    defer allocator.free(payload);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return false;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return false,
    };
    const auth_value = root.get("https://api.openai.com/auth") orelse return false;
    const auth = switch (auth_value) {
        .object => |object| object,
        else => return false,
    };
    return switch (auth.get(field) orelse return false) {
        .string => |value| value.len != 0,
        else => false,
    };
}

fn jwtAuthStringClaimAlloc(allocator: std.mem.Allocator, maybe_jwt: ?[]const u8, field: []const u8) !?[]u8 {
    const jwt = nonEmpty(maybe_jwt) orelse return null;
    const payload = jwtPayloadJsonAlloc(allocator, jwt) catch return null;
    defer allocator.free(payload);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    const auth_value = root.get("https://api.openai.com/auth") orelse return null;
    const auth = switch (auth_value) {
        .object => |object| object,
        else => return null,
    };
    return switch (auth.get(field) orelse return null) {
        .string => |value| if (value.len == 0) null else try allocator.dupe(u8, value),
        else => null,
    };
}

fn jwtPayloadParses(allocator: std.mem.Allocator, jwt: []const u8) bool {
    const payload = jwtPayloadJsonAlloc(allocator, jwt) catch return false;
    defer allocator.free(payload);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return false;
    defer parsed.deinit();
    return parsed.value == .object;
}

fn jwtPayloadJsonAlloc(allocator: std.mem.Allocator, jwt: []const u8) ![]u8 {
    var parts = std.mem.splitScalar(u8, jwt, '.');
    const header = parts.next() orelse return error.InvalidJwt;
    const payload = parts.next() orelse return error.InvalidJwt;
    const signature = parts.next() orelse return error.InvalidJwt;
    if (header.len == 0 or payload.len == 0 or signature.len == 0 or parts.next() != null) return error.InvalidJwt;

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(payload) catch return error.InvalidJwt;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    _ = std.base64.url_safe_no_pad.Decoder.decode(decoded, payload) catch return error.InvalidJwt;
    return decoded;
}

fn firstCommaValue(values: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, values, ',');
    while (it.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len != 0) return trimmed;
    }
    return null;
}

fn nonEmpty(value: ?[]const u8) ?[]const u8 {
    const present = value orelse return null;
    return if (present.len == 0) null else present;
}

test "inspectCodexBrokerAuthJson detects app-server token tuple without exposing values" {
    const auth_json =
        \\{
        \\  "auth_mode": "chatgpt",
        \\  "tokens": {
        \\    "id_token": "hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig",
        \\    "access_token": "hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig",
        \\    "refresh_token": "redacted-in-test"
        \\  }
        \\}
    ;

    const plan = inspectCodexBrokerAuthJson(std.testing.allocator, auth_json);
    try std.testing.expect(plan.can_supply);
    try std.testing.expect(plan.secret_readable);
    try std.testing.expect(plan.access_token_present);
    try std.testing.expect(plan.access_token_jwt_parseable);
    try std.testing.expect(plan.chatgpt_account_id_present);
    try std.testing.expectEqualStrings("tokens.id_token.auth.chatgpt_account_id", plan.chatgpt_account_id_source.?);
    try std.testing.expect(plan.chatgpt_plan_type_present);
    try std.testing.expectEqualStrings("tokens.id_token.auth.chatgpt_plan_type", plan.chatgpt_plan_type_source.?);
}

test "inspectCodexBrokerAuthJson rejects missing account metadata" {
    const auth_json =
        \\{
        \\  "auth_mode": "chatgpt",
        \\  "tokens": {
        \\    "access_token": "hdr.e30.sig",
        \\    "refresh_token": "redacted-in-test"
        \\  }
        \\}
    ;

    const plan = inspectCodexBrokerAuthJson(std.testing.allocator, auth_json);
    try std.testing.expect(!plan.can_supply);
    try std.testing.expect(plan.access_token_present);
    try std.testing.expect(plan.access_token_jwt_parseable);
    try std.testing.expect(!plan.chatgpt_account_id_present);
    try std.testing.expectEqualStrings("chatgpt_account_id_missing", plan.reason);
}

test "loadCodexBrokerCredentialsFromAuthJson extracts app-server credential values" {
    const auth_json =
        \\{
        \\  "auth_mode": "chatgpt",
        \\  "tokens": {
        \\    "id_token": "hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig",
        \\    "access_token": "hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig"
        \\  }
        \\}
    ;

    const credentials = try loadCodexBrokerCredentialsFromAuthJson(std.testing.allocator, auth_json);
    defer credentials.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("acct-test", credentials.chatgpt_account_id);
    try std.testing.expectEqualStrings("pro", credentials.chatgpt_plan_type.?);
    try std.testing.expect(std.mem.startsWith(u8, credentials.access_token, "hdr."));
}

test "inspectCodexBrokerProtocolOutput detects successful external auth login" {
    const stdout =
        \\{"id":1,"result":{}}
        \\{"id":2,"result":{"type":"chatgptAuthTokens"}}
        \\{"method":"account/login/completed","params":{"success":true}}
        \\{"method":"account/updated","params":{"authMode":"chatgptAuthTokens","planType":"pro"}}
    ;

    const observation = inspectCodexBrokerProtocolOutput(stdout);
    try std.testing.expect(observation.initialized);
    try std.testing.expect(observation.login_response);
    try std.testing.expect(observation.login_completed);
    try std.testing.expect(observation.account_updated);
    try std.testing.expect(!observation.experimental_api_required_error);
}

test "findCodexBrokerRefreshRequest extracts unauthorized request id" {
    const stdout =
        \\{"id":1,"result":{}}
        \\{"id":99,"method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized"}}
    ;

    var request = (try findCodexBrokerRefreshRequest(std.testing.allocator, stdout)).?;
    defer request.deinit(std.testing.allocator);
    switch (request.id) {
        .integer => |value| try std.testing.expectEqual(@as(i64, 99), value),
        else => return error.Unexpected,
    }
    try std.testing.expect(request.reason_unauthorized);
}

test "writeCodexAppServerRefreshResponse preserves request id" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    const access_token = try std.testing.allocator.dupe(u8, "test-access-token");
    errdefer std.testing.allocator.free(access_token);
    const account_id = try std.testing.allocator.dupe(u8, "test-account");
    errdefer std.testing.allocator.free(account_id);
    const plan_type = try std.testing.allocator.dupe(u8, "pro");
    errdefer std.testing.allocator.free(plan_type);
    const credentials = CodexBrokerCredentials{
        .access_token = access_token,
        .chatgpt_account_id = account_id,
        .chatgpt_plan_type = plan_type,
    };
    defer credentials.deinit(std.testing.allocator);

    try writeCodexAppServerRefreshResponse(buf.writer(), .{ .integer = 99 }, credentials);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"id\":99") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"accessToken\":\"test-access-token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"chatgptAccountId\":\"test-account\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"chatgptPlanType\":\"pro\"") != null);
}

fn runCodexLiveQa(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    if (!codexLiveQaConfirmed(args)) {
        if (args.json) {
            try writer.writeAll("{\"ok\":false,\"error\":\"confirmation_required\",\"required\":\"--confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls\",\"spends_provider_calls\":true}\n");
        } else {
            try writer.writeAll("oauth-mux Codex live QA is disabled.\n\n");
            try writer.writeAll("This command runs real Codex provider probes and can spend subscription quota.\n");
            try writer.writeAll("Re-run with --confirm-spend or OMUX_LIVE_QA_CONFIRM=spend-real-calls.\n");
        }
        return error.CodexLiveQaConfirmationRequired;
    }

    if (args.json) {
        try bootstrapCodexDirs(allocator, std.io.null_writer, args, root);
    } else {
        try bootstrapCodexDirs(allocator, writer, args, root);
    }

    if (args.json) {
        try writer.writeAll("{\"version\":");
        try std.json.stringify(cli.version, .{}, writer);
        try writer.writeAll(",\"ok\":");

        var route_buf = std.ArrayList(u8).init(allocator);
        defer route_buf.deinit();
        var capability_coverage = std.StringHashMap(bool).init(allocator);
        defer freeLiveQaCoverage(allocator, &capability_coverage);
        try seedLiveQaCapabilities(allocator, &capability_coverage, args.capabilities);

        var summary = LiveQaSummary{
            .capabilities_total = capability_coverage.count(),
        };
        try collectCodexLiveQaRoutesJson(allocator, &route_buf, args, &capability_coverage, &summary);
        summary.capabilities_covered = countLiveQaCoveredCapabilities(&capability_coverage);

        try writer.writeAll(if (summary.ok()) "true" else "false");
        try writer.writeAll(",\"spends_provider_calls\":true,\"accounts\":");
        try std.json.stringify(args.accounts, .{}, writer);
        try writer.writeAll(",\"capabilities\":");
        try std.json.stringify(args.capabilities, .{}, writer);
        try writer.print(
            ",\"routes_total\":{d},\"routes_available\":{d},\"routes_unavailable\":{d},\"probe_errors\":{d},\"failures\":{d},\"capabilities_total\":{d},\"capabilities_covered\":{d},\"capabilities_uncovered\":{d},\"routes\":[",
            .{
                summary.routes_total,
                summary.routes_available,
                summary.routes_unavailable,
                summary.probe_errors,
                summary.failureCount(),
                summary.capabilities_total,
                summary.capabilities_covered,
                summary.capabilitiesUncovered(),
            },
        );
        try writer.writeAll(route_buf.items);
        try writer.writeAll("]}\n");
        if (!summary.ok()) return error.CodexRouteProbeFailed;
        return;
    }

    try writer.writeAll("oauth-mux Codex live QA\n\n");
    try writer.print("store root:   {s}\n", .{root});
    try writer.print("accounts:     {s}\n", .{args.accounts});
    try writer.print("capabilities: {s}\n", .{args.capabilities});
    try writer.writeAll("confirmed:    yes, real provider probes may spend quota\n\n");

    try writer.writeAll("=== config validate ===\n");
    try validateCurrentConfig(allocator, writer);

    try writer.writeAll("\n=== codex login status ===\n");
    try runCodexLoginStatusAll(allocator, writer, args, root);

    try writer.writeAll("\n=== live probes ===\n");
    const failures = try runCodexLiveProbesCount(allocator, writer, args, true);

    try writer.writeAll("\n=== route liveness snapshot ===\n");
    try writeCodexRouteSnapshot(allocator, writer, args);

    try writer.writeAll("\n=== repair plan ===\n");
    try writeCodexRepairPlanSnapshot(allocator, writer, args);

    if (failures != 0) return error.CodexRouteProbeFailed;
}

const LiveQaSummary = struct {
    routes_total: usize = 0,
    routes_available: usize = 0,
    routes_unavailable: usize = 0,
    probe_errors: usize = 0,
    capabilities_total: usize = 0,
    capabilities_covered: usize = 0,

    fn capabilitiesUncovered(self: LiveQaSummary) usize {
        if (self.capabilities_covered >= self.capabilities_total) return 0;
        return self.capabilities_total - self.capabilities_covered;
    }

    fn ok(self: LiveQaSummary) bool {
        return self.routes_total > 0 and
            self.probe_errors == 0 and
            self.capabilities_total > 0 and
            self.capabilitiesUncovered() == 0;
    }

    fn failureCount(self: LiveQaSummary) usize {
        return self.probe_errors + self.capabilitiesUncovered();
    }
};

fn codexLiveQaConfirmed(args: cli.Command.CodexArgs) bool {
    if (args.confirm_spend) return true;
    const confirm = std.process.getEnvVarOwned(std.heap.page_allocator, "OMUX_LIVE_QA_CONFIRM") catch return false;
    defer std.heap.page_allocator.free(confirm);
    return std.mem.eql(u8, confirm, "spend-real-calls");
}

fn seedLiveQaCapabilities(
    allocator: std.mem.Allocator,
    coverage: *std.StringHashMap(bool),
    capabilities: []const u8,
) !void {
    var capability_it = std.mem.splitScalar(u8, capabilities, ',');
    while (capability_it.next()) |raw_capability| {
        const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
        if (capability.len == 0 or coverage.contains(capability)) continue;
        const key = try allocator.dupe(u8, capability);
        errdefer allocator.free(key);
        try coverage.put(key, false);
    }
}

fn countLiveQaCoveredCapabilities(coverage: *const std.StringHashMap(bool)) usize {
    var covered: usize = 0;
    var it = coverage.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.*) covered += 1;
    }
    return covered;
}

fn freeLiveQaCoverage(allocator: std.mem.Allocator, coverage: *std.StringHashMap(bool)) void {
    var it = coverage.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    coverage.deinit();
}

fn collectCodexLiveQaRoutesJson(
    allocator: std.mem.Allocator,
    routes: *std.ArrayList(u8),
    args: cli.Command.CodexArgs,
    capability_coverage: *std.StringHashMap(bool),
    summary: *LiveQaSummary,
) !void {
    var first = true;
    var account_it = std.mem.splitScalar(u8, args.accounts, ',');
    while (account_it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        var capability_it = std.mem.splitScalar(u8, args.capabilities, ',');
        while (capability_it.next()) |raw_capability| {
            const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
            if (capability.len == 0) continue;
            summary.routes_total += 1;

            var probe_buf = std.ArrayList(u8).init(allocator);
            defer probe_buf.deinit();
            const probe_error = runProbe(allocator, probe_buf.writer(), .{
                .provider = "codex",
                .account = account,
                .capability = capability,
                .json = true,
            });

            if (probe_error) |_| {
                summary.routes_available += 1;
                if (capability_coverage.getPtr(capability)) |covered| covered.* = true;
            } else |e| {
                if (liveQaErrorIsRecordedEvidence(e)) {
                    summary.routes_unavailable += 1;
                } else {
                    summary.probe_errors += 1;
                }
            }

            if (!first) try routes.append(',');
            first = false;
            const route_json = std.mem.trim(u8, probe_buf.items, " \t\r\n");
            if (route_json.len == 0) {
                try routes.appendSlice("{\"provider\":\"codex\",\"account\":");
                try std.json.stringify(account, .{}, routes.writer());
                try routes.appendSlice(",\"capability\":");
                try std.json.stringify(capability, .{}, routes.writer());
                try routes.appendSlice(",\"ok\":false,\"error\":\"ProbeDidNotProduceJson\"}");
            } else {
                try routes.appendSlice(route_json);
            }
        }
    }
}

fn liveQaErrorIsRecordedEvidence(e: anyerror) bool {
    return switch (e) {
        error.AllAccountsExhausted => true,
        else => false,
    };
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
    const merge_cmd = try std.fmt.allocPrint(allocator, "oauth-mux codex config-merge --candidate {s}", .{quoted_candidate_path});
    defer allocator.free(merge_cmd);

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
        try writer.writeByte(',');
        try writeCommandJson(writer, merge_cmd);
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
    try writer.print("  {s}\n", .{merge_cmd});
}

const CodexConfigMergeResult = struct {
    merged: bool,
    backup_created: bool,
    reason: []const u8,
};

fn runCodexConfigMerge(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const active_config_path = try paths.configFilePath(allocator);
    defer allocator.free(active_config_path);

    const candidate_path = if (args.candidate) |candidate|
        try paths.expandTilde(allocator, candidate)
    else
        try defaultCodexConfigCandidatePath(allocator, active_config_path);
    defer allocator.free(candidate_path);

    const backup_path = if (args.backup) |backup|
        try paths.expandTilde(allocator, backup)
    else
        try defaultCodexConfigBackupPath(allocator, active_config_path);
    defer allocator.free(backup_path);

    const result = try mergeCodexConfigCandidate(allocator, active_config_path, candidate_path, backup_path);
    try writeCodexConfigMergeResult(writer, active_config_path, candidate_path, backup_path, result, args.json);
}

fn defaultCodexConfigBackupPath(allocator: std.mem.Allocator, active_config_path: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s}.backup-{d}-{x}", .{
        active_config_path,
        std.time.timestamp(),
        std.crypto.random.int(u64),
    });
}

fn mergeCodexConfigCandidate(
    allocator: std.mem.Allocator,
    active_config_path: []const u8,
    candidate_path: []const u8,
    backup_path: []const u8,
) !CodexConfigMergeResult {
    var active = try config.loadFromPath(allocator, active_config_path);
    defer active.deinit();
    try config.validate(active.value, std.io.null_writer);

    if (codexMaxShapeConfigured(active.value)) {
        return .{
            .merged = false,
            .backup_created = false,
            .reason = "active_config_already_codex_max",
        };
    }

    var candidate = try config.loadFromPath(allocator, candidate_path);
    defer candidate.deinit();
    try config.validate(candidate.value, std.io.null_writer);
    if (!codexMaxShapeConfigured(candidate.value)) return error.ConfigValidationError;

    var merged_buf = std.ArrayList(u8).init(allocator);
    defer merged_buf.deinit();
    try writeMergedCodexConfigJson(merged_buf.writer(), active.value, candidate.value);

    const merged = try config.loadFromBytes(allocator, merged_buf.items);
    defer merged.deinit();
    try config.validate(merged.value, std.io.null_writer);
    if (!codexMaxShapeConfigured(merged.value)) return error.ConfigValidationError;

    if (fileExistsAbsolute(backup_path)) return error.PathAlreadyExists;
    if (std.fs.path.dirname(active_config_path)) |dir| try std.fs.cwd().makePath(dir);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ active_config_path, std.crypto.random.int(u64) });
    defer allocator.free(tmp_path);

    const tmp_file = try std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 });
    errdefer std.fs.deleteFileAbsolute(tmp_path) catch {};
    {
        defer tmp_file.close();
        try tmp_file.writeAll(merged_buf.items);
    }

    try std.fs.renameAbsolute(active_config_path, backup_path);
    std.fs.renameAbsolute(tmp_path, active_config_path) catch |e| {
        std.fs.renameAbsolute(backup_path, active_config_path) catch {};
        return e;
    };

    return .{
        .merged = true,
        .backup_created = true,
        .reason = "merged_codex_max_candidate",
    };
}

fn writeMergedCodexConfigJson(writer: anytype, active: config.Config, candidate: config.Config) !void {
    const codex_provider = candidate.providers.map.get("codex") orelse return error.ConfigValidationError;
    const codex_max_profile = candidate.profiles.map.get("codex-max") orelse return error.ConfigValidationError;
    const codex_mini_profile = candidate.profiles.map.get("codex-mini") orelse return error.ConfigValidationError;
    const health_weighted = candidate.strategies.map.get("health-weighted") orelse return error.ConfigValidationError;

    try writer.writeAll("{\"version\":");
    try writer.print("{d}", .{active.version});
    try writer.writeAll(",\"defaults\":");
    try std.json.stringify(active.defaults, .{}, writer);
    try writer.writeAll(",\"provider_definitions\":");
    try std.json.stringify(active.provider_definitions, .{}, writer);
    try writer.writeAll(",\"providers\":{");

    var first = true;
    var wrote_codex = false;
    var provider_it = active.providers.map.iterator();
    while (provider_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;

        const provider_name = entry.key_ptr.*;
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeByte(':');
        if (std.mem.eql(u8, provider_name, "codex")) {
            try writeMergedCodexProviderJson(writer, entry.value_ptr.*, codex_provider);
            wrote_codex = true;
        } else {
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }
    if (!wrote_codex) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify("codex", .{}, writer);
        try writer.writeByte(':');
        try writeMergedCodexProviderJson(writer, null, codex_provider);
    }

    try writer.writeAll("},\"profiles\":{");
    first = true;
    var profile_it = active.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        const profile_name = entry.key_ptr.*;
        if (std.mem.eql(u8, profile_name, "codex-max") or std.mem.eql(u8, profile_name, "codex-mini")) continue;

        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(profile_name, .{}, writer);
        try writer.writeByte(':');
        try std.json.stringify(entry.value_ptr.*, .{}, writer);
    }
    if (!first) try writer.writeByte(',');
    try std.json.stringify("codex-max", .{}, writer);
    try writer.writeByte(':');
    try std.json.stringify(codex_max_profile, .{}, writer);
    try writer.writeByte(',');
    try std.json.stringify("codex-mini", .{}, writer);
    try writer.writeByte(':');
    try std.json.stringify(codex_mini_profile, .{}, writer);

    try writer.writeAll("},\"strategies\":{");
    first = true;
    var wrote_health_weighted = false;
    var strategy_it = active.strategies.map.iterator();
    while (strategy_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;

        const strategy_name = entry.key_ptr.*;
        try std.json.stringify(strategy_name, .{}, writer);
        try writer.writeByte(':');
        try std.json.stringify(entry.value_ptr.*, .{}, writer);
        if (std.mem.eql(u8, strategy_name, "health-weighted")) wrote_health_weighted = true;
    }

    if (!wrote_health_weighted) {
        if (!first) try writer.writeByte(',');
        try std.json.stringify("health-weighted", .{}, writer);
        try writer.writeByte(':');
        try std.json.stringify(health_weighted, .{}, writer);
    }

    try writer.writeAll("}}\n");
}

fn writeMergedCodexProviderJson(
    writer: anytype,
    active_provider: ?config.ProviderConfig,
    candidate_provider: config.ProviderConfig,
) !void {
    try writer.writeAll("{\"kind\":");
    try std.json.stringify(candidate_provider.kind, .{}, writer);
    try writer.writeAll(",\"config_dir_env\":");
    if (candidate_provider.config_dir_env) |config_dir_env| {
        try std.json.stringify(config_dir_env, .{}, writer);
    } else if (active_provider) |provider_cfg| {
        if (provider_cfg.config_dir_env) |config_dir_env| {
            try std.json.stringify(config_dir_env, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"accounts\":{");

    var first = true;
    if (active_provider) |provider_cfg| {
        var active_account_it = provider_cfg.accounts.map.iterator();
        while (active_account_it.next()) |entry| {
            const account_name = entry.key_ptr.*;
            if (candidate_provider.accounts.map.get(account_name) != null) continue;

            if (!first) try writer.writeByte(',');
            first = false;
            try std.json.stringify(account_name, .{}, writer);
            try writer.writeByte(':');
            try std.json.stringify(entry.value_ptr.*, .{}, writer);
        }
    }

    var candidate_account_it = candidate_provider.accounts.map.iterator();
    while (candidate_account_it.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.writeByte(':');
        try std.json.stringify(entry.value_ptr.*, .{}, writer);
    }

    try writer.writeAll("}}");
}

fn writeCodexConfigMergeResult(
    writer: anytype,
    active_config_path: []const u8,
    candidate_path: []const u8,
    backup_path: []const u8,
    result: CodexConfigMergeResult,
    json: bool,
) !void {
    if (json) {
        try writer.writeAll("{\"merged\":");
        try writer.writeAll(if (result.merged) "true" else "false");
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(result.reason, .{}, writer);
        try writer.writeAll(",\"active_config\":");
        try std.json.stringify(active_config_path, .{}, writer);
        try writer.writeAll(",\"candidate_config\":");
        try std.json.stringify(candidate_path, .{}, writer);
        try writer.writeAll(",\"backup_config\":");
        if (result.backup_created) {
            try std.json.stringify(backup_path, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"next_commands\":[");
        try writeCommandJson(writer, "oauth-mux doctor --json");
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux setup codex --status-only");
        try writer.writeByte(',');
        try writeCommandJson(writer, "oauth-mux codex canary");
        try writer.writeAll("]}\n");
        return;
    }

    try writer.writeAll("oauth-mux Codex Max config merge\n\n");
    try writer.print("active config:    {s}\n", .{active_config_path});
    try writer.print("candidate config: {s}\n", .{candidate_path});
    if (result.backup_created) {
        try writer.print("backup config:    {s}\n", .{backup_path});
    } else {
        try writer.writeAll("backup config:    not created\n");
    }
    try writer.print("merged:           {s}\n", .{if (result.merged) "yes" else "no"});
    try writer.print("reason:           {s}\n\n", .{result.reason});
    try writer.writeAll("next:\n");
    try writer.writeAll("  oauth-mux doctor --json\n");
    try writer.writeAll("  oauth-mux setup codex --status-only\n");
    try writer.writeAll("  oauth-mux codex canary\n");
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
    const failures = try runCodexLiveProbesCount(allocator, writer, args, emit_headers);
    if (failures != 0) return error.CodexRouteProbeFailed;
}

fn runCodexLiveProbesCount(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, emit_headers: bool) !usize {
    var failures: usize = 0;
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
                else => failures += 1,
            };
        }
    }
    return failures;
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

fn writeCodexRuntimeDoctorSnapshot(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    var capability_it = std.mem.splitScalar(u8, args.capabilities, ',');
    while (capability_it.next()) |raw_capability| {
        const capability = std.mem.trim(u8, raw_capability, " \t\r\n");
        if (capability.len == 0) continue;

        if (!args.json) try writer.print("\n--- profile {s} ---\n", .{capability});
        runDoctorRuntime(allocator, writer, .{
            .mode = .runtime,
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
                    try writer.print("runtime doctor skipped for profile {s}: current config does not define that Codex profile\n", .{capability});
                }
            },
            else => return e,
        };
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

fn bootstrapOneClaudeDir(allocator: std.mem.Allocator, writer: anytype, root: []const u8, account: []const u8) !void {
    const dir = try claudeAccountDir(allocator, root, account);
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

fn claudeConfigRoot(allocator: std.mem.Allocator, override_root: ?[]const u8) ![]const u8 {
    if (override_root) |root| return try paths.expandTilde(allocator, root);
    if (try getEnvOwnedOrNull(allocator, "OMUX_CLAUDE_CONFIG_ROOT")) |root| {
        defer allocator.free(root);
        return try paths.expandTilde(allocator, root);
    }
    if (try getEnvOwnedOrNull(allocator, "XDG_DATA_HOME")) |xdg| {
        defer allocator.free(xdg);
        return try std.fs.path.join(allocator, &.{ xdg, "oauth-mux", "claude" });
    }
    const home = (try getEnvOwnedOrNull(allocator, "HOME")) orelse return error.ConfigNotFound;
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".local", "share", "oauth-mux", "claude" });
}

fn claudeAccountDir(allocator: std.mem.Allocator, root: []const u8, account: []const u8) ![]const u8 {
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

test "mergeCodexConfigCandidate preserves unrelated active providers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const active_path = try std.fs.path.join(std.testing.allocator, &.{ root, "config.json" });
    defer std.testing.allocator.free(active_path);
    const candidate_path = try std.fs.path.join(std.testing.allocator, &.{ root, "codex-max.config.json" });
    defer std.testing.allocator.free(candidate_path);
    const backup_path = try std.fs.path.join(std.testing.allocator, &.{ root, "config.backup.json" });
    defer std.testing.allocator.free(backup_path);

    const active_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "personal": {
        \\          "secret": { "backend": "env", "variable": "CLAUDE_TOKEN" }
        \\        }
        \\      }
        \\    },
        \\    "codex": {
        \\      "kind": "codex",
        \\      "config_dir_env": "CODEX_HOME",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "CODEX_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "default": {
        \\      "providers": ["claude:personal", "codex:default"],
        \\      "strategy": "health-weighted"
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
    ;

    {
        const file = try std.fs.createFileAbsolute(active_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(active_json);
    }
    {
        const file = try std.fs.createFileAbsolute(candidate_path, .{ .mode = 0o600 });
        defer file.close();
        try writeCodexMaxStarterConfig(std.testing.allocator, file.writer(), "/tmp/omux-codex");
    }

    const result = try mergeCodexConfigCandidate(std.testing.allocator, active_path, candidate_path, backup_path);
    try std.testing.expect(result.merged);
    try std.testing.expect(result.backup_created);

    const merged = try config.loadFromPath(std.testing.allocator, active_path);
    defer merged.deinit();
    try config.validate(merged.value, std.io.null_writer);
    try std.testing.expect(codexMaxShapeConfigured(merged.value));
    try std.testing.expect(merged.value.providers.map.get("claude") != null);
    try std.testing.expect(merged.value.profiles.map.get("default") != null);

    const backup = try config.loadFromPath(std.testing.allocator, backup_path);
    defer backup.deinit();
    try config.validate(backup.value, std.io.null_writer);
    try std.testing.expect(!codexMaxShapeConfigured(backup.value));
    try std.testing.expect(backup.value.providers.map.get("claude") != null);

    const noop = try mergeCodexConfigCandidate(std.testing.allocator, active_path, candidate_path, backup_path);
    try std.testing.expect(!noop.merged);
    try std.testing.expect(!noop.backup_created);
    try std.testing.expectEqualStrings("active_config_already_codex_max", noop.reason);
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

test "writeDiscoverJson includes stay-afloat agent-safe commands" {
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
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux doctor runtime --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux route explain --profile <profile> --capability <capability> --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux route select --profile <profile> --capability <capability> --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux repair-plan --profile <profile> --capability <capability> --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "oauth-mux repair run --profile <profile> --capability <capability> --json") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"proof_requirements\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"codex-max\",\"proof_status\":\"live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"auth-status\",\"proof_status\":\"local_live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"identity\",\"proof_status\":\"local_live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"status\",\"proof_status\":\"local_live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"resource-metadata\",\"proof_status\":\"public_live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"resource\",\"proof_status\":\"needs_operator_proof\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"identity-api-key\",\"proof_status\":\"local_live_proven\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "OMUX_FIGMA_PLAN_FILE_KEY") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "OMUX_MCP_RESOURCE_TOKEN") != null);
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

test "runtime doctor route scope reports only requested profile routes" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": { "name": "toy", "display_name": "Toy Provider" }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "a1": { "secret": { "backend": "env", "variable": "TOY_A1" } },
        \\        "a2": { "secret": { "backend": "env", "variable": "TOY_A2" } }
        \\      }
        \\    },
        \\    "stale": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "unused": { "secret": { "backend": "env", "variable": "TOY_UNUSED" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "work": {
        \\      "providers": ["toy:a1#chat", "toy:a2#chat"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "work", .capability = "chat" });
    defer routes.deinit();
    const stats = try collectRuntimeDoctorRouteStats(std.testing.allocator, parsed.value, true, routes.items);

    try std.testing.expect(stats.ok());
    try std.testing.expectEqual(@as(usize, 1), stats.providers);
    try std.testing.expectEqual(@as(usize, 2), stats.accounts);
    try std.testing.expectEqual(@as(usize, 2), stats.ready_accounts);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeDoctorRuntimeScopedJson(buf.writer(), std.testing.allocator, parsed.value, stats, "/tmp/oauth-mux/config.json", "", routes.items, .{
        .mode = .runtime,
        .profile = "work",
        .capability = "chat",
        .json = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"scope\":{\"profile\":\"work\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"route_reports\":[{\"provider\":\"toy\",\"account\":\"a1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"provider\":\"stale\"") == null);
}

test "provider runtime readiness reports missing command adapter binary" {
    const missing_binary = "omux-definitely-missing-claude-fixture";
    const def = provider_schema.ProviderDefinition{
        .name = "claude",
        .display_name = "Synthetic Claude",
        .extension_mode = .command_adapter,
        .runtime = .{
            .required_binaries = &.{missing_binary},
            .env_vars = &.{"CLAUDE_CONFIG_DIR"},
        },
        .capabilities = &.{
            .{
                .name = "auth-status",
                .probe = .{
                    .transport = .command,
                    .auth = .none,
                    .command = &.{ missing_binary, "auth", "status", "--json" },
                    .budget = .free_command,
                },
            },
        },
    };

    const readiness = try providerRuntimeReadiness(std.testing.allocator, def, "auth-status");
    switch (readiness) {
        .missing_binary => |binary| try std.testing.expectEqualStrings(missing_binary, binary),
        else => return error.TestUnexpectedResult,
    }

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRuntimeReadinessJson(buf.writer(), readiness);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"missing_binary\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, missing_binary) != null);
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

    try std.testing.expectEqual(RepairActionKind.probe_needed, action.kind);
    try std.testing.expectEqual(RepairMediation.probe, action.mediation);
    try std.testing.expectEqualStrings("warning", action.severity);
    try std.testing.expect(action.command == .probe);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, action.budget.?);
    try std.testing.expect(std.mem.indexOf(u8, action.message, "spend provider quota") != null);
}

test "daemon admission policy refuses provider spend by default" {
    const policy = config.PolicyConfig{};

    const spend_probe = daemonProbeAdmission(policy.daemon, .spend_provider);
    try std.testing.expect(!spend_probe.admitted);
    try std.testing.expectEqualStrings("budget_not_allowed", spend_probe.reason);

    const free_command = daemonProbeAdmission(policy.daemon, .free_command);
    try std.testing.expect(free_command.admitted);
    try std.testing.expectEqualStrings("allowed_by_policy", free_command.reason);

    const probe_action = RepairAction{
        .kind = .probe_needed,
        .severity = "warning",
        .message = "probe",
        .mediation = .probe,
        .command = .probe,
        .budget = .spend_provider,
    };
    const probe_repair = daemonRepairAdmission(policy.daemon, probe_action);
    try std.testing.expect(probe_repair.admitted);
    try std.testing.expectEqualStrings("no_repair_action", probe_repair.reason);

    const reauth = RepairAction{
        .kind = .reauth,
        .severity = "error",
        .message = "reauth",
        .mediation = .user_handoff,
        .owner = .upstream_cli_login,
        .budget = .interactive,
        .interactive = true,
        .mutating = true,
    };
    const repair = daemonRepairAdmission(policy.daemon, reauth);
    try std.testing.expect(!repair.admitted);
    try std.testing.expectEqualStrings("interactive_not_allowed", repair.reason);
}

test "writePolicyJson exposes effective daemon admission policy" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writePolicyJson(buf.writer(), .{});
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"allowed_budgets\":[\"free_local\",\"free_command\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"allow_interactive\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"allow_mutating\":false") != null);
}

test "daemon tick refuses spend provider probe by default" {
    const decision = daemonTickDecision((config.PolicyConfig{}).daemon, .{
        .route = .{ .provider = "codex", .account = "max-1", .capability = "codex-max" },
        .runtime = .ready,
        .health = null,
        .budget = .spend_provider,
        .action = .{
            .kind = .probe_needed,
            .severity = "warning",
            .message = "probe would spend",
            .mediation = .probe,
            .command = .probe,
            .budget = .spend_provider,
        },
        .selectable = false,
        .skip_reason = "unrecorded",
    }, 1000);

    try std.testing.expectEqualStrings("probe", decision.phase);
    try std.testing.expect(!decision.admitted);
    try std.testing.expectEqualStrings("budget_not_allowed", decision.reason);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, decision.budget.?);
    try std.testing.expect(!decision.executed);
    try std.testing.expectEqual(@as(?i64, 1000), decision.next_tick_after);
    try std.testing.expectEqualStrings("probe_due", decision.schedule_reason);
}

test "daemon tick reports selectable route as no-op" {
    const health = health_mod.AccountHealth{
        .liveness = .{ .live = .{ .availability = .available } },
    };
    const decision = daemonTickDecision((config.PolicyConfig{}).daemon, .{
        .route = .{ .provider = "codex", .account = "max-2", .capability = "codex-max" },
        .runtime = .ready,
        .health = health,
        .budget = .spend_provider,
        .action = .{
            .kind = .none,
            .severity = "ok",
            .message = "route is selectable",
        },
        .selectable = true,
        .skip_reason = "available",
    }, 1000);

    try std.testing.expectEqualStrings("none", decision.phase);
    try std.testing.expect(decision.admitted);
    try std.testing.expectEqualStrings("route_selectable", decision.reason);
    try std.testing.expect(!decision.executed);
    try std.testing.expect(decision.next_tick_after == null);
    try std.testing.expectEqualStrings("route_selectable", decision.schedule_reason);
}

test "daemon tick schedules interactive handoff recheck without admitting silent auth" {
    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const decision = daemonTickDecision((config.PolicyConfig{}).daemon, .{
        .route = route,
        .runtime = .{ .needs_reauth = .{ .methods = &.{"upstream_cli_login"}, .reason = "session_file_missing" } },
        .health = null,
        .budget = .spend_provider,
        .action = reauthAction(route, provider_schema.codex_def),
        .selectable = false,
        .skip_reason = "needs_reauth",
    }, 1000);

    try std.testing.expectEqualStrings("repair", decision.phase);
    try std.testing.expectEqualStrings("reauth", decision.action);
    try std.testing.expect(!decision.admitted);
    try std.testing.expect(decision.handoff);
    try std.testing.expectEqualStrings("interactive_not_allowed", decision.reason);
    try std.testing.expectEqual(@as(?i64, 1300), decision.next_tick_after);
    try std.testing.expectEqualStrings("handoff_recheck", decision.schedule_reason);
}

test "daemon tick schedules runtime repair recheck" {
    const decision = daemonTickDecision((config.PolicyConfig{}).daemon, .{
        .route = .{ .provider = "codex", .account = "max-1", .capability = "codex-max" },
        .runtime = .{ .unwritable_store = "/tmp/oauth-mux-test/store" },
        .health = null,
        .budget = .free_local,
        .action = .{
            .kind = .fix_runtime,
            .severity = "error",
            .message = "runtime is not ready",
            .mediation = .local_runtime,
            .budget = .free_local,
        },
        .selectable = false,
        .skip_reason = "unwritable_store",
    }, 1000);

    try std.testing.expectEqualStrings("observe", decision.phase);
    try std.testing.expect(decision.admitted);
    try std.testing.expectEqualStrings("observe_only", decision.reason);
    try std.testing.expectEqual(@as(?i64, 1300), decision.next_tick_after);
    try std.testing.expectEqualStrings("runtime_recheck", decision.schedule_reason);
}

test "daemon tick stats carries earliest schedule reason" {
    const evaluations = [_]RouteEvaluation{
        .{
            .route = .{ .provider = "codex", .account = "max-1", .capability = "codex-max" },
            .runtime = .ready,
            .health = null,
            .budget = .free_local,
            .action = .{
                .kind = .wait_for_quota,
                .severity = "warning",
                .message = "quota exhausted without known reset",
                .mediation = .wait,
                .budget = .free_local,
            },
            .selectable = false,
            .skip_reason = "quota_exhausted",
        },
        .{
            .route = .{ .provider = "codex", .account = "max-2", .capability = "codex-max" },
            .runtime = .{ .unwritable_store = "/tmp/oauth-mux-test/store" },
            .health = null,
            .budget = .free_local,
            .action = .{
                .kind = .fix_runtime,
                .severity = "error",
                .message = "runtime is not ready",
                .mediation = .local_runtime,
                .budget = .free_local,
            },
            .selectable = false,
            .skip_reason = "unwritable_store",
        },
    };
    const stats = daemonTickStats((config.PolicyConfig{}).daemon, &evaluations, 1000);

    try std.testing.expectEqual(@as(?i64, 1300), stats.next_tick_after);
    try std.testing.expect(stats.next_tick_reason != null);
    try std.testing.expectEqualStrings("runtime_recheck", stats.next_tick_reason.?);
}

test "daemon tick sleep honors earlier route wake-up hint" {
    const sleep_ms = daemonTickSleepMs(
        .{ .interval_ms = 60_000 },
        0,
        2,
        .{ .next_tick_after = 1030, .next_tick_reason = "rate_limit" },
        1000,
    );

    try std.testing.expectEqual(@as(u64, 30_000), sleep_ms);
}

test "daemon tick sleep is bounded by configured interval" {
    const sleep_ms = daemonTickSleepMs(
        .{ .interval_ms = 5_000 },
        0,
        2,
        .{ .next_tick_after = 1300, .next_tick_reason = "quota_reset" },
        1000,
    );

    try std.testing.expectEqual(@as(u64, 5_000), sleep_ms);
}

test "daemon tick sleep handles immediate and final wake-up cases" {
    try std.testing.expectEqual(
        @as(u64, 0),
        daemonTickSleepMs(.{ .interval_ms = 60_000 }, 0, 2, .{ .next_tick_after = 1000 }, 1000),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        daemonTickSleepMs(.{ .interval_ms = 60_000 }, 1, 2, .{ .next_tick_after = 1030 }, 1000),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        daemonTickSleepMs(.{ .interval_ms = 0 }, 0, 2, .{ .next_tick_after = 1030 }, 1000),
    );
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

    try std.testing.expectEqual(RepairActionKind.wait_for_quota, action.kind);
    try std.testing.expectEqual(RepairMediation.wait, action.mediation);
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
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mediation\":\"user_handoff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"repair_owner\":\"upstream_cli_login\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"interactive\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mutating\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
}

test "writeRepairActionJson emits claude upstream handoff without codex command" {
    const route = RepairPlanRoute{ .provider = "claude", .account = "pro", .capability = "auth-status" };
    const action = reauthAction(route, provider_schema.claude_def);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeRepairActionJson(buf.writer(), std.testing.allocator, action, route);
    try std.testing.expectEqual(RepairActionKind.reauth, action.kind);
    try std.testing.expectEqual(RepairMediation.user_handoff, action.mediation);
    try std.testing.expectEqual(types.RepairOwner.upstream_cli_login, action.owner.?);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"repair_owner\":\"upstream_cli_login\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":null") != null);
}

test "figma scope degradation carries provider-scope mediation" {
    const route = RepairPlanRoute{ .provider = "figma", .account = "team", .capability = "file-metadata" };
    const action = degradedAction(route, provider_schema.figma_def, .scope_insufficient, .free_command);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeRepairActionJson(buf.writer(), std.testing.allocator, action, route);
    try std.testing.expectEqual(RepairActionKind.scope_or_permission, action.kind);
    try std.testing.expectEqual(RepairMediation.provider_scope, action.mediation);
    try std.testing.expect(action.owner == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mediation\":\"provider_scope\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"repair_owner\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux probe --provider figma --account team --capability file-metadata --json\"") != null);
}

test "writeRepairActionJson emits runtime diagnostic command without executable repair" {
    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const action = repairActionFor(route, provider_schema.codex_def, .{ .unwritable_store = "config_dir" }, null, .spend_provider);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeRepairActionJson(buf.writer(), std.testing.allocator, action, route);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"fix_runtime\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mediation\":\"local_runtime\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"diagnostic_command\":\"oauth-mux doctor runtime --provider codex --account max-1 --capability codex-max --json\"") != null);
}

test "repairRunCandidate skips repair when profile already has selectable route" {
    const dead_route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const live_route = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-max" };
    const evaluations = [_]RouteEvaluation{
        .{
            .route = dead_route,
            .runtime = .{ .needs_reauth = .{ .methods = &.{"upstream_cli_login"}, .reason = "session_file_missing" } },
            .health = null,
            .budget = .spend_provider,
            .action = reauthAction(dead_route, provider_schema.codex_def),
            .selectable = false,
            .skip_reason = "needs_reauth",
        },
        .{
            .route = live_route,
            .runtime = .ready,
            .health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .available } } },
            .budget = .spend_provider,
            .action = .{ .kind = .none, .severity = "ok", .message = "route is selectable" },
            .selectable = true,
            .skip_reason = "available",
        },
    };

    try std.testing.expect(repairRunCandidate(&evaluations, 1, .{ .profile = "codex-max" }) == null);
    try std.testing.expectEqual(@as(?usize, 0), repairRunCandidate(&evaluations, null, .{ .profile = "codex-max" }));
}

test "repair run confirmation json refuses mutating reauth by default" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "config_dir": "/tmp/oauth-mux-test/max-1",
        \\          "secret": { "backend": "file", "path": "/tmp/oauth-mux-test/max-1/auth.json" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const evaluation = RouteEvaluation{
        .route = route,
        .runtime = .{ .needs_reauth = .{ .methods = &.{"upstream_cli_login"}, .reason = "session_file_missing" } },
        .health = null,
        .budget = .spend_provider,
        .action = reauthAction(route, provider_schema.codex_def),
        .selectable = false,
        .skip_reason = "needs_reauth",
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRepairRunConfirmationJson(buf.writer(), std.testing.allocator, parsed.value, evaluation, .{
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
        .json = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"confirmation_required\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"requires\":\"--confirm-repair\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
}

test "repair run json refuses confirmed interactive repair execution" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "config_dir": "/tmp/oauth-mux-test/max-1",
        \\          "secret": { "backend": "file", "path": "/tmp/oauth-mux-test/max-1/auth.json" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const evaluation = RouteEvaluation{
        .route = route,
        .runtime = .{ .needs_reauth = .{ .methods = &.{"upstream_cli_login"}, .reason = "session_file_missing" } },
        .health = null,
        .budget = .spend_provider,
        .action = reauthAction(route, provider_schema.codex_def),
        .selectable = false,
        .skip_reason = "needs_reauth",
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRepairRunJsonInteractiveUnsupported(buf.writer(), std.testing.allocator, parsed.value, evaluation, .{
        .provider = "codex",
        .account = "max-1",
        .capability = "codex-max",
        .confirm_repair = true,
        .json = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"error\":\"interactive_json_unsupported\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"executed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
}

test "route select picks first ready live route and explains skipped quota route" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": { "name": "toy", "display_name": "Toy Provider" }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "a1": { "secret": { "backend": "env", "variable": "TOY_A1" } },
        \\        "a2": { "secret": { "backend": "env", "variable": "TOY_A2" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "work": {
        \\      "providers": ["toy:a1#chat", "toy:a2#chat"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("toy", "a1", "chat", 429, 7200);
    _ = try store.getOrCreate("toy:a2#chat");

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "work" });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    const selected = firstSelectableRoute(evaluations.items).?;
    try std.testing.expectEqual(@as(usize, 1), selected);
    try std.testing.expectEqualStrings("quota_exhausted", evaluations.items[0].skip_reason);
    try std.testing.expect(evaluations.items[1].selectable);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRouteJson(buf.writer(), std.testing.allocator, parsed.value, evaluations.items, selected, .{
        .action = .select,
        .profile = "work",
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selected\":{\"provider\":\"toy\",\"account\":\"a2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":true,\"selectable_fallback_routes\":0,\"spare_fallback_ready\":false,\"single_route_at_risk\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience_actions\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"skip_reason\":\"quota_exhausted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"skip_reason\":\"available\"") != null);
}

test "stay-afloat next emits exact exec argv for selected fallback" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": { "name": "toy", "display_name": "Toy Provider" }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "a1": { "secret": { "backend": "env", "variable": "TOY_A1" } },
        \\        "a2": { "secret": { "backend": "env", "variable": "TOY_A2" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "work": {
        \\      "providers": ["toy:a1#chat", "toy:a2#chat"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("toy", "a1", "chat", 429, 7200);
    _ = try store.getOrCreate("toy:a2#chat");

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "work" });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    const selected = firstSelectableRoute(evaluations.items).?;
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeStayAfloatNextJson(buf.writer(), std.testing.allocator, parsed.value, evaluations.items, selected, null, .{
        .profile = "work",
        .capability = "chat",
        .json = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"action\":\"next\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ready_for_exec\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":true,\"selectable_fallback_routes\":0,\"spare_fallback_ready\":false,\"single_route_at_risk\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience_actions\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"claim\":{\"claim_version\":1,\"level\":\"prepared_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"spare_fallback_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"current_process_hotswap\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"launch_argv\":[\"oauth-mux\",\"stay-afloat\",\"launch\",\"--profile\",\"work\",\"--capability\",\"chat\",\"--\",\"<command>\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"next_action\":{\"kind\":\"exec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"exec_argv\":[\"oauth-mux\",\"exec\",\"--provider\",\"toy\",\"--account\",\"a2\",\"--capability\",\"chat\",\"--\",\"<command>\"]") != null);
}

test "stay-afloat next emits mediated repair action when no route is selectable" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "config_dir": "/tmp/oauth-mux-test/max-1",
        \\          "secret": { "backend": "file", "path": "/tmp/oauth-mux-test/max-1/auth.json" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "needs-reauth": {
        \\      "providers": ["codex:max-1#codex-max"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const evaluations = [_]RouteEvaluation{.{
        .route = route,
        .runtime = .{ .needs_reauth = .{ .methods = &.{"upstream_cli_login"}, .reason = "session_file_missing" } },
        .health = null,
        .budget = .spend_provider,
        .action = reauthAction(route, provider_schema.codex_def),
        .selectable = false,
        .skip_reason = "needs_reauth",
    }};

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeStayAfloatNextJson(buf.writer(), std.testing.allocator, parsed.value, &evaluations, null, 0, .{
        .profile = "needs-reauth",
        .capability = "codex-max",
        .json = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ready_for_exec\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":false,\"selectable_fallback_routes\":0,\"spare_fallback_ready\":false,\"single_route_at_risk\":false,\"state\":\"not_afloat\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"claim\":{\"claim_version\":1,\"level\":\"mediation_required\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"prepared_fallback\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"launch_argv\":[\"oauth-mux\",\"stay-afloat\",\"launch\",\"--profile\",\"needs-reauth\",\"--capability\",\"codex-max\",\"--\",\"<command>\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"next_action\":{\"kind\":\"repair\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"reauth\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mediation\":\"user_handoff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"repair_owner\":\"upstream_cli_login\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-1\"") != null);
}

test "route explain treats unrecorded health as probe needed" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": { "name": "toy", "display_name": "Toy Provider" }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "a1": { "secret": { "backend": "env", "variable": "TOY_A1" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "work": {
        \\      "providers": ["toy:a1#chat"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "work" });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    try std.testing.expect(firstSelectableRoute(evaluations.items) == null);
    try std.testing.expectEqualStrings("unrecorded", evaluations.items[0].skip_reason);
    try std.testing.expectEqual(RepairActionKind.probe_needed, evaluations.items[0].action.kind);
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

test "LiveQaSummary ok is capability coverage not every route availability" {
    const covered_with_unavailable_route = LiveQaSummary{
        .routes_total = 3,
        .routes_available = 2,
        .routes_unavailable = 1,
        .probe_errors = 0,
        .capabilities_total = 2,
        .capabilities_covered = 2,
    };
    try std.testing.expect(covered_with_unavailable_route.ok());
    try std.testing.expectEqual(@as(usize, 0), covered_with_unavailable_route.capabilitiesUncovered());

    const uncovered = LiveQaSummary{
        .routes_total = 3,
        .routes_available = 1,
        .routes_unavailable = 2,
        .probe_errors = 0,
        .capabilities_total = 2,
        .capabilities_covered = 1,
    };
    try std.testing.expect(!uncovered.ok());
    try std.testing.expectEqual(@as(usize, 1), uncovered.capabilitiesUncovered());
    try std.testing.expectEqual(@as(usize, 1), uncovered.failureCount());

    const machinery_error = LiveQaSummary{
        .routes_total = 2,
        .routes_available = 2,
        .probe_errors = 1,
        .capabilities_total = 2,
        .capabilities_covered = 2,
    };
    try std.testing.expect(!machinery_error.ok());
    try std.testing.expectEqual(@as(usize, 1), machinery_error.failureCount());
}

test "seedLiveQaCapabilities deduplicates requested coverage keys" {
    var coverage = std.StringHashMap(bool).init(std.testing.allocator);
    defer freeLiveQaCoverage(std.testing.allocator, &coverage);

    try seedLiveQaCapabilities(std.testing.allocator, &coverage, "codex-mini, codex-max,codex-mini");
    try std.testing.expectEqual(@as(usize, 2), coverage.count());
    try std.testing.expect(coverage.get("codex-mini").? == false);
    try std.testing.expect(coverage.get("codex-max").? == false);

    coverage.getPtr("codex-max").?.* = true;
    try std.testing.expectEqual(@as(usize, 1), countLiveQaCoveredCapabilities(&coverage));
}

test "supervise Codex usage-limit output classifier recognizes native screen" {
    try std.testing.expect(superviseOutputLooksLikeCodexUsageLimit("You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage"));
    try std.testing.expect(superviseOutputLooksLikeCodexUsageLimit("{\"type\":\"usage_limit_reached\"}"));
    try std.testing.expect(!superviseOutputLooksLikeCodexUsageLimit("ordinary child failure"));
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
    _ = @import("repair_state.zig");
}
