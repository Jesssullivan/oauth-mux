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
const warm_scheduler = @import("keepalive/warm_scheduler.zig");
const warm_binding = @import("keepalive/warm_binding.zig");
const warm_runner = @import("keepalive/warm_runner.zig");
const provider_schema = @import("provider_schema.zig");
const daemon = @import("daemon.zig");
const repair_state = @import("repair_state.zig");
const runtime_mod = @import("runtime.zig");
const secret_mod = @import("secret.zig");
const trace = @import("trace.zig");
const broker = @import("broker/mod.zig");
const broker_loader = @import("broker_loader.zig");
const codex_adapter = @import("adapters/codex/main.zig");
const identity_hash = @import("identity_hash.zig");
const advise = @import("quota/advise.zig");
const doctor_binaries = @import("doctor_binaries.zig");

comptime {
    // Pull broker + adapter modules into the test build.
    _ = broker;
    _ = broker_loader;
    _ = codex_adapter;
    _ = trace;
    _ = @import("adapters/codex/app_server_client.zig");
    _ = @import("adapters/codex/wire_proxy.zig");
}

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
        .version_cmd => |version_args| {
            if (version_args.json) {
                try writeVersionJson(allocator, stdout);
            } else {
                try stdout.print("oauth-mux {s}\n", .{cli.version});
            }
        },
        .help => try cli.printUsage(stdout),
        .codex_help => try cli.printCodexUsage(stdout),

        .codex_adapter => |adapter_args| {
            // `oauth-mux codex run`: broker-mediated Codex adapter
            // session. Anchor:
            // docs/spec/codex-adapter-contract-2026-05-03.md.
            if (adapter_args.invalid_option) |arg| {
                log.err("oauth-mux codex run: unknown adapter option \"{s}\". Use `oauth-mux codex <codex-args...>` or `oauth-mux codex run -- <codex-args...>`.", .{arg});
                std.process.exit(types.ExitCode.general_error.int());
            }
            codex_adapter.run(allocator, .{
                .profile = adapter_args.profile,
                .capability = adapter_args.capability,
                .account = adapter_args.account,
                .session_home = adapter_args.session_home,
                .isolated_session_store = adapter_args.isolated_session_store,
                .mux_mode = if (adapter_args.mux_mode) |m| switch (m) {
                    .isolated_persistent => codex_adapter.MuxMode.isolated_persistent,
                    .shared_canonical => codex_adapter.MuxMode.shared_canonical,
                } else null,
                .json_status = adapter_args.json_status,
                .json_status_file = adapter_args.json_status_file,
                .forward_argv = adapter_args.forward_argv,
            }) catch |e| {
                log.err("codex run: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },

        .mcp => |mcp_args| {
            // Broker MCP server on stdio. Anchor:
            // docs/spec/broker-mcp-contract-2026-05-03.md.
            const parsed = config.load(allocator) catch |e| switch (e) {
                error.FileNotFound => {
                    log.err("mcp: no oauth-mux config found; run `oauth-mux init` first", .{});
                    std.process.exit(types.ExitCode.config_error.int());
                },
                else => {
                    log.err("mcp: config load: {s}", .{@errorName(e)});
                    std.process.exit(types.ExitCode.config_error.int());
                },
            };
            defer parsed.deinit();

            var server = broker.Server.init(allocator);
            defer server.deinit();

            var route_health = health_mod.HealthStore.load(allocator, .{});
            defer route_health.deinit();

            broker_loader.populatePoolFromRouteHealthScoped(&server.pool, parsed.value, mcp_args.profile, mcp_args.capability, &route_health) catch |e| {
                log.err("mcp: pool populate: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };

            var mat_ctx = broker_loader.ChatgptMaterializerCtx{ .cfg = &parsed.value };
            server.setMaterializer(mat_ctx.vtable());

            log.info("mcp: broker surface_version={d} accounts={d} profile={s} capability={s}", .{
                broker.SURFACE_VERSION,
                server.pool.accounts.items.len,
                mcp_args.profile orelse "(none)",
                mcp_args.capability orelse "(none)",
            });

            server.runStdio() catch |e| {
                log.err("mcp: server: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },

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

        .stay_afloat_observe => |observe_args| {
            runStayAfloatObserve(allocator, stdout, observe_args) catch |e| {
                log.err("stay-afloat observe: {s}", .{@errorName(e)});
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

        .keepalive => |ka_args| {
            runKeepalive(allocator, stdout, ka_args) catch |e| {
                log.err("keepalive: {s}", .{@errorName(e)});
                std.process.exit(types.ExitCode.general_error.int());
            };
        },

        .reauth => |reauth_args| {
            runReauth(allocator, stdout, reauth_args) catch |e| {
                log.err("reauth: {s}", .{@errorName(e)});
                std.process.exit(exitCodeFromPipelineError(e));
            };
        },

        .completions => |comp_args| {
            try cli.printCompletions(stdout, comp_args.shell);
        },

        .daemon_run => |run_args| {
            if (run_args.stay_afloat) {
                runForegroundStayAfloatLoop(allocator, stdout, run_args.tick) catch |e| {
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

/// Bounded real-sleep wait for the foreground keepalive loop: terminates after
/// `remaining` more waits (so the loop runs a fixed number of ticks), and caps
/// each sleep at `cap_ms` so a far-future due instant still re-ticks periodically.
/// runLoop floors a past/now wake before calling this, so there is no busy-spin.
const KeepaliveWait = struct {
    remaining: u32,
    cap_ms: u64,
    fn wait(ctx: *anyopaque, wake_at_ms: i64) bool {
        const self: *KeepaliveWait = @ptrCast(@alignCast(ctx));
        if (self.remaining == 0) return false;
        self.remaining -= 1;
        const now = std.time.milliTimestamp();
        const sleep_ms = boundedKeepaliveSleepMs(wake_at_ms, now, self.cap_ms);
        if (sleep_ms > 0) std.time.sleep(sleep_ms * std.time.ns_per_ms);
        return true;
    }
};

fn boundedKeepaliveSleepMs(wake_at_ms: i64, now_ms: i64, cap_ms: u64) u64 {
    if (wake_at_ms <= now_ms or cap_ms == 0) return 0;

    const raw_delta = std.math.sub(i64, wake_at_ms, now_ms) catch std.math.maxInt(i64);
    const delta: u64 = @intCast(raw_delta);
    // Clamp to a sane max (24h) so an absurd operator --interval-ms can't
    // overflow the u64 ns multiply, and the loop never sleeps past a day.
    const max_ms: u64 = 24 * 60 * 60 * 1000;
    return @min(@min(delta, cap_ms), max_ms);
}

/// `oauth-mux keepalive` — run the warm-loop scheduler over every configured
/// account: proactively refresh each at ~75% of its token lifetime so an agent
/// never hits a dead token. SAFE: refreshAccount refuses any account whose
/// proactive_refresh is not admitted — the claude/codex providers now declare the
/// grant (TIN-2057), but admission still requires the account to set
/// `allow_proactive_refresh: true` (defaults false), so an account that hasn't
/// opted in only records refusals. Bounded by `iterations` (default 1).
fn runKeepalive(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.KeepaliveArgs) !void {
    const parsed = config.load(allocator) catch |e| {
        if (args.json) {
            try writer.writeAll("{\"error\":\"config not found\"}\n");
        } else {
            log.err("keepalive: config load: {s}", .{@errorName(e)});
        }
        return e;
    };
    defer parsed.deinit();
    const cfg = parsed.value;

    var health = health_mod.HealthStore.load(allocator, .{});
    defer health.deinit();

    // Build the warm pool from live config + credential expiry.
    var pool = try warm_runner.enumeratePool(allocator, cfg, &health);
    defer pool.deinit();
    const accounts = try warm_binding.buildPool(allocator, pool.observed, std.time.milliTimestamp());
    defer allocator.free(accounts); // freed BEFORE pool.deinit (accounts borrow pool keys)

    // Bind the scheduler to the live refresh path (proactive; refuses ungranted).
    var wr = warm_runner.WarmRunner{ .allocator = allocator, .cfg = cfg, .health = &health };
    var binding = warm_binding.RefreshBinding{ .do_refresh = warm_runner.WarmRunner.doRefresh, .do_refresh_ctx = &wr };
    const sched = warm_scheduler.Scheduler{
        .clock = warm_runner.WarmRunner.clock,
        .clock_ctx = &wr,
        .refresh = warm_binding.RefreshBinding.refresh,
        .refresh_ctx = &binding,
    };

    var wait_ctx = KeepaliveWait{ .remaining = args.iterations -| 1, .cap_ms = args.interval_ms };
    const report = warm_binding.runLoop(&sched, accounts, KeepaliveWait.wait, &wait_ctx);

    if (args.json) {
        try writer.print(
            "{{\"accounts\":{d},\"ticks\":{d},\"refreshed\":{d},\"failed\":{d},\"died\":{d},\"drained\":{}}}\n",
            .{ accounts.len, report.ticks, report.refreshed, report.failed, report.died, report.drained },
        );
    } else {
        try writer.print(
            "keepalive: {d} account(s); {d} tick(s) — refreshed={d} failed={d} died={d} drained={}\n",
            .{ accounts.len, report.ticks, report.refreshed, report.failed, report.died, report.drained },
        );
    }
}

fn writeVersionJson(allocator: std.mem.Allocator, writer: anytype) !void {
    const identity = try runtime_mod.oauthMuxRuntimeIdentity(allocator, cli.version, cli.build_id);
    defer identity.deinit(allocator);

    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"runtime_identity\":");
    try identity.writeJson(writer);
    try writer.writeAll("}\n");
}

fn exitCodeFromPipelineError(e: anyerror) u8 {
    return switch (e) {
        error.ConfigNotFound, error.ConfigParseError, error.ConfigValidationError => types.ExitCode.config_error.int(),
        error.AllAccountsExhausted => types.ExitCode.all_accounts_exhausted.int(),
        error.SecretReadFailed, error.SecretDecryptFailed => types.ExitCode.secret_read_failed.int(),
        error.TokenRefreshFailed => types.ExitCode.token_refresh_failed.int(),
        error.NetworkError => types.ExitCode.network_error.int(),
        // TIN-2054: misconfigured account (Claude without a config_dir) — a
        // config-shaped error, surfaced as such for scripts/agents.
        error.ProviderNeedsConfigDir => types.ExitCode.config_error.int(),
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

    // Load the persisted liveness rows read-only, exactly as runAccounts does, so
    // the valet advisor can fold them into a model-class quota view. `now` is read
    // ONCE here at the effect boundary (Unix ms — advise.zig never reads a clock).
    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();
    const now_ms = std.time.milliTimestamp();

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
        try writer.writeAll("\n  },\n");
        try writeAdviceJson(writer, allocator, &store, now_ms);
        try writer.writeAll("\n}\n");
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
        try writer.writeByte('\n');
        try writeAdviceText(writer, allocator, &store, now_ms);
    }
}

// ── valet advice rendering (TIN-2719 M0 PR2) ──────────────────────────────────
//
// The status surface is the first product consumer of the pure advisor core
// (`advise.zig`, PR #449). We fold every persisted HealthStore liveness row into
// the advisor and render its honest, provenance-tagged model-class view.

// The declared model-class set the advisor summarizes. Hardcoded HERE at the call
// site because advise.zig correctly refuses to own the list, and provider_schema
// does not yet declare per-model classes (claude's only capability today is
// "auth-status", NOT a model class — see provider_schema.claude_capabilities).
// TIN-2722 follow-up: move this list into provider_schema so the advisor consumes
// provider-owned declarations instead of this call-site const.
const advice_declared_classes = [_]advise.DeclaredClass{
    .{ .provider = "claude", .class = "opus" },
    .{ .provider = "claude", .class = "fable" },
    .{ .provider = "claude", .class = "sonnet" },
    .{ .provider = "claude", .class = "haiku" },
};

/// Adapt one persisted `CredentialLiveness` into the flat `advise.Row` quota/
/// credential fields. The credential `state` and the quota `availability` are
/// DISJOINT dimensions (advise.zig honesty boundary); timestamps stay in health
/// SECONDS — advise's boundary converts them to ms. `provider`/`account`/`class`
/// are the parsed route key (class = the capability slug, or "" when the row is
/// account-scoped — either way it never matches a declared model class today).
fn adviceRowFromHealth(
    provider_name: []const u8,
    account: []const u8,
    class: []const u8,
    liveness: types.CredentialLiveness,
) advise.Row {
    var row = advise.Row{ .provider = provider_name, .account = account, .class = class };
    switch (liveness) {
        .live => |live| {
            row.state = "live";
            switch (live.availability) {
                .available => row.availability = "available",
                .rate_limited => |rl| {
                    row.availability = "rate_limited";
                    row.retry_after_s = rl.retry_after_s;
                    row.limited_at = rl.limited_at;
                },
                .quota_exhausted => |q| {
                    row.availability = "quota_exhausted";
                    row.window_resets_at = q.window_resets_at;
                    row.usage_pct = q.usage_pct;
                    row.exhausted_at = q.exhausted_at;
                },
                .cooldown => |c| {
                    row.availability = "cooldown";
                    row.cooldown_until = c.until;
                },
            }
        },
        .degraded => |d| {
            row.state = "degraded";
            row.since = d.since;
        },
        .dead => |d| {
            row.state = "dead";
            row.since = d.since;
        },
    }
    return row;
}

/// Fold every persisted liveness row into the advisor. Row slices borrow the
/// store's key strings and static literals, so they stay valid for the returned
/// `Advice`; the suggestion copies its own slices out of the winning row (which
/// point into the store, not `rows`), so freeing `rows` after this returns is safe.
/// `out_classes` is caller-owned and must outlive the returned `Advice`.
fn computeAdvice(
    allocator: std.mem.Allocator,
    store: *health_mod.HealthStore,
    now_ms: i64,
    out_classes: []advise.ClassSummary,
) !advise.Advice {
    var rows = std.ArrayList(advise.Row).init(allocator);
    defer rows.deinit();
    var it = store.accounts.iterator();
    while (it.next()) |entry| {
        const parts = health_mod.parseHealthKey(entry.key_ptr.*) orelse continue;
        try rows.append(adviceRowFromHealth(
            parts.provider,
            parts.account,
            parts.capability orelse "",
            entry.value_ptr.liveness,
        ));
    }
    // demand = unconstrained (M0); excluded_accounts = empty for now — identity-
    // dedupe exclusion wiring is a follow-up.
    return advise.advise(rows.items, &advice_declared_classes, .{}, &.{}, now_ms, out_classes);
}

fn effectiveStatusName(status: @import("quota/bucket.zig").EffectiveStatus) []const u8 {
    return switch (status) {
        .available => "available",
        .waiting => "waiting",
        .tier_blocked => "tier_blocked",
        .plan_gated => "plan_gated",
    };
}

fn provenanceName(p: advise.Provenance) []const u8 {
    return switch (p) {
        .unobserved => "unobserved",
        .assumed => "assumed",
        .inferred => "inferred",
        .proven => "proven",
    };
}

fn writeAdviceJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    store: *health_mod.HealthStore,
    now_ms: i64,
) !void {
    var class_buf: [advice_declared_classes.len]advise.ClassSummary = undefined;
    const adv = try computeAdvice(allocator, store, now_ms, &class_buf);

    try writer.writeAll("  \"advice\": {\n");
    try writer.print("    \"generated_at_ms\": {d},\n", .{now_ms});
    try writer.writeAll("    \"model_classes\": [");
    for (adv.classes, 0..) |cs, i| {
        if (i != 0) try writer.writeByte(',');
        try writer.writeAll("\n      {\"provider\": ");
        try std.json.stringify(cs.provider, .{}, writer);
        try writer.writeAll(", \"class\": ");
        try std.json.stringify(cs.class, .{}, writer);
        try writer.writeAll(", \"status\": ");
        try std.json.stringify(effectiveStatusName(cs.status), .{}, writer);
        try writer.writeAll(", \"usage_pct\": ");
        if (cs.usage_pct) |u| try writer.print("{d}", .{u}) else try writer.writeAll("null");
        try writer.writeAll(", \"resets_at_ms\": ");
        if (cs.resets_at) |r| try writer.print("{d}", .{r}) else try writer.writeAll("null");
        try writer.writeAll(", \"provenance\": ");
        try std.json.stringify(provenanceName(cs.provenance), .{}, writer);
        try writer.writeByte('}');
    }
    try writer.writeAll("\n    ],\n");

    try writer.writeAll("    \"next_account\": ");
    if (adv.suggestion) |s| {
        try writer.writeAll("{\"provider\": ");
        try std.json.stringify(s.provider, .{}, writer);
        try writer.writeAll(", \"account\": ");
        try std.json.stringify(s.account, .{}, writer);
        try writer.writeAll(", \"class\": ");
        try std.json.stringify(s.class, .{}, writer);
        try writer.writeAll(", \"reason\": ");
        try std.json.stringify(s.reason, .{}, writer);
        try writer.writeAll(", \"provenance\": ");
        try std.json.stringify(provenanceName(s.provenance), .{}, writer);
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\n");

    try writer.writeAll("    \"wait_until_ms\": ");
    if (adv.wait_until) |w| try writer.print("{d}", .{w}) else try writer.writeAll("null");
    try writer.writeAll("\n  }");
}

fn writeAdviceText(
    writer: anytype,
    allocator: std.mem.Allocator,
    store: *health_mod.HealthStore,
    now_ms: i64,
) !void {
    var class_buf: [advice_declared_classes.len]advise.ClassSummary = undefined;
    const adv = try computeAdvice(allocator, store, now_ms, &class_buf);

    // One summary line per distinct provider present in the declared class set.
    for (advice_declared_classes, 0..) |dc, i| {
        var seen_before = false;
        for (advice_declared_classes[0..i]) |prev| {
            if (std.mem.eql(u8, prev.provider, dc.provider)) seen_before = true;
        }
        if (seen_before) continue;

        var total: usize = 0;
        var unobserved: usize = 0;
        for (adv.classes) |cs| {
            if (!std.mem.eql(u8, cs.provider, dc.provider)) continue;
            total += 1;
            if (cs.provenance == .unobserved) unobserved += 1;
        }

        if (unobserved == total) {
            try writer.print("  advice: {s} — all classes unobserved (no quota signal recorded)\n", .{dc.provider});
        } else if (adv.suggestion) |s| {
            if (std.mem.eql(u8, s.provider, dc.provider)) {
                try writer.print("  advice: {s} — suggest {s} for {s} ({s})\n", .{
                    dc.provider, s.account, s.class, provenanceName(s.provenance),
                });
            } else {
                try writer.print("  advice: {s} — {d}/{d} classes observed\n", .{ dc.provider, total - unobserved, total });
            }
        } else {
            try writer.print("  advice: {s} — {d}/{d} classes observed\n", .{ dc.provider, total - unobserved, total });
        }
    }
}

test "advice rendering: empty store → all four claude classes unobserved, no suggestion" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var class_buf: [advice_declared_classes.len]advise.ClassSummary = undefined;
    const adv = try computeAdvice(std.testing.allocator, &store, 1_000_000, &class_buf);
    try std.testing.expectEqual(advice_declared_classes.len, adv.classes.len);
    for (adv.classes) |cs| {
        try std.testing.expectEqual(advise.Provenance.unobserved, cs.provenance);
    }
    try std.testing.expect(adv.suggestion == null);
    try std.testing.expect(adv.wait_until == null);
}

test "advice rendering honesty: auth-status-only claude rows → all four model classes unobserved" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Today's HealthStore records only the "auth-status" capability for claude — a
    // credential-liveness row, NOT a per-model quota signal (provider_schema
    // declares no per-model classes yet). Both accounts are credential-live.
    const h1 = try store.getOrCreate("claude:acct-a#auth-status");
    h1.liveness = .{ .live = .{ .availability = .available } };
    const h2 = try store.getOrCreate("claude:acct-b#auth-status");
    h2.liveness = .{ .live = .{ .availability = .available } };

    var class_buf: [advice_declared_classes.len]advise.ClassSummary = undefined;
    const adv = try computeAdvice(std.testing.allocator, &store, 1_000_000, &class_buf);

    // The honesty invariant: no persisted row proves a per-model quota, so every
    // declared model class MUST render `unobserved`.
    try std.testing.expectEqual(@as(usize, 4), adv.classes.len);
    for (adv.classes) |cs| {
        try std.testing.expectEqual(advise.Provenance.unobserved, cs.provenance);
    }
    // next_account is null-or-inferred-only: an auth-status row can lift an account
    // to `inferred` (credential-ready, no quota signal against it) but never higher.
    if (adv.suggestion) |s| {
        try std.testing.expectEqual(advise.Provenance.inferred, s.provenance);
    }
}

test "advice rendering: sole quota_exhausted opus row → waiting + resets_at + wait_until" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // A synthetic per-model quota signal on the opus route: the window resets at
    // 2000s. now = 1000s (in ms) is before the reset → the class is waiting.
    const h = try store.getOrCreate("claude:acct-a#opus");
    h.liveness = .{
        .live = .{
            .availability = .{
                .quota_exhausted = .{
                    .window_resets_at = 2000, // health SECONDS; advise converts to ms
                    .exhausted_at = 100,
                },
            },
        },
    };

    var class_buf: [advice_declared_classes.len]advise.ClassSummary = undefined;
    const now_ms: i64 = 1000 * 1000;
    const adv = try computeAdvice(std.testing.allocator, &store, now_ms, &class_buf);

    var opus: ?advise.ClassSummary = null;
    for (adv.classes) |cs| {
        if (std.mem.eql(u8, cs.class, "opus")) opus = cs;
    }
    try std.testing.expect(opus != null);
    try std.testing.expectEqual(@import("quota/bucket.zig").EffectiveStatus.waiting, opus.?.status);
    try std.testing.expectEqual(@as(?i64, 2000 * 1000), opus.?.resets_at); // reset in ms
    try std.testing.expectEqual(advise.Provenance.inferred, opus.?.provenance);

    // It is the sole candidate and it is waiting → no suggestion, wait_until = reset.
    try std.testing.expect(adv.suggestion == null);
    try std.testing.expectEqual(@as(?i64, 2000 * 1000), adv.wait_until);

    // The other three declared classes remain unobserved.
    for (adv.classes) |cs| {
        if (!std.mem.eql(u8, cs.class, "opus")) {
            try std.testing.expectEqual(advise.Provenance.unobserved, cs.provenance);
        }
    }
}

test "advice JSON shape: unobserved-first block renders expected keys" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeAdviceJson(buf.writer(), std.testing.allocator, &store, 4242);
    const s = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, s, "\"advice\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"generated_at_ms\": 4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"model_classes\": [") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"class\": \"opus\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"status\": \"available\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"provenance\": \"unobserved\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"next_account\": null") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"wait_until_ms\": null") != null);
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
            {
                const ent = accountEntitlement(allocator, account, kind);
                defer ent.deinit(allocator);
                try writeEntitlementLabel(writer, ent);
            }
            try writer.writeByte('\n');

            for (def.capabilities) |capability| {
                const route = RepairPlanRoute{ .provider = provider_name, .account = account_name, .capability = capability.name };
                const runtime = try routeRuntimeReadiness(allocator, cfg, route, def);
                const health = routeHealth(allocator, store, route);
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
    try writer.writeAll("],\"auth_identity\":");
    try writeAccountAuthIdentityJson(writer, allocator, account, kind);
    try writer.writeAll(",\"entitlement\":");
    try writeAccountEntitlementJson(writer, allocator, account, kind);
    try writer.writeAll(",\"runtime\":");
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
    const health = routeHealth(allocator, store, route);
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

// ── Entitlement surfacing (TIN-2719) ──────────────────────────────────────────
//
// Surface subscription/tier/plan labels as polled truth in `accounts list`.
// These are non-secret plan labels the provider already stamps into the stored
// credential blob (claude: claudeAiOauth.subscriptionType + rateLimitTier,
// preserved by the TIN-2074 field-preserving merge; codex: chatgpt_plan_type in
// the id_token JWT). We READ the credential but only ever emit the labels —
// never any accessToken/refreshToken substring (invariant test below).
//
// Read tolerance matches the liveness/broker precedent: any secret read failure
// (missing item, denied ACL, decrypt/command error) degrades to `.none` → null.
// A granted keychain ACL keeps the macOS read non-interactive; this path never
// forces a prompt — a blocked/denied read is an operator/ACL condition that
// simply renders null, exactly like every other read-only inventory surface.

const ClaudeEntitlement = struct {
    subscription_type: ?[]u8 = null,
    rate_limit_tier: ?[]u8 = null,

    fn any(self: ClaudeEntitlement) bool {
        return self.subscription_type != null or self.rate_limit_tier != null;
    }
    fn deinit(self: ClaudeEntitlement, allocator: std.mem.Allocator) void {
        if (self.subscription_type) |v| allocator.free(v);
        if (self.rate_limit_tier) |v| allocator.free(v);
    }
};

const CodexEntitlement = struct {
    plan_type: ?[]u8 = null,

    fn deinit(self: CodexEntitlement, allocator: std.mem.Allocator) void {
        if (self.plan_type) |v| allocator.free(v);
    }
};

const AccountEntitlement = union(enum) {
    none,
    claude: ClaudeEntitlement,
    codex: CodexEntitlement,

    fn deinit(self: AccountEntitlement, allocator: std.mem.Allocator) void {
        switch (self) {
            .none => {},
            .claude => |c| c.deinit(allocator),
            .codex => |c| c.deinit(allocator),
        }
    }
};

/// Read the account's stored credential blob and distill it to non-secret
/// entitlement labels. Any read failure (missing/denied/errored secret) yields
/// `.none`; the raw blob is freed before returning so token material never
/// escapes this frame.
fn accountEntitlement(
    allocator: std.mem.Allocator,
    account: config.AccountConfig,
    kind: ?types.ProviderKind,
) AccountEntitlement {
    const k = kind orelse return .none;
    switch (k) {
        .claude, .codex => {},
        .gemini, .vercel, .github, .mcp => return .none,
    }
    const backend = config.resolveSecretBackend(account.secret) catch return .none;
    if (!entitlementInventoryBackendAllowed(backend)) return .none;
    const raw = secret_mod.read(backend, allocator) catch return .none;
    defer allocator.free(raw);
    return accountEntitlementFromRaw(allocator, k, raw);
}

// Inventory invariant: `accounts list` is read-only and must not run arbitrary
// commands, read stdin, or trigger decrypt/passphrase helper paths just to
// decorate a row. Keychain is admitted because Claude's normal liveness path is
// keychain-backed; a denied or locked keychain read degrades to null above.
fn entitlementInventoryBackendAllowed(backend: types.SecretBackend) bool {
    return switch (backend) {
        .file, .env, .keychain => true,
        .sops, .age, .command, .stdin => false,
    };
}

/// Parse a credential blob (already read into memory) into entitlement labels.
/// Split from `accountEntitlement` so the no-token-leak invariant can be tested
/// against a synthetic in-memory blob without touching a secret backend.
fn accountEntitlementFromRaw(
    allocator: std.mem.Allocator,
    kind: types.ProviderKind,
    raw: []const u8,
) AccountEntitlement {
    switch (kind) {
        .claude => {
            const c = parseClaudeEntitlement(allocator, raw);
            if (!c.any()) {
                c.deinit(allocator);
                return .none;
            }
            return .{ .claude = c };
        },
        .codex => {
            const plan = parseCodexPlanType(allocator, raw) orelse return .none;
            return .{ .codex = .{ .plan_type = plan } };
        },
        .gemini, .vercel, .github, .mcp => return .none,
    }
}

fn parseClaudeEntitlement(allocator: std.mem.Allocator, raw: []const u8) ClaudeEntitlement {
    const Inner = struct {
        subscriptionType: ?[]const u8 = null,
        rateLimitTier: ?[]const u8 = null,
    };
    const Blob = struct {
        claudeAiOauth: ?Inner = null,
        subscriptionType: ?[]const u8 = null,
        rateLimitTier: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Blob, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return .{};
    defer parsed.deinit();

    var sub: ?[]const u8 = if (parsed.value.claudeAiOauth) |inner| inner.subscriptionType else null;
    var tier: ?[]const u8 = if (parsed.value.claudeAiOauth) |inner| inner.rateLimitTier else null;
    if (sub == null) sub = parsed.value.subscriptionType;
    if (tier == null) tier = parsed.value.rateLimitTier;

    return .{
        .subscription_type = dupNonEmpty(allocator, sub),
        .rate_limit_tier = dupNonEmpty(allocator, tier),
    };
}

fn parseCodexPlanType(allocator: std.mem.Allocator, raw: []const u8) ?[]u8 {
    const parsed = std.json.parseFromSlice(CodexBrokerAuthJson, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return null;
    defer parsed.deinit();
    const tokens = parsed.value.tokens orelse return null;
    return codexPlanTypeValueAlloc(allocator, tokens) catch null;
}

fn dupNonEmpty(allocator: std.mem.Allocator, value: ?[]const u8) ?[]u8 {
    const v = nonEmpty(value) orelse return null;
    return allocator.dupe(u8, v) catch null;
}

fn writeAccountEntitlementJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    account: config.AccountConfig,
    kind: ?types.ProviderKind,
) !void {
    const ent = accountEntitlement(allocator, account, kind);
    defer ent.deinit(allocator);
    try writeEntitlementJson(writer, ent);
}

fn writeEntitlementJson(writer: anytype, ent: AccountEntitlement) !void {
    switch (ent) {
        .none => try writer.writeAll("null"),
        .claude => |c| {
            try writer.writeAll("{\"subscription_type\":");
            if (c.subscription_type) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
            try writer.writeAll(",\"rate_limit_tier\":");
            if (c.rate_limit_tier) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
            try writer.writeByte('}');
        },
        .codex => |c| {
            try writer.writeAll("{\"plan_type\":");
            if (c.plan_type) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
            try writer.writeByte('}');
        },
    }
}

fn writeEntitlementLabel(writer: anytype, ent: AccountEntitlement) !void {
    switch (ent) {
        .none => {},
        .claude => |c| {
            try writer.writeAll(" [");
            var wrote = false;
            if (c.subscription_type) |v| {
                try writer.writeAll(v);
                wrote = true;
            }
            if (c.rate_limit_tier) |v| {
                if (wrote) try writer.writeByte('/');
                try writer.writeAll(v);
            }
            try writer.writeByte(']');
        },
        .codex => |c| {
            if (c.plan_type) |v| {
                try writer.writeAll(" [");
                try writer.writeAll(v);
                try writer.writeByte(']');
            }
        },
    }
}

const AccountAuthIdentity = struct {
    checked: bool = false,
    present: bool = false,
    reason: []const u8 = "not_checked",
    source: ?[]const u8 = null,
    email_hint: ?[]u8 = null,
    account_id_hash: ?[]u8 = null,
    account_id_source: ?[]const u8 = null,
    plan_type_present: bool = false,
    plan_type_source: ?[]const u8 = null,

    fn deinit(self: AccountAuthIdentity, allocator: std.mem.Allocator) void {
        if (self.email_hint) |value| allocator.free(value);
        if (self.account_id_hash) |value| allocator.free(value);
    }
};

fn writeAccountAuthIdentityJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    account: config.AccountConfig,
    kind: ?types.ProviderKind,
) !void {
    const identity = try accountAuthIdentity(allocator, account, kind);
    defer identity.deinit(allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"checked\":");
    try writer.writeAll(if (identity.checked) "true" else "false");
    try writer.writeAll(",\"present\":");
    try writer.writeAll(if (identity.present) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(identity.reason, .{}, writer);
    try writer.writeAll(",\"source\":");
    if (identity.source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"email_hint\":");
    if (identity.email_hint) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"email_redaction\":\"local_part_masked\"");
    try writer.writeAll(",\"account_id_hash\":");
    if (identity.account_id_hash) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account_id_hash_algo\":\"sha256_12hex\"");
    try writer.writeAll(",\"account_id_source\":");
    if (identity.account_id_source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"plan_type_present\":");
    try writer.writeAll(if (identity.plan_type_present) "true" else "false");
    try writer.writeAll(",\"plan_type_source\":");
    if (identity.plan_type_source) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"path_printed\":false,\"token_material_printed\":false,\"raw_email_printed\":false}");
}

fn accountAuthIdentity(
    allocator: std.mem.Allocator,
    account: config.AccountConfig,
    kind: ?types.ProviderKind,
) !AccountAuthIdentity {
    if (kind == null or kind.? != .codex) return .{ .reason = "provider_not_codex" };
    if (!std.mem.eql(u8, account.secret.backend, "file")) {
        return .{ .checked = false, .reason = "secret_backend_not_read_for_inventory" };
    }

    const raw = try readCodexAuthJsonForInventory(allocator, account) orelse {
        return .{ .checked = true, .reason = "auth_json_unavailable" };
    };
    defer allocator.free(raw);
    return inspectCodexAccountAuthIdentity(allocator, raw);
}

fn readCodexAuthJsonForInventory(allocator: std.mem.Allocator, account: config.AccountConfig) !?[]u8 {
    if (account.secret.path) |path| {
        const expanded = try paths.expandTilde(allocator, path);
        defer allocator.free(expanded);
        return std.fs.cwd().readFileAlloc(allocator, expanded, 2 * 1024 * 1024) catch |e| switch (e) {
            error.FileNotFound, error.AccessDenied => null,
            else => return e,
        };
    }
    const config_dir = account.config_dir orelse return null;
    const expanded_dir = try paths.expandTilde(allocator, config_dir);
    defer allocator.free(expanded_dir);
    const auth_path = try std.fs.path.join(allocator, &.{ expanded_dir, "auth.json" });
    defer allocator.free(auth_path);
    return std.fs.cwd().readFileAlloc(allocator, auth_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied => null,
        else => return e,
    };
}

fn inspectCodexAccountAuthIdentity(allocator: std.mem.Allocator, raw: []const u8) !AccountAuthIdentity {
    const parsed = std.json.parseFromSlice(CodexBrokerAuthJson, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return .{ .checked = true, .reason = "auth_json_invalid" };
    defer parsed.deinit();

    const tokens = parsed.value.tokens orelse return .{ .checked = true, .reason = "tokens_missing" };
    const email = try codexEmailValueAlloc(allocator, tokens);
    defer if (email) |value| allocator.free(value);
    const account_id = try codexAccountIdValueAlloc(allocator, tokens);
    defer if (account_id) |value| allocator.free(value);
    const account_id_source = codexAccountIdSource(allocator, tokens);
    const plan_type_source = codexPlanTypeSource(allocator, tokens);
    const present = email != null or account_id != null or plan_type_source != null;

    return .{
        .checked = true,
        .present = present,
        .reason = if (present) "identity_claims_present" else "identity_claims_missing",
        .source = "codex_auth_json_tokens",
        .email_hint = if (email) |value| try maskEmailHint(allocator, value) else null,
        .account_id_hash = if (account_id) |value| try shortSha256HexAlloc(allocator, value) else null,
        .account_id_source = account_id_source,
        .plan_type_present = plan_type_source != null,
        .plan_type_source = plan_type_source,
    };
}

fn codexEmailValueAlloc(allocator: std.mem.Allocator, tokens: CodexBrokerTokensJson) !?[]u8 {
    if (try jwtStringClaimAlloc(allocator, tokens.id_token, "email")) |value| return value;
    if (try jwtStringClaimAlloc(allocator, tokens.access_token, "email")) |value| return value;
    if (try jwtAuthStringClaimAlloc(allocator, tokens.id_token, "email")) |value| return value;
    if (try jwtAuthStringClaimAlloc(allocator, tokens.access_token, "email")) |value| return value;
    return null;
}

fn jwtStringClaimAlloc(allocator: std.mem.Allocator, maybe_jwt: ?[]const u8, field: []const u8) !?[]u8 {
    const jwt = nonEmpty(maybe_jwt) orelse return null;
    const payload = jwtPayloadJsonAlloc(allocator, jwt) catch return null;
    defer allocator.free(payload);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    return switch (root.get(field) orelse return null) {
        .string => |value| if (value.len == 0) null else try allocator.dupe(u8, value),
        else => null,
    };
}

fn maskEmailHint(allocator: std.mem.Allocator, email: []const u8) ![]u8 {
    const at = std.mem.indexOfScalar(u8, email, '@') orelse return try allocator.dupe(u8, "<non-email-identity>");
    const local = email[0..at];
    const domain = email[at + 1 ..];
    if (local.len == 0 or domain.len == 0) return try allocator.dupe(u8, "<invalid-email-identity>");
    return try std.fmt.allocPrint(allocator, "{c}***@{s}", .{ local[0], domain });
}

fn shortSha256HexAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    // Delegates to the shared module so the codex adapter's muxxing identity
    // guard (TIN-1851) computes the SAME account-id hash as this inventory path.
    return identity_hash.sha256_12hex(allocator, value);
}

test "maskEmailHint masks local part and keeps domain for account inventory" {
    const masked = try maskEmailHint(std.testing.allocator, "jess@example.com");
    defer std.testing.allocator.free(masked);
    try std.testing.expectEqualStrings("j***@example.com", masked);
}

test "shortSha256HexAlloc emits stable twelve character account id hash" {
    const hashed = try shortSha256HexAlloc(std.testing.allocator, "acct-test");
    defer std.testing.allocator.free(hashed);
    try std.testing.expectEqual(@as(usize, 12), hashed.len);
    try std.testing.expectEqualStrings("660d25a9d7ee", hashed);
}

test "inspectCodexAccountAuthIdentity reports redacted auth-bound identity hints" {
    const auth_json =
        \\{
        \\  "auth_mode": "chatgpt",
        \\  "tokens": {
        \\    "id_token": "hdr.eyJlbWFpbCI6Implc3NAZXhhbXBsZS5jb20iLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig",
        \\    "access_token": "redacted-in-test",
        \\    "refresh_token": "redacted-in-test"
        \\  }
        \\}
    ;

    const identity = try inspectCodexAccountAuthIdentity(std.testing.allocator, auth_json);
    defer identity.deinit(std.testing.allocator);

    try std.testing.expect(identity.checked);
    try std.testing.expect(identity.present);
    try std.testing.expectEqualStrings("identity_claims_present", identity.reason);
    try std.testing.expectEqualStrings("codex_auth_json_tokens", identity.source.?);
    try std.testing.expectEqualStrings("j***@example.com", identity.email_hint.?);
    try std.testing.expectEqualStrings("660d25a9d7ee", identity.account_id_hash.?);
    try std.testing.expectEqualStrings("tokens.id_token.auth.chatgpt_account_id", identity.account_id_source.?);
    try std.testing.expect(identity.plan_type_present);
    try std.testing.expectEqualStrings("tokens.id_token.auth.chatgpt_plan_type", identity.plan_type_source.?);
}

test "entitlement claude surfaces tier labels and never leaks token material (TIN-2719)" {
    const alloc = std.testing.allocator;
    // Build a synthetic wrapped blob at RUNTIME. Token key names are assembled
    // by comptime concatenation and the token VALUES carry a distinctive canary
    // so the leak assertion is meaningful even though src/ is exempt from the
    // fixture_redaction scanner (which walks only test/fixtures + test/evidence).
    const at_key = "access" ++ "Token";
    const rt_key = "refresh" ++ "Token";
    const at_val = "sk-ant-oat01-LEAKCANARY-AAAA";
    const rt_val = "sk-ant-ort01-LEAKCANARY-BBBB";
    const raw = try std.fmt.allocPrint(
        alloc,
        "{{\"claudeAiOauth\":{{\"{s}\":\"{s}\",\"{s}\":\"{s}\",\"subscriptionType\":\"max\",\"rateLimitTier\":\"default_claude_max_20x\"}}}}",
        .{ at_key, at_val, rt_key, rt_val },
    );
    defer alloc.free(raw);

    const ent = accountEntitlementFromRaw(alloc, .claude, raw);
    defer ent.deinit(alloc);

    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    try writeEntitlementJson(buf.writer(), ent);
    const out = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, out, "\"subscription_type\":\"max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"rate_limit_tier\":\"default_claude_max_20x\"") != null);
    // SAFETY INVARIANT: no accessToken/refreshToken substring bleeds through.
    try std.testing.expect(std.mem.indexOf(u8, out, "LEAKCANARY") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, at_val) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, rt_val) == null);
}

test "entitlement claude flat (unwrapped) blob parses tier fields (TIN-2719)" {
    const alloc = std.testing.allocator;
    const at_key = "access" ++ "Token";
    const raw = try std.fmt.allocPrint(
        alloc,
        "{{\"{s}\":\"x\",\"subscriptionType\":\"max\",\"rateLimitTier\":\"default_claude_ai\"}}",
        .{at_key},
    );
    defer alloc.free(raw);
    const ent = accountEntitlementFromRaw(alloc, .claude, raw);
    defer ent.deinit(alloc);
    switch (ent) {
        .claude => |c| {
            try std.testing.expectEqualStrings("max", c.subscription_type.?);
            try std.testing.expectEqualStrings("default_claude_ai", c.rate_limit_tier.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "entitlement claude renders present field with null sibling (TIN-2719)" {
    const alloc = std.testing.allocator;
    const raw = "{\"claudeAiOauth\":{\"subscriptionType\":\"max\"}}";
    const ent = accountEntitlementFromRaw(alloc, .claude, raw);
    defer ent.deinit(alloc);
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    try writeEntitlementJson(buf.writer(), ent);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"subscription_type\":\"max\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"rate_limit_tier\":null") != null);
}

test "entitlement claude missing tier fields yields none (TIN-2719)" {
    const alloc = std.testing.allocator;
    const at_key = "access" ++ "Token";
    const raw = try std.fmt.allocPrint(alloc, "{{\"claudeAiOauth\":{{\"{s}\":\"x\"}}}}", .{at_key});
    defer alloc.free(raw);
    const ent = accountEntitlementFromRaw(alloc, .claude, raw);
    defer ent.deinit(alloc);
    try std.testing.expect(ent == .none);
}

test "entitlement claude malformed blob yields none (TIN-2719)" {
    const alloc = std.testing.allocator;
    const ent = accountEntitlementFromRaw(alloc, .claude, "{not valid json");
    defer ent.deinit(alloc);
    try std.testing.expect(ent == .none);
}

test "entitlement codex plan_type decodes from unpadded base64url id_token (TIN-2719)" {
    const alloc = std.testing.allocator;
    // payload decodes to
    // {"https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_is_fedramp":true}}
    const id_token = "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s";
    const raw = try std.fmt.allocPrint(
        alloc,
        "{{\"tokens\":{{\"access_token\":\"{s}\",\"account_id\":\"acc\",\"id_token\":\"{s}\"}}}}",
        .{ id_token, id_token },
    );
    defer alloc.free(raw);
    const ent = accountEntitlementFromRaw(alloc, .codex, raw);
    defer ent.deinit(alloc);
    switch (ent) {
        .codex => |c| try std.testing.expectEqualStrings("pro", c.plan_type.?),
        else => return error.TestUnexpectedResult,
    }
}

test "entitlement codex missing plan claim yields none (TIN-2719)" {
    const alloc = std.testing.allocator;
    // id_token payload {"sub":"x"} — no https://api.openai.com/auth claim.
    const raw = "{\"tokens\":{\"access_token\":\"h.eyJzdWIiOiJ4In0.s\",\"account_id\":\"acc\"}}";
    const ent = accountEntitlementFromRaw(alloc, .codex, raw);
    defer ent.deinit(alloc);
    try std.testing.expect(ent == .none);
}

test "entitlement never reads a command backend during inventory (TIN-2719)" {
    // Never-prompt invariant: `accounts list` must render null, never spawn an
    // arbitrary credential helper. If accountEntitlement reached secret_mod.read
    // it would run this echo and surface "max", so a green assert here proves
    // the read was skipped. Bites the pre-fix code, which read every backend
    // unconditionally.
    const alloc = std.testing.allocator;
    const acct = config.AccountConfig{
        .secret = .{
            .backend = "command",
            .command = &.{ "/bin/echo", "{\"subscriptionType\":\"max\",\"rateLimitTier\":\"default_claude_max_20x\"}" },
        },
    };
    const ent = accountEntitlement(alloc, acct, .claude);
    defer ent.deinit(alloc);
    try std.testing.expect(ent == .none);
}

test "entitlement inventory admits keychain and refuses helper backends (TIN-2719)" {
    try std.testing.expect(entitlementInventoryBackendAllowed(.{ .file = .{ .path = "/tmp/auth.json" } }));
    try std.testing.expect(entitlementInventoryBackendAllowed(.{ .env = .{ .variable = "OMUX_AUTH_JSON" } }));
    try std.testing.expect(entitlementInventoryBackendAllowed(.{ .keychain = .{ .service = "Claude Code-omux-test", .account = "work" } }));
    try std.testing.expect(!entitlementInventoryBackendAllowed(.{ .command = .{ .argv = &.{"omux-secret"} } }));
    try std.testing.expect(!entitlementInventoryBackendAllowed(.stdin));
    try std.testing.expect(!entitlementInventoryBackendAllowed(.{ .sops = .{ .path = "secrets.yaml" } }));
    try std.testing.expect(!entitlementInventoryBackendAllowed(.{ .age = .{ .path = "secret.age", .identity = "identity.txt" } }));
}

test "entitlement still reads a file backend during inventory (TIN-2719)" {
    // Bracket the never-prompt gate from the safe side: a non-interactive file
    // backend must stay readable so file-stored credentials still surface
    // their labels, proving the gate refuses only the prompt-hazardous arms.
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "cred.json",
        .data = "{\"subscriptionType\":\"max\",\"rateLimitTier\":\"default_claude_ai\"}",
    });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);
    const cred_path = try std.fs.path.join(alloc, &.{ dir_path, "cred.json" });
    defer alloc.free(cred_path);
    const acct = config.AccountConfig{
        .secret = .{ .backend = "file", .path = cred_path },
    };
    const ent = accountEntitlement(alloc, acct, .claude);
    defer ent.deinit(alloc);
    switch (ent) {
        .claude => |c| try std.testing.expectEqualStrings("max", c.subscription_type.?),
        else => return error.TestUnexpectedResult,
    }
}

test "accounts list --json emits entitlement present and absent (TIN-2719)" {
    const alloc = std.testing.allocator;

    // Present account: a codex auth.json with a plan-bearing id_token, written
    // to a real temp path so the read path exercises the file secret backend.
    const id_token = "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s";
    const auth_json = try std.fmt.allocPrint(
        alloc,
        "{{\"auth_mode\":\"chatgpt\",\"tokens\":{{\"id_token\":\"{s}\",\"access_token\":\"{s}\",\"account_id\":\"acc-present\"}}}}",
        .{ id_token, id_token },
    );
    defer alloc.free(auth_json);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "auth.json", .data = auth_json });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);
    const present_path = try std.fs.path.join(alloc, &.{ dir_path, "auth.json" });
    defer alloc.free(present_path);
    const absent_path = try std.fs.path.join(alloc, &.{ dir_path, "does-not-exist.json" });
    defer alloc.free(absent_path);

    const cfg_json = try std.fmt.allocPrint(
        alloc,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "present": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "absent": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ present_path, absent_path },
    );
    defer alloc.free(cfg_json);

    const parsed = try config.loadFromBytes(alloc, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(alloc, .{});
    defer store.deinit();

    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    try writeAccountsListJson(buf.writer(), alloc, parsed.value, &store, .{ .action = .list, .json = true, .provider = "codex" });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"entitlement\":{\"plan_type\":\"pro\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"entitlement\":null") != null);
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

    try std.json.stringify(account, .{}, writer);
    try writer.writeAll(":{\"priority\":");
    try writer.print("{d}", .{priority});
    try writer.writeAll(",\"config_dir\":");
    try std.json.stringify(account_dir, .{}, writer);
    if (comptime builtin.os.tag == .macos) {
        // macOS Claude Code persists credentials only in the login keychain
        // (TIN-2060 verified — .credentials.json is never written there);
        // the suffixed service and item account derive from config_dir at
        // load (TIN-2070), so the bare backend is the whole truth.
        try writer.writeAll(",\"secret\":{\"backend\":\"keychain\"}");
    } else {
        const credentials_path = try std.fs.path.join(allocator, &.{ account_dir, ".credentials.json" });
        defer allocator.free(credentials_path);
        try writer.writeAll(",\"secret\":{\"backend\":\"file\",\"path\":");
        try std.json.stringify(credentials_path, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll(",\"tags\":[\"oauth\",\"claude\"]}");
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
    revalidation_needed,
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
    const ok = try runCodexCli(allocator, expanded, &.{ "login", "--device-auth" });
    if (ok) recordCodexLoginSuccess(allocator, route.account);
    return ok;
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
            if (!repairRouteMatchesAccountFilter(parsed, args.account)) continue;
            if (args.capability) |requested_capability| {
                if (parsed.capability) |declared_capability| {
                    if (!std.mem.eql(u8, declared_capability, requested_capability)) continue;
                }
            }
            try routes.append(.{
                .provider = parsed.provider,
                .account = parsed.account,
                .capability = parsed.capability orelse args.capability,
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

fn repairRouteMatchesAccountFilter(route: RepairPlanRoute, account_filter: ?[]const u8) bool {
    const filter = account_filter orelse return true;
    if (std.mem.eql(u8, filter, route.account)) return true;
    if (std.mem.indexOfScalar(u8, filter, ':')) |colon| {
        if (!std.mem.eql(u8, filter[0..colon], route.provider)) return false;
        return std.mem.eql(u8, filter[colon + 1 ..], route.account);
    }
    return false;
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
        const health = routeHealth(allocator, store, route);
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
        if (try handoffPlanCommandAlloc(allocator, action, route)) |command| {
            defer allocator.free(command);
            try writer.print("    handoff_plan: {s}\n", .{command});
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
    const health = routeHealth(allocator, store, route);
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
    try writeRouteAdmissionJson(writer, cfg.policy, action, budget, route);
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
    try writer.writeAll(",\"handoff_plan_command\":");
    if (try handoffPlanCommandAlloc(allocator, action, route)) |command| {
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
    try writer.writeAll("},\"codex\":{");
    try writer.writeAll("\"auto_stay_afloat\":");
    try writer.writeAll(if (policy.codex.auto_stay_afloat) "true" else "false");
    try writer.writeAll(",\"allow_provider_spend\":");
    try writer.writeAll(if (policy.codex.allow_provider_spend) "true" else "false");
    try writer.writeAll(",\"allow_interactive_auth\":");
    try writer.writeAll(if (policy.codex.allow_interactive_auth) "true" else "false");
    const codex_effective = config.effectiveDaemonPolicyForProvider(policy, "codex");
    try writer.writeAll(",\"effective_daemon\":{");
    try writer.writeAll("\"allowed_budgets\":");
    try writeBudgetArrayJson(writer, codex_effective.allowed_budgets);
    try writer.writeAll(",\"allow_interactive\":");
    try writer.writeAll(if (codex_effective.allow_interactive) "true" else "false");
    try writer.writeAll(",\"allow_mutating\":");
    try writer.writeAll(if (codex_effective.allow_mutating) "true" else "false");
    try writer.writeAll("}}}");
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
    route: RepairPlanRoute,
) !void {
    const effective_policy = config.effectiveDaemonPolicyForProvider(policy, route.provider);
    const probe = daemonProbeAdmission(effective_policy, probe_budget);
    const repair = daemonRepairAdmission(effective_policy, action);

    try writer.writeByte('{');
    try writer.writeAll("\"effective_policy\":");
    try std.json.stringify(if (std.mem.eql(u8, route.provider, "codex") and policy.codex.auto_stay_afloat) "codex_auto_stay_afloat" else "daemon_default", .{}, writer);
    try writer.writeAll(",\"daemon_probe\":");
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
    return secret_mod.writebackPlan(backend, def.repair.owner, .{
        .provider_supports_refresh = def.repair.proactive_refresh != .unsupported,
        .account_opted_in = account.allow_proactive_refresh,
    });
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

fn routeHealth(allocator: std.mem.Allocator, store: *health_mod.HealthStore, route: RepairPlanRoute) ?health_mod.AccountHealth {
    const now = std.time.timestamp();
    const account_key = health_mod.accountKey(route.provider, route.account);
    const account_health = if (store.accounts.get(account_key.slice())) |health|
        effectiveHealthForRouteSelectionTraced(allocator, route, health, now, "account")
    else
        null;
    if (account_health) |health| {
        if (accountLivenessBlocksRoute(health.liveness)) return health;
    }

    if (route.capability) |capability| {
        const capability_key = health_mod.capabilityKey(route.provider, route.account, capability);
        if (store.accounts.get(capability_key.slice())) |health| {
            return effectiveHealthForRouteSelectionTraced(allocator, route, health, now, "capability");
        }
    }

    return account_health;
}

fn effectiveHealthForRouteSelectionTraced(
    allocator: std.mem.Allocator,
    route: RepairPlanRoute,
    raw: health_mod.AccountHealth,
    now: i64,
    source_scope: []const u8,
) health_mod.AccountHealth {
    const effective = health_mod.effectiveHealthForRouteSelection(raw, now);
    traceHealthNormalization(allocator, route.provider, route.account, route.capability, source_scope, raw.liveness, effective.liveness);
    return effective;
}

fn traceHealthNormalization(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    account_label: []const u8,
    capability: ?[]const u8,
    source_scope: []const u8,
    before: types.CredentialLiveness,
    after: types.CredentialLiveness,
) void {
    var before_buf: [128]u8 = undefined;
    var after_buf: [128]u8 = undefined;
    const before_summary = livenessSummaryIntoBuffer(before, &before_buf);
    const after_summary = livenessSummaryIntoBuffer(after, &after_buf);
    if (std.mem.eql(u8, before_summary, after_summary)) return;

    trace.append(allocator, "health.normalize", .info, &.{
        trace.string("provider", provider_name),
        trace.string("account_label", account_label),
        trace.string("capability", capability orelse "none"),
        trace.string("source_scope", source_scope),
        trace.string("before_liveness", before_summary),
        trace.string("after_liveness", after_summary),
        trace.boolean("token_material_printed", false),
        trace.boolean("path_printed", false),
    });
}

fn livenessSummaryIntoBuffer(liveness: types.CredentialLiveness, buf: []u8) []const u8 {
    var stream = std.io.fixedBufferStream(buf);
    health_mod.writeLivenessSummary(stream.writer(), liveness) catch return "unavailable";
    return stream.getWritten();
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
        .reauth_in_progress => return .{
            .kind = .wait_for_repair,
            .severity = "info",
            .message = "reauth handoff is already in progress",
            .mediation = .wait,
            .budget = .free_local,
        },
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
            .quota_exhausted => |quota| if (quotaWindowRevalidationNeeded(quota)) .{
                .kind = .revalidation_needed,
                .severity = "warning",
                .message = "quota reset window has passed; revalidate route health before using this route",
                .mediation = .probe,
                .command = .probe,
                .budget = budget,
            } else .{
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

fn quotaWindowRevalidationNeeded(quota: types.Availability.QuotaInfo) bool {
    const reset = quota.window_resets_at orelse return false;
    return std.time.timestamp() >= reset;
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

fn handoffPlanCommandAlloc(
    allocator: std.mem.Allocator,
    action: RepairAction,
    route: RepairPlanRoute,
) !?[]const u8 {
    if (action.mediation != .user_handoff) return null;
    if (action.command != .none) return null;
    if (action.owner == null or action.owner.? != .upstream_cli_login) return null;
    return try std.fmt.allocPrint(allocator, "oauth-mux enroll plan {s} --account {s} --json", .{ route.provider, route.account });
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

    // TIN-1811 Phase 2: never-halt cross-capability degradation, same as
    // runStayAfloatNext. selectDegradedRoute appends the chosen fallback onto
    // `evaluations`, so the index-based writers transparently surface it.
    const degraded = try selectDegradedRoute(
        allocator,
        parsed.value,
        &store,
        &evaluations,
        args.profile,
        args.capability,
        args.account,
    );
    const selected_index = degraded.index;

    if (args.json) {
        try writeRouteJson(writer, allocator, parsed.value, evaluations.items, selected_index, args, degraded.capability);
    } else {
        try writeRouteText(writer, allocator, parsed.value, evaluations.items, selected_index, args, degraded.capability);
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

    // TIN-1811 never-halt: if the requested capability has no live route, fall
    // through the profile's degradation chain to a live route one capability
    // away. selectDegradedRoute appends the chosen fallback evaluation onto
    // `evaluations`, so the index-based writers below transparently surface it.
    const degraded = try selectDegradedRoute(
        allocator,
        parsed.value,
        &store,
        &evaluations,
        args.profile,
        args.capability,
        args.account,
    );
    const selected_index = degraded.index;
    const degraded_capability = degraded.capability;
    const candidate_index = if (selected_index == null) firstActionableRoute(evaluations.items) else null;

    if (args.json) {
        try writeStayAfloatNextJson(writer, allocator, parsed.value, evaluations.items, selected_index, candidate_index, args, degraded_capability);
    } else {
        try writeStayAfloatNextText(writer, allocator, parsed.value, evaluations.items, selected_index, candidate_index, args, degraded_capability);
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
    // TIN-1811 Phase 2: never-halt launch. Each iteration re-evaluates the
    // requested capability and, only when no UN-ATTEMPTED selectable route
    // remains there, degrades across the profile's chain to an immediately-live
    // route. selectDegradedRouteNotAttempted only ever returns a selectable
    // (immediately-live) route, never a dead/quota one, so launch never targets a
    // throttled route. The loop terminates when it returns null (chain exhausted).
    while (true) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer evaluations.deinit();
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

        const degraded = try selectDegradedRouteNotAttempted(
            allocator,
            parsed.value,
            &store,
            &evaluations,
            selector.profile,
            selector.capability,
            selector.account,
            attempted_routes.items,
        );
        const selected_index = degraded.index;
        if (selected_index == null) {
            const candidate_index = firstActionableRoute(evaluations.items);
            try writeStayAfloatMediationText(writer, allocator, parsed.value, evaluations.items, null, candidate_index, selector, "oauth-mux stay-afloat launch");
            if (degraded.capability) |cap| try writer.print("  degraded_capability: {s}\n", .{cap});
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

const ObserveAttempt = struct {
    route: RepairPlanRoute,
    term: std.process.Child.Term,
    output_classification: ?[]const u8 = null,
    relaunch_admitted: bool,
    route_health_recorded: bool = false,
    event_recorded: bool = false,
    captured_stdout_bytes: usize = 0,
    captured_stderr_bytes: usize = 0,
};

const ObserveChildResult = struct {
    term: std.process.Child.Term,
    output_classification: ?[]const u8 = null,
    captured_stdout_bytes: usize = 0,
    captured_stderr_bytes: usize = 0,
};

const ObserveCaptureLimit = 512 * 1024;

const ObserveStreamCapture = struct {
    buffer: []u8,
    len: usize = 0,
    read_error: ?anyerror = null,
};

fn runStayAfloatObserve(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ObserveArgs,
) !void {
    if (args.target_argv.len == 0) {
        log.err("stay-afloat observe: no target command specified (use -- before the command)", .{});
        return error.ConfigValidationError;
    }
    if (args.stream_capture and !args.classify_codex_usage_limit) {
        log.err("stay-afloat observe: --stream-capture requires --classify-codex-usage-limit", .{});
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
    var attempts = std.ArrayList(ObserveAttempt).init(allocator);
    defer attempts.deinit();

    const relaunch_count: u32 = 0;
    var reason: []const u8 = "no_attempt";

    while (true) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer evaluations.deinit();
        try collectRouteEvaluations(allocator, parsed.value, &store, routes.items, &evaluations);

        // TIN-1811 Phase 2: degrade across the profile's chain only when no
        // un-attempted selectable route remains in the requested capability. Only
        // immediately-live routes are returned; quota/dead routes are never
        // observed against.
        const degraded = try selectDegradedRouteNotAttempted(
            allocator,
            parsed.value,
            &store,
            &evaluations,
            selector.profile,
            selector.capability,
            selector.account,
            attempted_routes.items,
        );
        const selected_index = degraded.index;
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

        const child_result = runObservedChild(allocator, &env_map, args) catch return error.ExecFailed;
        const route_health_recorded = if (observeOutputClassificationIsCodexUsageLimit(child_result.output_classification))
            recordStayAfloatObserveRouteHealth(&store, selected)
        else
            false;
        if (route_health_recorded) store.persist();

        // Relaunching the child is diagnostic evidence of session loss, not an
        // acceptable stay-afloat behavior. Keep the classifier and route-health
        // mutation, but never relaunch from this command.
        const relaunch_admitted = false;
        const event_recorded = recordStayAfloatObserveEvent(allocator, args, selected, child_result.term, child_result.output_classification, route_health_recorded);
        try attempts.append(.{
            .route = selected,
            .term = child_result.term,
            .output_classification = child_result.output_classification,
            .relaunch_admitted = relaunch_admitted,
            .route_health_recorded = route_health_recorded,
            .event_recorded = event_recorded,
            .captured_stdout_bytes = child_result.captured_stdout_bytes,
            .captured_stderr_bytes = child_result.captured_stderr_bytes,
        });

        reason = if (observeTermSucceeded(child_result.term))
            "target_completed"
        else if (route_health_recorded)
            "diagnostic_failure_recorded"
        else
            "target_failed";
        break;
    }

    if (args.json) {
        try writeStayAfloatObserveJson(writer, args, attempts.items, relaunch_count, reason);
    } else {
        try writeStayAfloatObserveText(writer, args, attempts.items, relaunch_count, reason);
    }
}

fn runObservedChild(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    args: cli.Command.ObserveArgs,
) !ObserveChildResult {
    var child = std.process.Child.init(args.target_argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = if (args.classify_codex_usage_limit) .Pipe else if (args.json) .Ignore else .Inherit;
    child.stderr_behavior = if (args.classify_codex_usage_limit) .Pipe else if (args.json) .Ignore else .Inherit;
    child.env_map = env_map;

    if (!args.classify_codex_usage_limit) {
        return .{ .term = try child.spawnAndWait() };
    }

    if (args.stream_capture) {
        return runObservedChildStreamingPipe(allocator, &child, args);
    }

    try child.spawn();

    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);

    child.collectOutput(allocator, &stdout_buf, &stderr_buf, ObserveCaptureLimit) catch |e| {
        _ = child.kill() catch null;
        return e;
    };
    const term = try child.wait();
    const classification: ?[]const u8 = if (observeOutputLooksLikeCodexUsageLimit(stdout_buf.items) or observeOutputLooksLikeCodexUsageLimit(stderr_buf.items))
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

fn runObservedChildStreamingPipe(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    args: cli.Command.ObserveArgs,
) !ObserveChildResult {
    try child.spawn();

    const stdout_storage = try allocator.alloc(u8, ObserveCaptureLimit);
    defer allocator.free(stdout_storage);
    const stderr_storage = try allocator.alloc(u8, ObserveCaptureLimit);
    defer allocator.free(stderr_storage);

    var stdout_capture = ObserveStreamCapture{ .buffer = stdout_storage };
    var stderr_capture = ObserveStreamCapture{ .buffer = stderr_storage };

    const stdout_file = child.stdout.?;
    const stderr_file = child.stderr.?;

    const parent_stdout = std.io.getStdOut();
    const parent_stderr = std.io.getStdErr();
    const stdout_target = if (args.json) parent_stderr else parent_stdout;

    const stdout_thread = try std.Thread.spawn(.{}, readObservedChildStream, .{ stdout_file, &stdout_capture, stdout_target });
    const stderr_thread = try std.Thread.spawn(.{}, readObservedChildStream, .{ stderr_file, &stderr_capture, parent_stderr });

    stdout_thread.join();
    stderr_thread.join();
    const term = try child.wait();

    if (stdout_capture.read_error) |err| return err;
    if (stderr_capture.read_error) |err| return err;

    const stdout_items = stdout_capture.buffer[0..stdout_capture.len];
    const stderr_items = stderr_capture.buffer[0..stderr_capture.len];
    const classification: ?[]const u8 = if (observeOutputLooksLikeCodexUsageLimit(stdout_items) or observeOutputLooksLikeCodexUsageLimit(stderr_items))
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

fn readObservedChildStream(
    input: std.fs.File,
    capture: *ObserveStreamCapture,
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
    args: cli.Command.ObserveArgs,
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

fn observeOutputClassificationIsCodexUsageLimit(classification: ?[]const u8) bool {
    return if (classification) |value| std.mem.eql(u8, value, "codex_usage_limit") else false;
}

fn observeOutputLooksLikeCodexUsageLimit(output: []const u8) bool {
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

fn recordStayAfloatObserveRouteHealth(store: *health_mod.HealthStore, route: RepairPlanRoute) bool {
    const key = repairPlanRouteHealthKey(route);
    const classification = types.HttpClassification{ .quota_exhausted = .{ .retry_after_s = 7200 } };
    // Effect boundary (TIN-2407 P0): this fn observes a child's stdout, so it owns
    // the clock read for the classification it records.
    const now_s = std.time.timestamp();
    store.recordHttpClassification(key.slice(), 429, classification, now_s);
    store.recordProbeEvidence(
        key.slice(),
        .observed_child_output,
        health_mod.retryAfterFromClassification(classification),
        health_mod.hintClassFromClassification(classification),
        health_mod.decisionFromClassification(classification),
    );
    return true;
}

fn recordStayAfloatObserveEvent(
    allocator: std.mem.Allocator,
    args: cli.Command.ObserveArgs,
    route: RepairPlanRoute,
    term: std.process.Child.Term,
    output_classification: ?[]const u8,
    route_health_recorded: bool,
) bool {
    const outcome = if (observeTermSucceeded(term))
        "target_completed"
    else
        "target_failed";
    const reason = output_classification orelse if (args.classify_exit_code != null) "operator_exit_code" else "child_exit";
    repair_state.appendEvent(allocator, .{
        .kind = "stay_afloat_observe",
        .profile = args.profile,
        .provider = route.provider,
        .account = route.account,
        .capability = route.capability orelse args.capability,
        .action = "observe",
        .outcome = outcome,
        .reason = reason,
        .ok = observeTermSucceeded(term),
        .executed = true,
        .interactive = args.stream_capture,
        .mutating = route_health_recorded,
    }) catch return false;
    return true;
}

fn observeClassificationSource(args: cli.Command.ObserveArgs) []const u8 {
    if (args.classify_exit_code != null and args.classify_codex_usage_limit) return "operator_exit_code_or_codex_usage_limit_output";
    if (args.classify_codex_usage_limit) return "codex_usage_limit_output";
    if (args.classify_exit_code != null) return "operator_exit_code";
    return "none";
}

fn observeCaptureTransport(args: cli.Command.ObserveArgs) []const u8 {
    if (!args.classify_codex_usage_limit) return if (args.json) "none" else "inherit";
    return if (args.stream_capture) "streaming_pipe" else "buffered_pipe";
}

fn observeTermSucceeded(term: std.process.Child.Term) bool {
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn observeTermKind(term: std.process.Child.Term) []const u8 {
    return switch (term) {
        .Exited => "exited",
        .Signal => "signal",
        .Stopped => "stopped",
        .Unknown => "unknown",
    };
}

fn observeTermCode(term: std.process.Child.Term) u32 {
    return switch (term) {
        .Exited => |code| code,
        .Signal => |signal| signal,
        .Stopped => |signal| signal,
        .Unknown => |code| code,
    };
}

fn writeStayAfloatObserveJson(
    writer: anytype,
    args: cli.Command.ObserveArgs,
    attempts: []const ObserveAttempt,
    relaunch_count: u32,
    reason: []const u8,
) !void {
    const ok = attempts.len > 0 and observeTermSucceeded(attempts[attempts.len - 1].term);
    const prepared_fallback = attempts.len > 0;
    try writer.writeAll("{\"version\":");
    try std.json.stringify(cli.version, .{}, writer);
    try writer.writeAll(",\"mode\":\"stay_afloat_observe\",\"ok\":");
    try writer.writeAll(if (ok) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(reason, .{}, writer);
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"observed_child_process\"");
    try writer.writeAll(",\"prepared_fallback\":");
    try writer.writeAll(if (prepared_fallback) "true" else "false");
    try writer.writeAll(",\"diagnostic_relaunch_observed\":");
    try writer.writeAll(if (relaunch_count > 0) "true" else "false");
    try writer.writeAll(",\"acceptable_seamless_behavior\":false");
    try writer.writeAll(",\"child_process_observed\":true,\"classification_source\":");
    try std.json.stringify(observeClassificationSource(args), .{}, writer);
    try writer.writeAll(",\"route_health_recorded\":");
    try writer.writeAll(if (observeAttemptsRecordedRouteHealth(attempts)) "true" else "false");
    try writer.writeAll(",\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"legacy_max_restarts\":");
    try writer.print("{d}", .{args.legacy_max_restarts});
    try writer.writeAll(",\"legacy_restart_aliases_used\":");
    try writer.writeAll(if (args.legacy_restart_aliases_used) "true" else "false");
    try writer.writeAll(",\"legacy_restart_aliases_effect\":");
    try std.json.stringify(if (args.legacy_restart_aliases_used) "compatibility_classification_only" else "none", .{}, writer);
    try writer.writeAll(",\"relaunch_enabled\":false");
    try writer.writeAll(",\"classify_exit_code\":");
    if (args.classify_exit_code) |code| try writer.print("{d}", .{code}) else try writer.writeAll("null");
    try writer.writeAll(",\"classify_codex_usage_limit\":");
    try writer.writeAll(if (args.classify_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"capture_transport\":");
    try std.json.stringify(observeCaptureTransport(args), .{}, writer);
    try writer.writeAll(",\"live_child_output_streamed\":");
    try writer.writeAll(if (args.stream_capture and args.classify_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"relaunch_count\":");
    try writer.print("{d}", .{relaunch_count});
    try writer.writeAll(",\"attempts\":[");
    for (attempts, 0..) |attempt, idx| {
        if (idx != 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"selected\":");
        try writeRouteSelectionJson(writer, attempt.route);
        try writer.writeAll(",\"term\":{\"kind\":");
        try std.json.stringify(observeTermKind(attempt.term), .{}, writer);
        try writer.writeAll(",\"code\":");
        try writer.print("{d}", .{observeTermCode(attempt.term)});
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
        try writer.writeAll(",\"relaunch_admitted\":");
        try writer.writeAll(if (attempt.relaunch_admitted) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"redaction\":{\"tokens_printed\":false,\"captured_output_in_json\":false,\"captured_output_printed\":false,\"live_child_output_streamed\":");
    try writer.writeAll(if (args.stream_capture and args.classify_codex_usage_limit) "true" else "false");
    try writer.writeAll(",\"raw_protocol_printed\":false}}\n");
}

fn writeStayAfloatObserveText(
    writer: anytype,
    args: cli.Command.ObserveArgs,
    attempts: []const ObserveAttempt,
    relaunch_count: u32,
    reason: []const u8,
) !void {
    const ok = attempts.len > 0 and observeTermSucceeded(attempts[attempts.len - 1].term);
    try writer.writeAll("oauth-mux stay-afloat observe\n\n");
    try writer.print("  ok: {s}\n", .{if (ok) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
    try writer.print("  legacy max restarts: {d} (relaunch disabled)\n", .{args.legacy_max_restarts});
    try writer.print("  legacy restart aliases: {s}", .{if (args.legacy_restart_aliases_used) "true" else "false"});
    if (args.legacy_restart_aliases_used) {
        try writer.writeAll(" (compatibility classification only)");
    }
    try writer.writeByte('\n');
    try writer.writeAll("  classify exit code: ");
    if (args.classify_exit_code) |code| try writer.print("{d}\n", .{code}) else try writer.writeAll("not configured\n");
    try writer.print("  classify Codex usage limit: {s}\n", .{if (args.classify_codex_usage_limit) "true" else "false"});
    try writer.print("  capture transport: {s}\n", .{observeCaptureTransport(args)});
    try writer.print("  live child output streamed: {s}\n", .{if (args.stream_capture and args.classify_codex_usage_limit) "true" else "false"});
    try writer.print("  relaunch count: {d}\n", .{relaunch_count});
    for (attempts, 0..) |attempt, idx| {
        try writer.print("  attempt {d}: {s}:{s}", .{ idx + 1, attempt.route.provider, attempt.route.account });
        if (attempt.route.capability) |cap| try writer.print("#{s}", .{cap});
        try writer.print(" {s}:{d} relaunch_admitted={s}", .{
            observeTermKind(attempt.term),
            observeTermCode(attempt.term),
            if (attempt.relaunch_admitted) "true" else "false",
        });
        if (attempt.output_classification) |classification| try writer.print(" classification={s}", .{classification});
        if (attempt.route_health_recorded) try writer.writeAll(" route_health_recorded=true");
        if (attempt.event_recorded) try writer.writeAll(" event_recorded=true");
        try writer.writeByte('\n');
    }
    try writer.writeAll("  boundary: diagnostic child observation only; relaunch is disabled and not an acceptable seamless stay-afloat behavior\n");
}

fn observeAttemptsRecordedRouteHealth(attempts: []const ObserveAttempt) bool {
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

    // TIN-1811 Phase 2: surface the never-halt cross-capability fallback in the
    // post-launch mediation snapshot, consistent with runStayAfloatNext.
    const degraded = try selectDegradedRoute(
        allocator,
        cfg,
        &store,
        &evaluations,
        selector.profile,
        selector.capability,
        selector.account,
    );
    const selected_index = degraded.index;
    const candidate_index = if (selected_index == null) firstActionableRoute(evaluations.items) else null;
    try writeStayAfloatMediationText(
        writer,
        allocator,
        cfg,
        evaluations.items,
        selected_index,
        candidate_index,
        selector,
        "oauth-mux stay-afloat launch",
    );
    if (degraded.capability) |cap| try writer.print("  degraded_capability: {s}\n", .{cap});
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

        // TIN-1811 Phase 2: never-halt degradation for daemon planning, so a tick
        // reports an immediately-live cross-capability route rather than a halt
        // when the requested capability is exhausted. Quota routes stay
        // unselectable here (launch-time); their recovery is reflected only in
        // the resilience accounting.
        var degraded = try selectDegradedRoute(allocator, parsed.value, &store, &evaluations, args.profile, args.capability, args.account);
        var selected_index = degraded.index;
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
            degraded = try selectDegradedRoute(allocator, parsed.value, &store, &evaluations, args.profile, args.capability, args.account);
            selected_index = degraded.index;
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

        const stats = daemonTickStats(parsed.value.policy, evaluations.items, observed_at);
        sleepBetweenDaemonTicks(args, idx, iterations, stats, observed_at);
    }

    if (args.json and iterations > 1) {
        try writer.writeAll("]}\n");
    }
}

fn runForegroundStayAfloatLoop(
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
    const stats = daemonTickStats(cfg.policy, evaluations, observed_at);

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

fn sameFallbackAccount(a: RepairPlanRoute, b: RepairPlanRoute) bool {
    return std.mem.eql(u8, a.provider, b.provider) and std.mem.eql(u8, a.account, b.account);
}

fn routeMatchesOptionalCapability(route: RepairPlanRoute, capability: ?[]const u8) bool {
    const expected = capability orelse return true;
    const actual = route.capability orelse return false;
    return std.mem.eql(u8, actual, expected);
}

fn selectedRouteIsSameAccount(evaluations: []const RouteEvaluation, selected_index: ?usize, route: RepairPlanRoute) bool {
    const selected = selectedRoute(evaluations, selected_index) orelse return false;
    return sameFallbackAccount(selected, route);
}

fn fallbackAccountSeenBefore(
    evaluations: []const RouteEvaluation,
    candidate_index: usize,
    selected_index: ?usize,
    capability: ?[]const u8,
    comptime include_recoverable_quota: bool,
) bool {
    const candidate = evaluations[candidate_index];
    for (evaluations[0..candidate_index], 0..) |previous, previous_idx| {
        if (selected_index) |selected| {
            if (previous_idx == selected) continue;
        }
        if (!sameFallbackAccount(previous.route, candidate.route)) continue;
        if (!routeMatchesOptionalCapability(previous.route, capability)) continue;
        const previous_counts = previous.selectable or (include_recoverable_quota and routeIsRecoverableQuota(previous));
        if (previous_counts) return true;
    }
    return false;
}

fn routeIsDistinctFallbackAccount(evaluations: []const RouteEvaluation, selected_index: ?usize, candidate_index: usize) bool {
    if (candidate_index >= evaluations.len) return false;
    if (selected_index) |selected| {
        if (candidate_index == selected) return false;
    }
    return !selectedRouteIsSameAccount(evaluations, selected_index, evaluations[candidate_index].route);
}

fn selectableFallbackRouteCount(evaluations: []const RouteEvaluation, selected_index: ?usize) usize {
    var count: usize = 0;
    for (evaluations, 0..) |evaluation, idx| {
        if (!evaluation.selectable) continue;
        if (selected_index) |selected| {
            if (idx == selected) continue;
        }
        if (selectedRouteIsSameAccount(evaluations, selected_index, evaluation.route)) continue;
        if (fallbackAccountSeenBefore(evaluations, idx, selected_index, null, false)) continue;
        count += 1;
    }
    return count;
}

// TIN-1812: a quota-exhausted route is LIVE-but-throttled, not dead. When it
// still carries a reset window in the future, it is a recoverable fallback: the
// pool is not actually halted, it just has to wait for the window. Returns true
// only for a quota_exhausted route whose window is set and has not yet passed
// (an expired window means the route needs revalidation, not a guaranteed wait).
fn routeIsRecoverableQuota(evaluation: RouteEvaluation) bool {
    const health = evaluation.health orelse return false;
    return switch (health.liveness) {
        .live => |live| switch (live.availability) {
            .quota_exhausted => |quota| quota.window_resets_at != null and
                !quotaWindowRevalidationNeeded(quota),
            else => false,
        },
        else => false,
    };
}

// TIN-1812: resilience-accounting count of routes that keep the pool afloat --
// immediately-selectable routes plus quota-exhausted routes that will recover at
// a known reset window. Used ONLY for reporting/state (so a quota-only pool is
// not a false "not_afloat"); it never makes a quota route selectable for
// immediate launch. With no quota routes this equals selectableFallbackRouteCount
// (scoped to `degraded_capability` when a cross-capability degrade occurred).
fn recoverableFallbackRouteCount(
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    degraded_capability: ?[]const u8,
) usize {
    var count: usize = 0;
    for (evaluations, 0..) |evaluation, idx| {
        if (selected_index) |selected| {
            if (idx == selected) continue;
        }
        const counts = evaluation.selectable or routeIsRecoverableQuota(evaluation);
        if (!counts) continue;
        if (degraded_capability) |cap| {
            const route_capability = evaluation.route.capability orelse continue;
            if (!std.mem.eql(u8, route_capability, cap)) continue;
        }
        if (selectedRouteIsSameAccount(evaluations, selected_index, evaluation.route)) continue;
        if (fallbackAccountSeenBefore(evaluations, idx, selected_index, degraded_capability, true)) continue;
        count += 1;
    }
    return count;
}

// TIN-1812: the soonest future quota reset window across all evaluations, so the
// resilience body can surface when the pool will recover. Null when no
// quota-exhausted route has a reachable (future) window.
fn soonestQuotaWindowReset(evaluations: []const RouteEvaluation) ?i64 {
    var soonest: ?i64 = null;
    for (evaluations) |evaluation| {
        if (!routeIsRecoverableQuota(evaluation)) continue;
        const health = evaluation.health orelse continue;
        const reset = switch (health.liveness) {
            .live => |live| switch (live.availability) {
                .quota_exhausted => |quota| quota.window_resets_at orelse continue,
                else => continue,
            },
            else => continue,
        };
        if (soonest == null or reset < soonest.?) soonest = reset;
    }
    return soonest;
}

fn writeRouteResilienceJson(
    writer: anytype,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    // TIN-1812: count quota-recoverable spares too so a quota-only pool is not a
    // false "not_afloat", and surface the soonest reset window.
    const recoverable_count = recoverableFallbackRouteCount(evaluations, selected_index, null);
    const soonest_reset = soonestQuotaWindowReset(evaluations);
    try writeRouteResilienceJsonWithCount(writer, selected_index, fallback_count, recoverable_count, soonest_reset);
}

// TIN-1811: resilience body parameterized by an externally computed spare-route
// count so cross-capability degradation can scope the count to the degraded
// capability while the existing single-capability callers keep their behavior.
//
// TIN-1812: `recoverable_fallback_count` additionally counts quota-exhausted
// routes that will recover at a known window. `selectable_fallback_routes`
// (immediately-live spares) is unchanged, but `state` is only "not_afloat" when
// there is neither a selected route NOR a recoverable fallback -- a quota route
// that will reset keeps the pool afloat (and surfaces recovery_window_resets_at).
fn writeRouteResilienceJsonWithCount(
    writer: anytype,
    selected_index: ?usize,
    fallback_count: usize,
    recoverable_fallback_count: usize,
    soonest_recovery_window_resets_at: ?i64,
) !void {
    const selected = selected_index != null;
    // A pool with no immediately-live route but a quota route that will recover
    // is "afloat" in the wait-and-continue sense (TIN-1812), not halted.
    const afloat = selected or recoverable_fallback_count > 0;
    try writer.writeByte('{');
    try writer.writeAll("\"selected_route_ready\":");
    try writer.writeAll(if (selected) "true" else "false");
    try writer.print(",\"selectable_fallback_routes\":{d}", .{fallback_count});
    try writer.print(",\"recoverable_fallback_routes\":{d}", .{recoverable_fallback_count});
    try writer.writeAll(",\"spare_fallback_ready\":");
    try writer.writeAll(if (selected and fallback_count > 0) "true" else "false");
    try writer.writeAll(",\"single_route_at_risk\":");
    try writer.writeAll(if (selected and fallback_count == 0) "true" else "false");
    try writer.writeAll(",\"recovery_window_resets_at\":");
    if (soonest_recovery_window_resets_at) |reset| {
        try writer.print("{d}", .{reset});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"state\":");
    try std.json.stringify(if (!afloat)
        "not_afloat"
    else if (selected and fallback_count > 0)
        "afloat_with_spare_fallback"
    else if (selected)
        "afloat_without_spare_fallback"
    else
        // No immediately-live route, but a quota route will recover: the pool is
        // not halted, it is waiting for a reset window (TIN-1812).
        "afloat_pending_quota_recovery", .{}, writer);
    try writer.writeByte('}');
}

fn writeRouteResilienceActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
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
    if (!codexBrokerSessionSingleRouteAtRisk(true, fallback_count)) {
        try writer.writeAll("[]");
        return;
    }
    const action_capability = capability orelse evaluations[selected].route.capability;
    const repair_summary = try codexPreflightRepairSummary(allocator, cfg, evaluations, selected_index, true, fallback_count > 0);
    try writeCodexBrokerSessionRiskActionsJsonWithSummary(writer, allocator, profile, action_capability, true, fallback_count, repair_summary);
}

fn writeRouteResilienceActionsText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    const selected = selected_index orelse return;
    if (selected >= evaluations.len) return;
    const route = evaluations[selected].route;
    if (!std.mem.eql(u8, route.provider, "codex")) return;
    const fallback_count = selectableFallbackRouteCount(evaluations, selected_index);
    if (!codexBrokerSessionSingleRouteAtRisk(true, fallback_count)) return;

    const repair_summary = try codexPreflightRepairSummary(allocator, cfg, evaluations, selected_index, true, fallback_count > 0);
    const has_provider_revalidation = codexBrokerSessionRepairSummaryHasProviderRevalidationCandidate(repair_summary);
    const has_wait = codexBrokerSessionRepairSummaryHasWaitCandidate(repair_summary);
    if (repair_summary.user_handoff_required and !has_provider_revalidation and !has_wait) {
        try writer.writeAll("  next: reauthenticate blocked Codex routes or enroll another Codex account\n");
    } else if (repair_summary.user_handoff_required) {
        try writer.writeAll("  next: reauthenticate blocked Codex routes, revalidate exhausted routes, enroll another Codex account, or wait for quota reset\n");
    } else {
        try writer.writeAll("  next: revalidate exhausted routes, enroll another Codex account, or wait for quota reset\n");
    }
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

fn runReauth(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ReauthArgs,
) !void {
    switch (args.action) {
        .start => try runReauthStart(allocator, writer, args),
        .wait => try runReauthWait(allocator, writer, args),
        .drain => try runReauthDrain(allocator, writer, args),
        .run => try runReauthRun(allocator, writer, args),
    }
}

fn runReauthStart(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ReauthArgs,
) !void {
    const provider_name = args.provider orelse return error.ConfigValidationError;
    const account = args.account orelse return error.ConfigValidationError;
    const key = repair_state.HandoffKey{
        .profile = args.profile,
        .provider = provider_name,
        .account = account,
        .capability = args.capability,
    };

    var lock = repair_state.acquireRepairLock(allocator, provider_name, account) catch |e| switch (e) {
        error.RepairInProgress => {
            try writeReauthStartResult(writer, allocator, args, false, false, true, false, "repair_lock_busy");
            return;
        },
        else => return e,
    };
    defer lock.release();

    const pending_before = try repair_state.hasPendingHandoff(allocator, key);
    if (!pending_before) {
        const command = try reauthCommandOwnedCommandAlloc(allocator, provider_name, account);
        defer allocator.free(command);
        try repair_state.appendEvent(allocator, .{
            .kind = "daemon_handoff",
            .profile = args.profile,
            .provider = provider_name,
            .account = account,
            .capability = args.capability,
            .action = "reauth_start",
            .command = command,
            .engine_run_available = false,
            .execution = "command_owned",
            .agent_safe = false,
            .spends_provider_calls = false,
            .budget = "1 interactive login",
            .repair_owner = "upstream_cli_login",
            .fresh_browser_context_required = reauthNeedsFreshBrowserContext(provider_name),
            .browser_context = "fresh_incognito_or_isolated_profile",
            .outcome = "handoff_queued",
            .reason = "reauth_user_mediated",
            .ok = false,
            .executed = false,
            .interactive = true,
            .mutating = true,
        });
    }

    try writeReauthStartResult(writer, allocator, args, true, !pending_before, false, true, if (pending_before) "handoff_already_pending" else "handoff_queued");
}

fn runReauthWait(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ReauthArgs,
) !void {
    const provider_name = args.provider orelse return error.ConfigValidationError;
    const account = args.account orelse return error.ConfigValidationError;
    const key = repair_state.HandoffKey{
        .profile = args.profile,
        .provider = provider_name,
        .account = account,
        .capability = args.capability,
    };

    var pending = try repair_state.hasPendingHandoff(allocator, key);
    const start_ms = std.time.milliTimestamp();
    while (pending and args.timeout_ms > 0) {
        const elapsed: u64 = @intCast(@max(0, std.time.milliTimestamp() - start_ms));
        if (elapsed >= args.timeout_ms) break;
        const remaining = args.timeout_ms - elapsed;
        const sleep_ms: u64 = @min(@as(u64, 100), remaining);
        std.time.sleep(sleep_ms * @as(u64, std.time.ns_per_ms));
        pending = try repair_state.hasPendingHandoff(allocator, key);
    }

    try writeReauthWaitResult(writer, args, pending, if (pending) "handoff_pending" else "handoff_resolved");
}

fn runReauthDrain(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ReauthArgs,
) !void {
    _ = args.provider; // Parsed for CLI compatibility; provider filtering is a later queue refinement.
    try repair_state.writeHandoffs(allocator, writer, args.json, 50, false);
}

fn runReauthRun(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.ReauthArgs,
) !void {
    const correlation_id = args.correlation_id orelse return error.ConfigValidationError;
    const split = std.mem.indexOfScalar(u8, correlation_id, ':');
    const provider_name = if (split) |idx| blk: {
        const value = correlation_id[0..idx];
        if (value.len == 0) return error.ConfigValidationError;
        break :blk value;
    } else args.provider orelse return error.ConfigValidationError;
    const account = if (split) |idx| blk: {
        const value = correlation_id[idx + 1 ..];
        if (value.len == 0) return error.ConfigValidationError;
        break :blk value;
    } else args.account orelse correlation_id;
    if (account.len == 0) return error.ConfigValidationError;
    const command = try reauthCommandOwnedCommandAlloc(allocator, provider_name, account);
    defer allocator.free(command);

    if (args.json) {
        try writer.writeAll("{\"ok\":false,\"action\":\"run\",\"correlation_id\":");
        try std.json.stringify(correlation_id, .{}, writer);
        try writer.writeAll(",\"provider\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"engine_run_available\":false,\"execution\":\"command_owned\",\"fresh_browser_context_required\":");
        try writer.writeAll(if (reauthNeedsFreshBrowserContext(provider_name)) "true" else "false");
        try writer.writeAll(",\"next_action\":");
        try std.json.stringify(command, .{}, writer);
        try writer.writeAll(",\"reason\":\"no_provider_flipped_to_engine_run\"}\n");
        return;
    }

    try writer.writeAll("oauth-mux reauth run\n\n");
    try writer.print("  correlation_id: {s}\n", .{correlation_id});
    try writer.writeAll("  engine_run_available: false\n");
    try writer.writeAll("  execution: command_owned\n");
    try writer.print("  fresh_browser_context_required: {s}\n", .{if (reauthNeedsFreshBrowserContext(provider_name)) "true" else "false"});
    try writer.print("  next_action: {s}\n", .{command});
    try writer.writeAll("  reason: no_provider_flipped_to_engine_run\n");
}

fn writeReauthStartResult(
    writer: anytype,
    allocator: std.mem.Allocator,
    args: cli.Command.ReauthArgs,
    ok: bool,
    queued: bool,
    lock_busy: bool,
    pending: bool,
    reason: []const u8,
) !void {
    const provider_name = args.provider orelse "";
    const account = args.account orelse "";
    const correlation_id = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ provider_name, account });
    defer allocator.free(correlation_id);
    const command = try reauthCommandOwnedCommandAlloc(allocator, provider_name, account);
    defer allocator.free(command);

    if (args.json) {
        try writer.writeAll("{\"ok\":");
        try writer.writeAll(if (ok) "true" else "false");
        try writer.writeAll(",\"action\":\"start\",\"profile\":");
        try writeOptionalJsonString(writer, args.profile);
        try writer.writeAll(",\"provider\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"capability\":");
        try writeOptionalJsonString(writer, args.capability);
        try writer.writeAll(",\"correlation_id\":");
        try std.json.stringify(correlation_id, .{}, writer);
        try writer.writeAll(",\"handoff_queued\":");
        try writer.writeAll(if (queued) "true" else "false");
        try writer.writeAll(",\"handoff_pending\":");
        try writer.writeAll(if (pending) "true" else "false");
        try writer.writeAll(",\"lock_busy\":");
        try writer.writeAll(if (lock_busy) "true" else "false");
        try writer.writeAll(",\"engine_run_available\":false,\"execution\":\"command_owned\",\"agent_safe\":false,\"interactive\":true,\"mutating\":true,\"spends_provider_calls\":false,\"budget\":\"1 interactive login\",\"repair_owner\":\"upstream_cli_login\",\"fresh_browser_context_required\":");
        try writer.writeAll(if (reauthNeedsFreshBrowserContext(provider_name)) "true" else "false");
        try writer.writeAll(",\"browser_context\":\"fresh_incognito_or_isolated_profile\",\"next_action\":");
        try std.json.stringify(command, .{}, writer);
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(reason, .{}, writer);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux reauth start\n\n");
    try writer.print("  ok: {s}\n", .{if (ok) "true" else "false"});
    try writer.print("  provider: {s}\n", .{provider_name});
    try writer.print("  account: {s}\n", .{account});
    if (args.profile) |profile| try writer.print("  profile: {s}\n", .{profile});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    try writer.print("  correlation_id: {s}\n", .{correlation_id});
    try writer.print("  handoff_queued: {s}\n", .{if (queued) "true" else "false"});
    try writer.print("  handoff_pending: {s}\n", .{if (pending) "true" else "false"});
    try writer.print("  lock_busy: {s}\n", .{if (lock_busy) "true" else "false"});
    try writer.writeAll("  execution: command_owned\n");
    try writer.print("  fresh_browser_context_required: {s}\n", .{if (reauthNeedsFreshBrowserContext(provider_name)) "true" else "false"});
    try writer.writeAll("  browser_context: fresh_incognito_or_isolated_profile\n");
    try writer.print("  next_action: {s}\n", .{command});
    try writer.print("  reason: {s}\n", .{reason});
}

fn writeReauthWaitResult(
    writer: anytype,
    args: cli.Command.ReauthArgs,
    pending: bool,
    reason: []const u8,
) !void {
    const provider_name = args.provider orelse "";
    const account = args.account orelse "";

    if (args.json) {
        try writer.writeAll("{\"ok\":true,\"action\":\"wait\",\"profile\":");
        try writeOptionalJsonString(writer, args.profile);
        try writer.writeAll(",\"provider\":");
        try std.json.stringify(provider_name, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(account, .{}, writer);
        try writer.writeAll(",\"capability\":");
        try writeOptionalJsonString(writer, args.capability);
        try writer.writeAll(",\"handoff_pending\":");
        try writer.writeAll(if (pending) "true" else "false");
        try writer.writeAll(",\"reason\":");
        try std.json.stringify(reason, .{}, writer);
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux reauth wait\n\n");
    try writer.print("  provider: {s}\n", .{provider_name});
    try writer.print("  account: {s}\n", .{account});
    try writer.print("  handoff_pending: {s}\n", .{if (pending) "true" else "false"});
    try writer.print("  reason: {s}\n", .{reason});
}

fn reauthCommandOwnedCommandAlloc(allocator: std.mem.Allocator, provider_name: []const u8, account: []const u8) ![]const u8 {
    if (std.mem.eql(u8, provider_name, "codex")) {
        return try std.fmt.allocPrint(allocator, "oauth-mux codex login-device {s}", .{account});
    }
    if (std.mem.eql(u8, provider_name, "claude")) {
        return try std.fmt.allocPrint(allocator, "oauth-mux enroll plan claude --account {s} --json", .{account});
    }
    return try std.fmt.allocPrint(allocator, "oauth-mux enroll plan {s} --account {s} --json", .{ provider_name, account });
}

fn reauthNeedsFreshBrowserContext(provider_name: []const u8) bool {
    return std.mem.eql(u8, provider_name, "codex");
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
        const decision = daemonTickDecision(cfg.policy, evaluation, std.time.timestamp());
        if (std.mem.eql(u8, decision.phase, "repair") and evaluation.action.interactive) {
            try queueDaemonHandoff(allocator, args, evaluation, decision, executions);
            return false;
        }
        if (!decision.admitted) continue;

        if (std.mem.eql(u8, decision.phase, "probe")) {
            return try executeDaemonProbe(allocator, cfg, args, evaluation, decision, executions);
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
    cfg: config.Config,
    args: cli.Command.DaemonTickArgs,
    evaluation: RouteEvaluation,
    decision: DaemonTickDecision,
    executions: *std.ArrayList(DaemonTickExecution),
) !bool {
    var scratch = std.ArrayList(u8).init(allocator);
    defer scratch.deinit();

    // TIN-2073: a probe-budget tick may rotate tokens only when daemon
    // policy explicitly grants mutation — the same operator consent the
    // repair phase requires. Default policy (allow_mutating=false) defers
    // typed; rotation then needs a mutation-admitted tick.
    const daemon_policy = config.effectiveDaemonPolicyForProvider(cfg.policy, evaluation.route.provider);

    var ok = true;
    var reason: []const u8 = "probe_completed";
    runProbe(allocator, scratch.writer(), .{
        .provider = evaluation.route.provider,
        .account = evaluation.route.account,
        .capability = evaluation.route.capability,
        .json = true,
        .allow_refresh_mutation = daemon_policy.allow_mutating,
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
        const health = routeHealth(allocator, store, route);
        const budget = routeProbeBudget(def, route.capability);
        const action = repairActionFor(route, def, runtime, health, budget);
        const selectable = routeSelectable(runtime, health);
        const skip_reason = if (selectable) "available" else routeSkipReason(runtime, health);
        try evaluations.append(.{
            .route = route,
            .runtime = runtime,
            .health = health,
            .budget = budget,
            .action = action,
            .selectable = selectable,
            .skip_reason = skip_reason,
        });
        traceRouteEvaluation(allocator, route, runtime, health, action, selectable, skip_reason);
    }
}

fn traceRouteEvaluation(
    allocator: std.mem.Allocator,
    route: RepairPlanRoute,
    runtime: types.RuntimeReadiness,
    route_health_value: ?health_mod.AccountHealth,
    action: RepairAction,
    selectable: bool,
    skip_reason: []const u8,
) void {
    var liveness_buf: [128]u8 = undefined;
    const liveness_summary = if (route_health_value) |current|
        livenessSummaryIntoBuffer(current.liveness, &liveness_buf)
    else
        "unrecorded";

    trace.append(allocator, "route.evaluate", .info, &.{
        trace.string("provider", route.provider),
        trace.string("account_label", route.account),
        trace.string("capability", route.capability orelse "none"),
        trace.string("runtime", runtimeReadinessSummary(runtime)),
        trace.string("liveness", liveness_summary),
        trace.string("action", @tagName(action.kind)),
        trace.string("skip_reason", skip_reason),
        trace.boolean("selectable", selectable),
        trace.boolean("token_material_printed", false),
        trace.boolean("path_printed", false),
    });
}

fn firstSelectableRoute(evaluations: []const RouteEvaluation) ?usize {
    for (evaluations, 0..) |evaluation, idx| {
        if (evaluation.selectable) return idx;
    }
    return null;
}

// TIN-1811: result of cross-capability degradation. When a live route was found
// one or more capabilities away from the requested one, `index` points into the
// (now extended) evaluations list and `capability` names the capability that was
// actually selected. `capability == null` means no degradation occurred.
const DegradedSelection = struct {
    index: ?usize = null,
    capability: ?[]const u8 = null,
};

// TIN-1811: collect a profile's routes for a single target capability, preserving
// each route's *declared* capability. This is used by degradation so the
// fallback set is explicit and does not inherit the originally requested
// capability label.
fn collectProfileRoutesForCapability(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    profile_name: []const u8,
    target_capability: []const u8,
    account_filter: ?[]const u8,
) !std.ArrayList(RepairPlanRoute) {
    var routes = std.ArrayList(RepairPlanRoute).init(allocator);
    errdefer routes.deinit();

    const profile = cfg.profiles.map.get(profile_name) orelse return error.ConfigValidationError;
    for (profile.providers) |provider_ref| {
        const parsed = parseRepairRouteSpec(provider_ref) orelse return error.ConfigValidationError;
        if (!repairRouteMatchesAccountFilter(parsed, account_filter)) continue;
        const declared = parsed.capability orelse continue;
        if (!std.mem.eql(u8, declared, target_capability)) continue;
        try routes.append(.{
            .provider = parsed.provider,
            .account = parsed.account,
            .capability = parsed.capability,
        });
    }
    return routes;
}

// TIN-1811: the never-halt fallback. When the requested capability's routes have
// no selectable route, walk the profile's capability_degradation_chain in order,
// re-evaluate the routes for each fallback capability, and append the first
// selectable degraded route onto `evaluations`. Returns the index of that
// appended evaluation plus the degraded capability so callers can surface it.
// A null chain (today's default) returns no selection, preserving the strictly
// capability-scoped behavior.
//
// CRITICAL: degradation only ever selects an IMMEDIATELY-LIVE route (one that
// `firstSelectableRoute` accepts). It never selects a dead/quota route to launch
// on; quota's "will recover" signal lives only in the resilience accounting
// (TIN-1812), not here.
fn selectDegradedRoute(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    evaluations: *std.ArrayList(RouteEvaluation),
    profile_name: ?[]const u8,
    requested_capability: ?[]const u8,
    account_filter: ?[]const u8,
) !DegradedSelection {
    return selectDegradedRouteCore(
        allocator,
        cfg,
        store,
        evaluations,
        profile_name,
        requested_capability,
        account_filter,
        null,
    );
}

// TIN-1811 Phase 2: launch/retry variant of selectDegradedRoute. The launch loops
// (runStayAfloatLaunch, runStayAfloatObserve) track `attempted_routes` and must
// skip a route once it has been launched on. As with the base selector, the
// requested capability is consulted first: degradation walks the chain only when
// no UN-ATTEMPTED selectable route exists in the requested capability. Degraded
// routes already attempted are likewise skipped, so a failed cross-capability
// launch is not retried in a loop.
fn selectDegradedRouteNotAttempted(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    evaluations: *std.ArrayList(RouteEvaluation),
    profile_name: ?[]const u8,
    requested_capability: ?[]const u8,
    account_filter: ?[]const u8,
    attempted_routes: []const RepairPlanRoute,
) !DegradedSelection {
    return selectDegradedRouteCore(
        allocator,
        cfg,
        store,
        evaluations,
        profile_name,
        requested_capability,
        account_filter,
        attempted_routes,
    );
}

// Shared core for selectDegradedRoute / selectDegradedRouteNotAttempted. When
// `attempted_routes` is null, selects the first selectable route; when non-null,
// selects the first selectable route not already in that attempted set (both in
// the requested capability and in any fallback capability).
fn selectDegradedRouteCore(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    store: *health_mod.HealthStore,
    evaluations: *std.ArrayList(RouteEvaluation),
    profile_name: ?[]const u8,
    requested_capability: ?[]const u8,
    account_filter: ?[]const u8,
    attempted_routes: ?[]const RepairPlanRoute,
) !DegradedSelection {
    if (firstSelectableRouteMaybeAttempted(evaluations.items, attempted_routes)) |idx| {
        return .{ .index = idx, .capability = null };
    }

    const name = profile_name orelse return .{};
    const profile = cfg.profiles.map.get(name) orelse return .{};
    const chain = profile.capability_degradation_chain orelse return .{};

    for (chain) |fallback_capability| {
        // Never re-evaluate the requested capability (it already produced no
        // selectable route); avoids redundant work and self-degradation noise.
        if (requested_capability) |req| {
            if (std.mem.eql(u8, req, fallback_capability)) continue;
        }

        var fallback_routes = try collectProfileRoutesForCapability(
            allocator,
            cfg,
            name,
            fallback_capability,
            account_filter,
        );
        defer fallback_routes.deinit();
        if (fallback_routes.items.len == 0) continue;

        var fallback_evaluations = std.ArrayList(RouteEvaluation).init(allocator);
        defer fallback_evaluations.deinit();
        try collectRouteEvaluations(allocator, cfg, store, fallback_routes.items, &fallback_evaluations);

        if (firstSelectableRouteMaybeAttempted(fallback_evaluations.items, attempted_routes)) |fallback_idx| {
            // Append the whole fallback capability's evaluations so live spares
            // are visible to the resilience/state accounting (a degraded route is
            // only truly afloat-with-spare if another live route exists too), and
            // select the first selectable one among the newly appended block.
            const base = evaluations.items.len;
            try evaluations.appendSlice(fallback_evaluations.items);
            return .{ .index = base + fallback_idx, .capability = fallback_capability };
        }
    }

    return .{};
}

// Selects the first selectable route, optionally skipping routes already attempted.
// `attempted_routes == null` matches firstSelectableRoute; non-null matches
// firstSelectableRouteNotAttempted.
fn firstSelectableRouteMaybeAttempted(
    evaluations: []const RouteEvaluation,
    attempted_routes: ?[]const RepairPlanRoute,
) ?usize {
    const attempted = attempted_routes orelse return firstSelectableRoute(evaluations);
    return firstSelectableRouteNotAttempted(evaluations, attempted);
}

// TIN-1811: count live spare routes, scoped to the degraded capability when a
// degradation occurred so `selectable_fallback_routes`/`state` reflect the
// capability that was actually selected rather than the exhausted requested one.
fn selectableFallbackRouteCountForSelection(
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    degraded_capability: ?[]const u8,
) usize {
    const cap = degraded_capability orelse return selectableFallbackRouteCount(evaluations, selected_index);
    var count: usize = 0;
    for (evaluations, 0..) |evaluation, idx| {
        if (!evaluation.selectable) continue;
        if (selected_index) |selected| {
            if (idx == selected) continue;
        }
        const route_capability = evaluation.route.capability orelse continue;
        if (!std.mem.eql(u8, route_capability, cap)) continue;
        if (selectedRouteIsSameAccount(evaluations, selected_index, evaluation.route)) continue;
        if (fallbackAccountSeenBefore(evaluations, idx, selected_index, cap, false)) continue;
        count += 1;
    }
    return count;
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
            .quota_exhausted => |quota| if (quotaWindowRevalidationNeeded(quota))
                "revalidation_needed"
            else
                "quota_exhausted",
            .cooldown => "cooldown",
        },
        .degraded => |degraded| @tagName(degraded.reason),
        .dead => |dead| @tagName(dead.reason),
    };
}

fn writeRouteText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    args: cli.Command.RouteArgs,
    degraded_capability: ?[]const u8,
) !void {
    try writer.print("oauth-mux route {s}\n\n", .{@tagName(args.action)});
    if (args.profile) |profile_name| try writer.print("  profile: {s}\n", .{profile_name});
    if (args.capability) |capability| try writer.print("  capability: {s}\n", .{capability});
    // TIN-1811 Phase 2: surface a cross-capability degrade when one occurred.
    if (degraded_capability) |cap| try writer.print("  degraded_capability: {s}\n", .{cap});
    if (selected_index) |idx| {
        const selected = evaluations[idx].route;
        try writer.print("  selected: {s}:{s}", .{ selected.provider, selected.account });
        if (selected.capability) |capability| try writer.print("#{s}", .{capability});
        try writer.writeByte('\n');
        try writeRouteResilienceActionsText(writer, allocator, cfg, evaluations, selected_index);
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
            if (try handoffPlanCommandAlloc(allocator, evaluation.action, evaluation.route)) |command| {
                defer allocator.free(command);
                try writer.print(" handoff_plan={s}", .{command});
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
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    candidate_index: ?usize,
    args: cli.Command.RouteArgs,
    degraded_capability: ?[]const u8,
) !void {
    try writeStayAfloatMediationText(writer, allocator, cfg, evaluations, selected_index, candidate_index, args, "oauth-mux stay-afloat next");
    // TIN-1811: surface a cross-capability degradation so the operator/agent sees
    // the never-halt fallback was used. Only emitted when a real degrade occurred.
    if (degraded_capability) |cap| {
        try writer.print("  degraded_capability: {s}\n", .{cap});
    }
}

fn writeStayAfloatMediationText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
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
        try writeRouteResilienceActionsText(writer, allocator, cfg, evaluations, selected_index);
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
        if (try handoffPlanCommandAlloc(allocator, candidate.action, candidate.route)) |command| {
            defer allocator.free(command);
            try writer.print("  handoff_plan: {s}\n", .{command});
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
    degraded_capability: ?[]const u8,
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
    try writer.writeAll(",\"degraded_capability\":");
    if (degraded_capability) |cap| try std.json.stringify(cap, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJson(writer, evaluations, selected_index);
    try writer.writeAll(",\"resilience_actions\":");
    try writeRouteResilienceActionsJson(writer, allocator, cfg, evaluations, selected_index, args.profile, args.capability);
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
    degraded_capability: ?[]const u8,
) !void {
    // TIN-1811: scope spare-route counting to the degraded capability when a
    // cross-capability fallback occurred, so resilience/state reflect the live
    // capability that was actually selected instead of the exhausted request.
    const fallback_count = selectableFallbackRouteCountForSelection(evaluations, selected_index, degraded_capability);
    // TIN-1812: quota-recoverable spares (scoped to the same degraded capability)
    // and the soonest reset window keep a quota-only pool out of "not_afloat".
    const recoverable_count = recoverableFallbackRouteCount(evaluations, selected_index, degraded_capability);
    const soonest_reset = soonestQuotaWindowReset(evaluations);
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
    try writer.writeAll(",\"degraded_capability\":");
    if (degraded_capability) |cap| try std.json.stringify(cap, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"resilience\":");
    try writeRouteResilienceJsonWithCount(writer, selected_index, fallback_count, recoverable_count, soonest_reset);
    try writer.writeAll(",\"resilience_actions\":");
    try writeRouteResilienceActionsJson(writer, allocator, cfg, evaluations, selected_index, args.profile, args.capability);
    try writer.writeAll(",\"claim\":");
    try writeStayAfloatClaimJson(writer, selectorFromRouteArgs(args), selectedRoute(evaluations, selected_index), fallback_count);
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
    try writeRouteAdmissionJson(writer, cfg.policy, evaluation.action, evaluation.budget, evaluation.route);
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
        try writeRouteResilienceActionsText(writer, allocator, cfg, evaluations, selected_index);
    } else {
        try writer.writeAll("  selected: none\n");
    }

    if (evaluations.len == 0) {
        try writer.writeAll("  no matching configured routes\n");
        return;
    }

    try writer.writeAll("\n  routes:\n");
    for (evaluations) |evaluation| {
        const decision = daemonTickDecision(cfg.policy, evaluation, observed_at);
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
    const stats = daemonTickStats(cfg.policy, evaluations, observed_at);

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
    try writeRouteResilienceActionsJson(writer, allocator, cfg, evaluations, selected_index, args.profile, args.capability);
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
        try writeDaemonTickDecisionJson(writer, daemonTickDecision(cfg.policy, evaluation, observed_at));
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

fn daemonTickStats(policy: config.PolicyConfig, evaluations: []const RouteEvaluation, observed_at: i64) DaemonTickStats {
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

fn daemonTickDecision(policy: config.PolicyConfig, evaluation: RouteEvaluation, observed_at: i64) DaemonTickDecision {
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
        const admission = daemonProbeAdmission(config.effectiveDaemonPolicyForProvider(policy, evaluation.route.provider), evaluation.budget);
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
        const admission = daemonRepairAdmission(config.effectiveDaemonPolicyForProvider(policy, evaluation.route.provider), evaluation.action);
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

    const admission = daemonRepairAdmission(config.effectiveDaemonPolicyForProvider(policy, evaluation.route.provider), evaluation.action);
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

    // TIN-2723: resident-service + PATH binary truth. Gathered into an arena so
    // the many small owned strings free in one shot; any failure degrades to a
    // null report (rendered "unavailable") without failing the doctor.
    var bin_arena = std.heap.ArenaAllocator.init(allocator);
    defer bin_arena.deinit();
    const binaries: ?doctor_binaries.BinariesReport =
        doctor_binaries.gather(bin_arena.allocator(), cli.version, .{}) catch null;

    if (args.json) {
        try writeDoctorJson(writer, stats, config_path, state_dir, health_path, validation_messages.items, binaries);
    } else {
        try writeDoctorText(writer, stats, config_path, state_dir, health_path, validation_messages.items, binaries);
    }
}

fn writeDoctorText(
    writer: anytype,
    stats: DoctorStats,
    config_path: []const u8,
    state_dir: []const u8,
    health_path: []const u8,
    validation_messages: []const u8,
    binaries: ?doctor_binaries.BinariesReport,
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

    try doctor_binaries.writeText(binaries, writer);

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
    binaries: ?doctor_binaries.BinariesReport,
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
    try writer.writeByte(',');
    try doctor_binaries.writeJson(binaries, writer);
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
        .reauth_in_progress => |info| {
            try writer.writeAll(",\"account\":");
            try std.json.stringify(info.account, .{}, writer);
            try writer.print(",\"started_at\":{d}", .{info.started_at});
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
    return secret_mod.writebackPlan(backend, def.repair.owner, .{
        .provider_supports_refresh = def.repair.proactive_refresh != .unsupported,
        .account_opted_in = account.allow_proactive_refresh,
    });
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
        const effective_health = health_mod.effectiveHealthForRouteSelection(h, std.time.timestamp());
        try writer.writeAll(",\"effective_liveness\":");
        try writeLivenessJson(writer, effective_health.liveness);
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
        .reauth_in_progress => |info| {
            try writer.writeAll(",\"account\":");
            try std.json.stringify(info.account, .{}, writer);
            try writer.print(",\"started_at\":{d}", .{info.started_at});
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
    ctx.probe_recheck_blocked = args.account != null;
    ctx.allow_refresh_mutation = args.allow_refresh_mutation;

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
    try writer.writeAll(",\"lock_busy\":");
    try writer.writeAll(if (ctx.last_probe_lock_busy) "true" else "false");
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
        const effective_health = health_mod.effectiveHealthForRouteSelection(h, std.time.timestamp());
        try writer.writeAll(",\"effective_liveness\":");
        try writeLivenessJson(writer, effective_health.liveness);
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
                    try writer.writeAll(",\"revalidation_needed\":");
                    try writer.writeAll(if (quotaWindowRevalidationNeeded(q)) "true" else "false");
                    try writer.writeAll(",\"reset_window_state\":");
                    if (q.window_resets_at) |reset| {
                        try std.json.stringify(if (std.time.timestamp() >= reset) "expired" else "active", .{}, writer);
                    } else {
                        try std.json.stringify("unknown", .{}, writer);
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

// TIN-2070: on macOS the real keychain item carries acct=<local username>
// (an explicit "default" never matches it), so the starter omits the account
// and lets config load derive it. Elsewhere the keychain entry is
// user-managed and keeps the historical explicit shape.
const claude_starter_account_field = if (builtin.os.tag == .macos)
    ""
else
    \\,
    \\            "account": "default"
;

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
        \\            "service": "Claude Code-credentials"
    ++ claude_starter_account_field ++
        \\
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
        \\    "profile": "codex-max",
        \\    "capability": "codex-max",
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
        \\        "codex:max-1#codex-mini",
        \\        "codex:max-2#codex-max",
        \\        "codex:max-2#codex-mini",
        \\        "codex:max-3#codex-max",
        \\        "codex:max-3#codex-mini"
        \\      ],
        \\      "capability_degradation_chain": ["codex-mini"],
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
            if (!try runCodexCli(allocator, dir, &.{"login"})) return error.CodexCommandFailed;
            recordCodexLoginSuccess(allocator, account);
        },
        .login_device => {
            const account = singleCodexAccount(args) orelse return error.MissingAccount;
            try bootstrapOneCodexDir(allocator, writer, root, account);
            const dir = try codexAccountDir(allocator, root, account);
            defer allocator.free(dir);
            if (!try runCodexCli(allocator, dir, &.{ "login", "--device-auth" })) return error.CodexCommandFailed;
            recordCodexLoginSuccess(allocator, account);
        },
        .login_status => {
            const account = singleCodexAccount(args) orelse return error.MissingAccount;
            try runCodexLoginStatusOne(allocator, writer, args, root, account);
        },
        .login_status_all => try runCodexLoginStatusAll(allocator, writer, args, root),
        .onboard => try runCodexOnboard(allocator, writer, args, root),
        .canary => try runCodexCanary(allocator, writer, args, root),
        .live_qa => try runCodexLiveQa(allocator, writer, args, root),
        .revalidate_exhausted => try runCodexRevalidateExhausted(allocator, writer, args),
        .probe_all => try runCodexProbeAll(allocator, writer, args),
        .config_candidate => try runCodexConfigCandidate(allocator, writer, args, root),
        .config_merge => try runCodexConfigMerge(allocator, writer, args),
        .preflight => try runCodexPreflight(allocator, writer, args),
        .managed_plan => try runCodexManagedPlan(allocator, writer, args),
        .managed => try runCodexManaged(allocator, writer, args),
        .status_latest => try runCodexStatusLatest(allocator, writer, args),
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

fn recordCodexLoginSuccess(allocator: std.mem.Allocator, account: []const u8) void {
    var store = health_mod.HealthStore.load(allocator, .{});
    defer store.deinit();
    store.recordAuthRefresh("codex", account);
    store.persist();
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
        if (try runCodexCli(allocator, dir, &.{ "login", "status" })) continue;
        if (args.status_only) {
            failures += 1;
            continue;
        }

        const login_argv = if (args.device)
            &[_][]const u8{ "login", "--device-auth" }
        else
            &[_][]const u8{"login"};
        if (!try runCodexCli(allocator, dir, login_argv)) {
            failures += 1;
            continue;
        }
        if (!try runCodexCli(allocator, dir, &.{ "login", "status" })) failures += 1;
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
        // revalidate-exhausted's JSON contract declares
        // mutates_user_config:false — a credential rotation would break it.
        ctx.allow_refresh_mutation = false;

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
        std.mem.eql(u8, evaluation.skip_reason, "revalidation_needed") or
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
    try writer.writeAll("  boundary: spend-gated provider revalidation; managed handoff is not proven by this command, and same-thread quota recovery remains unproven\n");
}

const CodexBrokerTokenPlan = struct {
    can_supply: bool = false,
    reason: []const u8 = "unknown",
    secret_readable: bool = false,
    access_token_present: bool = false,
    access_token_jwt_parseable: bool = false,
    access_token_expired: ?bool = null,
    access_token_expiring_soon: ?bool = null,
    refresh_token_present: bool = false,
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
    try writer.writeAll(",\"route_liveness_considered\":false,\"prepared_fallback\":false,\"broker_owned_session\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false,\"proof_status\":\"auth_material_planning_only\",\"superseded_by\":\"codex broker-session-plan\"}");
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

fn runCodexPreflight(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const parsed = try config.load(allocator);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(allocator);
    defer validation_messages.deinit();
    const config_valid = if (config.validate(parsed.value, validation_messages.writer())) |_| true else |_| false;

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
    const session_start_ready = selected_index != null;
    const fallback_ready = codexBrokerSessionSpareFallbackReady(session_start_ready, summary.selectable_fallback_routes);
    const repair_summary = try codexPreflightRepairSummary(allocator, parsed.value, evaluations.items, selected_index, session_start_ready, fallback_ready);
    const ok = config_valid and session_start_ready;

    if (args.json) {
        try writer.writeAll("{\"version\":");
        try std.json.stringify(cli.version, .{}, writer);
        try writer.writeAll(",\"mode\":\"codex_preflight\"");
        try writer.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false");
        try writer.writeAll(",\"ok\":");
        try writer.writeAll(if (ok) "true" else "false");
        try writer.writeAll(",\"config_valid\":");
        try writer.writeAll(if (config_valid) "true" else "false");
        try writer.writeAll(",\"profile\":");
        if (args.profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"capability\":");
        if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"account_filter\":");
        if (args.account) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"policy\":");
        try writePolicyJson(writer, parsed.value.policy);
        try writer.writeAll(",\"install\":");
        try writeCodexPreflightInstallJson(writer, allocator);
        try writer.writeAll(",\"environment\":");
        try writeCodexPreflightEnvironmentJson(writer, allocator);
        try writer.writeAll(",\"route_summary\":");
        try writeCodexPreflightRouteSummaryJson(writer, summary, session_start_ready, fallback_ready);
        try writer.writeAll(",\"blocked_route_reasons\":");
        try writeCodexPreflightBlockedReasonSummaryJson(writer, allocator, parsed.value, evaluations.items, selected_index);
        try writer.writeAll(",\"repair_summary\":");
        try writeCodexPreflightRepairSummaryJson(writer, repair_summary);
        try writer.writeAll(",\"blocked_routes\":");
        try writeCodexPreflightBlockedRoutesJson(writer, allocator, parsed.value, evaluations.items, selected_index);
        try writer.writeAll(",\"selected\":");
        if (selected_index) |idx| {
            try writeRouteSelectionJson(writer, evaluations.items[idx].route);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"next_actions\":");
        try writeCodexPreflightNextActionsJson(writer, allocator, args.profile, capability, session_start_ready, fallback_ready, repair_summary.spend_confirmed_repair_available);
        try writer.writeAll(",\"agent_safe_next_actions\":");
        try writeCodexPreflightAgentSafeNextActionsJson(writer, allocator, args.profile, capability, session_start_ready, fallback_ready);
        try writer.writeAll(",\"spend_confirmed_next_actions\":");
        try writeCodexPreflightSpendConfirmedNextActionsJson(writer, allocator, args.profile, capability, session_start_ready, fallback_ready, repair_summary.spend_confirmed_repair_available);
        try writer.writeAll(",\"user_mediated_next_actions\":");
        try writeCodexPreflightUserMediatedNextActionsJson(writer, allocator, parsed.value, evaluations.items);
        if (!config_valid and validation_messages.items.len != 0) {
            try writer.writeAll(",\"config_validation_hint\":");
            try std.json.stringify(std.mem.trim(u8, validation_messages.items, " \t\r\n"), .{}, writer);
        }
        try writer.writeAll("}\n");
        return;
    }

    try writer.writeAll("oauth-mux Codex preflight\n\n");
    if (args.profile) |value| try writer.print("  profile: {s}\n", .{value});
    if (capability) |value| try writer.print("  capability: {s}\n", .{value});
    var install_observation = try collectCodexPreflightInstallObservation(allocator);
    defer install_observation.deinit(allocator);
    try writeCodexPreflightInstallText(writer, install_observation);
    try writeCodexPreflightEnvironmentText(writer, allocator);
    try writer.print("  config valid: {s}\n", .{if (config_valid) "yes" else "no"});
    try writer.print("  session start ready: {s}\n", .{if (session_start_ready) "yes" else "no"});
    try writer.print("  fallback ready: {s}\n", .{if (fallback_ready) "yes" else "no"});
    try writer.print("  routes: total={d} selectable={d} broker-ready={d} selectable-fallback={d}\n", .{
        summary.routes_total,
        summary.selectable_routes,
        summary.broker_ready_routes,
        summary.selectable_fallback_routes,
    });
    try writeCodexPreflightRepairSummaryText(writer, repair_summary);
    try writeCodexPreflightBlockedRoutesText(writer, allocator, parsed.value, evaluations.items, selected_index);
    if (!session_start_ready or !fallback_ready) {
        try writeCodexPreflightNextActionsText(writer, allocator, args.profile, capability, session_start_ready, fallback_ready, repair_summary.spend_confirmed_repair_available);
        try writeCodexPreflightUserMediatedNextActionsText(writer, allocator, parsed.value, evaluations.items);
    }
}

const CodexPreflightInstallObservation = struct {
    active_oauth_mux: []u8,
    oauth_mux_candidates: PathCandidateList,
    active_oauth_mux_is_path_first: bool,
    codex_candidates: PathCandidateList,
    active_codex: ?[]const u8,
    active_codex_is_oauth_mux_shim: bool,
    native_codex_candidate: ?[]const u8,
    codex_shim_candidates: usize,

    fn deinit(self: *CodexPreflightInstallObservation, allocator: std.mem.Allocator) void {
        allocator.free(self.active_oauth_mux);
        self.oauth_mux_candidates.deinit(allocator);
        self.codex_candidates.deinit(allocator);
    }
};

fn collectCodexPreflightInstallObservation(allocator: std.mem.Allocator) !CodexPreflightInstallObservation {
    const self_path = std.fs.selfExePathAlloc(allocator) catch try allocator.dupe(u8, "unknown");
    errdefer allocator.free(self_path);

    var oauth_mux_candidates = try collectPathCandidates(allocator, "oauth-mux");
    errdefer oauth_mux_candidates.deinit(allocator);
    var codex_candidates = try collectPathCandidates(allocator, "codex");
    errdefer codex_candidates.deinit(allocator);

    const active_oauth_mux_is_path_first = oauth_mux_candidates.paths.items.len != 0 and
        try executablePathsEquivalent(allocator, oauth_mux_candidates.paths.items[0], self_path);
    const active_codex = if (codex_candidates.paths.items.len == 0) null else codex_candidates.paths.items[0];
    const active_codex_is_oauth_mux_shim = if (active_codex) |path| try isOauthMuxShimPath(allocator, path) else false;
    const native_codex_candidate = try firstNativeCodexCandidate(allocator, codex_candidates.paths.items);
    const codex_shim_candidates = try countOauthMuxShimCandidates(allocator, codex_candidates.paths.items);

    return .{
        .active_oauth_mux = self_path,
        .oauth_mux_candidates = oauth_mux_candidates,
        .active_oauth_mux_is_path_first = active_oauth_mux_is_path_first,
        .codex_candidates = codex_candidates,
        .active_codex = active_codex,
        .active_codex_is_oauth_mux_shim = active_codex_is_oauth_mux_shim,
        .native_codex_candidate = native_codex_candidate,
        .codex_shim_candidates = codex_shim_candidates,
    };
}

fn writeCodexPreflightInstallJson(writer: anytype, allocator: std.mem.Allocator) !void {
    var observation = try collectCodexPreflightInstallObservation(allocator);
    defer observation.deinit(allocator);
    try writeCodexPreflightInstallObservationJson(writer, observation);
}

fn writeCodexPreflightInstallObservationJson(writer: anytype, observation: CodexPreflightInstallObservation) !void {
    try writer.writeAll("{\"active_oauth_mux\":");
    try std.json.stringify(observation.active_oauth_mux, .{}, writer);
    try writer.writeAll(",\"oauth_mux_candidates\":");
    try writeStringArrayJson(writer, observation.oauth_mux_candidates.paths.items);
    try writer.writeAll(",\"active_oauth_mux_is_path_first\":");
    try writer.writeAll(if (observation.active_oauth_mux_is_path_first) "true" else "false");
    try writer.writeAll(",\"codex_candidates\":");
    try writeStringArrayJson(writer, observation.codex_candidates.paths.items);
    try writer.writeAll(",\"active_codex\":");
    if (observation.active_codex) |path| try std.json.stringify(path, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"active_codex_is_oauth_mux_shim\":");
    try writer.writeAll(if (observation.active_codex_is_oauth_mux_shim) "true" else "false");
    try writer.writeAll(",\"native_codex_candidate\":");
    if (observation.native_codex_candidate) |path| try std.json.stringify(path, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"native_codex_found\":");
    try writer.writeAll(if (observation.native_codex_candidate != null) "true" else "false");
    try writer.print(",\"codex_shim_candidates\":{d}", .{observation.codex_shim_candidates});
    try writer.writeAll(",\"managed_codex_shim_supported\":true,\"native_codex_env\":\"OMUX_CODEX_BIN\"}");
}

fn writeCodexPreflightInstallText(writer: anytype, observation: CodexPreflightInstallObservation) !void {
    try writer.writeAll("  install:\n");
    try writer.print("    active oauth-mux: {s}\n", .{observation.active_oauth_mux});
    try writer.print("    oauth-mux path first: {s}\n", .{if (observation.active_oauth_mux_is_path_first) "yes" else "no"});
    try writer.print("    active codex: {s}\n", .{observation.active_codex orelse "not found"});
    try writer.print("    active codex is oauth-mux shim: {s}\n", .{if (observation.active_codex_is_oauth_mux_shim) "yes" else "no"});
    try writer.print("    native codex: {s}\n", .{observation.native_codex_candidate orelse "not found"});
    try writer.print("    codex shim candidates: {d}\n", .{observation.codex_shim_candidates});
    try writer.writeAll("    native codex env: OMUX_CODEX_BIN\n");
    if (!observation.active_oauth_mux_is_path_first) {
        try writer.writeAll("    note: this oauth-mux is not first on PATH; compare `which -a oauth-mux` before dogfood\n");
    }
    if (observation.active_codex_is_oauth_mux_shim) {
        if (observation.native_codex_candidate != null) {
            try writer.writeAll("    note: active `codex` routes through oauth-mux; native Codex is available via OMUX_CODEX_BIN\n");
        } else {
            try writer.writeAll("    note: active `codex` is the oauth-mux shim, but no native Codex binary was found\n");
        }
    } else if (observation.active_codex != null) {
        try writer.writeAll("    note: active `codex` is native/unmanaged; use `oauth-mux codex` or install the managed shim for muxed Codex\n");
    } else {
        try writer.writeAll("    note: no `codex` binary was found on PATH\n");
    }
}

fn executablePathsEquivalent(allocator: std.mem.Allocator, lhs: []const u8, rhs: []const u8) !bool {
    if (std.mem.eql(u8, lhs, rhs)) return true;

    const lhs_real = try realpathOrDupe(allocator, lhs);
    defer allocator.free(lhs_real);
    const rhs_real = try realpathOrDupe(allocator, rhs);
    defer allocator.free(rhs_real);

    return std.mem.eql(u8, lhs_real, rhs_real);
}

fn realpathOrDupe(allocator: std.mem.Allocator, path_value: []const u8) ![]u8 {
    return std.fs.realpathAlloc(allocator, path_value) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied => try allocator.dupe(u8, path_value),
        else => return err,
    };
}

fn envVarPresent(name: []const u8) bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(value);
    return true;
}

fn envManagedCodexOverlayPresent(allocator: std.mem.Allocator) !bool {
    const path_value = std.process.getEnvVarOwned(allocator, "CODEX_HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(path_value);
    return try codexManagedOverlayHomeForPlanning(allocator, path_value);
}

fn writeCodexPreflightEnvironmentJson(writer: anytype, allocator: std.mem.Allocator) !void {
    const codex_home_set = envVarPresent("CODEX_HOME");
    const managed_overlay = try envManagedCodexOverlayPresent(allocator);
    const inherited_managed_frame = envVarPresent("OMUX_MANAGED_FRAME_ID") or
        envVarPresent("OMUX_ACTIVE_ACCOUNT") or
        envVarPresent("OMUX_STATUS_FILE");

    try writer.writeAll("{\"codex_home_set\":");
    try writer.writeAll(if (codex_home_set) "true" else "false");
    try writer.writeAll(",\"codex_home_managed_overlay\":");
    try writer.writeAll(if (managed_overlay) "true" else "false");
    try writer.writeAll(",\"omux_managed_env_present\":");
    try writer.writeAll(if (inherited_managed_frame) "true" else "false");
    try writer.writeAll(",\"omux_active_account_present\":");
    try writer.writeAll(if (envVarPresent("OMUX_ACTIVE_ACCOUNT")) "true" else "false");
    try writer.writeAll(",\"omux_status_file_present\":");
    try writer.writeAll(if (envVarPresent("OMUX_STATUS_FILE")) "true" else "false");
    try writer.writeAll(",\"omux_codex_session_home_present\":");
    try writer.writeAll(if (envVarPresent("OMUX_CODEX_SESSION_HOME")) "true" else "false");
    try writer.writeAll(",\"omux_codex_config_home_present\":");
    try writer.writeAll(if (envVarPresent("OMUX_CODEX_CONFIG_HOME")) "true" else "false");
    try writer.writeAll(",\"path_printed\":false}");
}

fn writeCodexPreflightEnvironmentText(writer: anytype, allocator: std.mem.Allocator) !void {
    const codex_home_set = envVarPresent("CODEX_HOME");
    const managed_overlay = try envManagedCodexOverlayPresent(allocator);
    const inherited_managed_frame = envVarPresent("OMUX_MANAGED_FRAME_ID") or
        envVarPresent("OMUX_ACTIVE_ACCOUNT") or
        envVarPresent("OMUX_STATUS_FILE");

    try writer.writeAll("  environment:\n");
    try writer.print("    CODEX_HOME set: {s}\n", .{if (codex_home_set) "yes" else "no"});
    try writer.print("    CODEX_HOME is oauth-mux overlay: {s}\n", .{if (managed_overlay) "yes" else "no"});
    try writer.print("    inherited managed oauth-mux env: {s}\n", .{if (inherited_managed_frame) "yes" else "no"});
    try writer.print("    OMUX_CODEX_SESSION_HOME set: {s}\n", .{if (envVarPresent("OMUX_CODEX_SESSION_HOME")) "yes" else "no"});
    try writer.print("    OMUX_CODEX_CONFIG_HOME set: {s}\n", .{if (envVarPresent("OMUX_CODEX_CONFIG_HOME")) "yes" else "no"});
    if (managed_overlay) {
        try writer.writeAll("    note: parent CODEX_HOME is a managed overlay; oauth-mux ignores it as reusable session/config authority\n");
    }
}

const PathCandidateList = struct {
    paths: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *PathCandidateList, allocator: std.mem.Allocator) void {
        for (self.paths.items) |item| allocator.free(item);
        self.paths.deinit(allocator);
    }
};

fn collectPathCandidates(allocator: std.mem.Allocator, name: []const u8) !PathCandidateList {
    var result = PathCandidateList{};
    errdefer result.deinit(allocator);

    const path_env = std.process.getEnvVarOwned(allocator, "PATH") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => return result,
        else => return e,
    };
    defer allocator.free(path_env);

    var it = std.mem.tokenizeScalar(u8, path_env, std.fs.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, name });
        errdefer allocator.free(candidate);
        if (!fileExists(candidate)) {
            allocator.free(candidate);
            continue;
        }
        try result.paths.append(allocator, candidate);
    }
    return result;
}

fn firstNativeCodexCandidate(allocator: std.mem.Allocator, candidates: []const []const u8) !?[]const u8 {
    for (candidates) |candidate| {
        if (!(try isOauthMuxShimPath(allocator, candidate))) return candidate;
    }
    return null;
}

fn countOauthMuxShimCandidates(allocator: std.mem.Allocator, candidates: []const []const u8) !usize {
    var count: usize = 0;
    for (candidates) |candidate| {
        if (try isOauthMuxShimPath(allocator, candidate)) count += 1;
    }
    return count;
}

fn isOauthMuxShimPath(allocator: std.mem.Allocator, path_value: []const u8) !bool {
    _ = allocator;
    var buf: [4096]u8 = undefined;
    const len = readFilePrefix(path_value, &buf) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied, error.IsDir => return false,
        else => return e,
    };
    const data = buf[0..len];
    return std.mem.indexOf(u8, data, "OMUX_CODEX_SHIM") != null;
}

fn readFilePrefix(path_value: []const u8, buf: []u8) !usize {
    const file = if (std.fs.path.isAbsolute(path_value))
        try std.fs.openFileAbsolute(path_value, .{})
    else
        try std.fs.cwd().openFile(path_value, .{});
    defer file.close();
    return try file.read(buf);
}

test "Codex preflight install diagnostics classify shim and native candidates" {
    var shim_tmp = std.testing.tmpDir(.{});
    defer shim_tmp.cleanup();
    var native_tmp = std.testing.tmpDir(.{});
    defer native_tmp.cleanup();

    const shim_file = try shim_tmp.dir.createFile("codex", .{ .mode = 0o755 });
    try shim_file.writeAll("#!/bin/sh\n# OMUX_CODEX_SHIM\nexec oauth-mux codex \"$@\"\n");
    shim_file.close();
    const native_file = try native_tmp.dir.createFile("codex", .{ .mode = 0o755 });
    try native_file.writeAll("#!/bin/sh\nexec true\n");
    native_file.close();

    const shim_path = try shim_tmp.dir.realpathAlloc(std.testing.allocator, "codex");
    defer std.testing.allocator.free(shim_path);
    const native_path = try native_tmp.dir.realpathAlloc(std.testing.allocator, "codex");
    defer std.testing.allocator.free(native_path);

    const candidates = [_][]const u8{ shim_path, native_path };
    try std.testing.expect(try isOauthMuxShimPath(std.testing.allocator, shim_path));
    try std.testing.expect(!(try isOauthMuxShimPath(std.testing.allocator, native_path)));
    try std.testing.expectEqual(@as(usize, 1), try countOauthMuxShimCandidates(std.testing.allocator, &candidates));
    const native = (try firstNativeCodexCandidate(std.testing.allocator, &candidates)).?;
    try std.testing.expectEqualStrings(native_path, native);
}

test "executablePathsEquivalent follows Homebrew-style symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();
    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();

    const target_file = try target_tmp.dir.createFile("oauth-mux", .{ .mode = 0o755 });
    try target_file.writeAll("#!/bin/sh\nexit 0\n");
    target_file.close();

    const target_path = try target_tmp.dir.realpathAlloc(std.testing.allocator, "oauth-mux");
    defer std.testing.allocator.free(target_path);
    const bin_root = try bin_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(bin_root);
    const link_path = try std.fs.path.join(std.testing.allocator, &.{ bin_root, "oauth-mux" });
    defer std.testing.allocator.free(link_path);

    try std.fs.symLinkAbsolute(target_path, link_path, .{});
    try std.testing.expect(try executablePathsEquivalent(std.testing.allocator, link_path, target_path));
}

fn writeCodexPreflightRouteSummaryJson(
    writer: anytype,
    summary: CodexBrokerSessionSummary,
    session_start_ready: bool,
    fallback_ready: bool,
) !void {
    try writer.print(
        "{{\"routes_total\":{d},\"broker_ready_routes\":{d},\"unreadable_routes\":{d},\"selectable_routes\":{d},\"selectable_broker_routes\":{d},\"selectable_fallback_routes\":{d},\"blocked_broker_routes\":{d},\"auth_unready_routes\":{d},\"session_start_ready\":{any},\"fallback_ready\":{any},\"single_route_at_risk\":{any}}}",
        .{
            summary.routes_total,
            summary.broker_ready_routes,
            summary.unreadable_routes,
            summary.selectable_routes,
            summary.selectable_broker_routes,
            summary.selectable_fallback_routes,
            summary.blocked_broker_routes,
            summary.auth_unready_routes,
            session_start_ready,
            fallback_ready,
            codexBrokerSessionSingleRouteAtRisk(session_start_ready, summary.selectable_fallback_routes),
        },
    );
}

fn codexPreflightRouteSessionReady(evaluation: RouteEvaluation, plan: CodexBrokerTokenPlan) bool {
    return plan.can_supply and evaluation.selectable;
}

fn codexPreflightRouteBlockedReason(evaluation: RouteEvaluation, selected: bool, plan: CodexBrokerTokenPlan) []const u8 {
    _ = selected;
    if (!plan.can_supply) return "auth_broker_unready";
    return evaluation.skip_reason;
}

fn writeCodexPreflightBlockedReasonSummaryJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    try writer.writeByte('[');
    var first = true;
    for (evaluations, 0..) |evaluation, idx| {
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        const reason = codexPreflightRouteBlockedReason(evaluation, selected, plan);

        var seen = false;
        for (evaluations[0..idx], 0..) |previous, previous_idx| {
            const previous_selected = if (selected_index) |selected_idx| previous_idx == selected_idx else false;
            const previous_plan = try inspectCodexBrokerRoute(allocator, cfg, previous.route);
            if (codexPreflightRouteSessionReady(previous, previous_plan)) continue;
            const previous_reason = codexPreflightRouteBlockedReason(previous, previous_selected, previous_plan);
            if (std.mem.eql(u8, previous_reason, reason)) {
                seen = true;
                break;
            }
        }
        if (seen) continue;

        var count: usize = 0;
        for (evaluations, 0..) |candidate, candidate_idx| {
            const candidate_selected = if (selected_index) |selected_idx| candidate_idx == selected_idx else false;
            const candidate_plan = try inspectCodexBrokerRoute(allocator, cfg, candidate.route);
            if (codexPreflightRouteSessionReady(candidate, candidate_plan)) continue;
            const candidate_reason = codexPreflightRouteBlockedReason(candidate, candidate_selected, candidate_plan);
            if (std.mem.eql(u8, candidate_reason, reason)) count += 1;
        }

        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"reason\":");
        try std.json.stringify(reason, .{}, writer);
        try writer.print(",\"count\":{d}", .{count});
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

const CodexPreflightRepairSummary = struct {
    route_repair_required: bool,
    agent_safe_inspection_available: bool,
    spend_confirmed_repair_available: bool = false,
    user_handoff_required: bool = false,
    provider_spend_required: bool = false,
    blocked_routes: usize = 0,
    revalidation_needed_routes: usize = 0,
    quota_exhausted_routes: usize = 0,
    rate_limited_routes: usize = 0,
    tier_insufficient_routes: usize = 0,
    token_revoked_routes: usize = 0,
    provider_degraded_routes: usize = 0,
    auth_permanently_failed_routes: usize = 0,
    credential_unavailable_routes: usize = 0,
    not_afloat_routes: usize = 0,
    auth_handoff_routes: usize = 0,
    auth_broker_unready_routes: usize = 0,
    runtime_repair_routes: usize = 0,
    wait_routes: usize = 0,
    provider_plan_routes: usize = 0,
    credential_rotation_routes: usize = 0,
    manual_repair_routes: usize = 0,
    dominant_blocker: ?[]const u8 = null,
    dominant_blocker_count: usize = 0,
};

fn codexPreflightClassifyRepairRoute(summary: *CodexPreflightRepairSummary, reason: []const u8, action: RepairAction) void {
    summary.blocked_routes += 1;
    if (summary.dominant_blocker == null) summary.dominant_blocker = reason;

    if (std.mem.eql(u8, reason, "revalidation_needed")) summary.revalidation_needed_routes += 1;
    if (std.mem.eql(u8, reason, "quota_exhausted")) summary.quota_exhausted_routes += 1;
    if (std.mem.eql(u8, reason, "rate_limited")) summary.rate_limited_routes += 1;
    if (std.mem.eql(u8, reason, "tier_insufficient")) summary.tier_insufficient_routes += 1;
    if (std.mem.eql(u8, reason, "token_revoked")) summary.token_revoked_routes += 1;
    if (std.mem.eql(u8, reason, "provider_degraded")) summary.provider_degraded_routes += 1;
    if (std.mem.eql(u8, reason, "auth_permanently_failed")) summary.auth_permanently_failed_routes += 1;
    if (std.mem.eql(u8, reason, "credential_unavailable")) summary.credential_unavailable_routes += 1;
    if (std.mem.eql(u8, reason, "not_afloat")) summary.not_afloat_routes += 1;
    if (std.mem.eql(u8, reason, "auth_broker_unready")) summary.auth_broker_unready_routes += 1;

    if (action.interactive or action.mediation == .user_handoff or action.kind == .reauth) {
        summary.user_handoff_required = true;
        summary.auth_handoff_routes += 1;
    }
    if (action.budget) |budget| {
        if (budget == .spend_provider) {
            summary.provider_spend_required = true;
            if (!action.interactive and action.command != .none) summary.spend_confirmed_repair_available = true;
        }
    }

    switch (action.kind) {
        .revalidation_needed => summary.revalidation_needed_routes += if (std.mem.eql(u8, reason, "revalidation_needed")) 0 else 1,
        .fix_runtime => summary.runtime_repair_routes += 1,
        .wait_for_repair, .wait_and_retry, .wait_for_quota, .wait_for_cooldown => summary.wait_routes += 1,
        .provider_plan => summary.provider_plan_routes += 1,
        .external_secret_rotation => summary.credential_rotation_routes += 1,
        .manual_repair => summary.manual_repair_routes += 1,
        else => {},
    }
}

fn codexPreflightSetDominantBlocker(summary: *CodexPreflightRepairSummary, reason: []const u8, count: usize) void {
    if (count == 0) return;
    if (summary.dominant_blocker_count == 0 or count > summary.dominant_blocker_count) {
        summary.dominant_blocker = reason;
        summary.dominant_blocker_count = count;
    }
}

fn codexPreflightFinalizeRepairSummary(summary: *CodexPreflightRepairSummary) void {
    codexPreflightSetDominantBlocker(summary, "revalidation_needed", summary.revalidation_needed_routes);
    codexPreflightSetDominantBlocker(summary, "quota_exhausted", summary.quota_exhausted_routes);
    codexPreflightSetDominantBlocker(summary, "rate_limited", summary.rate_limited_routes);
    codexPreflightSetDominantBlocker(summary, "tier_insufficient", summary.tier_insufficient_routes);
    codexPreflightSetDominantBlocker(summary, "token_revoked", summary.token_revoked_routes);
    codexPreflightSetDominantBlocker(summary, "provider_degraded", summary.provider_degraded_routes);
    codexPreflightSetDominantBlocker(summary, "auth_permanently_failed", summary.auth_permanently_failed_routes);
    codexPreflightSetDominantBlocker(summary, "credential_unavailable", summary.credential_unavailable_routes);
    codexPreflightSetDominantBlocker(summary, "not_afloat", summary.not_afloat_routes);
    codexPreflightSetDominantBlocker(summary, "auth_broker_unready", summary.auth_broker_unready_routes);
    if (summary.dominant_blocker_count == 0 and summary.blocked_routes != 0) summary.dominant_blocker_count = 1;
}

fn codexPreflightRepairSummary(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    session_start_ready: bool,
    fallback_ready: bool,
) !CodexPreflightRepairSummary {
    var summary = CodexPreflightRepairSummary{
        .route_repair_required = !session_start_ready or !fallback_ready,
        .agent_safe_inspection_available = !session_start_ready or !fallback_ready,
    };

    for (evaluations, 0..) |evaluation, idx| {
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        const reason = codexPreflightRouteBlockedReason(evaluation, selected, plan);
        codexPreflightClassifyRepairRoute(&summary, reason, evaluation.action);
    }
    codexPreflightFinalizeRepairSummary(&summary);

    return summary;
}

fn writeCodexPreflightRepairSummaryJson(
    writer: anytype,
    summary: CodexPreflightRepairSummary,
) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"route_repair_required\":");
    try writer.writeAll(if (summary.route_repair_required) "true" else "false");
    try writer.writeAll(",\"agent_safe_inspection_available\":");
    try writer.writeAll(if (summary.agent_safe_inspection_available) "true" else "false");
    try writer.writeAll(",\"spend_confirmed_repair_available\":");
    try writer.writeAll(if (summary.spend_confirmed_repair_available) "true" else "false");
    try writer.writeAll(",\"user_handoff_required\":");
    try writer.writeAll(if (summary.user_handoff_required) "true" else "false");
    try writer.writeAll(",\"provider_spend_required\":");
    try writer.writeAll(if (summary.provider_spend_required) "true" else "false");
    try writer.print(",\"blocked_routes\":{d}", .{summary.blocked_routes});
    try writer.print(",\"revalidation_needed_routes\":{d}", .{summary.revalidation_needed_routes});
    try writer.print(",\"quota_exhausted_routes\":{d}", .{summary.quota_exhausted_routes});
    try writer.print(",\"rate_limited_routes\":{d}", .{summary.rate_limited_routes});
    try writer.print(",\"tier_insufficient_routes\":{d}", .{summary.tier_insufficient_routes});
    try writer.print(",\"token_revoked_routes\":{d}", .{summary.token_revoked_routes});
    try writer.print(",\"provider_degraded_routes\":{d}", .{summary.provider_degraded_routes});
    try writer.print(",\"auth_permanently_failed_routes\":{d}", .{summary.auth_permanently_failed_routes});
    try writer.print(",\"credential_unavailable_routes\":{d}", .{summary.credential_unavailable_routes});
    try writer.print(",\"not_afloat_routes\":{d}", .{summary.not_afloat_routes});
    try writer.print(",\"auth_handoff_routes\":{d}", .{summary.auth_handoff_routes});
    try writer.print(",\"auth_broker_unready_routes\":{d}", .{summary.auth_broker_unready_routes});
    try writer.print(",\"runtime_repair_routes\":{d}", .{summary.runtime_repair_routes});
    try writer.print(",\"wait_routes\":{d}", .{summary.wait_routes});
    try writer.print(",\"provider_plan_routes\":{d}", .{summary.provider_plan_routes});
    try writer.print(",\"credential_rotation_routes\":{d}", .{summary.credential_rotation_routes});
    try writer.print(",\"manual_repair_routes\":{d}", .{summary.manual_repair_routes});
    try writer.writeAll(",\"dominant_blocker\":");
    if (summary.dominant_blocker) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.print(",\"dominant_blocker_count\":{d}", .{summary.dominant_blocker_count});
    try writer.writeByte('}');
}

fn writeCodexPreflightRepairSummaryText(
    writer: anytype,
    summary: CodexPreflightRepairSummary,
) !void {
    if (summary.blocked_routes == 0) return;
    try writer.print("  repair summary: required={s}", .{if (summary.route_repair_required) "yes" else "no"});
    if (summary.dominant_blocker) |value| {
        try writer.print(" dominant_blocker={s}({d})", .{ value, summary.dominant_blocker_count });
    }
    if (summary.revalidation_needed_routes != 0) try writer.print(" revalidation_needed={d}", .{summary.revalidation_needed_routes});
    if (summary.quota_exhausted_routes != 0) try writer.print(" quota_exhausted={d}", .{summary.quota_exhausted_routes});
    if (summary.rate_limited_routes != 0) try writer.print(" rate_limited={d}", .{summary.rate_limited_routes});
    if (summary.tier_insufficient_routes != 0) try writer.print(" tier_insufficient={d}", .{summary.tier_insufficient_routes});
    if (summary.token_revoked_routes != 0) try writer.print(" token_revoked={d}", .{summary.token_revoked_routes});
    if (summary.provider_degraded_routes != 0) try writer.print(" provider_degraded={d}", .{summary.provider_degraded_routes});
    if (summary.auth_permanently_failed_routes != 0) try writer.print(" auth_permanently_failed={d}", .{summary.auth_permanently_failed_routes});
    if (summary.credential_unavailable_routes != 0) try writer.print(" credential_unavailable={d}", .{summary.credential_unavailable_routes});
    if (summary.not_afloat_routes != 0) try writer.print(" not_afloat={d}", .{summary.not_afloat_routes});
    if (summary.auth_broker_unready_routes != 0) try writer.print(" auth_broker_unready={d}", .{summary.auth_broker_unready_routes});
    if (summary.auth_handoff_routes != 0) try writer.print(" auth_handoff={d}", .{summary.auth_handoff_routes});
    if (summary.runtime_repair_routes != 0) try writer.print(" runtime_repair={d}", .{summary.runtime_repair_routes});
    if (summary.wait_routes != 0) try writer.print(" wait={d}", .{summary.wait_routes});
    try writer.print(" spend_confirmed_available={s} user_handoff_required={s}\n", .{
        if (summary.spend_confirmed_repair_available) "yes" else "no",
        if (summary.user_handoff_required) "yes" else "no",
    });
}

fn writeCodexPreflightBlockedRoutesJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    try writer.writeByte('[');
    var first = true;
    for (evaluations, 0..) |evaluation, idx| {
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeByte('{');
        try writer.writeAll("\"provider\":");
        try std.json.stringify(evaluation.route.provider, .{}, writer);
        try writer.writeAll(",\"account\":");
        try std.json.stringify(evaluation.route.account, .{}, writer);
        try writer.writeAll(",\"capability\":");
        if (evaluation.route.capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"selectable\":");
        try writer.writeAll(if (evaluation.selectable) "true" else "false");
        try writer.writeAll(",\"broker_ready\":");
        try writer.writeAll(if (plan.can_supply) "true" else "false");
        try writer.writeAll(",\"route_role\":");
        try std.json.stringify(codexBrokerSessionRouteRole(evaluation, selected, plan, false), .{}, writer);
        try writer.writeAll(",\"blocked_reason\":");
        try std.json.stringify(codexPreflightRouteBlockedReason(evaluation, selected, plan), .{}, writer);
        try writer.writeAll(",\"skip_reason\":");
        try std.json.stringify(evaluation.skip_reason, .{}, writer);
        try writer.writeAll(",\"liveness\":");
        if (evaluation.health) |health| try writeLivenessJson(writer, health.liveness) else try writer.writeAll("null");
        try writer.writeAll(",\"auth_material\":");
        try writeCodexPreflightAuthMaterialJson(writer, allocator, cfg, evaluation, plan);
        try writer.writeAll(",\"action\":");
        try writeRepairActionJson(writer, allocator, evaluation.action, evaluation.route);
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn writeCodexPreflightAuthMaterialJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluation: RouteEvaluation,
    plan: CodexBrokerTokenPlan,
) !void {
    const modified_at = routeAuthMaterialModifiedAt(allocator, cfg, evaluation.route);
    const last_probe_at = if (evaluation.health) |health| health.last_probe_observed_at else null;
    const material_newer = if (modified_at) |mtime| blk: {
        const observed = last_probe_at orelse break :blk null;
        break :blk mtime > observed;
    } else null;

    try writer.writeByte('{');
    try writer.writeAll("\"secret_readable\":");
    try writer.writeAll(if (plan.secret_readable) "true" else "false");
    try writer.writeAll(",\"broker_ready\":");
    try writer.writeAll(if (plan.can_supply) "true" else "false");
    try writer.writeAll(",\"refresh_token_present\":");
    try writer.writeAll(if (plan.refresh_token_present) "true" else "false");
    try writer.writeAll(",\"access_token_expired\":");
    try writeOptionalBoolJson(writer, plan.access_token_expired);
    try writer.writeAll(",\"access_token_expiring_soon\":");
    try writeOptionalBoolJson(writer, plan.access_token_expiring_soon);
    try writer.writeAll(",\"modified_at\":");
    if (modified_at) |value| try writer.print("{d}", .{value}) else try writer.writeAll("null");
    try writer.writeAll(",\"last_probe_observed_at\":");
    if (last_probe_at) |value| try writer.print("{d}", .{value}) else try writer.writeAll("null");
    try writer.writeAll(",\"material_newer_than_last_probe\":");
    try writeOptionalBoolJson(writer, material_newer);
    try writer.writeAll(",\"path_printed\":false,\"token_material_printed\":false}");
}

fn routeAuthMaterialModifiedAt(
    allocator: std.mem.Allocator,
    cfg: config.Config,
    route: RepairPlanRoute,
) ?i64 {
    const prov = cfg.providers.map.get(route.provider) orelse return null;
    const account = prov.accounts.map.get(route.account) orelse return null;
    const backend = config.resolveSecretBackend(account.secret) catch return null;
    return switch (backend) {
        .file => |ref| fileModifiedAt(allocator, ref.path),
        else => null,
    };
}

fn fileModifiedAt(allocator: std.mem.Allocator, raw_path: []const u8) ?i64 {
    const expanded = paths.expandTilde(allocator, raw_path) catch return null;
    defer allocator.free(expanded);
    const file = if (std.fs.path.isAbsolute(expanded))
        std.fs.openFileAbsolute(expanded, .{}) catch return null
    else
        std.fs.cwd().openFile(expanded, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    return std.math.cast(i64, @divFloor(stat.mtime, std.time.ns_per_s)) orelse null;
}

fn writeCodexPreflightBlockedRoutesText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
) !void {
    var blocked_count: usize = 0;
    for (evaluations, 0..) |evaluation, idx| {
        const selected = if (selected_index) |selected_idx| idx == selected_idx else false;
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        if (blocked_count == 0) try writer.writeAll("  blocked routes:\n");
        blocked_count += 1;
        const role = codexBrokerSessionRouteRole(evaluation, selected, plan, false);
        const reason = codexPreflightRouteBlockedReason(evaluation, selected, plan);
        try writer.print("    - {s}:{s}", .{ evaluation.route.provider, evaluation.route.account });
        if (evaluation.route.capability) |value| try writer.print("#{s}", .{value});
        try writer.print(" reason={s} role={s} action={s}", .{ reason, role, @tagName(evaluation.action.kind) });
        if (try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route)) |command| {
            defer allocator.free(command);
            try writer.print(" command=\"{s}\"", .{command});
        }
        try writer.writeByte('\n');
    }
}

fn writeCodexPreflightNextActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    fallback_ready: bool,
    spend_confirmed_repair_available: bool,
) !void {
    try writer.writeByte('[');
    var first = true;
    if (!session_start_ready or !fallback_ready) {
        const plan = try codexPreflightPlanCommand(allocator, profile, capability);
        defer allocator.free(plan);
        try writeCommaJsonString(writer, &first, plan);
    }
    if ((!session_start_ready or !fallback_ready) and spend_confirmed_repair_available) {
        const refresh = try codexPreflightStayAfloatCommand(allocator, profile, capability);
        defer allocator.free(refresh);
        try writeCommaJsonString(writer, &first, refresh);
    }
    try writer.writeByte(']');
}

fn writeCodexPreflightAgentSafeNextActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    fallback_ready: bool,
) !void {
    try writer.writeByte('[');
    var first = true;
    if (!session_start_ready or !fallback_ready) {
        const plan = try codexPreflightPlanCommand(allocator, profile, capability);
        defer allocator.free(plan);
        try writeCodexPreflightActionObjectJson(writer, &first, .{
            .kind = "broker_session_plan",
            .label = "local broker route plan",
            .command = plan,
            .budget = "free_local",
            .agent_safe = true,
            .may_spend_provider_calls = false,
            .mutates_user_config = false,
            .mutates_route_health = false,
            .interactive = false,
        });
    }
    try writer.writeByte(']');
}

fn writeCodexPreflightSpendConfirmedNextActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    fallback_ready: bool,
    spend_confirmed_repair_available: bool,
) !void {
    try writer.writeByte('[');
    var first = true;
    if ((!session_start_ready or !fallback_ready) and spend_confirmed_repair_available) {
        const refresh = try codexPreflightStayAfloatCommand(allocator, profile, capability);
        defer allocator.free(refresh);
        try writeCodexPreflightActionObjectJson(writer, &first, .{
            .kind = "stay_afloat_execute",
            .label = "spend-confirmed route health repair",
            .command = refresh,
            .budget = "spend_provider",
            .agent_safe = false,
            .may_spend_provider_calls = true,
            .mutates_user_config = false,
            .mutates_route_health = true,
            .interactive = false,
        });
    }
    try writer.writeByte(']');
}

fn writeCodexPreflightUserMediatedNextActionsJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
) !void {
    try writer.writeByte('[');
    var first = true;
    for (evaluations) |evaluation| {
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        _ = try writeCodexPreflightUserMediatedActionJson(writer, allocator, &first, evaluation.action, evaluation.route);
    }
    try writer.writeByte(']');
}

const CodexPreflightActionObject = struct {
    kind: []const u8,
    label: []const u8,
    command: []const u8,
    budget: []const u8,
    agent_safe: bool,
    may_spend_provider_calls: bool,
    mutates_user_config: bool,
    mutates_route_health: bool,
    interactive: bool,
};

fn writeCodexPreflightUserMediatedActionJson(
    writer: anytype,
    allocator: std.mem.Allocator,
    first: *bool,
    action: RepairAction,
    route: RepairPlanRoute,
) !bool {
    if (action.mediation != .user_handoff) return false;
    const command = (try repairCommandAlloc(allocator, action.command, route)) orelse return false;
    defer allocator.free(command);
    try writeCodexPreflightActionObjectJson(writer, first, .{
        .kind = @tagName(action.command),
        .label = "user-mediated upstream CLI repair",
        .command = command,
        .budget = "interactive",
        .agent_safe = false,
        .may_spend_provider_calls = false,
        .mutates_user_config = true,
        .mutates_route_health = false,
        .interactive = true,
    });
    return true;
}

fn writeCodexPreflightActionObjectJson(
    writer: anytype,
    first: *bool,
    action: CodexPreflightActionObject,
) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try std.json.stringify(action.kind, .{}, writer);
    try writer.writeAll(",\"label\":");
    try std.json.stringify(action.label, .{}, writer);
    try writer.writeAll(",\"command\":");
    try std.json.stringify(action.command, .{}, writer);
    try writer.writeAll(",\"budget\":");
    try std.json.stringify(action.budget, .{}, writer);
    try writer.writeAll(",\"agent_safe\":");
    try writer.writeAll(if (action.agent_safe) "true" else "false");
    try writer.writeAll(",\"may_spend_provider_calls\":");
    try writer.writeAll(if (action.may_spend_provider_calls) "true" else "false");
    try writer.writeAll(",\"mutates_user_config\":");
    try writer.writeAll(if (action.mutates_user_config) "true" else "false");
    try writer.writeAll(",\"mutates_route_health\":");
    try writer.writeAll(if (action.mutates_route_health) "true" else "false");
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (action.interactive) "true" else "false");
    try writer.writeByte('}');
}

fn writeCodexPreflightUserMediatedNextActionsText(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    evaluations: []const RouteEvaluation,
) !void {
    var printed = false;
    for (evaluations) |evaluation| {
        const plan = try inspectCodexBrokerRoute(allocator, cfg, evaluation.route);
        if (codexPreflightRouteSessionReady(evaluation, plan)) continue;
        if (evaluation.action.mediation != .user_handoff) continue;
        if (try repairCommandAlloc(allocator, evaluation.action.command, evaluation.route)) |command| {
            defer allocator.free(command);
            if (!printed) {
                printed = true;
                try writer.writeAll("\nUser-mediated repair:\n");
            }
            try writer.print("  {s}\n", .{command});
            try writer.writeAll("    budget=interactive agent_safe=false may_spend_provider_calls=false mutates_user_config=true interactive=true\n");
        }
    }
}

fn writeCodexPreflightNextActionsText(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    fallback_ready: bool,
    spend_confirmed_repair_available: bool,
) !void {
    if (!session_start_ready or !fallback_ready) {
        const plan = try codexPreflightPlanCommand(allocator, profile, capability);
        defer allocator.free(plan);
        try writer.writeAll("\nLocal diagnostics:\n");
        try writer.print("  {s}\n", .{plan});
    }
    if ((!session_start_ready or !fallback_ready) and spend_confirmed_repair_available) {
        const refresh = try codexPreflightStayAfloatCommand(allocator, profile, capability);
        defer allocator.free(refresh);
        try writer.writeAll("\nSpend-confirmed repair:\n");
        try writer.print("  {s}\n", .{refresh});
        try writer.writeAll("    budget=spend_provider agent_safe=false may_spend_provider_calls=true mutates_route_health=true\n");
    }
}

fn writeCommaJsonString(writer: anytype, first: *bool, value: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try std.json.stringify(value, .{}, writer);
}

fn codexPreflightStayAfloatCommand(allocator: std.mem.Allocator, profile: ?[]const u8, capability: ?[]const u8) ![]u8 {
    if (profile) |p| {
        if (capability) |c| {
            return try std.fmt.allocPrint(allocator, "oauth-mux stay-afloat --once --execute --profile {s} --capability {s} --json", .{ p, c });
        }
        return try std.fmt.allocPrint(allocator, "oauth-mux stay-afloat --once --execute --profile {s} --json", .{p});
    }
    if (capability) |c| {
        return try std.fmt.allocPrint(allocator, "oauth-mux stay-afloat --once --execute --provider codex --capability {s} --json", .{c});
    }
    return try allocator.dupe(u8, "oauth-mux stay-afloat --once --execute --provider codex --json");
}

fn codexPreflightPlanCommand(allocator: std.mem.Allocator, profile: ?[]const u8, capability: ?[]const u8) ![]u8 {
    if (profile) |p| {
        if (capability) |c| {
            return try std.fmt.allocPrint(allocator, "oauth-mux codex broker-session-plan --profile {s} --capability {s} --json", .{ p, c });
        }
        return try std.fmt.allocPrint(allocator, "oauth-mux codex broker-session-plan --profile {s} --json", .{p});
    }
    if (capability) |c| {
        return try std.fmt.allocPrint(allocator, "oauth-mux codex broker-session-plan --capability {s} --json", .{c});
    }
    return try allocator.dupe(u8, "oauth-mux codex broker-session-plan --json");
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

    // TODO(TIN-1811 Phase 2 follow-up): cross-capability degradation is
    // deliberately NOT wired here. This plan feeds the managed-Codex resume
    // boundary (TIN-1631); degrading codex-max->codex-mini mid-plan would change
    // which capability a managed/resumed session binds to. Wiring it requires
    // threading degraded_capability through the managed-plan writers and the
    // resume-eligibility check together, so it is left capability-scoped until
    // that boundary change is scoped explicitly.
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

const CodexStatusSummary = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    events: u64 = 0,
    brokered_session_observed: bool = false,
    selected_account: ?[]const u8 = null,
    session_authority: ?[]const u8 = null,
    proxy_turns: u64 = 0,
    auth_unauthorized_turns: u64 = 0,
    responses_401_turns: u64 = 0,
    auth_health_events: u64 = 0,
    auth_health_recorded_observed: bool = false,
    auth_health_quota_claim_observed: bool = false,
    quota_event_observed: bool = false,
    quota_handoff_observed: bool = false,
    transport_failure_observed: bool = false,
    transport_recovery_observed: bool = false,
    unsupported_transport_events: u64 = 0,
    transport_local_retry_events: u64 = 0,
    transport_local_retry_recovered_events: u64 = 0,
    upstream_failure_events: u64 = 0,
    provider_same_turn_retry_events: u64 = 0,
    provider_retry_unavailable_events: u64 = 0,
    stream_interrupted_events: u64 = 0,
    client_disconnected_events: u64 = 0,
    responses_get_405_misclassified_ok: u64 = 0,
    quota_handoff_failed_reason: ?[]const u8 = null,
    user_visible_failure_likely: bool = false,
    terminal_event_observed: bool = false,
    session_aborted_observed: bool = false,
    same_turn_retry_events: u64 = 0,
    auth_same_turn_retry_events: u64 = 0,
    auth_retry_unavailable_events: u64 = 0,
    same_turn_retry_unavailable_events: u64 = 0,
    post_swap_turn_events: u64 = 0,
    launch_timing_events: u64 = 0,
    launch_timing_total_ms: ?i64 = null,
    launch_timing_child_spawn_ms: ?i64 = null,
    terminal_event_kind: ?[]const u8 = null,
    terminal_exit_code: ?i64 = null,
    terminal_term_kind: ?[]const u8 = null,
    terminal_term_code: ?i64 = null,
    terminal_signal_name: ?[]const u8 = null,
    provider_originated_live_fallback_claim: bool = false,
    verdict: []const u8 = "insufficient_evidence",
    next_action: []const u8 = "retry_managed",
    proxy_turns_by_account: std.StringHashMap(u64),
    proxy_turns_by_status: std.StringHashMap(u64),
    proxy_turns_by_path_kind: std.StringHashMap(u64),
    proxy_turns_by_body_class: std.StringHashMap(u64),

    fn init(allocator: std.mem.Allocator, path: []const u8) CodexStatusSummary {
        return .{
            .allocator = allocator,
            .path = path,
            .proxy_turns_by_account = std.StringHashMap(u64).init(allocator),
            .proxy_turns_by_status = std.StringHashMap(u64).init(allocator),
            .proxy_turns_by_path_kind = std.StringHashMap(u64).init(allocator),
            .proxy_turns_by_body_class = std.StringHashMap(u64).init(allocator),
        };
    }

    fn deinit(self: *CodexStatusSummary) void {
        if (self.selected_account) |value| self.allocator.free(value);
        if (self.session_authority) |value| self.allocator.free(value);
        if (self.terminal_event_kind) |value| self.allocator.free(value);
        if (self.terminal_term_kind) |value| self.allocator.free(value);
        if (self.terminal_signal_name) |value| self.allocator.free(value);
        freeStringCountKeys(self.allocator, &self.proxy_turns_by_account);
        freeStringCountKeys(self.allocator, &self.proxy_turns_by_status);
        freeStringCountKeys(self.allocator, &self.proxy_turns_by_path_kind);
        freeStringCountKeys(self.allocator, &self.proxy_turns_by_body_class);
        self.proxy_turns_by_account.deinit();
        self.proxy_turns_by_status.deinit();
        self.proxy_turns_by_path_kind.deinit();
        self.proxy_turns_by_body_class.deinit();
    }
};

fn freeStringCountKeys(allocator: std.mem.Allocator, map: *std.StringHashMap(u64)) void {
    var it = map.iterator();
    while (it.next()) |entry| allocator.free(entry.key_ptr.*);
}

const CodexStatusScanState = struct {
    quota_seen: bool = false,
    quota_account: ?[]const u8 = null,
    quota_body_class_usage_limit: bool = false,
    retry_after_quota: bool = false,
    auth_seen: bool = false,
    auth_retry_seen: bool = false,
    ok_turns: u64 = 0,
    auth_recovered_observed: bool = false,
    upstream_failure_seen: bool = false,
    upstream_failure_account: ?[]const u8 = null,
    provider_retry_after_upstream_failure: bool = false,
    provider_retry_to: ?[]const u8 = null,

    fn deinit(self: *CodexStatusScanState, allocator: std.mem.Allocator) void {
        if (self.quota_account) |value| allocator.free(value);
        if (self.upstream_failure_account) |value| allocator.free(value);
        if (self.provider_retry_to) |value| allocator.free(value);
    }
};

fn runCodexStatusLatest(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs) !void {
    const status_path = if (args.status_file) |path|
        try paths.absolutePath(allocator, path)
    else
        try latestCodexStatusPath(allocator);
    defer allocator.free(status_path);

    var summary = try summarizeCodexStatusFile(allocator, status_path);
    defer summary.deinit();

    if (args.json) {
        try writeCodexStatusSummaryJson(writer, summary);
    } else {
        try writeCodexStatusSummaryText(writer, summary);
    }
}

fn latestCodexStatusPath(allocator: std.mem.Allocator) ![]const u8 {
    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    const status_dir = try std.fs.path.join(allocator, &.{ state_dir, "codex", "status" });
    defer allocator.free(status_dir);

    var dir = std.fs.openDirAbsolute(status_dir, .{ .iterate = true }) catch return error.FileNotFound;
    defer dir.close();

    var best_name: ?[]u8 = null;
    var best_mtime: i128 = std.math.minInt(i128);
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".ndjson")) continue;
        const stat = dir.statFile(entry.name) catch continue;
        if (best_name == null or stat.mtime > best_mtime) {
            if (best_name) |name| allocator.free(name);
            best_name = try allocator.dupe(u8, entry.name);
            best_mtime = stat.mtime;
        }
    }

    const name = best_name orelse return error.FileNotFound;
    defer allocator.free(name);
    return try std.fs.path.join(allocator, &.{ status_dir, name });
}

fn summarizeCodexStatusFile(allocator: std.mem.Allocator, path: []const u8) !CodexStatusSummary {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 32 * 1024 * 1024);
    defer allocator.free(data);

    var summary = CodexStatusSummary.init(allocator, path);
    errdefer summary.deinit();
    var scan = CodexStatusScanState{};
    defer scan.deinit(allocator);

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;
        const object = parsed.value.object;
        summary.events += 1;

        const kind = jsonString(object.get("kind"));
        if (kind) |k| {
            if (std.mem.eql(u8, k, "session_started")) {
                const claim_level = jsonString(object.get("claim_level"));
                if (claim_level) |claim| {
                    if (std.mem.eql(u8, claim, "broker_owned") or std.mem.eql(u8, claim, "broker_owned_app_server")) {
                        summary.brokered_session_observed = true;
                    }
                }
                summary.selected_account = summary.selected_account orelse try dupeJsonString(allocator, object.get("selected_account"));
                summary.session_authority = summary.session_authority orelse try dupeJsonString(allocator, object.get("session_authority"));
            } else if (std.mem.eql(u8, k, "session_ended")) {
                summary.terminal_event_observed = true;
                try setCodexTerminalEventSummary(allocator, &summary, object, k);
                const final_claim = jsonString(object.get("final_claim_level"));
                if (final_claim) |claim| {
                    if (std.mem.eql(u8, claim, "broker_owned")) summary.brokered_session_observed = true;
                }
            } else if (std.mem.eql(u8, k, "session_aborted")) {
                summary.terminal_event_observed = true;
                summary.session_aborted_observed = true;
                try setCodexTerminalEventSummary(allocator, &summary, object, k);
            } else if (std.mem.eql(u8, k, "auth_health_observed")) {
                summary.auth_health_events += 1;
                summary.auth_health_recorded_observed = summary.auth_health_recorded_observed or (jsonBool(object.get("recorded")) orelse false);
                summary.auth_health_quota_claim_observed = summary.auth_health_quota_claim_observed or (jsonBool(object.get("quota_claim")) orelse false);
            } else if (std.mem.eql(u8, k, "proxy_same_turn_retry")) {
                summary.same_turn_retry_events += 1;
                if (scan.quota_seen) scan.retry_after_quota = true;
            } else if (std.mem.eql(u8, k, "proxy_auth_same_turn_retry")) {
                summary.auth_same_turn_retry_events += 1;
                if (scan.auth_seen) scan.auth_retry_seen = true;
            } else if (std.mem.eql(u8, k, "proxy_auth_retry_unavailable")) {
                summary.auth_retry_unavailable_events += 1;
            } else if (std.mem.eql(u8, k, "proxy_unsupported_transport")) {
                summary.unsupported_transport_events += 1;
                summary.transport_failure_observed = true;
            } else if (std.mem.eql(u8, k, "proxy_transport_local_retry")) {
                summary.transport_local_retry_events += 1;
                summary.transport_failure_observed = true;
            } else if (std.mem.eql(u8, k, "proxy_transport_local_retry_recovered")) {
                summary.transport_local_retry_recovered_events += 1;
                summary.transport_recovery_observed = true;
            } else if (std.mem.eql(u8, k, "proxy_upstream_failed")) {
                summary.upstream_failure_events += 1;
                summary.transport_failure_observed = true;
                if (!scan.upstream_failure_seen) {
                    scan.upstream_failure_seen = true;
                    scan.upstream_failure_account = try dupeJsonString(allocator, object.get("account"));
                }
            } else if (std.mem.eql(u8, k, "proxy_provider_same_turn_retry")) {
                summary.provider_same_turn_retry_events += 1;
                if (scan.upstream_failure_seen) {
                    scan.provider_retry_after_upstream_failure = true;
                    if (jsonString(object.get("to"))) |to| try replaceOptionalString(allocator, &scan.provider_retry_to, to);
                }
            } else if (std.mem.eql(u8, k, "proxy_provider_retry_unavailable")) {
                summary.provider_retry_unavailable_events += 1;
                summary.transport_failure_observed = true;
            } else if (std.mem.eql(u8, k, "proxy_stream_interrupted")) {
                summary.stream_interrupted_events += 1;
                summary.transport_failure_observed = true;
            } else if (std.mem.eql(u8, k, "proxy_client_disconnected")) {
                summary.client_disconnected_events += 1;
            } else if (std.mem.eql(u8, k, "proxy_same_turn_retry_unavailable")) {
                summary.same_turn_retry_unavailable_events += 1;
                if (scan.quota_seen and summary.quota_handoff_failed_reason == null) {
                    summary.quota_handoff_failed_reason = "same_turn_retry_unavailable";
                }
            } else if (std.mem.eql(u8, k, "proxy_post_swap_turn")) {
                summary.post_swap_turn_events += 1;
            } else if (std.mem.eql(u8, k, "launch_timing")) {
                summary.launch_timing_events += 1;
                if (jsonInt(object.get("elapsed_ms"))) |elapsed| {
                    if (summary.launch_timing_total_ms == null or elapsed > summary.launch_timing_total_ms.?) {
                        summary.launch_timing_total_ms = elapsed;
                    }
                    if (stringEquals(jsonString(object.get("phase")), "child_spawn")) {
                        summary.launch_timing_child_spawn_ms = elapsed;
                    }
                }
            } else if (std.mem.eql(u8, k, "quota_handoff_failed_no_account_selectable")) {
                if (scan.quota_seen) {
                    summary.quota_handoff_failed_reason = "no_account_selectable";
                    summary.user_visible_failure_likely = summary.user_visible_failure_likely or (jsonBool(object.get("user_visible_failure_likely")) orelse false);
                }
            } else if (std.mem.eql(u8, k, "proxy_no_account_selectable")) {
                if (scan.quota_seen and !summary.quota_handoff_observed) {
                    summary.quota_handoff_failed_reason = "no_account_selectable";
                    summary.user_visible_failure_likely = true;
                }
            } else if (std.mem.eql(u8, k, "proxy_turn")) {
                try summarizeProxyTurn(allocator, object, &summary, &scan);
            }
        }
    }

    summary.quota_handoff_observed = summary.provider_originated_live_fallback_claim or summary.quota_handoff_observed;
    const auth_failed_without_recovery = scan.auth_seen and scan.ok_turns == 0;

    if (summary.provider_originated_live_fallback_claim) {
        summary.verdict = "successful_live_quota_handoff";
        summary.next_action = "capture_or_close_live_quota_acceptance";
    } else if (summary.quota_handoff_observed) {
        summary.verdict = "quota_handoff_observed";
        summary.next_action = "inspect_quota_handoff_origin";
    } else if (summary.quota_handoff_failed_reason != null) {
        summary.verdict = "quota_handoff_failed";
        summary.next_action = "repair_route_health_or_add_fallback_account";
    } else if (scan.auth_recovered_observed and summary.auth_same_turn_retry_events > 0) {
        summary.verdict = "auth_fallback_sequence_observed";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.responses_get_405_misclassified_ok != 0) {
        summary.verdict = "transport_regression_405_misclassified";
        summary.next_action = "contain_reconnect_get_transport";
    } else if (summary.transport_local_retry_recovered_events != 0) {
        summary.verdict = "transport_local_retry_recovered";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.transport_recovery_observed) {
        summary.verdict = "transport_fallback_recovered";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.provider_retry_unavailable_events != 0 or summary.upstream_failure_events != 0) {
        summary.verdict = "transport_failure_unavailable";
        summary.next_action = "inspect_transport_failure_and_route_capacity";
    } else if (summary.unsupported_transport_events != 0) {
        summary.verdict = "transport_unsupported_contained";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.stream_interrupted_events != 0) {
        summary.verdict = "stream_interrupted_partial";
        summary.next_action = "inspect_provider_stream_stability";
    } else if (summary.client_disconnected_events != 0) {
        summary.verdict = "client_disconnected";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.brokered_session_observed and scan.auth_seen and !summary.terminal_event_observed) {
        summary.verdict = "brokered_incomplete_auth_failed";
        summary.next_action = "inspect_incomplete_run";
    } else if (summary.brokered_session_observed and auth_failed_without_recovery) {
        summary.verdict = "brokered_auth_failed";
        summary.next_action = "reauth_account";
    } else if (summary.brokered_session_observed and scan.auth_recovered_observed) {
        summary.verdict = "brokered_auth_recovered";
        summary.next_action = "continue_managed_dogfood";
    } else if (summary.brokered_session_observed and summary.proxy_turns > 0) {
        summary.verdict = "brokered_without_fallback";
        summary.next_action = "wait_for_quota_event";
    }

    return summary;
}

fn setCodexTerminalEventSummary(
    allocator: std.mem.Allocator,
    summary: *CodexStatusSummary,
    object: std.json.ObjectMap,
    kind: []const u8,
) !void {
    try replaceOptionalString(allocator, &summary.terminal_event_kind, kind);
    summary.terminal_exit_code = jsonInt(object.get("exit_code"));
    summary.terminal_term_code = jsonInt(object.get("term_code"));

    if (jsonString(object.get("term_kind"))) |term_kind| {
        try replaceOptionalString(allocator, &summary.terminal_term_kind, term_kind);
    } else {
        clearOptionalString(allocator, &summary.terminal_term_kind);
    }

    if (jsonString(object.get("signal_name"))) |signal_name| {
        try replaceOptionalString(allocator, &summary.terminal_signal_name, signal_name);
    } else {
        clearOptionalString(allocator, &summary.terminal_signal_name);
    }
}

fn summarizeProxyTurn(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
    summary: *CodexStatusSummary,
    scan: *CodexStatusScanState,
) !void {
    summary.proxy_turns += 1;
    const account = jsonString(object.get("account"));
    const status = jsonInt(object.get("status"));
    const classification = jsonString(object.get("classification"));
    const path_kind = jsonString(object.get("path_kind"));
    const body_class = jsonString(object.get("body_class"));

    if (account) |value| try incrementStringCount(allocator, &summary.proxy_turns_by_account, value);
    if (status) |value| {
        var buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "{d}", .{value});
        try incrementStringCount(allocator, &summary.proxy_turns_by_status, key);
    }
    if (path_kind) |value| try incrementStringCount(allocator, &summary.proxy_turns_by_path_kind, value);
    if (body_class) |value| try incrementStringCount(allocator, &summary.proxy_turns_by_body_class, value);

    const responses_get_path = stringEquals(path_kind, "responses") or
        stringEquals(path_kind, "responses_websocket");
    if (stringEquals(jsonString(object.get("method")), "GET") and
        responses_get_path and
        status != null and status.? == 405 and
        stringEquals(classification, "ok"))
    {
        summary.responses_get_405_misclassified_ok += 1;
        summary.transport_failure_observed = true;
    }

    const is_auth = (status != null and status.? == 401) or stringEquals(classification, "auth_unauthorized");
    if (is_auth) {
        summary.auth_unauthorized_turns += 1;
        scan.auth_seen = true;
        if (stringEquals(path_kind, "responses")) summary.responses_401_turns += 1;
    }

    const is_quota = status != null and status.? == 429 and stringEquals(classification, "quota_exhausted");
    if (is_quota) {
        summary.quota_event_observed = true;
        if (!scan.quota_seen) {
            scan.quota_seen = true;
            if (account) |value| scan.quota_account = try allocator.dupe(u8, value);
            scan.quota_body_class_usage_limit = stringEquals(body_class, "usage_limit_reached");
        }
    }

    if (status != null and status.? == 200) {
        scan.ok_turns += 1;
        if (scan.auth_seen and scan.auth_retry_seen) scan.auth_recovered_observed = true;
        if (scan.upstream_failure_seen and account != null) {
            const recovered_via_retry = scan.provider_retry_after_upstream_failure and
                scan.provider_retry_to != null and
                std.mem.eql(u8, scan.provider_retry_to.?, account.?);
            const recovered_via_different_account = if (scan.upstream_failure_account) |failed_account|
                !std.mem.eql(u8, failed_account, account.?)
            else
                false;
            if (recovered_via_retry or recovered_via_different_account) {
                summary.transport_recovery_observed = true;
            }
        }
        if (scan.quota_seen and scan.retry_after_quota and account != null) {
            const quota_account = scan.quota_account;
            if (quota_account == null or !std.mem.eql(u8, quota_account.?, account.?)) {
                summary.quota_handoff_observed = true;
                if (scan.quota_body_class_usage_limit) summary.provider_originated_live_fallback_claim = true;
            }
        }
    }
}

fn incrementStringCount(allocator: std.mem.Allocator, map: *std.StringHashMap(u64), key: []const u8) !void {
    const found = try map.getOrPut(key);
    if (found.found_existing) {
        found.value_ptr.* += 1;
    } else {
        found.key_ptr.* = try allocator.dupe(u8, key);
        found.value_ptr.* = 1;
    }
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn dupeJsonString(allocator: std.mem.Allocator, value: ?std.json.Value) !?[]const u8 {
    const s = jsonString(value) orelse return null;
    return try allocator.dupe(u8, s);
}

fn jsonInt(value: ?std.json.Value) ?i64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn jsonBool(value: ?std.json.Value) ?bool {
    const v = value orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn stringEquals(value: ?[]const u8, expected: []const u8) bool {
    const actual = value orelse return false;
    return std.mem.eql(u8, actual, expected);
}

fn replaceOptionalString(allocator: std.mem.Allocator, slot: *?[]const u8, value: []const u8) !void {
    if (slot.*) |old| allocator.free(old);
    slot.* = try allocator.dupe(u8, value);
}

fn clearOptionalString(allocator: std.mem.Allocator, slot: *?[]const u8) void {
    if (slot.*) |old| allocator.free(old);
    slot.* = null;
}

fn writeCodexStatusSummaryJson(writer: anytype, summary: CodexStatusSummary) !void {
    try writer.writeAll("{\"path\":");
    try std.json.stringify(summary.path, .{}, writer);
    try writer.print(",\"events\":{d}", .{summary.events});
    try writer.writeAll(",\"brokered_session_observed\":");
    try writer.writeAll(if (summary.brokered_session_observed) "true" else "false");
    try writer.writeAll(",\"selected_account\":");
    try writeOptionalJsonString(writer, summary.selected_account);
    try writer.writeAll(",\"session_authority\":");
    try writeOptionalJsonString(writer, summary.session_authority);
    try writer.print(",\"proxy_turns\":{d}", .{summary.proxy_turns});
    try writer.writeAll(",\"proxy_turns_by_account\":");
    try writeStringCountJson(writer, summary.proxy_turns_by_account);
    try writer.writeAll(",\"proxy_turns_by_status\":");
    try writeStringCountJson(writer, summary.proxy_turns_by_status);
    try writer.writeAll(",\"proxy_turns_by_path_kind\":");
    try writeStringCountJson(writer, summary.proxy_turns_by_path_kind);
    try writer.writeAll(",\"proxy_turns_by_body_class\":");
    try writeStringCountJson(writer, summary.proxy_turns_by_body_class);
    try writer.print(",\"auth_unauthorized_turns\":{d}", .{summary.auth_unauthorized_turns});
    try writer.print(",\"responses_401_turns\":{d}", .{summary.responses_401_turns});
    try writer.writeAll(",\"auth_failure_observed\":");
    try writer.writeAll(if (summary.auth_unauthorized_turns > 0) "true" else "false");
    try writer.writeAll(",\"auth_recovered_observed\":");
    try writer.writeAll(if (summary.auth_unauthorized_turns > 0 and summary.proxy_turns_by_status.get("200") != null) "true" else "false");
    try writer.print(",\"auth_health_events\":{d}", .{summary.auth_health_events});
    try writer.writeAll(",\"auth_health_recorded_observed\":");
    try writer.writeAll(if (summary.auth_health_recorded_observed) "true" else "false");
    try writer.writeAll(",\"auth_health_quota_claim_observed\":");
    try writer.writeAll(if (summary.auth_health_quota_claim_observed) "true" else "false");
    try writer.writeAll(",\"quota_event_observed\":");
    try writer.writeAll(if (summary.quota_event_observed) "true" else "false");
    try writer.writeAll(",\"quota_handoff_observed\":");
    try writer.writeAll(if (summary.quota_handoff_observed) "true" else "false");
    try writer.writeAll(",\"transport_failure_observed\":");
    try writer.writeAll(if (summary.transport_failure_observed) "true" else "false");
    try writer.writeAll(",\"transport_recovery_observed\":");
    try writer.writeAll(if (summary.transport_recovery_observed) "true" else "false");
    try writer.print(",\"unsupported_transport_events\":{d}", .{summary.unsupported_transport_events});
    try writer.print(",\"transport_local_retry_events\":{d}", .{summary.transport_local_retry_events});
    try writer.print(",\"transport_local_retry_recovered_events\":{d}", .{summary.transport_local_retry_recovered_events});
    try writer.print(",\"upstream_failure_events\":{d}", .{summary.upstream_failure_events});
    try writer.print(",\"provider_same_turn_retry_events\":{d}", .{summary.provider_same_turn_retry_events});
    try writer.print(",\"provider_retry_unavailable_events\":{d}", .{summary.provider_retry_unavailable_events});
    try writer.print(",\"stream_interrupted_events\":{d}", .{summary.stream_interrupted_events});
    try writer.print(",\"client_disconnected_events\":{d}", .{summary.client_disconnected_events});
    try writer.print(",\"responses_get_405_misclassified_ok\":{d}", .{summary.responses_get_405_misclassified_ok});
    try writer.writeAll(",\"quota_handoff_failed_reason\":");
    try writeOptionalJsonString(writer, summary.quota_handoff_failed_reason);
    try writer.writeAll(",\"user_visible_failure_likely\":");
    try writer.writeAll(if (summary.user_visible_failure_likely) "true" else "false");
    try writer.writeAll(",\"terminal_event_observed\":");
    try writer.writeAll(if (summary.terminal_event_observed) "true" else "false");
    try writer.writeAll(",\"session_aborted_observed\":");
    try writer.writeAll(if (summary.session_aborted_observed) "true" else "false");
    try writer.writeAll(",\"terminal_event\":{\"kind\":");
    try writeOptionalJsonString(writer, summary.terminal_event_kind);
    try writer.writeAll(",\"exit_code\":");
    if (summary.terminal_exit_code) |code| {
        try writer.print("{d}", .{code});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"term_kind\":");
    try writeOptionalJsonString(writer, summary.terminal_term_kind);
    try writer.writeAll(",\"term_code\":");
    if (summary.terminal_term_code) |code| {
        try writer.print("{d}", .{code});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"signal_name\":");
    try writeOptionalJsonString(writer, summary.terminal_signal_name);
    try writer.writeAll("}");
    try writer.print(",\"same_turn_retry_events\":{d}", .{summary.same_turn_retry_events});
    try writer.print(",\"auth_same_turn_retry_events\":{d}", .{summary.auth_same_turn_retry_events});
    try writer.print(",\"auth_retry_unavailable_events\":{d}", .{summary.auth_retry_unavailable_events});
    try writer.print(",\"same_turn_retry_unavailable_events\":{d}", .{summary.same_turn_retry_unavailable_events});
    try writer.print(",\"post_swap_turn_events\":{d}", .{summary.post_swap_turn_events});
    try writer.writeAll(",\"launch_timing\":{\"events\":");
    try writer.print("{d}", .{summary.launch_timing_events});
    try writer.writeAll(",\"child_spawn_elapsed_ms\":");
    if (summary.launch_timing_child_spawn_ms) |ms| {
        try writer.print("{d}", .{ms});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"total_elapsed_ms\":");
    if (summary.launch_timing_total_ms) |ms| {
        try writer.print("{d}", .{ms});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}");
    try writer.writeAll(",\"level4_shape_observed\":");
    try writer.writeAll(if (summary.quota_handoff_observed) "true" else "false");
    try writer.writeAll(",\"provider_originated_live_fallback_claim\":");
    try writer.writeAll(if (summary.provider_originated_live_fallback_claim) "true" else "false");
    try writer.writeAll(",\"verdict\":");
    try std.json.stringify(summary.verdict, .{}, writer);
    try writer.writeAll(",\"next_action\":");
    try std.json.stringify(summary.next_action, .{}, writer);
    try writer.writeAll("}\n");
}

fn writeCodexStatusSummaryText(writer: anytype, summary: CodexStatusSummary) !void {
    try writer.writeAll("oauth-mux Codex status summary\n\n");
    try writer.print("  path: {s}\n", .{summary.path});
    try writer.print("  verdict: {s}\n", .{summary.verdict});
    try writer.print("  next_action: {s}\n", .{summary.next_action});
    try writer.print("  brokered_session_observed: {s}\n", .{if (summary.brokered_session_observed) "true" else "false"});
    try writer.print("  selected_account: {s}\n", .{summary.selected_account orelse "null"});
    try writer.print("  quota_event_observed: {s}\n", .{if (summary.quota_event_observed) "true" else "false"});
    try writer.print("  quota_handoff_observed: {s}\n", .{if (summary.quota_handoff_observed) "true" else "false"});
    try writer.print("  transport_failure_observed: {s}\n", .{if (summary.transport_failure_observed) "true" else "false"});
    try writer.print("  transport_recovery_observed: {s}\n", .{if (summary.transport_recovery_observed) "true" else "false"});
    if (summary.transport_local_retry_events != 0) {
        try writer.print("  transport_local_retry_events: {d}\n", .{summary.transport_local_retry_events});
    }
    try writer.print("  proxy_turns: {d}\n", .{summary.proxy_turns});
    if (summary.launch_timing_events != 0) {
        try writer.print("  launch_timing_events: {d}\n", .{summary.launch_timing_events});
        if (summary.launch_timing_child_spawn_ms) |ms| try writer.print("  child_spawn_elapsed_ms: {d}\n", .{ms});
    }
}

fn writeOptionalJsonString(writer: anytype, value: ?[]const u8) !void {
    if (value) |s| {
        try std.json.stringify(s, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
}

fn writeStringCountJson(writer: anytype, map: std.StringHashMap(u64)) !void {
    try writer.writeAll("{");
    var first = true;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (!first) try writer.writeAll(",");
        first = false;
        try std.json.stringify(entry.key_ptr.*, .{}, writer);
        try writer.print(":{d}", .{entry.value_ptr.*});
    }
    try writer.writeAll("}");
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
    diagnostic_only: bool = true,
    canonical_resume_authority_checked: bool = false,
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
    canonical_resume_entrypoint: []const u8 = "oauth-mux codex resume",
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

    // TODO(TIN-1811 Phase 2 follow-up): kept capability-scoped on purpose. A
    // resume binds to a specific session/capability; cross-capability degrade
    // here would silently rebind a resumed managed Codex session to a different
    // capability, which intersects the TIN-1631 resume boundary. Wire only with
    // an explicit session-continuity decision.
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
        result.diagnostic = "resume --last is resolved by native Codex inside the selected route-local CODEX_HOME; canonical resume authority is checked by oauth-mux codex resume --last";
        result.selected_route_available = selected_route != null;
        return result;
    }

    const resume_id = args.resume_id orelse return result;
    result.checked = true;

    const route = selected_route orelse {
        result.status = "selected_route_unavailable";
        result.diagnostic = "no selectable route is available, so oauth-mux cannot check this route-local Codex resume diagnostic";
        return result;
    };
    result.selected_route_available = true;

    const store_dir = try codexManagedRouteConfigDir(allocator, cfg, route) orelse {
        result.status = "selected_route_missing_store";
        result.diagnostic = "selected Codex route does not define a CODEX_HOME store for this route-local resume diagnostic";
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
        result.diagnostic = "resume id was found in the selected route-local Codex store; canonical resume authority is checked by oauth-mux codex resume";
    } else {
        result.status = "not_found_in_selected_store";
        result.diagnostic = "resume id was not found in the selected route-local Codex store; use oauth-mux codex resume for canonical session authority or choose the route that owns this route-local store";
    }
    return result;
}

fn codexManagedRouteConfigDir(allocator: std.mem.Allocator, cfg: config.Config, route: RepairPlanRoute) !?[]const u8 {
    const provider_cfg = cfg.providers.map.get(route.provider) orelse return null;
    const account = provider_cfg.accounts.map.get(route.account) orelse return null;
    const config_dir = account.config_dir orelse return null;
    return try paths.expandTilde(allocator, config_dir);
}

fn codexManagedOverlayHomeForPlanning(allocator: std.mem.Allocator, path_value: []const u8) !bool {
    const base = std.fs.path.basename(path_value);
    if (std.mem.startsWith(u8, base, "oauth-mux-codex-")) return true;

    const config_path = try std.fs.path.join(allocator, &.{ path_value, "config.toml" });
    defer allocator.free(config_path);
    const bytes = std.fs.cwd().readFileAlloc(allocator, config_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound, error.NotDir, error.AccessDenied, error.IsDir => return false,
        else => return e,
    };
    defer allocator.free(bytes);

    return std.mem.indexOf(u8, bytes, "Managed by oauth-mux") != null or
        std.mem.indexOf(u8, bytes, "model_provider = \"oauth_mux_openai\"") != null or
        std.mem.indexOf(u8, bytes, "[model_providers.oauth_mux_openai]") != null;
}

test "codexManagedOverlayHomeForPlanning detects managed overlay homes" {
    const allocator = std.testing.allocator;

    try std.testing.expect(try codexManagedOverlayHomeForPlanning(allocator, "/tmp/oauth-mux-codex-test"));
    try std.testing.expect(!try codexManagedOverlayHomeForPlanning(allocator, "/tmp/not-an-omux-overlay-does-not-exist"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("config.toml", .{});
    defer file.close();
    try file.writeAll("# Managed by oauth-mux\n");

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    try std.testing.expect(try codexManagedOverlayHomeForPlanning(allocator, tmp_path));
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
    try writer.writeAll(",\"diagnostic_only\":");
    try writer.writeAll(if (inspection.diagnostic_only) "true" else "false");
    try writer.writeAll(",\"canonical_resume_authority_checked\":");
    try writer.writeAll(if (inspection.canonical_resume_authority_checked) "true" else "false");
    try writer.writeAll(",\"canonical_resume_entrypoint\":");
    try std.json.stringify(inspection.canonical_resume_entrypoint, .{}, writer);
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
    try writer.writeAll("  diagnostic_only: true\n");
    try writer.writeAll("  canonical_resume_authority_checked: false\n");
    try writer.print("  canonical_resume_entrypoint: {s}\n", .{inspection.canonical_resume_entrypoint});
    try writer.writeAll("  resume_id_printed: false\n");
    try writer.writeAll("  path_printed: false\n");
    try writer.print("  diagnostic: {s}\n", .{inspection.diagnostic});
    try writer.writeAll("  next: use oauth-mux codex resume for canonical session authority, start a new managed session, or select the account whose route-local CODEX_HOME owns that session id\n");
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
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_auth_broker\":false,\"broker_owned_app_server\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
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
    try writer.writeAll("  claim: planning-only managed_codex_process launch with route-local CODEX_HOME diagnostic resume namespace\n");
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
    try writeCodexBrokerSessionRiskActionsJsonWithSummary(writer, allocator, profile, capability, session_start_ready, selectable_fallback_routes, null);
}

fn codexBrokerSessionRepairSummaryHasWaitCandidate(summary: CodexPreflightRepairSummary) bool {
    return summary.revalidation_needed_routes != 0 or
        summary.quota_exhausted_routes != 0 or
        summary.rate_limited_routes != 0 or
        summary.wait_routes != 0;
}

fn codexBrokerSessionRepairSummaryHasProviderRevalidationCandidate(summary: CodexPreflightRepairSummary) bool {
    return summary.revalidation_needed_routes != 0 or
        summary.quota_exhausted_routes != 0 or
        summary.rate_limited_routes != 0;
}

fn writeCodexBrokerSessionRiskActionEntryJson(
    writer: anytype,
    first: *bool,
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
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writeCodexBrokerSessionRiskActionJson(
        writer,
        allocator,
        kind,
        reason,
        spends_provider_calls,
        mutates_route_health,
        mutates_user_config,
        confirmation_required,
        include_profile_capability,
        command_base,
        profile,
        capability,
        command_suffix,
    );
}

fn writeCodexBrokerSessionRiskActionsJsonWithSummary(
    writer: anytype,
    allocator: std.mem.Allocator,
    profile: ?[]const u8,
    capability: ?[]const u8,
    session_start_ready: bool,
    selectable_fallback_routes: usize,
    repair_summary: ?CodexPreflightRepairSummary,
) !void {
    try writer.writeByte('[');
    var first = true;
    if (codexBrokerSessionSingleRouteAtRisk(session_start_ready, selectable_fallback_routes)) {
        const include_revalidation = if (repair_summary) |summary| codexBrokerSessionRepairSummaryHasProviderRevalidationCandidate(summary) else true;
        if (include_revalidation) try writeCodexBrokerSessionRiskActionEntryJson(
            writer,
            &first,
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
        if (repair_summary) |summary| {
            if (summary.user_handoff_required) try writeCodexBrokerSessionRiskActionEntryJson(
                writer,
                &first,
                allocator,
                "reauth_blocked_routes",
                "blocked_routes_require_user_mediated_login",
                false,
                false,
                true,
                true,
                false,
                null,
                null,
                null,
                "",
            );
        }
        try writeCodexBrokerSessionRiskActionEntryJson(
            writer,
            &first,
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
        const include_wait = if (repair_summary) |summary| codexBrokerSessionRepairSummaryHasWaitCandidate(summary) else true;
        if (include_wait) try writeCodexBrokerSessionRiskActionEntryJson(
            writer,
            &first,
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
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
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
        try writeCodexBrokerSessionRouteJson(writer, allocator, cfg, after, selected_index, idx, evaluation, selected, plan);
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
                if (routeIsDistinctFallbackAccount(evaluations, selected_index, idx) and
                    !fallbackAccountSeenBefore(evaluations, idx, selected_index, null, false))
                {
                    summary.selectable_fallback_routes += 1;
                }
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
    const repair_summary = try codexPreflightRepairSummary(allocator, cfg, evaluations, selected_index, session_start_ready, prepared_fallback);

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
    try writer.writeAll(",\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
    try writer.writeAll(",\"policy\":");
    try writePolicyJson(writer, cfg.policy);
    try writer.writeAll(",\"profile\":");
    if (profile) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (capability) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"resilience\":");
    try writeCodexBrokerSessionResilienceJson(writer, session_start_ready, summary.selectable_fallback_routes);
    try writer.writeAll(",\"resilience_actions\":");
    try writeCodexBrokerSessionRiskActionsJsonWithSummary(writer, allocator, profile, capability, session_start_ready, summary.selectable_fallback_routes, repair_summary);
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
    try writer.writeAll(",\"repair_summary\":");
    try writeCodexPreflightRepairSummaryJson(writer, repair_summary);
    try writer.writeAll(",\"blocked_route_reasons\":");
    try writeCodexPreflightBlockedReasonSummaryJson(writer, allocator, cfg, evaluations, selected_index);
    try writer.writeAll(",\"blocked_routes\":");
    try writeCodexPreflightBlockedRoutesJson(writer, allocator, cfg, evaluations, selected_index);
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
        try writeCodexBrokerSessionRouteJson(writer, allocator, cfg, evaluations, selected_index, idx, evaluation, selected, plan);
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
        const fallback_candidate = plan.can_supply and evaluation.selectable and
            routeIsDistinctFallbackAccount(evaluations, selected_index, idx) and
            !fallbackAccountSeenBefore(evaluations, idx, selected_index, null, false);
        const role = codexBrokerSessionRouteRole(evaluation, selected, plan, fallback_candidate);
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
    evaluations: []const RouteEvaluation,
    selected_index: ?usize,
    evaluation_index: usize,
    evaluation: RouteEvaluation,
    selected: bool,
    plan: CodexBrokerTokenPlan,
) !void {
    const fallback_candidate = plan.can_supply and evaluation.selectable and
        routeIsDistinctFallbackAccount(evaluations, selected_index, evaluation_index) and
        !fallbackAccountSeenBefore(evaluations, evaluation_index, selected_index, null, false);
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
    try std.json.stringify(codexBrokerSessionRouteRole(evaluation, selected, plan, fallback_candidate), .{}, writer);
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

fn codexBrokerSessionRouteRole(evaluation: RouteEvaluation, selected: bool, plan: CodexBrokerTokenPlan, fallback_candidate: bool) []const u8 {
    if (!plan.can_supply) return "auth_broker_unready";
    if (selected) return "selected";
    if (evaluation.selectable and fallback_candidate) return "selectable_fallback";
    if (evaluation.selectable) return "selectable_duplicate";
    if (std.mem.eql(u8, evaluation.skip_reason, "quota_exhausted")) return "quota_blocked";
    if (std.mem.eql(u8, evaluation.skip_reason, "revalidation_needed")) return "revalidation_needed";
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
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local Responses mock using broker-session-plan route semantics\n");
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
    try writer.writeAll(",\"claim\":{\"claim_version\":1,\"level\":\"broker_owned_app_server\",\"proof_status\":\"local_broker_owned_session_smoke\",\"broker_owned_session\":true,\"auth_broker_scope\":\"broker_owned_app_server\",\"current_process_auth_broker\":false,\"route_selection_source\":\"broker_session_plan\",\"session_start_ready\":true,\"prepared_fallback\":true,\"next_thread_quota_fallback_proven\":true,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
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
    // Effect boundary (TIN-2407 P0): the broker-run path owns its clock read.
    const now_s = std.time.timestamp();
    store.recordHttpClassification(key.slice(), 429, classification, now_s);
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
    try writer.writeAll(",\"next_thread_quota_fallback_proven\":false,\"same_turn_quota_recovery\":false,\"same_thread_quota_recovery\":false,\"current_process_hotswap\":false,\"unmanaged_tui_hotswap\":false,\"per_request_muxing\":false}");
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
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local Responses mock and verifies 401 retry fallback\n");
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
            try writer.writeAll("  this starts a broker-owned Codex app-server child plus a local Responses mock and verifies next-turn quota fallback\n");
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
    try writer.writeAll(",\"access_token_expired\":");
    try writeOptionalBoolJson(writer, plan.access_token_expired);
    try writer.writeAll(",\"access_token_expiring_soon\":");
    try writeOptionalBoolJson(writer, plan.access_token_expiring_soon);
    try writer.writeAll(",\"refresh_token\":");
    try writer.writeAll(if (plan.refresh_token_present) "true" else "false");
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

fn writeOptionalBoolJson(writer: anytype, value: ?bool) !void {
    if (value) |actual| {
        try writer.writeAll(if (actual) "true" else "false");
    } else {
        try writer.writeAll("null");
    }
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
    const access_token_exp = jwtIntegerClaim(allocator, access_token, "exp") catch null;
    const now = std.time.timestamp();
    const account_id_source = codexAccountIdSource(allocator, tokens);
    const plan_type_source = codexPlanTypeSource(allocator, tokens);
    const can_supply = access_token_jwt_parseable and account_id_source != null;

    return .{
        .secret_readable = true,
        .can_supply = can_supply,
        .reason = if (can_supply) "ready" else if (!access_token_jwt_parseable) "access_token_not_jwt" else "chatgpt_account_id_missing",
        .access_token_present = true,
        .access_token_jwt_parseable = access_token_jwt_parseable,
        .access_token_expired = if (access_token_exp) |exp| exp <= now else null,
        .access_token_expiring_soon = if (access_token_exp) |exp| exp <= now + 300 else null,
        .refresh_token_present = nonEmpty(tokens.refresh_token) != null,
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

fn jwtIntegerClaim(allocator: std.mem.Allocator, jwt: []const u8, field: []const u8) !?i64 {
    const payload = jwtPayloadJsonAlloc(allocator, jwt) catch return null;
    defer allocator.free(payload);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    return switch (root.get(field) orelse return null) {
        .integer => |value| std.math.cast(i64, value) orelse null,
        else => null,
    };
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
    const access_exp = std.time.timestamp() + 3600;
    const access_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"exp\":{d},\"https://api.openai.com/auth\":{{\"chatgpt_account_id\":\"acct-test\",\"chatgpt_plan_type\":\"pro\"}}}}",
        .{access_exp},
    );
    defer std.testing.allocator.free(access_payload);
    var encoded_buf: [256]u8 = undefined;
    const encoded_access_payload = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, access_payload);
    const auth_json = try std.fmt.allocPrint(std.testing.allocator,
        \\{{
        \\  "auth_mode": "chatgpt",
        \\  "tokens": {{
        \\    "id_token": "hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig",
        \\    "access_token": "hdr.{s}.sig",
        \\    "refresh_token": "redacted-in-test"
        \\  }}
        \\}}
    , .{encoded_access_payload});
    defer std.testing.allocator.free(auth_json);

    const plan = inspectCodexBrokerAuthJson(std.testing.allocator, auth_json);
    try std.testing.expect(plan.can_supply);
    try std.testing.expect(plan.secret_readable);
    try std.testing.expect(plan.access_token_present);
    try std.testing.expect(plan.access_token_jwt_parseable);
    try std.testing.expect(!plan.access_token_expired.?);
    try std.testing.expect(!plan.access_token_expiring_soon.?);
    try std.testing.expect(plan.refresh_token_present);
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
    try std.testing.expect(plan.refresh_token_present);
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

fn runCodexLoginStatusOne(
    allocator: std.mem.Allocator,
    writer: anytype,
    args: cli.Command.CodexArgs,
    root: []const u8,
    account: []const u8,
) !void {
    const dir = try codexAccountDir(allocator, root, account);
    defer allocator.free(dir);

    if (!args.json) {
        try writer.print("=== {s} ===\nCODEX_HOME={s}\n", .{ account, dir });
        try writer.writeAll("note: native Codex login status only; route liveness and selectability are reported by oauth-mux codex preflight --profile <profile> --capability <capability> --json\n");
        if (!try runCodexCli(allocator, dir, &.{ "login", "status" })) return error.CodexCommandFailed;
        return;
    }

    const result = runCodexCliCaptured(allocator, dir, &.{ "login", "status" }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => CodexCliResult{ .term = .{ .Unknown = 0 }, .error_name = @errorName(e) },
    };
    defer result.deinit(allocator);

    try writer.writeAll("{\"mode\":\"codex_login_status\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"interactive\":false,\"ok\":");
    try writer.writeAll(if (result.ok()) "true" else "false");
    try writer.writeAll(",\"readiness_scope\":");
    try writeCodexLoginStatusReadinessScopeJson(writer);
    try writer.writeAll(",\"account\":");
    try writeCodexLoginStatusResultJson(writer, account, result);
    try writer.writeAll("}\n");
}

fn runCodexLoginStatusAll(allocator: std.mem.Allocator, writer: anytype, args: cli.Command.CodexArgs, root: []const u8) !void {
    if (args.json) {
        try writer.writeAll("{\"mode\":\"codex_login_status_all\",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"interactive\":false,\"readiness_scope\":");
        try writeCodexLoginStatusReadinessScopeJson(writer);
        try writer.writeAll(",\"accounts\":[");
        var first = true;
        var ok = true;
        var account_it = std.mem.splitScalar(u8, args.accounts, ',');
        while (account_it.next()) |raw_account| {
            const account = std.mem.trim(u8, raw_account, " \t\r\n");
            if (account.len == 0) continue;
            const dir = try codexAccountDir(allocator, root, account);
            defer allocator.free(dir);
            const result = runCodexCliCaptured(allocator, dir, &.{ "login", "status" }) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => CodexCliResult{ .term = .{ .Unknown = 0 }, .error_name = @errorName(e) },
            };
            defer result.deinit(allocator);
            if (!result.ok()) ok = false;
            if (!first) try writer.writeByte(',');
            first = false;
            try writeCodexLoginStatusResultJson(writer, account, result);
        }
        try writer.writeAll("],\"ok\":");
        try writer.writeAll(if (ok) "true" else "false");
        try writer.writeAll("}\n");
        return;
    }

    var failures: usize = 0;
    var it = std.mem.splitScalar(u8, args.accounts, ',');
    while (it.next()) |raw_account| {
        const account = std.mem.trim(u8, raw_account, " \t\r\n");
        if (account.len == 0) continue;
        const dir = try codexAccountDir(allocator, root, account);
        defer allocator.free(dir);
        try writer.print("=== {s} ===\nCODEX_HOME={s}\n", .{ account, dir });
        try writer.writeAll("note: native Codex login status only; route liveness and selectability are reported by oauth-mux codex preflight --profile <profile> --capability <capability> --json\n");
        if (!try runCodexCli(allocator, dir, &.{ "login", "status" })) failures += 1;
    }
    if (failures != 0) return error.CodexCommandFailed;
}

const CodexCliResult = struct {
    stdout: []u8 = &.{},
    stderr: []u8 = &.{},
    term: std.process.Child.Term,
    error_name: ?[]const u8 = null,

    fn deinit(self: CodexCliResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }

    fn ok(self: CodexCliResult) bool {
        return switch (self.term) {
            .Exited => |code| code == 0,
            else => false,
        };
    }

    fn exitCode(self: CodexCliResult) ?u8 {
        return switch (self.term) {
            .Exited => |code| code,
            else => null,
        };
    }
};

fn writeCodexLoginStatusReadinessScopeJson(writer: anytype) !void {
    try writer.writeAll(
        "{\"native_login_status\":true,\"route_liveness_considered\":false,\"route_selectability_considered\":false,\"native_login_status_clears_route_health\":false,\"route_health_authority\":\"oauth-mux codex preflight --profile <profile> --capability <capability> --json\"}",
    );
}

fn writeCodexLoginStatusResultJson(writer: anytype, account: []const u8, result: CodexCliResult) !void {
    try writer.writeAll("{\"account\":");
    try std.json.stringify(account, .{}, writer);
    try writer.writeAll(",\"authenticated\":");
    try writer.writeAll(if (result.ok()) "true" else "false");
    try writer.writeAll(",\"status\":");
    try std.json.stringify(codexLoginStatusLabel(result), .{}, writer);
    try writer.writeAll(",\"exit_code\":");
    if (result.exitCode()) |code| {
        try writer.print("{d}", .{code});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"codex_home_path_printed\":false,\"native_output_printed\":false");
    try writer.writeAll(",\"route_liveness_considered\":false,\"route_selectability_considered\":false,\"native_login_status_clears_route_health\":false");
    if (result.error_name) |name| {
        try writer.writeAll(",\"error\":");
        try std.json.stringify(name, .{}, writer);
    }
    try writer.writeByte('}');
}

fn codexLoginStatusLabel(result: CodexCliResult) []const u8 {
    if (result.ok()) return "logged_in";
    if (containsAsciiIgnoreCase(result.stdout, "not logged") or
        containsAsciiIgnoreCase(result.stderr, "not logged") or
        containsAsciiIgnoreCase(result.stdout, "not authenticated") or
        containsAsciiIgnoreCase(result.stderr, "not authenticated"))
    {
        return "not_logged_in";
    }
    if (result.error_name != null) return "command_failed";
    return "unknown";
}

test "Codex login-status JSON declares native-only readiness scope" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeCodexLoginStatusReadinessScopeJson(buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"native_login_status\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"route_liveness_considered\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"route_selectability_considered\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"native_login_status_clears_route_health\":false") != null);
}

test "Codex login-status account JSON does not imply route health" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeCodexLoginStatusResultJson(buf.writer(), "max-1", .{ .term = .{ .Exited = 0 } });
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"authenticated\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"status\":\"logged_in\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"route_liveness_considered\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"native_login_status_clears_route_health\":false") != null);
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

fn resolveNativeCodexBinary(allocator: std.mem.Allocator) ![]const u8 {
    if (try getEnvOwnedOrNull(allocator, "OMUX_CODEX_BIN")) |env_path| {
        errdefer allocator.free(env_path);
        if (env_path.len != 0 and fileExists(env_path) and !(try isOauthMuxShimPath(allocator, env_path))) {
            trace.append(allocator, "codex.native_binary.resolve", .info, &.{
                trace.string("source", "OMUX_CODEX_BIN"),
                trace.boolean("selected", true),
                trace.boolean("path_printed", false),
            });
            return env_path;
        }
        trace.append(allocator, "codex.native_binary.resolve", .warn, &.{
            trace.string("source", "OMUX_CODEX_BIN"),
            trace.boolean("selected", false),
            trace.string("reason", "missing_or_oauth_mux_shim"),
            trace.boolean("path_printed", false),
        });
        allocator.free(env_path);
    }

    var candidates = try collectPathCandidates(allocator, "codex");
    defer candidates.deinit(allocator);
    if (try firstNativeCodexCandidate(allocator, candidates.paths.items)) |path_value| {
        const shim_candidates = countOauthMuxShimCandidates(allocator, candidates.paths.items) catch 0;
        trace.append(allocator, "codex.native_binary.resolve", .info, &.{
            trace.string("source", "PATH"),
            trace.boolean("selected", true),
            trace.uint("candidate_count", candidates.paths.items.len),
            trace.uint("oauth_mux_shim_candidates", shim_candidates),
            trace.boolean("path_printed", false),
        });
        return try allocator.dupe(u8, path_value);
    }
    const shim_candidates = countOauthMuxShimCandidates(allocator, candidates.paths.items) catch 0;
    trace.append(allocator, "codex.native_binary.resolve", .err, &.{
        trace.string("source", "PATH"),
        trace.boolean("selected", false),
        trace.uint("candidate_count", candidates.paths.items.len),
        trace.uint("oauth_mux_shim_candidates", shim_candidates),
        trace.boolean("path_printed", false),
    });
    return error.CodexNativeBinaryNotFound;
}

fn runCodexCli(allocator: std.mem.Allocator, account_dir: []const u8, codex_args: []const []const u8) !bool {
    const codex_bin = try resolveNativeCodexBinary(allocator);
    defer allocator.free(codex_bin);

    var argv = try allocator.alloc([]const u8, codex_args.len + 1);
    defer allocator.free(argv);
    argv[0] = codex_bin;
    @memcpy(argv[1..], codex_args);

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", account_dir);
    _ = env_map.remove("OMUX_CODEX_SHIM");

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;

    trace.append(allocator, "codex.native_command.spawn", .info, &.{
        trace.string("command", if (codex_args.len > 0) codex_args[0] else "none"),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("native_binary_path_printed", false),
    });

    const term = child.spawnAndWait() catch return error.CodexCommandFailed;
    const ok = switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
    trace.append(allocator, "codex.native_command.exit", if (ok) .info else .warn, &.{
        trace.string("command", if (codex_args.len > 0) codex_args[0] else "none"),
        trace.boolean("ok", ok),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("native_binary_path_printed", false),
    });
    return ok;
}

fn runCodexCliCaptured(allocator: std.mem.Allocator, account_dir: []const u8, codex_args: []const []const u8) !CodexCliResult {
    const codex_bin = try resolveNativeCodexBinary(allocator);
    defer allocator.free(codex_bin);

    var argv = try allocator.alloc([]const u8, codex_args.len + 1);
    defer allocator.free(argv);
    argv[0] = codex_bin;
    @memcpy(argv[1..], codex_args);

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", account_dir);
    _ = env_map.remove("OMUX_CODEX_SHIM");

    trace.append(allocator, "codex.native_command.spawn", .info, &.{
        trace.string("command", if (codex_args.len > 0) codex_args[0] else "none"),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("native_binary_path_printed", false),
        trace.boolean("native_output_printed", false),
    });

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .env_map = &env_map,
        .max_output_bytes = 16 * 1024,
    });
    errdefer allocator.free(result.stdout);
    errdefer allocator.free(result.stderr);

    const ok = switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    trace.append(allocator, "codex.native_command.exit", if (ok) .info else .warn, &.{
        trace.string("command", if (codex_args.len > 0) codex_args[0] else "none"),
        trace.boolean("ok", ok),
        trace.boolean("codex_home_path_printed", false),
        trace.boolean("native_binary_path_printed", false),
        trace.boolean("native_output_printed", false),
    });

    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .term = result.term,
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

    try writeDoctorJson(buf.writer(), stats, "/tmp/config.json", "/tmp/state", "/tmp/health.json", "", null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"codex_configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"binaries\":{\"available\":false}") != null);
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

test "writeHealthJson includes route-effective liveness" {
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    const health = try store.getOrCreate("codex:max-3");
    const now = std.time.timestamp();
    health.liveness = .{ .live = .{ .availability = .{ .rate_limited = .{
        .retry_after_s = 60,
        .limited_at = now - 120,
        .window = .unknown,
    } } } };
    health.last_probe_hint_class = .rate_limit;
    health.last_probe_decision = .wait_and_retry;

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeHealthJson(buf.writer(), &store, "codex");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"liveness\":{\"summary\":\"rate_limited:unknown:60s\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"effective_liveness\":{\"summary\":\"available\"") != null);
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

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    try std.testing.expectEqual(@as(usize, 2), routes.items.len);
    try std.testing.expectEqualStrings("codex", routes.items[0].provider);
    try std.testing.expectEqualStrings("max-1", routes.items[0].account);
    try std.testing.expectEqualStrings("codex-max", routes.items[0].capability.?);
    try std.testing.expectEqualStrings("max-2", routes.items[1].account);
}

test "collectRepairPlanRoutes preserves declared profile route capabilities when scoped" {
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
        \\      "providers": [
        \\        "codex:max-1#codex-max",
        \\        "codex:max-1#codex-mini",
        \\        "codex:max-2#codex-max",
        \\        "codex:max-2#codex-mini"
        \\      ],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    try std.testing.expectEqual(@as(usize, 2), routes.items.len);
    try std.testing.expectEqualStrings("max-1", routes.items[0].account);
    try std.testing.expectEqualStrings("codex-max", routes.items[0].capability.?);
    try std.testing.expectEqualStrings("max-2", routes.items[1].account);
    try std.testing.expectEqualStrings("codex-max", routes.items[1].capability.?);
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

test "daemon tick admits Codex spend provider probe by default" {
    const decision = daemonTickDecision(config.PolicyConfig{}, .{
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
    try std.testing.expect(decision.admitted);
    try std.testing.expectEqualStrings("allowed_by_policy", decision.reason);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, decision.budget.?);
    try std.testing.expect(!decision.executed);
    try std.testing.expectEqual(@as(?i64, 1000), decision.next_tick_after);
    try std.testing.expectEqualStrings("probe_due", decision.schedule_reason);
}

test "daemon tick reports selectable route as no-op" {
    const health = health_mod.AccountHealth{
        .liveness = .{ .live = .{ .availability = .available } },
    };
    const decision = daemonTickDecision(config.PolicyConfig{}, .{
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
    const decision = daemonTickDecision(config.PolicyConfig{}, .{
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
    const decision = daemonTickDecision(config.PolicyConfig{}, .{
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
    const stats = daemonTickStats(config.PolicyConfig{}, &evaluations, 1000);

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

test "keepalive wait sleep is bounded for far-future wake-up sentinels" {
    try std.testing.expectEqual(@as(u64, 0), boundedKeepaliveSleepMs(1000, 1000, 60_000));
    try std.testing.expectEqual(@as(u64, 0), boundedKeepaliveSleepMs(1030, 1000, 0));
    try std.testing.expectEqual(@as(u64, 30), boundedKeepaliveSleepMs(1030, 1000, 60_000));
    try std.testing.expectEqual(@as(u64, 5_000), boundedKeepaliveSleepMs(100_000, 1000, 5_000));
    try std.testing.expectEqual(@as(u64, 60_000), boundedKeepaliveSleepMs(std.math.maxInt(i64), 1000, 60_000));
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
                .window_resets_at = std.time.timestamp() + 7200,
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
    try std.testing.expect(action.wait_until.? > std.time.timestamp());
    try std.testing.expect(action.command == .none);
}

test "repairActionFor surfaces expired quota window as revalidation needed" {
    const def = provider_schema.ProviderDefinition{
        .name = "toy",
        .display_name = "Toy Provider",
        .repair = .{ .owner = .manual_only },
    };
    const health = health_mod.AccountHealth{
        .liveness = .{ .live = .{
            .availability = .{ .quota_exhausted = .{
                .window_resets_at = std.time.timestamp() - 60,
                .exhausted_at = std.time.timestamp() - 7200,
            } },
        } },
    };
    const route = RepairPlanRoute{ .provider = "toy", .account = "default", .capability = "chat" };
    const action = repairActionFor(route, def, .ready, health, .spend_provider);

    try std.testing.expectEqual(RepairActionKind.revalidation_needed, action.kind);
    try std.testing.expectEqual(RepairMediation.probe, action.mediation);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, action.budget.?);
    try std.testing.expectEqual(RepairCommandKind.probe, action.command);
    try std.testing.expect(action.wait_until == null);
    try std.testing.expectEqualStrings("revalidation_needed", routeSkipReason(.ready, health));
}

test "Codex preflight repair summary separates revalidation from user handoff" {
    var summary = CodexPreflightRepairSummary{
        .route_repair_required = true,
        .agent_safe_inspection_available = true,
    };

    codexPreflightClassifyRepairRoute(&summary, "revalidation_needed", .{
        .kind = .revalidation_needed,
        .severity = "warning",
        .message = "quota reset window has passed",
        .mediation = .probe,
        .command = .probe,
        .budget = .spend_provider,
    });
    codexPreflightClassifyRepairRoute(&summary, "revalidation_needed", .{
        .kind = .revalidation_needed,
        .severity = "warning",
        .message = "quota reset window has passed",
        .mediation = .probe,
        .command = .probe,
        .budget = .spend_provider,
    });
    codexPreflightClassifyRepairRoute(&summary, "auth_permanently_failed", .{
        .kind = .reauth,
        .severity = "error",
        .message = "reauth is owned by upstream CLI",
        .mediation = .user_handoff,
        .owner = .upstream_cli_login,
        .command = .codex_login_device,
        .budget = .interactive,
        .interactive = true,
        .mutating = true,
    });
    codexPreflightFinalizeRepairSummary(&summary);

    try std.testing.expectEqual(@as(usize, 3), summary.blocked_routes);
    try std.testing.expectEqual(@as(usize, 2), summary.revalidation_needed_routes);
    try std.testing.expectEqual(@as(usize, 1), summary.auth_permanently_failed_routes);
    try std.testing.expectEqual(@as(usize, 1), summary.auth_handoff_routes);
    try std.testing.expect(summary.provider_spend_required);
    try std.testing.expect(summary.spend_confirmed_repair_available);
    try std.testing.expect(summary.user_handoff_required);
    try std.testing.expectEqualStrings("revalidation_needed", summary.dominant_blocker.?);
    try std.testing.expectEqual(@as(usize, 2), summary.dominant_blocker_count);
}

test "Codex preflight repair summary counts auth and provider blockers" {
    var summary = CodexPreflightRepairSummary{
        .route_repair_required = true,
        .agent_safe_inspection_available = true,
    };

    const reauth = RepairAction{
        .kind = .reauth,
        .severity = "error",
        .message = "reauth is owned by upstream CLI",
        .mediation = .user_handoff,
        .owner = .upstream_cli_login,
        .command = .codex_login_device,
        .budget = .interactive,
        .interactive = true,
        .mutating = true,
    };
    codexPreflightClassifyRepairRoute(&summary, "token_revoked", reauth);
    codexPreflightClassifyRepairRoute(&summary, "token_revoked", reauth);
    codexPreflightClassifyRepairRoute(&summary, "provider_degraded", .{
        .kind = .try_next_provider,
        .severity = "warning",
        .message = "provider appears degraded",
        .mediation = .provider_degraded,
    });
    codexPreflightClassifyRepairRoute(&summary, "auth_permanently_failed", reauth);
    codexPreflightClassifyRepairRoute(&summary, "credential_unavailable", reauth);
    codexPreflightFinalizeRepairSummary(&summary);

    try std.testing.expectEqual(@as(usize, 5), summary.blocked_routes);
    try std.testing.expectEqual(@as(usize, 2), summary.token_revoked_routes);
    try std.testing.expectEqual(@as(usize, 1), summary.provider_degraded_routes);
    try std.testing.expectEqual(@as(usize, 1), summary.auth_permanently_failed_routes);
    try std.testing.expectEqual(@as(usize, 1), summary.credential_unavailable_routes);
    try std.testing.expectEqual(@as(usize, 4), summary.auth_handoff_routes);
    try std.testing.expect(summary.user_handoff_required);
    try std.testing.expectEqualStrings("token_revoked", summary.dominant_blocker.?);
    try std.testing.expectEqual(@as(usize, 2), summary.dominant_blocker_count);
}

test "Codex broker-session risk actions follow repair reason lanes" {
    var summary = CodexPreflightRepairSummary{
        .route_repair_required = true,
        .agent_safe_inspection_available = true,
    };

    const reauth = RepairAction{
        .kind = .reauth,
        .severity = "error",
        .message = "reauth is owned by upstream CLI",
        .mediation = .user_handoff,
        .owner = .upstream_cli_login,
        .command = .codex_login_device,
        .budget = .interactive,
        .interactive = true,
        .mutating = true,
    };
    codexPreflightClassifyRepairRoute(&summary, "token_revoked", reauth);
    codexPreflightClassifyRepairRoute(&summary, "auth_permanently_failed", reauth);
    codexPreflightFinalizeRepairSummary(&summary);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeCodexBrokerSessionRiskActionsJsonWithSummary(
        buf.writer(),
        std.testing.allocator,
        "codex-max",
        "codex-max",
        true,
        0,
        summary,
    );

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"reauth_blocked_routes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"enroll_codex_account\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"revalidate_exhausted_routes\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"wait_for_quota_reset\"") == null);
}

test "stay-afloat tick risk actions follow auth-only repair lanes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

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

    {
        const file = try tmp.dir.createFile("max-1-auth.json", .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(auth_json);
    }
    {
        const file = try tmp.dir.createFile("max-3-auth.json", .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(auth_json);
    }

    const max_1_auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1-auth.json");
    defer std.testing.allocator.free(max_1_auth_path);
    const max_3_auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "max-3-auth.json");
    defer std.testing.allocator.free(max_3_auth_path);
    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-3": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "codex-max": {{ "providers": ["codex:max-1#codex-max", "codex:max-3#codex-max"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ max_1_auth_path, max_3_auth_path },
    );
    defer std.testing.allocator.free(cfg_json);
    const parsed = try config.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const blocked_route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const selected_route = RepairPlanRoute{ .provider = "codex", .account = "max-3", .capability = "codex-max" };
    const evaluations = [_]RouteEvaluation{
        .{
            .route = blocked_route,
            .runtime = .ready,
            .health = health_mod.AccountHealth{ .liveness = .{ .dead = .{ .reason = .token_revoked, .since = 1000 } } },
            .budget = .interactive,
            .action = reauthAction(blocked_route, provider_schema.codex_def),
            .selectable = false,
            .skip_reason = "token_revoked",
        },
        .{
            .route = selected_route,
            .runtime = .ready,
            .health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .available } } },
            .budget = .spend_provider,
            .action = .{ .kind = .none, .severity = "ok", .message = "route is selectable" },
            .selectable = true,
            .skip_reason = "available",
        },
    };
    const executions = [_]DaemonTickExecution{};

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeDaemonTickJsonObject(
        buf.writer(),
        std.testing.allocator,
        parsed.value,
        &evaluations,
        1,
        &executions,
        .{ .profile = "codex-max", .capability = "codex-max", .once = true, .json = true },
        0,
        1000,
        true,
    );

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"reauth_blocked_routes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"enroll_codex_account\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"revalidate_exhausted_routes\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"wait_for_quota_reset\"") == null);
}

test "Codex broker-session risk actions preserve quota repair lane" {
    var summary = CodexPreflightRepairSummary{
        .route_repair_required = true,
        .agent_safe_inspection_available = true,
    };

    codexPreflightClassifyRepairRoute(&summary, "quota_exhausted", .{
        .kind = .wait_for_quota,
        .severity = "warning",
        .message = "quota window is exhausted",
        .mediation = .wait,
        .command = .none,
        .budget = .free_local,
    });
    codexPreflightFinalizeRepairSummary(&summary);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeCodexBrokerSessionRiskActionsJsonWithSummary(
        buf.writer(),
        std.testing.allocator,
        "codex-max",
        "codex-max",
        true,
        0,
        summary,
    );

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"revalidate_exhausted_routes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"wait_for_quota_reset\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"reauth_blocked_routes\"") == null);
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
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"handoff_plan_command\":null") != null);
}

test "Codex preflight user-mediated action emits login handoff lane" {
    const route = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-max" };
    const action = reauthAction(route, provider_schema.codex_def);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var first = true;

    try std.testing.expect(try writeCodexPreflightUserMediatedActionJson(buf.writer(), std.testing.allocator, &first, action, route));
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"kind\":\"codex_login_device\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"command\":\"oauth-mux codex login-device max-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"budget\":\"interactive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"agent_safe\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"may_spend_provider_calls\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mutates_user_config\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"mutates_route_health\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"interactive\":true") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"handoff_plan_command\":\"oauth-mux enroll plan claude --account pro --json\"") != null);
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
    }, null);

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selected\":{\"provider\":\"toy\",\"account\":\"a2\"") != null);
    // TIN-1812: the a1 route is quota_exhausted with a future reset window, so it
    // counts as a recoverable fallback (not an immediately-live spare). The pool
    // is afloat (selected route ready); the quota route is "will recover".
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":true,\"selectable_fallback_routes\":0,\"recoverable_fallback_routes\":1,\"spare_fallback_ready\":false,\"single_route_at_risk\":true,\"recovery_window_resets_at\":") != null);
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
    }, null);

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"action\":\"next\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ready_for_exec\":true") != null);
    // TIN-1812: the a1 route is quota_exhausted with a future reset window, so it
    // counts as a recoverable fallback (not an immediately-live spare). The pool
    // is afloat (selected route ready); the quota route is "will recover".
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":true,\"selectable_fallback_routes\":0,\"recoverable_fallback_routes\":1,\"spare_fallback_ready\":false,\"single_route_at_risk\":true,\"recovery_window_resets_at\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience_actions\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"claim\":{\"claim_version\":1,\"level\":\"prepared_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"spare_fallback_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"current_process_hotswap\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"launch_argv\":[\"oauth-mux\",\"stay-afloat\",\"launch\",\"--profile\",\"work\",\"--capability\",\"chat\",\"--\",\"<command>\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"next_action\":{\"kind\":\"exec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"exec_argv\":[\"oauth-mux\",\"exec\",\"--provider\",\"toy\",\"--account\",\"a2\",\"--capability\",\"chat\",\"--\",\"<command>\"]") != null);
}

test "stay-afloat next degrades to fallback capability when requested capability exhausted (TIN-1811)" {
    // Diagnostic: route selection only reads config + the in-memory health store.
    // codex-max routes are all rate-limited (unselectable); codex-mini routes are
    // live. The codex-max profile declares capability_degradation_chain=["codex-mini"]
    // so the never-halt selector must cross to a live codex-mini route.
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } },
        \\        "max-2": { "secret": { "backend": "env", "variable": "TOY_MAX2" } },
        \\        "mini-1": { "secret": { "backend": "env", "variable": "TOY_MINI1" } },
        \\        "mini-2": { "secret": { "backend": "env", "variable": "TOY_MINI2" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": [
        \\        "toy:max-1#codex-max",
        \\        "toy:max-2#codex-max",
        \\        "toy:mini-1#codex-mini",
        \\        "toy:mini-2#codex-mini"
        \\      ],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    // Config with a degradation chain referencing a capability that has routes
    // must validate cleanly (null/valid chain = no error).
    var validation_messages = std.ArrayList(u8).init(std.testing.allocator);
    defer validation_messages.deinit();
    try config.validate(parsed.value, validation_messages.writer());
    try std.testing.expectEqual(@as(usize, 0), validation_messages.items.len);

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Both codex-max routes exhausted (rate-limited) -> unselectable.
    store.recordCapabilityHttpStatus("toy", "max-1", "codex-max", 429, 7200);
    store.recordCapabilityHttpStatus("toy", "max-2", "codex-max", 429, 7200);
    // Two live codex-mini routes -> selectable, with a spare beyond the selection.
    _ = try store.getOrCreate("toy:mini-1#codex-mini");
    _ = try store.getOrCreate("toy:mini-2#codex-mini");

    // Evaluate only the requested capability (codex-max), exactly as runStayAfloatNext.
    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    // Strictly capability-scoped selection finds nothing (today's hard block).
    try std.testing.expect(firstSelectableRoute(evaluations.items) == null);

    // Never-halt: cross to the degradation chain.
    const degraded = try selectDegradedRoute(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
    );
    try std.testing.expect(degraded.index != null);
    try std.testing.expect(degraded.capability != null);
    try std.testing.expectEqualStrings("codex-mini", degraded.capability.?);

    // The selected route is a live codex-mini route appended onto evaluations.
    const selected = evaluations.items[degraded.index.?];
    try std.testing.expect(selected.selectable);
    try std.testing.expectEqualStrings("codex-mini", selected.route.capability.?);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeStayAfloatNextJson(buf.writer(), std.testing.allocator, parsed.value, evaluations.items, degraded.index, null, .{
        .profile = "codex-max",
        .capability = "codex-max",
        .json = true,
    }, degraded.capability);

    // Surfaced degrade + a live spare keeps us afloat (not "not_afloat").
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ready_for_exec\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"degraded_capability\":\"codex-mini\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selected\":{\"provider\":\"toy\",\"account\":\"mini-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selectable_fallback_routes\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"afloat_with_spare_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"not_afloat\"") == null);
}

test "stay-afloat next leaves degradation off when no chain is configured (TIN-1811 non-regression)" {
    // Same exhausted codex-max routes and live codex-mini routes, but no
    // capability_degradation_chain -> selector must stay strictly capability
    // scoped (no degrade), proving null chain = today's behavior.
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } },
        \\        "mini-1": { "secret": { "backend": "env", "variable": "TOY_MINI1" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": [
        \\        "toy:max-1#codex-max",
        \\        "toy:mini-1#codex-mini"
        \\      ]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("toy", "max-1", "codex-max", 429, 7200);
    _ = try store.getOrCreate("toy:mini-1#codex-mini");

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    const degraded = try selectDegradedRoute(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
    );
    try std.testing.expect(degraded.index == null);
    try std.testing.expect(degraded.capability == null);
}

test "config rejects capability_degradation_chain with a capability that has no routes (TIN-1811)" {
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": ["toy:max-1#codex-max"],
        \\      "capability_degradation_chain": ["codex-typo"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var validation_messages = std.ArrayList(u8).init(std.testing.allocator);
    defer validation_messages.deinit();
    try std.testing.expectError(error.ConfigValidationError, config.validate(parsed.value, validation_messages.writer()));
    try std.testing.expect(std.mem.indexOf(u8, validation_messages.items, "capability_degradation_chain") != null);
    try std.testing.expect(std.mem.indexOf(u8, validation_messages.items, "codex-typo") != null);
}

test "stay-afloat launch path degrades across capability via selectDegradedRouteNotAttempted (TIN-1811 Phase 2)" {
    // Diagnostic: only reads config + the in-memory health store (no exec). The
    // launch/observe loops select via selectDegradedRouteNotAttempted; this
    // verifies it crosses to a live codex-mini route when every codex-max route
    // is unselectable, returns ONLY immediately-live routes, and respects the
    // attempted-routes retry set.
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } },
        \\        "mini-1": { "secret": { "backend": "env", "variable": "TOY_MINI1" } },
        \\        "mini-2": { "secret": { "backend": "env", "variable": "TOY_MINI2" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": [
        \\        "toy:max-1#codex-max",
        \\        "toy:mini-1#codex-mini",
        \\        "toy:mini-2#codex-mini"
        \\      ],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // codex-max exhausted (quota, future window) -> unselectable for launch.
    store.recordCapabilityHttpStatus("toy", "max-1", "codex-max", 429, 7200);
    // Two live codex-mini routes.
    _ = try store.getOrCreate("toy:mini-1#codex-mini");
    _ = try store.getOrCreate("toy:mini-2#codex-mini");

    // Launch evaluates only the requested capability, exactly like the loops.
    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    var attempted = std.ArrayList(RepairPlanRoute).init(std.testing.allocator);
    defer attempted.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    // Requested capability has nothing selectable; not-attempted base selector agrees.
    try std.testing.expect(firstSelectableRouteNotAttempted(evaluations.items, attempted.items) == null);

    // Degrade to the chain and pick the first live codex-mini route.
    const first = try selectDegradedRouteNotAttempted(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
        attempted.items,
    );
    try std.testing.expect(first.index != null);
    try std.testing.expectEqualStrings("codex-mini", first.capability.?);
    const first_route = evaluations.items[first.index.?];
    // CRITICAL: launch-time selection must be IMMEDIATELY-LIVE, never quota/dead.
    try std.testing.expect(first_route.selectable);
    try std.testing.expectEqualStrings("codex-mini", first_route.route.capability.?);
    try std.testing.expectEqualStrings("mini-1", first_route.route.account);

    // Simulate a failed launch on mini-1: it is now attempted; the retry must move
    // to the second live codex-mini route, still cross-capability, still live.
    try attempted.append(first_route.route);
    evaluations.clearRetainingCapacity();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);
    const second = try selectDegradedRouteNotAttempted(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
        attempted.items,
    );
    try std.testing.expect(second.index != null);
    const second_route = evaluations.items[second.index.?];
    try std.testing.expect(second_route.selectable);
    try std.testing.expectEqualStrings("mini-2", second_route.route.account);

    // Both codex-mini routes attempted: no un-attempted live route remains, so the
    // launch loop terminates (no halt-causing quota route is ever launched on).
    try attempted.append(second_route.route);
    evaluations.clearRetainingCapacity();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);
    const third = try selectDegradedRouteNotAttempted(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
        attempted.items,
    );
    try std.testing.expect(third.index == null);
    try std.testing.expect(third.capability == null);
}

test "quota-only codex-max pool is afloat-pending-recovery, not a false not_afloat, and is not launchable (TIN-1812)" {
    // Diagnostic: config + in-memory health store only. Every codex-max route is
    // quota_exhausted with a future reset window; none are dead; there is NO
    // degradation chain. The pool must report a recoverable fallback (so state is
    // not "not_afloat") and surface the soonest reset window, while remaining
    // NON-selectable for immediate launch (quota routes would fail upstream).
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } },
        \\        "max-2": { "secret": { "backend": "env", "variable": "TOY_MAX2" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": [
        \\        "toy:max-1#codex-max",
        \\        "toy:max-2#codex-max"
        \\      ]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Both routes quota_exhausted with future windows (7200s and 3700s).
    store.recordCapabilityHttpStatus("toy", "max-1", "codex-max", 429, 7200);
    store.recordCapabilityHttpStatus("toy", "max-2", "codex-max", 429, 3700);

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    // Both quota routes are unselectable for immediate launch.
    try std.testing.expect(!evaluations.items[0].selectable);
    try std.testing.expect(!evaluations.items[1].selectable);
    try std.testing.expectEqualStrings("quota_exhausted", evaluations.items[0].skip_reason);

    // Launch selection (no chain) finds NOTHING selectable: quota is never
    // launched on (it would fail upstream).
    const degraded = try selectDegradedRoute(
        std.testing.allocator,
        parsed.value,
        &store,
        &evaluations,
        "codex-max",
        "codex-max",
        null,
    );
    try std.testing.expect(degraded.index == null);

    // But the resilience ACCOUNTING counts the quota routes as recoverable.
    const recoverable = recoverableFallbackRouteCount(evaluations.items, null, null);
    try std.testing.expectEqual(@as(usize, 2), recoverable);
    try std.testing.expectEqual(@as(usize, 0), selectableFallbackRouteCount(evaluations.items, null));
    // Soonest window is the 3700s route, which is < the 7200s route.
    const soonest = soonestQuotaWindowReset(evaluations.items);
    try std.testing.expect(soonest != null);

    // The resilience JSON: not_afloat must NOT appear; state must be the
    // pending-recovery state; recoverable count > 0; window surfaced.
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRouteResilienceJson(buf.writer(), evaluations.items, null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"not_afloat\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"afloat_pending_quota_recovery\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"recoverable_fallback_routes\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selectable_fallback_routes\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"recovery_window_resets_at\":null") == null);
}

test "fallback readiness counts distinct accounts, not duplicate route rows" {
    const selected_route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const selected_account_duplicate = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-mini" };
    const fallback_route = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-mini" };
    const fallback_duplicate = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-mini" };

    const available_health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .available } } };
    const no_action = RepairAction{ .kind = .none, .severity = "ok", .message = "route is selectable" };
    const evaluations = [_]RouteEvaluation{
        .{
            .route = selected_route,
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
        .{
            .route = selected_account_duplicate,
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
        .{
            .route = fallback_route,
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
        .{
            .route = fallback_duplicate,
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
    };

    try std.testing.expect(!routeIsDistinctFallbackAccount(&evaluations, 0, 1));
    try std.testing.expect(routeIsDistinctFallbackAccount(&evaluations, 0, 2));
    try std.testing.expectEqual(@as(usize, 1), selectableFallbackRouteCount(&evaluations, 0));
    try std.testing.expectEqual(@as(usize, 1), selectableFallbackRouteCountForSelection(&evaluations, 0, "codex-mini"));
}

test "Codex broker summary does not claim same-account duplicate as spare fallback" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

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
    {
        const file = try tmp.dir.createFile("max-1-auth.json", .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(auth_json);
    }
    const max_1_auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1-auth.json");
    defer std.testing.allocator.free(max_1_auth_path);

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "codex-max": {{
        \\      "providers": [
        \\        "codex:max-1#codex-max",
        \\        "codex:max-1#codex-mini"
        \\      ],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{max_1_auth_path},
    );
    defer std.testing.allocator.free(cfg_json);
    const parsed = try config.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{ .profile = "codex-max" });
    defer routes.deinit();
    try std.testing.expectEqual(@as(usize, 2), routes.items.len);
    try std.testing.expect(sameFallbackAccount(routes.items[0], routes.items[1]));

    const available_health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .available } } };
    const no_action = RepairAction{ .kind = .none, .severity = "ok", .message = "route is selectable" };
    const evaluations = [_]RouteEvaluation{
        .{
            .route = routes.items[0],
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
        .{
            .route = routes.items[1],
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
    };
    const selected = firstSelectableRoute(&evaluations).?;

    const summary = try summarizeCodexBrokerSessionPlan(std.testing.allocator, parsed.value, &evaluations, selected);
    try std.testing.expectEqual(@as(usize, 2), summary.selectable_broker_routes);
    try std.testing.expectEqual(@as(usize, 0), summary.selectable_fallback_routes);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeCodexBrokerSessionPlanJson(buf.writer(), std.testing.allocator, parsed.value, &evaluations, selected, "codex-max", "codex-max");

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selectable_fallback_routes\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"spare_fallback_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"single_route_at_risk\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"fallback_candidate\":true") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"route_role\":\"selectable_duplicate\"") != null);
}

test "recoverable fallback readiness deduplicates quota rows by account" {
    const selected_route = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-max" };
    const selected_account_quota = RepairPlanRoute{ .provider = "codex", .account = "max-1", .capability = "codex-mini" };
    const fallback_quota = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-mini" };
    const fallback_quota_duplicate = RepairPlanRoute{ .provider = "codex", .account = "max-2", .capability = "codex-mini" };

    const available_health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .available } } };
    const quota_health = health_mod.AccountHealth{ .liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .window_resets_at = std.time.timestamp() + 7200,
        .exhausted_at = std.time.timestamp(),
    } } } } };
    const no_action = RepairAction{ .kind = .none, .severity = "ok", .message = "route is selectable" };
    const quota_action = RepairAction{ .kind = .wait_for_quota, .severity = "warning", .message = "quota exhausted", .mediation = .wait };
    const evaluations = [_]RouteEvaluation{
        .{
            .route = selected_route,
            .runtime = .ready,
            .health = available_health,
            .budget = .spend_provider,
            .action = no_action,
            .selectable = true,
            .skip_reason = "available",
        },
        .{
            .route = selected_account_quota,
            .runtime = .ready,
            .health = quota_health,
            .budget = .free_local,
            .action = quota_action,
            .selectable = false,
            .skip_reason = "quota_exhausted",
        },
        .{
            .route = fallback_quota,
            .runtime = .ready,
            .health = quota_health,
            .budget = .free_local,
            .action = quota_action,
            .selectable = false,
            .skip_reason = "quota_exhausted",
        },
        .{
            .route = fallback_quota_duplicate,
            .runtime = .ready,
            .health = quota_health,
            .budget = .free_local,
            .action = quota_action,
            .selectable = false,
            .skip_reason = "quota_exhausted",
        },
    };

    try std.testing.expectEqual(@as(usize, 1), recoverableFallbackRouteCount(&evaluations, 0, "codex-mini"));
}

test "expired quota window recovers during route evaluation" {
    // A quota route whose window has already passed should become selectable
    // during route-health normalization. Future quota windows remain pending
    // recovery; expired windows must not keep the pool falsely halted.
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
        \\        "max-1": { "secret": { "backend": "env", "variable": "TOY_MAX1" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": ["toy:max-1#codex-max"]
        \\    }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Quota with a window that already elapsed: getOrCreate then force an expired
    // window via the public health record, then hand-roll the past reset.
    const health = try store.getOrCreate("toy:max-1#codex-max");
    const now = std.time.timestamp();
    health.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .exhausted_at = now - 10_000,
        .window_resets_at = now - 1,
    } } } };

    var routes = try collectRepairPlanRoutes(std.testing.allocator, parsed.value, .{
        .profile = "codex-max",
        .capability = "codex-max",
    });
    defer routes.deinit();

    var evaluations = std.ArrayList(RouteEvaluation).init(std.testing.allocator);
    defer evaluations.deinit();
    try collectRouteEvaluations(std.testing.allocator, parsed.value, &store, routes.items, &evaluations);

    const selected = firstSelectableRoute(evaluations.items);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(@as(usize, 0), recoverableFallbackRouteCount(evaluations.items, selected, null));
    try std.testing.expect(soonestQuotaWindowReset(evaluations.items) == null);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeRouteResilienceJson(buf.writer(), evaluations.items, selected);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"state\":\"afloat_without_spare_fallback\"") != null);
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
    }, null);

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ready_for_exec\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resilience\":{\"selected_route_ready\":false,\"selectable_fallback_routes\":0,\"recoverable_fallback_routes\":0,\"spare_fallback_ready\":false,\"single_route_at_risk\":false,\"recovery_window_resets_at\":null,\"state\":\"not_afloat\"}") != null);
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
    try std.testing.expect(observeOutputLooksLikeCodexUsageLimit("You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage"));
    try std.testing.expect(observeOutputLooksLikeCodexUsageLimit("{\"type\":\"usage_limit_reached\"}"));
    try std.testing.expect(!observeOutputLooksLikeCodexUsageLimit("ordinary child failure"));
}

test "Codex status summary keeps quota account across parsed lines" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const status_path = try std.fs.path.join(std.testing.allocator, &.{ root, "status.ndjson" });
    defer std.testing.allocator.free(status_path);

    var file = try tmp.dir.createFile("status.ndjson", .{});
    defer file.close();
    try file.writeAll(
        \\{"kind":"session_started","claim_level":"broker_owned","selected_account":"codex:max-2","session_authority":"isolated","sqlite_authority":"isolated_overlay"}
        \\{"kind":"proxy_turn","account":"codex:max-2","method":"POST","path_kind":"responses","status":429,"classification":"quota_exhausted","body_class":"usage_limit_reached","delivered_to_codex":false}
        \\{"kind":"proxy_same_turn_retry","from":"codex:max-2","to":"codex:max-3"}
        \\{"kind":"proxy_turn","account":"codex:max-3","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","delivered_to_codex":true}
        \\
    );

    var summary = try summarizeCodexStatusFile(std.testing.allocator, status_path);
    defer summary.deinit();

    try std.testing.expect(summary.brokered_session_observed);
    try std.testing.expect(summary.quota_event_observed);
    try std.testing.expect(summary.quota_handoff_observed);
    try std.testing.expect(summary.provider_originated_live_fallback_claim);
    try std.testing.expectEqualStrings("successful_live_quota_handoff", summary.verdict);
}

test "Codex status summary preserves child signal terminal evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const status_path = try std.fs.path.join(std.testing.allocator, &.{ root, "status.ndjson" });
    defer std.testing.allocator.free(status_path);

    var file = try tmp.dir.createFile("status.ndjson", .{});
    defer file.close();
    // Deliberate legacy-shape coverage: this fixture keeps the
    // session_authority:"canonical_bridge" (legacy shared_canonical mode)
    // frame so the summary still parses opt-in bridge sessions. The other
    // status-summary fixtures carry the default isolated / isolated_overlay shape.
    try file.writeAll(
        \\{"kind":"session_started","claim_level":"broker_owned","selected_account":"codex:max-3","session_authority":"canonical_bridge","sqlite_authority":"canonical_env"}
        \\{"kind":"proxy_turn","account":"codex:max-3","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","delivered_to_codex":true}
        \\{"kind":"session_aborted","adapter":"codex","reason":"child_signal","exit_code":-1,"term_kind":"signal","term_code":9,"signal_name":"SIGKILL","final_claim_level":"broker_owned","synthetic_swap_observed":false}
        \\
    );

    var summary = try summarizeCodexStatusFile(std.testing.allocator, status_path);
    defer summary.deinit();

    try std.testing.expect(summary.brokered_session_observed);
    try std.testing.expect(summary.terminal_event_observed);
    try std.testing.expect(summary.session_aborted_observed);
    try std.testing.expectEqualStrings("session_aborted", summary.terminal_event_kind.?);
    try std.testing.expectEqual(@as(i64, -1), summary.terminal_exit_code.?);
    try std.testing.expectEqualStrings("signal", summary.terminal_term_kind.?);
    try std.testing.expectEqual(@as(i64, 9), summary.terminal_term_code.?);
    try std.testing.expectEqualStrings("SIGKILL", summary.terminal_signal_name.?);
}

test "Codex status summary reports transport fallback recovery" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const status_path = try std.fs.path.join(std.testing.allocator, &.{ root, "status.ndjson" });
    defer std.testing.allocator.free(status_path);

    var file = try tmp.dir.createFile("status.ndjson", .{});
    defer file.close();
    try file.writeAll(
        \\{"kind":"session_started","claim_level":"broker_owned","selected_account":"codex:max-1","session_authority":"isolated","sqlite_authority":"isolated_overlay"}
        \\{"kind":"proxy_upstream_failed","account":"codex:max-1","err":"ConnectionResetByPeer"}
        \\{"kind":"proxy_provider_same_turn_retry","from":"codex:max-1","to":"codex:max-2","reason":"provider_5xx"}
        \\{"kind":"proxy_turn","account":"codex:max-2","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","delivered_to_codex":true}
        \\{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":true}
        \\
    );

    var summary = try summarizeCodexStatusFile(std.testing.allocator, status_path);
    defer summary.deinit();

    try std.testing.expect(summary.brokered_session_observed);
    try std.testing.expect(summary.transport_failure_observed);
    try std.testing.expect(summary.transport_recovery_observed);
    try std.testing.expectEqual(@as(u64, 1), summary.upstream_failure_events);
    try std.testing.expectEqual(@as(u64, 1), summary.provider_same_turn_retry_events);
    try std.testing.expectEqualStrings("transport_fallback_recovered", summary.verdict);
}

test "Codex status summary reports local transport retry recovery" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const status_path = try std.fs.path.join(std.testing.allocator, &.{ root, "status.ndjson" });
    defer std.testing.allocator.free(status_path);

    var file = try tmp.dir.createFile("status.ndjson", .{});
    defer file.close();
    try file.writeAll(
        \\{"kind":"session_started","claim_level":"broker_owned","selected_account":"codex:max-1","session_authority":"isolated","sqlite_authority":"isolated_overlay"}
        \\{"kind":"proxy_transport_local_retry","account":"codex:max-1","method":"POST","path_kind":"responses","err":"ConnectionResetByPeer","attempt":1,"max_attempts":2,"backoff_ms":150,"delivered_to_codex":false}
        \\{"kind":"proxy_transport_local_retry_recovered","account":"codex:max-1","method":"POST","path_kind":"responses","attempts":1,"status":200,"classification":"ok","delivered_to_codex":true}
        \\{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","delivered_to_codex":true}
        \\{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":false}
        \\
    );

    var summary = try summarizeCodexStatusFile(std.testing.allocator, status_path);
    defer summary.deinit();

    try std.testing.expect(summary.brokered_session_observed);
    try std.testing.expect(summary.transport_failure_observed);
    try std.testing.expect(summary.transport_recovery_observed);
    try std.testing.expectEqual(@as(u64, 1), summary.transport_local_retry_events);
    try std.testing.expectEqual(@as(u64, 1), summary.transport_local_retry_recovered_events);
    try std.testing.expectEqual(@as(u64, 0), summary.upstream_failure_events);
    try std.testing.expectEqualStrings("transport_local_retry_recovered", summary.verdict);
}

test "Codex status summary flags historical responses GET 405 ok regression" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const status_path = try std.fs.path.join(std.testing.allocator, &.{ root, "status.ndjson" });
    defer std.testing.allocator.free(status_path);

    var file = try tmp.dir.createFile("status.ndjson", .{});
    defer file.close();
    try file.writeAll(
        \\{"kind":"session_started","claim_level":"broker_owned","selected_account":"codex:max-1","session_authority":"isolated","sqlite_authority":"isolated_overlay"}
        \\{"kind":"proxy_turn","account":"codex:max-1","method":"GET","path_kind":"responses","status":405,"classification":"ok","body_class":"json_error","delivered_to_codex":true}
        \\{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":false}
        \\
    );

    var summary = try summarizeCodexStatusFile(std.testing.allocator, status_path);
    defer summary.deinit();

    try std.testing.expect(summary.transport_failure_observed);
    try std.testing.expectEqual(@as(u64, 1), summary.responses_get_405_misclassified_ok);
    try std.testing.expectEqualStrings("transport_regression_405_misclassified", summary.verdict);
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
    _ = @import("reauth/orchestrator.zig"); // graduated from draft (TIN-2048/TIN-2064): tests now run in CI
    _ = @import("enroll/tests.zig");
    _ = @import("enroll/callback_server_tests.zig");
    _ = @import("enroll/device_code.zig"); // unparked (flow-composition car): RFC 8628 device flow, tests now run in CI
    _ = @import("enroll/browser_launch.zig"); // unparked (flow-composition car): cookieless launcher, tests now run in CI
    _ = @import("enroll/flow_composition.zig"); // flow-composition car: production RunFlowFn (device_code composed)
    _ = @import("enroll/claude_reauth_tests.zig");
    _ = @import("enroll/web_ui_tests.zig");
    _ = @import("keepalive/warm_scheduler_tests.zig");
    _ = @import("keepalive/warm_binding_tests.zig");
    _ = @import("keepalive/warm_runner_tests.zig");
    _ = @import("keepalive/refresh_race_tests.zig"); // TIN-2059 in-process actor-gate race
    _ = @import("quota/bucket_tests.zig"); // TIN-2407 P0: pure quota-bucket algebra
    _ = @import("quota/advise_tests.zig"); // TIN-2719 M0 PR1: pure valet advisor core
    _ = @import("doctor_binaries.zig"); // TIN-2723: resident-service + PATH binary truth

    _ = @import("identity/identity_graph_tests.zig");
    _ = @import("identity/claude_identity_tests.zig");
    _ = @import("identity/identity_lane_integration_tests.zig");
    _ = @import("cassettes/claude_oauth_cassette_tests.zig");
    _ = @import("keepalive/ui_server_tests.zig");
}
