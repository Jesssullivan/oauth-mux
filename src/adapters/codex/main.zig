//! Codex adapter — `oauth-mux codex run`.
//!
//! Anchor: docs/spec/codex-adapter-contract-2026-05-03.md.
//!
//! Skeleton model: child-owned codex session. This gives
//! users the unmodified codex TUI/exec experience — we don't render a
//! TUI, don't drive JSON-RPC, don't spawn `codex app-server`. We:
//!   1. broker.populatePool from the active oauth-mux Config (profile
//!      filtered).
//!   2. account/select to pick a credited account.
//!   3. Find that account's per-account CODEX_HOME (already managed by
//!      oauth-mux at enroll time).
//!   4. spawn `codex` with CODEX_HOME pointed at that directory.
//!      The user sees real codex while oauth-mux keeps owning the
//!      proxy/broker boundary.
//!
//! The adapter writes a generated config.toml that points Codex at a
//! localhost wire proxy owned by oauth-mux. The parent process stays
//! alive to broker HTTP traffic and account selection while the Codex
//! child keeps the same process id.
//!
//! The JSON-RPC IDE-role client in app_server_client.zig stays for
//! future broker-mediated automation (the broker-* surfaces, scripted
//! use, Phase 4 demolition follow-ups). It is not on the
//! `oauth-mux codex run` default path.

const std = @import("std");
const broker = @import("../../broker/mod.zig");
const broker_types = @import("../../broker/types.zig");
const broker_loader = @import("../../broker_loader.zig");
const config_mod = @import("../../config.zig");
const shell = @import("../../shell.zig");
const wire_proxy = @import("wire_proxy.zig");

pub const RunOptions = struct {
    profile: ?[]const u8 = null,
    account: ?[]const u8 = null,
    /// If true, emit NDJSON status frames to stderr.
    json_status: bool = false,
    /// Args after `--` to forward to codex unchanged.
    forward_argv: []const []const u8 = &.{},
};

pub const RunError = error{
    NoConfig,
    PoolPopulateFailed,
    NoAccountSelectable,
    NoCodexHome,
};

/// Resolve the per-account CODEX_HOME directory. Order:
///   1. AccountConfig.config_dir if set.
///   2. dirname(secret.path) when secret.backend == "file" (the
///      common case: oauth-mux's enrollment placed auth.json inside
///      a per-account directory we can use as CODEX_HOME directly).
fn resolveCodexHome(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    account_id: []const u8,
) !?[]u8 {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return null;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse return null;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse return null;

    if (acct_cfg.config_dir) |cd| {
        return try expandTilde(allocator, cd);
    }
    if (std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        const path = acct_cfg.secret.path orelse return null;
        const expanded = try expandTilde(allocator, path);
        defer allocator.free(expanded);
        const dir = std.fs.path.dirname(expanded) orelse return null;
        return try allocator.dupe(u8, dir);
    }
    return null;
}

fn expandTilde(allocator: std.mem.Allocator, p: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, p, "~/")) return try allocator.dupe(u8, p);
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home, p[1..] });
}

pub fn run(allocator: std.mem.Allocator, opts: RunOptions) !void {
    const stderr = std.io.getStdErr().writer();

    // 1. Load oauth-mux config + populate broker pool.
    const parsed = config_mod.load(allocator) catch |e| {
        try stderr.print("oauth-mux codex: config load: {s}\n", .{@errorName(e)});
        return RunError.NoConfig;
    };
    defer parsed.deinit();

    var server = broker.Server.init(allocator);
    defer server.deinit();
    broker_loader.populatePool(&server.pool, parsed.value, opts.profile) catch {
        return RunError.PoolPopulateFailed;
    };

    // 2. Elect an account (honoring --account pin if set).
    const elected = if (opts.account) |pin| pin: {
        for (server.pool.accounts.items) |a| {
            if (std.mem.eql(u8, a.id, pin)) break :pin a;
        }
        try stderr.print("oauth-mux codex: --account {s} not in profile\n", .{pin});
        return RunError.NoAccountSelectable;
    } else server.pool.elect(opts.profile, null, &.{}) catch |e| switch (e) {
        broker_types.BrokerError.NoAccountSelectable => {
            try stderr.writeAll("oauth-mux codex: no selectable account in profile\n");
            return RunError.NoAccountSelectable;
        },
        else => return e,
    };

    // 3. Resolve the per-account CODEX_HOME.
    const codex_home = (try resolveCodexHome(allocator, parsed.value, elected.id)) orelse {
        try stderr.print(
            "oauth-mux codex: cannot resolve CODEX_HOME for {s}; account needs config_dir or file secret\n",
            .{elected.id},
        );
        return RunError.NoCodexHome;
    };
    defer allocator.free(codex_home);

    // 4. Bind the wire-layer reverse proxy. The adapter stays alive
    // as the broker/proxy owner while the codex child runs with
    // inherited stdio. This is not a restart fallback; the same child
    // process makes the synthetic post-swap request in the smoke.
    var mat_ctx = broker_loader.ChatgptMaterializerCtx{ .cfg = &parsed.value };
    var proxy = wire_proxy.Proxy.bind(
        allocator,
        &server.pool,
        mat_ctx.vtable(),
        stderr.any(),
    ) catch |e| {
        try stderr.print("oauth-mux codex: proxy bind: {s}\n", .{@errorName(e)});
        return e;
    };
    defer proxy.deinit();
    proxy.profile = opts.profile;
    const proxy_port = proxy.port();

    // 5. Write a managed config.toml in the per-account CODEX_HOME
    // pointing model_providers.openai at the local proxy.
    try writeManagedConfigToml(allocator, codex_home, proxy_port);

    if (opts.json_status) {
        try stderr.print(
            "{{\"kind\":\"session_started\",\"adapter\":\"codex\",\"selected_account\":\"{s}\",\"codex_home_path_printed\":false,\"proxy_port\":{d},\"claim_level\":\"broker_owned\"}}\n",
            .{ elected.id, proxy_port },
        );
    }

    // 6. Build argv: `codex` plus any forwarded user args.
    const codex_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_BIN") catch
        try allocator.dupe(u8, "codex");
    defer allocator.free(codex_bin);

    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(allocator);
    try argv.append(allocator, codex_bin);
    for (opts.forward_argv) |a| try argv.append(allocator, a);

    // 7. Build env: copy current, set CODEX_HOME and OMUX_ACTIVE_*.
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("CODEX_HOME", codex_home);
    try env_map.put("OMUX_ACTIVE_PROVIDER", "codex");
    const account_only = elected.id[std.mem.indexOfScalar(u8, elected.id, ':').? + 1 ..];
    try env_map.put("OMUX_ACTIVE_ACCOUNT", account_only);
    if (opts.profile) |p| try env_map.put("OMUX_ACTIVE_PROFILE", p);

    // 8. Spawn codex as child with inherited stdio (so the user gets
    // the real codex TUI). The adapter stays alive in parent.
    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;
    child.spawn() catch |e| {
        try stderr.print("oauth-mux codex: spawn: {s}\n", .{@errorName(e)});
        return e;
    };

    // 9. Start the proxy thread. It loops on serveOne until the
    // shutdown flag is set after the child exits.
    var shutdown = std.atomic.Value(bool).init(false);
    const proxy_thread = try std.Thread.spawn(
        .{},
        proxyThreadMain,
        .{ &proxy, &shutdown },
    );

    // 10. Wait for codex to exit; signal proxy to stop.
    const term = child.wait() catch |e| {
        try stderr.print("oauth-mux codex: child wait: {s}\n", .{@errorName(e)});
        shutdown.store(true, .release);
        proxy_thread.join();
        return e;
    };

    shutdown.store(true, .release);
    // Tickle the proxy thread out of accept() by connecting once.
    tickleProxy(proxy_port);
    proxy_thread.join();

    if (opts.json_status) {
        const exit_code: i32 = switch (term) {
            .Exited => |c| c,
            else => -1,
        };
        try stderr.print(
            "{{\"kind\":\"session_ended\",\"adapter\":\"codex\",\"exit_code\":{d},\"final_claim_level\":\"{s}\",\"synthetic_swap_observed\":{any}}}\n",
            .{ exit_code, proxy.peakClaimLevel().toString(), proxy.syntheticSwapSeen() },
        );
    }

    // Propagate exit code.
    switch (term) {
        .Exited => |c| if (c != 0) std.process.exit(c),
        else => std.process.exit(1),
    }
}

fn proxyThreadMain(p: *wire_proxy.Proxy, shutdown: *std.atomic.Value(bool)) void {
    while (!shutdown.load(.acquire)) {
        p.serveOne() catch |e| {
            // Server error or accept failure; if shutting down, exit.
            if (shutdown.load(.acquire)) return;
            std.debug.print("proxy: serveOne: {s}\n", .{@errorName(e)});
            // Continue serving; transient errors should not kill the
            // proxy mid-session.
        };
    }
}

/// Open a TCP connection to the proxy and immediately close it. This
/// wakes the proxy thread out of a blocking accept() during shutdown.
fn tickleProxy(port: u16) void {
    const addr = std.net.Address.parseIp("127.0.0.1", port) catch return;
    const sock = std.net.tcpConnectToAddress(addr) catch return;
    sock.close();
}

fn writeManagedConfigToml(
    allocator: std.mem.Allocator,
    codex_home: []const u8,
    proxy_port: u16,
) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/config.toml", .{codex_home});
    defer allocator.free(path);

    var contents = std.ArrayListUnmanaged(u8){};
    defer contents.deinit(allocator);
    const w = contents.writer(allocator);
    try w.writeAll("# Managed by oauth-mux. Phase 2 wire proxy override.\n");
    try w.writeAll("# Anchor: docs/spec/codex-adapter-contract-2026-05-03.md §4\n\n");
    try w.print("[model_providers.openai]\n", .{});
    try w.print("name = \"openai\"\n", .{});
    try w.print("base_url = \"http://127.0.0.1:{d}/backend-api/codex\"\n", .{proxy_port});
    try w.writeAll("wire_api = \"responses\"\n");
    try w.writeAll("requires_openai_auth = true\n");

    const f = try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = true });
    defer f.close();
    try f.writeAll(contents.items);
}

test "RunOptions defaults" {
    const opts = RunOptions{};
    try std.testing.expect(opts.profile == null);
    try std.testing.expect(!opts.json_status);
    try std.testing.expectEqual(@as(usize, 0), opts.forward_argv.len);
}

test "expandTilde no-op when no tilde" {
    const a = try expandTilde(std.testing.allocator, "/no/tilde/here");
    defer std.testing.allocator.free(a);
    try std.testing.expectEqualStrings("/no/tilde/here", a);
}
