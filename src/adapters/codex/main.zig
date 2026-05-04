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
//!   3. Resolve that account's auth.json source from the oauth-mux
//!      account store.
//!   4. Create a per-session CODEX_HOME overlay with a copied auth.json
//!      and generated proxy config.toml.
//!   5. spawn `codex` with CODEX_HOME pointed at that overlay.
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
    /// Optional file path for NDJSON status frames. When set, status
    /// frames are written here instead of stderr so real Codex terminal
    /// output cannot corrupt the evidence stream.
    json_status_file: ?[]const u8 = null,
    /// Args after `--` to forward to codex unchanged.
    forward_argv: []const []const u8 = &.{},
};

pub const RunError = error{
    NoConfig,
    PoolPopulateFailed,
    NoAccountSelectable,
    NoCodexHome,
};

/// Resolve the account's source auth.json path. Order:
///   1. secret.path when secret.backend == "file" (the normal
///      oauth-mux enrollment shape).
///   2. AccountConfig.config_dir/auth.json when config_dir exists.
fn resolveCodexAuthPath(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    account_id: []const u8,
) !?[]u8 {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return null;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse return null;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse return null;

    if (std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        const path = acct_cfg.secret.path orelse return null;
        return try expandTilde(allocator, path);
    }
    if (acct_cfg.config_dir) |cd| {
        const dir = try expandTilde(allocator, cd);
        defer allocator.free(dir);
        return try std.fs.path.join(allocator, &.{ dir, "auth.json" });
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
    const emit_status = opts.json_status or opts.json_status_file != null;

    var status_file: ?std.fs.File = null;
    defer if (status_file) |*file| file.close();
    var status_writer = stderr.any();
    if (opts.json_status_file) |path| {
        status_file = try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = true });
        status_writer = status_file.?.writer().any();
    }

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

    // 3. Resolve the selected account auth source. Runtime CODEX_HOME
    // is a per-session overlay, never the shared account store.
    const source_auth_path = (try resolveCodexAuthPath(allocator, parsed.value, elected.id)) orelse {
        try stderr.print(
            "oauth-mux codex: cannot resolve auth.json for {s}; account needs config_dir or file secret\n",
            .{elected.id},
        );
        return RunError.NoCodexHome;
    };
    defer allocator.free(source_auth_path);

    // 4. Bind the wire-layer reverse proxy. The adapter stays alive
    // as the broker/proxy owner while the codex child runs with
    // inherited stdio. This is not a restart fallback; the same child
    // process makes the synthetic post-swap request in the smoke.
    var mat_ctx = broker_loader.ChatgptMaterializerCtx{ .cfg = &parsed.value };
    var proxy = wire_proxy.Proxy.bind(
        allocator,
        &server.pool,
        mat_ctx.vtable(),
        status_writer,
    ) catch |e| {
        try stderr.print("oauth-mux codex: proxy bind: {s}\n", .{@errorName(e)});
        return e;
    };
    defer proxy.deinit();
    proxy.profile = opts.profile;
    const proxy_port = proxy.port();

    // 5. Create a per-session CODEX_HOME overlay containing copied
    // auth material and generated proxy config. This prevents two
    // concurrent adapter sessions from clobbering the same account
    // store's config.toml.
    const codex_home = try makeSessionCodexHome(allocator, source_auth_path, proxy_port);
    defer {
        std.fs.cwd().deleteTree(codex_home) catch {};
        allocator.free(codex_home);
    }

    if (emit_status) {
        try status_writer.print(
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

    if (emit_status) {
        const exit_code: i32 = switch (term) {
            .Exited => |c| c,
            else => -1,
        };
        try status_writer.print(
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

fn makeSessionCodexHome(
    allocator: std.mem.Allocator,
    source_auth_path: []const u8,
    proxy_port: u16,
) ![]u8 {
    const tmp_root = std.process.getEnvVarOwned(allocator, "TMPDIR") catch
        try allocator.dupe(u8, "/tmp");
    defer allocator.free(tmp_root);
    return try createSessionCodexHomeUnder(allocator, tmp_root, source_auth_path, proxy_port);
}

fn createSessionCodexHomeUnder(
    allocator: std.mem.Allocator,
    tmp_root: []const u8,
    source_auth_path: []const u8,
    proxy_port: u16,
) ![]u8 {
    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const hex = std.fmt.bytesToHex(nonce, .lower);
    const name = try std.fmt.allocPrint(allocator, "oauth-mux-codex-{s}", .{hex[0..]});
    defer allocator.free(name);

    const session_home = try std.fs.path.join(allocator, &.{ tmp_root, name });
    errdefer allocator.free(session_home);
    try std.fs.cwd().makePath(session_home);
    errdefer std.fs.cwd().deleteTree(session_home) catch {};

    const auth_dst = try std.fs.path.join(allocator, &.{ session_home, "auth.json" });
    defer allocator.free(auth_dst);
    try copyFileContents(allocator, source_auth_path, auth_dst);

    if (std.fs.path.dirname(source_auth_path)) |source_dir| {
        const install_src = try std.fs.path.join(allocator, &.{ source_dir, "installation_id" });
        defer allocator.free(install_src);
        const install_dst = try std.fs.path.join(allocator, &.{ session_home, "installation_id" });
        defer allocator.free(install_dst);
        copyFileContents(allocator, install_src, install_dst) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
    }

    try writeManagedConfigToml(allocator, session_home, proxy_port);
    return session_home;
}

fn copyFileContents(
    allocator: std.mem.Allocator,
    source_path: []const u8,
    dest_path: []const u8,
) !void {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, source_path, 2 * 1024 * 1024);
    defer allocator.free(bytes);
    const f = try std.fs.cwd().createFile(dest_path, .{ .mode = 0o600, .truncate = true });
    defer f.close();
    try f.writeAll(bytes);
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
    try std.testing.expect(opts.json_status_file == null);
    try std.testing.expectEqual(@as(usize, 0), opts.forward_argv.len);
}

test "expandTilde no-op when no tilde" {
    const a = try expandTilde(std.testing.allocator, "/no/tilde/here");
    defer std.testing.allocator.free(a);
    try std.testing.expectEqualStrings("/no/tilde/here", a);
}

test "createSessionCodexHomeUnder copies auth and does not clobber source config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    {
        const install = try tmp.dir.createFile("account/installation_id", .{ .mode = 0o600 });
        defer install.close();
        try install.writeAll("install-fixture\n");
    }
    {
        const cfg = try tmp.dir.createFile("account/config.toml", .{ .mode = 0o600 });
        defer cfg.close();
        try cfg.writeAll("preexisting = true\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const session_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678);
    defer {
        std.fs.cwd().deleteTree(session_home) catch {};
        std.testing.allocator.free(session_home);
    }

    const session_auth = try std.fs.path.join(std.testing.allocator, &.{ session_home, "auth.json" });
    defer std.testing.allocator.free(session_auth);
    const copied_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_auth, 1024);
    defer std.testing.allocator.free(copied_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"fixture\"}}\n", copied_auth);

    const session_install = try std.fs.path.join(std.testing.allocator, &.{ session_home, "installation_id" });
    defer std.testing.allocator.free(session_install);
    const copied_install = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_install, 1024);
    defer std.testing.allocator.free(copied_install);
    try std.testing.expectEqualStrings("install-fixture\n", copied_install);

    const session_config = try std.fs.path.join(std.testing.allocator, &.{ session_home, "config.toml" });
    defer std.testing.allocator.free(session_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_config, 4096);
    defer std.testing.allocator.free(generated_config);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "127.0.0.1:45678") != null);

    const source_config = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "config.toml" });
    defer std.testing.allocator.free(source_config);
    const original_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, source_config, 1024);
    defer std.testing.allocator.free(original_config);
    try std.testing.expectEqualStrings("preexisting = true\n", original_config);
}
