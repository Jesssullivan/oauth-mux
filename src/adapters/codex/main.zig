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
//!   4. Create a per-session CODEX_HOME overlay with copied auth material,
//!      generated proxy config.toml, and bridged session-authority paths.
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
    /// Optional canonical Codex session authority home. Defaults to the
    /// parent CODEX_HOME when set, otherwise ~/.codex.
    session_home: ?[]const u8 = null,
    /// If true, do not bridge canonical sessions/history into the
    /// managed CODEX_HOME overlay.
    isolated_session_store: bool = false,
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
    SessionAuthorityUnavailable,
};

const SessionAuthorityMode = enum {
    canonical_bridge,
    isolated,

    fn toString(self: SessionAuthorityMode) []const u8 {
        return switch (self) {
            .canonical_bridge => "canonical_bridge",
            .isolated => "isolated",
        };
    }
};

const SessionCodexHome = struct {
    path: []u8,
    session_authority: SessionAuthorityMode,
    authority_home: ?[]u8 = null,
    auth_initial_hash: [32]u8,

    fn deinit(self: SessionCodexHome, allocator: std.mem.Allocator) void {
        std.fs.cwd().deleteTree(self.path) catch {};
        allocator.free(self.path);
        if (self.authority_home) |home| allocator.free(home);
    }
};

const ResumeMode = enum {
    none,
    chooser,
    last,
    explicit,

    fn toString(self: ResumeMode) []const u8 {
        return switch (self) {
            .none => "none",
            .chooser => "chooser",
            .last => "last",
            .explicit => "explicit",
        };
    }
};

const ResumeRequest = struct {
    mode: ResumeMode = .none,
    explicit_id: ?[]const u8 = null,

    fn requested(self: ResumeRequest) bool {
        return self.mode != .none;
    }
};

const RolloutEntry = struct {
    size: u64,
    mtime: i128,
};

const RolloutSnapshot = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(RolloutEntry) = .{},

    fn init(allocator: std.mem.Allocator) RolloutSnapshot {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *RolloutSnapshot) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.entries.deinit(self.allocator);
    }

    fn count(self: *const RolloutSnapshot) usize {
        return self.entries.count();
    }
};

const ResumeObservation = struct {
    rollouts_before: usize = 0,
    rollouts_after: usize = 0,
    changed_existing: usize = 0,
    created: usize = 0,
    explicit_target_found_before: ?bool = null,
    explicit_target_changed: ?bool = null,
};

const AuthWritebackObservation = struct {
    overlay_auth_present: bool = false,
    source_auth_present: bool = false,
    changed: bool = false,
    written: bool = false,
    source_conflict: bool = false,
    ok: bool = true,
    error_name: ?[]const u8 = null,
};

const SessionAuthorityEntryKind = enum {
    directory,
    file,
};

const SessionAuthorityEntry = struct {
    name: []const u8,
    kind: SessionAuthorityEntryKind,
};

const codex_session_authority_entries = [_]SessionAuthorityEntry{
    .{ .name = "sessions", .kind = .directory },
    .{ .name = "shell_snapshots", .kind = .directory },
    .{ .name = "history.jsonl", .kind = .file },
    .{ .name = "session_index.jsonl", .kind = .file },
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
        status_file = openStatusFile(path) catch |e| {
            try stderr.print("oauth-mux codex: cannot open --json-status-file: {s}\n", .{@errorName(e)});
            return e;
        };
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
    // auth material, generated proxy config, and canonical session
    // authority references unless isolation was explicitly requested.
    // This prevents concurrent adapter sessions from clobbering
    // auth/config while keeping resume/history behavior aligned with
    // bare Codex.
    const codex_home = try makeSessionCodexHome(
        allocator,
        source_auth_path,
        proxy_port,
        opts.session_home,
        opts.isolated_session_store,
    );
    defer codex_home.deinit(allocator);

    const resume_request = detectResumeRequest(opts.forward_argv);
    var resume_snapshot: ?RolloutSnapshot = null;
    defer if (resume_snapshot) |*snapshot| snapshot.deinit();
    if (resume_request.requested()) {
        if (codex_home.authority_home) |authority_home| {
            resume_snapshot = try snapshotRollouts(allocator, authority_home);
        }
    }

    if (emit_status) {
        try status_writer.print(
            "{{\"kind\":\"session_started\",\"adapter\":\"codex\",\"selected_account\":\"{s}\",\"codex_home_path_printed\":false,\"proxy_port\":{d},\"claim_level\":\"broker_owned\",\"auth_authority\":\"mux_owned_overlay\",\"managed_config\":\"mux_owned_overlay\",\"session_authority\":\"{s}\",\"session_paths_printed\":false}}\n",
            .{ elected.id, proxy_port, codex_home.session_authority.toString() },
        );
        if (resume_request.requested()) {
            try writeResumePreflightStatus(
                status_writer,
                resume_request,
                codex_home.session_authority,
                if (resume_snapshot) |*snapshot| snapshot.count() else 0,
                if (resume_snapshot) |*snapshot| findExplicitResumeTarget(snapshot, resume_request.explicit_id) != null else null,
            );
        }
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
    try env_map.put("CODEX_HOME", codex_home.path);
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

    const auth_writeback = observeAuthWriteback(allocator, codex_home.path, source_auth_path, codex_home.auth_initial_hash) catch |e| failed: {
        try stderr.print("oauth-mux codex: auth writeback failed: {s}\n", .{@errorName(e)});
        break :failed AuthWritebackObservation{
            .ok = false,
            .error_name = @errorName(e),
        };
    };
    if (auth_writeback.source_conflict) {
        try stderr.writeAll("oauth-mux codex: auth writeback conflict; not overwriting newer account auth\n");
    }

    if (emit_status) {
        try writeAuthWritebackStatus(status_writer, auth_writeback);
        if (resume_request.requested()) {
            const observation = if (codex_home.authority_home) |authority_home|
                try observeResumeWriteback(allocator, authority_home, if (resume_snapshot) |*snapshot| snapshot else null, resume_request)
            else
                ResumeObservation{};
            try writeResumeWritebackStatus(status_writer, resume_request, codex_home.session_authority, observation);
        }
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

fn openStatusFile(path: []const u8) !std.fs.File {
    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }
    return try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = true });
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
    session_home_override: ?[]const u8,
    isolated_session_store: bool,
) !SessionCodexHome {
    const tmp_root = std.process.getEnvVarOwned(allocator, "TMPDIR") catch
        try allocator.dupe(u8, "/tmp");
    defer allocator.free(tmp_root);
    const session_authority_home = try resolveCodexSessionAuthorityHome(allocator, session_home_override, isolated_session_store);
    defer if (session_authority_home) |path| allocator.free(path);
    return try createSessionCodexHomeUnder(allocator, tmp_root, source_auth_path, proxy_port, session_authority_home);
}

fn createSessionCodexHomeUnder(
    allocator: std.mem.Allocator,
    tmp_root: []const u8,
    source_auth_path: []const u8,
    proxy_port: u16,
    session_authority_home: ?[]const u8,
) !SessionCodexHome {
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
    const auth_initial_hash = try hashFileContents(allocator, auth_dst);

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
    const session_authority = if (session_authority_home) |home| mode: {
        try bridgeCodexSessionAuthority(allocator, session_home, home);
        break :mode SessionAuthorityMode.canonical_bridge;
    } else SessionAuthorityMode.isolated;

    return .{
        .path = session_home,
        .session_authority = session_authority,
        .authority_home = if (session_authority_home) |home| try allocator.dupe(u8, home) else null,
        .auth_initial_hash = auth_initial_hash,
    };
}

fn resolveCodexSessionAuthorityHome(
    allocator: std.mem.Allocator,
    session_home_override: ?[]const u8,
    isolated_session_store: bool,
) !?[]u8 {
    if (isolated_session_store) return null;
    if (session_home_override) |path| return try expandTilde(allocator, path);
    if (std.process.getEnvVarOwned(allocator, "OMUX_CODEX_SESSION_HOME")) |path| {
        return path;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "CODEX_HOME")) |path| {
        return path;
    } else |_| {}
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".codex" });
}

fn bridgeCodexSessionAuthority(
    allocator: std.mem.Allocator,
    session_home: []const u8,
    authority_home: []const u8,
) !void {
    try ensureCodexSessionAuthority(allocator, authority_home);
    for (codex_session_authority_entries) |entry| {
        const target = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(target);
        const link = try std.fs.path.join(allocator, &.{ session_home, entry.name });
        defer allocator.free(link);
        try std.fs.symLinkAbsolute(target, link, .{ .is_directory = entry.kind == .directory });
    }
}

fn ensureCodexSessionAuthority(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
) !void {
    try std.fs.cwd().makePath(authority_home);
    for (codex_session_authority_entries) |entry| {
        const target = try std.fs.path.join(allocator, &.{ authority_home, entry.name });
        defer allocator.free(target);
        switch (entry.kind) {
            .directory => try std.fs.cwd().makePath(target),
            .file => try ensureFileExists(target),
        }
    }
}

fn ensureFileExists(path: []const u8) !void {
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch |e| switch (e) {
        error.FileNotFound => try std.fs.cwd().createFile(path, .{ .mode = 0o600, .truncate = false }),
        else => return e,
    };
    file.close();
}

fn detectResumeRequest(argv: []const []const u8) ResumeRequest {
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        if (!std.mem.eql(u8, argv[i], "resume")) continue;
        if (i + 1 >= argv.len) return .{ .mode = .chooser };
        const next = argv[i + 1];
        if (std.mem.eql(u8, next, "--last") or std.mem.eql(u8, next, "-l")) {
            return .{ .mode = .last };
        }
        if (std.mem.startsWith(u8, next, "-")) {
            return .{ .mode = .chooser };
        }
        return .{ .mode = .explicit, .explicit_id = next };
    }
    return .{};
}

fn snapshotRollouts(allocator: std.mem.Allocator, authority_home: []const u8) !RolloutSnapshot {
    var snapshot = RolloutSnapshot.init(allocator);
    errdefer snapshot.deinit();
    const sessions_dir = try std.fs.path.join(allocator, &.{ authority_home, "sessions" });
    defer allocator.free(sessions_dir);
    try snapshotRolloutsUnder(allocator, sessions_dir, &snapshot);
    return snapshot;
}

fn snapshotRolloutsUnder(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    snapshot: *RolloutSnapshot,
) !void {
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(path);
        switch (entry.kind) {
            .directory => try snapshotRolloutsUnder(allocator, path, snapshot),
            .file, .sym_link => {
                if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
                const stat = std.fs.cwd().statFile(path) catch continue;
                const owned_path = try allocator.dupe(u8, path);
                errdefer allocator.free(owned_path);
                try snapshot.entries.put(allocator, owned_path, .{
                    .size = stat.size,
                    .mtime = stat.mtime,
                });
            },
            else => {},
        }
    }
}

fn findExplicitResumeTarget(snapshot: *const RolloutSnapshot, explicit_id: ?[]const u8) ?[]const u8 {
    const id = explicit_id orelse return null;
    var it = snapshot.entries.keyIterator();
    while (it.next()) |path| {
        if (std.mem.indexOf(u8, path.*, id) != null) return path.*;
    }
    return null;
}

fn observeResumeWriteback(
    allocator: std.mem.Allocator,
    authority_home: []const u8,
    before: ?*const RolloutSnapshot,
    request: ResumeRequest,
) !ResumeObservation {
    var after = try snapshotRollouts(allocator, authority_home);
    defer after.deinit();

    var observation = ResumeObservation{
        .rollouts_before = if (before) |snapshot| snapshot.count() else 0,
        .rollouts_after = after.count(),
        .explicit_target_found_before = if (request.explicit_id != null and before != null)
            findExplicitResumeTarget(before.?, request.explicit_id) != null
        else
            null,
        .explicit_target_changed = if (request.explicit_id != null) false else null,
    };

    var it = after.entries.iterator();
    while (it.next()) |after_entry| {
        if (before) |snapshot| {
            if (snapshot.entries.get(after_entry.key_ptr.*)) |before_entry| {
                const changed = before_entry.size != after_entry.value_ptr.size or
                    before_entry.mtime != after_entry.value_ptr.mtime;
                if (changed) {
                    observation.changed_existing += 1;
                    if (request.explicit_id) |id| {
                        if (std.mem.indexOf(u8, after_entry.key_ptr.*, id) != null) {
                            observation.explicit_target_changed = true;
                        }
                    }
                }
            } else {
                observation.created += 1;
            }
        } else {
            observation.created += 1;
        }
    }

    return observation;
}

fn writeOptionalBool(writer: anytype, value: ?bool) !void {
    if (value) |v| {
        try writer.writeAll(if (v) "true" else "false");
    } else {
        try writer.writeAll("null");
    }
}

fn writeResumePreflightStatus(
    writer: anytype,
    request: ResumeRequest,
    authority: SessionAuthorityMode,
    rollouts_before: usize,
    explicit_target_found_before: ?bool,
) !void {
    try writer.print(
        "{{\"kind\":\"resume_preflight\",\"mode\":\"{s}\",\"session_authority\":\"{s}\",\"rollouts_before\":{d},\"explicit_id_provided\":{s},\"explicit_target_found_before\":",
        .{
            request.mode.toString(),
            authority.toString(),
            rollouts_before,
            if (request.explicit_id != null) "true" else "false",
        },
    );
    try writeOptionalBool(writer, explicit_target_found_before);
    try writer.writeAll(",\"session_id_printed\":false,\"path_printed\":false}\n");
}

fn writeResumeWritebackStatus(
    writer: anytype,
    request: ResumeRequest,
    authority: SessionAuthorityMode,
    observation: ResumeObservation,
) !void {
    try writer.print(
        "{{\"kind\":\"resume_writeback\",\"mode\":\"{s}\",\"session_authority\":\"{s}\",\"rollouts_before\":{d},\"rollouts_after\":{d},\"changed_existing\":{d},\"created\":{d},\"explicit_target_found_before\":",
        .{
            request.mode.toString(),
            authority.toString(),
            observation.rollouts_before,
            observation.rollouts_after,
            observation.changed_existing,
            observation.created,
        },
    );
    try writeOptionalBool(writer, observation.explicit_target_found_before);
    try writer.writeAll(",\"explicit_target_changed\":");
    try writeOptionalBool(writer, observation.explicit_target_changed);
    try writer.writeAll(",\"session_id_printed\":false,\"path_printed\":false}\n");
}

fn writeAuthWritebackStatus(
    writer: anytype,
    observation: AuthWritebackObservation,
) !void {
    try writer.print(
        "{{\"kind\":\"auth_writeback\",\"auth_authority\":\"mux_owned_overlay\",\"overlay_auth_present\":{any},\"source_auth_present\":{any},\"changed\":{any},\"written\":{any},\"source_conflict\":{any},\"ok\":{any},\"token_material_printed\":false,\"path_printed\":false",
        .{
            observation.overlay_auth_present,
            observation.source_auth_present,
            observation.changed,
            observation.written,
            observation.source_conflict,
            observation.ok,
        },
    );
    if (observation.error_name) |name| {
        try writer.print(",\"error\":\"{s}\"", .{name});
    }
    try writer.writeAll("}\n");
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

fn observeAuthWriteback(
    allocator: std.mem.Allocator,
    session_home: []const u8,
    source_auth_path: []const u8,
    initial_auth_hash: [32]u8,
) !AuthWritebackObservation {
    var observation = AuthWritebackObservation{};

    const overlay_auth_path = try std.fs.path.join(allocator, &.{ session_home, "auth.json" });
    defer allocator.free(overlay_auth_path);

    const overlay_bytes = std.fs.cwd().readFileAlloc(allocator, overlay_auth_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => return observation,
        else => return e,
    };
    defer allocator.free(overlay_bytes);
    observation.overlay_auth_present = true;

    const overlay_hash = hashBytes(overlay_bytes);
    observation.changed = !std.mem.eql(u8, overlay_hash[0..], initial_auth_hash[0..]);

    var source_bytes: ?[]u8 = null;
    defer if (source_bytes) |bytes| allocator.free(bytes);
    source_bytes = std.fs.cwd().readFileAlloc(allocator, source_auth_path, 2 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };
    observation.source_auth_present = source_bytes != null;

    if (!observation.changed) return observation;

    if (source_bytes) |bytes| {
        if (std.mem.eql(u8, overlay_bytes, bytes)) {
            return observation;
        }
        const source_hash = hashBytes(bytes);
        if (!std.mem.eql(u8, source_hash[0..], initial_auth_hash[0..])) {
            observation.source_conflict = true;
            observation.ok = false;
            return observation;
        }
    }

    if (observation.changed) {
        try writeFileReplaceBytes(allocator, source_auth_path, overlay_bytes);
        observation.written = true;
    }

    return observation;
}

fn hashFileContents(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![32]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(bytes);
    return hashBytes(bytes);
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn writeFileReplaceBytes(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
) !void {
    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ path, std.crypto.random.int(u64) });
    defer allocator.free(tmp_path);

    const is_absolute = std.fs.path.isAbsolute(path);
    const file = if (is_absolute)
        try std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 })
    else
        try std.fs.cwd().createFile(tmp_path, .{ .exclusive = true, .mode = 0o600 });
    errdefer {
        if (is_absolute) {
            std.fs.deleteFileAbsolute(tmp_path) catch {};
        } else {
            std.fs.cwd().deleteFile(tmp_path) catch {};
        }
    }

    {
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
    }

    if (is_absolute) {
        try std.fs.renameAbsolute(tmp_path, path);
    } else {
        try std.fs.cwd().rename(tmp_path, path);
    }
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
    try w.writeAll("model_provider = \"oauth_mux_openai\"\n\n");
    try w.print("[model_providers.oauth_mux_openai]\n", .{});
    try w.print("name = \"oauth-mux OpenAI proxy\"\n", .{});
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
    try std.testing.expect(opts.session_home == null);
    try std.testing.expect(!opts.isolated_session_store);
    try std.testing.expect(!opts.json_status);
    try std.testing.expect(opts.json_status_file == null);
    try std.testing.expectEqual(@as(usize, 0), opts.forward_argv.len);
}

test "expandTilde no-op when no tilde" {
    const a = try expandTilde(std.testing.allocator, "/no/tilde/here");
    defer std.testing.allocator.free(a);
    try std.testing.expectEqualStrings("/no/tilde/here", a);
}

test "openStatusFile property: nested parents are created" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const cases = [_][]const u8{
        "status.ndjson",
        "one/status.ndjson",
        "one/two/status.ndjson",
        "one/two/three/status.ndjson",
    };

    for (cases) |relative| {
        const status_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, relative });
        defer std.testing.allocator.free(status_path);
        const file = try openStatusFile(status_path);
        try file.writeAll("{\"ok\":true}\n");
        file.close();

        const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, status_path, 1024);
        defer std.testing.allocator.free(bytes);
        try std.testing.expectEqualStrings("{\"ok\":true}\n", bytes);
    }
}

test "detectResumeRequest classifies forwarded Codex resume shapes" {
    const none = detectResumeRequest(&.{ "--model", "gpt-5.5" });
    try std.testing.expectEqual(ResumeMode.none, none.mode);

    const chooser = detectResumeRequest(&.{"resume"});
    try std.testing.expectEqual(ResumeMode.chooser, chooser.mode);

    const last = detectResumeRequest(&.{ "--no-alt-screen", "resume", "--last" });
    try std.testing.expectEqual(ResumeMode.last, last.mode);

    const short_last = detectResumeRequest(&.{ "resume", "-l" });
    try std.testing.expectEqual(ResumeMode.last, short_last.mode);

    const explicit = detectResumeRequest(&.{ "resume", "019dea53-49a0-7890-9580-e88decb97af0" });
    try std.testing.expectEqual(ResumeMode.explicit, explicit.mode);
    try std.testing.expectEqualStrings("019dea53-49a0-7890-9580-e88decb97af0", explicit.explicit_id.?);
}

test "resume writeback observation reports existing rollout changes without printing paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("canonical/sessions/2026/05/06");
    {
        const rollout = try tmp.dir.createFile("canonical/sessions/2026/05/06/rollout-managed-good-session.jsonl", .{ .mode = 0o600 });
        defer rollout.close();
        try rollout.writeAll("{\"fixture\":true}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);
    const rollout_path = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions", "2026", "05", "06", "rollout-managed-good-session.jsonl" });
    defer std.testing.allocator.free(rollout_path);

    var before = try snapshotRollouts(std.testing.allocator, canonical_path);
    defer before.deinit();
    try std.testing.expectEqual(@as(usize, 1), before.count());

    {
        const rollout = try std.fs.cwd().openFile(rollout_path, .{ .mode = .write_only });
        defer rollout.close();
        try rollout.seekFromEnd(0);
        try rollout.writeAll("{\"managed\":true}\n");
    }

    const request = ResumeRequest{ .mode = .explicit, .explicit_id = "managed-good-session" };
    const observation = try observeResumeWriteback(std.testing.allocator, canonical_path, &before, request);
    try std.testing.expectEqual(@as(usize, 1), observation.rollouts_before);
    try std.testing.expectEqual(@as(usize, 1), observation.rollouts_after);
    try std.testing.expectEqual(@as(usize, 1), observation.changed_existing);
    try std.testing.expectEqual(@as(usize, 0), observation.created);
    try std.testing.expectEqual(true, observation.explicit_target_found_before.?);
    try std.testing.expectEqual(true, observation.explicit_target_changed.?);
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

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(SessionAuthorityMode.isolated, codex_home.session_authority);

    const session_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(session_auth);
    const copied_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_auth, 1024);
    defer std.testing.allocator.free(copied_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"fixture\"}}\n", copied_auth);

    const session_install = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "installation_id" });
    defer std.testing.allocator.free(session_install);
    const copied_install = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_install, 1024);
    defer std.testing.allocator.free(copied_install);
    try std.testing.expectEqualStrings("install-fixture\n", copied_install);

    const session_config = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "config.toml" });
    defer std.testing.allocator.free(session_config);
    const generated_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, session_config, 4096);
    defer std.testing.allocator.free(generated_config);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "127.0.0.1:45678") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "model_provider = \"oauth_mux_openai\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.oauth_mux_openai]") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated_config, "[model_providers.openai]") == null);

    const source_config = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "config.toml" });
    defer std.testing.allocator.free(source_config);
    const original_config = try std.fs.cwd().readFileAlloc(std.testing.allocator, source_config, 1024);
    defer std.testing.allocator.free(original_config);
    try std.testing.expectEqualStrings("preexisting = true\n", original_config);
}

test "observeAuthWriteback imports changed overlay auth into mux source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"old\",\"refresh_token\":\"old-rt\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null);
    defer codex_home.deinit(std.testing.allocator);

    const overlay_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(overlay_auth);
    {
        const auth = try std.fs.cwd().createFile(overlay_auth, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"new\",\"refresh_token\":\"new-rt\"}}\n");
    }

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(observation.changed);
    try std.testing.expect(observation.written);
    try std.testing.expect(!observation.source_conflict);
    try std.testing.expect(observation.ok);
    try std.testing.expect(observation.error_name == null);

    const source_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, auth_path, 1024);
    defer std.testing.allocator.free(source_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"new\",\"refresh_token\":\"new-rt\"}}\n", source_auth);
}

test "observeAuthWriteback leaves unchanged overlay auth alone" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"same\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null);
    defer codex_home.deinit(std.testing.allocator);

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(!observation.changed);
    try std.testing.expect(!observation.written);
    try std.testing.expect(!observation.source_conflict);
    try std.testing.expect(observation.ok);
    try std.testing.expect(observation.error_name == null);
}

test "observeAuthWriteback refuses to overwrite independently changed mux source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"old\",\"refresh_token\":\"old-rt\"}}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, null);
    defer codex_home.deinit(std.testing.allocator);

    const overlay_auth = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "auth.json" });
    defer std.testing.allocator.free(overlay_auth);
    {
        const auth = try std.fs.cwd().createFile(overlay_auth, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"overlay-new\",\"refresh_token\":\"overlay-rt\"}}\n");
    }
    {
        const auth = try std.fs.cwd().createFile(auth_path, .{ .mode = 0o600, .truncate = true });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"source-new\",\"refresh_token\":\"source-rt\"}}\n");
    }

    const observation = try observeAuthWriteback(std.testing.allocator, codex_home.path, auth_path, codex_home.auth_initial_hash);
    try std.testing.expect(observation.overlay_auth_present);
    try std.testing.expect(observation.source_auth_present);
    try std.testing.expect(observation.changed);
    try std.testing.expect(!observation.written);
    try std.testing.expect(observation.source_conflict);
    try std.testing.expect(!observation.ok);

    const source_auth = try std.fs.cwd().readFileAlloc(std.testing.allocator, auth_path, 1024);
    defer std.testing.allocator.free(source_auth);
    try std.testing.expectEqualStrings("{\"tokens\":{\"access_token\":\"source-new\",\"refresh_token\":\"source-rt\"}}\n", source_auth);
}

test "createSessionCodexHomeUnder bridges canonical session authority without copying" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("account");
    {
        const auth = try tmp.dir.createFile("account/auth.json", .{ .mode = 0o600 });
        defer auth.close();
        try auth.writeAll("{\"tokens\":{\"access_token\":\"fixture\"}}\n");
    }
    try tmp.dir.makePath("canonical/sessions/2026/05/05");
    try tmp.dir.makePath("canonical/shell_snapshots");
    {
        const session = try tmp.dir.createFile("canonical/sessions/2026/05/05/session.jsonl", .{ .mode = 0o600 });
        defer session.close();
        try session.writeAll("{\"fixture\":true}\n");
    }

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "account", "auth.json" });
    defer std.testing.allocator.free(auth_path);
    const canonical_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "canonical" });
    defer std.testing.allocator.free(canonical_path);

    const codex_home = try createSessionCodexHomeUnder(std.testing.allocator, root_path, auth_path, 45678, canonical_path);
    defer codex_home.deinit(std.testing.allocator);
    try std.testing.expectEqual(SessionAuthorityMode.canonical_bridge, codex_home.session_authority);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sessions_link = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions" });
    defer std.testing.allocator.free(sessions_link);
    const sessions_target = try std.fs.readLinkAbsolute(sessions_link, &link_buf);
    const expected_sessions_target = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions" });
    defer std.testing.allocator.free(expected_sessions_target);
    try std.testing.expectEqualStrings(expected_sessions_target, sessions_target);

    const bridged_session = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions", "2026", "05", "05", "session.jsonl" });
    defer std.testing.allocator.free(bridged_session);
    const session_bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, bridged_session, 1024);
    defer std.testing.allocator.free(session_bytes);
    try std.testing.expectEqualStrings("{\"fixture\":true}\n", session_bytes);

    const overlay_marker = try std.fs.path.join(std.testing.allocator, &.{ codex_home.path, "sessions", "managed-write.jsonl" });
    defer std.testing.allocator.free(overlay_marker);
    {
        const marker = try std.fs.cwd().createFile(overlay_marker, .{ .mode = 0o600 });
        defer marker.close();
        try marker.writeAll("via overlay\n");
    }
    const canonical_marker = try std.fs.path.join(std.testing.allocator, &.{ canonical_path, "sessions", "managed-write.jsonl" });
    defer std.testing.allocator.free(canonical_marker);
    const marker_bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, canonical_marker, 1024);
    defer std.testing.allocator.free(marker_bytes);
    try std.testing.expectEqualStrings("via overlay\n", marker_bytes);

    try std.fs.cwd().deleteTree(codex_home.path);
    const marker_after_overlay_delete = try std.fs.cwd().readFileAlloc(std.testing.allocator, canonical_marker, 1024);
    defer std.testing.allocator.free(marker_after_overlay_delete);
    try std.testing.expectEqualStrings("via overlay\n", marker_after_overlay_delete);
}
