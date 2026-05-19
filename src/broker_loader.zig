//! Bridge between the existing oauth-mux Config and the broker
//! AccountPool + CredentialMaterializer. Lives at the same level as
//! main.zig so it can import both `config.zig` and `broker/mod.zig`
//! without leaking either side across module boundaries.
//!
//! Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.2 / §2.3.
//! Adapter consumer: src/broker/account_pool.zig + Server.materializer.

const std = @import("std");
const config_mod = @import("config.zig");
const broker = @import("broker/mod.zig");
const broker_types = @import("broker/types.zig");
const health_mod = @import("health.zig");
const oauth = @import("oauth.zig");
const paths = @import("paths.zig");
const trace = @import("trace.zig");
const types = @import("types.zig");

/// Populate `pool` with one entry per `<provider>:<account>` defined in
/// the active Config. Liveness is `.unknown` and availability is
/// `.available`; Phase 2 wires real health correlation.
///
/// `profile_name` (optional) restricts visible accounts to those listed
/// in the named profile. Profile entries may be `provider:account` or
/// `provider:account#capability`; we match the `provider:account`
/// prefix. Out-of-profile accounts stay in the pool but are marked
/// non-selectable so callers can introspect why they're hidden.
pub fn populatePool(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
) !void {
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |prov_entry| {
        const provider_name = prov_entry.key_ptr.*;
        const provider_cfg = prov_entry.value_ptr.*;
        var acc_it = provider_cfg.accounts.map.iterator();
        while (acc_it.next()) |acc_entry| {
            const account_name = acc_entry.key_ptr.*;
            const id_buf = try std.fmt.allocPrint(
                pool.allocator,
                "{s}:{s}",
                .{ provider_name, account_name },
            );
            defer pool.allocator.free(id_buf);
            try pool.add(.{
                .id = id_buf,
                .selectable = true,
                .liveness = .unknown,
                .availability = .available,
            });
        }
    }

    if (profile_name) |pname| {
        if (cfg.profiles.map.get(pname)) |profile| {
            // Build a slice-of-slices into the original profile entries,
            // each trimmed to the `provider:account` prefix. No
            // allocation; restrictToAllowList only reads.
            var allow_buf = std.ArrayListUnmanaged([]const u8){};
            defer allow_buf.deinit(pool.allocator);
            for (profile.providers) |entry| {
                const head = if (std.mem.indexOfScalar(u8, entry, '#')) |idx| entry[0..idx] else entry;
                try allow_buf.append(pool.allocator, head);
            }
            pool.restrictToAllowList(allow_buf.items);
        }
    }
}

/// Populate and then apply the same durable route/account health gate used by
/// `broker-session-plan`: account-level dead/quota/rate state dominates, then
/// the profile route's capability health is considered. Missing health leaves
/// the route non-selectable so managed adapter launch cannot silently bypass
/// route repair evidence.
pub fn populatePoolFromRouteHealth(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    store: *health_mod.HealthStore,
) !void {
    try populatePoolFromRouteHealthScoped(pool, cfg, profile_name, null, store);
}

pub fn populatePoolFromRouteHealthScoped(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    capability_name: ?[]const u8,
    store: *health_mod.HealthStore,
) !void {
    try populatePool(pool, cfg, profile_name);
    applyRouteHealth(pool, cfg, profile_name, capability_name, store);
}

pub const CodexAuthRepairSummary = struct {
    attempted: usize = 0,
    refreshed: usize = 0,
    failed: usize = 0,
    skipped: usize = 0,
};

/// Repair Codex auth-dead durable health when the account store still has a
/// refresh token. Codex's native child can refresh only the account it starts
/// under; proxy fallback accounts need this preflight or an expired access
/// token is misclassified as a permanently dead route.
pub fn repairRefreshableCodexAuthFailures(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    store: *health_mod.HealthStore,
) CodexAuthRepairSummary {
    var summary = CodexAuthRepairSummary{};
    const provider_cfg = cfg.providers.map.get("codex") orelse return summary;

    var it = provider_cfg.accounts.map.iterator();
    while (it.next()) |entry| {
        const account_name = entry.key_ptr.*;
        const account_cfg = entry.value_ptr.*;

        // The unmanaged default store is refreshed by the Codex child itself.
        // oauth-mux should preflight-refresh only route-local account stores.
        if (account_cfg.config_dir == null) {
            summary.skipped += 1;
            continue;
        }

        const key = health_mod.accountKey("codex", account_name);
        const health = store.accounts.get(key.slice()) orelse {
            summary.skipped += 1;
            continue;
        };
        if (!authHealthCanBeRefreshRepaired(health)) {
            summary.skipped += 1;
            continue;
        }

        summary.attempted += 1;
        refreshCodexAccountAuthFile(allocator, cfg, "codex", account_name, account_cfg) catch {
            summary.failed += 1;
            continue;
        };

        markAuthRefreshRepaired(store, key.slice());
        summary.refreshed += 1;
    }

    if (summary.refreshed != 0) store.persist();
    return summary;
}

fn applyRouteHealth(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    capability_name: ?[]const u8,
    store: *health_mod.HealthStore,
) void {
    for (pool.accounts.items) |*entry| {
        if (!entry.selectable) continue;
        const route_health = routeHealthForPoolAccount(pool.allocator, cfg, profile_name, capability_name, entry.id, store) orelse {
            entry.selectable = false;
            entry.liveness = .unknown;
            entry.availability = .unknown;
            continue;
        };
        applyHealthToPoolEntry(entry, route_health);
    }
}

fn routeHealthForPoolAccount(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    requested_capability: ?[]const u8,
    account_id: []const u8,
    store: *health_mod.HealthStore,
) ?health_mod.AccountHealth {
    const now = std.time.timestamp();
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return null;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];
    const account_key = health_mod.accountKey(provider, account);
    if (store.accounts.get(account_key.slice())) |account_health| {
        const effective = health_mod.effectiveHealthForRouteSelection(account_health, now);
        tracePoolHealthNormalization(allocator, provider, account, null, "account", account_health.liveness, effective.liveness);
        if (accountLivenessBlocksRoute(effective.liveness)) {
            if (authMaterialRepairHealth(allocator, cfg, provider, account, account_health)) |repaired| return repaired;
            return effective;
        }
    }

    if (profile_name) |name| {
        if (cfg.profiles.map.get(name)) |profile| {
            for (profile.providers) |profile_entry| {
                const hash = std.mem.indexOfScalar(u8, profile_entry, '#') orelse continue;
                const head = profile_entry[0..hash];
                if (!std.mem.eql(u8, head, account_id)) continue;
                const capability = profile_entry[hash + 1 ..];
                if (requested_capability) |want| {
                    if (!std.mem.eql(u8, capability, want)) continue;
                }
                const capability_key = health_mod.capabilityKey(provider, account, capability);
                if (store.accounts.get(capability_key.slice())) |capability_health| {
                    const effective = health_mod.effectiveHealthForRouteSelection(capability_health, now);
                    tracePoolHealthNormalization(allocator, provider, account, capability, "capability", capability_health.liveness, effective.liveness);
                    if (accountLivenessBlocksRoute(effective.liveness)) {
                        if (authMaterialRepairHealth(allocator, cfg, provider, account, capability_health)) |repaired| return repaired;
                    }
                    return effective;
                }
            }
        }
    }

    if (requested_capability) |capability| {
        const capability_key = health_mod.capabilityKey(provider, account, capability);
        if (store.accounts.get(capability_key.slice())) |capability_health| {
            const effective = health_mod.effectiveHealthForRouteSelection(capability_health, now);
            tracePoolHealthNormalization(allocator, provider, account, capability, "capability", capability_health.liveness, effective.liveness);
            if (accountLivenessBlocksRoute(effective.liveness)) {
                if (authMaterialRepairHealth(allocator, cfg, provider, account, capability_health)) |repaired| return repaired;
            }
            return effective;
        }
    }

    if (store.accounts.get(account_key.slice())) |account_health| {
        const effective = health_mod.effectiveHealthForRouteSelection(account_health, now);
        tracePoolHealthNormalization(allocator, provider, account, null, "account", account_health.liveness, effective.liveness);
        if (accountLivenessBlocksRoute(effective.liveness)) {
            if (authMaterialRepairHealth(allocator, cfg, provider, account, account_health)) |repaired| return repaired;
        }
        return effective;
    }
    return null;
}

fn tracePoolHealthNormalization(
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

fn accountLivenessBlocksRoute(liveness: types.CredentialLiveness) bool {
    return switch (liveness) {
        .dead, .degraded => true,
        .live => |live| switch (live.availability) {
            .available => false,
            .rate_limited, .quota_exhausted, .cooldown => true,
        },
    };
}

fn authMaterialRepairHealth(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    health: health_mod.AccountHealth,
) ?health_mod.AccountHealth {
    const observed_at = health.last_probe_observed_at orelse return null;
    const auth_mtime_ns = accountAuthMaterialMtimeNs(allocator, cfg, provider, account) orelse return null;
    const observed_ns = @as(i128, observed_at) * std.time.ns_per_s;
    if (auth_mtime_ns <= observed_ns) return null;

    return .{
        .liveness = .{ .live = .{ .availability = .available } },
        .last_probe_source = .credential_validation,
        .last_probe_observed_at = @intCast(@divFloor(auth_mtime_ns, std.time.ns_per_s)),
        .last_probe_hint_class = .none,
        .last_probe_decision = .use_this,
    };
}

fn accountAuthMaterialMtimeNs(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
) ?i128 {
    const provider_cfg = cfg.providers.map.get(provider) orelse return null;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse return null;

    const auth_path = accountAuthMaterialPath(allocator, acct_cfg) catch return null;
    defer allocator.free(auth_path);

    const file = if (std.fs.path.isAbsolute(auth_path))
        std.fs.openFileAbsolute(auth_path, .{}) catch return null
    else
        std.fs.cwd().openFile(auth_path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    return stat.mtime;
}

fn accountAuthMaterialPath(
    allocator: std.mem.Allocator,
    acct_cfg: config_mod.AccountConfig,
) ![]const u8 {
    if (std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        if (acct_cfg.secret.path) |path| return try paths.expandTilde(allocator, path);
    }
    if (acct_cfg.config_dir) |dir_raw| {
        const dir = try paths.expandTilde(allocator, dir_raw);
        defer allocator.free(dir);
        return try std.fs.path.join(allocator, &.{ dir, "auth.json" });
    }
    return error.FileNotFound;
}

fn authHealthCanBeRefreshRepaired(health: health_mod.AccountHealth) bool {
    if (health.last_probe_hint_class) |hint| {
        if (hint == .auth_dead) return true;
    }
    return switch (health.liveness) {
        .dead => true,
        .live, .degraded => false,
    };
}

fn markAuthRefreshRepaired(store: *health_mod.HealthStore, key: []const u8) void {
    const health = store.getOrCreate(key) catch return;
    health.liveness = .{ .live = .{ .availability = .available } };
    health.last_http_status = null;
    health.last_probe_source = .credential_validation;
    health.last_probe_observed_at = std.time.timestamp();
    health.last_probe_retry_after_s = null;
    health.last_probe_hint_class = .none;
    health.last_probe_decision = .use_this;
    health.consecutive_failures = 0;
    health.quota_exhausted_until = null;
    health.rate_limited_until = null;
}

fn refreshCodexAccountAuthFile(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    acct_cfg: config_mod.AccountConfig,
) !void {
    const path = try accountAuthMaterialPath(allocator, acct_cfg);
    defer allocator.free(path);

    const bytes = try readFileAlloc(allocator, path);
    defer allocator.free(bytes);

    var material = try parseCodexAuthRefreshMaterial(allocator, bytes);
    defer material.deinit(allocator);
    const refresh_token = material.refresh_token orelse return error.NoRefreshToken;

    const def = config_mod.resolveProviderDefinition(cfg, provider);
    const token_url = def.auth.token_endpoint orelse oauth.refreshUrl(.codex) orelse return error.NoTokenEndpoint;
    const result = try oauth.refreshToken(allocator, token_url, refresh_token, def.auth.client_id);
    defer allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| allocator.free(rt);

    const refreshed = try buildRefreshedCodexAuthJson(allocator, material, result);
    defer allocator.free(refreshed);
    try writeFileReplace(path, refreshed, allocator);

    _ = account;
}

const CodexAuthRefreshState = enum {
    not_needed,
    needed,
    unavailable,
};

fn refreshCodexAuthState(allocator: std.mem.Allocator, bytes: []const u8) CodexAuthRefreshState {
    var material = parseCodexAuthRefreshMaterial(allocator, bytes) catch return .not_needed;
    defer material.deinit(allocator);
    const exp = jwtExpiresAt(allocator, material.access_token) catch return .not_needed;
    if (exp > std.time.timestamp() + 300) return .not_needed;
    return if (material.refresh_token != null) .needed else .unavailable;
}

fn refreshCodexAuthBeforeMaterialize(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    acct_cfg: config_mod.AccountConfig,
    bytes: []const u8,
) broker_types.BrokerError!bool {
    if (!std.mem.eql(u8, provider, "codex")) return false;
    if (acct_cfg.config_dir == null) return false;
    switch (refreshCodexAuthState(allocator, bytes)) {
        .not_needed => return false,
        .unavailable => return broker_types.BrokerError.SecretUnavailable,
        .needed => {},
    }
    refreshCodexAccountAuthFile(allocator, cfg, provider, account, acct_cfg) catch
        return broker_types.BrokerError.SecretUnavailable;
    return true;
}

fn codexAuthShouldRefresh(allocator: std.mem.Allocator, bytes: []const u8) bool {
    return refreshCodexAuthState(allocator, bytes) == .needed;
}

const CodexAuthRefreshMaterial = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    account_id: []const u8,
    id_token: ?[]const u8 = null,
    auth_mode: ?[]const u8 = null,

    fn deinit(self: *CodexAuthRefreshMaterial, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |value| allocator.free(value);
        allocator.free(self.account_id);
        if (self.id_token) |value| allocator.free(value);
        if (self.auth_mode) |value| allocator.free(value);
    }
};

fn parseCodexAuthRefreshMaterial(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) broker_types.BrokerError!CodexAuthRefreshMaterial {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return broker_types.BrokerError.ParseError;
    defer parsed.deinit();

    if (parsed.value != .object) return broker_types.BrokerError.InvalidShape;
    const tokens_v = parsed.value.object.get("tokens") orelse return broker_types.BrokerError.InvalidShape;
    if (tokens_v != .object) return broker_types.BrokerError.InvalidShape;

    const access_v = tokens_v.object.get("access_token") orelse return broker_types.BrokerError.InvalidShape;
    if (access_v != .string) return broker_types.BrokerError.InvalidShape;
    const account_v = tokens_v.object.get("account_id") orelse return broker_types.BrokerError.InvalidShape;
    if (account_v != .string) return broker_types.BrokerError.InvalidShape;

    const access_token = allocator.dupe(u8, access_v.string) catch return broker_types.BrokerError.OutOfMemory;
    const account_id = allocator.dupe(u8, account_v.string) catch {
        allocator.free(access_token);
        return broker_types.BrokerError.OutOfMemory;
    };
    var material = CodexAuthRefreshMaterial{
        .access_token = access_token,
        .account_id = account_id,
    };
    errdefer material.deinit(allocator);

    if (tokens_v.object.get("refresh_token")) |refresh_v| {
        if (refresh_v == .string) {
            material.refresh_token = allocator.dupe(u8, refresh_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    if (tokens_v.object.get("id_token")) |id_v| {
        if (id_v == .string) {
            material.id_token = allocator.dupe(u8, id_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    if (parsed.value.object.get("auth_mode")) |mode_v| {
        if (mode_v == .string) {
            material.auth_mode = allocator.dupe(u8, mode_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    return material;
}

fn buildRefreshedCodexAuthJson(
    allocator: std.mem.Allocator,
    material: CodexAuthRefreshMaterial,
    result: oauth.RefreshResult,
) ![]const u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);

    try w.writeAll("{\"OPENAI_API_KEY\":null,\"tokens\":{");
    var first = true;
    if (material.id_token) |id_token| {
        try writeJsonField(w, &first, "id_token", id_token);
    }
    try writeJsonField(w, &first, "access_token", result.access_token);
    try writeJsonField(w, &first, "refresh_token", result.refresh_token orelse material.refresh_token.?);
    try writeJsonField(w, &first, "account_id", material.account_id);
    try w.writeAll("},\"auth_mode\":");
    try std.json.stringify(material.auth_mode orelse "Chatgpt", .{}, w);
    try w.writeAll("}\n");
    return try out.toOwnedSlice(allocator);
}

fn writeJsonField(writer: anytype, first: *bool, name: []const u8, value: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try std.json.stringify(name, .{}, writer);
    try writer.writeByte(':');
    try std.json.stringify(value, .{}, writer);
}

fn jwtExpiresAt(allocator: std.mem.Allocator, jwt: []const u8) !i64 {
    const dot1 = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.BadJwt;
    const after_header = jwt[dot1 + 1 ..];
    const dot2 = std.mem.indexOfScalar(u8, after_header, '.') orelse return error.BadJwt;
    const payload_b64 = after_header[0..dot2];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try decoder.calcSizeForSlice(payload_b64);
    const payload_buf = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_buf);
    try decoder.decode(payload_buf, payload_b64);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_buf, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.BadJwt;
    const exp_v = parsed.value.object.get("exp") orelse return error.BadJwt;
    if (exp_v != .integer) return error.BadJwt;
    return exp_v.integer;
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1 << 20);
}

fn writeFileReplace(path: []const u8, bytes: []const u8, allocator: std.mem.Allocator) !void {
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

fn applyHealthToPoolEntry(entry: *broker.account_pool_mod.AccountSummary, health: health_mod.AccountHealth) void {
    entry.selectable = types.selectable(health.liveness, .ready);
    switch (health.liveness) {
        .dead => {
            entry.liveness = .dead;
            entry.availability = .unknown;
        },
        .degraded => {
            entry.liveness = .degraded;
            entry.availability = .unknown;
        },
        .live => |live| {
            entry.liveness = .live;
            entry.availability = switch (live.availability) {
                .available => .available,
                .rate_limited => .rate_limited,
                .quota_exhausted => .quota_exhausted,
                .cooldown => .cooldown,
            };
            switch (live.availability) {
                .rate_limited => |rl| entry.next_eligible_at = rl.limited_at + @as(i64, rl.retry_after_s),
                .quota_exhausted => |quota| entry.next_eligible_at = quota.window_resets_at,
                .cooldown => |cooldown| entry.next_eligible_at = cooldown.until,
                .available => entry.next_eligible_at = null,
            }
        },
    }
}

// ── credential materializer ──────────────────────────────────────────

/// Holds a borrowed reference to a loaded Config so the broker's
/// CredentialMaterializer vtable can find an account's configured
/// secret store. Lifetime: must outlive the broker server.
pub const ChatgptMaterializerCtx = struct {
    cfg: *const config_mod.Config,

    /// Cast to/from the broker's opaque ctx pointer.
    pub fn vtable(self: *ChatgptMaterializerCtx) broker_types.CredentialMaterializer {
        return .{
            .ctx = @as(*anyopaque, @ptrCast(self)),
            .materialize_chatgpt = chatgptThunk,
        };
    }
};

fn chatgptThunk(
    raw: *anyopaque,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const self: *ChatgptMaterializerCtx = @ptrCast(@alignCast(raw));
    return materializeChatgpt(self.cfg.*, allocator, account_id);
}

/// Resolve a `provider:account` to a chatgpt_auth_tokens tuple by
/// reading the account's configured secret store. Phase 1 supports the
/// `backend: "file"` shape, which is what oauth-mux uses for managed
/// codex accounts under ~/.config/oauth-mux/codex/<account>/auth.json.
pub fn materializeChatgpt(
    cfg: config_mod.Config,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse
        return broker_types.BrokerError.InvalidParams;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse
        return broker_types.BrokerError.AccountNotFound;
    if (!std.mem.eql(u8, provider, "codex") and !std.mem.eql(u8, provider_cfg.kind, "codex")) {
        // chatgpt_auth_tokens is a Codex app-server credential shape. Refuse
        // providers that are neither the built-in Codex key nor Codex-kind
        // before touching their account stores.
        return broker_types.BrokerError.UnsupportedShape;
    }
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse
        return broker_types.BrokerError.AccountNotFound;

    if (!std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        // Phase 1: only file-backend is wired. Other backends
        // (keychain, sops/age, command, env, stdin) need their own
        // secret/*.zig invocations, follow-up.
        return broker_types.BrokerError.SecretUnavailable;
    }
    const path_raw = acct_cfg.secret.path orelse
        return broker_types.BrokerError.SecretUnavailable;

    // Tilde-expand a leading ~ for ergonomics; otherwise use the path
    // as-is.
    const path = if (std.mem.startsWith(u8, path_raw, "~/")) blk: {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch
            return broker_types.BrokerError.SecretUnavailable;
        defer allocator.free(home);
        break :blk std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path_raw[1..] }) catch
            return broker_types.BrokerError.OutOfMemory;
    } else allocator.dupe(u8, path_raw) catch
        return broker_types.BrokerError.OutOfMemory;
    defer allocator.free(path);

    var bytes = readFileAlloc(allocator, path) catch
        return broker_types.BrokerError.SecretUnavailable;
    defer allocator.free(bytes);

    if (try refreshCodexAuthBeforeMaterialize(allocator, cfg, provider, account, acct_cfg, bytes)) {
        const refreshed_bytes = readFileAlloc(allocator, path) catch
            return broker_types.BrokerError.SecretUnavailable;
        allocator.free(bytes);
        bytes = refreshed_bytes;
    }

    return parseAuthJson(allocator, bytes);
}

test "materializeChatgpt rejects non-Codex providers before reading secrets" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "work": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "file",
        \\            "path": "/tmp/omux-this-file-must-not-be-read"
        \\          }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "claude": { "providers": ["claude:work#auth-status"] }
        \\  }
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.UnsupportedShape,
        materializeChatgpt(parsed.value, std.testing.allocator, "claude:work"),
    );
}

/// Parse a codex-shaped auth.json into ChatgptAuthTokens. Schema
/// reference: codex-rs/login/src/auth/storage.rs (AuthDotJson).
fn parseAuthJson(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return broker_types.BrokerError.ParseError;
    defer parsed.deinit();

    if (parsed.value != .object) return broker_types.BrokerError.InvalidShape;
    const tokens_v = parsed.value.object.get("tokens") orelse return broker_types.BrokerError.InvalidShape;
    if (tokens_v != .object) return broker_types.BrokerError.InvalidShape;

    const access_v = tokens_v.object.get("access_token") orelse return broker_types.BrokerError.InvalidShape;
    if (access_v != .string) return broker_types.BrokerError.InvalidShape;
    const account_v = tokens_v.object.get("account_id") orelse return broker_types.BrokerError.InvalidShape;
    if (account_v != .string) return broker_types.BrokerError.InvalidShape;

    const access_token = allocator.dupe(u8, access_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(access_token);
    const acct_id = allocator.dupe(u8, account_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(acct_id);

    // Best-effort: extract chatgpt_plan_type and chatgpt_account_is_fedramp
    // from the id_token JWT's "https://api.openai.com/auth" claim. JWT
    // body is the second base64url-encoded segment; we decode it and
    // look up the nested field. Failure is non-fatal: plan_type stays
    // null, fedramp stays false.
    var plan_type: ?[]const u8 = null;
    var fedramp = false;
    if (tokens_v.object.get("id_token")) |id_v| {
        if (id_v == .string) {
            extractIdTokenClaims(allocator, id_v.string, &plan_type, &fedramp) catch {};
        }
    }

    return broker_types.ChatgptAuthTokens{
        .access_token = access_token,
        .account_id = acct_id,
        .plan_type = plan_type,
        .fedramp = fedramp,
    };
}

fn extractIdTokenClaims(
    allocator: std.mem.Allocator,
    jwt: []const u8,
    out_plan_type: *?[]const u8,
    out_fedramp: *bool,
) !void {
    // JWT shape: header.payload.signature, all base64url-no-padding.
    const dot1 = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.BadJwt;
    const after_header = jwt[dot1 + 1 ..];
    const dot2 = std.mem.indexOfScalar(u8, after_header, '.') orelse return error.BadJwt;
    const payload_b64 = after_header[0..dot2];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try decoder.calcSizeForSlice(payload_b64);
    const payload_buf = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_buf);
    try decoder.decode(payload_buf, payload_b64);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_buf, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return;

    const auth_claim = parsed.value.object.get("https://api.openai.com/auth") orelse return;
    if (auth_claim != .object) return;

    if (auth_claim.object.get("chatgpt_plan_type")) |pt| {
        if (pt == .string) {
            out_plan_type.* = try allocator.dupe(u8, pt.string);
        }
    }
    if (auth_claim.object.get("chatgpt_account_is_fedramp")) |f| {
        if (f == .bool) out_fedramp.* = f.bool;
    }
}

test "parseAuthJson minimal shape" {
    const bytes =
        \\{
        \\  "OPENAI_API_KEY": null,
        \\  "tokens": {
        \\    "id_token": "ignored.eyJ9.x",
        \\    "access_token": "AT-1234",
        \\    "refresh_token": "RT-5678",
        \\    "account_id": "acc-abc"
        \\  },
        \\  "last_refresh": "now",
        \\  "auth_mode": "Chatgpt"
        \\}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("AT-1234", tokens.access_token);
    try std.testing.expectEqualStrings("acc-abc", tokens.account_id);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
}

test "parseAuthJson rejects missing tokens key" {
    const bytes = "{\"OPENAI_API_KEY\":null,\"auth_mode\":\"Chatgpt\"}";
    const result = parseAuthJson(std.testing.allocator, bytes);
    try std.testing.expectError(broker_types.BrokerError.InvalidShape, result);
}

test "parseAuthJson tolerates malformed id_token (silent fallback)" {
    // Single dot instead of two — JWT extractor returns BadJwt, but we
    // swallow it and keep plan_type/fedramp at defaults.
    const bytes =
        \\{"tokens":{"access_token":"AT","account_id":"AID","id_token":"only-one-dot"}}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
    try std.testing.expectEqualStrings("AT", tokens.access_token);
}

test "parseAuthJson with plan_type from id_token" {
    // id_token payload: {"https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_is_fedramp":true}}
    // base64url-no-pad encoded:
    const id_token = "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s";
    const bytes = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"tokens":{{"access_token":"a","account_id":"b","id_token":"{s}"}}}}
    , .{id_token});
    defer std.testing.allocator.free(bytes);

    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pro", tokens.plan_type.?);
    try std.testing.expect(tokens.fedramp);
}

test "codex auth refresh detection uses access token exp" {
    const expired_auth =
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","refresh_token":"rt","account_id":"acc"}}
    ;
    try std.testing.expect(codexAuthShouldRefresh(std.testing.allocator, expired_auth));
    try std.testing.expectEqual(
        CodexAuthRefreshState.unavailable,
        refreshCodexAuthState(std.testing.allocator,
            \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","account_id":"acc"}}
        ),
    );

    const future_exp = std.time.timestamp() + 3600;
    var payload_buf: [64]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_buf, "{{\"exp\":{d}}}", .{future_exp});
    var encoded_buf: [128]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, payload);
    const fresh_auth = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"tokens":{{"access_token":"h.{s}.s","refresh_token":"rt","account_id":"acc"}}}}
    , .{encoded});
    defer std.testing.allocator.free(fresh_auth);
    try std.testing.expect(!codexAuthShouldRefresh(std.testing.allocator, fresh_auth));
}

test "materializeChatgpt refuses expired codex token when refresh is unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","account_id":"acc"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const config_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(config_dir);

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ config_dir, auth_path },
    );
    defer std.testing.allocator.free(cfg_json);

    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.SecretUnavailable,
        materializeChatgpt(parsed.value, std.testing.allocator, "codex:max-1"),
    );
}

test "materializeChatgpt refuses stale codex token when refresh fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","refresh_token":"rt","account_id":"acc"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const config_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(config_dir);

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex-test": {{
        \\      "name": "codex-test",
        \\      "auth": {{
        \\        "token_endpoint": "://invalid",
        \\        "client_id": "client"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex-test",
        \\      "accounts": {{
        \\        "max-1": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ config_dir, auth_path },
    );
    defer std.testing.allocator.free(cfg_json);

    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.SecretUnavailable,
        materializeChatgpt(parsed.value, std.testing.allocator, "codex:max-1"),
    );
}

test "buildRefreshedCodexAuthJson preserves account id and retained refresh token" {
    const material = CodexAuthRefreshMaterial{
        .access_token = "old-access",
        .refresh_token = "old-refresh",
        .account_id = "acc-1",
        .id_token = "id-token",
        .auth_mode = "Chatgpt",
    };
    const refreshed = try buildRefreshedCodexAuthJson(std.testing.allocator, material, .{
        .access_token = "new-access",
        .refresh_token = null,
        .expires_in = 3600,
    });
    defer std.testing.allocator.free(refreshed);

    var parsed = try parseAuthJson(std.testing.allocator, refreshed);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("new-access", parsed.access_token);
    try std.testing.expectEqualStrings("acc-1", parsed.account_id);

    var raw = try parseCodexAuthRefreshMaterial(std.testing.allocator, refreshed);
    defer raw.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("old-refresh", raw.refresh_token.?);
    try std.testing.expectEqualStrings("id-token", raw.id_token.?);
}

// ── pool population (above) ──────────────────────────────────────────

test "populatePool from JSON config" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, null);

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);
}

test "populatePool with profile filter narrows selectable" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, "codex-max");

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expect(std.mem.eql(u8, elected.id, "codex:max-1") or std.mem.eql(u8, elected.id, "codex:max-2"));

    var claude_present_and_blocked = false;
    for (pool.accounts.items) |a| {
        if (std.mem.eql(u8, a.id, "claude:personal")) {
            try std.testing.expect(!a.selectable);
            claude_present_and_blocked = true;
        }
    }
    try std.testing.expect(claude_present_and_blocked);
}

test "populatePoolFromRouteHealth mirrors broker-session-plan route health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } },
        \\        "max-3": { "priority": 10, "secret": { "backend": "file", "path": "/tmp/c" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max", "codex:max-3#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);
    _ = try store.getOrCreate("codex:max-2#codex-max");
    // max-3 has no route health and must not be silently admitted.

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-2", elected.id);

    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.quota_exhausted, entry.availability);
        }
        if (std.mem.eql(u8, entry.id, "codex:max-3")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.unknown, entry.availability);
        }
    }
}

test "populatePoolFromRouteHealth lets expired provider degradation yield to capability health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .degraded = .{
        .reason = .provider_degraded,
        .since = now - 120,
        .retry_at = now - 1,
    } };
    account_health.last_probe_hint_class = .provider_degraded;
    account_health.last_probe_decision = .try_next_provider;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

test "populatePoolFromRouteHealth lets expired account rate limit yield to capability health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .live = .{ .availability = .{ .rate_limited = .{
        .retry_after_s = 60,
        .limited_at = now - 120,
        .window = .unknown,
    } } } };
    account_health.last_probe_hint_class = .rate_limit;
    account_health.last_probe_decision = .wait_and_retry;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

test "populatePoolFromRouteHealth keeps auth-dead account health global" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .dead = .{
        .reason = .token_revoked,
        .since = now - 120,
    } };
    account_health.last_probe_hint_class = .auth_dead;
    account_health.last_probe_decision = .try_next_account;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect(null, null, &.{}));
    try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, pool.accounts.items[0].liveness);
}

test "populatePoolFromRouteHealth treats newer auth material as route repair evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"AT","account_id":"AID"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "default": {{ "priority": 10, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const health = try store.getOrCreate("codex:default");
    health.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .window_resets_at = 1_800_000_000,
        .exhausted_at = 1,
    } } } };
    health.last_probe_observed_at = 1;
    health.last_probe_source = .broker_run_live;
    health.last_probe_hint_class = .quota_exhausted;
    health.last_probe_decision = .try_next_account;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, null, &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:default", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}
