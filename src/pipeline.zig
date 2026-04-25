const std = @import("std");
const types = @import("types.zig");
const config_mod = @import("config.zig");
const secret = @import("secret.zig");
const provider = @import("provider.zig");
const health_mod = @import("health.zig");
const shell_mod = @import("shell.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const oauth = @import("oauth.zig");

pub const Context = struct {
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile_name: ?[]const u8 = null,
    provider_name: ?[]const u8 = null,
    provider_kind: ?types.ProviderKind = null,
    account_name: ?[]const u8 = null,
    token: ?provider.TokenFields = null,
    health: *health_mod.HealthStore,
    env_pairs: std.ArrayList([2][]const u8),
    allocated_values: std.ArrayList([]const u8),
    target_argv: []const []const u8 = &.{},
    shell: types.ShellKind = .posix,

    pub fn init(allocator: std.mem.Allocator, cfg: config_mod.Config, store: *health_mod.HealthStore) Context {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .health = store,
            .env_pairs = std.ArrayList([2][]const u8).init(allocator),
            .allocated_values = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Context) void {
        if (self.token) |tok| {
            self.allocator.free(tok.access_token);
            if (tok.refresh_token) |rt| self.allocator.free(rt);
        }
        for (self.allocated_values.items) |v| self.allocator.free(v);
        self.allocated_values.deinit();
        self.env_pairs.deinit();
    }

    fn addEnvOwned(self: *Context, key: []const u8, owned_value: []const u8) !void {
        self.allocated_values.append(owned_value) catch {
            self.allocator.free(owned_value);
            return error.OutOfMemory;
        };
        self.env_pairs.append(.{ key, owned_value }) catch return error.OutOfMemory;
    }
};

pub const PipelineError = types.PipelineError;

/// Full pipeline for `exec` mode: select account, read secret, validate, inject, exec.
pub fn runExec(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectAccount(ctx);
    try readSecret(ctx);
    try validateToken(ctx);
    try injectEnv(ctx);
}

/// Full pipeline for `env` mode: select account, read secret, validate, inject (no exec).
pub fn runEnv(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectAccount(ctx);
    try readSecret(ctx);
    try validateToken(ctx);
    try injectEnv(ctx);
}

fn resolveProvider(ctx: *Context) PipelineError!void {
    // If provider already set (from CLI flag), use it
    if (ctx.provider_name != null) {
        if (ctx.provider_name) |name| {
            ctx.provider_kind = types.ProviderKind.fromString(name);
        }
        return;
    }

    // Try auto-detecting from target command
    if (ctx.target_argv.len > 0) {
        if (provider.detectProvider(ctx.target_argv)) |kind| {
            ctx.provider_kind = kind;
            ctx.provider_name = kind.displayName();
            log.debug("pipeline: auto-detected provider {s}", .{kind.displayName()});
            return;
        }
    }

    // Use profile's first provider
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            if (profile.providers.len > 0) {
                const spec = profile.providers[0];
                if (splitProviderAccount(spec)) |pa| {
                    ctx.provider_name = pa.provider;
                    ctx.account_name = pa.account;
                    ctx.provider_kind = types.ProviderKind.fromString(pa.provider);
                    return;
                }
            }
        }
    }

    // Fall back to config default
    if (ctx.cfg.defaults.provider) |def| {
        ctx.provider_name = def;
        ctx.provider_kind = types.ProviderKind.fromString(def);
        return;
    }

    return error.ProviderNotFound;
}

fn selectAccount(ctx: *Context) PipelineError!void {
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;

    // If profile specifies provider:account pairs, use health-based selection
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            for (profile.providers) |spec| {
                if (splitProviderAccount(spec)) |pa| {
                    if (!std.mem.eql(u8, pa.provider, prov_name)) continue;
                    const key = accountKey(pa.provider, pa.account);
                    if (ctx.health.isAvailable(key.slice())) {
                        ctx.account_name = pa.account;
                        ctx.provider_name = pa.provider;
                        ctx.provider_kind = types.ProviderKind.fromString(pa.provider);
                        log.debug("pipeline: selected {s}:{s}", .{ pa.provider, pa.account });
                        return;
                    }
                }
            }
        }
    }

    // If account already set (from provider:account spec), keep it
    if (ctx.account_name != null) return;

    // Pick highest-priority account from the provider
    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    var best_name: ?[]const u8 = null;
    var best_priority: i32 = std.math.minInt(i32);

    var it = prov_cfg.accounts.map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const acct = entry.value_ptr.*;
        const key = accountKey(prov_name, name);
        if (!ctx.health.isAvailable(key.slice())) continue;
        if (acct.priority > best_priority) {
            best_priority = acct.priority;
            best_name = name;
        }
    }

    ctx.account_name = best_name orelse return error.AllAccountsExhausted;
    log.debug("pipeline: selected {s}:{s} (priority {d})", .{ prov_name, best_name.?, best_priority });
}

fn readSecret(ctx: *Context) PipelineError!void {
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;

    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;

    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch return error.ConfigParseError;

    const raw = secret.read(backend, ctx.allocator) catch |e| {
        log.err("secret: {s}:{s}: {s}", .{ prov_name, acct_name, @errorName(e) });
        const key = accountKey(prov_name, acct_name);
        ctx.health.recordFailure(key.slice(), .auth_failure);
        return error.SecretReadFailed;
    };
    defer ctx.allocator.free(raw);

    const kind = ctx.provider_kind orelse types.ProviderKind.fromString(prov_name) orelse return error.ProviderNotFound;
    ctx.token = provider.parseToken(kind, raw, ctx.allocator) catch {
        log.err("token: parse failed for {s}:{s}", .{ prov_name, acct_name });
        return error.TokenParseFailed;
    };
}

fn validateToken(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const kind = ctx.provider_kind orelse return error.ProviderNotFound;

    // API keys don't expire
    if (tok.token_type == .api_key) {
        const key = accountKey(prov, acct);
        ctx.health.recordSuccess(key.slice());
        return;
    }

    // Check expiry (with 30s skew to refresh before actual expiry)
    if (tok.expires_at) |exp| {
        const now = std.time.timestamp();
        if (now >= exp - 30) {
            if (tok.refresh_token) |rt| {
                log.info("token: expired for {s}:{s}, attempting refresh", .{ prov, acct });
                try attemptRefresh(ctx, kind, rt);
            } else {
                return error.TokenExpired;
            }
        }
    }

    const key = accountKey(prov, acct);
    ctx.health.recordSuccess(key.slice());
}

fn attemptRefresh(ctx: *Context, kind: types.ProviderKind, rt: []const u8) PipelineError!void {
    const url = oauth.refreshUrl(kind) orelse {
        log.warn("token: no refresh URL for {s}", .{kind.displayName()});
        return error.TokenRefreshFailed;
    };

    const result = oauth.refreshToken(ctx.allocator, url, rt, null) catch |e| {
        log.err("token: refresh failed: {s}", .{@errorName(e)});
        const prov = ctx.provider_name orelse return error.ProviderNotFound;
        const acct = ctx.account_name orelse return error.AccountNotFound;
        const key = accountKey(prov, acct);
        ctx.health.recordFailure(key.slice(), .auth_failure);
        return error.TokenRefreshFailed;
    };

    // Update the token in context
    if (ctx.token) |old| {
        ctx.allocator.free(old.access_token);
        if (old.refresh_token) |old_rt| ctx.allocator.free(old_rt);
    }
    ctx.token = .{
        .access_token = result.access_token,
        .refresh_token = result.refresh_token,
        .expires_at = if (result.expires_in) |ei| std.time.timestamp() + ei else null,
    };

    log.info("token: refreshed successfully", .{});
}

fn injectEnv(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const kind = ctx.provider_kind orelse return error.ProviderNotFound;
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;

    // Check for persistent config_dir on the account
    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;

    if (acct_cfg.config_dir) |dir| {
        // Persistent config dir mode
        if (kind.configDirEnv()) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            ctx.addEnvOwned(env_var, expanded) catch return error.OutOfMemory;
        }
    } else if (kind.configDirEnv()) |env_var| {
        // Tmpdir mode: write credential file to temp dir
        const cred_content = provider.buildCredentialFile(kind, tok, ctx.allocator) catch return error.OutOfMemory;
        defer ctx.allocator.free(cred_content);

        const tmp_dir = createTmpCredDir(ctx.allocator, kind, cred_content) catch return error.OutOfMemory;
        ctx.addEnvOwned(env_var, tmp_dir) catch return error.OutOfMemory;
    }

    // For providers without config dir isolation, inject token directly as env var
    switch (kind) {
        .github => {
            ctx.env_pairs.append(.{ "GH_TOKEN", tok.access_token }) catch return error.OutOfMemory;
        },
        .vercel => {
            ctx.env_pairs.append(.{ "VERCEL_TOKEN", tok.access_token }) catch return error.OutOfMemory;
        },
        .mcp => {
            ctx.env_pairs.append(.{ "MCP_TOKEN", tok.access_token }) catch return error.OutOfMemory;
        },
        else => {},
    }

    // Breadcrumb env vars
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROVIDER", prov_name }) catch return error.OutOfMemory;
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_ACCOUNT", acct_name }) catch return error.OutOfMemory;
    if (ctx.profile_name) |pn| {
        ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROFILE", pn }) catch return error.OutOfMemory;
    }
}

fn createTmpCredDir(allocator: std.mem.Allocator, kind: types.ProviderKind, content: []const u8) ![]const u8 {
    const fname = provider.credentialFileName(kind);
    const tmp_base = std.posix.getenv("TMPDIR") orelse "/tmp";
    const dir_path = std.fmt.allocPrint(allocator, "{s}/oauth-mux-{d}", .{ tmp_base, std.time.timestamp() }) catch return error.OutOfMemory;

    std.fs.makeDirAbsolute(dir_path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.OutOfMemory,
    };

    const file_path = std.fs.path.join(allocator, &.{ dir_path, fname }) catch return error.OutOfMemory;
    defer allocator.free(file_path);

    const file = std.fs.createFileAbsolute(file_path, .{ .mode = 0o600 }) catch return error.OutOfMemory;
    defer file.close();
    file.writeAll(content) catch return error.OutOfMemory;

    return dir_path;
}

const ProviderAccount = struct {
    provider: []const u8,
    account: []const u8,
};

fn splitProviderAccount(spec: []const u8) ?ProviderAccount {
    if (std.mem.indexOf(u8, spec, ":")) |idx| {
        return .{
            .provider = spec[0..idx],
            .account = spec[idx + 1 ..],
        };
    }
    return null;
}

const KeyBuf = struct {
    buf: [128]u8 = undefined,
    len: usize = 0,

    fn slice(self: *const KeyBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

fn accountKey(prov: []const u8, acct: []const u8) KeyBuf {
    var kb = KeyBuf{};
    for (prov) |c| {
        if (kb.len >= 127) break;
        kb.buf[kb.len] = c;
        kb.len += 1;
    }
    if (kb.len < 127) {
        kb.buf[kb.len] = ':';
        kb.len += 1;
    }
    for (acct) |c| {
        if (kb.len >= 127) break;
        kb.buf[kb.len] = c;
        kb.len += 1;
    }
    return kb;
}

test "splitProviderAccount" {
    const pa = splitProviderAccount("claude:work").?;
    try std.testing.expectEqualStrings("claude", pa.provider);
    try std.testing.expectEqualStrings("work", pa.account);

    try std.testing.expect(splitProviderAccount("nocolon") == null);
}
