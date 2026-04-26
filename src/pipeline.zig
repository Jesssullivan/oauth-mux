const std = @import("std");
const types = @import("types.zig");
const config_mod = @import("config.zig");
const secret = @import("secret.zig");
const provider = @import("provider.zig");
const provider_schema = @import("provider_schema.zig");
const health_mod = @import("health.zig");
const shell_mod = @import("shell.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const oauth = @import("oauth.zig");
const probe = @import("probe.zig");

pub const Context = struct {
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile_name: ?[]const u8 = null,
    provider_name: ?[]const u8 = null,
    provider_kind: ?types.ProviderKind = null,
    account_name: ?[]const u8 = null,
    capability_name: ?[]const u8 = null,
    token: ?provider.TokenFields = null,
    health: *health_mod.HealthStore,
    env_pairs: std.ArrayList([2][]const u8),
    allocated_values: std.ArrayList([]const u8),
    target_argv: []const []const u8 = &.{},
    shell: types.ShellKind = .posix,
    last_probe_executed: bool = false,
    last_probe_status: ?u16 = null,
    last_probe_decision: ?types.MuxDecision = null,

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

/// Full pipeline with retry-across-accounts.
/// For each candidate account: read → validate → if ok, inject.
/// On recoverable failure: mark account, try next.
/// On exhaustion of all accounts: return AllAccountsExhausted.
pub fn runExec(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectWithFallback(ctx);
    try injectEnv(ctx);
}

pub fn runEnv(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectWithFallback(ctx);
    try injectEnv(ctx);
}

pub fn runProbe(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectWithFallback(ctx);
}

/// The retry loop: try each candidate account in priority order.
/// On failure, record the typed failure and move to the next candidate.
fn selectWithFallback(ctx: *Context) PipelineError!void {
    const candidates = gatherCandidates(ctx);
    if (candidates.len == 0) return error.AllAccountsExhausted;

    var last_err: PipelineError = error.AllAccountsExhausted;
    var skipped_providers: [32][]const u8 = undefined;
    var skipped_provider_count: usize = 0;

    for (candidates) |candidate| {
        if (providerWasSkipped(skipped_providers[0..skipped_provider_count], candidate.provider)) {
            log.debug("pipeline: skip {s}:{s} (provider already skipped)", .{ candidate.provider, candidate.account });
            continue;
        }

        const key = health_mod.accountKey(candidate.provider, candidate.account);
        const decision = ctx.health.muxDecisionFor(candidate.provider, candidate.account, candidate.capability);

        switch (decision) {
            .try_next_account => {
                log.debug("pipeline: skip {s}:{s} (health: try_next)", .{ candidate.provider, candidate.account });
                continue;
            },
            .try_next_provider => {
                if (skipped_provider_count < skipped_providers.len) {
                    skipped_providers[skipped_provider_count] = candidate.provider;
                    skipped_provider_count += 1;
                }
                log.debug("pipeline: skip {s}:{s} (health: try_next_provider)", .{ candidate.provider, candidate.account });
                continue;
            },
            .give_up => {
                log.debug("pipeline: skip {s}:{s} (health: give_up)", .{ candidate.provider, candidate.account });
                continue;
            },
            .wait_and_retry => {
                // Could wait, but for now try next account
                log.debug("pipeline: skip {s}:{s} (health: rate limited)", .{ candidate.provider, candidate.account });
                continue;
            },
            .use_this => {},
        }

        // Set context for this attempt
        ctx.provider_name = candidate.provider;
        ctx.account_name = candidate.account;
        ctx.capability_name = candidate.capability;
        ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, candidate.provider);

        // Try the read → validate path
        readSecret(ctx) catch |e| {
            ctx.health.recordFailure(key.slice(), .auth_failure);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        validateToken(ctx) catch |e| {
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        const post_probe_decision = probeCapability(ctx) catch |e| {
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };
        switch (post_probe_decision) {
            .use_this => {},
            .try_next_provider => {
                if (skipped_provider_count < skipped_providers.len) {
                    skipped_providers[skipped_provider_count] = candidate.provider;
                    skipped_provider_count += 1;
                }
                freeCurrentToken(ctx);
                continue;
            },
            .try_next_account, .wait_and_retry, .give_up => {
                freeCurrentToken(ctx);
                continue;
            },
        }

        // Success — this account works
        log.info("pipeline: using {s}:{s}", .{ candidate.provider, candidate.account });
        return;
    }

    return last_err;
}

fn providerWasSkipped(skipped_providers: []const []const u8, provider_name: []const u8) bool {
    for (skipped_providers) |skipped| {
        if (std.mem.eql(u8, skipped, provider_name)) return true;
    }
    return false;
}

fn freeCurrentToken(ctx: *Context) void {
    if (ctx.token) |tok| {
        ctx.allocator.free(tok.access_token);
        if (tok.refresh_token) |rt| ctx.allocator.free(rt);
        ctx.token = null;
    }
}

const Candidate = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
    priority: i32,
};

fn gatherCandidates(ctx: *Context) []const Candidate {
    // Static buffer — up to 32 candidates
    const S = struct {
        var buf: [32]Candidate = undefined;
    };
    var count: usize = 0;

    // If profile specified, use its provider:account list
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            for (profile.providers) |spec| {
                if (splitProviderAccount(spec)) |pa| {
                    // If provider filter set, skip non-matching
                    if (ctx.provider_name) |filter| {
                        if (!std.mem.eql(u8, pa.provider, filter)) continue;
                    }
                    if (ctx.account_name) |account_filter| {
                        if (!std.mem.eql(u8, pa.account, account_filter)) continue;
                    }
                    if (count < S.buf.len) {
                        const prov_cfg = ctx.cfg.providers.map.get(pa.provider) orelse continue;
                        const acct_cfg = prov_cfg.accounts.map.get(pa.account) orelse continue;
                        S.buf[count] = .{
                            .provider = pa.provider,
                            .account = pa.account,
                            .capability = pa.capability orelse ctx.capability_name,
                            .priority = acct_cfg.priority,
                        };
                        count += 1;
                    }
                }
            }
        }
    }

    // If no profile or profile yielded nothing, gather from provider config
    if (count == 0) {
        const prov_name = ctx.provider_name orelse ctx.cfg.defaults.provider orelse return S.buf[0..0];
        const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return S.buf[0..0];

        if (ctx.account_name) |account_filter| {
            if (prov_cfg.accounts.map.get(account_filter)) |acct_cfg| {
                if (count < S.buf.len) {
                    S.buf[count] = .{
                        .provider = prov_name,
                        .account = account_filter,
                        .capability = ctx.capability_name,
                        .priority = acct_cfg.priority,
                    };
                    count += 1;
                }
            }
        } else {
            var it = prov_cfg.accounts.map.iterator();
            while (it.next()) |entry| {
                if (count < S.buf.len) {
                    S.buf[count] = .{
                        .provider = prov_name,
                        .account = entry.key_ptr.*,
                        .capability = ctx.capability_name,
                        .priority = entry.value_ptr.priority,
                    };
                    count += 1;
                }
            }
        }
    }

    // Sort by priority descending (insertion sort, small N)
    var i: usize = 1;
    while (i < count) : (i += 1) {
        var j = i;
        while (j > 0 and S.buf[j].priority > S.buf[j - 1].priority) {
            const tmp = S.buf[j];
            S.buf[j] = S.buf[j - 1];
            S.buf[j - 1] = tmp;
            j -= 1;
        }
    }

    return S.buf[0..count];
}

fn resolveProvider(ctx: *Context) PipelineError!void {
    // If provider already set (from CLI flag), use it
    if (ctx.provider_name != null) {
        if (ctx.provider_name) |name| {
            ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, name);
        }
        return;
    }

    // Try auto-detecting from target command
    if (ctx.target_argv.len > 0) {
        if (provider.detectProvider(ctx.target_argv)) |kind| {
            ctx.provider_kind = kind;
            ctx.provider_name = @tagName(kind);
            log.debug("pipeline: auto-detected provider {s}", .{kind.displayName()});
            return;
        }
    }

    // A profile supplies an ordered mux lane. Leave provider_name unset here so
    // gatherCandidates can fan out across every provider listed in the profile.
    // Explicit --provider and target-command detection are handled above and
    // still act as provider filters.
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            if (profile.providers.len > 0) return;
        }
    }

    // Fall back to config default
    if (ctx.cfg.defaults.provider) |def| {
        ctx.provider_name = def;
        ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, def);
        return;
    }

    return error.ProviderNotFound;
}

fn readSecret(ctx: *Context) PipelineError!void {
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;

    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;

    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch return error.ConfigParseError;

    const raw = secret.read(backend, ctx.allocator) catch |e| {
        log.err("secret: {s}:{s}: {s}", .{ prov_name, acct_name, @errorName(e) });
        const key = health_mod.accountKey(prov_name, acct_name);
        ctx.health.recordFailure(key.slice(), .auth_failure);
        return error.SecretReadFailed;
    };
    defer ctx.allocator.free(raw);

    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov_name);
    const generic = provider_schema.parseTokenGeneric(def, raw, ctx.allocator) catch {
        log.debug("token: schema parse failed for {s}:{s}, trying legacy parser", .{ prov_name, acct_name });
        const kind = ctx.provider_kind orelse return error.ProviderNotFound;
        ctx.token = provider.parseToken(kind, raw, ctx.allocator) catch {
            log.err("token: parse failed for {s}:{s}", .{ prov_name, acct_name });
            return error.TokenParseFailed;
        };
        return;
    };
    ctx.token = .{
        .access_token = generic.access_token,
        .refresh_token = generic.refresh_token,
        .token_type = generic.token_type,
        .expires_at = generic.expires_at,
    };
}

fn validateToken(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;

    // API keys don't expire
    if (tok.token_type == .api_key) {
        const key = health_mod.accountKey(prov, acct);
        ctx.health.recordSuccess(key.slice());
        ctx.health.recordProbeEvidence(key.slice(), .credential_validation, null, .none, .use_this);
        return;
    }

    // Check expiry (with 30s skew to refresh before actual expiry)
    if (tok.expires_at) |exp| {
        const now = std.time.timestamp();
        if (now >= exp - 30) {
            if (tok.refresh_token) |rt| {
                log.info("token: expired for {s}:{s}, attempting refresh", .{ prov, acct });
                try attemptRefresh(ctx, rt);
            } else {
                return error.TokenExpired;
            }
        }
    }

    const key = health_mod.accountKey(prov, acct);
    ctx.health.recordSuccess(key.slice());
    ctx.health.recordProbeEvidence(key.slice(), .credential_validation, null, .none, .use_this);
}

fn probeCapability(ctx: *Context) PipelineError!types.MuxDecision {
    const capability = ctx.capability_name orelse return .use_this;
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const plan = provider_schema.probePlanForCapability(def, capability) orelse return .use_this;

    var probe_env = buildProbeEnv(ctx, prov, acct, def, plan) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ConfigValidationError,
    };
    defer probe_env.deinit();

    const result = probe.execute(ctx.allocator, plan, tok.access_token, probe_env.pairs.items) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedMethod, error.UnsupportedTransport => return error.ConfigValidationError,
        error.NetworkError => return error.NetworkError,
    };
    defer result.deinit(ctx.allocator);

    const classification = probe.classifyResult(ctx.allocator, def, plan, result);
    ctx.last_probe_executed = true;
    ctx.last_probe_status = result.status;
    var evidence_key: health_mod.KeyBuf = undefined;
    switch (classification) {
        .dead => {
            const key = health_mod.accountKey(prov, acct);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification);
            evidence_key = key;
        },
        else => {
            const key = health_mod.capabilityKey(prov, acct, capability);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification);
            evidence_key = key;
        },
    }

    const decision = ctx.health.muxDecisionFor(prov, acct, capability);
    ctx.last_probe_decision = decision;
    ctx.health.recordProbeEvidence(
        evidence_key.slice(),
        .capability_probe,
        result.retry_after_s,
        health_mod.hintClassFromClassification(classification),
        decision,
    );
    return decision;
}

const ProbeEnv = struct {
    allocator: std.mem.Allocator,
    pairs: std.ArrayList([2][]const u8),
    allocated_values: std.ArrayList([]const u8),

    fn init(allocator: std.mem.Allocator) ProbeEnv {
        return .{
            .allocator = allocator,
            .pairs = std.ArrayList([2][]const u8).init(allocator),
            .allocated_values = std.ArrayList([]const u8).init(allocator),
        };
    }

    fn deinit(self: *ProbeEnv) void {
        for (self.allocated_values.items) |value| self.allocator.free(value);
        self.allocated_values.deinit();
        self.pairs.deinit();
    }

    fn addOwned(self: *ProbeEnv, key: []const u8, owned_value: []const u8) !void {
        self.allocated_values.append(owned_value) catch {
            self.allocator.free(owned_value);
            return error.OutOfMemory;
        };
        self.pairs.append(.{ key, owned_value }) catch return error.OutOfMemory;
    }

    fn addBorrowed(self: *ProbeEnv, key: []const u8, value: []const u8) !void {
        self.pairs.append(.{ key, value }) catch return error.OutOfMemory;
    }
};

fn buildProbeEnv(
    ctx: *Context,
    prov: []const u8,
    acct: []const u8,
    def: provider_schema.ProviderDefinition,
    plan: provider_schema.ProbePlan,
) !ProbeEnv {
    var env = ProbeEnv.init(ctx.allocator);
    errdefer env.deinit();

    if (plan.transport != .command) return env;

    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return error.AccountNotFound;
    const config_dir_env = providerConfigDirEnv(prov_cfg, def, ctx.provider_kind);

    if (acct_cfg.config_dir) |dir| {
        if (config_dir_env) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            try env.addOwned(env_var, expanded);
        }
    }

    try env.addBorrowed("OMUX_ACTIVE_PROVIDER", prov);
    try env.addBorrowed("OMUX_ACTIVE_ACCOUNT", acct);
    try env.addBorrowed("OMUX_ACTIVE_CAPABILITY", plan.capability);
    if (ctx.profile_name) |profile| try env.addBorrowed("OMUX_ACTIVE_PROFILE", profile);

    return env;
}

fn attemptRefresh(ctx: *Context, rt: []const u8) PipelineError!void {
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const url = def.auth.token_endpoint orelse fallbackRefreshUrl(ctx) orelse {
        log.warn("token: no refresh URL for {s}", .{prov});
        return error.TokenRefreshFailed;
    };

    const result = oauth.refreshToken(ctx.allocator, url, rt, def.auth.client_id) catch |e| {
        log.err("token: refresh failed: {s}", .{@errorName(e)});
        const acct = ctx.account_name orelse return error.AccountNotFound;
        const key = health_mod.accountKey(prov, acct);
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

fn fallbackRefreshUrl(ctx: *Context) ?[]const u8 {
    const kind = ctx.provider_kind orelse return null;
    return oauth.refreshUrl(kind);
}

fn injectEnv(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov_name);

    // Check for persistent config_dir on the account
    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;
    const config_dir_env = providerConfigDirEnv(prov_cfg, def, ctx.provider_kind);

    if (acct_cfg.config_dir) |dir| {
        // Persistent config dir mode
        if (config_dir_env) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            ctx.addEnvOwned(env_var, expanded) catch return error.OutOfMemory;
        }
    } else if (config_dir_env) |env_var| {
        // Tmpdir mode: write credential file to temp dir
        const schema_token = schemaTokenFromProviderToken(tok);
        const cred_content = provider_schema.buildCredentialGeneric(def, schema_token, ctx.allocator) catch return error.OutOfMemory;
        defer ctx.allocator.free(cred_content);

        const tmp_dir = createTmpCredDir(ctx.allocator, def.injection.credential_filename, cred_content) catch return error.OutOfMemory;
        ctx.addEnvOwned(env_var, tmp_dir) catch return error.OutOfMemory;
    }

    if (def.injection.direct_env) |direct_env| {
        for (direct_env) |mapping| {
            if (tokenFieldValue(tok, mapping[1])) |value| {
                ctx.env_pairs.append(.{ mapping[0], value }) catch return error.OutOfMemory;
            }
        }
    }

    // Breadcrumb env vars
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROVIDER", prov_name }) catch return error.OutOfMemory;
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_ACCOUNT", acct_name }) catch return error.OutOfMemory;
    if (ctx.profile_name) |pn| {
        ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROFILE", pn }) catch return error.OutOfMemory;
    }
    if (ctx.capability_name) |capability| {
        ctx.env_pairs.append(.{ "OMUX_ACTIVE_CAPABILITY", capability }) catch return error.OutOfMemory;
    }
}

fn providerConfigDirEnv(
    prov_cfg: config_mod.ProviderConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) ?[]const u8 {
    if (prov_cfg.config_dir_env) |env_var| return env_var;
    if (def.injection.config_dir_env) |env_var| return env_var;
    if (kind) |k| return k.configDirEnv();
    return null;
}

fn schemaTokenFromProviderToken(tok: provider.TokenFields) provider_schema.TokenFields {
    return .{
        .access_token = tok.access_token,
        .refresh_token = tok.refresh_token,
        .token_type = tok.token_type,
        .expires_at = tok.expires_at,
    };
}

fn tokenFieldValue(tok: provider.TokenFields, field: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, field, "access_token")) return tok.access_token;
    if (std.mem.eql(u8, field, "refresh_token")) return tok.refresh_token;
    return null;
}

fn createTmpCredDir(allocator: std.mem.Allocator, fname: []const u8, content: []const u8) ![]const u8 {
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
    capability: ?[]const u8 = null,
};

fn splitProviderAccount(spec: []const u8) ?ProviderAccount {
    const parsed = health_mod.parseHealthKey(spec) orelse return null;
    return .{
        .provider = parsed.provider,
        .account = parsed.account,
        .capability = parsed.capability,
    };
}

test "splitProviderAccount" {
    const pa = splitProviderAccount("claude:work").?;
    try std.testing.expectEqualStrings("claude", pa.provider);
    try std.testing.expectEqualStrings("work", pa.account);
    try std.testing.expect(pa.capability == null);

    const route = splitProviderAccount("codex:max-1#codex-max").?;
    try std.testing.expectEqualStrings("codex", route.provider);
    try std.testing.expectEqualStrings("max-1", route.account);
    try std.testing.expectEqualStrings("codex-max", route.capability.?);

    try std.testing.expect(splitProviderAccount("nocolon") == null);
}

test "runEnv uses configured provider definition" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("toy-auth.json", .{});
    defer auth_file.close();
    try auth_file.writeAll(
        \\{"tokens":{"access":"toy-at","refresh":"toy-rt"}}
    );

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "toy-auth.json");
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access",
        \\        "refresh_token_path": "tokens.refresh"
        \\      }},
        \\      "injection": {{
        \\        "direct_env": [["TOY_TOKEN", "access_token"]]
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("toy", ctx.provider_name.?);
    try std.testing.expect(ctx.provider_kind == null);
    try expectEnvPair(ctx.env_pairs.items, "TOY_TOKEN", "toy-at");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_PROVIDER", "toy");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "default");
}

test "runEnv honors capability route health from profile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access_token",
        \\        "refresh_token_path": "tokens.refresh_token"
        \\      }},
        \\      "injection": {{ "direct_env": [["TOY_TOKEN", "access_token"]] }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "mux": {{ "providers": ["codex:max-1#codex-route", "codex:max-2#codex-route"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-route", 429, 7200);

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "mux";

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("codex", ctx.provider_name.?);
    try std.testing.expectEqualStrings("max-2", ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-route", ctx.capability_name.?);
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-route");
}

test "runEnv routes around degraded capability without poisoning account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "max": {{ "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }},
        \\    "mini": {{ "providers": ["codex:max-1#codex-mini", "codex:max-2#codex-mini"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const degraded_route = health_mod.capabilityKey("codex", "max-1", "codex-max");
    store.recordHttpClassification(
        degraded_route.slice(),
        403,
        .{ .degraded = .tier_insufficient },
    );

    var max_ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer max_ctx.deinit();
    max_ctx.profile_name = "max";

    try runEnv(&max_ctx);

    try std.testing.expectEqualStrings("max-2", max_ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-max", max_ctx.capability_name.?);
    try expectEnvPair(max_ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
    try expectEnvPair(max_ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-max");

    var mini_ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer mini_ctx.deinit();
    mini_ctx.profile_name = "mini";

    try runEnv(&mini_ctx);

    try std.testing.expectEqualStrings("max-1", mini_ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-mini", mini_ctx.capability_name.?);
    try expectEnvPair(mini_ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-1");
    try expectEnvPair(mini_ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-mini");
}

test "runProbe honors explicit account filter without a configured probe plan" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "max-2";
    ctx.capability_name = "codex-route";

    try runProbe(&ctx);

    try std.testing.expectEqualStrings("codex", ctx.provider_name.?);
    try std.testing.expectEqualStrings("max-2", ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-route", ctx.capability_name.?);
    try std.testing.expect(!ctx.last_probe_executed);
    try std.testing.expect(store.accounts.get("codex:max-2") != null);
    try std.testing.expect(store.accounts.get("codex:max-1") == null);
}

test "runEnv skips remaining accounts for degraded provider" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const toy_file = try tmp.dir.createFile("toy.json", .{});
    defer toy_file.close();
    try toy_file.writeAll(
        \\{"tokens":{"access":"toy-at"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);
    const toy_path = try tmp.dir.realpathAlloc(std.testing.allocator, "toy.json");
    defer std.testing.allocator.free(toy_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{ "access_token_path": "tokens.access" }},
        \\      "injection": {{ "direct_env": [["TOY_TOKEN", "access_token"]] }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }},
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "priority": 10, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "mux": {{ "providers": ["codex:max-1", "codex:max-2", "toy:default"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path, toy_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordHttpClassification("codex:max-1", 500, .provider_degraded);

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "mux";

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("toy", ctx.provider_name.?);
    try std.testing.expectEqualStrings("default", ctx.account_name.?);
    try expectEnvPair(ctx.env_pairs.items, "TOY_TOKEN", "toy-at");
    try expectMissingEnvValue(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
}

fn expectEnvPair(pairs: []const [2][]const u8, key: []const u8, value: []const u8) !void {
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair[0], key)) {
            try std.testing.expectEqualStrings(value, pair[1]);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

fn expectMissingEnvValue(pairs: []const [2][]const u8, key: []const u8, value: []const u8) !void {
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair[0], key) and std.mem.eql(u8, pair[1], value)) {
            return error.TestUnexpectedResult;
        }
    }
}
