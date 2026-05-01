const std = @import("std");
const builtin = @import("builtin");
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
const env = @import("env.zig");
const repair_state = @import("repair_state.zig");
const runtime = @import("runtime.zig");

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
    probe_only: bool = false,
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
    ctx.probe_only = true;
    defer ctx.probe_only = false;
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

        if (ctx.probe_only and probePlanUsesNoCredential(ctx)) {
            const post_probe_decision = probeCapability(ctx) catch |e| {
                recordCandidateFailure(ctx, key.slice(), e);
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

            log.info("pipeline: using {s}:{s}", .{ candidate.provider, candidate.account });
            return;
        }

        // Try the read → validate path
        readSecret(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        validateToken(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        const post_probe_decision = probeCapability(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
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
    }
    ctx.token = null;
}

fn probePlanUsesNoCredential(ctx: *Context) bool {
    const capability = ctx.capability_name orelse return false;
    const prov = ctx.provider_name orelse return false;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const plan = provider_schema.probePlanForCapability(def, capability) orelse return false;
    return plan.auth == .none;
}

fn recordCandidateFailure(ctx: *Context, key: []const u8, err: PipelineError) void {
    switch (err) {
        error.SecretReadFailed,
        error.SecretDecryptFailed,
        error.TokenParseFailed,
        error.TokenExpired,
        error.TokenRefreshFailed,
        error.TokenRevoked,
        => ctx.health.recordFailure(key, .auth_failure),
        error.RateLimited => ctx.health.recordFailure(key, .rate_limited),
        error.NetworkError => ctx.health.recordFailure(key, .timeout),
        error.ConfigNotFound,
        error.ConfigParseError,
        error.ConfigValidationError,
        error.RuntimeNotReady,
        => {},
        else => ctx.health.recordFailure(key, .error_response),
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
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const plan = provider_schema.probePlanForCapability(def, capability) orelse return .use_this;
    const access_token = if (ctx.token) |tok|
        tok.access_token
    else switch (plan.auth) {
        .none => "",
        else => return error.TokenParseFailed,
    };

    if (plan.transport == .command) {
        const readiness = runtime.routeReadiness(ctx.allocator, ctx.cfg, .{
            .provider = prov,
            .account = acct,
            .capability = capability,
        }, def) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RuntimeNotReady,
        };
        if (!readiness.isReady()) return error.RuntimeNotReady;
    }

    var probe_env = buildProbeEnv(ctx, prov, acct, def, plan) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ConfigValidationError,
    };
    defer probe_env.deinit();

    const result = probe.execute(ctx.allocator, plan, access_token, probe_env.pairs.items) catch |e| switch (e) {
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
        result.retry_after_s orelse health_mod.retryAfterFromClassification(classification),
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
    var probe_env = ProbeEnv.init(ctx.allocator);
    errdefer probe_env.deinit();

    if (plan.transport != .command) return probe_env;

    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return error.AccountNotFound;
    const config_dir_env = providerConfigDirEnv(prov_cfg, def, ctx.provider_kind);

    if (acct_cfg.config_dir) |dir| {
        if (config_dir_env) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            try probe_env.addOwned(env_var, expanded);
        }
    }

    try probe_env.addBorrowed("OMUX_ACTIVE_PROVIDER", prov);
    try probe_env.addBorrowed("OMUX_ACTIVE_ACCOUNT", acct);
    try probe_env.addBorrowed("OMUX_ACTIVE_CAPABILITY", plan.capability);
    if (ctx.profile_name) |profile| try probe_env.addBorrowed("OMUX_ACTIVE_PROFILE", profile);

    return probe_env;
}

fn attemptRefresh(ctx: *Context, rt: []const u8) PipelineError!void {
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const writeback = try refreshWritebackBackend(ctx, def);
    const url = def.auth.token_endpoint orelse fallbackRefreshUrl(ctx) orelse {
        log.warn("token: no refresh URL for {s}", .{prov});
        recordRefreshEvent(ctx, writeback.plan, "no_token_endpoint", "token_endpoint_missing", false, false);
        return error.TokenRefreshFailed;
    };

    const result = oauth.refreshToken(ctx.allocator, url, rt, def.auth.client_id) catch |e| {
        log.err("token: refresh failed: {s}", .{@errorName(e)});
        recordRefreshEvent(ctx, writeback.plan, "token_endpoint_failed", @errorName(e), false, true);
        return error.TokenRefreshFailed;
    };
    errdefer ctx.allocator.free(result.access_token);
    errdefer if (result.refresh_token) |new_rt| ctx.allocator.free(new_rt);

    const expires_at = if (result.expires_in) |ei| std.time.timestamp() + ei else null;
    var retained_refresh_token: ?[]const u8 = null;
    var retained_refresh_token_from_old = false;
    if (result.refresh_token) |new_rt| {
        retained_refresh_token = new_rt;
    } else {
        retained_refresh_token = ctx.allocator.dupe(u8, rt) catch return error.OutOfMemory;
        retained_refresh_token_from_old = true;
    }
    errdefer if (retained_refresh_token_from_old) {
        if (retained_refresh_token) |old_rt| ctx.allocator.free(old_rt);
    };

    const credential = provider_schema.buildCredentialGeneric(
        def,
        .{
            .access_token = result.access_token,
            .refresh_token = retained_refresh_token,
            .expires_at = expires_at,
        },
        ctx.allocator,
    ) catch {
        recordRefreshEvent(ctx, writeback.plan, "credential_build_failed", "credential_template_failed", false, true);
        return error.TokenRefreshFailed;
    };
    defer ctx.allocator.free(credential);

    secret.writeReplace(writeback.backend, credential, ctx.allocator) catch |e| {
        log.err("token: refresh writeback failed for {s}: {s}", .{ prov, @errorName(e) });
        recordRefreshEvent(ctx, writeback.plan, "writeback_failed", @errorName(e), false, true);
        return error.TokenRefreshFailed;
    };

    // Update the token in context
    if (ctx.token) |old| {
        ctx.allocator.free(old.access_token);
        if (old.refresh_token) |old_rt| ctx.allocator.free(old_rt);
    }
    ctx.token = .{
        .access_token = result.access_token,
        .refresh_token = retained_refresh_token,
        .expires_at = expires_at,
    };

    recordRefreshEvent(ctx, writeback.plan, "persisted", writeback.plan.reason, true, true);
    log.info("token: refreshed successfully", .{});
}

const RefreshWriteback = struct {
    backend: types.SecretBackend,
    plan: secret.WritebackPlan,
};

fn refreshWritebackBackend(
    ctx: *Context,
    def: provider_schema.ProviderDefinition,
) PipelineError!RefreshWriteback {
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return error.AccountNotFound;
    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch return error.ConfigValidationError;
    const plan = secret.writebackPlan(backend, def.repair.owner);
    if (!plan.automatic_refresh_admitted) {
        log.warn("token: refresh writeback not admitted for {s}:{s}: {s}", .{ prov, acct, plan.reason });
        recordRefreshEvent(ctx, plan, "not_admitted", plan.reason, false, false);
        return error.TokenRefreshFailed;
    }
    return .{
        .backend = backend,
        .plan = plan,
    };
}

fn recordRefreshEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: []const u8,
    reason: ?[]const u8,
    ok: bool,
    executed: bool,
) void {
    if (comptime builtin.is_test) return;
    repair_state.appendEvent(ctx.allocator, .{
        .kind = "token_refresh",
        .profile = ctx.profile_name,
        .provider = ctx.provider_name,
        .account = ctx.account_name,
        .capability = ctx.capability_name,
        .action = "refresh",
        .writeback_capability = @tagName(plan.capability),
        .automatic_refresh_admitted = plan.automatic_refresh_admitted,
        .outcome = outcome,
        .reason = reason,
        .ok = ok,
        .executed = executed,
        .interactive = false,
        .mutating = true,
    }) catch {};
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
    const tmp_base = (try env.get(allocator, "TMPDIR")) orelse try allocator.dupe(u8, "/tmp");
    defer allocator.free(tmp_base);
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

test "refreshWritebackBackend admits only oauth-mux owned file writeback" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const admitted_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "https://example.invalid/token" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(admitted_json);

    const admitted = try config_mod.loadFromBytes(std.testing.allocator, admitted_json);
    defer admitted.deinit();
    var admitted_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer admitted_store.deinit();
    var admitted_ctx = Context.init(std.testing.allocator, admitted.value, &admitted_store);
    defer admitted_ctx.deinit();
    admitted_ctx.provider_name = "toy";
    admitted_ctx.account_name = "default";
    const admitted_writeback = try refreshWritebackBackend(&admitted_ctx, config_mod.resolveProviderDefinition(admitted.value, "toy"));
    try std.testing.expect(admitted_writeback.plan.automatic_refresh_admitted);
    switch (admitted_writeback.backend) {
        .file => |ref| try std.testing.expectEqualStrings(auth_path, ref.path),
        else => return error.TestUnexpectedResult,
    }

    const upstream_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "upstream_cli_login" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(upstream_json);

    const upstream = try config_mod.loadFromBytes(std.testing.allocator, upstream_json);
    defer upstream.deinit();
    var upstream_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer upstream_store.deinit();
    var upstream_ctx = Context.init(std.testing.allocator, upstream.value, &upstream_store);
    defer upstream_ctx.deinit();
    upstream_ctx.provider_name = "toy";
    upstream_ctx.account_name = "default";
    try std.testing.expectError(
        error.TokenRefreshFailed,
        refreshWritebackBackend(&upstream_ctx, config_mod.resolveProviderDefinition(upstream.value, "toy")),
    );

    const readonly_json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "repair": { "owner": "oauth_mux_refresh" }
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": { "secret": { "backend": "env", "variable": "TOY_AUTH" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const readonly = try config_mod.loadFromBytes(std.testing.allocator, readonly_json);
    defer readonly.deinit();
    var readonly_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer readonly_store.deinit();
    var readonly_ctx = Context.init(std.testing.allocator, readonly.value, &readonly_store);
    defer readonly_ctx.deinit();
    readonly_ctx.provider_name = "toy";
    readonly_ctx.account_name = "default";
    try std.testing.expectError(
        error.TokenRefreshFailed,
        refreshWritebackBackend(&readonly_ctx, config_mod.resolveProviderDefinition(readonly.value, "toy")),
    );
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
        \\  "provider_definitions": {{
        \\    "codex": {{
        \\      "name": "codex",
        \\      "display_name": "Synthetic Codex",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access_token",
        \\        "refresh_token_path": "tokens.refresh_token"
        \\      }},
        \\      "injection": {{
        \\        "direct_env": [["OPENAI_API_KEY", "access_token"]]
        \\      }}
        \\    }}
        \\  }},
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

test "runProbe executes auth none command probe without reading missing secret" {
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": { "provider": "toy" },
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "status",
        \\          "probe": {
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["sh", "-c", "printf '{\"loggedIn\":true}'"],
        \\            "budget": "free_command"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        {
        \\          "status": 400,
        \\          "hint_contains": "\"loggedIn\":false",
        \\          "class": { "dead": "token_revoked" }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "toy": { "providers": ["toy:default#status"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try runProbe(&ctx);

    try std.testing.expect(ctx.last_probe_executed);
    try std.testing.expect(ctx.token == null);
    try std.testing.expectEqual(@as(?u16, 200), ctx.last_probe_status);
    try std.testing.expectEqual(types.MuxDecision.use_this, ctx.last_probe_decision.?);
    try std.testing.expect(store.accounts.get("toy:default#status") != null);
}

test "runProbe does not poison liveness when command probe binary is missing" {
    const missing_binary = "omux-definitely-missing-probe-runtime";
    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "capabilities": [
        \\        {{
        \\          "name": "status",
        \\          "probe": {{
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["{s}", "status"],
        \\            "budget": "free_command"
        \\          }}
        \\        }}
        \\      ],
        \\      "failure_rules": [
        \\        {{ "status_min": 500, "status_max": 599, "class": {{ "provider_degraded": {{}} }} }}
        \\      ]
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "toy": {{ "providers": ["toy:default#status"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{missing_binary},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try std.testing.expectError(error.RuntimeNotReady, runProbe(&ctx));
    try std.testing.expect(!ctx.last_probe_executed);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default").?);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default#status").?);
}

test "runProbe does not poison liveness when command account runtime is unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const missing_config_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "missing-store" });
    defer std.testing.allocator.free(missing_config_dir);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "injection": {{ "config_dir_env": "TOY_HOME" }},
        \\      "runtime": {{
        \\        "env_vars": ["TOY_HOME"],
        \\        "writable_paths": ["TOY_HOME"],
        \\        "session_paths": ["TOY_HOME/session.json"]
        \\      }},
        \\      "capabilities": [
        \\        {{
        \\          "name": "status",
        \\          "probe": {{
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["sh", "-c", "printf '{{\"loggedIn\":true}}'"],
        \\            "budget": "free_command"
        \\          }}
        \\        }}
        \\      ],
        \\      "failure_rules": [
        \\        {{ "status_min": 500, "status_max": 599, "class": {{ "provider_degraded": {{}} }} }}
        \\      ]
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "toy": {{ "providers": ["toy:default#status"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{missing_config_dir},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try std.testing.expectError(error.RuntimeNotReady, runProbe(&ctx));
    try std.testing.expect(!ctx.last_probe_executed);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default").?);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default#status").?);
}

fn expectUnpoisonedRuntimeHealth(health: health_mod.AccountHealth) !void {
    switch (health.liveness) {
        .live => |live| switch (live.availability) {
            .available => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(health.last_http_status == null);
    try std.testing.expect(health.last_probe_source == null);
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
