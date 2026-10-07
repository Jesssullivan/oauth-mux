//! Provider-scoped, bounded capacity polling. A failed fetch never invents a
//! zero balance: the last successful observation expires on its own deadline.
const std = @import("std");
const domain = @import("domain.zig");
const transport = @import("transport.zig");

pub const Limits = struct {
    pub const pending = 16;
    pub const tracked_accounts = 1024;
    pub const poll_interval_seconds: i64 = 60;
    pub const freshness_seconds: i64 = 120;
    pub const bookkeeping_seconds: i64 = 3600;
};

pub const github_core: domain.Resource = .{
    .kind = "api-calls",
    .target = "core",
    .unit = .calls,
    .scope = "github:rest:core",
};

/// Ordinary included-use permission is a provider decision, separate from
/// remaining percentages, credit balances, and exact-model request readiness.
/// Native Codex can use credits when this flag is false; neither this resource
/// nor spend-control metadata is an all-model request admission rule.
pub const codex_ordinary_access: domain.Resource = .{
    .kind = "usage-access",
    .target = "codex",
    .unit = .custom,
    .unit_name = "provider-decision",
    .scope = "codex:ordinary-included",
};

const Provider = enum { github, codex };

const Pending = struct {
    id: u64,
    account_id: []const u8,
    grant_id: []const u8,
    generation: u64,
    resource: domain.Resource = github_core,
    provider: Provider = .github,

    fn deinit(self: Pending, allocator: std.mem.Allocator) void {
        allocator.free(self.account_id);
        allocator.free(self.grant_id);
    }
};

const LastPoll = struct { account_id: []const u8, at: i64 };
const Admission = struct {
    pending: Pending,
    pending_index: usize,
    poll_index: usize,
    new_poll: bool,
};

/// The daemon state owner calls these methods; this coordinator has no worker
/// thread and retains no credentials. The transport copies and owns the secret
/// only for the duration of its bounded request.
pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    pending: [Limits.pending]?Pending = @splat(null),
    last_polls: [Limits.tracked_accounts]?LastPoll = @splat(null),

    pub fn init(allocator: std.mem.Allocator) Coordinator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Coordinator) void {
        for (self.pending) |entry| if (entry) |pending| pending.deinit(self.allocator);
        for (self.last_polls) |entry| if (entry) |poll| self.allocator.free(poll.account_id);
        self.* = undefined;
    }

    /// Check scheduling before decrypting retained credentials. prepare still
    /// rechecks admission, so this does not confer grant or source authority.
    pub fn due(self: *const Coordinator, account_id: []const u8, now: i64) bool {
        if (now < 0 or self.accountPending(account_id)) return false;
        var pending_slot = false;
        for (self.pending) |entry| if (entry == null) {
            pending_slot = true;
            break;
        };
        if (!pending_slot) return false;
        var bookkeeping_slot = false;
        for (self.last_polls) |entry| {
            if (entry) |poll| {
                if (eql(poll.account_id, account_id)) return elapsed(poll.at, now, Limits.poll_interval_seconds);
                if (elapsed(poll.at, now, Limits.bookkeeping_seconds) and !self.accountPending(poll.account_id)) bookkeeping_slot = true;
            } else bookkeeping_slot = true;
        }
        return bookkeeping_slot;
    }

    pub fn submitGithubCapacity(self: *Coordinator, client: *transport.Client, grant: domain.Grant, secret: []const u8, now: i64) !u64 {
        var admission = try self.prepare(grant, now);
        errdefer self.rollback(admission);
        // All metadata allocations precede submit: a successful request always
        // has a tracked consumer even if the allocator subsequently fails.
        const id = try client.fetchJson(.{
            .endpoint = .github_capacity,
            .account_id = grant.account_id,
            .grant_id = grant.id,
            .access_token = secret,
            .timeout_ms = 10_000,
            .max_response_bytes = 64 * 1024,
        });
        admission.pending.id = id;
        self.commit(admission, now);
        return id;
    }

    pub fn submitCodexUsage(self: *Coordinator, client: *transport.Client, grant: domain.Grant, secret: []const u8, provider_account_id: ?[]const u8, now: i64) !u64 {
        var admission = try self.prepareFor(grant, now, .codex);
        errdefer self.rollback(admission);
        const id = try client.fetchJson(.{
            .endpoint = .codex_usage,
            .account_id = grant.account_id,
            .grant_id = grant.id,
            .access_token = secret,
            .provider_account_id = provider_account_id,
            .timeout_ms = 10_000,
            .max_response_bytes = 128 * 1024,
        });
        admission.pending.id = id;
        self.commit(admission, now);
        return id;
    }

    /// True means this completion belongs to an observation request, including
    /// failed and obsolete requests. Only a verified fresh response mutates
    /// state. The caller still owns and disposes the transport completion.
    pub fn take(self: *Coordinator, completion: *const transport.Completion, state: *domain.State, now: i64) !bool {
        const index = self.pendingIndex(completion.id) orelse return false;
        const pending = self.pending[index].?;
        self.pending[index] = null;
        defer pending.deinit(self.allocator);

        const grant = state.grant(pending.grant_id) orelse return true;
        if (grant.generation != pending.generation or !eql(grant.account_id, pending.account_id)) return true;
        if (pending.provider == .codex) {
            if (!codexCapacityEligible(state, grant, now)) return true;
            switch (completion.result) {
                .failure => {},
                .response => |response| _ = try observeCodexUsage(state, grant, response, now),
            }
            return true;
        }
        if (!githubCapacityEligible(state, grant, now)) return true;

        switch (completion.result) {
            .failure => return true,
            .response => |response| {
                var parsed = response.githubCapacity(self.allocator) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => return true,
                };
                defer parsed.deinit();
                const core = parsed.value.resources.core;
                // GitHub's authenticated core bucket is hourly; reset is an
                // epoch-second deadline. A future/expired window is unusable.
                // https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
                if (core.reset <= now or core.reset - 3600 > now) return true;
                const freshness = std.math.add(i64, now, Limits.freshness_seconds) catch std.math.maxInt(i64);
                // Verified GitHub identities deduplicate to one domain account
                // across authorized sources and grants. Its opaque local handle
                // names the known core bucket without exporting provider IDs.
                const bucket = try std.fmt.allocPrint(self.allocator, "github:{s}:core", .{pending.account_id});
                defer self.allocator.free(bucket);
                try state.observe(.{
                    .account_id = pending.account_id,
                    .resource = pending.resource,
                    .bucket_id = bucket,
                    .remaining = @floatFromInt(core.remaining),
                    .limit = @floatFromInt(core.limit),
                    .window_start = core.reset - 3600,
                    .window_end = core.reset,
                    .observed_at = now,
                    .expires_at = @min(freshness, core.reset),
                    .provenance = .provider_api,
                });
                return true;
            },
        }
    }

    /// Forgotten accounts do not occupy cooldown slots forever. In-flight
    /// requests keep their metadata until their bounded transport completion.
    pub fn prune(self: *Coordinator, state: *const domain.State, now: i64) void {
        for (&self.last_polls) |*entry| {
            const poll = entry.* orelse continue;
            if (self.accountPending(poll.account_id)) continue;
            if (state.account(poll.account_id) == null or elapsed(poll.at, now, Limits.bookkeeping_seconds)) {
                self.allocator.free(poll.account_id);
                entry.* = null;
            }
        }
    }

    fn prepare(self: *Coordinator, grant: domain.Grant, now: i64) !Admission {
        return self.prepareFor(grant, now, .github);
    }

    fn prepareFor(self: *Coordinator, grant: domain.Grant, now: i64, provider: Provider) !Admission {
        try validateGrantFor(grant, now, provider);
        if (self.accountPending(grant.account_id)) return error.AlreadyPolling;
        // Independently of lifecycle pruning, long-idle accounts age out of
        // bookkeeping, allowing bounded state to serve new enrolled accounts.
        self.pruneTimes(now);
        var pending_index: ?usize = null;
        for (self.pending, 0..) |entry, index| if (entry == null) {
            pending_index = index;
            break;
        };
        if (pending_index == null) return error.PollBackpressure;

        var poll_index: ?usize = null;
        var free_poll: ?usize = null;
        for (self.last_polls, 0..) |entry, index| {
            if (entry) |poll| {
                if (eql(poll.account_id, grant.account_id)) {
                    if (!elapsed(poll.at, now, Limits.poll_interval_seconds)) return error.PollTooSoon;
                    poll_index = index;
                    break;
                }
            } else if (free_poll == null) free_poll = index;
        }
        const selected_poll = poll_index orelse free_poll orelse return error.PollBackpressure;
        const account_id = try self.allocator.dupe(u8, grant.account_id);
        errdefer self.allocator.free(account_id);
        const grant_id = try self.allocator.dupe(u8, grant.id);
        errdefer self.allocator.free(grant_id);
        const new_poll = poll_index == null;
        if (new_poll) {
            // Finish allocation before touching the optional slot. Assigning
            // an aggregate containing `try` can partially initialize its tag
            // before failure, leaving deinit with an uninitialized pointer.
            const poll_account_id = try self.allocator.dupe(u8, grant.account_id);
            self.last_polls[selected_poll] = .{ .account_id = poll_account_id, .at = now };
        }
        return .{
            .pending = .{ .id = 0, .account_id = account_id, .grant_id = grant_id, .generation = grant.generation, .provider = provider },
            .pending_index = pending_index.?,
            .poll_index = selected_poll,
            .new_poll = new_poll,
        };
    }

    fn rollback(self: *Coordinator, admission: Admission) void {
        admission.pending.deinit(self.allocator);
        if (admission.new_poll) {
            self.allocator.free(self.last_polls[admission.poll_index].?.account_id);
            self.last_polls[admission.poll_index] = null;
        }
    }

    fn commit(self: *Coordinator, admission: Admission, now: i64) void {
        std.debug.assert(admission.pending.id != 0);
        self.pending[admission.pending_index] = admission.pending;
        self.last_polls[admission.poll_index].?.at = now;
    }

    fn pendingIndex(self: *const Coordinator, id: u64) ?usize {
        for (self.pending, 0..) |entry, index| if (entry) |pending| {
            if (pending.id == id) return index;
        };
        return null;
    }

    fn accountPending(self: *const Coordinator, account_id: []const u8) bool {
        for (self.pending) |entry| if (entry) |pending| {
            if (eql(pending.account_id, account_id)) return true;
        };
        return false;
    }

    fn pruneTimes(self: *Coordinator, now: i64) void {
        for (&self.last_polls) |*entry| {
            const poll = entry.* orelse continue;
            if (elapsed(poll.at, now, Limits.bookkeeping_seconds) and !self.accountPending(poll.account_id)) {
                self.allocator.free(poll.account_id);
                entry.* = null;
            }
        }
    }
};

/// Check before custody decryption or outgoing IO, and again when consuming a
/// completion. Eligibility itself never reads secrets or contacts a provider.
pub fn githubCapacityEligible(state: *const domain.State, grant: domain.Grant, now: i64) bool {
    validateGrantFor(grant, now, .github) catch return false;
    const current = state.grant(grant.id) orelse return false;
    if (current.generation != grant.generation or !eql(current.account_id, grant.account_id) or !eql(current.source_id, grant.source_id)) return false;
    validateGrantFor(current, now, .github) catch return false;
    const account = state.account(grant.account_id) orelse return false;
    const identity = account.identity;
    if (!identity.verified or !eql(identity.provider, "github") or !eql(identity.issuer, "https://github.com")) return false;
    if (numericSubject(identity.subject) == null) return false;
    return sourceAuthorized(state, current.source_id, now, "github");
}

pub fn codexCapacityEligible(state: *const domain.State, grant: domain.Grant, now: i64) bool {
    validateGrantFor(grant, now, .codex) catch return false;
    const current = state.grant(grant.id) orelse return false;
    if (current.generation != grant.generation or !eql(current.account_id, grant.account_id) or !eql(current.source_id, grant.source_id)) return false;
    validateGrantFor(current, now, .codex) catch return false;
    const account = state.account(grant.account_id) orelse return false;
    const identity = account.identity;
    if (!identity.verified or !eql(identity.provider, "codex") or !eql(identity.issuer, "https://chatgpt.com") or identity.subject.len == 0 or identity.tenant.len == 0) return false;
    return sourceAuthorized(state, current.source_id, now, "codex");
}

/// Ingest only after enrollment established the user and workspace identity.
/// Missing or invalid usage data adds no zero balance. Percentage denominators
/// and shared quota identities are unspecified by WHAM, so bucket IDs remain
/// unknown and these observations cannot produce additive account totals.
pub fn observeCodexUsage(state: *domain.State, grant: domain.Grant, response: transport.Response, now: i64) !usize {
    if (!codexCapacityEligible(state, grant, now)) return 0;
    var parsed = response.codexUsage(state.allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return 0,
    };
    defer parsed.deinit();
    const identity = state.account(grant.account_id).?.identity;
    if (!eql(parsed.value.user_id, identity.subject) or !eql(parsed.value.account_id, identity.tenant)) return 0;
    const expires = std.math.add(i64, now, Limits.freshness_seconds) catch return 0;
    var arena = std.heap.ArenaAllocator.init(state.allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var observations: std.ArrayList(domain.Observation) = .empty;
    if (parsed.value.rate_limit) |limit| try addCodexLimit(scratch, &observations, grant.account_id, "codex", limit, true, now, expires);
    if (parsed.value.additional_rate_limits) |additional| for (additional) |entry| {
        if (entry.rate_limit) |limit| try addCodexLimit(scratch, &observations, grant.account_id, entry.metered_feature, limit, false, now, expires);
    };
    if (parsed.value.spend_control) |control| {
        try observations.append(scratch, .{
            .account_id = grant.account_id,
            .resource = .{ .kind = "usage-access", .target = "codex", .unit = .custom, .unit_name = "provider-decision", .scope = "codex:spend-control" },
            .bucket_id = "",
            .remaining = if (control.reached) 0 else 1,
            .limit = 1,
            .window_start = now,
            .window_end = expires,
            .observed_at = now,
            .expires_at = expires,
            .status = if (control.reached) .unavailable else .ready,
            .provenance = .provider_api,
        });
    }
    if (observations.items.len == 0) return 0;
    try state.observeBatch(observations.items);
    return observations.items.len;
}

fn addCodexLimit(allocator: std.mem.Allocator, observations: *std.ArrayList(domain.Observation), account_id: []const u8, feature: []const u8, limit: transport.CodexUsage.RateLimit, ordinary: bool, now: i64, expires: i64) !void {
    const access_resource: domain.Resource = if (ordinary) codex_ordinary_access else .{
        .kind = "usage-access",
        .target = feature,
        .unit = .custom,
        .unit_name = "provider-decision",
        .scope = try std.fmt.allocPrint(allocator, "codex:feature:{s}", .{feature}),
    };
    try observations.append(allocator, .{
        .account_id = account_id,
        .resource = access_resource,
        .bucket_id = "",
        .remaining = if (limit.allowed) 1 else 0,
        .limit = 1,
        .window_start = now,
        .window_end = expires,
        .observed_at = now,
        .expires_at = expires,
        .status = if (limit.allowed) .ready else .unavailable,
        .provenance = .provider_api,
    });
    for ([_]?transport.CodexUsage.Window{ limit.primary_window, limit.secondary_window }, [_][]const u8{ "primary", "secondary" }) |window, name| {
        const value = window orelse continue;
        const start = std.math.sub(i64, value.reset_at, value.limit_window_seconds) catch continue;
        if (start > now or value.reset_at <= now) continue;
        const scope = if (ordinary)
            try std.fmt.allocPrint(allocator, "codex:ordinary-included:{s}:{d}s", .{ name, value.limit_window_seconds })
        else
            try std.fmt.allocPrint(allocator, "codex:feature:{s}:{s}:{d}s", .{ feature, name, value.limit_window_seconds });
        try observations.append(allocator, .{
            .account_id = account_id,
            .resource = .{ .kind = "subscription-usage", .target = feature, .unit = .custom, .unit_name = "percent-of-window", .scope = scope },
            .bucket_id = "",
            .remaining = @floatFromInt(@max(100 - @as(i64, value.used_percent), 0)),
            .limit = 100,
            .window_start = start,
            .window_end = value.reset_at,
            .observed_at = now,
            .expires_at = @min(expires, value.reset_at),
            // This is remaining included percentage, independent of allowed.
            .status = .ready,
            .provenance = .provider_api,
        });
    }
}

fn validateGrantFor(grant: domain.Grant, now: i64, provider: Provider) !void {
    if (now < 0) return error.InvalidTime;
    for ([_][]const u8{ grant.id, grant.account_id }) |handle| {
        if (handle.len == 0 or handle.len > 128) return error.InvalidScope;
        for (handle) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidScope;
    }
    if (grant.status != .ready or grant.generation == 0) return error.GrantNotReady;
    const audience = switch (provider) {
        .github => "https://github.com",
        .codex => "https://chatgpt.com",
    };
    if (!eql(grant.audience, audience)) return error.WrongAudience;
    switch (grant.credential_kind) {
        .api_key, .oauth_access => {},
        .oauth_refresh, .cookie_session, .browser_bound => return error.UnsupportedCredential,
    }
    var account_read = false;
    for (grant.purposes) |purpose| switch (purpose) {
        .account_read => account_read = true,
        .request, .renewal => {},
    };
    if (!account_read) return error.AccountReadRequired;
    if (grant.provider_expires_at) |expiry| if (expiry <= now) return error.GrantExpired;
    if (grant.custody_expires_at) |expiry| if (expiry <= now) return error.GrantExpired;
}

fn sourceAuthorized(state: *const domain.State, source_id: []const u8, now: i64, provider: []const u8) bool {
    for (state.sources.items) |source| {
        if (!eql(source.id, source_id)) continue;
        if (source.status == .disconnected or source.authorized_at > now) return false;
        if (source.authorized_until) |expiry| if (expiry <= now) return false;
        if (source.provider.len != 0 and !eql(source.provider, provider)) return false;
        return true;
    }
    return false;
}

fn numericSubject(subject: []const u8) ?u64 {
    if (subject.len == 0 or subject.len > 20) return null;
    for (subject) |byte| if (!std.ascii.isDigit(byte)) return null;
    const value = std.fmt.parseInt(u64, subject, 10) catch return null;
    return if (value == 0) null else value;
}

fn elapsed(at: i64, now: i64, interval: i64) bool {
    if (now < at) return false;
    return now - at >= interval;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn fixtureState(allocator: std.mem.Allocator) !domain.State {
    var state = domain.State.init(allocator);
    errdefer state.deinit();
    _ = try state.connectSource(.{ .id = "fixture-source", .provider = "github", .kind = .explicit, .authorized_at = 1 });
    _ = try state.enroll(.{ .account_id = "fixture-account", .source_id = "fixture-source", .identity = .{
        .provider = "github",
        .issuer = "https://github.com",
        .subject = "424242",
        .verified = true,
    } }, 4000);
    _ = try state.addGrant(.{
        .id = "fixture-grant",
        .account_id = "fixture-account",
        .source_id = "fixture-source",
        .credential_kind = .oauth_access,
        .purposes = &.{ .request, .account_read },
        .audience = "https://github.com",
    });
    return state;
}

fn trackFixture(coordinator: *Coordinator, grant: domain.Grant, id: u64, now: i64) !void {
    var admission = try coordinator.prepare(grant, now);
    admission.pending.id = id;
    coordinator.commit(admission, now);
}

fn fixtureResponse(allocator: std.mem.Allocator, id: u64, status: u16, body: []const u8) !transport.Completion {
    return .{ .id = id, .result = .{ .response = .{ .status = status, .body = try allocator.dupe(u8, body), .streaming = false } } };
}

const fixture_capacity = "{\"resources\":{\"core\":{\"limit\":5000,\"remaining\":4321,\"used\":679,\"reset\":7200}}}";

test "successful capacity is scoped to a verified identity and bounded by provider reset" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 1, 7100);
    var completion = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer completion.deinit(allocator);
    try std.testing.expect(try coordinator.take(&completion, &state, 7100));
    try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
    const observation = state.observations.items[0];
    try std.testing.expectEqualStrings("github:fixture-account:core", observation.bucket_id);
    try std.testing.expect(std.mem.indexOf(u8, observation.bucket_id, state.accounts.items[0].identity.subject) == null);
    try std.testing.expect(domain.sameResource(github_core, observation.resource));
    try std.testing.expectEqual(@as(f64, 4321), observation.remaining);
    try std.testing.expectEqual(@as(?f64, 5000), observation.limit);
    try std.testing.expectEqual(@as(i64, 3600), observation.window_start);
    try std.testing.expectEqual(@as(i64, 7200), observation.expires_at);
    try std.testing.expect(!(try coordinator.take(&completion, &state, 7100)));
}

test "failed malformed expired and obsolete responses preserve prior capacity" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 1, 4000);
    var good = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer good.deinit(allocator);
    try std.testing.expect(try coordinator.take(&good, &state, 4000));
    const revision = state.revision;
    const cases = [_]struct { status: u16, body: []const u8 }{
        .{ .status = 429, .body = "{}" },
        .{ .status = 200, .body = "{}" },
        .{ .status = 200, .body = "{\"resources\":{\"core\":{\"limit\":3,\"remaining\":4,\"used\":0,\"reset\":7200}}}" },
        .{ .status = 200, .body = "{\"resources\":{\"core\":{\"limit\":3,\"remaining\":2,\"used\":1,\"reset\":4000}}}" },
    };
    for (cases, 0..) |case, index| {
        const now: i64 = 4060 + @as(i64, @intCast(index)) * 60;
        try trackFixture(&coordinator, state.grant("fixture-grant").?, index + 2, now);
        var completion = try fixtureResponse(allocator, index + 2, case.status, case.body);
        defer completion.deinit(allocator);
        try std.testing.expect(try coordinator.take(&completion, &state, now));
    }
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 10, 4360);
    const failure: transport.Completion = .{ .id = 10, .result = .{ .failure = .deadline } };
    try std.testing.expect(try coordinator.take(&failure, &state, 4360));
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 11, 4420);
    try state.reconcile(.{ .grant_id = "fixture-grant", .expected_generation = 1, .next_generation = 2, .status = .ready });
    var stale = try fixtureResponse(allocator, 11, 200, fixture_capacity);
    defer stale.deinit(allocator);
    const rotated_revision = state.revision;
    try std.testing.expect(try coordinator.take(&stale, &state, 4420));
    try std.testing.expectEqual(rotated_revision, state.revision);
    try std.testing.expectEqual(revision + 1, rotated_revision);
    try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
    try std.testing.expectEqual(@as(f64, 4321), state.observations.items[0].remaining);
    try std.testing.expectEqual(@as(i64, 4120), state.observations.items[0].expires_at);
}

test "authorization is rechecked at completion while source detachment retains access" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 1, 4000);
    try state.detachSource("fixture-source");
    var completion = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer completion.deinit(allocator);
    try std.testing.expect(try coordinator.take(&completion, &state, 4000));
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 2, 4060);
    state.sources.items[0].authorized_until = 4060;
    completion.id = 2;
    const revision = state.revision;
    try std.testing.expect(try coordinator.take(&completion, &state, 4060));
    try std.testing.expectEqual(revision, state.revision);
    state.sources.items[0].authorized_until = null;
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 3, 4120);
    try state.disconnectSource("fixture-source");
    completion.id = 3;
    const disconnected_revision = state.revision;
    try std.testing.expect(try coordinator.take(&completion, &state, 4120));
    try std.testing.expectEqual(disconnected_revision, state.revision);
}

test "polling requires account-read authority and prevents concurrent requests and fast retries" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    var grant = state.grant("fixture-grant").?;
    try std.testing.expect(coordinator.due(grant.account_id, 4000));
    grant.purposes = &.{.request};
    try std.testing.expectError(error.AccountReadRequired, coordinator.prepare(grant, 4000));
    grant.purposes = &.{.account_read};
    grant.audience = "https://example.invalid";
    try std.testing.expectError(error.WrongAudience, coordinator.prepare(grant, 4000));
    grant.audience = "https://github.com";
    grant.credential_kind = .browser_bound;
    try std.testing.expectError(error.UnsupportedCredential, coordinator.prepare(grant, 4000));
    grant.credential_kind = .oauth_access;
    grant.custody_expires_at = 4000;
    try std.testing.expectError(error.GrantExpired, coordinator.prepare(grant, 4000));
    grant.custody_expires_at = null;
    try trackFixture(&coordinator, grant, 1, 4000);
    try std.testing.expect(!coordinator.due(grant.account_id, 4060));
    try std.testing.expectError(error.AlreadyPolling, coordinator.prepare(grant, 4060));
    const failure: transport.Completion = .{ .id = 1, .result = .{ .failure = .transport } };
    try std.testing.expect(try coordinator.take(&failure, &state, 4000));
    try std.testing.expectError(error.PollTooSoon, coordinator.prepare(grant, 4059));
    try std.testing.expectError(error.PollTooSoon, coordinator.prepare(grant, 3999));
    try std.testing.expect(!coordinator.due(grant.account_id, 4059));
    try std.testing.expect(!coordinator.due(grant.account_id, 3999));
    try std.testing.expect(coordinator.due(grant.account_id, 4060));
    const admission = try coordinator.prepare(grant, 4060);
    coordinator.rollback(admission);
    coordinator.prune(&state, 7600);
    for (coordinator.last_polls) |entry| try std.testing.expect(entry == null);
}

test "unverified wrong-issuer and nonnumeric subjects cannot supply capacity" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    var completion = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer completion.deinit(allocator);
    for (0..3) |index| {
        const now: i64 = 4000 + @as(i64, @intCast(index)) * 60;
        const identity = &state.accounts.items[0].identity;
        const verified = identity.verified;
        const issuer = identity.issuer;
        const subject = identity.subject;
        defer {
            identity.verified = verified;
            identity.issuer = issuer;
            identity.subject = subject;
        }
        switch (index) {
            0 => identity.verified = false,
            1 => identity.issuer = "https://example.invalid",
            2 => identity.subject = "fixture-subject",
            else => unreachable,
        }
        try trackFixture(&coordinator, state.grant("fixture-grant").?, index + 1, now);
        completion.id = index + 1;
        try std.testing.expect(try coordinator.take(&completion, &state, now));
    }
    try std.testing.expectEqual(@as(usize, 0), state.observations.items.len);
}

test "bounded pending and account bookkeeping release idle and forgotten records" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    var grant = state.grant("fixture-grant").?;
    for (0..Limits.pending) |index| {
        const account_id = try std.fmt.allocPrint(allocator, "fixture-{d}", .{index});
        defer allocator.free(account_id);
        grant.account_id = account_id;
        try trackFixture(&coordinator, grant, index + 1, 4000);
    }
    grant.account_id = "fixture-extra";
    try std.testing.expectError(error.PollBackpressure, coordinator.prepare(grant, 4000));
    for (0..Limits.pending) |index| {
        const failure: transport.Completion = .{ .id = index + 1, .result = .{ .failure = .canceled } };
        try std.testing.expect(try coordinator.take(&failure, &state, 4000));
    }
    coordinator.prune(&state, 4000);
    for (coordinator.last_polls) |entry| try std.testing.expect(entry == null);
    for (0..Limits.tracked_accounts) |index| {
        coordinator.last_polls[index] = .{ .account_id = try std.fmt.allocPrint(allocator, "fixture-{d}", .{index}), .at = 4000 };
    }
    try std.testing.expectError(error.PollBackpressure, coordinator.prepare(grant, 4059));
    const admission = try coordinator.prepare(grant, 7600);
    coordinator.rollback(admission);
    for (coordinator.last_polls) |entry| try std.testing.expect(entry == null);
}

test "grants for one identity share a cooldown and quota bucket including genuine exhaustion" {
    const allocator = std.testing.allocator;
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    var other = state.grant("fixture-grant").?;
    other.id = "fixture-other-grant";
    _ = try state.addGrant(other);
    try trackFixture(&coordinator, state.grant("fixture-grant").?, 1, 4000);
    try std.testing.expectError(error.AlreadyPolling, coordinator.prepare(other, 4000));
    var completion = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer completion.deinit(allocator);
    try std.testing.expect(try coordinator.take(&completion, &state, 4000));
    const initial_bucket = try allocator.dupe(u8, state.observations.items[0].bucket_id);
    defer allocator.free(initial_bucket);
    try std.testing.expectError(error.PollTooSoon, coordinator.prepare(other, 4059));
    try trackFixture(&coordinator, other, 2, 4060);
    var exhausted = try fixtureResponse(allocator, 2, 200, "{\"resources\":{\"core\":{\"limit\":5000,\"remaining\":0,\"used\":5000,\"reset\":7200}}}");
    defer exhausted.deinit(allocator);
    try std.testing.expect(try coordinator.take(&exhausted, &state, 4060));
    try std.testing.expectEqual(@as(usize, 1), state.observations.items.len);
    try std.testing.expectEqualStrings(initial_bucket, state.observations.items[0].bucket_id);
    const aggregate = state.aggregate("github", "https://github.com", github_core, 3600, 7200, 4060);
    try std.testing.expect(aggregate.complete);
    try std.testing.expectEqual(@as(usize, 1), aggregate.buckets);
    try std.testing.expectEqual(@as(f64, 0), aggregate.remaining);
    try std.testing.expectEqual(@as(?f64, 5000), aggregate.limit);
}

fn exerciseAllocationFailure(allocator: std.mem.Allocator) !void {
    var state = try fixtureState(allocator);
    defer state.deinit();
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    const grant = state.grant("fixture-grant").?;
    const first = try coordinator.prepare(grant, 4000);
    coordinator.rollback(first);
    try trackFixture(&coordinator, grant, 1, 4000);
    var response = try fixtureResponse(allocator, 1, 200, fixture_capacity);
    defer response.deinit(allocator);
    try std.testing.expect(try coordinator.take(&response, &state, 4000));
    const second = try coordinator.prepare(grant, 4060);
    coordinator.rollback(second);
}

test "allocation failures release admission metadata and partially parsed observations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseAllocationFailure, .{});
}

fn codexFixtureState(allocator: std.mem.Allocator) !domain.State {
    var state = domain.State.init(allocator);
    errdefer state.deinit();
    _ = try state.connectSource(.{ .id = "codex-source", .provider = "codex", .kind = .native_store, .authorized_at = 1 });
    _ = try state.enroll(.{ .account_id = "codex-account", .source_id = "codex-source", .identity = .{
        .provider = "codex",
        .issuer = "https://chatgpt.com",
        .subject = "user-a",
        .tenant = "workspace-a",
        .verified = true,
    } }, 4000);
    _ = try state.addGrant(.{ .id = "codex-grant", .account_id = "codex-account", .source_id = "codex-source", .credential_kind = .oauth_access, .purposes = &.{ .request, .account_read }, .audience = "https://chatgpt.com" });
    return state;
}

const codex_fixture_usage =
    \\{"account_id":"workspace-a","user_id":"user-a","plan_type":"plus","rate_limit":{"allowed":true,"limit_reached":true,"primary_window":{"used_percent":100,"limit_window_seconds":3600,"reset_after_seconds":3200,"reset_at":7200},"secondary_window":{"used_percent":25,"limit_window_seconds":7200,"reset_after_seconds":6000,"reset_at":10000}},"additional_rate_limits":[{"limit_name":"Review allowance","metered_feature":"codex-reviews","normal_model_slug":"gpt-example","rate_limit":{"allowed":false,"limit_reached":false,"primary_window":{"used_percent":10,"limit_window_seconds":600,"reset_after_seconds":500,"reset_at":4500}}}],"credits":{"has_credits":true,"unlimited":false,"balance":"17.25"},"spend_control":{"reached":false}}
;

test "Codex windows retain percentages and feature scope independently of usage permission" {
    const allocator = std.testing.allocator;
    var state = try codexFixtureState(allocator);
    defer state.deinit();
    var completion = try fixtureResponse(allocator, 1, 200, codex_fixture_usage);
    defer completion.deinit(allocator);
    const grant = state.grant("codex-grant").?;
    try std.testing.expect(codexCapacityEligible(&state, grant, 4000));
    try std.testing.expectEqual(@as(usize, 6), try observeCodexUsage(&state, grant, completion.result.response, 4000));
    try std.testing.expectEqual(@as(usize, 6), state.observations.items.len);
    var windows: usize = 0;
    for (state.observations.items) |observation| {
        try std.testing.expectEqualStrings("", observation.bucket_id);
        try std.testing.expectEqual(domain.Unit.custom, observation.resource.unit);
        try std.testing.expect(observation.expires_at <= 4120);
        try std.testing.expect(!eql(observation.resource.target, "gpt-example"));
        if (eql(observation.resource.kind, "subscription-usage")) {
            windows += 1;
            try std.testing.expectEqualStrings("percent-of-window", observation.resource.unit_name);
            try std.testing.expectEqual(domain.ObservationStatus.ready, observation.status);
            if (eql(observation.resource.scope, "codex:ordinary-included:primary:3600s")) {
                try std.testing.expectEqual(@as(f64, 0), observation.remaining);
                try std.testing.expectEqual(@as(i64, 3600), observation.window_start);
                try std.testing.expectEqual(@as(i64, 7200), observation.window_end);
            }
            const total = state.aggregate("codex", "https://chatgpt.com", observation.resource, observation.window_start, observation.window_end, 4000);
            try std.testing.expect(!total.complete);
            try std.testing.expectEqual(@as(usize, 0), total.buckets);
        } else if (domain.sameResource(observation.resource, codex_ordinary_access)) {
            try std.testing.expectEqual(domain.ObservationStatus.ready, observation.status);
            try std.testing.expectEqual(@as(f64, 1), observation.remaining);
        } else if (eql(observation.resource.scope, "codex:feature:codex-reviews")) {
            try std.testing.expectEqual(domain.ObservationStatus.unavailable, observation.status);
            try std.testing.expectEqual(@as(f64, 0), observation.remaining);
        }
    }
    try std.testing.expectEqual(@as(usize, 3), windows);
}

test "Codex absent failed malformed and mismatched usage cannot erase fresh evidence" {
    const allocator = std.testing.allocator;
    var state = try codexFixtureState(allocator);
    defer state.deinit();
    var good = try fixtureResponse(allocator, 1, 200, codex_fixture_usage);
    defer good.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 6), try observeCodexUsage(&state, state.grant("codex-grant").?, good.result.response, 4000));
    const revision = state.revision;
    const cases = [_]struct { status: u16, body: []const u8 }{
        .{ .status = 429, .body = "{}" },
        .{ .status = 200, .body = "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\"}" },
        .{ .status = 200, .body = "{\"account_id\":\"other-workspace\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":{\"allowed\":false,\"limit_reached\":true}}" },
        .{ .status = 200, .body = "{\"account_id\":\"workspace-a\",\"user_id\":\"other-user\",\"plan_type\":\"plus\",\"rate_limit\":{\"allowed\":false,\"limit_reached\":true}}" },
        .{ .status = 200, .body = "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":{\"allowed\":false}}" },
    };
    for (cases) |case| {
        var completion = try fixtureResponse(allocator, 2, case.status, case.body);
        defer completion.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), try observeCodexUsage(&state, state.grant("codex-grant").?, completion.result.response, 4060));
        try std.testing.expectEqual(revision, state.revision);
    }
    var coordinator = Coordinator.init(allocator);
    defer coordinator.deinit();
    var admission = try coordinator.prepareFor(state.grant("codex-grant").?, 4060, .codex);
    admission.pending.id = 3;
    coordinator.commit(admission, 4060);
    try state.reconcile(.{ .grant_id = "codex-grant", .expected_generation = 1, .next_generation = 2, .status = .ready });
    good.id = 3;
    const rotated = state.revision;
    try std.testing.expect(try coordinator.take(&good, &state, 4060));
    try std.testing.expectEqual(rotated, state.revision);
}

fn exerciseCodexAllocationFailure(allocator: std.mem.Allocator) !void {
    var state = try codexFixtureState(allocator);
    defer state.deinit();
    var completion = try fixtureResponse(allocator, 1, 200, codex_fixture_usage);
    defer completion.deinit(allocator);
    const revision = state.revision;
    const count = observeCodexUsage(&state, state.grant("codex-grant").?, completion.result.response, 4000) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), state.observations.items.len);
        try std.testing.expectEqual(revision, state.revision);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 6), count);
}

test "Codex multi-window observation is atomic across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseCodexAllocationFailure, .{});
}
