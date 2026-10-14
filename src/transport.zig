//! Bounded, account-scoped libcurl client. Only the owner thread touches easy
//! handles. The sole cross-thread curl call is the documented multi wakeup.
//! Resource requests never carry refresh credentials. Separately issued opaque
//! OAuth tickets use their own bounded owner-only channel and one-shot fence.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const browser = @import("browser_grant.zig");
const root = @import("root");
const oauth_token = @import("oauth_token.zig");
const oauth_authority = @import("oauth_issue_authority.zig");
const oauth_enrollment = @import("oauth_enrollment.zig");
const catalog_authority = @import("siwc_catalog_authority.zig");
const siwc_catalog = @import("siwc_catalog.zig");
const siwc_pair = @import("siwc_pair.zig");
const envelope = @import("envelope.zig");
// Only a dedicated Bazel test probe opts into local fixture transport. Shipping
// daemon/CLI roots have no declaration and cannot enable fixtures through IPC.
const fixtures_enabled = builtin.is_test or (if (@hasDecl(root, "allow_transport_fixtures")) root.allow_transport_fixtures else false);

pub const Limits = struct {
    pub const outstanding = 32;
    pub const concurrent = 8;
    pub const chunks = 32;
    pub const chunk_bytes = 16 * 1024;
    pub const body_bytes = 64 * 1024;
    pub const response_bytes = 4 * 1024 * 1024;
    pub const credential_bytes = 16 * 1024;
    pub const deadline_ms = 120_000;
};

/// Each endpoint is a reviewed declaration. URLs never come from control RPC,
/// page content, redirects, imported cookies, or provider response bodies.
pub const Endpoint = enum {
    github_identity,
    github_capacity,
    codex_identity,
    codex_usage,
    openai_model_catalog,
    fixture_identity,
    fixture_tls_identity,
    codex_oauth_token,
    omux_oss_oauth_token,
    fixture_oauth_token,
    fixture_oss_oauth_token,
    openai_jwks,
    fixture_jwks,
    fixture_siwc_catalog,

    pub fn origin(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity, .github_capacity => "https://api.github.com",
            .codex_identity, .codex_usage => "https://chatgpt.com",
            .openai_model_catalog => "https://api.openai.com",
            .fixture_identity => "http://127.0.0.1",
            .fixture_tls_identity => "https://localhost",
            .codex_oauth_token, .omux_oss_oauth_token, .openai_jwks => "https://auth.openai.com",
            .fixture_oauth_token, .fixture_oss_oauth_token, .fixture_jwks, .fixture_siwc_catalog => "http://127.0.0.1",
        };
    }

    pub fn path(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity => "/user",
            .github_capacity => "/rate_limit",
            .codex_identity, .codex_usage => "/backend-api/wham/usage",
            .openai_model_catalog, .fixture_siwc_catalog => "/v1/models",
            .fixture_identity, .fixture_tls_identity => "/identity",
            .codex_oauth_token, .fixture_oauth_token => "/oauth/token",
            .omux_oss_oauth_token, .fixture_oss_oauth_token => "/api/accounts/oauth/token",
            .openai_jwks, .fixture_jwks => "/.well-known/jwks.json",
        };
    }

    pub fn host(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity, .github_capacity => "api.github.com",
            .codex_identity, .codex_usage => "chatgpt.com",
            .openai_model_catalog => "api.openai.com",
            .fixture_identity => "127.0.0.1",
            .fixture_tls_identity => "localhost",
            .codex_oauth_token, .omux_oss_oauth_token, .openai_jwks => "auth.openai.com",
            .fixture_oauth_token, .fixture_oss_oauth_token, .fixture_jwks, .fixture_siwc_catalog => "127.0.0.1",
        };
    }

    pub fn provesIdentity(self: Endpoint) bool {
        return switch (self) {
            .github_identity, .codex_identity, .codex_usage, .fixture_identity, .fixture_tls_identity => true,
            .github_capacity, .openai_model_catalog, .codex_oauth_token, .omux_oss_oauth_token, .fixture_oauth_token, .fixture_oss_oauth_token, .openai_jwks, .fixture_jwks, .fixture_siwc_catalog => false,
        };
    }
};

// Borrowed only from a trusted in-process owner that outlives Client.deinit.
// Keeps an existing awake cutoff through allocation, queueing and curl work;
// no epoch conversion or newly renewed relative budget is required.
pub const AbsoluteDeadline = struct {
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    pub fn remaining(self: AbsoluteDeadline) !u32 {
        if (self.until.clock != .awake) return error.InvalidDeadline;
        const ms = self.until.durationFromNow(self.io).raw.toMilliseconds();
        if (ms <= 0) return error.InvalidDeadline;
        return @intCast(@min(ms, Limits.deadline_ms));
    }
    fn expired(self: AbsoluteDeadline) bool {
        return self.until.clock != .awake or self.until.durationFromNow(self.io).raw.toNanoseconds() <= 0;
    }
};

pub const Request = struct {
    endpoint: Endpoint,
    account_id: []const u8,
    grant_id: []const u8,
    access_token: ?[]const u8 = null,
    /// Native account/workspace hint is routing input, never identity evidence.
    /// Only the fixed Codex usage endpoint accepts this header; enrollment must
    /// compare the authenticated response account_id with any supplied hint.
    provider_account_id: ?[]const u8 = null,
    /// Origin, request path, lease and store provenance stay attached to cookie
    /// headers. Raw headers are absent from the public request interface.
    browser_authorization: ?browser.ScopedHeader = null,
    method: enum { get, post } = .get,
    body: []const u8 = "",
    timeout_ms: u32 = 10_000,
    absolute_deadline: ?AbsoluteDeadline = null,
    max_response_bytes: usize = 1024 * 1024,
    streaming: bool = false,
    /// Test-only fixture route; never admitted by a non-test executable.
    fixture_port: u16 = 0,

    pub fn validate(self: Request) !void {
        // Even test roots cannot turn a resource request into a token issuer.
        if (self.endpoint == .codex_oauth_token or self.endpoint == .omux_oss_oauth_token or self.endpoint == .fixture_oauth_token or self.endpoint == .fixture_oss_oauth_token) return error.UndeclaredEndpoint;
        if (self.endpoint == .openai_jwks or self.endpoint == .fixture_jwks or self.endpoint == .fixture_siwc_catalog) return error.UndeclaredEndpoint;
        if (!validHandle(self.account_id) or !validHandle(self.grant_id)) return error.InvalidScope;
        if (self.timeout_ms == 0 or self.timeout_ms > Limits.deadline_ms) return error.InvalidDeadline;
        if (self.absolute_deadline) |deadline| _ = try deadline.remaining();
        if (self.max_response_bytes == 0 or self.max_response_bytes > Limits.response_bytes) return error.InvalidLimit;
        if (self.body.len > Limits.body_bytes) return error.RequestTooLarge;
        // All current declarations are observations. A future write/refresh
        // endpoint must separately declare and constrain its method.
        if (self.method != .get) return error.UndeclaredMethod;
        if (self.method == .get and self.body.len != 0) return error.UnexpectedBody;
        if (self.access_token != null and self.browser_authorization != null) return error.AmbiguousAuthorization;
        if (self.provider_account_id) |account_hint| {
            if ((self.endpoint != .codex_identity and self.endpoint != .codex_usage) or self.access_token == null or !validProviderId(account_hint)) return error.InvalidAccountHint;
        }
        const cookie_bytes: ?[]const u8 = if (self.browser_authorization) |auth| auth.bytes else null;
        for ([_]?[]const u8{ self.access_token, cookie_bytes }) |credential| {
            if (credential) |value| {
                if (value.len == 0 or value.len > Limits.credential_bytes) return error.InvalidCredential;
                for (value) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidCredential;
            }
        }
        if (self.browser_authorization) |auth| {
            if (!std.mem.eql(u8, auth.host, self.endpoint.host()) or !std.mem.eql(u8, auth.request_path, self.endpoint.path())) return error.CredentialAudienceMismatch;
            if (!validHandle(auth.store_id) or self.endpoint == .fixture_identity or self.endpoint == .fixture_tls_identity) return error.InvalidCredential;
            if (auth.partition_key) |key| try browser.validatePartition(key);
            if (auth.first_party_domain) |domain| if (!browser.validFirstPartyDomain(domain)) return error.InvalidCredential;
            const now = wallClockSeconds();
            if (auth.custody_until_unix <= now or (auth.provider_expires_unix != null and auth.provider_expires_unix.? <= now)) return error.CredentialExpired;
        }
        if (self.endpoint == .fixture_identity or self.endpoint == .fixture_tls_identity) {
            if (!fixtures_enabled or self.fixture_port == 0) return error.UndeclaredEndpoint;
        } else if (self.fixture_port != 0) return error.UndeclaredEndpoint;
    }
};

fn validHandle(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}

fn validProviderId(value: []const u8) bool {
    if (value.len == 0 or value.len > 256) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "-_:.|", byte) == null) return false;
    return true;
}

pub const Failure = enum {
    canceled,
    deadline,
    response_too_large,
    transport,
    tls,
    allocation,
    invalid_json,
};

/// GitHub's numeric user ID is durable; login is display metadata only.
/// https://docs.github.com/en/rest/users/users#get-the-authenticated-user
pub const GitHubIdentity = struct {
    id: u64,
    login: []const u8,
    type: []const u8,
};

/// Endpoint-specific observation, deliberately distinct from Omux totals.
/// Caller supplies observation time and the verified identity/bucket mapping.
pub const GitHubCapacity = struct {
    pub const Bucket = struct { limit: u64, remaining: u64, reset: i64, used: u64 };
    resources: struct { core: Bucket },
};

/// Fields verified from the native Codex backend-client/OpenAPI schema.
/// Workspace/account identity stays distinct from user identity. JWT claims and
/// a request account hint never replace this authenticated provider response.
pub const CodexIdentity = struct {
    account_id: []const u8,
    user_id: []const u8,
    plan_type: []const u8,

    pub const Plan = enum {
        guest,
        free,
        go,
        plus,
        pro,
        prolite,
        free_workspace,
        team,
        self_serve_business_prolite,
        self_serve_business_usage_based,
        business,
        ent26,
        enterprise_cbp_automation,
        enterprise_cbp_usage_based,
        education,
        quorum,
        k12,
        enterprise,
        edu,
        edu_plus,
        edu_pro,
        unknown,
    };

    /// Preserve future plan strings in plan_type while exposing known plan
    /// categories. An unknown plan does not invent entitlement or quota.
    pub fn plan(self: CodexIdentity) Plan {
        return std.meta.stringToEnum(Plan, self.plan_type) orelse .unknown;
    }

    pub fn matchesHint(self: CodexIdentity, expected: ?[]const u8) bool {
        return if (expected) |hint| std.mem.eql(u8, self.account_id, hint) else true;
    }
};

/// Reviewed native WHAM usage fields. Provider percentages and access decisions
/// are distinct; neither establishes an absolute token budget or model support.
/// Unknown optional provider fields remain outside the observation contract.
pub const CodexUsage = struct {
    account_id: []const u8,
    user_id: []const u8,
    plan_type: []const u8,
    rate_limit: ?RateLimit = null,
    additional_rate_limits: ?[]const Additional = null,
    credits: ?Credits = null,
    spend_control: ?struct { reached: bool } = null,
    rate_limit_reached_type: ?struct { type: []const u8 } = null,

    pub const Window = struct {
        used_percent: i32,
        limit_window_seconds: i32,
        reset_after_seconds: i32,
        reset_at: i64,
    };
    pub const RateLimit = struct {
        allowed: bool,
        limit_reached: bool,
        primary_window: ?Window = null,
        secondary_window: ?Window = null,
    };
    pub const Additional = struct {
        limit_name: []const u8,
        metered_feature: []const u8,
        rate_limit: ?RateLimit = null,
        /// Native picker metadata only. Never an exact-model quota declaration.
        normal_model_slug: ?[]const u8 = null,
    };
    pub const Credits = struct {
        has_credits: bool,
        unlimited: bool,
        /// Opaque provider decimal string; no inferred tokens or currency unit.
        balance: ?[]const u8 = null,
    };

    pub fn identity(self: CodexUsage) CodexIdentity {
        return .{ .account_id = self.account_id, .user_id = self.user_id, .plan_type = self.plan_type };
    }

    fn validate(self: CodexUsage) !void {
        try validateCodexIdentity(self.identity());
        if (self.rate_limit) |limit| try validateRateLimit(limit);
        if (self.additional_rate_limits) |additional| {
            if (additional.len > 32) return error.InvalidCapacity;
            for (additional, 0..) |entry, index| {
                if (!validProviderId(entry.metered_feature) or !validDisplay(entry.limit_name, 256)) return error.InvalidCapacity;
                if (entry.normal_model_slug) |slug| if (!validProviderId(slug)) return error.InvalidCapacity;
                for (additional[0..index]) |previous| if (std.mem.eql(u8, previous.metered_feature, entry.metered_feature)) return error.InvalidCapacity;
                if (entry.rate_limit) |limit| try validateRateLimit(limit);
            }
        }
        if (self.credits) |credits| if (credits.balance) |balance| if (!validDisplay(balance, 128)) return error.InvalidCapacity;
        if (self.rate_limit_reached_type) |reached| if (!validProviderId(reached.type)) return error.InvalidCapacity;
    }

    fn validateRateLimit(limit: RateLimit) !void {
        for ([_]?Window{ limit.primary_window, limit.secondary_window }) |window| {
            if (window) |value| {
                // Percentages outside the reviewed range are unknown data,
                // never fabricated zero remaining or authorization evidence.
                if (value.used_percent < 0 or value.used_percent > 100 or value.limit_window_seconds <= 0 or value.reset_after_seconds < 0 or value.reset_at <= 0) return error.InvalidCapacity;
            }
        }
    }
};

fn validDisplay(value: []const u8, cap: usize) bool {
    if (value.len == 0 or value.len > cap) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn validateCodexIdentity(identity: CodexIdentity) !void {
    if (!validProviderId(identity.account_id) or !validProviderId(identity.user_id) or identity.plan_type.len == 0 or identity.plan_type.len > 64) return error.InvalidIdentity;
    for (identity.plan_type) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_' and byte != '-') return error.InvalidIdentity;
}

pub const Response = struct {
    status: u16,
    body: []u8,
    /// A streaming response delivers payload through pollChunk instead.
    streaming: bool,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.body);
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn parseJson(self: Response, allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
        if (self.streaming) return error.StreamingResponse;
        return std.json.parseFromSlice(std.json.Value, allocator, self.body, .{ .allocate = .alloc_always });
    }

    pub fn githubIdentity(self: Response, allocator: std.mem.Allocator) !std.json.Parsed(GitHubIdentity) {
        if (self.streaming or self.status != 200) return error.IdentityUnavailable;
        var parsed = try std.json.parseFromSlice(GitHubIdentity, allocator, self.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        errdefer parsed.deinit();
        if (parsed.value.id == 0 or parsed.value.login.len == 0 or parsed.value.login.len > 256 or parsed.value.type.len == 0 or parsed.value.type.len > 128) return error.InvalidIdentity;
        for (parsed.value.login) |byte| if (byte < 0x21 or byte >= 0x7f) return error.InvalidIdentity;
        for (parsed.value.type) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') return error.InvalidIdentity;
        return parsed;
    }

    pub fn githubCapacity(self: Response, allocator: std.mem.Allocator) !std.json.Parsed(GitHubCapacity) {
        if (self.streaming or self.status != 200) return error.CapacityUnavailable;
        var parsed = try std.json.parseFromSlice(GitHubCapacity, allocator, self.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        errdefer parsed.deinit();
        const bucket = parsed.value.resources.core;
        if (bucket.remaining > bucket.limit or bucket.used > bucket.limit or bucket.reset <= 0) return error.InvalidCapacity;
        return parsed;
    }

    pub fn codexIdentity(self: Response, allocator: std.mem.Allocator) !std.json.Parsed(CodexIdentity) {
        if (self.streaming or self.status != 200) return error.IdentityUnavailable;
        var parsed = try std.json.parseFromSlice(CodexIdentity, allocator, self.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        errdefer parsed.deinit();
        try validateCodexIdentity(parsed.value);
        return parsed;
    }

    pub fn codexUsage(self: Response, allocator: std.mem.Allocator) !std.json.Parsed(CodexUsage) {
        if (self.streaming or self.status != 200) return error.CapacityUnavailable;
        var parsed = try std.json.parseFromSlice(CodexUsage, allocator, self.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        errdefer parsed.deinit();
        try parsed.value.validate();
        return parsed;
    }
};

const OAuthResponseData = struct {
    allocator: std.mem.Allocator,
    status: u16,
    body: []u8,
    sha256: [32]u8,
    received_unix: i64,
    original: AbsoluteDeadline,
    binding: oauth_enrollment.Binding,
    profile_sha256: [32]u8,
    issued_revision: u64,
    issued_client_id: []u8,
    endpoint: Endpoint,
    fence: *oauth_authority.DispatchFence,
    references: std.atomic.Value(usize) = .init(1),
};
/// Held token reply from the sole actual curl dispatch. Raw caller bodies,
/// endpoint labels and response digests cannot construct this provenance.
pub const OAuthResponse = opaque {
    pub fn status(self: *const OAuthResponse) u16 {
        return oauthResponseData(self).status;
    }
    pub fn responseSha256(self: *const OAuthResponse) [32]u8 {
        return oauthResponseData(self).sha256;
    }
    pub fn receivedUnix(self: *const OAuthResponse) i64 {
        return oauthResponseData(self).received_unix;
    }
    pub fn issuedClientId(self: *const OAuthResponse) []const u8 {
        return oauthResponseData(self).issued_client_id;
    }
    pub fn isOwnOss(self: *const OAuthResponse) bool {
        const endpoint = oauthResponseData(self).endpoint;
        return endpoint == .omux_oss_oauth_token or (builtin.is_test and endpoint == .fixture_oss_oauth_token);
    }
    pub fn recheck(self: *const OAuthResponse, ticket: *const oauth_authority.IssuedTicket) !void {
        const data = oauthResponseData(self);
        if (!std.meta.eql(data.binding, ticket.binding()) or data.issued_revision != ticket.committedRevision() or !std.crypto.timing_safe.eql([32]u8, data.profile_sha256, ticket.registrationProfileSha256())) return error.OAuthResponseAuthorityChanged;
        if (!std.meta.eql(data.original.io, ticket.clockIo()) or !std.meta.eql(data.original.until, ticket.originalUntil()) or !std.mem.eql(u8, data.issued_client_id, ticket.issuedClientId())) return error.OAuthResponseAuthorityChanged;
        if (!ticket.matchesDispatchFence(data.fence)) return error.OAuthResponseAuthorityChanged;
        try ticket.checkBeforeVerification();
        try self.checkHeld();
    }
    pub fn copyForEncryptedCustody(self: *const OAuthResponse, allocator: std.mem.Allocator, ticket: *const oauth_authority.IssuedTicket) !envelope.Secret {
        try self.recheck(ticket);
        var result: envelope.Secret = .{ .allocator = allocator, .bytes = try allocator.dupe(u8, oauthResponseData(self).body) };
        errdefer result.deinit();
        var copied: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(result.bytes, &copied, .{});
        if (!std.crypto.timing_safe.eql([32]u8, copied, self.responseSha256())) return error.OAuthResponseAuthorityChanged;
        try self.recheck(ticket);
        return result;
    }
    fn checkHeld(self: *const OAuthResponse) !void {
        const data = oauthResponseData(self);
        _ = try data.original.remaining();
        try data.fence.checkBeforeCompletion();
        if ((data.endpoint == .fixture_oauth_token or data.endpoint == .fixture_oss_oauth_token) and !builtin.is_test) return error.OAuthResponseAuthorityChanged;
        const now = std.Io.Clock.real.now(data.original.io).toSeconds();
        if (now < data.received_unix or now - data.received_unix > 120) return error.OAuthResponseAuthorityChanged;
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data.body, &actual, .{});
        if (!std.crypto.timing_safe.eql([32]u8, actual, data.sha256)) return error.OAuthResponseAuthorityChanged;
        _ = try data.original.remaining();
        try data.fence.checkBeforeCompletion();
    }
    pub fn evidence(self: *const OAuthResponse, allocator: std.mem.Allocator) !oauth_token.Evidence {
        try self.checkHeld();
        const data = oauthResponseData(self);
        var parsed_reply = try oauth_token.parse(allocator, data.status, data.body);
        errdefer parsed_reply.deinit();
        try self.checkHeld();
        return parsed_reply;
    }
    pub fn retain(self: *OAuthResponse) void {
        _ = oauthResponseDataMut(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *OAuthResponse) void {
        const data = oauthResponseDataMut(self);
        if (data.references.fetchSub(1, .acq_rel) != 1) return;
        std.crypto.secureZero(u8, data.body);
        data.allocator.free(data.body);
        data.allocator.free(data.issued_client_id);
        data.fence.deinit();
        data.allocator.destroy(data);
    }
};
fn oauthResponseData(self: *const OAuthResponse) *const OAuthResponseData {
    return @ptrCast(@alignCast(self));
}
fn oauthResponseDataMut(self: *OAuthResponse) *OAuthResponseData {
    return @ptrCast(@alignCast(self));
}
pub const OAuthCompletion = struct {
    id: u64,
    owner: ?*Client = null,
    result: union(enum) { response: *OAuthResponse, failure: Failure },
    pub fn deinit(self: *OAuthCompletion, allocator: std.mem.Allocator) void {
        _ = allocator;
        switch (self.result) {
            .response => |response| response.deinit(),
            .failure => {},
        }
        if (self.owner) |owner| owner.releaseCompletion(self.id);
        self.* = undefined;
    }
};

const CatalogResponseData = struct {
    allocator: std.mem.Allocator,
    body: []u8,
    digest: [32]u8,
    received_unix: i64,
    original: AbsoluteDeadline,
    context: siwc_pair.CatalogContext,
    lease: ?catalog_authority.LeaseContext,
    revision: u64,
    fence: *catalog_authority.DispatchFence,
    fixture: bool,
};
/// Internal actual HTTPS/current-pair observation provenance, never a request
/// lease, credential export or inference entitlement. Raw bodies cannot mint it.
pub const CatalogResponse = opaque {
    pub fn responseSha256(self: *const CatalogResponse) [32]u8 {
        return catalogResponseData(self).digest;
    }
    pub fn receivedUnix(self: *const CatalogResponse) i64 {
        return catalogResponseData(self).received_unix;
    }
    pub fn recheck(self: *const CatalogResponse, ticket: *const catalog_authority.Ticket) !void {
        const d = catalogResponseData(self);
        if (!std.meta.eql(d.context, ticket.context()) or !std.meta.eql(d.lease, ticket.leaseContext()) or d.revision != ticket.committedRevision() or !ticket.matchesFence(d.fence) or !std.meta.eql(d.original.io, ticket.clockIo()) or !std.meta.eql(d.original.until, ticket.originalUntil())) return error.SiwcCatalogAuthorityChanged;
        try self.checkHeld();
        try ticket.checkActive();
    }
    fn checkHeld(self: *const CatalogResponse) !void {
        const d = catalogResponseData(self);
        if (d.fixture and !builtin.is_test) return error.SiwcCatalogAuthorityChanged;
        _ = try d.original.remaining();
        try d.fence.checkAfterIo();
        const now = std.Io.Clock.real.now(d.original.io).toSeconds();
        if (now < d.received_unix or now - d.received_unix > siwc_catalog.freshness_seconds) return error.SiwcCatalogAuthorityChanged;
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(d.body, &actual, .{});
        if (!std.crypto.timing_safe.eql([32]u8, d.digest, actual)) return error.SiwcCatalogAuthorityChanged;
        _ = try d.original.remaining();
        try d.fence.checkAfterIo();
    }
    pub fn evidence(self: *const CatalogResponse, a: std.mem.Allocator, ticket: *const catalog_authority.Ticket) !siwc_catalog.Catalog {
        try self.recheck(ticket);
        var parsed_catalog = try siwc_catalog.parse(a, 200, catalogResponseData(self).body);
        errdefer parsed_catalog.deinit();
        try self.recheck(ticket);
        return parsed_catalog;
    }
    pub fn deinit(self: *CatalogResponse) void {
        const d: *CatalogResponseData = @ptrCast(@alignCast(self));
        std.crypto.secureZero(u8, d.body);
        d.allocator.free(d.body);
        d.fence.deinit();
        d.allocator.destroy(d);
    }
};
fn catalogResponseData(self: *const CatalogResponse) *const CatalogResponseData {
    return @ptrCast(@alignCast(self));
}
pub const CatalogCompletion = struct {
    id: u64,
    owner: ?*Client = null,
    result: union(enum) { response: *CatalogResponse, failure: Failure },
    pub fn deinit(self: *CatalogCompletion, a: std.mem.Allocator) void {
        _ = a;
        switch (self.result) {
            .response => |response| response.deinit(),
            .failure => {},
        }
        if (self.owner) |owner| owner.releaseCompletion(self.id);
        self.* = undefined;
    }
};

const JwksCapture = struct {
    binding: oauth_enrollment.Binding,
    profile_sha256: [32]u8,
    issued_revision: u64,
    issued_client_id: []const u8,
};
const JwksData = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    sha256: [32]u8,
    received_unix: i64,
    original: AbsoluteDeadline,
    provenance: enum { issuer_https, fixture_loopback },
    fence: ?*oauth_authority.DispatchFence,
    capture: ?JwksCapture,
    references: std.atomic.Value(usize) = .init(1),
};
/// Only the fixed HTTPS owner completion can construct a production lease.
/// Raw key bytes, labels or a caller Boolean provide no key authority.
pub const JwksLease = opaque {
    pub fn bytes(self: *const JwksLease) []const u8 {
        return jwksData(self).bytes;
    }
    pub fn sha256(self: *const JwksLease) [32]u8 {
        return jwksData(self).sha256;
    }
    pub fn receivedUnix(self: *const JwksLease) i64 {
        return jwksData(self).received_unix;
    }
    pub fn recheckTicket(self: *const JwksLease, ticket: *const oauth_authority.IssuedTicket) !void {
        const data = jwksData(self);
        const capture = data.capture orelse return error.JwksAuthorityChanged;
        const fence = data.fence orelse return error.JwksAuthorityChanged;
        if (!std.meta.eql(capture.binding, ticket.binding()) or capture.issued_revision != ticket.committedRevision() or !std.crypto.timing_safe.eql([32]u8, capture.profile_sha256, ticket.registrationProfileSha256()) or !std.mem.eql(u8, capture.issued_client_id, ticket.issuedClientId()) or !ticket.matchesDispatchFence(fence)) return error.JwksAuthorityChanged;
        try ticket.checkBeforeVerification();
        try self.recheck(.{ .io = ticket.clockIo(), .until = ticket.originalUntil() });
    }
    pub fn recheck(self: *const JwksLease, expected: AbsoluteDeadline) !void {
        const data = jwksData(self);
        if (!std.meta.eql(data.original.io, expected.io) or !std.meta.eql(data.original.until, expected.until)) return error.JwksAuthorityChanged;
        _ = try data.original.remaining();
        if (data.fence) |fence| try fence.checkBeforeCompletion();
        if (data.provenance == .fixture_loopback and !builtin.is_test) return error.JwksAuthorityChanged;
        const now = std.Io.Clock.real.now(data.original.io).toSeconds();
        if (now < data.received_unix or now - data.received_unix > 60) return error.JwksAuthorityChanged;
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data.bytes, &actual, .{});
        if (!std.crypto.timing_safe.eql([32]u8, actual, data.sha256)) return error.JwksAuthorityChanged;
        _ = try data.original.remaining();
        if (data.fence) |fence| try fence.checkBeforeCompletion();
    }
    pub fn retain(self: *JwksLease) void {
        _ = jwksDataMut(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *JwksLease) void {
        const data = jwksDataMut(self);
        if (data.references.fetchSub(1, .acq_rel) != 1) return;
        std.crypto.secureZero(u8, data.bytes);
        data.allocator.free(data.bytes);
        if (data.capture) |capture| data.allocator.free(capture.issued_client_id);
        if (data.fence) |fence| fence.deinit();
        data.allocator.destroy(data);
    }
};
fn jwksData(self: *const JwksLease) *const JwksData {
    return @ptrCast(@alignCast(self));
}
fn jwksDataMut(self: *JwksLease) *JwksData {
    return @ptrCast(@alignCast(self));
}
pub const JwksCompletion = struct {
    id: u64,
    owner: ?*Client = null,
    result: union(enum) { lease: *JwksLease, failure: Failure },
    pub fn deinit(self: *JwksCompletion, allocator: std.mem.Allocator) void {
        _ = allocator;
        switch (self.result) {
            .lease => |lease| lease.deinit(),
            .failure => {},
        }
        if (self.owner) |owner| owner.releaseCompletion(self.id);
        self.* = undefined;
    }
};

pub const Completion = struct {
    id: u64,
    owner: ?*Client = null,
    result: union(enum) { response: Response, failure: Failure },

    pub fn deinit(self: *Completion, allocator: std.mem.Allocator) void {
        // Disposing a stream result also relinquishes unread chunks. Otherwise
        // a completed/abandoned consumer could monopolize the shared chunk ring.
        switch (self.result) {
            .response => |*response| response.deinit(allocator),
            .failure => {},
        }
        if (self.owner) |owner| owner.releaseCompletion(self.id);
        self.* = undefined;
    }
};

/// Value-owned chunks avoid allocator traffic and cap total buffered stream
/// data. Consumers must drain chunks before disposing their request's result.
pub const Chunk = struct {
    id: u64,
    bytes: [Limits.chunk_bytes]u8,
    len: usize,

    pub fn slice(self: *const Chunk) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn clear(self: *Chunk) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.* = undefined;
    }
};

fn Ring(comptime T: type, comptime capacity: usize) type {
    return struct {
        items: [capacity]T = undefined,
        read: usize = 0,
        count: usize = 0,

        fn push(self: *@This(), value: T) bool {
            if (self.count == capacity) return false;
            self.items[(self.read + self.count) % capacity] = value;
            self.count += 1;
            return true;
        }

        fn pop(self: *@This()) ?T {
            if (self.count == 0) return null;
            const value = self.items[self.read];
            std.crypto.secureZero(u8, std.mem.asBytes(&self.items[self.read]));
            self.read = (self.read + 1) % capacity;
            self.count -= 1;
            return value;
        }
    };
}

const OwnedRequest = struct {
    request: Request,
    oauth: ?oauth_authority.DispatchMaterial = null,
    catalog: ?catalog_authority.DispatchMaterial = null,
    oauth_binding: ?oauth_enrollment.Binding = null,
    oauth_profile_sha256: [32]u8 = @splat(0),
    oauth_issued_revision: u64 = 0,
    jwks: bool = false,
    jwks_fence: ?*oauth_authority.DispatchFence = null,
    jwks_capture: ?JwksCapture = null,

    fn init(allocator: std.mem.Allocator, value: Request) !OwnedRequest {
        try value.validate();
        var request = value;
        request.account_id = try allocator.dupe(u8, value.account_id);
        errdefer allocator.free(request.account_id);
        request.grant_id = try allocator.dupe(u8, value.grant_id);
        errdefer allocator.free(request.grant_id);
        request.body = try allocator.dupe(u8, value.body);
        errdefer {
            std.crypto.secureZero(u8, @constCast(request.body));
            allocator.free(request.body);
        }
        request.access_token = if (value.access_token) |token| try allocator.dupe(u8, token) else null;
        errdefer if (request.access_token) |token| {
            std.crypto.secureZero(u8, @constCast(token));
            allocator.free(token);
        };
        request.provider_account_id = if (value.provider_account_id) |id| try allocator.dupe(u8, id) else null;
        errdefer if (request.provider_account_id) |id| {
            std.crypto.secureZero(u8, @constCast(id));
            allocator.free(id);
        };
        request.browser_authorization = if (value.browser_authorization) |auth| try duplicateBrowserAuthorization(allocator, auth) else null;
        return .{ .request = request };
    }

    /// Material comes only from a consumed opaque durable-issued ticket.
    /// On failure material still belongs to the caller; success moves ownership.
    fn initOAuth(allocator: std.mem.Allocator, material: oauth_authority.DispatchMaterial) !OwnedRequest {
        try material.fence.checkBeforeDispatch();
        if (!validHandle(material.grant_id)) return error.InvalidScope;
        if (material.account_id) |account| if (!validHandle(account)) return error.InvalidScope;
        if (material.grant == .refresh and material.account_id == null) return error.InvalidScope;
        const endpoint: Endpoint = switch (material.endpoint) {
            .codex_token => .codex_oauth_token,
            .omux_oss_token => .omux_oss_oauth_token,
            .fixture_token => |port| if (fixtures_enabled and port != 0) .fixture_oauth_token else return error.UndeclaredEndpoint,
        };
        const absolute: AbsoluteDeadline = .{ .io = material.io, .until = material.until };
        const remaining = try absolute.remaining();
        var encoded = try oauth_token.encode(allocator, material.encoding, material.client_id, material.resource, material.grant);
        errdefer encoded.deinit();
        try material.fence.checkBeforeDispatch();
        _ = try absolute.remaining();
        return .{ .request = .{
            .endpoint = endpoint,
            .account_id = material.account_id orelse "",
            .grant_id = material.grant_id,
            .method = .post,
            .body = encoded.bytes,
            .absolute_deadline = absolute,
            .timeout_ms = remaining,
            .max_response_bytes = oauth_token.max_body_bytes,
            .streaming = false,
            .fixture_port = switch (material.endpoint) {
                .codex_token, .omux_oss_token => 0,
                .fixture_token => |port| port,
            },
        }, .oauth = material };
    }

    fn initCatalog(a: std.mem.Allocator, material: catalog_authority.DispatchMaterial) !OwnedRequest {
        try material.fence.checkBeforeDispatch();
        if (material.fixture_port != 0 and !builtin.is_test) return error.UndeclaredEndpoint;
        const original: AbsoluteDeadline = .{ .io = material.io, .until = material.until };
        const remaining = try original.remaining();
        const account_id = try a.dupe(u8, &material.context.account_id);
        errdefer a.free(account_id);
        const grant_id = try a.dupe(u8, &material.context.access_grant_id);
        errdefer a.free(grant_id);
        try material.fence.checkBeforeDispatch();
        _ = try original.remaining();
        return .{ .catalog = material, .request = .{
            .endpoint = if (material.fixture_port != 0) .fixture_siwc_catalog else .openai_model_catalog,
            .account_id = account_id,
            .grant_id = grant_id,
            .access_token = material.access.bytes,
            .absolute_deadline = original,
            .timeout_ms = @min(remaining, 10_000),
            .max_response_bytes = siwc_catalog.maximum_body_bytes,
            .fixture_port = material.fixture_port,
        } };
    }

    fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        if (self.catalog) |*material| {
            allocator.free(self.request.account_id);
            allocator.free(self.request.grant_id);
            material.deinit();
            return;
        }
        if (self.jwks) {
            if (self.jwks_capture) |capture| allocator.free(capture.issued_client_id);
            if (self.jwks_fence) |fence| fence.deinit();
            return;
        }
        if (self.oauth) |*material| {
            std.crypto.secureZero(u8, @constCast(self.request.body));
            allocator.free(self.request.body);
            material.deinit(allocator);
            return;
        }
        allocator.free(self.request.account_id);
        allocator.free(self.request.grant_id);
        std.crypto.secureZero(u8, @constCast(self.request.body));
        allocator.free(self.request.body);
        if (self.request.access_token) |value| {
            std.crypto.secureZero(u8, @constCast(value));
            allocator.free(value);
        }
        if (self.request.provider_account_id) |value| {
            std.crypto.secureZero(u8, @constCast(value));
            allocator.free(value);
        }
        if (self.request.browser_authorization) |*auth| destroyBrowserAuthorization(allocator, auth);
    }
};

const Transfer = struct {
    owner: *Client,
    id: u64,
    request: OwnedRequest,
    deadline: u64,
    easy: ?*c.CURL = null,
    headers: ?*c.struct_curl_slist = null,
    url: ?[:0]u8 = null,
    authorization: ?[:0]u8 = null,
    account_hint: ?[:0]u8 = null,
    cookie: ?[:0]u8 = null,
    body: std.ArrayList(u8) = .empty,
    received: usize = 0,
    response_received_unix: ?i64 = null,
    paused: bool = false,
    failure: ?Failure = null,
    oauth_dispatch_started: bool = false,
    catalog_dispatch_started: bool = false,

    fn deinit(self: *Transfer) void {
        const allocator = self.owner.allocator;
        if (self.easy) |easy| c.curl_easy_cleanup(easy);
        if (self.headers) |headers| {
            // curl_slist_append duplicates each header. Wipe those copies too.
            var node: ?*c.struct_curl_slist = headers;
            while (node) |item| {
                std.crypto.secureZero(u8, std.mem.span(item.data));
                node = item.next;
            }
            c.curl_slist_free_all(headers);
        }
        if (self.url) |url| allocator.free(url);
        if (self.authorization) |auth| {
            std.crypto.secureZero(u8, auth);
            allocator.free(auth);
        }
        if (self.account_hint) |hint| {
            std.crypto.secureZero(u8, hint);
            allocator.free(hint);
        }
        if (self.cookie) |cookie| {
            std.crypto.secureZero(u8, cookie);
            allocator.free(cookie);
        }
        std.crypto.secureZero(u8, self.body.items);
        self.body.deinit(allocator);
        self.request.deinit(allocator);
        allocator.destroy(self);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    multi: *c.CURLM,
    ca_bundle: ?[:0]u8 = null,
    thread: ?std.Thread = null,
    lock_value: std.atomic.Value(u8) = .init(0),
    stopping: bool = false,
    closed: bool = false,
    next_id: u64 = 1,
    outstanding: usize = 0,
    starts: Ring(*Transfer, Limits.outstanding) = .{},
    cancels: Ring(u64, Limits.outstanding) = .{},
    results: Ring(Completion, Limits.outstanding) = .{},
    oauth_results: Ring(OAuthCompletion, Limits.outstanding) = .{},
    jwks_results: Ring(JwksCompletion, Limits.outstanding) = .{},
    catalog_results: Ring(CatalogCompletion, Limits.outstanding) = .{},
    chunks: Ring(Chunk, Limits.chunks) = .{},
    active: [Limits.concurrent]?*Transfer = @splat(null),

    /// curl global initialization is process-owned: no client calls global
    /// cleanup while another client or another dependency may still use curl.
    /// The allocator must support concurrent owner/caller allocations. Daemon
    /// callers use std.heap.smp_allocator; tests use the thread-safe test heap.
    pub fn init(allocator: std.mem.Allocator) !*Client {
        // Portable package launchers explicitly supply their declared public CA
        // bundle. This environment input controls trust, never provider routing
        // or credentials. Native Nix development uses the pinned curl default.
        const ca_bundle = if (std.c.getenv("OMUX_CA_BUNDLE")) |value| std.mem.span(value) else null;
        return initWithTrust(allocator, .{ .ca_bundle_path = ca_bundle });
    }

    pub const Trust = struct {
        ca_bundle_path: ?[]const u8 = null,

        pub fn validate(self: Trust) !void {
            if (self.ca_bundle_path) |path| {
                if (path.len == 0 or path.len > 4096 or path[0] != '/') return error.InvalidTrustConfiguration;
                for (path) |byte| if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidTrustConfiguration;
            }
        }
    };

    pub fn initWithTrust(allocator: std.mem.Allocator, trust: Trust) !*Client {
        try trust.validate();
        if (c.curl_global_init(c.CURL_GLOBAL_DEFAULT) != c.CURLE_OK) return error.CurlInit;
        const version = c.curl_version_info(c.CURLVERSION_NOW) orelse return error.CurlInit;
        // A synchronous DNS backend could block the owner despite cancellation
        // or deadlines; accept only the flake's verified async resolver/TLS build.
        if (version[0].features & c.CURL_VERSION_ASYNCHDNS == 0 or version[0].features & c.CURL_VERSION_SSL == 0) return error.UnsupportedCurlFeatures;
        const multi = c.curl_multi_init() orelse return error.CurlInit;
        errdefer _ = c.curl_multi_cleanup(multi);
        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);
        self.* = .{ .allocator = allocator, .multi = multi };
        self.ca_bundle = if (trust.ca_bundle_path) |path| try allocator.dupeSentinel(u8, path, 0) else null;
        errdefer if (self.ca_bundle) |path| allocator.free(path);
        self.thread = try std.Thread.spawn(.{}, ownerMain, .{self});
        return self;
    }

    pub fn deinit(self: *Client) void {
        self.lock();
        self.stopping = true;
        self.unlock();
        self.wakeup();
        self.thread.?.join();
        while (self.poll()) |item| {
            var completion = item;
            completion.deinit(self.allocator);
        }
        while (self.pollOAuth()) |item| {
            var completion = item;
            completion.deinit(self.allocator);
        }
        while (self.pollCatalog()) |item| {
            var completion = item;
            completion.deinit(self.allocator);
        }
        while (self.pollJwks()) |item| {
            var completion = item;
            completion.deinit(self.allocator);
        }
        while (self.pollChunk()) |item| {
            var chunk = item;
            chunk.clear();
        }
        _ = c.curl_multi_cleanup(self.multi);
        if (self.ca_bundle) |path| self.allocator.free(path);
        self.ca_bundle = null;
        self.lock();
        self.closed = true;
        const destroy_now = self.outstanding == 0;
        self.unlock();
        // A consumed owned response may outlive shutdown. Its admission lease
        // retains this small owner object until that completion is disposed.
        if (destroy_now) self.allocator.destroy(self);
    }

    pub fn submit(self: *Client, request: Request) !u64 {
        try request.validate();
        self.lock();
        if (self.stopping) {
            self.unlock();
            return error.Stopping;
        }
        if (self.outstanding == Limits.outstanding) {
            self.unlock();
            return error.Backpressure;
        }
        if (self.next_id == std.math.maxInt(u64)) {
            self.unlock();
            return error.IdExhausted;
        }
        const id = self.next_id;
        self.next_id += 1;
        self.outstanding += 1;
        self.unlock();
        const admitted_at = monotonicMilliseconds();
        errdefer self.releaseReservation();
        var owned = try OwnedRequest.init(self.allocator, request);
        errdefer owned.deinit(self.allocator);
        const transfer = try self.allocator.create(Transfer);
        errdefer self.allocator.destroy(transfer);
        self.lock();
        defer self.unlock();
        if (self.stopping) return error.Stopping;
        // Allocation follows reservation: concurrent rejected submits cannot
        // allocate outside the outstanding request budget. Original absolute
        // expiry after that work refuses before any transfer is enqueued.
        if (request.absolute_deadline) |deadline| _ = try deadline.remaining();
        transfer.* = .{ .owner = self, .id = id, .request = owned, .deadline = admitted_at + request.timeout_ms };
        std.debug.assert(self.starts.push(transfer));
        self.wakeup();
        return id;
    }

    /// No URL/token/profile/Boolean control request can call this path. Claim
    /// consumes the retained ticket before any HTTP admission or allocation;
    /// failures cannot replay it. The actor records issued uncertainty.
    pub fn startOAuth(self: *Client, ticket: *oauth_authority.IssuedTicket) !u64 {
        var material: ?oauth_authority.DispatchMaterial = try ticket.claim(self.allocator);
        defer if (material) |*value| value.deinit(self.allocator);
        errdefer if (material) |*value| {
            _ = value.fence.invalidate();
        };
        self.lock();
        if (self.stopping) {
            self.unlock();
            return error.Stopping;
        }
        if (self.outstanding == Limits.outstanding) {
            self.unlock();
            return error.Backpressure;
        }
        if (self.next_id == std.math.maxInt(u64)) {
            self.unlock();
            return error.IdExhausted;
        }
        const id = self.next_id;
        self.next_id += 1;
        self.outstanding += 1;
        self.unlock();
        errdefer self.releaseReservation();
        const admitted_at = monotonicMilliseconds();
        var owned = try OwnedRequest.initOAuth(self.allocator, material.?);
        material = null;
        errdefer {
            _ = owned.oauth.?.fence.invalidate();
            owned.deinit(self.allocator);
        }
        owned.oauth_binding = ticket.binding();
        owned.oauth_profile_sha256 = ticket.registrationProfileSha256();
        owned.oauth_issued_revision = ticket.committedRevision();
        if (builtin.is_test) if (ticket.modelRoutes()) |routes| {
            if (owned.request.endpoint != .omux_oss_oauth_token or routes.token_port == 0 or routes.jwks_port == 0) return error.InvalidScope;
            owned.request.endpoint = .fixture_oss_oauth_token;
            owned.request.fixture_port = routes.token_port;
        };
        const transfer = try self.allocator.create(Transfer);
        errdefer self.allocator.destroy(transfer);
        self.lock();
        defer self.unlock();
        if (self.stopping) return error.Stopping;
        try owned.oauth.?.fence.checkBeforeDispatch();
        _ = try owned.request.absolute_deadline.?.remaining();
        transfer.* = .{ .owner = self, .id = id, .request = owned, .deadline = admitted_at + owned.request.timeout_ms };
        std.debug.assert(self.starts.push(transfer));
        self.wakeup();
        return id;
    }

    /// Public key discovery has its own fixed route and result provenance. It
    /// never borrows resource/request credentials or permits arbitrary URLs.
    pub fn startJwks(self: *Client, ticket: *oauth_authority.IssuedTicket) !u64 {
        try ticket.claimJwks();
        const fence = ticket.retainFence();
        errdefer {
            _ = fence.invalidate();
            fence.deinit();
        }
        var port: u16 = 0;
        if (builtin.is_test) if (ticket.modelRoutes()) |routes| {
            if (routes.token_port == 0 or routes.jwks_port == 0) return error.InvalidScope;
            port = routes.jwks_port;
        };
        return self.enqueueJwks(.{ .io = ticket.clockIo(), .until = ticket.originalUntil() }, port, fence, .{ .binding = ticket.binding(), .profile_sha256 = ticket.registrationProfileSha256(), .issued_revision = ticket.committedRevision(), .issued_client_id = ticket.issuedClientId() });
    }

    /// The retained fence moves only on success; fixture-only raw deadlines
    /// cannot construct shipping key authority.
    fn enqueueJwks(self: *Client, original: AbsoluteDeadline, fixture_port: u16, fence: ?*oauth_authority.DispatchFence, capture: ?JwksCapture) !u64 {
        if (fixture_port != 0 and !builtin.is_test) return error.UndeclaredEndpoint;
        if (fixture_port == 0 and (fence == null or capture == null)) return error.JwksAuthorityChanged;
        if (capture) |selected| if (selected.issued_client_id.len == 0 or selected.issued_client_id.len > 256) return error.JwksAuthorityChanged;
        if (fence) |value| try value.checkBeforeCompletion();
        const nanoseconds = original.until.durationFromNow(original.io).raw.toNanoseconds();
        if (nanoseconds <= 0 or nanoseconds > 120_000_000_000) return error.InvalidDeadline;
        const remaining = try original.remaining();
        self.lock();
        if (self.stopping) {
            self.unlock();
            return error.Stopping;
        }
        if (self.outstanding == Limits.outstanding) {
            self.unlock();
            return error.Backpressure;
        }
        if (self.next_id == std.math.maxInt(u64)) {
            self.unlock();
            return error.IdExhausted;
        }
        const id = self.next_id;
        self.next_id += 1;
        self.outstanding += 1;
        self.unlock();
        errdefer self.releaseReservation();
        const admitted_at = monotonicMilliseconds();
        var retained_capture = capture;
        if (retained_capture) |*selected| selected.issued_client_id = try self.allocator.dupe(u8, selected.issued_client_id);
        errdefer if (retained_capture) |selected| self.allocator.free(selected.issued_client_id);
        const transfer = try self.allocator.create(Transfer);
        errdefer self.allocator.destroy(transfer);
        self.lock();
        defer self.unlock();
        if (self.stopping) return error.Stopping;
        _ = try original.remaining();
        if (fence) |value| try value.checkBeforeCompletion();
        transfer.* = .{
            .owner = self,
            .id = id,
            .request = .{
                .request = .{
                    .endpoint = if (fixture_port == 0) .openai_jwks else .fixture_jwks,
                    .account_id = "",
                    .grant_id = "",
                    .absolute_deadline = original,
                    .timeout_ms = remaining,
                    .max_response_bytes = oauth_token.max_body_bytes,
                    .fixture_port = fixture_port,
                },
                .jwks = true,
                .jwks_fence = fence,
                .jwks_capture = retained_capture,
            },
            .deadline = admitted_at + remaining,
        };
        std.debug.assert(self.starts.push(transfer));
        self.wakeup();
        return id;
    }

    /// Actual actor/current-pair ticket only. Generic ATs, source labels or a
    /// native thread placeholder cannot enter this observation result channel.
    pub fn startCatalog(self: *Client, ticket: *catalog_authority.Ticket) !u64 {
        var material: ?catalog_authority.DispatchMaterial = try ticket.claim(self.allocator);
        defer if (material) |*held| held.deinit();
        errdefer if (material) |*held| {
            _ = held.fence.invalidate();
        };
        self.lock();
        if (self.stopping) {
            self.unlock();
            return error.Stopping;
        }
        if (self.outstanding == Limits.outstanding) {
            self.unlock();
            return error.Backpressure;
        }
        if (self.next_id == std.math.maxInt(u64)) {
            self.unlock();
            return error.IdExhausted;
        }
        const id = self.next_id;
        self.next_id += 1;
        self.outstanding += 1;
        self.unlock();
        errdefer self.releaseReservation();
        const admitted_at = monotonicMilliseconds();
        var owned = try OwnedRequest.initCatalog(self.allocator, material.?);
        material = null;
        errdefer {
            _ = owned.catalog.?.fence.invalidate();
            owned.deinit(self.allocator);
        }
        const transfer = try self.allocator.create(Transfer);
        errdefer self.allocator.destroy(transfer);
        self.lock();
        defer self.unlock();
        if (self.stopping) return error.Stopping;
        try owned.catalog.?.fence.checkBeforeDispatch();
        _ = try owned.request.absolute_deadline.?.remaining();
        transfer.* = .{ .owner = self, .id = id, .request = owned, .deadline = admitted_at + owned.request.timeout_ms };
        std.debug.assert(self.starts.push(transfer));
        self.wakeup();
        return id;
    }
    pub fn pollCatalog(self: *Client) ?CatalogCompletion {
        self.lock();
        defer self.unlock();
        return self.catalog_results.pop();
    }

    pub fn cancel(self: *Client, id: u64) !void {
        self.lock();
        defer self.unlock();
        if (self.stopping) return error.Stopping;
        if (!self.cancels.push(id)) return error.Backpressure;
        self.wakeup();
    }

    pub fn fetchJson(self: *Client, request: Request) !u64 {
        if (request.streaming) return error.StreamingResponse;
        return self.submit(request);
    }

    pub fn fetchIdentity(self: *Client, request: Request) !u64 {
        if (!request.endpoint.provesIdentity()) return error.NotAnIdentityEndpoint;
        if (request.access_token == null and request.browser_authorization == null) return error.AuthenticationRequired;
        return self.fetchJson(request);
    }

    /// An explicit abandon is cancellation plus release of buffered payload.
    pub fn abandon(self: *Client, id: u64) !void {
        try self.cancel(id);
        self.discardChunks(id);
    }

    pub fn discardChunks(self: *Client, id: u64) void {
        self.lock();
        const count = self.chunks.count;
        for (0..count) |_| {
            var item = self.chunks.pop().?;
            if (item.id == id) item.clear() else std.debug.assert(self.chunks.push(item));
        }
        // Shutdown sets stopping under this same lock before freeing CURLM.
        if (!self.stopping) self.wakeup();
        self.unlock();
    }

    fn releaseCompletion(self: *Client, id: u64) void {
        self.discardChunks(id);
        self.releaseReservation();
    }

    fn releaseReservation(self: *Client) void {
        self.lock();
        self.outstanding -= 1;
        const destroy_now = self.closed and self.outstanding == 0;
        self.unlock();
        if (destroy_now) self.allocator.destroy(self);
    }

    pub fn poll(self: *Client) ?Completion {
        self.lock();
        defer self.unlock();
        const result = self.results.pop() orelse return null;
        return result;
    }

    /// Token bodies never enter poll(), used by resource/identity observers.
    pub fn pollOAuth(self: *Client) ?OAuthCompletion {
        self.lock();
        defer self.unlock();
        return self.oauth_results.pop();
    }

    pub fn pollJwks(self: *Client) ?JwksCompletion {
        self.lock();
        defer self.unlock();
        return self.jwks_results.pop();
    }

    pub fn pollChunk(self: *Client) ?Chunk {
        self.lock();
        const result = self.chunks.pop();
        if (result != null and !self.stopping) self.wakeup();
        self.unlock();
        return result;
    }

    fn lock(self: *Client) void {
        while (self.lock_value.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Client) void {
        self.lock_value.store(0, .release);
    }

    fn wakeup(self: *Client) void {
        _ = c.curl_multi_wakeup(self.multi);
    }

    fn ownerMain(self: *Client) void {
        while (true) {
            self.lock();
            const stopping = self.stopping;
            self.unlock();
            if (stopping) break;
            self.processCancels();
            for (&self.active) |*slot| {
                if (slot.* != null) continue;
                self.lock();
                const transfer = self.starts.pop();
                self.unlock();
                const item = transfer orelse break;
                if (transferExpired(item)) {
                    self.complete(item, .deadline);
                    continue;
                }
                if (!oauthFenceLive(item)) {
                    self.complete(item, .canceled);
                    continue;
                }
                self.configure(item) catch |err| {
                    self.complete(item, if (err == error.OutOfMemory) .allocation else if (err == error.InvalidDeadline) .deadline else .transport);
                    continue;
                };
                if (transferExpired(item)) {
                    self.complete(item, .deadline);
                    continue;
                }
                if (item.request.catalog) |*material| {
                    material.fence.beginDispatch() catch {
                        self.complete(item, .canceled);
                        continue;
                    };
                    item.catalog_dispatch_started = true;
                } else if (item.request.oauth) |*material| {
                    material.fence.beginDispatch() catch {
                        self.complete(item, .canceled);
                        continue;
                    };
                    item.oauth_dispatch_started = true;
                } else if (item.request.jwks_fence) |fence| {
                    // Key lookup is part of the already issued operation; it
                    // cannot spend the token CAS again or renew its lifetime.
                    fence.checkBeforeCompletion() catch {
                        self.complete(item, .canceled);
                        continue;
                    };
                }
                if (c.curl_multi_add_handle(self.multi, item.easy.?) != c.CURLM_OK) {
                    self.complete(item, .transport);
                    continue;
                }
                slot.* = item;
            }
            for (&self.active) |*slot| {
                if (slot.*) |transfer| {
                    if (transferExpired(transfer)) {
                        _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                        slot.* = null;
                        self.complete(transfer, .deadline);
                    } else if (!oauthFenceLive(transfer)) {
                        _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                        slot.* = null;
                        self.complete(transfer, .canceled);
                    } else if (transfer.paused) {
                        self.lock();
                        const can_resume = self.chunks.count < Limits.chunks;
                        self.unlock();
                        if (can_resume) {
                            transfer.paused = false;
                            if (c.curl_easy_pause(transfer.easy.?, c.CURLPAUSE_CONT) != c.CURLE_OK) {
                                _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                                slot.* = null;
                                self.complete(transfer, .transport);
                            }
                        }
                    }
                }
            }
            var running: c_int = 0;
            if (c.curl_multi_perform(self.multi, &running) != c.CURLM_OK) {
                self.cancelActive(.transport);
            }
            var remaining: c_int = 0;
            while (c.curl_multi_info_read(self.multi, &remaining)) |message| {
                if (message.*.msg != c.CURLMSG_DONE) continue;
                // curl invalidates CURLMsg storage upon handle removal.
                const completed_handle = message.*.easy_handle;
                const completed_code = message.*.data.result;
                for (&self.active) |*slot| {
                    if (slot.*) |transfer| {
                        if (transfer.easy != completed_handle) continue;
                        _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                        slot.* = null;
                        self.complete(transfer, if (transferExpired(transfer)) .deadline else transfer.failure orelse failureFromCurl(completed_code));
                        break;
                    }
                }
            }
            var count: c_int = 0;
            // Bounded fallback polling also covers a missed wakeup on admission.
            if (c.curl_multi_poll(self.multi, null, 0, 25, &count) != c.CURLM_OK) self.cancelActive(.transport);
        }
        self.cancelActive(.canceled);
        while (true) {
            self.lock();
            const queued = self.starts.pop();
            self.unlock();
            self.complete(queued orelse break, .canceled);
        }
    }

    fn processCancels(self: *Client) void {
        // A producer continuously refilling the cancel queue must not starve
        // deadline checks or network progress on other accounts.
        for (0..Limits.outstanding) |_| {
            self.lock();
            const id = self.cancels.pop();
            self.unlock();
            const canceled = id orelse break;
            for (&self.active) |*slot| {
                if (slot.*) |transfer| {
                    if (transfer.id == canceled) {
                        _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                        slot.* = null;
                        self.complete(transfer, .canceled);
                    }
                }
            }
            self.lock();
            // Rotate once rather than allocate a second pending queue.
            const pending = self.starts.count;
            var removed: ?*Transfer = null;
            for (0..pending) |_| {
                const transfer = self.starts.pop().?;
                if (transfer.id == canceled) removed = transfer else std.debug.assert(self.starts.push(transfer));
            }
            self.unlock();
            if (removed) |transfer| self.complete(transfer, .canceled);
        }
    }

    fn cancelActive(self: *Client, failure: Failure) void {
        for (&self.active) |*slot| {
            if (slot.*) |transfer| {
                _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                slot.* = null;
                self.complete(transfer, failure);
            }
        }
    }

    fn configure(self: *Client, transfer: *Transfer) !void {
        const request = transfer.request.request;
        // Reserve the bounded token-response buffer before endpoint dispatch.
        // Appending secret bytes must never realloc/free an unwiped old buffer.
        if (transfer.request.catalog != null) try transfer.body.ensureTotalCapacity(self.allocator, siwc_catalog.maximum_body_bytes) else if (transfer.request.oauth != null or transfer.request.jwks) try transfer.body.ensureTotalCapacity(self.allocator, oauth_token.max_body_bytes);
        const easy = c.curl_easy_init() orelse return error.CurlInit;
        transfer.easy = easy;
        transfer.url = if (request.endpoint == .fixture_identity or request.endpoint == .fixture_tls_identity or request.endpoint == .fixture_oauth_token or request.endpoint == .fixture_oss_oauth_token or request.endpoint == .fixture_jwks or request.endpoint == .fixture_siwc_catalog)
            try self.allocator.printSentinel("{s}:{d}{s}", .{ request.endpoint.origin(), request.fixture_port, request.endpoint.path() }, 0)
        else
            try self.allocator.printSentinel("{s}{s}", .{ request.endpoint.origin(), request.endpoint.path() }, 0);
        try setPointer(easy, c.CURLOPT_URL, transfer.url.?.ptr);
        const protocols: [*:0]const u8 = if (request.endpoint == .fixture_identity or request.endpoint == .fixture_oauth_token or request.endpoint == .fixture_oss_oauth_token or request.endpoint == .fixture_jwks or request.endpoint == .fixture_siwc_catalog) "http" else "https";
        try setPointer(easy, c.CURLOPT_PROTOCOLS_STR, protocols);
        try setPointer(easy, c.CURLOPT_REDIR_PROTOCOLS_STR, "https");
        try setLong(easy, c.CURLOPT_FOLLOWLOCATION, 0);
        try setLong(easy, c.CURLOPT_MAXREDIRS, 0);
        try setLong(easy, c.CURLOPT_SSL_VERIFYPEER, 1);
        try setLong(easy, c.CURLOPT_SSL_VERIFYHOST, 2);
        if (self.ca_bundle) |path| {
            try setPointer(easy, c.CURLOPT_CAINFO, path.ptr);
            // NULL removes the compile-time Nix CAPATH fallback. The public CA
            // file supplied by the portable package is the sole bundle input.
            try setPointer(easy, c.CURLOPT_CAPATH, @as(?[*:0]const u8, null));
        } else if (builtin.os.tag == .macos) {
            try setLong(easy, c.CURLOPT_SSL_OPTIONS, c.CURLSSLOPT_NATIVE_CA);
        }
        try setLong(easy, c.CURLOPT_NOSIGNAL, 1);
        try setLong(easy, c.CURLOPT_NETRC, c.CURL_NETRC_IGNORED);
        try setPointer(easy, c.CURLOPT_PROXY, "");
        try setPointer(easy, c.CURLOPT_NOPROXY, "*");
        try setLong(easy, c.CURLOPT_UNRESTRICTED_AUTH, 0);
        try setLong(easy, c.CURLOPT_HTTP_VERSION, c.CURL_HTTP_VERSION_1_1);
        try setLong(easy, c.CURLOPT_FRESH_CONNECT, 1);
        try setLong(easy, c.CURLOPT_FORBID_REUSE, 1);
        try setLong(easy, c.CURLOPT_HTTP_CONTENT_DECODING, 0);
        try setPointer(easy, c.CURLOPT_ACCEPT_ENCODING, "identity");
        try setPointer(easy, c.CURLOPT_USERAGENT, "omux/0.2.0-dev");
        var remaining = @max(1, transfer.deadline -| monotonicMilliseconds());
        if (request.absolute_deadline) |deadline| remaining = @min(remaining, try deadline.remaining());
        try setLong(easy, c.CURLOPT_CONNECTTIMEOUT_MS, @intCast(@min(remaining, 10_000)));
        try setLong(easy, c.CURLOPT_TIMEOUT_MS, @intCast(remaining));
        try setPointer(easy, c.CURLOPT_WRITEDATA, transfer);
        if (c.curl_easy_setopt(easy, c.CURLOPT_WRITEFUNCTION, @as(*const fn ([*c]u8, usize, usize, ?*anyopaque) callconv(.c) usize, writeCallback)) != c.CURLE_OK) return error.CurlOption;
        try appendHeader(transfer, "Accept: application/json");
        if (request.endpoint == .github_identity or request.endpoint == .github_capacity) try appendHeader(transfer, "X-GitHub-Api-Version: 2022-11-28");
        if (request.access_token) |token| {
            transfer.authorization = try self.allocator.printSentinel("Authorization: Bearer {s}", .{token}, 0);
            try appendHeader(transfer, transfer.authorization.?.ptr);
        }
        if (request.provider_account_id) |hint| {
            transfer.account_hint = try self.allocator.printSentinel("ChatGPT-Account-Id: {s}", .{hint}, 0);
            try appendHeader(transfer, transfer.account_hint.?.ptr);
        }
        if (request.browser_authorization) |auth| {
            const now = wallClockSeconds();
            if (auth.custody_until_unix <= now or (auth.provider_expires_unix != null and auth.provider_expires_unix.? <= now)) return error.CredentialExpired;
            transfer.cookie = try self.allocator.dupeSentinel(u8, auth.bytes, 0);
            try setPointer(easy, c.CURLOPT_COOKIE, transfer.cookie.?.ptr);
        }
        if (request.method == .post) {
            const material = transfer.request.oauth orelse return error.UndeclaredMethod;
            try appendHeader(transfer, switch (material.encoding) {
                .form => "Content-Type: application/x-www-form-urlencoded",
                .json => "Content-Type: application/json",
            });
            try setLong(easy, c.CURLOPT_POST, 1);
            try setLong(easy, c.CURLOPT_POSTFIELDSIZE, @intCast(request.body.len));
            try setPointer(easy, c.CURLOPT_POSTFIELDS, request.body.ptr);
        }
        try setPointer(easy, c.CURLOPT_HTTPHEADER, transfer.headers);
    }

    fn complete(self: *Client, transfer: *Transfer, failure: ?Failure) void {
        var result: Completion = .{ .id = transfer.id, .owner = self, .result = .{ .failure = .transport } };
        if (failure) |reason| {
            result.result = .{ .failure = reason };
        } else {
            var status: c_long = 0;
            if (c.curl_easy_getinfo(transfer.easy.?, c.CURLINFO_RESPONSE_CODE, &status) != c.CURLE_OK or status < 100 or status > 599) {
                result.result = .{ .failure = .transport };
            } else if (if (transfer.request.catalog != null or transfer.request.oauth != null or transfer.request.jwks) self.allocator.dupe(u8, transfer.body.items) else transfer.body.toOwnedSlice(self.allocator)) |body| {
                // OAuth keeps the original allocation held until deinit wipes
                // it; toOwnedSlice could shrink by freeing unwiped old storage.
                result.result = .{ .response = .{ .status = @intCast(status), .body = body, .streaming = transfer.request.request.streaming } };
            } else |_| result.result = .{ .failure = .allocation };
        }
        // Allocation/readback at completion also consumes the same original
        // trusted cutoff; a successful curl result cannot renew it.
        if (transfer.request.request.absolute_deadline) |deadline| if (deadline.expired()) {
            if (result.result == .response) {
                std.crypto.secureZero(u8, result.result.response.body);
                self.allocator.free(result.result.response.body);
            }
            result.result = .{ .failure = .deadline };
        };
        // Retained cancellation/tuple/cutoff remains live after curl and
        // response ownership allocation. Late retirement cannot publish tokens.
        if (!oauthFenceLive(transfer)) {
            if (result.result == .response) {
                std.crypto.secureZero(u8, result.result.response.body);
                self.allocator.free(result.result.response.body);
            }
            result.result = .{ .failure = if (transferExpired(transfer)) .deadline else .canceled };
        }
        switch (result.result) {
            .failure => {
                if (transfer.request.oauth) |*material| _ = material.fence.invalidate();
                if (transfer.request.jwks_fence) |fence| _ = fence.invalidate();
                self.discardChunks(transfer.id);
            },
            .response => {},
        }
        var token_result: ?OAuthCompletion = null;
        if (transfer.request.oauth != null) {
            token_result = .{ .id = result.id, .owner = self, .result = .{ .failure = .transport } };
            switch (result.result) {
                .failure => |reason| token_result.?.result = .{ .failure = reason },
                .response => |response| {
                    if (self.retainOAuthResponse(transfer, response)) |retained| {
                        token_result.?.result = .{ .response = retained };
                    } else |err| {
                        std.crypto.secureZero(u8, response.body);
                        self.allocator.free(response.body);
                        if (transfer.request.oauth) |*material| _ = material.fence.invalidate();
                        token_result.?.result = .{ .failure = if (err == error.OutOfMemory) .allocation else if (err == error.InvalidDeadline) .deadline else .canceled };
                    }
                },
            }
        }
        var key_result: ?JwksCompletion = null;
        if (transfer.request.jwks) {
            key_result = .{ .id = result.id, .owner = self, .result = .{ .failure = .transport } };
            switch (result.result) {
                .failure => |reason| key_result.?.result = .{ .failure = reason },
                .response => |response| {
                    if (self.retainJwksResponse(transfer, response)) |lease| {
                        key_result.?.result = .{ .lease = lease };
                    } else |err| {
                        std.crypto.secureZero(u8, response.body);
                        self.allocator.free(response.body);
                        if (transfer.request.jwks_fence) |fence| _ = fence.invalidate();
                        key_result.?.result = .{ .failure = if (err == error.OutOfMemory) .allocation else if (err == error.InvalidDeadline) .deadline else .transport };
                    }
                },
            }
        }
        var catalog_result: ?CatalogCompletion = null;
        if (transfer.request.catalog != null) {
            catalog_result = .{ .id = result.id, .owner = self, .result = .{ .failure = .transport } };
            switch (result.result) {
                .failure => |reason| catalog_result.?.result = .{ .failure = reason },
                .response => |response| {
                    if (self.retainCatalogResponse(transfer, response)) |held| {
                        catalog_result.?.result = .{ .response = held };
                    } else |err| {
                        std.crypto.secureZero(u8, response.body);
                        self.allocator.free(response.body);
                        catalog_result.?.result = .{ .failure = if (err == error.OutOfMemory) .allocation else if (err == error.InvalidDeadline) .deadline else .transport };
                    }
                },
            }
        }
        transfer.deinit();
        self.lock();
        if (catalog_result) |models| {
            std.debug.assert(self.catalog_results.push(models));
        } else if (key_result) |keys| {
            std.debug.assert(self.jwks_results.push(keys));
        } else if (token_result) |tokens| {
            std.debug.assert(self.oauth_results.push(tokens));
        } else {
            std.debug.assert(self.results.push(result));
        }
        self.unlock();
    }

    fn retainCatalogResponse(self: *Client, transfer: *const Transfer, response: Response) !*CatalogResponse {
        const material = transfer.request.catalog orelse return error.SiwcCatalogAuthorityChanged;
        const request = transfer.request.request;
        if (!transfer.catalog_dispatch_started or response.status != 200 or response.body.len == 0 or response.body.len > siwc_catalog.maximum_body_bytes or request.method != .get or request.streaming or request.browser_authorization != null or request.provider_account_id != null or request.access_token == null or !std.mem.eql(u8, request.access_token.?, material.access.bytes)) return error.SiwcCatalogAuthorityChanged;
        const fixture = switch (request.endpoint) {
            .openai_model_catalog => false,
            .fixture_siwc_catalog => if (builtin.is_test) true else return error.UndeclaredEndpoint,
            else => return error.UndeclaredEndpoint,
        };
        const original = request.absolute_deadline orelse return error.InvalidDeadline;
        _ = try original.remaining();
        try material.fence.checkAfterIo();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(response.body, &digest, .{});
        const d = try self.allocator.create(CatalogResponseData);
        errdefer self.allocator.destroy(d);
        d.* = .{ .allocator = self.allocator, .body = response.body, .digest = digest, .received_unix = transfer.response_received_unix orelse return error.SiwcCatalogAuthorityChanged, .original = original, .context = material.context, .lease = material.lease, .revision = material.committed_revision, .fence = material.fence, .fixture = fixture };
        const retained: *CatalogResponse = @ptrCast(d);
        try retained.checkHeld();
        material.fence.retain();
        return retained;
    }

    /// Body ownership moves only on success; no exposed raw response factory.
    fn retainOAuthResponse(self: *Client, transfer: *const Transfer, response: Response) !*OAuthResponse {
        const material = transfer.request.oauth orelse return error.OAuthResponseAuthorityChanged;
        const request = transfer.request.request;
        if (!transfer.oauth_dispatch_started or request.method != .post or request.streaming or request.access_token != null or request.browser_authorization != null or request.provider_account_id != null) return error.OAuthResponseAuthorityChanged;
        switch (request.endpoint) {
            .codex_oauth_token, .omux_oss_oauth_token => {},
            .fixture_oauth_token, .fixture_oss_oauth_token => if (!builtin.is_test) return error.OAuthResponseAuthorityChanged,
            else => return error.OAuthResponseAuthorityChanged,
        }
        const original = request.absolute_deadline orelse return error.InvalidDeadline;
        const binding = transfer.request.oauth_binding orelse return error.OAuthResponseAuthorityChanged;
        if (response.body.len > oauth_token.max_body_bytes) return error.OAuthResponseAuthorityChanged;
        _ = try original.remaining();
        try material.fence.checkBeforeCompletion();
        const data = try self.allocator.create(OAuthResponseData);
        errdefer self.allocator.destroy(data);
        const client_id = try self.allocator.dupe(u8, material.client_id);
        errdefer self.allocator.free(client_id);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(response.body, &digest, .{});
        data.* = .{ .allocator = self.allocator, .status = response.status, .body = response.body, .sha256 = digest, .received_unix = transfer.response_received_unix orelse std.Io.Clock.real.now(original.io).toSeconds(), .original = original, .binding = binding, .profile_sha256 = transfer.request.oauth_profile_sha256, .issued_revision = transfer.request.oauth_issued_revision, .issued_client_id = client_id, .endpoint = request.endpoint, .fence = material.fence };
        const retained: *OAuthResponse = @ptrCast(data);
        try retained.checkHeld();
        material.fence.retain();
        return retained;
    }

    /// Body ownership moves only on success. This constructor is private to
    /// the actual curl owner, not exposed as a raw-key/source-Boolean factory.
    fn retainJwksResponse(self: *Client, transfer: *const Transfer, response: Response) !*JwksLease {
        const request = transfer.request.request;
        if (!transfer.request.jwks or response.status != 200 or response.body.len == 0 or response.body.len > oauth_token.max_body_bytes) return error.InvalidJwksResponse;
        if (request.method != .get or request.streaming or request.access_token != null or request.browser_authorization != null or request.provider_account_id != null) return error.InvalidJwksResponse;
        const provenance: @FieldType(JwksData, "provenance") = switch (request.endpoint) {
            .openai_jwks => if (transfer.request.jwks_fence != null and transfer.request.jwks_capture != null) .issuer_https else return error.JwksAuthorityChanged,
            .fixture_jwks => if (builtin.is_test) .fixture_loopback else return error.UndeclaredEndpoint,
            else => return error.UndeclaredEndpoint,
        };
        const original = request.absolute_deadline orelse return error.InvalidDeadline;
        _ = try original.remaining();
        const data = try self.allocator.create(JwksData);
        errdefer self.allocator.destroy(data);
        var capture = transfer.request.jwks_capture;
        if (capture) |*selected| selected.issued_client_id = try self.allocator.dupe(u8, selected.issued_client_id);
        errdefer if (capture) |selected| self.allocator.free(selected.issued_client_id);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(response.body, &digest, .{});
        data.* = .{ .allocator = self.allocator, .bytes = response.body, .sha256 = digest, .received_unix = transfer.response_received_unix orelse std.Io.Clock.real.now(original.io).toSeconds(), .original = original, .provenance = provenance, .fence = transfer.request.jwks_fence, .capture = capture };
        const lease: *JwksLease = @ptrCast(data);
        try lease.recheck(original);
        if (data.fence) |fence| fence.retain();
        return lease;
    }
};

fn appendHeader(transfer: *Transfer, value: [*:0]const u8) !void {
    const headers = c.curl_slist_append(transfer.headers, value) orelse return error.OutOfMemory;
    transfer.headers = headers;
}

fn setLong(easy: *c.CURL, option: c.CURLoption, value: c_long) !void {
    if (c.curl_easy_setopt(easy, option, value) != c.CURLE_OK) return error.CurlOption;
}

fn setPointer(easy: *c.CURL, option: c.CURLoption, value: anytype) !void {
    if (c.curl_easy_setopt(easy, option, value) != c.CURLE_OK) return error.CurlOption;
}

fn failureFromCurl(code: c.CURLcode) ?Failure {
    return switch (code) {
        c.CURLE_OK => null,
        c.CURLE_OPERATION_TIMEDOUT => .deadline,
        c.CURLE_PEER_FAILED_VERIFICATION, c.CURLE_SSL_CONNECT_ERROR, c.CURLE_SSL_CACERT_BADFILE => .tls,
        c.CURLE_OUT_OF_MEMORY => .allocation,
        else => .transport,
    };
}

fn oauthFenceLive(transfer: *const Transfer) bool {
    if (transfer.request.catalog) |material| {
        if (transfer.catalog_dispatch_started) material.fence.checkAfterIo() catch return false else material.fence.checkBeforeDispatch() catch return false;
    }
    if (transfer.request.jwks_fence) |fence| fence.checkBeforeCompletion() catch return false;
    if (transfer.request.oauth) |material| {
        if (transfer.oauth_dispatch_started) {
            material.fence.checkBeforeCompletion() catch return false;
        } else {
            material.fence.checkBeforeDispatch() catch return false;
        }
    }
    return true;
}

fn transferExpired(transfer: *const Transfer) bool {
    if (monotonicMilliseconds() >= transfer.deadline) return true;
    return if (transfer.request.request.absolute_deadline) |deadline| deadline.expired() else false;
}

fn monotonicMilliseconds() u64 {
    var time: c.struct_timespec = undefined;
    if (c.clock_gettime(c.CLOCK_MONOTONIC, &time) != 0) @panic("monotonic clock unavailable");
    return @as(u64, @intCast(time.tv_sec)) * 1000 + @as(u64, @intCast(time.tv_nsec)) / 1_000_000;
}

fn wallClockSeconds() i64 {
    var time: c.struct_timespec = undefined;
    if (c.clock_gettime(c.CLOCK_REALTIME, &time) != 0) @panic("wall clock unavailable");
    return @intCast(time.tv_sec);
}

fn duplicateBrowserAuthorization(allocator: std.mem.Allocator, auth: browser.ScopedHeader) !browser.ScopedHeader {
    var owned = auth;
    owned.bytes = try allocator.dupe(u8, auth.bytes);
    errdefer {
        std.crypto.secureZero(u8, owned.bytes);
        allocator.free(owned.bytes);
    }
    owned.host = try allocator.dupe(u8, auth.host);
    errdefer allocator.free(owned.host);
    owned.request_path = try allocator.dupe(u8, auth.request_path);
    errdefer allocator.free(owned.request_path);
    owned.store_id = try allocator.dupe(u8, auth.store_id);
    errdefer allocator.free(owned.store_id);
    owned.first_party_domain = if (auth.first_party_domain) |value| try allocator.dupe(u8, value) else null;
    errdefer if (owned.first_party_domain) |value| allocator.free(value);
    if (auth.partition_key) |key| owned.partition_key = .{ .top_level_site = try allocator.dupe(u8, key.top_level_site), .has_cross_site_ancestor = key.has_cross_site_ancestor };
    return owned;
}

fn destroyBrowserAuthorization(allocator: std.mem.Allocator, auth: *browser.ScopedHeader) void {
    allocator.free(auth.host);
    allocator.free(auth.request_path);
    allocator.free(auth.store_id);
    if (auth.first_party_domain) |value| allocator.free(value);
    if (auth.partition_key) |key| allocator.free(key.top_level_site);
    auth.deinit(allocator);
}

fn writeCallback(data: [*c]u8, size: usize, count: usize, context: ?*anyopaque) callconv(.c) usize {
    const transfer: *Transfer = @ptrCast(@alignCast(context.?));
    const length = std.math.mul(usize, size, count) catch {
        transfer.failure = .response_too_large;
        return 0;
    };
    if (length > transfer.request.request.max_response_bytes - transfer.received) {
        transfer.failure = .response_too_large;
        return 0;
    }
    const bytes = data[0..length];
    if (length != 0 and transfer.response_received_unix == null and (transfer.request.catalog != null or transfer.request.oauth != null or transfer.request.jwks)) {
        const original = transfer.request.request.absolute_deadline orelse {
            transfer.failure = .transport;
            return 0;
        };
        // Anchor receipt age/relative expiry to the first delivered body byte,
        // before completion allocations or later verifier work can consume time.
        transfer.response_received_unix = std.Io.Clock.real.now(original.io).toSeconds();
    }
    if (transfer.request.request.streaming) {
        if (length > Limits.chunk_bytes) {
            transfer.failure = .response_too_large;
            return 0;
        }
        transfer.owner.lock();
        defer transfer.owner.unlock();
        if (transfer.owner.chunks.count == Limits.chunks) {
            transfer.paused = true;
            return c.CURL_WRITEFUNC_PAUSE;
        }
        var chunk: Chunk = .{ .id = transfer.id, .bytes = @splat(0), .len = length };
        @memcpy(chunk.bytes[0..length], bytes);
        std.debug.assert(transfer.owner.chunks.push(chunk));
    } else {
        transfer.body.appendSlice(transfer.owner.allocator, bytes) catch {
            transfer.failure = .allocation;
            return 0;
        };
    }
    transfer.received += length;
    return length;
}

test "fixed endpoints distinguish identity from catalog and reject production fixture routing" {
    try std.testing.expect(Endpoint.github_identity.provesIdentity());
    try std.testing.expect(!Endpoint.openai_model_catalog.provesIdentity());
    try std.testing.expectEqualStrings("https://api.github.com", Endpoint.github_capacity.origin());
    const request: Request = .{ .endpoint = .github_identity, .account_id = "account-1", .grant_id = "grant-1" };
    try request.validate();
    var malformed = request;
    malformed.fixture_port = 1234;
    try std.testing.expectError(error.UndeclaredEndpoint, malformed.validate());
    malformed = request;
    malformed.access_token = "token\r\nHost: localhost";
    try std.testing.expectError(error.InvalidCredential, malformed.validate());
    malformed = request;
    malformed.max_response_bytes = Limits.response_bytes + 1;
    try std.testing.expectError(error.InvalidLimit, malformed.validate());
}

test "bounded queues retain FIFO and reject additional entries" {
    var ring: Ring(u64, 2) = .{};
    try std.testing.expect(ring.push(1));
    try std.testing.expect(ring.push(2));
    try std.testing.expect(!ring.push(3));
    try std.testing.expectEqual(@as(u64, 1), ring.pop().?);
    try std.testing.expect(ring.push(3));
    try std.testing.expectEqual(@as(u64, 2), ring.pop().?);
    try std.testing.expectEqual(@as(u64, 3), ring.pop().?);
    try std.testing.expect(ring.pop() == null);
}

/// Socket fixtures are private loopback servers with no external dependency and
/// no enrolled secrets. They exercise the real linked multi engine under Bazel.
const Fixture = struct {
    const AcceptPhase = enum(u8) { waiting, active, stopped, finished };
    descriptor: c_int,
    stop_read: c_int = -1,
    stop_write: c_int = -1,
    accept_phase: std.atomic.Value(AcceptPhase) = .init(.finished),
    accept_poll_entered: std.atomic.Value(bool) = .init(false),
    accept_ready: std.atomic.Value(bool) = .init(false),
    stop_prevented_accept: std.atomic.Value(bool) = .init(false),
    draining_accepted: std.atomic.Value(bool) = .init(false),
    // Test-only pre-accept race; its wait spends the original accept deadline.
    hold_accept_model: bool = false,
    port: u16,
    mode: enum { json, redirect, oversized, delayed, stream, oauth_form, oauth_oss, oauth_redirect, oauth_large, oauth_hold, jwks, jwks_redirect, jwks_large, jwks_delayed },
    jwks_body: []const u8 = "{\"keys\":[]}",
    token_body: ?[]const u8 = null,
    expected_client: [256]u8 = @splat(0),
    expected_client_len: usize = 0,
    expected_redirect: [256]u8 = @splat(0),
    expected_redirect_len: usize = 0,
    expected_refresh_ticket: ?*const oauth_authority.IssuedTicket = null,
    suppress_reply: bool = false,
    response_delay_ms: u32 = 0,
    response_status: u16 = 200,
    hold_reply: bool = false,
    release_reply: std.atomic.Value(bool) = .init(false),
    accept_timeout_ms: c_int = 1500,
    thread: ?std.Thread = null,
    request_seen: std.atomic.Value(bool) = .init(false),
    authorization_seen: std.atomic.Value(bool) = .init(false),
    oauth_wire_valid: std.atomic.Value(bool) = .init(false),
    jwks_wire_valid: std.atomic.Value(bool) = .init(false),
    oauth_no_ambient_headers: std.atomic.Value(bool) = .init(false),
    request_count: std.atomic.Value(u32) = .init(0),
    delay_ms: u32 = 200,

    fn listen(mode: @FieldType(Fixture, "mode")) !Fixture {
        const descriptor = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
        if (descriptor < 0) return error.FixtureSocket;
        errdefer _ = c.close(descriptor);
        var address = std.mem.zeroes(c.struct_sockaddr_in);
        address.sin_family = c.AF_INET;
        address.sin_addr.s_addr = c.htonl(0x7f000001);
        address.sin_port = 0;
        if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
        if (c.bind(descriptor, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0) return error.FixtureBind;
        if (c.listen(descriptor, 1) != 0) return error.FixtureListen;
        var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
        if (c.getsockname(descriptor, @ptrCast(&address), &length) != 0) return error.FixtureAddress;
        return .{ .descriptor = descriptor, .port = c.ntohs(address.sin_port), .mode = mode };
    }

    fn start(self: *Fixture) !void {
        if (self.descriptor < 0 or self.thread != null) return error.TestServerStarted;
        // Allocate only when this Fixture owns a worker. CatalogServer borrows
        // only listen()'s raw listener and must not inherit hidden pipe owners.
        var wake: [2]c_int = undefined;
        if (@hasDecl(c, "pipe2") and @hasDecl(c, "O_CLOEXEC")) {
            if (c.pipe2(&wake, c.O_CLOEXEC) != 0) return error.FixtureWake;
        } else {
            if (c.pipe(&wake) != 0) return error.FixtureWake;
        }
        self.stop_read = wake[0];
        self.stop_write = wake[1];
        errdefer {
            _ = c.close(self.stop_read);
            _ = c.close(self.stop_write);
            self.stop_read = -1;
            self.stop_write = -1;
        }
        for (wake) |fd| {
            const flags = c.fcntl(fd, c.F_GETFD);
            if (flags < 0 or c.fcntl(fd, c.F_SETFD, flags | c.FD_CLOEXEC) != 0) return error.FixtureWake;
        }
        self.accept_phase.store(.waiting, .release);
        errdefer self.accept_phase.store(.finished, .release);
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn deinit(self: *Fixture) void {
        if (self.thread) |thread| {
            // One owner arbitrates only NEW acceptance. Accepted work keeps all
            // original header/body/wire/reply checks and is joined unchanged.
            if (self.accept_phase.cmpxchgStrong(.waiting, .stopped, .acq_rel, .acquire)) |prior| {
                if (prior == .active) self.draining_accepted.store(true, .release);
            } else {
                const byte: u8 = 1;
                while (true) {
                    const written = c.write(self.stop_write, &byte, 1);
                    if (written < 0 and std.c.errno(written) == .INTR) continue;
                    // The private read end stays owned until after join. Exactly
                    // one byte is written once, so this pipe cannot fill.
                    if (written != 1) @panic("fixture stop wake failed");
                    break;
                }
            }
            thread.join();
            self.thread = null;
        }
        // Worker/accepted peer are gone before any descriptor can be reused.
        for ([_]*c_int{ &self.descriptor, &self.stop_read, &self.stop_write }) |fd| {
            if (fd.* >= 0) {
                _ = c.close(fd.*);
                fd.* = -1;
            }
        }
    }

    fn serve(self: *Fixture) void {
        defer self.accept_phase.store(.finished, .release);
        const accept_until = monotonicMilliseconds() + @as(u64, @intCast(self.accept_timeout_ms));
        var pollfds = [_]c.struct_pollfd{
            .{ .fd = self.descriptor, .events = c.POLLIN, .revents = 0 },
            .{ .fd = self.stop_read, .events = c.POLLIN, .revents = 0 },
        };
        self.accept_poll_entered.store(true, .release);
        if (c.poll(&pollfds, pollfds.len, self.accept_timeout_ms) <= 0) return;
        if (pollfds[1].revents != 0) {
            self.stop_prevented_accept.store(true, .release);
            return;
        }
        if (pollfds[0].revents & c.POLLIN == 0) return;
        self.accept_ready.store(true, .release);
        while (self.hold_accept_model and self.accept_phase.load(.acquire) == .waiting) {
            if (monotonicMilliseconds() >= accept_until) return;
            sleepMilliseconds(2);
        }
        if (self.accept_phase.cmpxchgStrong(.waiting, .active, .acq_rel, .acquire) != null) {
            self.stop_prevented_accept.store(true, .release);
            return;
        }
        const peer = c.accept(self.descriptor, null, null);
        if (peer < 0) return;
        defer _ = c.close(peer);
        if (@hasDecl(c, "SO_NOSIGPIPE")) {
            const enabled: c_int = 1;
            _ = c.setsockopt(peer, c.SOL_SOCKET, c.SO_NOSIGPIPE, &enabled, @sizeOf(c_int));
        }
        var request: [oauth_token.max_body_bytes + 4096]u8 = undefined;
        defer std.crypto.secureZero(u8, &request);
        var length: usize = 0;
        while (length < request.len) {
            const received = c.recv(peer, request[length..].ptr, request.len - length, 0);
            if (received <= 0) return;
            length += @intCast(received);
            if (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") != null) break;
        }
        const oauth_request = switch (self.mode) {
            .oauth_form, .oauth_oss, .oauth_redirect, .oauth_large, .oauth_hold => true,
            .json, .redirect, .oversized, .delayed, .stream, .jwks, .jwks_redirect, .jwks_large, .jwks_delayed => false,
        };
        if (oauth_request) {
            const end = std.mem.indexOf(u8, request[0..length], "\r\n\r\n") orelse return;
            const header = request[0..end];
            const content_at = std.ascii.findIgnoreCase(header, "content-length:") orelse return;
            const number_start = content_at + "content-length:".len;
            const number_end = std.mem.indexOfScalarPos(u8, header, number_start, '\r') orelse header.len;
            const body_length = std.fmt.parseInt(usize, std.mem.trim(u8, header[number_start..number_end], " \t"), 10) catch return;
            if (body_length == 0 or body_length > oauth_token.max_body_bytes or end + 4 + body_length > request.len) return;
            while (length < end + 4 + body_length) {
                var readable: c.struct_pollfd = .{ .fd = peer, .events = c.POLLIN, .revents = 0 };
                if (c.poll(&readable, 1, 1500) <= 0) return;
                const received = c.recv(peer, request[length..].ptr, end + 4 + body_length - length, 0);
                if (received <= 0) return;
                length += @intCast(received);
            }
            const body = request[end + 4 .. end + 4 + body_length];
            self.oauth_no_ambient_headers.store(std.ascii.findIgnoreCase(header, "authorization:") == null and std.ascii.findIgnoreCase(header, "cookie:") == null and std.ascii.findIgnoreCase(header, "chatgpt-account-id:") == null, .release);
            var valid = std.ascii.findIgnoreCase(header, "content-type: application/x-www-form-urlencoded") != null;
            if (self.mode == .oauth_oss) {
                valid = valid and std.mem.startsWith(u8, header, "POST /api/accounts/oauth/token HTTP/1.1\r\n") and self.ossFormMatches(body);
            } else {
                valid = valid and std.mem.startsWith(u8, header, "POST /oauth/token HTTP/1.1\r\n") and std.mem.startsWith(u8, body, "grant_type=authorization_code&client_id=omux-fixture-client&code=synthetic-callback-code&redirect_uri=http%3A%2F%2F127.0.0.1%2Fauth%2Fcallback&code_verifier=");
                const verifier = std.mem.indexOf(u8, body, "&code_verifier=") orelse return;
                valid = valid and body[verifier + "&code_verifier=".len ..].len == 86;
            }
            self.oauth_wire_valid.store(valid, .release);
        }
        switch (self.mode) {
            .jwks, .jwks_redirect, .jwks_large, .jwks_delayed => {
                const end = std.mem.indexOf(u8, request[0..length], "\r\n\r\n") orelse return;
                const header = request[0..end];
                const valid = std.mem.startsWith(u8, header, "GET /.well-known/jwks.json HTTP/1.1\r\n") and std.ascii.findIgnoreCase(header, "authorization:") == null and std.ascii.findIgnoreCase(header, "cookie:") == null and std.ascii.findIgnoreCase(header, "chatgpt-account-id:") == null and length == end + 4;
                self.jwks_wire_valid.store(valid, .release);
            },
            else => {},
        }
        _ = self.request_count.fetchAdd(1, .acq_rel);
        self.authorization_seen.store(std.mem.indexOf(u8, request[0..length], "Authorization: Bearer fixture-token") != null, .release);
        self.request_seen.store(true, .release);
        if (self.suppress_reply) return;
        if (self.hold_reply) {
            const original = monotonicMilliseconds() + 3000;
            while (!self.release_reply.load(.acquire)) {
                if (monotonicMilliseconds() >= original) return;
                sleepMilliseconds(2);
            }
        }
        if (self.response_delay_ms != 0) sleepMilliseconds(self.response_delay_ms);
        switch (self.mode) {
            .json => sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"subject\":\"fixture-1\"}"),
            .redirect => sendAll(peer, "HTTP/1.1 302 Found\r\nLocation: https://undeclared.invalid/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            .oversized => sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            .delayed => {
                sleepMilliseconds(self.delay_ms);
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            },
            .oauth_form, .oauth_hold => {
                if (self.mode == .oauth_hold) sleepMilliseconds(self.delay_ms);
                sendOAuthResponse(peer);
            },
            .oauth_oss => {
                const body = self.token_body orelse return;
                var header: [256]u8 = undefined;
                const bytes = std.fmt.bufPrint(&header, "HTTP/1.1 {d} Fixture\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ self.response_status, body.len }) catch return;
                sendAll(peer, bytes);
                sendAll(peer, body);
            },
            .oauth_redirect => sendAll(peer, "HTTP/1.1 302 Found\r\nLocation: https://undeclared.invalid/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            .oauth_large => {
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n");
                const payload: [oauth_token.max_body_bytes + 1]u8 = @splat('x');
                sendAll(peer, &payload);
            },
            .jwks, .jwks_delayed => {
                if (self.mode == .jwks_delayed) sleepMilliseconds(self.delay_ms);
                var header: [256]u8 = undefined;
                const bytes = std.fmt.bufPrint(&header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.jwks_body.len}) catch return;
                sendAll(peer, bytes);
                sendAll(peer, self.jwks_body);
            },
            .jwks_redirect => sendAll(peer, "HTTP/1.1 302 Found\r\nLocation: https://undeclared.invalid/keys\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            .jwks_large => {
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n");
                const payload: [oauth_token.max_body_bytes + 1]u8 = @splat('x');
                sendAll(peer, &payload);
            },
            .stream => {
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 786432\r\nConnection: close\r\n\r\n");
                const payload: [16384]u8 = @splat('x');
                for (0..48) |_| sendAll(peer, &payload);
            },
        }
    }

    fn sendOAuthResponse(descriptor: c_int) void {
        const body = "{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-successor-refresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        var header: [256]u8 = undefined;
        const bytes = std.fmt.bufPrint(&header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.len}) catch return;
        sendAll(descriptor, bytes);
        sendAll(descriptor, body);
    }

    fn ossFormMatches(self: *const Fixture, body: []const u8) bool {
        if (self.expected_refresh_ticket) |ticket| return self.ossRefreshMatches(ticket, body);
        var iterator = std.mem.splitScalar(u8, body, '&');
        var seen: u8 = 0;
        while (iterator.next()) |field| {
            const equals = std.mem.indexOfScalar(u8, field, '=') orelse return false;
            const name = field[0..equals];
            const index: u3 = if (std.mem.eql(u8, name, "grant_type")) 0 else if (std.mem.eql(u8, name, "client_id")) 1 else if (std.mem.eql(u8, name, "code")) 2 else if (std.mem.eql(u8, name, "redirect_uri")) 3 else if (std.mem.eql(u8, name, "code_verifier")) 4 else if (std.mem.eql(u8, name, "resource")) 5 else return false;
            const bit = @as(u8, 1) << index;
            if (seen & bit != 0) return false;
            seen |= bit;
            var decoded: [4096]u8 = undefined;
            defer std.crypto.secureZero(u8, &decoded);
            const value = decodeFixtureForm(&decoded, field[equals + 1 ..]) orelse return false;
            switch (index) {
                0 => if (!std.mem.eql(u8, value, "authorization_code")) return false,
                1 => if (!std.mem.eql(u8, value, self.expected_client[0..self.expected_client_len])) return false,
                2 => if (value.len == 0 or value.len > 4096) return false,
                3 => if (!std.mem.eql(u8, value, self.expected_redirect[0..self.expected_redirect_len])) return false,
                4 => {
                    if (value.len < 43 or value.len > 128) return false;
                    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "-._~", byte) == null) return false;
                },
                5 => if (!std.mem.eql(u8, value, "https://api.openai.com/v1")) return false,
                6, 7 => unreachable,
            }
        }
        return seen == 0b11_1111;
    }

    fn ossRefreshMatches(self: *const Fixture, ticket: *const oauth_authority.IssuedTicket, body: []const u8) bool {
        var iterator = std.mem.splitScalar(u8, body, '&');
        var seen: u8 = 0;
        while (iterator.next()) |field| {
            const equals = std.mem.indexOfScalar(u8, field, '=') orelse return false;
            const name = field[0..equals];
            const index: u2 = if (std.mem.eql(u8, name, "grant_type")) 0 else if (std.mem.eql(u8, name, "client_id")) 1 else if (std.mem.eql(u8, name, "refresh_token")) 2 else if (std.mem.eql(u8, name, "resource")) 3 else return false;
            const bit = @as(u8, 1) << index;
            if (seen & bit != 0) return false;
            seen |= bit;
            var decoded: [16 * 1024]u8 = undefined;
            defer std.crypto.secureZero(u8, &decoded);
            const value = decodeFixtureForm(&decoded, field[equals + 1 ..]) orelse return false;
            switch (index) {
                0 => if (!std.mem.eql(u8, value, "refresh_token")) return false,
                1 => if (!std.mem.eql(u8, value, self.expected_client[0..self.expected_client_len])) return false,
                2 => if (!oauth_authority.testing.matchesOwnedRefreshWire(ticket, value)) return false,
                3 => if (!std.mem.eql(u8, value, "https://api.openai.com/v1")) return false,
            }
        }
        return seen == 0b1111;
    }

    fn decodeFixtureForm(storage: []u8, encoded: []const u8) ?[]const u8 {
        var read: usize = 0;
        var written: usize = 0;
        while (read < encoded.len) {
            if (written == storage.len) return null;
            if (encoded[read] == '%') {
                if (encoded.len - read < 3) return null;
                storage[written] = std.fmt.parseInt(u8, encoded[read + 1 .. read + 3], 16) catch return null;
                read += 3;
            } else {
                storage[written] = if (encoded[read] == '+') ' ' else encoded[read];
                read += 1;
            }
            written += 1;
        }
        return storage[0..written];
    }

    fn sendAll(descriptor: c_int, bytes: []const u8) void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const written = c.send(descriptor, bytes[offset..].ptr, bytes.len - offset, if (@hasDecl(c, "MSG_NOSIGNAL")) c.MSG_NOSIGNAL else 0);
            if (written <= 0) return;
            offset += @intCast(written);
        }
    }
};

fn sleepMilliseconds(milliseconds: u32) void {
    const time: c.struct_timespec = .{ .tv_sec = @intCast(milliseconds / 1000), .tv_nsec = @intCast((milliseconds % 1000) * 1_000_000) };
    _ = c.nanosleep(&time, null);
}

fn fixtureRequest(port: u16) Request {
    return .{ .endpoint = .fixture_identity, .fixture_port = port, .account_id = "fixture-account", .grant_id = "fixture-grant", .access_token = "fixture-token", .timeout_ms = 1000 };
}

fn awaitOAuthResult(client: *Client) !OAuthCompletion {
    for (0..300) |_| {
        if (client.pollOAuth()) |result| return result;
        sleepMilliseconds(5);
    }
    return error.FixtureTimeout;
}

fn awaitJwksResult(client: *Client) !JwksCompletion {
    for (0..1500) |_| {
        if (client.pollJwks()) |result| return result;
        sleepMilliseconds(2);
    }
    return error.FixtureTimeout;
}

pub const testing = struct {
    /// Independent fixture region: no token/JWKS Server bodies are changed.
    /// Exact Bearer comparison is private to an actual Store-backed ticket.
    pub const CatalogServer = struct {
        allocator: std.mem.Allocator,
        listener: c_int,
        local_port: u16,
        reply: envelope.Secret,
        status: u16,
        delay_ms: u32,
        ticket: ?*catalog_authority.Ticket = null,
        thread: ?std.Thread = null,
        requests: std.atomic.Value(u32) = .init(0),
        wire_valid: std.atomic.Value(bool) = .init(false),
        hold_reply: std.atomic.Value(bool) = .init(false),
        release_reply: std.atomic.Value(bool) = .init(false),

        pub fn listen(a: std.mem.Allocator, status: u16, body: []const u8, delay_ms: u32) !CatalogServer {
            if (!builtin.is_test) return error.TestOnly;
            if (body.len == 0 or body.len > siwc_catalog.maximum_body_bytes + 1 or delay_ms > 1000 or status < 200 or status > 599) return error.InvalidModelRoute;
            const listener = try Fixture.listen(.json);
            errdefer _ = c.close(listener.descriptor);
            return .{ .allocator = a, .listener = listener.descriptor, .local_port = listener.port, .reply = .{ .allocator = a, .bytes = try a.dupe(u8, body) }, .status = status, .delay_ms = delay_ms };
        }
        pub fn port(self: *const CatalogServer) u16 {
            return self.local_port;
        }
        pub fn start(self: *CatalogServer, ticket: *catalog_authority.Ticket) !void {
            if (!builtin.is_test or self.thread != null or self.ticket != null) return error.InvalidModelRoute;
            try ticket.checkActive();
            ticket.retain();
            self.ticket = ticket;
            errdefer {
                ticket.deinit();
                self.ticket = null;
            }
            self.thread = try std.Thread.spawn(.{}, serve, .{self});
        }
        pub fn requestCount(self: *const CatalogServer) u32 {
            return self.requests.load(.acquire);
        }
        pub fn validWire(self: *const CatalogServer) bool {
            return self.wire_valid.load(.acquire);
        }
        pub fn holdReply(self: *CatalogServer) !void {
            if (!builtin.is_test or self.thread != null) return error.InvalidModelRoute;
            self.hold_reply.store(true, .release);
        }
        pub fn releaseReply(self: *CatalogServer) void {
            self.release_reply.store(true, .release);
        }
        pub fn deinit(self: *CatalogServer) void {
            self.releaseReply();
            if (self.thread) |thread| thread.join();
            _ = c.close(self.listener);
            if (self.ticket) |ticket| ticket.deinit();
            self.reply.deinit();
            self.* = undefined;
        }
        fn serve(self: *CatalogServer) void {
            var readable: c.struct_pollfd = .{ .fd = self.listener, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&readable, 1, 2000) <= 0) return;
            const descriptor = c.accept(self.listener, null, null);
            if (descriptor < 0) return;
            defer _ = c.close(descriptor);
            if (@hasDecl(c, "SO_NOSIGPIPE")) {
                const enabled: c_int = 1;
                _ = c.setsockopt(descriptor, c.SOL_SOCKET, c.SO_NOSIGPIPE, &enabled, @sizeOf(c_int));
            }
            var request: [32 * 1024]u8 = undefined;
            defer std.crypto.secureZero(u8, &request);
            var length: usize = 0;
            while (length < request.len) {
                var ready: c.struct_pollfd = .{ .fd = descriptor, .events = c.POLLIN, .revents = 0 };
                if (c.poll(&ready, 1, 1000) <= 0) return;
                const count = c.recv(descriptor, request[length..].ptr, request.len - length, 0);
                if (count <= 0) return;
                length += @intCast(count);
                if (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") != null) break;
            }
            _ = self.requests.fetchAdd(1, .acq_rel);
            const end = std.mem.indexOf(u8, request[0..length], "\r\n\r\n") orelse return;
            const headers = request[0..end];
            var authorization: ?[]const u8 = null;
            var valid = std.mem.startsWith(u8, headers, "GET /v1/models HTTP/1.1\r\n") and length == end + 4;
            var lines = std.mem.splitSequence(u8, headers, "\r\n");
            _ = lines.next();
            while (lines.next()) |line| {
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
                    valid = false;
                    continue;
                };
                const name = line[0..colon];
                const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
                if (std.ascii.eqlIgnoreCase(name, "authorization")) {
                    if (authorization != null) valid = false;
                    authorization = value;
                }
                if (std.ascii.eqlIgnoreCase(name, "cookie") or std.ascii.eqlIgnoreCase(name, "chatgpt-account-id") or std.ascii.eqlIgnoreCase(name, "content-length") or std.ascii.eqlIgnoreCase(name, "transfer-encoding")) valid = false;
            }
            valid = valid and authorization != null and catalog_authority.testing.matchesAuthorization(self.ticket.?, authorization.?);
            self.wire_valid.store(valid, .release);
            if (!valid) return;
            if (self.delay_ms != 0) _ = c.poll(null, 0, @intCast(self.delay_ms));
            while (self.hold_reply.load(.acquire) and !self.release_reply.load(.acquire)) {
                if (self.ticket.?.originalUntil().durationFromNow(self.ticket.?.clockIo()).raw.toNanoseconds() <= 0) return;
                _ = c.poll(null, 0, 5);
            }
            var header: [256]u8 = undefined;
            const prefix = std.fmt.bufPrint(&header, "HTTP/1.1 {d} Catalog\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n{s}\r\n", .{ self.status, self.reply.bytes.len, if (self.status == 302) "Location: http://127.0.0.1:1/forbidden\r\n" else "" }) catch return;
            Fixture.sendAll(descriptor, prefix);
            Fixture.sendAll(descriptor, self.reply.bytes);
        }
    };

    /// Runtime synthetic signed replies still traverse real loopback curl.
    /// This server has no receipt/profile constructor or provider capability.
    pub const Server = struct {
        allocator: std.mem.Allocator,
        fixture: Fixture,
        body: ?envelope.Secret = null,
        deinitialized: bool = false,

        pub fn listenToken(a: std.mem.Allocator) !Server {
            if (!builtin.is_test) return error.UndeclaredEndpoint;
            return .{ .allocator = a, .fixture = try Fixture.listen(.oauth_oss) };
        }
        pub fn listenJwks(a: std.mem.Allocator) !Server {
            if (!builtin.is_test) return error.UndeclaredEndpoint;
            return .{ .allocator = a, .fixture = try Fixture.listen(.jwks) };
        }
        pub fn port(self: *const Server) u16 {
            return self.fixture.port;
        }
        pub fn setBody(self: *Server, bytes: []const u8) !void {
            if (self.fixture.thread != null) return error.TestServerStarted;
            if (bytes.len == 0 or bytes.len > oauth_token.max_body_bytes) return error.InvalidJwksResponse;
            const owned: envelope.Secret = .{ .allocator = self.allocator, .bytes = try self.allocator.dupe(u8, bytes) };
            if (self.body) |*previous| previous.deinit();
            self.body = owned;
            switch (self.fixture.mode) {
                .oauth_oss => self.fixture.token_body = self.body.?.bytes,
                .jwks => self.fixture.jwks_body = self.body.?.bytes,
                else => unreachable,
            }
        }
        pub fn start(self: *Server, ticket: *const oauth_authority.IssuedTicket) !void {
            if (!builtin.is_test) return error.UndeclaredEndpoint;
            if (self.fixture.thread != null or self.body == null) return error.TestServerStarted;
            const renewing = blk: {
                ticket.requireOwnedOssRenewal() catch {
                    try ticket.requireOwnedOssEnrollment();
                    break :blk false;
                };
                break :blk true;
            };
            const routes = ticket.modelRoutes() orelse return error.InvalidScope;
            switch (self.fixture.mode) {
                .oauth_oss => {
                    if (routes.token_port != self.port()) return error.InvalidScope;
                    const client_id = ticket.issuedClientId();
                    const binding = ticket.binding();
                    const redirect = binding.redirect();
                    if (renewing) {
                        // The expectation retains only the original sealed
                        // ticket; it never exposes or invents RT authority.
                        const owned: *oauth_authority.IssuedTicket = @constCast(ticket);
                        owned.retain();
                        self.fixture.expected_refresh_ticket = ticket;
                    }
                    if (client_id.len == 0 or client_id.len > 256 or (!renewing and redirect.len == 0) or redirect.len > 256) return error.InvalidScope;
                    self.fixture.expected_client_len = client_id.len;
                    @memcpy(self.fixture.expected_client[0..client_id.len], client_id);
                    self.fixture.expected_redirect_len = redirect.len;
                    @memcpy(self.fixture.expected_redirect[0..redirect.len], redirect);
                },
                .jwks => {
                    if (routes.jwks_port != self.port()) return error.InvalidScope;
                    if (renewing) self.fixture.accept_timeout_ms = @intCast(@min(@as(u64, 5000), try (AbsoluteDeadline{ .io = ticket.clockIo(), .until = ticket.originalUntil() }).remaining()));
                },
                else => unreachable,
            }
            _ = try (AbsoluteDeadline{ .io = ticket.clockIo(), .until = ticket.originalUntil() }).remaining();
            try self.fixture.start();
        }
        pub fn setFailureModel(self: *Server, suppress_reply: bool, delay_ms: u32) !void {
            if (!builtin.is_test or self.fixture.thread != null or delay_ms > 3000) return error.InvalidScope;
            self.fixture.suppress_reply = suppress_reply;
            self.fixture.response_delay_ms = delay_ms;
        }
        pub fn setHoldModel(self: *Server) !void {
            if (!builtin.is_test or self.fixture.thread != null) return error.InvalidScope;
            self.fixture.hold_reply = true;
        }
        pub fn releaseModelReply(self: *Server) void {
            if (builtin.is_test) self.fixture.release_reply.store(true, .release);
        }
        pub fn setStatusModel(self: *Server, status: u16) !void {
            if (!builtin.is_test or self.fixture.thread != null or status < 200 or status > 599) return error.InvalidScope;
            self.fixture.response_status = status;
        }
        pub fn started(self: *const Server) bool {
            return self.fixture.thread != null;
        }
        pub fn requestCount(self: *const Server) u32 {
            return self.fixture.request_count.load(.acquire);
        }
        pub fn wireValid(self: *const Server) bool {
            return switch (self.fixture.mode) {
                .oauth_oss => self.fixture.oauth_wire_valid.load(.acquire) and self.fixture.oauth_no_ambient_headers.load(.acquire),
                .jwks => self.fixture.jwks_wire_valid.load(.acquire),
                else => false,
            };
        }
        pub fn deinit(self: *Server) void {
            if (self.deinitialized) return;
            self.fixture.deinit();
            if (self.fixture.expected_refresh_ticket) |ticket| @constCast(ticket).deinit();
            if (self.body) |*body| body.deinit();
            std.crypto.secureZero(u8, &self.fixture.expected_client);
            std.crypto.secureZero(u8, &self.fixture.expected_redirect);
            self.* = undefined;
            self.deinitialized = true;
        }
    };

    /// Genuine loopback curl completion with explicit modeled provenance. This
    /// cannot mint shipping HTTPS key authority or qualify provider algorithms.
    pub fn jwksLease(io: std.Io, a: std.mem.Allocator, body: []const u8, until: std.Io.Clock.Timestamp) !*JwksLease {
        if (!builtin.is_test) return error.JwksAuthorityChanged;
        if (body.len == 0 or body.len > oauth_token.max_body_bytes) return error.InvalidJwksResponse;
        var server = try Fixture.listen(.jwks);
        server.jwks_body = body;
        defer server.deinit();
        try server.start();
        const client = try Client.init(a);
        defer client.deinit();
        _ = try client.enqueueJwks(.{ .io = io, .until = until }, server.port, null, null);
        var completed = try awaitJwksResult(client);
        defer completed.deinit(a);
        const lease = switch (completed.result) {
            .lease => |value| value,
            .failure => return error.InvalidJwksResponse,
        };
        try std.testing.expect(server.jwks_wire_valid.load(.acquire));
        lease.retain();
        return lease;
    }
};

fn awaitResult(client: *Client) !Completion {
    for (0..300) |_| {
        if (client.poll()) |result| return result;
        sleepMilliseconds(5);
    }
    return error.FixtureTimeout;
}

const FixtureShutdownModel = struct {
    fn wait(flag: *const std.atomic.Value(bool)) !void {
        const until = monotonicMilliseconds() + 3000;
        while (!flag.load(.acquire)) {
            if (monotonicMilliseconds() >= until) return error.FixtureTimeout;
            sleepMilliseconds(2);
        }
    }
    fn connect(port: u16) !c_int {
        const peer = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
        if (peer < 0) return error.FixtureSocket;
        errdefer _ = c.close(peer);
        var address = std.mem.zeroes(c.struct_sockaddr_in);
        address.sin_family = c.AF_INET;
        address.sin_addr.s_addr = c.htonl(0x7f000001);
        address.sin_port = c.htons(port);
        if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
        if (c.connect(peer, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0) return error.FixtureConnect;
        return peer;
    }
    fn expectClosed(fds: []const c_int) !void {
        for (fds) |fd| {
            const observed = c.fcntl(fd, c.F_GETFD);
            try std.testing.expect(observed == -1 and std.c.errno(observed) == .BADF);
        }
    }
    fn receive(peer: c_int, out: []u8) ![]const u8 {
        const until = monotonicMilliseconds() + 3000;
        var length: usize = 0;
        while (length < out.len) {
            const now = monotonicMilliseconds();
            if (now >= until) return error.FixtureTimeout;
            var readable: c.struct_pollfd = .{ .fd = peer, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&readable, 1, @intCast(until - now)) <= 0) return error.FixtureTimeout;
            const count = c.recv(peer, out[length..].ptr, out.len - length, 0);
            if (count < 0 and std.c.errno(count) == .INTR) continue;
            if (count < 0) return error.FixtureRead;
            if (count == 0) return out[0..length];
            length += @intCast(count);
        }
        return error.FixtureResponseBound;
    }
    const Stopper = struct {
        fixture: *Fixture,
        returned: std.atomic.Value(bool) = .init(false),
        fn run(self: *Stopper) void {
            self.fixture.deinit();
            self.returned.store(true, .release);
        }
    };
};

test "fixture cleanup owns unstarted payload and repeated destruction never closes a reused descriptor" {
    const M = FixtureShutdownModel;
    var server = try testing.Server.listenJwks(std.testing.allocator);
    defer server.deinit();
    try server.setBody("{\"keys\":[]}");
    const listener = server.fixture.descriptor;
    try std.testing.expectEqual(@as(c_int, -1), server.fixture.stop_read);
    try std.testing.expectEqual(@as(c_int, -1), server.fixture.stop_write);
    server.deinit();
    try M.expectClosed(&.{listener});
    const unrelated = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    try std.testing.expect(unrelated >= 0);
    defer _ = c.close(unrelated);
    try std.testing.expectEqual(listener, unrelated);
    server.deinit();
    try std.testing.expect(c.fcntl(unrelated, c.F_GETFD) >= 0);
}

test "unused fixture listener cleanup wakes original poll joins worker and closes every owned fd" {
    const M = FixtureShutdownModel;
    var server = try Fixture.listen(.jwks);
    defer server.deinit();
    try server.start();
    const fds = [_]c_int{ server.descriptor, server.stop_read, server.stop_write };
    for (fds[1..]) |fd| try std.testing.expect(c.fcntl(fd, c.F_GETFD) & c.FD_CLOEXEC != 0);
    try M.wait(&server.accept_poll_entered);
    server.deinit();
    try std.testing.expect(server.thread == null);
    try std.testing.expectEqual(Fixture.AcceptPhase.finished, server.accept_phase.load(.acquire));
    try std.testing.expect(server.stop_prevented_accept.load(.acquire));
    try std.testing.expect(!server.draining_accepted.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), server.request_count.load(.acquire));
    try std.testing.expect(!server.request_seen.load(.acquire));
    try M.expectClosed(&fds);
    server.deinit();
    try std.testing.expectEqual(@as(u32, 0), server.request_count.load(.acquire));
}

test "fixture stop wins ready connection admission without parsing or replying to late work" {
    const M = FixtureShutdownModel;
    var server = try Fixture.listen(.json);
    defer server.deinit();
    server.hold_accept_model = true;
    const peer = try M.connect(server.port);
    defer _ = c.close(peer);
    Fixture.sendAll(peer, "GET /identity HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try server.start();
    const fds = [_]c_int{ server.descriptor, server.stop_read, server.stop_write };
    try M.wait(&server.accept_ready);
    server.deinit();
    try std.testing.expect(server.stop_prevented_accept.load(.acquire));
    try std.testing.expect(!server.draining_accepted.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), server.request_count.load(.acquire));
    try std.testing.expect(!server.request_seen.load(.acquire));
    try std.testing.expect(server.thread == null);
    try M.expectClosed(&fds);
    var readable: c.struct_pollfd = .{ .fd = peer, .events = c.POLLIN, .revents = 0 };
    try std.testing.expect(c.poll(&readable, 1, 0) > 0);
    var byte: [1]u8 = undefined;
    try std.testing.expect(c.recv(peer, &byte, byte.len, 0) <= 0);
}

test "fixture accepted request wins stop and drains original full body and wire checks before fd removal" {
    const M = FixtureShutdownModel;
    var server = try Fixture.listen(.oauth_form);
    defer server.deinit();
    try server.start();
    const fds = [_]c_int{ server.descriptor, server.stop_read, server.stop_write };
    const peer = try M.connect(server.port);
    defer _ = c.close(peer);
    const verifier: [86]u8 = @splat('a');
    var body_buffer: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &body_buffer);
    const body = try std.fmt.bufPrint(&body_buffer, "grant_type=authorization_code&client_id=omux-fixture-client&code=synthetic-callback-code&redirect_uri=http%3A%2F%2F127.0.0.1%2Fauth%2Fcallback&code_verifier={s}", .{&verifier});
    var header_buffer: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buffer, "POST /oauth/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {d}\r\n\r\n", .{body.len});
    Fixture.sendAll(peer, header);
    Fixture.sendAll(peer, body[0..32]);
    try M.wait(&server.accept_ready);
    // Observe active admission before starting owner teardown.
    const until = monotonicMilliseconds() + 3000;
    while (server.accept_phase.load(.acquire) != .active) {
        if (monotonicMilliseconds() >= until) return error.FixtureTimeout;
        sleepMilliseconds(2);
    }
    var stopper: M.Stopper = .{ .fixture = &server };
    const thread = try std.Thread.spawn(.{}, M.Stopper.run, .{&stopper});
    defer {
        // On an assertion/error, EOF still lets the original body reader drain.
        _ = c.shutdown(peer, c.SHUT_RDWR);
        thread.join();
    }
    try M.wait(&server.draining_accepted);
    try std.testing.expect(!stopper.returned.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), server.request_count.load(.acquire));
    for (fds) |fd| try std.testing.expect(c.fcntl(fd, c.F_GETFD) >= 0);
    Fixture.sendAll(peer, body[32..]);
    var response_buffer: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);
    const response = try M.receive(peer, &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try M.wait(&stopper.returned);
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
    try std.testing.expect(server.oauth_wire_valid.load(.acquire));
    try std.testing.expect(server.oauth_no_ambient_headers.load(.acquire));
    try std.testing.expect(server.request_seen.load(.acquire));
    try std.testing.expect(!server.stop_prevented_accept.load(.acquire));
    try std.testing.expect(server.thread == null);
    try M.expectClosed(&fds);
}

test "real curl multi fetch returns owned JSON and never follows authenticated redirects" {
    const allocator = std.testing.allocator;
    var server = try Fixture.listen(.json);
    defer server.deinit();
    try server.start();
    const client = try Client.init(allocator);
    defer client.deinit();
    const id = try client.submit(fixtureRequest(server.port));
    var result = try awaitResult(client);
    defer result.deinit(allocator);
    try std.testing.expectEqual(id, result.id);
    const response = result.result.response;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    var parsed = try response.parseJson(allocator);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("fixture-1", parsed.value.object.get("subject").?.string);
    try std.testing.expect(server.authorization_seen.load(.acquire));

    var redirect = try Fixture.listen(.redirect);
    defer redirect.deinit();
    try redirect.start();
    _ = try client.submit(fixtureRequest(redirect.port));
    var redirected = try awaitResult(client);
    defer redirected.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 302), redirected.result.response.status);
}

test "cancellation, absolute deadlines and response caps reach the owner" {
    const allocator = std.testing.allocator;
    const client = try Client.init(allocator);
    defer client.deinit();
    var delayed = try Fixture.listen(.delayed);
    defer delayed.deinit();
    try delayed.start();
    const id = try client.submit(fixtureRequest(delayed.port));
    for (0..100) |_| {
        if (delayed.request_seen.load(.acquire)) break;
        sleepMilliseconds(2);
    }
    try client.cancel(id);
    var canceled = try awaitResult(client);
    defer canceled.deinit(allocator);
    try std.testing.expectEqual(Failure.canceled, canceled.result.failure);

    var deadline = try Fixture.listen(.delayed);
    defer deadline.deinit();
    try deadline.start();
    var request = fixtureRequest(deadline.port);
    request.timeout_ms = 20;
    _ = try client.submit(request);
    var expired = try awaitResult(client);
    defer expired.deinit(allocator);
    try std.testing.expectEqual(Failure.deadline, expired.result.failure);

    var large = try Fixture.listen(.oversized);
    defer large.deinit();
    try large.start();
    request = fixtureRequest(large.port);
    request.max_response_bytes = 32;
    _ = try client.submit(request);
    var capped = try awaitResult(client);
    defer capped.deinit(allocator);
    try std.testing.expectEqual(Failure.response_too_large, capped.result.failure);
}

test "slow stream consumer pauses and resumes within the bounded chunk budget" {
    const allocator = std.testing.allocator;
    var server = try Fixture.listen(.stream);
    defer server.deinit();
    try server.start();
    const client = try Client.init(allocator);
    defer client.deinit();
    var request = fixtureRequest(server.port);
    request.streaming = true;
    request.timeout_ms = 3000;
    const id = try client.submit(request);
    sleepMilliseconds(50);
    client.lock();
    const buffered = client.chunks.count;
    client.unlock();
    try std.testing.expect(buffered <= Limits.chunks);
    var received: usize = 0;
    var completion: ?Completion = null;
    for (0..600) |_| {
        while (client.pollChunk()) |item| {
            var chunk = item;
            try std.testing.expectEqual(id, chunk.id);
            for (chunk.slice()) |byte| try std.testing.expectEqual(@as(u8, 'x'), byte);
            received += chunk.len;
            chunk.clear();
        }
        if (client.poll()) |result| {
            completion = result;
            break;
        }
        sleepMilliseconds(5);
    }
    var result = completion orelse return error.FixtureTimeout;
    defer result.deinit(allocator);
    while (client.pollChunk()) |item| {
        var chunk = item;
        received += chunk.len;
        chunk.clear();
    }
    try std.testing.expectEqual(@as(usize, 786432), received);
    try std.testing.expectEqual(@as(u16, 200), result.result.response.status);
    try std.testing.expectEqual(@as(usize, 0), result.result.response.body.len);
}

test "abandoning paused stream releases chunks and owned completion survives shutdown" {
    const allocator = std.testing.allocator;
    var stream = try Fixture.listen(.stream);
    defer stream.deinit();
    try stream.start();
    const client = try Client.init(allocator);
    var closed = false;
    errdefer if (!closed) client.deinit();
    var request = fixtureRequest(stream.port);
    request.streaming = true;
    const id = try client.submit(request);
    sleepMilliseconds(50);
    try client.abandon(id);
    var canceled = try awaitResult(client);
    try std.testing.expectEqual(Failure.canceled, canceled.result.failure);
    try std.testing.expect(client.pollChunk() == null);
    canceled.deinit(allocator);

    var next = try Fixture.listen(.json);
    defer next.deinit();
    try next.start();
    _ = try client.fetchIdentity(fixtureRequest(next.port));
    var completion = try awaitResult(client);
    client.deinit();
    closed = true;
    defer completion.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), completion.result.response.status);
    try std.testing.expectEqualStrings("{\"subject\":\"fixture-1\"}", completion.result.response.body);
}

test "browser authorization cannot cross a declared endpoint or outlive custody" {
    var header = [_]u8{ 'a', '=', 'b' };
    var request: Request = .{
        .endpoint = .github_identity,
        .account_id = "account-1",
        .grant_id = "grant-1",
        .browser_authorization = .{ .bytes = &header, .host = "other.invalid", .request_path = "/user", .store_id = "store-1", .partition_key = null, .first_party_domain = null, .custody_until_unix = wallClockSeconds() + 10, .provider_expires_unix = null },
    };
    try std.testing.expectError(error.CredentialAudienceMismatch, request.validate());
    request.browser_authorization.?.host = "api.github.com";
    request.browser_authorization.?.custody_until_unix = wallClockSeconds() - 1;
    try std.testing.expectError(error.CredentialExpired, request.validate());
}

test "typed provider readers retain durable identity and separate capacity evidence" {
    const allocator = std.testing.allocator;
    var identity: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"id\":123,\"login\":\"renamed-user\",\"type\":\"User\",\"email\":\"discarded@example.invalid\"}"), .streaming = false };
    defer identity.deinit(allocator);
    var parsed = try identity.githubIdentity(allocator);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 123), parsed.value.id);
    try std.testing.expectEqualStrings("renamed-user", parsed.value.login);
    var quota: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"resources\":{\"core\":{\"limit\":5000,\"remaining\":4900,\"used\":100,\"reset\":2000},\"search\":{\"limit\":30}}}"), .streaming = false };
    defer quota.deinit(allocator);
    var capacity = try quota.githubCapacity(allocator);
    defer capacity.deinit();
    try std.testing.expectEqual(@as(u64, 4900), capacity.value.resources.core.remaining);
    quota.status = 403;
    try std.testing.expectError(error.CapacityUnavailable, quota.githubCapacity(allocator));
    identity.status = 401;
    try std.testing.expectError(error.IdentityUnavailable, identity.githubIdentity(allocator));
}

test "request admission remains bounded through queued work and unread completions" {
    var server = try Fixture.listen(.delayed);
    defer server.deinit();
    try server.start();
    const client = try Client.init(std.testing.allocator);
    defer client.deinit();
    const request = fixtureRequest(server.port);
    for (0..Limits.outstanding) |_| _ = try client.submit(request);
    try std.testing.expectError(error.Backpressure, client.submit(request));
    // Closing the owner cancels active and pending work and disposes all
    // reserved completions, including requests never dispatched to the server.
}

test "Codex authenticated identity keeps user, workspace and plan separate" {
    const allocator = std.testing.allocator;
    var response: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":null}"), .streaming = false };
    defer response.deinit(allocator);
    var identity = try response.codexIdentity(allocator);
    defer identity.deinit();
    try std.testing.expectEqualStrings("user-a", identity.value.user_id);
    try std.testing.expectEqualStrings("workspace-a", identity.value.account_id);
    try std.testing.expectEqual(CodexIdentity.Plan.plus, identity.value.plan());
    try std.testing.expect(identity.value.matchesHint("workspace-a"));
    try std.testing.expect(!identity.value.matchesHint("workspace-b"));

    var future: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"account_id\":\"workspace-b\",\"user_id\":\"user-a\",\"plan_type\":\"future_plan\"}"), .streaming = false };
    defer future.deinit(allocator);
    var future_identity = try future.codexIdentity(allocator);
    defer future_identity.deinit();
    try std.testing.expectEqual(CodexIdentity.Plan.unknown, future_identity.value.plan());
    try std.testing.expectEqualStrings(identity.value.user_id, future_identity.value.user_id);
    try std.testing.expect(!std.mem.eql(u8, identity.value.account_id, future_identity.value.account_id));

    var invalid: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"account_id\":\"\",\"user_id\":\"user-a\",\"plan_type\":\"plus\"}"), .streaming = false };
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidIdentity, invalid.codexIdentity(allocator));
    response.status = 401;
    try std.testing.expectError(error.IdentityUnavailable, response.codexIdentity(allocator));

    var request: Request = .{ .endpoint = .codex_identity, .account_id = "account-1", .grant_id = "grant-1", .access_token = "fixture-token", .provider_account_id = "workspace-a" };
    try request.validate();
    request.endpoint = .github_identity;
    try std.testing.expectError(error.InvalidAccountHint, request.validate());
    request.endpoint = .codex_identity;
    request.provider_account_id = "workspace-a\r\nInjected: secret";
    try std.testing.expectError(error.InvalidAccountHint, request.validate());
}

test "portable trust input is explicit and rejects malformed bundle paths" {
    try (Client.Trust{ .ca_bundle_path = "/portable/lib/omux/share/ca-bundle.crt" }).validate();
    try (Client.Trust{}).validate();
    try std.testing.expectError(error.InvalidTrustConfiguration, (Client.Trust{ .ca_bundle_path = "relative/ca.pem" }).validate());
    try std.testing.expectError(error.InvalidTrustConfiguration, (Client.Trust{ .ca_bundle_path = "/tmp/ca\n.pem" }).validate());
    try std.testing.expectError(error.InvalidTrustConfiguration, (Client.Trust{ .ca_bundle_path = "" }).validate());
    var oversized: [4097]u8 = @splat('a');
    oversized[0] = '/';
    try std.testing.expectError(error.InvalidTrustConfiguration, (Client.Trust{ .ca_bundle_path = &oversized }).validate());
}

test "Codex usage preserves provider decisions, percentage seconds and opaque credits" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"account_id":"workspace-a","user_id":"user-a","plan_type":"future_plan","rate_limit":{"allowed":true,"limit_reached":true,"primary_window":{"used_percent":100,"limit_window_seconds":18000,"reset_after_seconds":42,"reset_at":2147483700}},"additional_rate_limits":[{"limit_name":"Research allowance","metered_feature":"codex-research","normal_model_slug":"gpt-example","rate_limit":{"allowed":false,"limit_reached":false}}],"credits":{"has_credits":true,"unlimited":false,"balance":"17.25"},"future_extension":{"allowed":true}}
    ;
    var response: Response = .{ .status = 200, .body = try allocator.dupe(u8, payload), .streaming = false };
    defer response.deinit(allocator);
    var parsed = try response.codexUsage(allocator);
    defer parsed.deinit();
    try std.testing.expectEqual(CodexIdentity.Plan.unknown, parsed.value.identity().plan());
    try std.testing.expect(parsed.value.rate_limit.?.allowed);
    try std.testing.expectEqual(@as(i32, 100), parsed.value.rate_limit.?.primary_window.?.used_percent);
    try std.testing.expectEqual(@as(i32, 18000), parsed.value.rate_limit.?.primary_window.?.limit_window_seconds);
    try std.testing.expectEqual(@as(i64, 2147483700), parsed.value.rate_limit.?.primary_window.?.reset_at);
    try std.testing.expect(!parsed.value.additional_rate_limits.?[0].rate_limit.?.allowed);
    try std.testing.expectEqualStrings("17.25", parsed.value.credits.?.balance.?);
}

test "Codex absent usage remains unknown and malformed or duplicate windows fail closed" {
    const allocator = std.testing.allocator;
    var missing: Response = .{ .status = 200, .body = try allocator.dupe(u8, "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":null,\"credits\":null}"), .streaming = false };
    defer missing.deinit(allocator);
    var parsed = try missing.codexUsage(allocator);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.rate_limit == null);
    const invalid = [_][]const u8{
        "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":{\"allowed\":true,\"limit_reached\":false,\"primary_window\":{\"used_percent\":-1,\"limit_window_seconds\":3600,\"reset_after_seconds\":2,\"reset_at\":7200}}}",
        "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"rate_limit\":{\"allowed\":true,\"limit_reached\":false,\"primary_window\":{\"used_percent\":101,\"limit_window_seconds\":3600,\"reset_after_seconds\":2,\"reset_at\":7200}}}",
        "{\"account_id\":\"workspace-a\",\"user_id\":\"user-a\",\"plan_type\":\"plus\",\"additional_rate_limits\":[{\"limit_name\":\"One\",\"metered_feature\":\"same\"},{\"limit_name\":\"Two\",\"metered_feature\":\"same\"}]}",
    };
    for (invalid) |payload| {
        var response: Response = .{ .status = 200, .body = try allocator.dupe(u8, payload), .streaming = false };
        defer response.deinit(allocator);
        try std.testing.expectError(error.InvalidCapacity, response.codexUsage(allocator));
    }
}

test "trusted original awake cutoff remains fixed through real curl and rejects expired admission" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const expired: AbsoluteDeadline = .{ .io = io, .until = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) }) };
    var request: Request = .{ .endpoint = .codex_identity, .account_id = "synthetic-account", .grant_id = "synthetic-operation", .absolute_deadline = expired };
    try std.testing.expectError(error.InvalidDeadline, request.validate());
    var wrong_clock = expired;
    wrong_clock.until.clock = .real;
    request.absolute_deadline = wrong_clock;
    try std.testing.expectError(error.InvalidDeadline, request.validate());
    const client = try Client.init(a);
    defer client.deinit();
    var delayed = try Fixture.listen(.delayed);
    defer delayed.deinit();
    try delayed.start();
    request = fixtureRequest(delayed.port);
    request.timeout_ms = 5000;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(20) });
    request.absolute_deadline = .{ .io = io, .until = until };
    const retained = request.absolute_deadline.?.until;
    // A loaded scheduler may consume the original short cutoff before
    // submit's allocation/enqueue recheck. That correct refusal is a predicate,
    // not a transport failure and never permission to extend the cutoff.
    if (client.submit(request)) |_| {
        var completion = try awaitResult(client);
        defer completion.deinit(a);
        try std.testing.expectEqual(Failure.deadline, completion.result.failure);
    } else |err| try std.testing.expectEqual(error.InvalidDeadline, err);
    try std.testing.expectEqual(retained, request.absolute_deadline.?.until);
    try std.testing.expectError(error.InvalidDeadline, request.absolute_deadline.?.remaining());
}

test "original awake deadline expires after observed real curl request without renewing timestamp" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const client = try Client.init(a);
    defer client.deinit();
    var delayed = try Fixture.listen(.delayed);
    delayed.delay_ms = 2000;
    defer delayed.deinit();
    try delayed.start();
    var request = fixtureRequest(delayed.port);
    request.timeout_ms = 5000;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(500) });
    request.absolute_deadline = .{ .io = io, .until = until };
    _ = client.submit(request) catch |err| {
        if (err == error.InvalidDeadline) return error.SkipZigTest;
        return err;
    };
    // Active-curl evidence requires the actual socket fixture to observe the
    // request. If scheduling consumes admission/queue time instead, record a
    // skipped active predicate, not a fabricated active-curl pass.
    for (0..100) |_| {
        if (delayed.request_seen.load(.acquire) or until.durationFromNow(io).raw.toNanoseconds() <= 0) break;
        sleepMilliseconds(5);
    }
    var completion = try awaitResult(client);
    defer completion.deinit(a);
    try std.testing.expectEqual(Failure.deadline, completion.result.failure);
    try std.testing.expectEqual(until, request.absolute_deadline.?.until);
    try std.testing.expectError(error.InvalidDeadline, request.absolute_deadline.?.remaining());
    if (!delayed.request_seen.load(.acquire)) return error.SkipZigTest;
    try std.testing.expect(delayed.authorization_seen.load(.acquire));
}

test "resource requests cannot borrow OAuth token endpoint authority" {
    var resource: Request = .{ .endpoint = .codex_oauth_token, .account_id = "fixture-account", .grant_id = "fixture-grant" };
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    resource.method = .post;
    resource.body = "grant_type=refresh_token&refresh_token=synthetic-unissued";
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    resource.endpoint = .fixture_oauth_token;
    resource.fixture_port = 12345;
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    try std.testing.expect(!Endpoint.codex_oauth_token.provesIdentity());
    resource.endpoint = .omux_oss_oauth_token;
    resource.fixture_port = 0;
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    try std.testing.expect(!Endpoint.omux_oss_oauth_token.provesIdentity());
    try std.testing.expectEqualStrings("https://auth.openai.com", Endpoint.omux_oss_oauth_token.origin());
    try std.testing.expectEqualStrings("/api/accounts/oauth/token", Endpoint.omux_oss_oauth_token.path());
    try std.testing.expectEqualStrings("/oauth/token", Endpoint.codex_oauth_token.path());
}

test "actual committed code ticket sends one bounded form POST without ambient authority" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_form);
    defer server.deinit();
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    try std.testing.expectEqual(@as(u64, 3), issued.issued_revision);
    try server.start();
    const client = try Client.init(a);
    defer client.deinit();
    const id = try client.startOAuth(issued.ticket);
    // Replay refusal must not invalidate the original accepted worker fence.
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(issued.ticket));
    var result = try awaitOAuthResult(client);
    defer result.deinit(a);
    try std.testing.expectEqual(id, result.id);
    try std.testing.expect(client.poll() == null);
    try std.testing.expectEqual(@as(u16, 200), result.result.response.status());
    try result.result.response.recheck(issued.ticket);
    try std.testing.expectEqualStrings("omux-fixture-client", result.result.response.issuedClientId());
    var tokens = try result.result.response.evidence(a);
    defer tokens.deinit();
    const received_sha256 = result.result.response.responseSha256();
    try std.testing.expectEqualSlices(u8, &received_sha256, &tokens.response_sha256);
    try std.testing.expectEqualStrings("synthetic-access", tokens.access_token);
    try std.testing.expectEqualStrings("synthetic-successor-refresh", tokens.refresh_token.?);
    try std.testing.expectEqual(@as(?u32, 3600), tokens.expires_in);
    try std.testing.expect(server.oauth_wire_valid.load(.acquire));
    try std.testing.expect(server.oauth_no_ambient_headers.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
    try issued.fence.checkBeforeCompletion();
    var retained = try issued.store.readSnapshot();
    defer retained.deinit();
    try std.testing.expectEqual(issued.issued_revision, retained.revision);
    // Transport evidence has no actor grant-activation or completion mutation.
    try std.testing.expect(std.mem.indexOf(u8, retained.json, "exchange_issued") != null);
}

test "retired code ticket refuses before HTTP admission and cannot be replayed" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_form);
    defer server.deinit();
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    try std.testing.expectEqual(oauth_authority.Cancellation.prevented_before_dispatch, issued.invalidate());
    const client = try Client.init(a);
    defer client.deinit();
    try std.testing.expectError(error.OAuthDispatchRefused, client.startOAuth(issued.ticket));
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(issued.ticket));
    client.lock();
    const outstanding = client.outstanding;
    client.unlock();
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    try std.testing.expectEqual(@as(u32, 0), server.request_count.load(.acquire));
}

test "in flight code cancellation returns uncertainty without publishing token bytes" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_hold);
    defer server.deinit();
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    try server.start();
    const client = try Client.init(a);
    defer client.deinit();
    _ = try client.startOAuth(issued.ticket);
    for (0..200) |_| {
        if (server.request_seen.load(.acquire)) break;
        sleepMilliseconds(2);
    }
    try std.testing.expect(server.request_seen.load(.acquire));
    try std.testing.expectEqual(oauth_authority.Cancellation.issued_or_racing, issued.invalidate());
    var result = try awaitOAuthResult(client);
    defer result.deinit(a);
    try std.testing.expectEqual(Failure.canceled, result.result.failure);
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(issued.ticket));
    try std.testing.expectError(error.OAuthCompletionIndeterminate, issued.fence.checkBeforeCompletion());
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
}

test "OAuth redirect and response cap never reissue a consumed code" {
    const a = std.testing.allocator;
    const client = try Client.init(a);
    defer client.deinit();
    var redirect = try Fixture.listen(.oauth_redirect);
    defer redirect.deinit();
    var redirected_issue = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, redirect.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer redirected_issue.deinit();
    try redirect.start();
    _ = try client.startOAuth(redirected_issue.ticket);
    var redirected = try awaitOAuthResult(client);
    defer redirected.deinit(a);
    try std.testing.expectEqual(@as(u16, 302), redirected.result.response.status());
    try std.testing.expectError(error.OAuthEndpointRejected, redirected.result.response.evidence(a));
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(redirected_issue.ticket));
    try std.testing.expectEqual(@as(u32, 1), redirect.request_count.load(.acquire));
    var large = try Fixture.listen(.oauth_large);
    defer large.deinit();
    var large_issue = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, large.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer large_issue.deinit();
    try large.start();
    _ = try client.startOAuth(large_issue.ticket);
    var capped = try awaitOAuthResult(client);
    defer capped.deinit(a);
    try std.testing.expectEqual(Failure.response_too_large, capped.result.failure);
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(large_issue.ticket));
    try std.testing.expectEqual(@as(u32, 1), large.request_count.load(.acquire));
}

test "unread resource completions preserve OAuth admission budget and consume refused ticket" {
    const a = std.testing.allocator;
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, 12345, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    const client = try Client.init(a);
    defer client.deinit();
    var request = fixtureRequest(1);
    request.timeout_ms = 50;
    for (0..Limits.outstanding) |_| _ = try client.submit(request);
    try std.testing.expectError(error.Backpressure, client.startOAuth(issued.ticket));
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(issued.ticket));
    // Refusal invalidates only the consumed attempt, not an accepted worker.
    try std.testing.expectError(error.OAuthDispatchRefused, issued.fence.checkBeforeDispatch());
}

test "issued original awake cutoff expires after real OAuth POST without renewing work" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_hold);
    server.delay_ms = 3500;
    defer server.deinit();
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, until);
    defer issued.deinit();
    try server.start();
    const client = try Client.init(a);
    defer client.deinit();
    _ = try client.startOAuth(issued.ticket);
    var received: ?OAuthCompletion = null;
    for (0..900) |_| {
        if (client.pollOAuth()) |value| {
            received = value;
            break;
        }
        sleepMilliseconds(5);
    }
    var result = received orelse return error.FixtureTimeout;
    defer result.deinit(a);
    try std.testing.expect(server.request_seen.load(.acquire));
    try std.testing.expectEqual(Failure.deadline, result.result.failure);
    try std.testing.expect(until.durationFromNow(std.testing.io).raw.toNanoseconds() <= 0);
    try std.testing.expectError(error.OAuthTicketConsumed, client.startOAuth(issued.ticket));
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
    var retained = try issued.store.readSnapshot();
    defer retained.deinit();
    try std.testing.expectEqual(issued.issued_revision, retained.revision);
}

test "owned OAuth completion survives curl shutdown and keeps response isolated" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_form);
    defer server.deinit();
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    try server.start();
    const client = try Client.init(a);
    var closed = false;
    errdefer if (!closed) client.deinit();
    _ = try client.startOAuth(issued.ticket);
    var result = try awaitOAuthResult(client);
    client.deinit();
    closed = true;
    defer result.deinit(a);
    var tokens = try result.result.response.evidence(a);
    defer tokens.deinit();
    try std.testing.expectEqualStrings("synthetic-access", tokens.access_token);
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
}

test "opaque token completion binds original ticket and wipes custody copy on refusal" {
    const a = std.testing.allocator;
    var server = try Fixture.listen(.oauth_form);
    defer server.deinit();
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    var foreign = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, server.port, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer foreign.deinit();
    try server.start();
    const client = try Client.init(a);
    defer client.deinit();
    _ = try client.startOAuth(issued.ticket);
    var completed = try awaitOAuthResult(client);
    defer completed.deinit(a);
    const response = completed.result.response;
    try response.recheck(issued.ticket);
    try std.testing.expectError(error.OAuthResponseAuthorityChanged, response.recheck(foreign.ticket));
    try std.testing.expectError(error.OAuthResponseAuthorityChanged, response.copyForEncryptedCustody(a, foreign.ticket));
    var copied = try response.copyForEncryptedCustody(a, issued.ticket);
    defer copied.deinit();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(copied.bytes, &digest, .{});
    const expected = response.responseSha256();
    try std.testing.expectEqualSlices(u8, &expected, &digest);
    // Fault injection stays private to this source model. No raw constructor
    // or mutable response body is exported to an actor/control caller.
    oauthResponseDataMut(response).body[0] ^= 1;
    try std.testing.expectError(error.OAuthResponseAuthorityChanged, response.evidence(a));
    try std.testing.expectError(error.OAuthResponseAuthorityChanged, response.copyForEncryptedCustody(a, issued.ticket));
}

test "JWKS opaque lease comes from actual bounded GET and retains exact original clock" {
    const a = std.testing.allocator;
    const original: AbsoluteDeadline = .{ .io = std.testing.io, .until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }) };
    var resource: Request = .{ .endpoint = .openai_jwks, .account_id = "fixture-account", .grant_id = "fixture-grant" };
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    resource.endpoint = .fixture_jwks;
    try std.testing.expectError(error.UndeclaredEndpoint, resource.validate());
    try std.testing.expectEqualStrings("https://auth.openai.com", Endpoint.openai_jwks.origin());
    try std.testing.expectEqualStrings("/.well-known/jwks.json", Endpoint.openai_jwks.path());
    var server = try Fixture.listen(.jwks);
    defer server.deinit();
    try server.start();
    const client = try Client.init(a);
    defer client.deinit();
    const id = try client.enqueueJwks(original, server.port, null, null);
    var completion = try awaitJwksResult(client);
    defer completion.deinit(a);
    try std.testing.expectEqual(id, completion.id);
    try std.testing.expect(client.poll() == null and client.pollOAuth() == null);
    const lease = completion.result.lease;
    try lease.recheck(original);
    try std.testing.expectEqualStrings("{\"keys\":[]}", lease.bytes());
    try std.testing.expect(server.jwks_wire_valid.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
    var changed = original;
    changed.until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(9) });
    try std.testing.expectError(error.JwksAuthorityChanged, lease.recheck(changed));
    jwksDataMut(lease).received_unix -= 61;
    try std.testing.expectError(error.JwksAuthorityChanged, lease.recheck(original));
    jwksDataMut(lease).received_unix += 61;
    jwksDataMut(lease).bytes[0] ^= 1;
    try std.testing.expectError(error.JwksAuthorityChanged, lease.recheck(original));
}

test "JWKS redirect and response ceiling create no key authority" {
    const a = std.testing.allocator;
    const client = try Client.init(a);
    defer client.deinit();
    for ([_]@FieldType(Fixture, "mode"){ .jwks_redirect, .jwks_large }) |mode| {
        var server = try Fixture.listen(mode);
        defer server.deinit();
        try server.start();
        _ = try client.enqueueJwks(.{ .io = std.testing.io, .until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }) }, server.port, null, null);
        var completion = try awaitJwksResult(client);
        defer completion.deinit(a);
        try std.testing.expectEqual(if (mode == .jwks_large) Failure.response_too_large else Failure.transport, completion.result.failure);
        try std.testing.expectEqual(@as(u32, 1), server.request_count.load(.acquire));
    }
}

test "JWKS uses shared admission and cannot renew original cutoff" {
    const a = std.testing.allocator;
    const client = try Client.init(a);
    defer client.deinit();
    try std.testing.expectError(error.InvalidDeadline, client.enqueueJwks(.{ .io = std.testing.io, .until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(121) }) }, 1, null, null));
    var delayed = try Fixture.listen(.jwks_delayed);
    delayed.delay_ms = 2000;
    defer delayed.deinit();
    try delayed.start();
    const original: AbsoluteDeadline = .{ .io = std.testing.io, .until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(1500) }) };
    _ = try client.enqueueJwks(original, delayed.port, null, null);
    {
        var completion = try awaitJwksResult(client);
        defer completion.deinit(a);
        try std.testing.expect(delayed.request_seen.load(.acquire));
        try std.testing.expectEqual(Failure.deadline, completion.result.failure);
    }
    var request = fixtureRequest(1);
    request.timeout_ms = 50;
    for (0..Limits.outstanding) |_| _ = try client.submit(request);
    try std.testing.expectError(error.Backpressure, client.enqueueJwks(.{ .io = std.testing.io, .until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }) }, 1, null, null));
}

test "generic code ticket cannot borrow owned OSS key fetch authority or replay its key claim" {
    const a = std.testing.allocator;
    var issued = try oauth_authority.testing.CodeFixture.create(std.testing.io, a, 12345, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(10) }));
    defer issued.deinit();
    const client = try Client.init(a);
    defer client.deinit();
    try std.testing.expectError(error.OAuthAuthorityChanged, client.startJwks(issued.ticket));
    try std.testing.expectError(error.OAuthJwksAlreadyIssued, client.startJwks(issued.ticket));
    client.lock();
    const outstanding = client.outstanding;
    client.unlock();
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    try std.testing.expect(client.pollJwks() == null and client.pollOAuth() == null and client.poll() == null);
}

test "actual Store OSS issued client drives Form exchange and same attempt key provenance" {
    const a = std.testing.allocator;
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(15) });
    var token_server = try testing.Server.listenToken(a);
    defer token_server.deinit();
    var key_server = try testing.Server.listenJwks(a);
    defer key_server.deinit();
    var issued = try oauth_authority.testing.OssRegistrationFixture.create(std.testing.io, a, token_server.port(), key_server.port(), until);
    defer issued.deinit();
    var foreign = try oauth_authority.testing.OssRegistrationFixture.create(std.testing.io, a, token_server.port(), key_server.port(), until);
    defer foreign.deinit();
    try token_server.setBody("{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-successor-refresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
    try key_server.setBody("{\"keys\":[]}");
    try token_server.start(issued.ticket);
    try key_server.start(issued.ticket);
    const client = try Client.init(a);
    defer client.deinit();
    const token_id = try client.startOAuth(issued.ticket);
    var tokens = try awaitOAuthResult(client);
    defer tokens.deinit(a);
    try std.testing.expectEqual(token_id, tokens.id);
    const response = tokens.result.response;
    try std.testing.expect(response.isOwnOss());
    try response.recheck(issued.ticket);
    try std.testing.expectError(error.OAuthResponseAuthorityChanged, response.recheck(foreign.ticket));
    try std.testing.expect(token_server.wireValid());
    try std.testing.expectEqual(@as(u32, 1), token_server.requestCount());
    const key_id = try client.startJwks(issued.ticket);
    // A duplicate key claim does not cancel the already accepted attempt.
    try std.testing.expectError(error.OAuthJwksAlreadyIssued, client.startJwks(issued.ticket));
    var keys = try awaitJwksResult(client);
    defer keys.deinit(a);
    try std.testing.expectEqual(key_id, keys.id);
    const lease = keys.result.lease;
    try lease.recheckTicket(issued.ticket);
    try std.testing.expectError(error.JwksAuthorityChanged, lease.recheckTicket(foreign.ticket));
    try std.testing.expect(key_server.wireValid());
    try std.testing.expectEqual(@as(u32, 1), key_server.requestCount());
    try std.testing.expect(client.poll() == null);
    var saved = try issued.store.readSnapshot();
    defer saved.deinit();
    try std.testing.expectEqual(issued.issued_revision, saved.revision);
    try std.testing.expect(std.mem.indexOf(u8, saved.json, "exchange_issued") != null);
    // Empty public keys and unverified syntax cannot activate a grant. The
    // transport has not changed the issued row or minted a paired refresh.
    try std.testing.expectEqual(oauth_authority.Cancellation.issued_or_racing, issued.invalidate());
    try std.testing.expectError(error.OAuthCompletionIndeterminate, response.recheck(issued.ticket));
    try std.testing.expectError(error.OAuthCompletionIndeterminate, lease.recheckTicket(issued.ticket));
}
