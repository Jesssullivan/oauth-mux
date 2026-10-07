//! Bounded, account-scoped libcurl client. Only the owner thread touches easy
//! handles. The sole cross-thread curl call is the documented multi wakeup.
//! Refresh credentials are deliberately absent from this resource-client API.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const browser = @import("browser_grant.zig");
const root = @import("root");
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

    pub fn origin(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity, .github_capacity => "https://api.github.com",
            .codex_identity, .codex_usage => "https://chatgpt.com",
            .openai_model_catalog => "https://api.openai.com",
            .fixture_identity => "http://127.0.0.1",
            .fixture_tls_identity => "https://localhost",
        };
    }

    pub fn path(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity => "/user",
            .github_capacity => "/rate_limit",
            .codex_identity, .codex_usage => "/backend-api/wham/usage",
            .openai_model_catalog => "/v1/models",
            .fixture_identity, .fixture_tls_identity => "/identity",
        };
    }

    pub fn host(self: Endpoint) []const u8 {
        return switch (self) {
            .github_identity, .github_capacity => "api.github.com",
            .codex_identity, .codex_usage => "chatgpt.com",
            .openai_model_catalog => "api.openai.com",
            .fixture_identity => "127.0.0.1",
            .fixture_tls_identity => "localhost",
        };
    }

    pub fn provesIdentity(self: Endpoint) bool {
        return switch (self) {
            .github_identity, .codex_identity, .codex_usage, .fixture_identity, .fixture_tls_identity => true,
            .github_capacity, .openai_model_catalog => false,
        };
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
    max_response_bytes: usize = 1024 * 1024,
    streaming: bool = false,
    /// Test-only fixture route; never admitted by a non-test executable.
    fixture_port: u16 = 0,

    pub fn validate(self: Request) !void {
        if (!validHandle(self.account_id) or !validHandle(self.grant_id)) return error.InvalidScope;
        if (self.timeout_ms == 0 or self.timeout_ms > Limits.deadline_ms) return error.InvalidDeadline;
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

    fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
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
    paused: bool = false,
    failure: ?Failure = null,

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
        // allocate outside the outstanding request budget.
        transfer.* = .{ .owner = self, .id = id, .request = owned, .deadline = admitted_at + request.timeout_ms };
        std.debug.assert(self.starts.push(transfer));
        self.wakeup();
        return id;
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
                if (monotonicMilliseconds() >= item.deadline) {
                    self.complete(item, .deadline);
                    continue;
                }
                self.configure(item) catch |err| {
                    self.complete(item, if (err == error.OutOfMemory) .allocation else .transport);
                    continue;
                };
                if (c.curl_multi_add_handle(self.multi, item.easy.?) != c.CURLM_OK) {
                    self.complete(item, .transport);
                    continue;
                }
                slot.* = item;
            }
            for (&self.active) |*slot| {
                if (slot.*) |transfer| {
                    if (monotonicMilliseconds() >= transfer.deadline) {
                        _ = c.curl_multi_remove_handle(self.multi, transfer.easy.?);
                        slot.* = null;
                        self.complete(transfer, .deadline);
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
                        self.complete(transfer, transfer.failure orelse failureFromCurl(completed_code));
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
        const easy = c.curl_easy_init() orelse return error.CurlInit;
        transfer.easy = easy;
        transfer.url = if (request.endpoint == .fixture_identity or request.endpoint == .fixture_tls_identity)
            try self.allocator.printSentinel("{s}:{d}{s}", .{ request.endpoint.origin(), request.fixture_port, request.endpoint.path() }, 0)
        else
            try self.allocator.printSentinel("{s}{s}", .{ request.endpoint.origin(), request.endpoint.path() }, 0);
        try setPointer(easy, c.CURLOPT_URL, transfer.url.?.ptr);
        const protocols: [*:0]const u8 = if (request.endpoint == .fixture_identity) "http" else "https";
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
        try setLong(easy, c.CURLOPT_CONNECTTIMEOUT_MS, @intCast(@min(request.timeout_ms, 10_000)));
        try setLong(easy, c.CURLOPT_TIMEOUT_MS, @intCast(@max(1, transfer.deadline -| monotonicMilliseconds())));
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
            try appendHeader(transfer, "Content-Type: application/json");
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
            } else if (transfer.body.toOwnedSlice(self.allocator)) |body| {
                result.result = .{ .response = .{ .status = @intCast(status), .body = body, .streaming = transfer.request.request.streaming } };
            } else |_| result.result = .{ .failure = .allocation };
        }
        switch (result.result) {
            .failure => self.discardChunks(transfer.id),
            .response => {},
        }
        transfer.deinit();
        self.lock();
        std.debug.assert(self.results.push(result));
        self.unlock();
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
    descriptor: c_int,
    port: u16,
    mode: enum { json, redirect, oversized, delayed, stream },
    thread: ?std.Thread = null,
    request_seen: std.atomic.Value(bool) = .init(false),
    authorization_seen: std.atomic.Value(bool) = .init(false),

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
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn deinit(self: *Fixture) void {
        if (self.thread) |thread| thread.join();
        _ = c.close(self.descriptor);
    }

    fn serve(self: *Fixture) void {
        var pollfd: c.struct_pollfd = .{ .fd = self.descriptor, .events = c.POLLIN, .revents = 0 };
        if (c.poll(&pollfd, 1, 1500) <= 0) return;
        const peer = c.accept(self.descriptor, null, null);
        if (peer < 0) return;
        defer _ = c.close(peer);
        if (@hasDecl(c, "SO_NOSIGPIPE")) {
            const enabled: c_int = 1;
            _ = c.setsockopt(peer, c.SOL_SOCKET, c.SO_NOSIGPIPE, &enabled, @sizeOf(c_int));
        }
        var request: [8192]u8 = undefined;
        var length: usize = 0;
        while (length < request.len) {
            const received = c.recv(peer, request[length..].ptr, request.len - length, 0);
            if (received <= 0) return;
            length += @intCast(received);
            if (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") != null) break;
        }
        self.authorization_seen.store(std.mem.indexOf(u8, request[0..length], "Authorization: Bearer fixture-token") != null, .release);
        self.request_seen.store(true, .release);
        switch (self.mode) {
            .json => sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"subject\":\"fixture-1\"}"),
            .redirect => sendAll(peer, "HTTP/1.1 302 Found\r\nLocation: https://undeclared.invalid/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            .oversized => sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            .delayed => {
                sleepMilliseconds(200);
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            },
            .stream => {
                sendAll(peer, "HTTP/1.1 200 OK\r\nContent-Length: 786432\r\nConnection: close\r\n\r\n");
                const payload: [16384]u8 = @splat('x');
                for (0..48) |_| sendAll(peer, &payload);
            },
        }
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

fn awaitResult(client: *Client) !Completion {
    for (0..300) |_| {
        if (client.poll()) |result| return result;
        sleepMilliseconds(5);
    }
    return error.FixtureTimeout;
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
