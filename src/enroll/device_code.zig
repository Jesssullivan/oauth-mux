//! DeviceCodeFlow: RFC 8628 OAuth 2.0 Device Authorization Grant.
//!
//! Flow:
//!   1. POST device_authorization  -> {device_code, user_code, verification_uri, interval}
//!   2. Display user_code + verification_uri  (NOT secrets; safe to display)
//!   3. Poll the token endpoint with device_code until:
//!        - success                  -> tokens (+ id_token)
//!        - authorization_pending    -> wait `interval`, retry
//!        - slow_down                -> increase interval, retry
//!        - access_denied            -> typed error
//!        - expired / timeout        -> typed error
//!   4. Extract email + account_id (from id_token JWT or userinfo) for the gate.
//!
//! The device code itself is NOT a secret (it is bound to this client+grant and is
//! safe to print). Only the resulting access/refresh tokens are secret.
//!
//! INJECTED SEAMS: device_authorize (HTTP), poll_token (HTTP), extract_identity,
//! display_instructions, and a CLOCK/SLEEP seam so timeout + slow_down + backoff
//! are testable with NO real waiting and NO real network. Imports only `std`.

const std = @import("std");

pub const DeviceCodeError = error{
    AuthorizationDenied,
    Timeout,
    HttpFailed,
    InvalidResponse,
    IdentityExtractFailed,
    OutOfMemory,
};

/// RFC 8628 §3.2 device authorization response. Slices are allocator-owned.
pub const DeviceAuthResponse = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: []const u8,
    verification_uri_complete: ?[]const u8 = null,
    expires_in: i64 = 1800,
    interval: i64 = 5,
};

/// RFC 8628 §3.5 token response (success). Slices are allocator-owned.
pub const TokenExchangeResponse = struct {
    access_token: []const u8,
    token_type: []const u8 = "Bearer",
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    /// JWT containing email + account_id claims (provider-dependent).
    id_token: ?[]const u8 = null,
};

pub const IdentityInfo = struct {
    email: []const u8,
    account_id: []const u8,
};

/// Successful flow result. Caller owns all slices.
pub const FlowResult = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    expires_at: ?i64,
    email: []const u8,
    account_id: []const u8,
};

// ── Injected seams ───────────────────────────────────────────────────────────

/// POST to the device_authorization endpoint.
pub const DeviceAuthorizeFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    device_auth_url: []const u8,
    client_id: []const u8,
    scope: []const u8,
) error{ HttpFailed, InvalidResponse, OutOfMemory }!DeviceAuthResponse;

/// Poll the token endpoint. RFC 8628 §3.5 error codes are surfaced as the
/// pending/slow_down/denied errors; everything else collapses to HttpFailed /
/// InvalidResponse.
pub const PollTokenFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    token_url: []const u8,
    device_code: []const u8,
    client_id: []const u8,
) error{
    HttpFailed,
    InvalidResponse,
    OutOfMemory,
    AuthorizationPending,
    SlowDown,
    AuthorizationDenied,
}!TokenExchangeResponse;

/// Extract email + account_id from the id_token (JWT) or via userinfo introspection
/// over the access_token. Returned slices are allocator-owned.
pub const ExtractIdentityFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    id_token: ?[]const u8,
    access_token: []const u8,
) error{ InvalidToken, OutOfMemory }!IdentityInfo;

/// Display the (non-secret) user_code + verification URI to the operator.
pub const DisplayInstructionsFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    user_code: []const u8,
    verification_uri: []const u8,
    verification_uri_complete: ?[]const u8,
) error{OutOfMemory}!void;

/// CLOCK/SLEEP seam. Returns "now" in seconds and sleeps for `seconds`. Injected
/// so tests can advance a virtual clock and never actually wait. The real impl
/// wraps std.time.timestamp() / std.time.sleep().
pub const ClockFn = *const fn (ctx: *anyopaque) i64;
pub const SleepFn = *const fn (ctx: *anyopaque, seconds: i64) void;

pub const DeviceCodeSeams = struct {
    device_authorize: DeviceAuthorizeFn,
    poll_token: PollTokenFn,
    extract_identity: ExtractIdentityFn,
    display_instructions: DisplayInstructionsFn,
    clock: ClockFn,
    sleep: SleepFn,

    device_authorize_ctx: *anyopaque,
    poll_token_ctx: *anyopaque,
    extract_identity_ctx: *anyopaque,
    display_instructions_ctx: *anyopaque,
    clock_ctx: *anyopaque,
    sleep_ctx: *anyopaque,
};

pub const DeviceCodeFlow = struct {
    allocator: std.mem.Allocator,
    seams: DeviceCodeSeams,
    device_auth_url: []const u8,
    token_url: []const u8,
    client_id: []const u8,
    scope: []const u8,
    /// Overall deadline (seconds). The provider's expires_in clamps this lower.
    timeout_s: i64 = 1800,
    /// RFC 8628 §3.5: on slow_down, increase interval by at least 5s.
    slow_down_increment_s: i64 = 5,
    max_poll_interval_s: i64 = 120,

    pub fn init(
        allocator: std.mem.Allocator,
        seams: DeviceCodeSeams,
        device_auth_url: []const u8,
        token_url: []const u8,
        client_id: []const u8,
        scope: []const u8,
    ) DeviceCodeFlow {
        return .{
            .allocator = allocator,
            .seams = seams,
            .device_auth_url = device_auth_url,
            .token_url = token_url,
            .client_id = client_id,
            .scope = scope,
        };
    }

    fn freeDeviceAuth(self: *const DeviceCodeFlow, da: DeviceAuthResponse) void {
        self.allocator.free(da.device_code);
        self.allocator.free(da.user_code);
        self.allocator.free(da.verification_uri);
        if (da.verification_uri_complete) |u| self.allocator.free(u);
    }

    fn freeTokenResp(self: *const DeviceCodeFlow, tr: TokenExchangeResponse) void {
        self.allocator.free(tr.access_token);
        self.allocator.free(tr.token_type);
        if (tr.refresh_token) |rt| self.allocator.free(rt);
        if (tr.scope) |s| self.allocator.free(s);
        if (tr.id_token) |it| self.allocator.free(it);
    }

    /// Execute the device code flow end-to-end. On success returns owned tokens +
    /// provider-confirmed identity. Caller owns all returned slices.
    pub fn run(self: *const DeviceCodeFlow) DeviceCodeError!FlowResult {
        // 1. Request device authorization.
        const dev_auth = self.seams.device_authorize(
            self.allocator,
            self.seams.device_authorize_ctx,
            self.device_auth_url,
            self.client_id,
            self.scope,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.HttpFailed => return error.HttpFailed,
            error.InvalidResponse => return error.InvalidResponse,
        };
        defer self.freeDeviceAuth(dev_auth);

        // 2. Display the non-secret user_code + verification URI.
        self.seams.display_instructions(
            self.allocator,
            self.seams.display_instructions_ctx,
            dev_auth.user_code,
            dev_auth.verification_uri,
            dev_auth.verification_uri_complete,
        ) catch return error.OutOfMemory;

        // 3. Poll the token endpoint, honoring interval / slow_down / deadline.
        const start = self.seams.clock(self.seams.clock_ctx);
        const deadline = start + @min(self.timeout_s, dev_auth.expires_in);
        var poll_interval = dev_auth.interval;

        while (true) {
            // Deadline check happens BEFORE sleeping so a zero-interval virtual
            // clock can still time out deterministically.
            if (self.seams.clock(self.seams.clock_ctx) >= deadline) {
                return error.Timeout;
            }

            self.seams.sleep(self.seams.sleep_ctx, poll_interval);

            const token_resp = self.seams.poll_token(
                self.allocator,
                self.seams.poll_token_ctx,
                self.token_url,
                dev_auth.device_code,
                self.client_id,
            ) catch |err| switch (err) {
                error.AuthorizationPending => continue,
                error.SlowDown => {
                    poll_interval = @min(
                        self.max_poll_interval_s,
                        poll_interval + self.slow_down_increment_s,
                    );
                    continue;
                },
                error.AuthorizationDenied => return error.AuthorizationDenied,
                error.OutOfMemory => return error.OutOfMemory,
                error.HttpFailed => return error.HttpFailed,
                error.InvalidResponse => return error.InvalidResponse,
            };
            // From here (on a successful poll) the token response is owned by us;
            // free on every exit. The error `continue`s above never reach here.
            defer self.freeTokenResp(token_resp);

            // 4. Extract identity for the confirm gate.
            const identity = self.seams.extract_identity(
                self.allocator,
                self.seams.extract_identity_ctx,
                token_resp.id_token,
                token_resp.access_token,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidToken => return error.IdentityExtractFailed,
            };
            // identity.email / identity.account_id are owned; token dupes below may
            // still fail, so those failure branches must free identity explicitly.

            const expires_at: ?i64 = if (token_resp.expires_in) |e|
                self.seams.clock(self.seams.clock_ctx) + e
            else
                null;

            // Allocate to locals with explicit cleanup so a later dupe failure
            // never leaks an earlier one. (Building these inline in the struct
            // literal leaked `access_token` when the `refresh_token` dupe OOM'd.)
            const access_owned = self.allocator.dupe(u8, token_resp.access_token) catch {
                self.allocator.free(identity.email);
                self.allocator.free(identity.account_id);
                return error.OutOfMemory;
            };
            const refresh_owned: ?[]const u8 = if (token_resp.refresh_token) |rt|
                (self.allocator.dupe(u8, rt) catch {
                    self.allocator.free(access_owned);
                    self.allocator.free(identity.email);
                    self.allocator.free(identity.account_id);
                    return error.OutOfMemory;
                })
            else
                null;

            return FlowResult{
                .access_token = access_owned,
                .refresh_token = refresh_owned,
                .expires_at = expires_at,
                .email = identity.email,
                .account_id = identity.account_id,
            };
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TESTS (no network, no real sleeping)
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Drives the seams: a scripted poll sequence + a virtual clock that advances on
/// each sleep, so timeouts are deterministic and instantaneous.
const Harness = struct {
    /// Poll responses to serve, in order. Each entry is an error code or success.
    const PollStep = union(enum) {
        pending,
        slow_down,
        denied,
        success,
    };
    poll_script: []const PollStep,
    poll_index: usize = 0,

    /// Virtual clock (seconds). Advances by the slept amount on every sleep call.
    now: i64 = 1000,
    slept_total: i64 = 0,
    sleep_calls: usize = 0,
    /// Records the interval passed to each sleep, for backoff assertions.
    last_sleep_interval: i64 = 0,

    display_called: bool = false,
    /// If true, the clock auto-advances even without sleeps (used to force timeout
    /// while every poll says pending).
    auto_advance_per_poll: i64 = 0,

    fn deviceAuthorize(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        _: []const u8,
        _: []const u8,
        _: []const u8,
    ) error{ HttpFailed, InvalidResponse, OutOfMemory }!DeviceAuthResponse {
        _ = ctx;
        // OOM-safe: free earlier dupes if a later one fails (so checkAllAllocationFailures
        // exercises run()'s leak-safety, not a leak in this fake).
        const dc = try allocator.dupe(u8, "DEVICE_CODE_SECRET_OK_TO_HOLD");
        errdefer allocator.free(dc);
        const uc = try allocator.dupe(u8, "WXYZ-7788");
        errdefer allocator.free(uc);
        const vu = try allocator.dupe(u8, "https://auth.example.com/device");
        errdefer allocator.free(vu);
        const vuc = try allocator.dupe(u8, "https://auth.example.com/device?user_code=WXYZ-7788");
        errdefer allocator.free(vuc);
        return .{
            .device_code = dc,
            .user_code = uc,
            .verification_uri = vu,
            .verification_uri_complete = vuc,
            .expires_in = 600,
            .interval = 5,
        };
    }

    fn pollToken(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        _: []const u8,
        _: []const u8,
        _: []const u8,
    ) error{
        HttpFailed,
        InvalidResponse,
        OutOfMemory,
        AuthorizationPending,
        SlowDown,
        AuthorizationDenied,
    }!TokenExchangeResponse {
        const self: *Harness = @ptrCast(@alignCast(ctx));
        // If we ran off the end of the script, keep saying pending.
        const step: PollStep = if (self.poll_index < self.poll_script.len)
            self.poll_script[self.poll_index]
        else
            .pending;
        self.poll_index += 1;

        return switch (step) {
            .pending => error.AuthorizationPending,
            .slow_down => error.SlowDown,
            .denied => error.AuthorizationDenied,
            .success => blk: {
                const at = try allocator.dupe(u8, "ACCESS_secret");
                errdefer allocator.free(at);
                const tt = try allocator.dupe(u8, "Bearer");
                errdefer allocator.free(tt);
                const rt = try allocator.dupe(u8, "REFRESH_secret");
                errdefer allocator.free(rt);
                const sc = try allocator.dupe(u8, "openid email");
                errdefer allocator.free(sc);
                const it = try allocator.dupe(u8, "header.payload.sig");
                errdefer allocator.free(it); // redundant today (last alloc), kept for insert-safety
                break :blk .{
                    .access_token = at,
                    .token_type = tt,
                    .expires_in = 3600,
                    .refresh_token = rt,
                    .scope = sc,
                    .id_token = it,
                };
            },
        };
    }

    fn extractIdentity(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        _: ?[]const u8,
        _: []const u8,
    ) error{ InvalidToken, OutOfMemory }!IdentityInfo {
        _ = ctx;
        const em = try allocator.dupe(u8, "dev@example.com");
        errdefer allocator.free(em);
        const aid = try allocator.dupe(u8, "acct_dev_42");
        return .{ .email = em, .account_id = aid };
    }

    fn display(
        _: std.mem.Allocator,
        ctx: *anyopaque,
        _: []const u8,
        _: []const u8,
        _: ?[]const u8,
    ) error{OutOfMemory}!void {
        const self: *Harness = @ptrCast(@alignCast(ctx));
        self.display_called = true;
    }

    fn clock(ctx: *anyopaque) i64 {
        const self: *Harness = @ptrCast(@alignCast(ctx));
        // Auto-advance models wall time passing between deadline checks.
        self.now += self.auto_advance_per_poll;
        return self.now;
    }

    fn sleepVirtual(ctx: *anyopaque, seconds: i64) void {
        const self: *Harness = @ptrCast(@alignCast(ctx));
        self.now += seconds;
        self.slept_total += seconds;
        self.sleep_calls += 1;
        self.last_sleep_interval = seconds;
    }

    fn seams(self: *Harness) DeviceCodeSeams {
        return .{
            .device_authorize = Harness.deviceAuthorize,
            .poll_token = Harness.pollToken,
            .extract_identity = Harness.extractIdentity,
            .display_instructions = Harness.display,
            .clock = Harness.clock,
            .sleep = Harness.sleepVirtual,
            .device_authorize_ctx = @ptrCast(self),
            .poll_token_ctx = @ptrCast(self),
            .extract_identity_ctx = @ptrCast(self),
            .display_instructions_ctx = @ptrCast(self),
            .clock_ctx = @ptrCast(self),
            .sleep_ctx = @ptrCast(self),
        };
    }
};

fn freeResult(allocator: std.mem.Allocator, r: FlowResult) void {
    allocator.free(r.access_token);
    if (r.refresh_token) |rt| allocator.free(rt);
    allocator.free(r.email);
    allocator.free(r.account_id);
}

/// Drive the flow to success under the given allocator and free the result. Used
/// by the OOM-safety check below: every allocation in `run()` (including the
/// FlowResult access/refresh dupes) propagates OutOfMemory and must not leak.
fn runHappyToCompletion(allocator: std.mem.Allocator) !void {
    var h = Harness{ .poll_script = &.{.success} };
    const flow = DeviceCodeFlow.init(allocator, h.seams(), "https://x/device", "https://x/token", "cid", "openid");
    const r = try flow.run();
    freeResult(allocator, r);
}

test "device_code: run() is OOM-safe at every allocation point (regression: FlowResult dupe must not leak access_token)" {
    // checkAllAllocationFailures re-runs the flow failing at each allocation index
    // in turn, asserting OutOfMemory is returned AND nothing leaks. Before the fix,
    // failing on the refresh_token dupe leaked the already-duped access_token.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, runHappyToCompletion, .{});
}

test "device_code: authorization_pending x2 then success yields token + identity" {
    const allocator = testing.allocator;
    var h = Harness{ .poll_script = &.{ .pending, .pending, .success } };
    const flow = DeviceCodeFlow.init(
        allocator,
        h.seams(),
        "https://auth.example.com/device_authorization",
        "https://auth.example.com/token",
        "client_abc",
        "openid email",
    );

    const result = try flow.run();
    defer freeResult(allocator, result);

    try testing.expect(h.display_called);
    try testing.expectEqualStrings("ACCESS_secret", result.access_token);
    try testing.expectEqualStrings("REFRESH_secret", result.refresh_token.?);
    try testing.expectEqualStrings("dev@example.com", result.email);
    try testing.expectEqualStrings("acct_dev_42", result.account_id);
    // Two pending polls => at least two sleeps before success.
    try testing.expect(h.sleep_calls >= 3);
}

test "device_code: timeout returns typed Timeout error" {
    const allocator = testing.allocator;
    // Every poll says pending; auto-advance the clock 200s per deadline check so we
    // blow past the 600s expires_in quickly and deterministically (no real wait).
    var h = Harness{
        .poll_script = &.{ .pending, .pending, .pending, .pending, .pending, .pending, .pending, .pending },
        .auto_advance_per_poll = 200,
    };
    const flow = DeviceCodeFlow.init(
        allocator,
        h.seams(),
        "https://auth.example.com/device_authorization",
        "https://auth.example.com/token",
        "client_abc",
        "openid email",
    );

    try testing.expectError(error.Timeout, flow.run());
}

test "device_code: slow_down increases the poll interval (backoff respected)" {
    const allocator = testing.allocator;
    // pending(5s), slow_down(->10s), then success.
    var h = Harness{ .poll_script = &.{ .pending, .slow_down, .success } };
    const flow = DeviceCodeFlow.init(
        allocator,
        h.seams(),
        "https://auth.example.com/device_authorization",
        "https://auth.example.com/token",
        "client_abc",
        "openid email",
    );

    const result = try flow.run();
    defer freeResult(allocator, result);

    // After the slow_down, the next sleep interval must have grown from 5 to 10.
    try testing.expectEqual(@as(i64, 10), h.last_sleep_interval);
}

test "device_code: access_denied returns typed AuthorizationDenied error" {
    const allocator = testing.allocator;
    var h = Harness{ .poll_script = &.{ .pending, .denied } };
    const flow = DeviceCodeFlow.init(
        allocator,
        h.seams(),
        "https://auth.example.com/device_authorization",
        "https://auth.example.com/token",
        "client_abc",
        "openid email",
    );

    try testing.expectError(error.AuthorizationDenied, flow.run());
}
