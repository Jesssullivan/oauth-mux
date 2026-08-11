//! Localhost HTTP/1.1 reverse proxy for Codex's
//! `/backend-api/codex/...` endpoints.
//!
//! Anchor: docs/spec/codex-adapter-contract-2026-05-03.md §4 (Wire-Layer
//! Proxy Spec) + §3 (401-vs-429 Handling Matrix).
//!
//! The proxy is the load-bearing piece that lets account swap happen
//! without restarting the unmodified `codex` child process. It sits at
//! 127.0.0.1:<dynamic-port> with codex's generated
//! `openai_base_url` pointed at it while keeping Codex's built-in
//! `model_provider = "openai"` namespace (via a generated config.toml in
//! the per-session CODEX_HOME). Keeping the built-in provider id is
//! load-bearing for native resume-picker parity because Codex filters
//! persisted sessions by `threads.model_provider`.
//! On every request:
//!
//!   1. Read the inbound request from codex.
//!   2. Substitute the three account-bound headers (Authorization,
//!      ChatGPT-Account-ID, X-OpenAI-Fedramp) with the broker's
//!      currently-elected account's values, except when Codex has
//!      refreshed the same elected account inside the managed overlay.
//!      In that same-account case, preserve the child's refreshed
//!      Authorization so the proxy does not pin Codex to a stale
//!      materialized access token.
//!   3. Forward all other headers UNCHANGED — including the eight
//!      load-bearing ones from §4.2 (User-Agent, originator,
//!      x-codex-installation-id, x-codex-turn-state,
//!      x-codex-turn-metadata, OpenAI-Beta, traceparent, tracestate).
//!   4. Reject unsupported WebSocket upgrade attempts locally; otherwise send
//!      to chatgpt.com over TLS.
//!   5. Classify the response (200 / 401 / 429+usage_limit_reached /
//!      429+usage_not_included / other-429 / 5xx).
//!   6. Feed the typed outcome to the shared attempt reducer. A model-bearing
//!      request may consume exactly one follow-up: either one confirmed-not-sent
//!      retry on the same account, or one distinct-account alternate after a
//!      fully buffered 401/403/429. Provider 5xx passes through to Codex, and
//!      ambiguity, cancellation, or any started response is terminal.
//!   7. Stream the final response body verbatim back to codex (SSE works
//!      because chunked-transfer is forwarded byte-for-byte).
//!
//! Phase 2 scope (honestly labelled limitations):
//!   - Synchronous, single-connection-at-a-time (codex sends one
//!     request per turn). No request pipelining.
//!   - **Streaming for 200/3xx/5xx; buffered for retry-eligible 4xx.** SSE turns
//!     stream byte-for-byte from upstream to codex via Connection:close
//!     framing — the TUI animation moves in real time. Only 4xx responses stay
//!     buffered (with a 64 KiB cap) because 401/403/429 are the explicit
//!     pre-body alternate boundary. Provider 5xx is never replayed by omux.
//!   - No WebSocket upgrade support. If Codex requests a WS upgrade, the proxy
//!     returns a local HTTP 426 fallback signal and never forwards it upstream
//!     as a plain HTTP GET. Phase 2.2 adds WS pass-through.
//!   - The one permitted cross-account alternate drops `x-codex-turn-state`
//!     because that token is likely tied to the previous account's server-side
//!     state. Synthetic tests prove the structure; live provider-originated
//!     quota proof is still required before promoting the runtime claim level.

const std = @import("std");
const builtin = @import("builtin");
const broker_types = @import("../../broker/types.zig");
const account_pool_mod = @import("../../broker/account_pool.zig");
const broker_attempt_policy = @import("../../broker/attempt_policy.zig");
const broker_decision = @import("../../broker/decision.zig");
const broker_lease_state = @import("../../broker/lease_state.zig");
const broker_model_demand = @import("../../broker/model_demand.zig");
const broker_route_observation = @import("../../broker/route_observation.zig");
const advisory_usage = @import("../../quota/advisory_usage.zig");
const env = @import("../../env.zig");
const health_mod = @import("../../health.zig");
const managed_harness_contract = @import("../../managed_harness_contract.zig");
const provider_schema = @import("../../provider_schema.zig");
const trace = @import("../../trace.zig");
const core_types = @import("../../types.zig");

const DEFAULT_UPSTREAM_HOST = "chatgpt.com";
const DEFAULT_UPSTREAM_SCHEME = "https";
const UPSTREAM_BASE_PATH = "/backend-api/codex";
const PROXY_IO_TIMEOUT_DEFAULT_MS: i32 = 30_000;
const PROXY_IO_TIMEOUT_MAX_MS: i32 = 10 * 60 * 1000;
const PROXY_UPSTREAM_RESPONSE_TIMEOUT_DEFAULT_MS: i32 = 30_000;
const PROXY_UPSTREAM_RESPONSE_TIMEOUT_MAX_MS: i32 = 10 * 60 * 1000;
const PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_DEFAULT_MS: i32 = 10 * 60 * 1000;
const PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_MAX_MS: i32 = 60 * 60 * 1000;
const REPLAY_REQUEST_LIMIT_BYTES: usize = @intCast(managed_harness_contract.replay_request_limit_bytes);
const REPLAY_SIDECAR_LIMIT_BYTES: usize = @intCast(managed_harness_contract.replay_sidecar_limit_bytes);
const REPLAY_HOST_LIMIT_BYTES: usize = @intCast(managed_harness_contract.replay_host_limit_bytes);

pub const RouteState = enum {
    available,
    auth_failed,
    quota_exhausted,
    rate_limited,
    tier_insufficient,
    provider_degraded,
    credential_unavailable,
};

const CandidateRejection = struct {
    account: []const u8,
    state: RouteState,
    reason: []const u8,
};

/// Resolve the upstream host. `OMUX_UPSTREAM_HOST` overrides for
/// in-session integration tests (the smoke harness binds a stub
/// upstream on 127.0.0.1:<port> and points the proxy at it).
/// Production: falls back to chatgpt.com.
fn upstreamHost(allocator: std.mem.Allocator) []const u8 {
    if (std.process.getEnvVarOwned(allocator, "OMUX_UPSTREAM_HOST")) |v| {
        return v;
    } else |_| {
        return allocator.dupe(u8, DEFAULT_UPSTREAM_HOST) catch DEFAULT_UPSTREAM_HOST;
    }
}

fn upstreamScheme(allocator: std.mem.Allocator) []const u8 {
    if (std.process.getEnvVarOwned(allocator, "OMUX_UPSTREAM_SCHEME")) |v| {
        return v;
    } else |_| {
        return allocator.dupe(u8, DEFAULT_UPSTREAM_SCHEME) catch DEFAULT_UPSTREAM_SCHEME;
    }
}

fn configuredPositiveTimeoutMs(
    allocator: std.mem.Allocator,
    env_name: []const u8,
    default_ms: i32,
    max_ms: i32,
) i32 {
    const raw = std.process.getEnvVarOwned(allocator, env_name) catch return default_ms;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const parsed = std.fmt.parseInt(i32, trimmed, 10) catch return default_ms;
    if (parsed <= 0) return default_ms;
    return @min(parsed, max_ms);
}

fn configuredProxyIoTimeoutMs(allocator: std.mem.Allocator) i32 {
    return configuredPositiveTimeoutMs(
        allocator,
        "OMUX_PROXY_IO_TIMEOUT_MS",
        PROXY_IO_TIMEOUT_DEFAULT_MS,
        PROXY_IO_TIMEOUT_MAX_MS,
    );
}

fn configuredProxyUpstreamResponseTimeoutMs(allocator: std.mem.Allocator) i32 {
    return configuredPositiveTimeoutMs(
        allocator,
        "OMUX_PROXY_UPSTREAM_RESPONSE_TIMEOUT_MS",
        PROXY_UPSTREAM_RESPONSE_TIMEOUT_DEFAULT_MS,
        PROXY_UPSTREAM_RESPONSE_TIMEOUT_MAX_MS,
    );
}

fn configuredProxyUpstreamBodyIdleTimeoutMs(allocator: std.mem.Allocator) i32 {
    return configuredPositiveTimeoutMs(
        allocator,
        "OMUX_PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_MS",
        PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_DEFAULT_MS,
        PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_MAX_MS,
    );
}

const ProxyIoWaitError = std.posix.PollError || error{ ConnectionTimedOut, ConnectionResetByPeer };

fn pollSocket(handle: std.posix.socket_t, events: i16, timeout_ms: i32) ProxyIoWaitError!i16 {
    var fds = [_]std.posix.pollfd{.{
        .fd = handle,
        .events = events,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&fds, timeout_ms);
    if (ready == 0) return error.ConnectionTimedOut;
    if (fds[0].revents & events == 0 and fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL | std.posix.POLL.HUP) != 0) {
        return error.ConnectionResetByPeer;
    }
    return fds[0].revents;
}

fn waitForSocket(handle: std.posix.socket_t, events: i16, timeout_ms: i32) ProxyIoWaitError!void {
    _ = try pollSocket(handle, events, timeout_ms);
}

fn waitForUpstreamResponseStart(http_req: *std.http.Client.Request, timeout_ms: i32) ProxyIoWaitError!i16 {
    const connection = http_req.connection orelse return 0;
    return try pollSocket(connection.stream.handle, @intCast(std.posix.POLL.IN), timeout_ms);
}

const SocketReceiveTimeoutError = std.posix.SetSockOptError || error{InvalidSocketState};

fn setSocketReceiveTimeoutMs(handle: std.posix.socket_t, timeout_ms: i32) SocketReceiveTimeoutError!void {
    if (builtin.os.tag == .windows) {
        var timeout: u32 = @intCast(@max(timeout_ms, 0));
        try std.posix.setsockopt(
            handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );
        return;
    }

    const timeout = std.posix.timeval{
        .sec = @intCast(@divTrunc(timeout_ms, 1000)),
        .usec = @intCast(@rem(timeout_ms, 1000) * 1000),
    };
    switch (std.posix.errno(std.posix.system.setsockopt(
        handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout).ptr,
        @intCast(std.mem.asBytes(&timeout).len),
    ))) {
        .SUCCESS => {},
        .BADF, .FAULT, .INVAL => return error.InvalidSocketState,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .DOM => return error.TimeoutTooBig,
        .ISCONN => return error.AlreadyConnected,
        .NOPROTOOPT => return error.InvalidProtocolOption,
        .NOMEM => return error.SystemResources,
        .NOBUFS => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        .NODEV => return error.NoDevice,
        .OPNOTSUPP => return error.OperationNotSupported,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn setUpstreamResponseReadTimeout(http_req: *std.http.Client.Request, timeout_ms: i32) SocketReceiveTimeoutError!void {
    const connection = http_req.connection orelse return;
    try setSocketReceiveTimeoutMs(connection.stream.handle, timeout_ms);
}

fn clearUpstreamResponseReadTimeout(http_req: *std.http.Client.Request) void {
    setUpstreamResponseReadTimeout(http_req, 0) catch {};
}

fn waitForUpstreamResponseHeaders(http_req: *std.http.Client.Request, timeout_ms: i32) !void {
    const revents = try waitForUpstreamResponseStart(http_req, timeout_ms);
    const can_set_deadline = revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL | std.posix.POLL.HUP) == 0;
    if (can_set_deadline) {
        try setUpstreamResponseReadTimeout(http_req, timeout_ms);
    }

    const started_ns = std.time.nanoTimestamp();
    http_req.wait() catch |err| {
        if (err == error.ConnectionTimedOut) return error.ConnectionTimedOut;
        if (err == error.UnexpectedReadFailure) {
            const timeout_ns = @as(i128, timeout_ms) * std.time.ns_per_ms;
            const slack_ns = 50 * std.time.ns_per_ms;
            if (std.time.nanoTimestamp() - started_ns + slack_ns >= timeout_ns) {
                return error.ConnectionTimedOut;
            }
        }
        return err;
    };
    if (can_set_deadline) {
        clearUpstreamResponseReadTimeout(http_req);
    }
}

fn setUpstreamBodyIdleReadTimeoutIfSafe(http_req: *std.http.Client.Request, timeout_ms: i32) bool {
    const connection = http_req.connection orelse return false;
    const revents = pollSocket(connection.stream.handle, @intCast(std.posix.POLL.IN), 0) catch |err| switch (err) {
        error.ConnectionTimedOut => 0,
        error.ConnectionResetByPeer => return false,
        else => return false,
    };
    if (revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL | std.posix.POLL.HUP) != 0) return false;
    setSocketReceiveTimeoutMs(connection.stream.handle, timeout_ms) catch return false;
    return true;
}

fn timeoutLikelyElapsed(started_ns: i128, timeout_ms: i32) bool {
    const timeout_ns = @as(i128, timeout_ms) * std.time.ns_per_ms;
    const slack_ns = 50 * std.time.ns_per_ms;
    return std.time.nanoTimestamp() - started_ns + slack_ns >= timeout_ns;
}

const TimedUpstreamBodyReader = struct {
    request: *std.http.Client.Request,
    timeout_ms: i32,
    timeout_active: bool,

    pub const ReadError = std.http.Client.Request.ReadError;
    pub const Reader = std.io.Reader(*TimedUpstreamBodyReader, ReadError, read);

    pub fn reader(self: *TimedUpstreamBodyReader) Reader {
        return .{ .context = self };
    }

    pub fn read(self: *TimedUpstreamBodyReader, buffer: []u8) ReadError!usize {
        if (buffer.len == 0) return 0;
        const started_ns = std.time.nanoTimestamp();
        return self.request.read(buffer) catch |err| {
            if (err == error.ConnectionTimedOut) return error.ConnectionTimedOut;
            if (self.timeout_active and err == error.UnexpectedReadFailure and timeoutLikelyElapsed(started_ns, self.timeout_ms)) {
                return error.ConnectionTimedOut;
            }
            return err;
        };
    }
};

const TimedProxyStream = struct {
    stream: std.net.Stream,
    timeout_ms: i32,

    pub const ReadError = std.net.Stream.ReadError || ProxyIoWaitError;
    pub const WriteError = std.net.Stream.WriteError || ProxyIoWaitError;
    pub const Reader = std.io.Reader(TimedProxyStream, ReadError, read);
    pub const Writer = std.io.Writer(TimedProxyStream, WriteError, write);

    pub fn reader(self: TimedProxyStream) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: TimedProxyStream) Writer {
        return .{ .context = self };
    }

    pub fn read(self: TimedProxyStream, buffer: []u8) ReadError!usize {
        if (buffer.len == 0) return 0;
        try waitForSocket(self.stream.handle, @intCast(std.posix.POLL.IN), self.timeout_ms);
        return self.stream.read(buffer);
    }

    pub fn write(self: TimedProxyStream, bytes: []const u8) WriteError!usize {
        if (bytes.len == 0) return 0;
        try waitForSocket(self.stream.handle, @intCast(std.posix.POLL.OUT), self.timeout_ms);
        return self.stream.write(bytes);
    }
};

pub const Proxy = struct {
    allocator: std.mem.Allocator,
    server: std.net.Server,
    addr: std.net.Address,

    /// Borrowed reference to the broker's account pool. The proxy
    /// elects/marks against this pool directly rather than over MCP
    /// because the embedded broker is in-process for `oauth-mux codex run`.
    /// In a daemon-attached topology (post-Phase 5) this would become
    /// MCP calls.
    pool: *account_pool_mod.AccountPool,

    /// Borrowed materializer used to resolve `provider:account` ->
    /// chatgpt_auth_tokens tuple per request. Owned by the adapter.
    materializer: broker_types.CredentialMaterializer,

    /// Restrict materialization (and election) to this profile name's
    /// allow-list. Owned by the adapter for the proxy lifetime.
    profile: ?[]const u8 = null,

    /// Capability scope for durable route health written by observed
    /// broker-run traffic. Borrowed from managed launch options.
    capability: ?[]const u8 = null,

    /// The account selected before the managed Codex child was launched.
    /// Bootstrap and non-model traffic remains pinned here; only a parsed,
    /// exact-model Responses request may enter shared route election.
    /// Borrowed from the pool for the proxy lifetime.
    launch_account: ?[]const u8 = null,

    /// stderr writer for redacted diagnostic logs. Never carries token
    /// material; emits NDJSON status frames the adapter can correlate.
    log_writer: std.io.AnyWriter,

    /// The account we signed the previous request with, if any. Used
    /// to detect account changes between turns. On the very NEXT
    /// request after the elected account changes, the proxy drops the
    /// `x-codex-turn-state` sticky-routing token from the outbound
    /// headers — that token binds a conversation thread to the prior
    /// account's `sub` server-side (per issue openai/codex#16894), and
    /// carrying it across a swap surfaces "previous account's usage
    /// limit" warnings even though the new account had room.
    /// Owned by self.allocator.
    previous_account: ?[]const u8 = null,

    /// The strongest claim level this adapter publishes in status frames.
    /// Live handoff proof is recorded as typed evidence events; claim-level
    /// promotion remains separate until the broader same-thread semantics are
    /// settled.
    peak_claim: broker_types.ClaimLevel = .broker_owned,

    /// True once the proxy observed an account change inside one
    /// adapter-owned child process. This is useful synthetic evidence,
    /// but is deliberately separate from the live claim ladder.
    synthetic_swap_seen: bool = false,

    auth_failure_tracker: AuthFailureTracker = .{},

    /// Retained request bodies count against the v0.2 64 MiB sidecar replay
    /// budget before they become alternate-eligible. The 256 MiB host-wide
    /// ceiling remains an explicit cross-process integration bound: this
    /// adapter process has no authoritative host reservation owner yet.
    replay_reservation: ReplayReservation = .{},

    pub fn bind(
        allocator: std.mem.Allocator,
        pool: *account_pool_mod.AccountPool,
        materializer: broker_types.CredentialMaterializer,
        log_writer: std.io.AnyWriter,
    ) !Proxy {
        const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
        var server = try loopback.listen(.{ .reuse_address = true });
        errdefer server.deinit();
        const bound = server.listen_address;
        return Proxy{
            .allocator = allocator,
            .server = server,
            .addr = bound,
            .pool = pool,
            .materializer = materializer,
            .log_writer = log_writer,
        };
    }

    pub fn deinit(self: *Proxy) void {
        std.debug.assert(self.replay_reservation.outstanding() == 0);
        self.server.deinit();
        if (self.previous_account) |a| self.allocator.free(a);
        self.previous_account = null;
        self.auth_failure_tracker.deinit(self.allocator);
    }

    pub fn port(self: *const Proxy) u16 {
        return self.addr.getPort();
    }

    /// Returns the highest claim level any turn through this proxy
    /// has actually achieved. Adapter reads this at session_ended.
    pub fn peakClaimLevel(self: *const Proxy) broker_types.ClaimLevel {
        return self.peak_claim;
    }

    pub fn syntheticSwapSeen(self: *const Proxy) bool {
        return self.synthetic_swap_seen;
    }

    pub fn authFailureObservation(self: *const Proxy) AuthFailureObservation {
        return self.auth_failure_tracker.observation();
    }

    /// Accept one connection, handle one HTTP/1.1 transaction, close.
    /// Returns when the transaction is complete (or fails). Caller
    /// invokes this in a loop while the codex child is alive.
    pub fn serveOne(self: *Proxy) !void {
        var conn = try self.server.accept();
        defer conn.stream.close();
        const stream = TimedProxyStream{
            .stream = conn.stream,
            .timeout_ms = configuredProxyIoTimeoutMs(self.allocator),
        };
        try self.handleConnection(stream);
    }

    fn handleConnection(self: *Proxy, stream: TimedProxyStream) !void {
        const reader = stream.reader();
        const writer = stream.writer();

        try self.handleRequest(reader, writer);
    }

    fn handleRequest(self: *Proxy, reader: anytype, writer: anytype) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        // ── 1. Parse inbound request ────────────────────────────
        const req = parseRequest(a, reader, &self.replay_reservation) catch |err| {
            // EndOfStream on accept is the shutdown tickle from the
            // adapter — silently bail without writing a response.
            if (err == error.EndOfStream) return;
            self.logEvent("proxy_request_parse_error", .{ .err = @errorName(err) });
            try writeStatus(writer, 400, "Bad Request");
            return;
        };
        defer self.replay_reservation.release(req.reserved_bytes);

        const shared_request = mapSharedCoreRequest(req);

        if (unsupportedResponsesGetTransport(&req)) |transport| {
            var delivered_to_codex = true;
            var write_error: ?[]const u8 = null;
            writeUnsupportedWebSocketResponse(writer) catch |err| {
                if (!isClientDisconnectWriteError(err)) return err;
                delivered_to_codex = false;
                write_error = @errorName(err);
            };
            self.logUnsupportedTransport(req, transport, delivered_to_codex, write_error);
            return;
        }

        var rejections = std.ArrayListUnmanaged(CandidateRejection){};
        var live_request = LiveRequestState.init(req, shared_request.demand);
        var final_account: ?[]const u8 = null;
        var pending_buffered: ?BufferedResponse = null;
        var pending_failure_kind: ?broker_types.QuotaKind = null;
        var pending_failure_account: ?[]const u8 = null;
        var prior_attempt_account: ?[]const u8 = null;
        var retry_is_same_route_transport = false;
        var elected = self.electLiveRequestRoute(a, shared_request.demand, null) catch |err| {
            appendPoolRejections(a, self.pool, live_request.attemptedItems(), &rejections) catch {};
            self.logEvent("proxy_no_account_selectable", .{
                .attempted = live_request.attemptedItems(),
                .rejections = rejections.items,
                .err = @errorName(err),
            });
            self.traceNoAccountSelectable(req, null, live_request.attemptedItems(), rejections.items);
            _ = try self.writeNoAccountSelectableResponseOrClientDisconnect(a, writer, req, "", rejections.items);
            return;
        };

        attempt_loop: while (true) {
            // `beginAttempt` is the executable two-attempt fence. It also
            // returns the original immutable body/model view used below, so a
            // follow-up cannot silently mutate demand or payload bytes.
            const live_attempt = live_request.beginAttempt(elected.id) catch {
                self.logEvent("proxy_attempt_budget_exhausted", .{
                    .attempted = live_request.attemptedItems(),
                });
                return error.AttemptBudgetExceeded;
            };

            var tokens = self.materializer.materialize_chatgpt(
                self.materializer.ctx,
                a,
                elected.id,
            ) catch |err| {
                appendRejection(a, &rejections, elected.id, .credential_unavailable, @errorName(err)) catch {};
                self.logEvent("proxy_materialize_failed", .{ .account = elected.id, .err = @errorName(err) });
                self.pool.markUnauthorized(elected.id) catch {};
                self.recordDurableRouteState(elected.id, elected.capability, .credential_unavailable, 0, null);
                if (pending_buffered) |buffered| {
                    _ = try self.writeBufferedStoredResponseOrClientDisconnect(
                        writer,
                        req,
                        pending_failure_account orelse elected.id,
                        buffered,
                        true,
                    );
                } else {
                    _ = try self.writeProviderUnavailableResponseOrClientDisconnect(
                        a,
                        writer,
                        req,
                        elected.id,
                        @errorName(err),
                        rejections.items,
                        live_request.attempts_started > 1,
                    );
                }
                return;
            };
            // tokens lives in arena `a`; deinit-on-arena-drop.
            _ = &tokens;

            live_request.acceptMaterializedIdentity(tokens.account_id, retry_is_same_route_transport) catch |err| {
                appendRejection(a, &rejections, elected.id, .credential_unavailable, @errorName(err)) catch {};
                self.logEvent("proxy_materialized_identity_refused", .{
                    .account = elected.id,
                    .err = @errorName(err),
                    .alternate = live_request.attempts_started > 1 and !retry_is_same_route_transport,
                    .upstream_called = false,
                });
                if (pending_buffered) |buffered| {
                    _ = try self.writeBufferedStoredResponseOrClientDisconnect(
                        writer,
                        req,
                        pending_failure_account orelse elected.id,
                        buffered,
                        true,
                    );
                } else {
                    _ = try self.writeProviderUnavailableResponseOrClientDisconnect(
                        a,
                        writer,
                        req,
                        elected.id,
                        @errorName(err),
                        rejections.items,
                        live_request.attempts_started > 1,
                    );
                }
                return;
            };

            // ── 3. Build outbound request with substituted headers ──
            const retrying_inside_turn = live_request.attempts_started > 1;
            var out_headers = HeaderList.init(a);
            var attempt_req = req;
            attempt_req.body = live_attempt.body;
            const cross_account_alternate = retrying_inside_turn and !retry_is_same_route_transport;
            const preserved_child_auth = try buildOutboundHeaders(a, &attempt_req, &out_headers, tokens, cross_account_alternate);
            if (preserved_child_auth) {
                self.logEvent("proxy_preserved_child_auth", .{
                    .account = elected.id,
                    .reason = "same_account_child_refresh",
                });
            }

            // Detect account change since the previous request. If this is
            // a post-swap turn, drop x-codex-turn-state — the token is the
            // server-side sticky-routing handle for the prior account's
            // conversation thread; carrying it across a swap is the most
            // likely way to break the post-swap turn (issue
            // openai/codex#16894). Dropping it forces a fresh thread on
            // the new account, which is the explicit Phase 2 default
            // (synthetic next-turn swap structure, NOT Level 5 thread continuity).
            const account_changed = if (self.previous_account) |prev|
                !std.mem.eql(u8, prev, elected.id)
            else
                false;
            if (account_changed) {
                out_headers.remove("x-codex-turn-state");
                self.logEvent("proxy_post_swap_turn", .{
                    .from = self.previous_account.?,
                    .to = elected.id,
                    .dropped = "x-codex-turn-state",
                });
                self.synthetic_swap_seen = true;
            }

            if (retrying_inside_turn) {
                if (retry_is_same_route_transport) {
                    self.logSameRouteTransportRetry(elected.id);
                } else {
                    self.logRetryEvent(prior_attempt_account.?, elected.id, pending_failure_kind orelse .quota_exhausted);
                    self.synthetic_swap_seen = true;
                }
            }

            // Inbound body bytes are preserved exactly for both attempts.
            const forward_result = try forwardAndStream(a, attempt_req, out_headers, reader, writer);
            const status_and_class = switch (forward_result) {
                .response => |response| response,
                .transport_failure => |failure| {
                    self.logEvent("proxy_upstream_failed", .{
                        .account = elected.id,
                        .err = failure.err_name,
                        .send_state = @tagName(failure.send_state),
                    });
                    self.traceUpstreamFailure(req, elected.id, failure.err_name);
                    const transition = live_request.observe(.{ .transport_failure = failure.send_state });
                    switch (transition.decision) {
                        .retry_same_route => {
                            prior_attempt_account = elected.id;
                            retry_is_same_route_transport = true;
                            continue :attempt_loop;
                        },
                        .retry_alternate => unreachable,
                        .finish_original => {
                            appendRejection(a, &rejections, elected.id, .provider_degraded, failure.err_name) catch {};
                            if (pending_buffered) |buffered| {
                                _ = try self.writeBufferedStoredResponseOrClientDisconnect(
                                    writer,
                                    req,
                                    pending_failure_account orelse elected.id,
                                    buffered,
                                    true,
                                );
                            } else {
                                const delivered = try self.writeProviderUnavailableResponseOrClientDisconnect(
                                    a,
                                    writer,
                                    req,
                                    elected.id,
                                    failure.err_name,
                                    rejections.items,
                                    live_request.attempts_started > 1,
                                );
                                self.traceProviderUnavailable(req, elected.id, failure.err_name, rejections.items, delivered);
                            }
                            final_account = elected.id;
                            break :attempt_loop;
                        },
                    }
                },
            };

            if (status_and_class.stream_outcome.kind == .client_disconnected) {
                _ = live_request.observe(.canceled);
                self.logEvent("proxy_client_disconnected", .{
                    .account = elected.id,
                    .method = req.method,
                    .path_kind = pathKind(req.path),
                    .status = status_and_class.status,
                    .err = status_and_class.stream_outcome.err orelse "client_disconnected",
                    .bytes_streamed = status_and_class.stream_outcome.bytes_streamed,
                    .retry_attempted = false,
                });
                final_account = elected.id;
                break;
            }

            if (status_and_class.stream_outcome.kind == .upstream_interrupted) {
                _ = live_request.observe(.{ .upstream_status = .{
                    .status = status_and_class.status,
                    .delivery = .downstream_started,
                } });
                const err_name = status_and_class.stream_outcome.err orelse "stream_interrupted";
                appendRejection(a, &rejections, elected.id, .provider_degraded, err_name) catch {};
                self.logEvent("proxy_stream_interrupted", .{
                    .account = elected.id,
                    .method = req.method,
                    .path_kind = pathKind(req.path),
                    .status = status_and_class.status,
                    .err = err_name,
                    .bytes_streamed = status_and_class.stream_outcome.bytes_streamed,
                    .delivered_to_codex = true,
                    .retry_attempted = false,
                });
                self.traceUpstreamFailure(req, elected.id, err_name);
                final_account = elected.id;
                break;
            }

            // ── 5. Apply classification + log ──────────────────────
            if (status_and_class.classification.kind == .provider_5xx) {
                // Provider failures are not account readiness evidence. The
                // pass-through event is logged, but route health is unchanged.
            } else {
                self.applyClassification(elected.id, elected.capability, status_and_class.classification) catch |err| {
                    self.logEvent("proxy_apply_classification_failed", .{ .account = elected.id, .err = @errorName(err) });
                };
            }

            const transition = live_request.observe(mapSharedCoreHttpOutcome(status_and_class));
            const retrying = switch (transition.decision) {
                .retry_same_route, .retry_alternate => true,
                .finish_original => false,
            };
            self.logProxyTurn(elected.id, req, status_and_class, !retrying);
            final_account = elected.id;

            switch (transition.decision) {
                .finish_original => {
                    if (status_and_class.buffered_response) |buffered| {
                        if (!try self.writeBufferedStoredResponseOrClientDisconnect(
                            writer,
                            req,
                            elected.id,
                            buffered,
                            live_request.attempts_started > 1,
                        )) break;
                    }
                    break;
                },
                .retry_same_route => unreachable,
                .retry_alternate => {
                    const state = routeStateFromClassification(status_and_class.classification.kind);
                    appendRejection(a, &rejections, elected.id, state, @tagName(status_and_class.classification.kind)) catch {};
                    pending_buffered = status_and_class.buffered_response;
                    pending_failure_kind = status_and_class.classification.kind;
                    pending_failure_account = elected.id;
                    prior_attempt_account = elected.id;
                    retry_is_same_route_transport = false;

                    elected = self.electLiveRequestRoute(a, shared_request.demand, elected.id) catch |err| {
                        appendPoolRejections(a, self.pool, live_request.attemptedItems(), &rejections) catch {};
                        self.logEvent("proxy_alternate_unavailable", .{
                            .from = pending_failure_account orelse "",
                            .err = @errorName(err),
                            .attempted = live_request.attemptedItems(),
                            .rejections = rejections.items,
                        });
                        self.traceNoAccountSelectable(req, pending_failure_kind, live_request.attemptedItems(), rejections.items);
                        if (pending_buffered) |buffered| {
                            _ = try self.writeBufferedStoredResponseOrClientDisconnect(
                                writer,
                                req,
                                pending_failure_account orelse "",
                                buffered,
                                true,
                            );
                        }
                        return;
                    };
                    continue;
                },
            }
        }

        // Track previous_account for next-request swap detection.
        if (final_account) |account| {
            if (self.previous_account) |old| self.allocator.free(old);
            self.previous_account = self.allocator.dupe(u8, account) catch null;
        }
    }

    fn electLiveRequestRoute(
        self: *Proxy,
        allocator: std.mem.Allocator,
        demand: ?broker_model_demand.ModelDemand,
        exclude_account: ?[]const u8,
    ) !account_pool_mod.AccountSummary {
        if (demand == null) {
            // Bootstrap and non-model traffic never enters alternate election.
            if (exclude_account != null) return broker_types.BrokerError.NoAccountSelectable;
            const launch = self.launch_account orelse return broker_types.BrokerError.NoAccountSelectable;
            return launchPoolRoute(self.pool, launch);
        }

        const now_s = std.time.timestamp();
        self.pool.refreshTimeBased(now_s);
        return electSharedPoolRoute(
            allocator,
            self.pool,
            demand.?,
            self.previous_account orelse self.launch_account,
            exclude_account,
            now_s,
        );
    }

    fn writeBufferedStoredResponseOrClientDisconnect(
        self: *Proxy,
        writer: anytype,
        req: Request,
        account_id: []const u8,
        response: BufferedResponse,
        retry_attempted: bool,
    ) !bool {
        writeBufferedStoredResponse(writer, response) catch |err| {
            if (isClientDisconnectWriteError(err)) {
                self.logClientDisconnected(account_id, req, response.status, @errorName(err), 0, retry_attempted);
                return false;
            }
            return err;
        };
        return true;
    }

    fn writeProviderUnavailableResponseOrClientDisconnect(
        self: *Proxy,
        allocator: std.mem.Allocator,
        writer: anytype,
        req: Request,
        account_id: []const u8,
        err_name: []const u8,
        rejections: []const CandidateRejection,
        retry_attempted: bool,
    ) !bool {
        writeProviderUnavailableResponse(allocator, writer, account_id, err_name, rejections) catch |err| {
            if (isClientDisconnectWriteError(err)) {
                self.logClientDisconnected(account_id, req, 503, @errorName(err), 0, retry_attempted);
                return false;
            }
            return err;
        };
        return true;
    }

    fn writeNoAccountSelectableResponseOrClientDisconnect(
        self: *Proxy,
        allocator: std.mem.Allocator,
        writer: anytype,
        req: Request,
        account_id: []const u8,
        rejections: []const CandidateRejection,
    ) !bool {
        writeNoAccountSelectableResponse(allocator, writer, self.profile, rejections) catch |err| {
            if (isClientDisconnectWriteError(err)) {
                self.logClientDisconnected(account_id, req, 503, @errorName(err), 0, true);
                return false;
            }
            return err;
        };
        return true;
    }

    fn logClientDisconnected(
        self: *Proxy,
        account_id: []const u8,
        req: Request,
        status: u16,
        err_name: []const u8,
        bytes_streamed: usize,
        retry_attempted: bool,
    ) void {
        self.logEvent("proxy_client_disconnected", .{
            .account = account_id,
            .method = req.method,
            .path_kind = pathKind(req.path),
            .status = status,
            .err = err_name,
            .bytes_streamed = bytes_streamed,
            .retry_attempted = retry_attempted,
        });
    }

    fn logUnsupportedTransport(
        self: *Proxy,
        req: Request,
        transport: []const u8,
        delivered_to_codex: bool,
        write_error: ?[]const u8,
    ) void {
        self.logEvent("proxy_unsupported_transport", .{
            .transport = transport,
            .method = req.method,
            .path_kind = pathKind(req.path),
            .status = 426,
            .fallback_signal = "http_426",
            .upstream_called = false,
            .delivered_to_codex = delivered_to_codex,
            .err = write_error,
        });
        trace.append(self.allocator, "codex.proxy.unsupported_transport", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("transport", transport),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.uint("status", 426),
            trace.string("fallback_signal", "http_426"),
            trace.boolean("upstream_called", false),
            trace.boolean("delivered_to_codex", delivered_to_codex),
            trace.string("write_error", write_error orelse "none"),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn logProxyTurn(
        self: *Proxy,
        account_id: []const u8,
        req: Request,
        status_and_class: StatusAndClassification,
        delivered_to_codex: bool,
    ) void {
        self.auth_failure_tracker.observe(self.allocator, account_id, req.path, status_and_class.classification);
        self.logEvent("proxy_turn", .{
            .account = account_id,
            .method = req.method,
            .path_kind = pathKind(req.path),
            .status = status_and_class.status,
            .classification = @tagName(status_and_class.classification.kind),
            .body_class = status_and_class.body_class orelse "none",
            .claim_level = self.peak_claim.toString(),
            .streamed = status_and_class.streamed,
            .delivered_to_codex = delivered_to_codex,
        });
        trace.append(self.allocator, "codex.proxy.turn", if (status_and_class.classification.kind == .ok) .info else .warn, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", accountLabel(account_id)),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.uint("status", status_and_class.status),
            trace.string("classification", @tagName(status_and_class.classification.kind)),
            trace.string("body_class", status_and_class.body_class orelse "none"),
            trace.string("claim_level", self.peak_claim.toString()),
            trace.boolean("streamed", status_and_class.streamed),
            trace.boolean("delivered_to_codex", delivered_to_codex),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn applyClassification(
        self: *Proxy,
        account_id: []const u8,
        capability: ?[]const u8,
        c: Classification,
    ) !void {
        var store = health_mod.HealthStore.load(std.heap.page_allocator, .{});
        defer store.deinit();
        // Effect boundary (TIN-2407 P0): read AFTER the store load, preserving
        // the pre-inversion ordering (the old internal read happened post-load),
        // so persisted instants never shift by the load-crossing skew.
        const now_unix = std.time.timestamp();
        try applyClassificationWithStore(self.pool, &store, account_id, c, now_unix, capability orelse self.capability);
        store.persist();
    }

    fn recordDurableRouteState(
        self: *Proxy,
        account_id: []const u8,
        capability: ?[]const u8,
        state: RouteState,
        status: u16,
        retry_after_s: ?u32,
    ) void {
        var store = health_mod.HealthStore.load(std.heap.page_allocator, .{});
        defer store.deinit();
        // Effect boundary (TIN-2407 P0): read AFTER the store load (mirrors
        // applyClassification; preserves the pre-inversion read ordering).
        const now_unix = std.time.timestamp();
        recordDurableRouteStateInStore(&store, account_id, capability orelse self.capability, state, status, retry_after_s, now_unix);
        store.persist();
    }

    fn logRetryEvent(
        self: *Proxy,
        from: []const u8,
        to: []const u8,
        reason: broker_types.QuotaKind,
    ) void {
        if (reason == .auth_unauthorized) {
            self.logEvent("proxy_auth_same_turn_retry", .{
                .from = from,
                .to = to,
                .reason = @tagName(reason),
                .dropped = "x-codex-turn-state",
            });
            self.traceRetry(from, to, reason);
            return;
        }

        self.logEvent("proxy_same_turn_retry", .{
            .from = from,
            .to = to,
            .reason = @tagName(reason),
            .dropped = "x-codex-turn-state",
        });
        self.traceRetry(from, to, reason);
    }

    fn logSameRouteTransportRetry(self: *Proxy, account_id: []const u8) void {
        self.logEvent("proxy_same_route_transport_retry", .{
            .account = account_id,
            .confirmed_not_sent = true,
            .max_upstream_attempts = 2,
        });
        trace.append(self.allocator, "codex.proxy.same_route_transport_retry", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", accountLabel(account_id)),
            trace.boolean("confirmed_not_sent", true),
            trace.uint("max_upstream_attempts", 2),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn traceRetry(
        self: *Proxy,
        from: []const u8,
        to: []const u8,
        reason: broker_types.QuotaKind,
    ) void {
        trace.append(self.allocator, "codex.proxy.retry", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("from_account_label", accountLabel(from)),
            trace.string("to_account_label", accountLabel(to)),
            trace.string("reason", @tagName(reason)),
            trace.string("dropped_header_class", "turn_state"),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn traceNoAccountSelectable(
        self: *Proxy,
        req: Request,
        pending_kind: ?broker_types.QuotaKind,
        attempted: []const []const u8,
        rejections: []const CandidateRejection,
    ) void {
        trace.append(self.allocator, "codex.proxy.no_account_selectable", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("profile", self.profile orelse "none"),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.string("pending_failure", if (pending_kind) |kind| @tagName(kind) else "none"),
            trace.uint("attempted_count", @intCast(attempted.len)),
            trace.uint("rejections_total", @intCast(rejections.len)),
            trace.uint("auth_failed", @intCast(countRejectionsByState(rejections, .auth_failed))),
            trace.uint("quota_exhausted", @intCast(countRejectionsByState(rejections, .quota_exhausted))),
            trace.uint("rate_limited", @intCast(countRejectionsByState(rejections, .rate_limited))),
            trace.uint("tier_insufficient", @intCast(countRejectionsByState(rejections, .tier_insufficient))),
            trace.uint("provider_degraded", @intCast(countRejectionsByState(rejections, .provider_degraded))),
            trace.uint("credential_unavailable", @intCast(countRejectionsByState(rejections, .credential_unavailable))),
            trace.boolean("agent_safe_next_action_available", true),
            trace.boolean("spend_confirmed_next_action_available", true),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn traceProviderUnavailable(
        self: *Proxy,
        req: Request,
        account_id: []const u8,
        err: []const u8,
        rejections: []const CandidateRejection,
        delivered_to_codex: bool,
    ) void {
        trace.append(self.allocator, "codex.proxy.provider_unavailable", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", accountLabel(account_id)),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.string("transport_error", err),
            trace.uint("rejections_total", @intCast(rejections.len)),
            trace.boolean("delivered_to_codex", delivered_to_codex),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn traceUpstreamFailure(
        self: *Proxy,
        req: Request,
        account_id: []const u8,
        err: []const u8,
    ) void {
        trace.append(self.allocator, "codex.proxy.upstream_failure", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", accountLabel(account_id)),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.string("transport_error", err),
            trace.boolean("token_material_printed", false),
            trace.boolean("raw_account_id_printed", false),
            trace.boolean("session_ids_printed", false),
        });
    }

    fn logEvent(self: *Proxy, kind: []const u8, fields: anytype) void {
        // Minimal NDJSON log frame; never includes token material.
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        w.writeAll("{\"kind\":\"") catch return;
        w.writeAll(kind) catch return;
        w.writeAll("\"") catch return;

        // Emit any fields the call site provided. Compile-time
        // reflection over the anytype struct.
        const T = @TypeOf(fields);
        const info = @typeInfo(T);
        if (info == .@"struct") {
            inline for (info.@"struct".fields) |f| {
                w.writeAll(",\"") catch return;
                w.writeAll(f.name) catch return;
                w.writeAll("\":") catch return;
                const value = @field(fields, f.name);
                std.json.stringify(value, .{}, w) catch return;
            }
        }
        w.writeAll("}\n") catch return;
        self.log_writer.writeAll(buf.items) catch {};
    }
};

const SharedCoreRequest = struct {
    demand: ?broker_model_demand.ModelDemand = null,
    lease_quality: broker_lease_state.ProjectionQuality = .unavailable,
};

const ModelScanError = error{
    Unparseable,
    Missing,
    Duplicate,
    NotString,
    OutOfMemory,
};

fn scanModelToken(scanner: *std.json.Scanner, allocator: std.mem.Allocator) ModelScanError!std.json.Token {
    return scanner.nextAlloc(allocator, .alloc_if_needed) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Unparseable,
    };
}

fn skipModelValue(scanner: *std.json.Scanner) ModelScanError!void {
    const token_type = scanner.peekNextTokenType() catch return error.Unparseable;
    switch (token_type) {
        .object_end, .array_end, .end_of_document => return error.Unparseable,
        else => {},
    }
    scanner.skipValue() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unparseable,
    };
}

fn scanExactModelDemand(allocator: std.mem.Allocator, body: []const u8) ModelScanError!broker_model_demand.ModelDemand {
    var scanner = std.json.Scanner.initCompleteInput(allocator, body);
    defer scanner.deinit();
    switch (try scanModelToken(&scanner, allocator)) {
        .object_begin => {},
        else => return error.Unparseable,
    }

    var demand: ?broker_model_demand.ModelDemand = null;
    while (true) {
        const key = switch (try scanModelToken(&scanner, allocator)) {
            .object_end => {
                switch (try scanModelToken(&scanner, allocator)) {
                    .end_of_document => return demand orelse error.Missing,
                    else => return error.Unparseable,
                }
            },
            .string => |value| value,
            .allocated_string => |value| value,
            else => return error.Unparseable,
        };
        if (std.mem.eql(u8, key, "model")) {
            if (demand != null) return error.Duplicate;
            const model = switch (try scanModelToken(&scanner, allocator)) {
                .string => |value| value,
                .allocated_string => |value| value,
                else => return error.NotString,
            };
            demand = broker_model_demand.ModelDemand.init(model) catch return error.NotString;
        } else {
            try skipModelValue(&scanner);
        }
    }
}

/// Allocation-bounded parsing of the only traffic class eligible for managed
/// account continuity. Parse failure remains bootstrap/non-model traffic: it is
/// forwarded on the launch account and can never trigger a cross-account replay.
fn mapSharedCoreRequest(req: Request) SharedCoreRequest {
    var mapped = SharedCoreRequest{};
    if (!req.replayable()) return mapped;
    if (!std.mem.eql(u8, req.method, "POST") or
        !std.mem.eql(u8, pathKind(req.path), "responses"))
    {
        return mapped;
    }

    // Fixed scratch bounds observation overhead only. It is not a request-body
    // replay reservation and conveys no 32/64/256 MiB eligibility claim.
    var scratch: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    mapped.demand = scanExactModelDemand(fixed.allocator(), req.body) catch return mapped;
    return mapped;
}

const LiveAttempt = struct {
    account_id: []const u8,
    body: []const u8,
    demand: ?broker_model_demand.ModelDemand,
};

/// Request-local executable budget. The immutable body and typed exact-model
/// demand are retained once and returned unchanged for every permitted attempt.
const LiveRequestState = struct {
    body: []const u8,
    demand: ?broker_model_demand.ModelDemand,
    policy_state: broker_attempt_policy.State,
    attempted: [2][]const u8 = undefined,
    attempts_started: u8 = 0,
    /// Raw provider identity is held only in this request arena. It is never
    /// logged or persisted; unlike route labels and stale pool hashes, it is
    /// authoritative for the distinct-account alternate fence.
    first_materialized_identity: ?[]const u8 = null,

    fn init(req: Request, demand: ?broker_model_demand.ModelDemand) LiveRequestState {
        return .{
            .body = req.body,
            .demand = demand,
            .policy_state = if (demand != null and req.replayable())
                .{ .initial = .eligible_reserved }
            else
                .{ .initial = .{ .stream_once = .reservation_unavailable } },
        };
    }

    fn beginAttempt(self: *LiveRequestState, account_id: []const u8) error{ AttemptBudgetExceeded, AttemptNotAuthorized }!LiveAttempt {
        if (self.attempts_started >= self.attempted.len) return error.AttemptBudgetExceeded;
        if (self.attempts_started == 1) {
            switch (self.policy_state) {
                .same_route_retry_in_flight => {
                    if (!std.mem.eql(u8, account_id, self.attempted[0])) return error.AttemptNotAuthorized;
                },
                .alternate_in_flight => {
                    if (std.mem.eql(u8, account_id, self.attempted[0])) return error.AttemptNotAuthorized;
                },
                .initial, .terminal => return error.AttemptNotAuthorized,
            }
        }
        self.attempted[self.attempts_started] = account_id;
        self.attempts_started += 1;
        return .{
            .account_id = account_id,
            .body = self.body,
            .demand = self.demand,
        };
    }

    fn acceptMaterializedIdentity(
        self: *LiveRequestState,
        identity: []const u8,
        same_route_retry: bool,
    ) error{ EmptyMaterializedIdentity, MaterializedIdentityChanged, SameMaterializedIdentityAlternate }!void {
        if (identity.len == 0) return error.EmptyMaterializedIdentity;
        const first = self.first_materialized_identity orelse {
            self.first_materialized_identity = identity;
            return;
        };
        if (same_route_retry) {
            if (!std.mem.eql(u8, first, identity)) return error.MaterializedIdentityChanged;
            return;
        }
        if (std.mem.eql(u8, first, identity)) return error.SameMaterializedIdentityAlternate;
    }

    fn observe(
        self: *LiveRequestState,
        outcome: broker_attempt_policy.Outcome,
    ) broker_attempt_policy.Transition {
        const transition = broker_attempt_policy.reduce(self.policy_state, outcome);
        self.policy_state = transition.next;
        return transition;
    }

    fn attemptedItems(self: *const LiveRequestState) []const []const u8 {
        return self.attempted[0..self.attempts_started];
    }
};

fn poolRouteAdmission(
    account: account_pool_mod.AccountSummary,
    required_capability: []const u8,
    exclude_account: ?[]const u8,
) broker_route_observation.RouteAdmission {
    if (exclude_account) |excluded| {
        if (std.mem.eql(u8, account.id, excluded)) return .unavailable;
    }
    if (account.duplicate_of != null) return .identity_conflict;
    if (account.capability == null or
        !std.mem.eql(u8, account.capability.?, required_capability))
    {
        return .unavailable;
    }
    return switch (account.liveness) {
        .dead => .dead,
        .degraded => .unavailable,
        .live, .unknown => if (!account.selectable and
            (account.availability == .available or account.availability == .unknown))
            .unavailable
        else
            .admitted,
    };
}

fn launchPoolRoute(
    pool: *const account_pool_mod.AccountPool,
    launch_account: []const u8,
) broker_types.BrokerError!account_pool_mod.AccountSummary {
    for (pool.accounts.items) |account| {
        if (std.mem.eql(u8, account.id, launch_account)) return account;
    }
    return broker_types.BrokerError.NoAccountSelectable;
}

fn poolReactiveObservation(account: account_pool_mod.AccountSummary) ?advisory_usage.Reactive {
    return switch (account.availability) {
        .available => if (account.selectable and account.health_observed_at != null)
            .{
                .readiness = .available,
                .resets_at_s = std.math.add(
                    i64,
                    account.health_observed_at.?,
                    advisory_usage.FRESHNESS_WINDOW_S,
                ) catch std.math.maxInt(i64),
            }
        else
            null,
        .rate_limited, .quota_exhausted, .cooldown => if (account.next_eligible_at) |reset|
            .{ .readiness = .exhausted, .resets_at_s = reset }
        else
            null,
        .unknown => null,
    };
}

const route_handle_len = "route-".len + 12;

fn routeHandleForAccount(
    account_id: []const u8,
    storage: *[route_handle_len]u8,
) broker_route_observation.RouteHandle {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(account_id, &digest, .{});
    const text = std.fmt.bufPrint(
        storage,
        "route-{x}",
        .{std.fmt.fmtSliceHexLower(digest[0..6])},
    ) catch unreachable;
    return broker_route_observation.RouteHandle.parse(text) catch unreachable;
}

/// Translate the already-scoped Codex pool into the shared exact-model route
/// vocabulary and run the shared decision reducer. TIN-3320 runtime projection
/// is intentionally not consumed here yet: quality remains `unavailable`; only
/// this process's current route is supplied as a sticky hint.
fn electSharedPoolRoute(
    allocator: std.mem.Allocator,
    pool: *const account_pool_mod.AccountPool,
    demand: broker_model_demand.ModelDemand,
    sticky_account: ?[]const u8,
    exclude_account: ?[]const u8,
    now_s: i64,
) !account_pool_mod.AccountSummary {
    const plan = provider_schema.probePlanForCapability(
        provider_schema.codex_def,
        demand.exact_model.bytes(),
    ) orelse return broker_types.BrokerError.NoAccountSelectable;

    const rows = try allocator.alloc(broker_route_observation.RouteEvidence, pool.accounts.items.len);
    defer allocator.free(rows);
    const route_storage = try allocator.alloc([route_handle_len]u8, pool.accounts.items.len);
    defer allocator.free(route_storage);
    for (pool.accounts.items, 0..) |account, index| {
        const observation: broker_route_observation.RouteObservation = .{
            .route = routeHandleForAccount(account.id, &route_storage[index]),
            .identity = if (account.account_id_hash) |hash|
                broker_route_observation.IdentityEvidence.fromBorrowed(hash)
            else
                null,
            .exact_model = demand.exact_model,
            .admission = poolRouteAdmission(account, plan.capability, exclude_account),
            .reactive = poolReactiveObservation(account),
        };
        rows[index] = broker_route_observation.project(observation, now_s);
    }

    var leases = broker_lease_state.missingProjection();
    var sticky_storage: [route_handle_len]u8 = undefined;
    if (sticky_account) |sticky| {
        leases.view.sticky_route = routeHandleForAccount(sticky, &sticky_storage);
    }
    const decision = broker_decision.reduce(demand, rows, leases.view);
    const selected = switch (decision) {
        .select_route => |route| route.text,
        .no_route => return broker_types.BrokerError.NoAccountSelectable,
    };
    for (rows, 0..) |row, index| {
        if (std.mem.eql(u8, row.route.text, selected)) return pool.accounts.items[index];
    }
    return broker_types.BrokerError.NoAccountSelectable;
}

fn mapSharedCoreHttpOutcome(
    result: StatusAndClassification,
) broker_attempt_policy.Outcome {
    return .{ .upstream_status = .{
        .status = result.status,
        .delivery = if (result.buffered_response == null)
            .downstream_started
        else
            .buffered_before_downstream,
    } };
}

fn routeStateFromClassification(kind: broker_types.QuotaKind) RouteState {
    return switch (kind) {
        .ok => .available,
        .auth_unauthorized => .auth_failed,
        .quota_exhausted => .quota_exhausted,
        .rate_limited => .rate_limited,
        .tier_insufficient => .tier_insufficient,
        .provider_5xx => .provider_degraded,
    };
}

fn accountLabel(account_id: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return account_id;
    if (colon + 1 >= account_id.len) return account_id;
    return account_id[colon + 1 ..];
}

fn retryAfterSeconds(now_unix: i64, resets_at: ?i64, kind: broker_types.QuotaKind) ?u32 {
    const reset = resets_at orelse return switch (kind) {
        .quota_exhausted => 7 * 24 * 60 * 60,
        .rate_limited => 60,
        .provider_5xx => 60,
        else => null,
    };
    if (reset <= now_unix) return 0;
    const delta = reset - now_unix;
    return @intCast(@min(delta, std.math.maxInt(u32)));
}

fn applyClassificationWithStore(
    pool: *account_pool_mod.AccountPool,
    store: *health_mod.HealthStore,
    account_id: []const u8,
    c: Classification,
    now_unix: i64,
    capability: ?[]const u8,
) !void {
    if (c.kind == .provider_5xx) return;
    recordDurableClassificationInStore(store, account_id, c, now_unix, capability);
    switch (c.kind) {
        .ok => {
            for (pool.accounts.items) |*account| {
                if (!std.mem.eql(u8, account.id, account_id)) continue;
                account.health_observed_at = now_unix;
                account.availability = .available;
                if (account.liveness != .dead) account.selectable = true;
                break;
            }
        },
        .quota_exhausted => {
            const until = c.resets_at orelse (now_unix + 7 * 24 * 60 * 60);
            try pool.markQuotaExhausted(account_id, until);
            markPoolObservationAt(pool, account_id, now_unix);
        },
        .rate_limited => {
            const until = c.resets_at orelse (now_unix + 60);
            try pool.markRateLimited(account_id, until);
            markPoolObservationAt(pool, account_id, now_unix);
        },
        .auth_unauthorized => {
            try pool.markUnauthorized(account_id);
            markPoolObservationAt(pool, account_id, now_unix);
        },
        // A provider failure is not an account failure. The durable observation
        // is retained, but live selection must not rotate accounts for 5xx.
        .provider_5xx => {},
        .tier_insufficient => {
            // Recorded for telemetry only; no pool mutation.
        },
    }
}

fn markPoolObservationAt(pool: *account_pool_mod.AccountPool, account_id: []const u8, now_s: i64) void {
    for (pool.accounts.items) |*account| {
        if (!std.mem.eql(u8, account.id, account_id)) continue;
        account.health_observed_at = now_s;
        return;
    }
}

fn recordDurableClassificationInStore(
    store: *health_mod.HealthStore,
    account_id: []const u8,
    c: Classification,
    now_unix: i64,
    capability: ?[]const u8,
) void {
    const state = routeStateFromClassification(c.kind);
    const status: u16 = c.http_status orelse switch (c.kind) {
        .ok => 200,
        .auth_unauthorized => 401,
        .quota_exhausted, .rate_limited, .tier_insufficient => 429,
        .provider_5xx => 500,
    };
    const retry_after_s = retryAfterSeconds(now_unix, c.resets_at, c.kind);
    recordDurableRouteStateInStore(store, account_id, capability, state, status, retry_after_s, now_unix);
}

fn recordDurableRouteStateInStore(
    store: *health_mod.HealthStore,
    account_id: []const u8,
    capability: ?[]const u8,
    state: RouteState,
    status: u16,
    retry_after_s: ?u32,
    // TIN-2407 P0 clock inversion: caller supplies the observation instant.
    now_unix: i64,
) void {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return;
    if (colon == 0 or colon + 1 >= account_id.len) return;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];
    const key = switch (state) {
        .auth_failed, .credential_unavailable => health_mod.accountKey(provider, account),
        else => if (capability) |cap| health_mod.capabilityKey(provider, account, cap) else health_mod.accountKey(provider, account),
    };

    const classification: core_types.HttpClassification = switch (state) {
        .available => .success,
        .auth_failed => .{ .dead = .token_revoked },
        .quota_exhausted => .{ .quota_exhausted = .{ .retry_after_s = retry_after_s orelse 7 * 24 * 60 * 60 } },
        .rate_limited => .{ .rate_limited = .{
            .retry_after_s = retry_after_s orelse 60,
            .window = .unknown,
        } },
        .tier_insufficient => .{ .degraded = .tier_insufficient },
        .provider_degraded => .provider_degraded,
        .credential_unavailable => .{ .dead = .credential_unavailable },
    };

    store.recordHttpClassification(key.slice(), status, classification, now_unix);
    store.recordProbeEvidence(
        key.slice(),
        .broker_run_live,
        retry_after_s,
        switch (state) {
            .available => .none,
            .auth_failed, .credential_unavailable => .auth_dead,
            .quota_exhausted => .quota_exhausted,
            .rate_limited => .rate_limit,
            .tier_insufficient => .tier_insufficient,
            .provider_degraded => .provider_degraded,
        },
        switch (state) {
            .available => .use_this,
            .rate_limited => .wait_and_retry,
            .provider_degraded => .try_next_provider,
            .auth_failed, .quota_exhausted, .tier_insufficient, .credential_unavailable => .try_next_account,
        },
    );
}

fn containsAccount(items: []const []const u8, account_id: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, account_id)) return true;
    }
    return false;
}

fn rejectionIndex(rejections: []const CandidateRejection, account_id: []const u8) ?usize {
    for (rejections, 0..) |rejection, idx| {
        if (std.mem.eql(u8, rejection.account, account_id)) return idx;
    }
    return null;
}

fn appendRejection(
    allocator: std.mem.Allocator,
    rejections: *std.ArrayListUnmanaged(CandidateRejection),
    account_id: []const u8,
    state: RouteState,
    reason: []const u8,
) !void {
    if (rejectionIndex(rejections.items, account_id)) |idx| {
        rejections.items[idx] = .{ .account = account_id, .state = state, .reason = reason };
        return;
    }
    try rejections.append(allocator, .{ .account = account_id, .state = state, .reason = reason });
}

fn appendPoolRejections(
    allocator: std.mem.Allocator,
    pool: *const account_pool_mod.AccountPool,
    attempted: []const []const u8,
    rejections: *std.ArrayListUnmanaged(CandidateRejection),
) !void {
    for (pool.accounts.items) |account| {
        if (rejectionIndex(rejections.items, account.id) != null) continue;
        if (containsAccount(attempted, account.id)) {
            try appendRejection(allocator, rejections, account.id, .credential_unavailable, "attempted_without_success");
            continue;
        }
        const state = routeStateFromPoolAccount(account);
        const reason = poolAccountRejectionReason(account, state);
        try appendRejection(allocator, rejections, account.id, state, reason);
    }
}

fn routeStateFromPoolAccount(account: account_pool_mod.AccountSummary) RouteState {
    if (!account.selectable) {
        if (account.liveness == .dead) return .auth_failed;
        if (account.liveness == .degraded) return .provider_degraded;
        if (account.availability == .quota_exhausted) return .quota_exhausted;
        if (account.availability == .rate_limited) return .rate_limited;
        return .credential_unavailable;
    }
    return switch (account.availability) {
        .available => .available,
        .quota_exhausted => .quota_exhausted,
        .rate_limited => .rate_limited,
        .cooldown, .unknown => .credential_unavailable,
    };
}

fn poolAccountRejectionReason(account: account_pool_mod.AccountSummary, state: RouteState) []const u8 {
    if (!account.selectable) return switch (state) {
        .auth_failed => "auth_failed",
        .quota_exhausted => "quota_exhausted",
        .rate_limited => "rate_limited",
        .tier_insufficient => "tier_insufficient",
        .provider_degraded => "provider_degraded",
        .credential_unavailable => "not_selectable",
        .available => "not_selectable",
    };
    return switch (state) {
        .available => "not_attempted",
        .auth_failed => "auth_failed",
        .quota_exhausted => "quota_exhausted",
        .rate_limited => "rate_limited",
        .tier_insufficient => "tier_insufficient",
        .provider_degraded => "provider_degraded",
        .credential_unavailable => "credential_unavailable",
    };
}

pub const AuthFailureObservation = struct {
    account: ?[]const u8 = null,
    accounts: []const AuthAccountObservation = &.{},
    auth_unauthorized_turns: usize = 0,
    responses_401_turns: usize = 0,
    recovered_after_401: bool = false,

    pub fn unrecovered(self: AuthFailureObservation) bool {
        for (self.accounts) |account| {
            if (account.unrecovered()) return true;
        }
        return false;
    }
};

pub const AuthAccountObservation = struct {
    account: []const u8,
    auth_unauthorized_turns: usize = 0,
    responses_401_turns: usize = 0,
    recovered_after_401: bool = false,

    pub fn unrecovered(self: AuthAccountObservation) bool {
        return self.auth_unauthorized_turns > 0 and !self.recovered_after_401;
    }
};

const AuthFailureTracker = struct {
    accounts: std.ArrayListUnmanaged(AuthAccountObservation) = .{},

    fn deinit(self: *AuthFailureTracker, allocator: std.mem.Allocator) void {
        self.accounts.deinit(allocator);
    }

    fn getOrCreate(
        self: *AuthFailureTracker,
        allocator: std.mem.Allocator,
        account_id: []const u8,
    ) !*AuthAccountObservation {
        for (self.accounts.items) |*entry| {
            if (std.mem.eql(u8, entry.account, account_id)) return entry;
        }
        try self.accounts.append(allocator, .{ .account = account_id });
        return &self.accounts.items[self.accounts.items.len - 1];
    }

    fn observe(
        self: *AuthFailureTracker,
        allocator: std.mem.Allocator,
        account_id: []const u8,
        path: []const u8,
        classification: Classification,
    ) void {
        switch (classification.kind) {
            .auth_unauthorized => {
                const entry = self.getOrCreate(allocator, account_id) catch return;
                entry.auth_unauthorized_turns += 1;
                entry.recovered_after_401 = false;
                if (std.mem.eql(u8, pathKind(path), "responses")) {
                    entry.responses_401_turns += 1;
                }
            },
            .ok => {
                for (self.accounts.items) |*entry| {
                    if (std.mem.eql(u8, entry.account, account_id) and entry.auth_unauthorized_turns > 0) {
                        entry.recovered_after_401 = true;
                    }
                }
            },
            else => {},
        }
    }

    fn observation(self: AuthFailureTracker) AuthFailureObservation {
        var total_auth: usize = 0;
        var total_responses: usize = 0;
        var first_unrecovered: ?[]const u8 = null;
        var any_recovered = false;
        for (self.accounts.items) |entry| {
            total_auth += entry.auth_unauthorized_turns;
            total_responses += entry.responses_401_turns;
            if (entry.recovered_after_401) any_recovered = true;
            if (first_unrecovered == null and entry.unrecovered()) first_unrecovered = entry.account;
        }
        return .{
            .account = first_unrecovered,
            .accounts = self.accounts.items,
            .auth_unauthorized_turns = total_auth,
            .responses_401_turns = total_responses,
            .recovered_after_401 = any_recovered,
        };
    }
};

// ── Request parsing ──────────────────────────────────────────────────

const RequestBodyMode = union(enum) {
    /// Complete retained bytes. This is the only replay-eligible form.
    buffered,
    /// The body remains unread on the inbound connection and is forwarded
    /// exactly once with the declared length.
    stream_content_length: usize,
    /// Unknown-length inbound chunk framing is decoded and forwarded once.
    stream_chunked,
};

const Request = struct {
    method: []const u8,
    path: []const u8,
    headers: HeaderList,
    body: []const u8,
    body_mode: RequestBodyMode = .buffered,
    reserved_bytes: usize = 0,

    fn replayable(self: Request) bool {
        return self.body_mode == .buffered;
    }
};

/// Per-sidecar replay reservation. `reserve` is overflow-safe and never lets
/// retained bodies exceed the active v0.2 64 MiB sidecar budget. Host-wide
/// accounting (256 MiB) requires a cross-process owner and is deliberately not
/// fabricated by this in-process state.
const ReplayReservation = struct {
    reserved: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    budget_bytes: usize = REPLAY_SIDECAR_LIMIT_BYTES,

    fn reserve(self: *ReplayReservation, amount: usize) bool {
        var current = self.reserved.load(.monotonic);
        while (true) {
            if (current > self.budget_bytes or amount > self.budget_bytes - current) return false;
            const next = current + amount;
            if (self.reserved.cmpxchgWeak(current, next, .acq_rel, .monotonic)) |actual| {
                current = actual;
            } else {
                return true;
            }
        }
    }

    fn release(self: *ReplayReservation, amount: usize) void {
        if (amount == 0) return;
        const prior = self.reserved.fetchSub(amount, .acq_rel);
        std.debug.assert(prior >= amount);
    }

    fn outstanding(self: *ReplayReservation) usize {
        return self.reserved.load(.acquire);
    }
};

const HeaderList = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(struct { name: []const u8, value: []const u8 }) = .{},

    fn init(a: std.mem.Allocator) HeaderList {
        return .{ .allocator = a };
    }

    fn append(self: *HeaderList, name: []const u8, value: []const u8) !void {
        try self.items.append(self.allocator, .{ .name = name, .value = value });
    }

    /// Replace any prior value(s) of `name` with `value` (case-insensitive).
    fn set(self: *HeaderList, name: []const u8, value: []const u8) !void {
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (asciiEqlIgnoreCase(self.items.items[i].name, name)) {
                _ = self.items.swapRemove(i);
            } else {
                i += 1;
            }
        }
        try self.append(name, value);
    }

    fn find(self: *const HeaderList, name: []const u8) ?[]const u8 {
        for (self.items.items) |h| {
            if (asciiEqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Remove all headers matching `name` (case-insensitive).
    fn remove(self: *HeaderList, name: []const u8) void {
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (asciiEqlIgnoreCase(self.items.items[i].name, name)) {
                _ = self.items.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn asciiTokenContainsIgnoreCase(value: []const u8, expected: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const token = std.mem.trim(u8, part, " \t\r\n");
        if (asciiEqlIgnoreCase(token, expected)) return true;
    }
    return false;
}

fn isWebSocketUpgradeRequest(req: *const Request) bool {
    if (!std.mem.eql(u8, req.method, "GET")) return false;
    if (req.headers.find("Sec-WebSocket-Key") != null) return true;
    const upgrade = req.headers.find("Upgrade") orelse return false;
    if (!asciiTokenContainsIgnoreCase(upgrade, "websocket")) return false;
    if (req.headers.find("Connection")) |connection| {
        return asciiTokenContainsIgnoreCase(connection, "upgrade");
    }
    return true;
}

fn unsupportedResponsesGetTransport(req: *const Request) ?[]const u8 {
    if (!std.mem.eql(u8, req.method, "GET")) return null;
    const kind = pathKind(req.path);
    if (!std.mem.eql(u8, kind, "responses") and
        !std.mem.eql(u8, kind, "responses_websocket"))
    {
        return null;
    }
    if (isWebSocketUpgradeRequest(req)) return "websocket";
    return "responses_get";
}

fn parseRequest(
    a: std.mem.Allocator,
    reader: anytype,
    reservation: *ReplayReservation,
) !Request {
    // Request line: METHOD SP PATH SP HTTP/1.1 CRLF
    const start_line = try readLine(a, reader, 8 * 1024);
    const sp1 = std.mem.indexOfScalar(u8, start_line, ' ') orelse return error.BadRequestLine;
    const sp2 = std.mem.indexOfScalarPos(u8, start_line, sp1 + 1, ' ') orelse return error.BadRequestLine;
    const method = start_line[0..sp1];
    const path = start_line[sp1 + 1 .. sp2];

    var headers = HeaderList.init(a);
    while (true) {
        const line = try readLine(a, reader, 16 * 1024);
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHeader;
        const name = line[0..colon];
        var v_start = colon + 1;
        while (v_start < line.len and (line[v_start] == ' ' or line[v_start] == '\t')) v_start += 1;
        try headers.append(name, line[v_start..]);
    }

    if (headers.find("content-length") != null and headers.find("transfer-encoding") != null) {
        return error.AmbiguousBodyFraming;
    }

    // Retain only a fully bounded, successfully reserved body. Oversize,
    // unknown-length, and sidecar-budget-miss bodies stay unread and become a
    // single backpressured upstream stream. They cannot acquire exact-model
    // demand or any retry entitlement.
    var body: []const u8 = &.{};
    var body_mode: RequestBodyMode = .buffered;
    var reserved_bytes: usize = 0;
    if (headers.find("content-length")) |cl_str| {
        const cl = try std.fmt.parseInt(usize, cl_str, 10);
        if (cl <= REPLAY_REQUEST_LIMIT_BYTES and reservation.reserve(cl)) {
            errdefer reservation.release(cl);
            const body_buf = try a.alloc(u8, cl);
            try reader.readNoEof(body_buf);
            body = body_buf;
            reserved_bytes = cl;
        } else {
            body_mode = .{ .stream_content_length = cl };
        }
    } else if (headers.find("transfer-encoding")) |te| {
        if (!asciiTokenContainsIgnoreCase(te, "chunked")) return error.UnsupportedTransferEncoding;
        body_mode = .stream_chunked;
    }

    return Request{
        .method = try a.dupe(u8, method),
        .path = try a.dupe(u8, path),
        .headers = headers,
        .body = body,
        .body_mode = body_mode,
        .reserved_bytes = reserved_bytes,
    };
}

fn readLine(a: std.mem.Allocator, reader: anytype, max: usize) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    while (true) {
        if (buf.items.len >= max) return error.LineTooLong;
        const b = try reader.readByte();
        if (b == '\r') {
            const next = try reader.readByte();
            if (next != '\n') return error.BadLineEnding;
            return try buf.toOwnedSlice(a);
        }
        try buf.append(a, b);
    }
}

/// Forward selected headers from inbound to outbound. Drop hop-by-hop
/// headers, the three account-bound headers we substitute, and wire
/// framing headers owned by std.http.Client (Host, Content-Length,
/// Transfer-Encoding). Per RFC 7230 §6.1, hop-by-hop headers MUST NOT
/// be forwarded by intermediaries.
fn copyForwardingHeaders(in: *const HeaderList, out: *HeaderList) !void {
    const skip_substituted = [_][]const u8{
        "authorization",
        "chatgpt-account-id",
        "x-openai-fedramp",
        // std.http.Client owns request framing:
        "host",
        "content-length",
        // hop-by-hop:
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    };
    outer: for (in.items.items) |h| {
        for (skip_substituted) |s| {
            if (asciiEqlIgnoreCase(h.name, s)) continue :outer;
        }
        try out.append(h.name, h.value);
    }
}

fn setOutboundAuthHeaders(
    a: std.mem.Allocator,
    inbound: *const HeaderList,
    out: *HeaderList,
    tokens: broker_types.ChatgptAuthTokens,
) !bool {
    if (shouldPreserveChildAuth(
        inbound.find("ChatGPT-Account-ID"),
        inbound.find("Authorization"),
        tokens.account_id,
    )) {
        try out.set("Authorization", inbound.find("Authorization").?);
        try out.set("ChatGPT-Account-ID", inbound.find("ChatGPT-Account-ID").?);
        if (inbound.find("X-OpenAI-Fedramp")) |fedramp| {
            try out.set("X-OpenAI-Fedramp", fedramp);
        } else if (tokens.fedramp) {
            try out.set("X-OpenAI-Fedramp", "true");
        }
        return true;
    }

    try out.set("Authorization", try std.fmt.allocPrint(a, "Bearer {s}", .{tokens.access_token}));
    try out.set("ChatGPT-Account-ID", tokens.account_id);
    if (tokens.fedramp) {
        try out.set("X-OpenAI-Fedramp", "true");
    }
    return false;
}

fn shouldPreserveChildAuth(
    inbound_account_id: ?[]const u8,
    inbound_authorization: ?[]const u8,
    elected_account_id: []const u8,
) bool {
    const account_id = inbound_account_id orelse return false;
    const authorization = inbound_authorization orelse return false;
    if (authorization.len == 0) return false;
    return std.mem.eql(u8, account_id, elected_account_id);
}

fn buildOutboundHeaders(
    a: std.mem.Allocator,
    req: *const Request,
    out: *HeaderList,
    tokens: broker_types.ChatgptAuthTokens,
    drop_turn_state: bool,
) !bool {
    try copyForwardingHeaders(&req.headers, out);
    const preserved_child_auth = try setOutboundAuthHeaders(a, &req.headers, out, tokens);
    if (drop_turn_state) out.remove("x-codex-turn-state");
    return preserved_child_auth;
}

// ── Forwarding + streaming (uses std.http.Client for TLS) ────────────

const BufferedResponse = struct {
    status: u16,
    headers: HeaderList,
    body: []const u8,
};

const StreamOutcomeKind = enum {
    complete,
    client_disconnected,
    upstream_interrupted,
};

const StreamOutcome = struct {
    kind: StreamOutcomeKind = .complete,
    err: ?[]const u8 = null,
    bytes_streamed: usize = 0,
};

const StatusAndClassification = struct {
    status: u16,
    classification: Classification,
    /// Redacted body classification for non-2xx diagnostic evidence.
    /// Never contains raw response bytes.
    body_class: ?[]const u8 = null,
    /// True if the body was streamed verbatim to the client (no buffer);
    /// false if it was buffered for classification/retry or never
    /// arrived (early failure).
    streamed: bool,
    stream_outcome: StreamOutcome = .{},
    /// Present when the response was buffered and has not yet been written to
    /// Codex. The caller may retry first, then write this only if recovery is
    /// unavailable or the retry also fails with a buffered response.
    buffered_response: ?BufferedResponse = null,
};

const TransportFailure = struct {
    err_name: []const u8,
    send_state: broker_attempt_policy.SendState,
};

const ForwardResult = union(enum) {
    response: StatusAndClassification,
    transport_failure: TransportFailure,
};

/// Forward the inbound request to chatgpt.com and write the response
/// directly to the client writer.
///
/// Retry-eligible 4xx responses are buffered before any bytes reach Codex. Only
/// a 401/403/429 may authorize the single alternate. Provider 5xx responses are
/// streamed through unchanged. 429 also needs the body to distinguish quota,
/// rate-limit, and tier outcomes.
///
/// Non-error responses (including 200 streaming SSE) are streamed byte-for-byte
/// from upstream's reader to the client. Connection-close framing is used so we
/// don't have to re-chunk std.http.Client's already-decoded body bytes.
fn forwardAndStream(
    a: std.mem.Allocator,
    req: Request,
    out_headers: HeaderList,
    inbound_reader: anytype,
    client_writer: anytype,
) !ForwardResult {
    var client = std.http.Client{ .allocator = a };
    defer client.deinit();

    const scheme = upstreamScheme(a);
    defer if (!std.mem.eql(u8, scheme, DEFAULT_UPSTREAM_SCHEME)) a.free(scheme);
    const host = upstreamHost(a);
    defer if (!std.mem.eql(u8, host, DEFAULT_UPSTREAM_HOST)) a.free(host);
    const upstream_path = try upstreamPathForRequest(a, req.path);
    defer a.free(upstream_path);
    const url = try std.fmt.allocPrint(a, "{s}://{s}{s}", .{ scheme, host, upstream_path });
    defer a.free(url);
    const uri = try std.Uri.parse(url);

    var extra = std.ArrayListUnmanaged(std.http.Header){};
    defer extra.deinit(a);
    for (out_headers.items.items) |h| {
        try extra.append(a, .{ .name = h.name, .value = h.value });
    }

    var server_header_buf: [16 * 1024]u8 = undefined;
    var http_req = client.open(parseMethod(req.method), uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = extra.items,
    }) catch |err| {
        if (isConfirmedNotSentTransportError(err)) {
            return .{ .transport_failure = .{
                .err_name = @errorName(err),
                .send_state = .confirmed_not_sent,
            } };
        }
        return err;
    };
    defer http_req.deinit();

    const has_request_body = switch (req.body_mode) {
        .buffered => req.body.len > 0,
        .stream_content_length => |len| len > 0,
        .stream_chunked => true,
    };
    switch (req.body_mode) {
        .buffered => if (req.body.len > 0) {
            http_req.transfer_encoding = .{ .content_length = req.body.len };
        },
        .stream_content_length => |len| http_req.transfer_encoding = .{ .content_length = len },
        .stream_chunked => http_req.transfer_encoding = .chunked,
    }
    http_req.send() catch |err| return .{ .transport_failure = .{
        .err_name = @errorName(err),
        .send_state = .ambiguous,
    } };
    if (has_request_body) {
        writeRequestBody(&http_req, req, inbound_reader) catch |err| return .{ .transport_failure = .{
            .err_name = @errorName(err),
            .send_state = .ambiguous,
        } };
        http_req.finish() catch |err| return .{ .transport_failure = .{
            .err_name = @errorName(err),
            .send_state = .ambiguous,
        } };
    }
    waitForUpstreamResponseHeaders(&http_req, configuredProxyUpstreamResponseTimeoutMs(a)) catch |err| return .{ .transport_failure = .{
        .err_name = @errorName(err),
        .send_state = .ambiguous,
    } };

    const status_u16: u16 = @intFromEnum(http_req.response.status);

    // Only 4xx responses are retry decision points. Provider 5xx is streamed
    // unchanged so Codex owns its native retry behavior, even for large or
    // interrupted bodies.
    if (status_u16 >= 400 and status_u16 < 500) {
        // Cap at 64 KiB — chatgpt.com's error JSON/HTML bodies are small.
        const body_idle_timeout_ms = configuredProxyUpstreamBodyIdleTimeoutMs(a);
        var upstream_body_reader = TimedUpstreamBodyReader{
            .request = &http_req,
            .timeout_ms = body_idle_timeout_ms,
            .timeout_active = setUpstreamBodyIdleReadTimeoutIfSafe(&http_req, body_idle_timeout_ms),
        };
        const body = upstream_body_reader.reader().readAllAlloc(a, 64 * 1024) catch |err| {
            if (err == error.OutOfMemory) return err;
            return .{ .transport_failure = .{
                .err_name = @errorName(err),
                .send_state = .ambiguous,
            } };
        };
        const classification = classify(a, status_u16, body);
        return .{ .response = .{
            .status = status_u16,
            .classification = classification,
            .body_class = classification.body_class orelse classifyHttpErrorBody(body),
            .streamed = false,
            .buffered_response = .{
                .status = status_u16,
                .headers = try captureResponseHeaders(a, http_req.response),
                .body = body,
            },
        } };
    }

    const classification = classify(a, status_u16, &.{});
    const body_idle_timeout_ms = configuredProxyUpstreamBodyIdleTimeoutMs(a);
    var upstream_body_reader = TimedUpstreamBodyReader{
        .request = &http_req,
        .timeout_ms = body_idle_timeout_ms,
        .timeout_active = setUpstreamBodyIdleReadTimeoutIfSafe(&http_req, body_idle_timeout_ms),
    };
    const stream_outcome = writeStreamedResponse(client_writer, http_req.response, upstream_body_reader.reader());
    return .{ .response = .{
        .status = status_u16,
        .classification = classification,
        .streamed = true,
        .stream_outcome = stream_outcome,
    } };
}

fn writeRequestBody(http_req: *std.http.Client.Request, req: Request, inbound_reader: anytype) !void {
    switch (req.body_mode) {
        .buffered => if (req.body.len > 0) try http_req.writeAll(req.body),
        .stream_content_length => |len| try copyExactRequestBody(http_req, inbound_reader, len),
        .stream_chunked => try copyChunkedRequestBody(http_req, inbound_reader),
    }
}

fn copyExactRequestBody(
    upstream_writer: anytype,
    inbound_reader: anytype,
    length: usize,
) !void {
    var remaining = length;
    var buffer: [64 * 1024]u8 = undefined;
    while (remaining > 0) {
        const want = @min(remaining, buffer.len);
        const n = try inbound_reader.read(buffer[0..want]);
        if (n == 0) return error.EndOfStream;
        try upstream_writer.writeAll(buffer[0..n]);
        remaining -= n;
    }
}

fn readFixedCrlfLine(inbound_reader: anytype, storage: []u8) ![]const u8 {
    var len: usize = 0;
    while (true) {
        if (len >= storage.len) return error.LineTooLong;
        const byte = try inbound_reader.readByte();
        if (byte == '\r') {
            if (try inbound_reader.readByte() != '\n') return error.BadLineEnding;
            return storage[0..len];
        }
        storage[len] = byte;
        len += 1;
    }
}

fn consumeChunkTrailers(inbound_reader: anytype) !void {
    var total: usize = 0;
    var line_storage: [16 * 1024]u8 = undefined;
    while (true) {
        const line = try readFixedCrlfLine(inbound_reader, &line_storage);
        total = std.math.add(usize, total, line.len + 2) catch return error.TrailersTooLarge;
        if (total > 64 * 1024) return error.TrailersTooLarge;
        if (line.len == 0) return;
    }
}

fn copyChunkedRequestBody(upstream_writer: anytype, inbound_reader: anytype) !void {
    var size_storage: [128]u8 = undefined;
    while (true) {
        const size_line = try readFixedCrlfLine(inbound_reader, &size_storage);
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size_text = std.mem.trim(u8, size_line[0..semi], " \t");
        if (size_text.len == 0) return error.BadChunkSize;
        const size = std.fmt.parseInt(usize, size_text, 16) catch return error.BadChunkSize;
        if (size == 0) {
            try consumeChunkTrailers(inbound_reader);
            return;
        }
        try copyExactRequestBody(upstream_writer, inbound_reader, size);
        if (try inbound_reader.readByte() != '\r' or try inbound_reader.readByte() != '\n') {
            return error.BadLineEnding;
        }
    }
}

fn isConfirmedNotSentTransportError(err: anyerror) bool {
    return err == error.BrokenPipe or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionRefused or
        err == error.ConnectionTimedOut or
        err == error.NetworkUnreachable or
        err == error.HostLacksNetworkAddresses or
        err == error.TemporaryNameServerFailure or
        err == error.NameServerFailure or
        err == error.UnknownHostName or
        err == error.UnexpectedWriteFailure or
        err == error.EndOfStream or
        err == error.HttpConnectionClosing or
        err == error.TlsInitializationFailed or
        err == error.TlsAlert or
        err == error.TlsFailure or
        err == error.TlsConnectionTruncated;
}

fn isClientDisconnectWriteError(err: anyerror) bool {
    return err == error.BrokenPipe or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionTimedOut or
        err == error.EndOfStream;
}

fn pathKind(path: []const u8) []const u8 {
    if (std.mem.eql(u8, path, "/backend-api/codex/responses")) return "responses";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/responses?")) return "responses";
    if (std.mem.eql(u8, path, "/backend-api/responses")) return "responses";
    if (std.mem.startsWith(u8, path, "/backend-api/responses?")) return "responses";
    if (std.mem.eql(u8, path, "/backend-api/codex/responses/compact")) return "responses_compact";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/responses/compact?")) return "responses_compact";
    if (std.mem.eql(u8, path, "/backend-api/responses/compact")) return "responses_compact";
    if (std.mem.startsWith(u8, path, "/backend-api/responses/compact?")) return "responses_compact";
    if (std.mem.eql(u8, path, "/backend-api/models")) return "models";
    if (std.mem.startsWith(u8, path, "/backend-api/models?")) return "models";
    if (std.mem.eql(u8, path, "/backend-api/codex/models")) return "models";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/models?")) return "models";
    if (pathHasEndpointPrefix(path, "/backend-api/codex/memories/trace_summarize")) return "memories_trace_summarize";
    if (pathHasEndpointPrefix(path, "/backend-api/memories/trace_summarize")) return "memories_trace_summarize";
    if (std.mem.indexOf(u8, path, "responses_websockets") != null) return "responses_websocket";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/")) return "codex_other";
    return "unknown";
}

fn upstreamPathForRequest(a: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, path, "/backend-api/codex/")) {
        return try a.dupe(u8, path);
    }
    if (pathHasEndpointPrefix(path, "/backend-api/responses")) {
        return try std.fmt.allocPrint(a, "/backend-api/codex{s}", .{path["/backend-api".len..]});
    }
    if (pathHasEndpointPrefix(path, "/backend-api/models")) {
        return try std.fmt.allocPrint(a, "/backend-api/codex{s}", .{path["/backend-api".len..]});
    }
    if (pathHasEndpointPrefix(path, "/backend-api/memories/trace_summarize")) {
        return try std.fmt.allocPrint(a, "/backend-api/codex{s}", .{path["/backend-api".len..]});
    }
    return try a.dupe(u8, path);
}

fn pathHasEndpointPrefix(path: []const u8, endpoint: []const u8) bool {
    if (std.mem.eql(u8, path, endpoint)) return true;
    if (!std.mem.startsWith(u8, path, endpoint)) return false;
    if (path.len <= endpoint.len) return false;
    return path[endpoint.len] == '?' or path[endpoint.len] == '/';
}

fn classifyHttpErrorBody(body: []const u8) []const u8 {
    if (body.len == 0) return "empty";
    if (std.mem.indexOf(u8, body, "cloudflare") != null) {
        if (std.mem.indexOf(u8, body, "400 Bad Request") != null) return "cloudflare_bad_request";
        if (std.mem.indexOf(u8, body, "403 Forbidden") != null) return "cloudflare_forbidden";
        return "cloudflare_html";
    }
    if (std.mem.indexOf(u8, body, "\"error\"") != null) return "json_error";
    if (std.mem.indexOf(u8, body, "<html") != null or std.mem.indexOf(u8, body, "<!DOCTYPE html") != null) return "html_error";
    return "other";
}

fn parseMethod(s: []const u8) std.http.Method {
    if (std.mem.eql(u8, s, "GET")) return .GET;
    if (std.mem.eql(u8, s, "POST")) return .POST;
    if (std.mem.eql(u8, s, "PUT")) return .PUT;
    if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
    if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
    if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
    if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
    return .POST;
}

// ── Classification ───────────────────────────────────────────────────

pub const Classification = struct {
    kind: broker_types.QuotaKind,
    http_status: ?u16 = null,
    /// Unix seconds when the account becomes eligible again, if known.
    resets_at: ?i64 = null,
    /// Free-form body class label (for telemetry only).
    body_class: ?[]const u8 = null,
};

/// Inspect the response status + body to derive a typed quota event.
/// Per codex-rs/codex-api/src/api_bridge.rs L80–104:
///   429 + body.error.type == "usage_limit_reached" → quota_exhausted
///   429 + body.error.type == "usage_not_included" → tier_insufficient
///   429 (other)                                    → rate_limited
///   401                                            → auth_unauthorized
///   403                                            → tier_insufficient
///   5xx                                            → provider_5xx
///   2xx / 3xx / 4xx (other)                        → ok
pub fn classify(
    a: std.mem.Allocator,
    status: u16,
    body_preview: []const u8,
) Classification {
    if (status == 401) return .{ .kind = .auth_unauthorized, .http_status = status };
    if (status == 403) return .{ .kind = .tier_insufficient, .http_status = status };
    if (status >= 500 and status < 600) return .{ .kind = .provider_5xx, .http_status = status };

    if (status == 429) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, body_preview, .{
            .ignore_unknown_fields = true,
        }) catch {
            return .{ .kind = .rate_limited, .http_status = status };
        };
        defer parsed.deinit();
        if (parsed.value != .object) return .{ .kind = .rate_limited, .http_status = status };
        const err_v = parsed.value.object.get("error") orelse return .{ .kind = .rate_limited, .http_status = status };
        if (err_v != .object) return .{ .kind = .rate_limited, .http_status = status };
        const type_v = err_v.object.get("type") orelse return .{ .kind = .rate_limited, .http_status = status };
        if (type_v != .string) return .{ .kind = .rate_limited, .http_status = status };

        if (std.mem.eql(u8, type_v.string, "usage_limit_reached")) {
            var resets: ?i64 = null;
            if (err_v.object.get("resets_at")) |rv| {
                if (rv == .integer) resets = rv.integer;
            }
            return .{ .kind = .quota_exhausted, .http_status = status, .resets_at = resets, .body_class = "usage_limit_reached" };
        }
        if (std.mem.eql(u8, type_v.string, "usage_not_included")) {
            return .{ .kind = .tier_insufficient, .http_status = status, .body_class = "usage_not_included" };
        }
        return .{ .kind = .rate_limited, .http_status = status };
    }

    return .{ .kind = .ok, .http_status = status };
}

// ── Response writing ─────────────────────────────────────────────────

fn writeStatus(writer: anytype, code: u16, reason: []const u8) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ code, reason });
    try writer.writeAll("Content-Length: 0\r\nConnection: close\r\n\r\n");
}

fn writeNoAccountSelectableResponse(
    allocator: std.mem.Allocator,
    writer: anytype,
    profile: ?[]const u8,
    rejections: []const CandidateRejection,
) !void {
    var body = std.ArrayListUnmanaged(u8){};
    defer body.deinit(allocator);
    const w = body.writer(allocator);
    const preflight_command = if (profile) |value|
        try std.fmt.allocPrint(allocator, "oauth-mux codex preflight --profile {s} --json", .{value})
    else
        try allocator.dupe(u8, "oauth-mux codex preflight --json");
    defer allocator.free(preflight_command);
    const repair_command = if (profile) |value|
        try std.fmt.allocPrint(allocator, "oauth-mux stay-afloat --once --execute --profile {s} --json", .{value})
    else
        try allocator.dupe(u8, "oauth-mux stay-afloat --once --execute --provider codex --json");
    defer allocator.free(repair_command);

    try w.writeAll("{\"error\":{\"type\":\"oauth_mux_no_account_selectable\",\"code\":\"oauth_mux_no_account_selectable\",\"message\":");
    try std.json.stringify(
        "oauth-mux: no selectable Codex fallback account; route repair is required. Inspect the redacted status artifact or run codex preflight.",
        .{},
        w,
    );
    try w.writeAll(",\"preflight_command\":");
    try std.json.stringify(preflight_command, .{}, w);
    try w.writeAll(",\"spends_provider_calls\":false,\"mutates_user_config\":false,\"mutates_route_health\":false");
    try w.writeAll(",\"rejection_summary\":");
    try writeNoAccountRejectionSummaryJson(w, rejections);
    try w.writeAll(",\"agent_safe_next_actions\":[");
    try writeNoAccountNextActionJson(w, .{
        .kind = "codex_preflight",
        .label = "diagnostic Codex preflight",
        .command = preflight_command,
        .budget = "free_local",
        .agent_safe = true,
        .may_spend_provider_calls = false,
        .mutates_user_config = false,
        .mutates_route_health = false,
        .interactive = false,
    });
    try w.writeAll("],\"spend_confirmed_next_actions\":[");
    try writeNoAccountNextActionJson(w, .{
        .kind = "stay_afloat_execute",
        .label = "spend-confirmed route health repair",
        .command = repair_command,
        .budget = "spend_provider",
        .agent_safe = false,
        .may_spend_provider_calls = true,
        .mutates_user_config = false,
        .mutates_route_health = true,
        .interactive = false,
    });
    try w.writeByte(']');
    try w.writeAll(",\"rejections\":[");
    for (rejections, 0..) |rejection, idx| {
        if (idx != 0) try w.writeByte(',');
        try w.writeAll("{\"account\":");
        try std.json.stringify(rejection.account, .{}, w);
        try w.writeAll(",\"state\":");
        try std.json.stringify(@tagName(rejection.state), .{}, w);
        try w.writeAll(",\"reason\":");
        try std.json.stringify(rejection.reason, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}}\n");

    try writer.writeAll("HTTP/1.1 503 Service Unavailable\r\n");
    try writer.writeAll("Content-Type: application/json\r\n");
    try writer.print("Content-Length: {d}\r\n", .{body.items.len});
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(body.items);
}

const NoAccountNextAction = struct {
    kind: []const u8,
    label: []const u8,
    command: []const u8,
    budget: []const u8,
    agent_safe: bool,
    may_spend_provider_calls: bool,
    mutates_user_config: bool,
    mutates_route_health: bool,
    interactive: bool,
};

fn writeNoAccountNextActionJson(writer: anytype, action: NoAccountNextAction) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try std.json.stringify(action.kind, .{}, writer);
    try writer.writeAll(",\"label\":");
    try std.json.stringify(action.label, .{}, writer);
    try writer.writeAll(",\"command\":");
    try std.json.stringify(action.command, .{}, writer);
    try writer.writeAll(",\"budget\":");
    try std.json.stringify(action.budget, .{}, writer);
    try writer.writeAll(",\"agent_safe\":");
    try writer.writeAll(if (action.agent_safe) "true" else "false");
    try writer.writeAll(",\"may_spend_provider_calls\":");
    try writer.writeAll(if (action.may_spend_provider_calls) "true" else "false");
    try writer.writeAll(",\"mutates_user_config\":");
    try writer.writeAll(if (action.mutates_user_config) "true" else "false");
    try writer.writeAll(",\"mutates_route_health\":");
    try writer.writeAll(if (action.mutates_route_health) "true" else "false");
    try writer.writeAll(",\"interactive\":");
    try writer.writeAll(if (action.interactive) "true" else "false");
    try writer.writeByte('}');
}

fn writeUnsupportedWebSocketResponse(writer: anytype) !void {
    const body =
        "{\"error\":{\"type\":\"oauth_mux_unsupported_transport\",\"code\":\"oauth_mux_unsupported_transport\",\"message\":\"oauth-mux: Codex WebSocket responses transport is not supported by this managed proxy; falling back to HTTP Responses transport.\"}}\n";
    try writer.writeAll("HTTP/1.1 426 Upgrade Required\r\n");
    try writer.writeAll("Content-Type: application/json\r\n");
    try writer.print("Content-Length: {d}\r\n", .{body.len});
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(body);
}

fn writeNoAccountRejectionSummaryJson(writer: anytype, rejections: []const CandidateRejection) !void {
    try writer.writeByte('{');
    try writer.print("\"total\":{d}", .{rejections.len});
    try writer.print(",\"auth_failed\":{d}", .{countRejectionsByState(rejections, .auth_failed)});
    try writer.print(",\"quota_exhausted\":{d}", .{countRejectionsByState(rejections, .quota_exhausted)});
    try writer.print(",\"rate_limited\":{d}", .{countRejectionsByState(rejections, .rate_limited)});
    try writer.print(",\"tier_insufficient\":{d}", .{countRejectionsByState(rejections, .tier_insufficient)});
    try writer.print(",\"provider_degraded\":{d}", .{countRejectionsByState(rejections, .provider_degraded)});
    try writer.print(",\"credential_unavailable\":{d}", .{countRejectionsByState(rejections, .credential_unavailable)});
    try writer.writeByte('}');
}

fn countRejectionsByState(rejections: []const CandidateRejection, state: RouteState) usize {
    var count: usize = 0;
    for (rejections) |rejection| {
        if (rejection.state == state) count += 1;
    }
    return count;
}

fn writeProviderUnavailableResponse(
    allocator: std.mem.Allocator,
    writer: anytype,
    account: []const u8,
    err: []const u8,
    rejections: []const CandidateRejection,
) !void {
    var body = std.ArrayListUnmanaged(u8){};
    defer body.deinit(allocator);
    const w = body.writer(allocator);

    try w.writeAll("{\"error\":{\"type\":\"oauth_mux_provider_unavailable\",\"code\":\"oauth_mux_provider_unavailable\",\"message\":");
    try std.json.stringify(
        "oauth-mux: the managed Codex request could not be forwarded safely. No cross-account replay was attempted; this is not credential-dead evidence. Inspect the redacted status artifact before retrying.",
        .{},
        w,
    );
    try w.writeAll(",\"account\":");
    try std.json.stringify(account, .{}, w);
    try w.writeAll(",\"transport_error\":");
    try std.json.stringify(err, .{}, w);
    try w.writeAll(",\"rejections\":[");
    for (rejections, 0..) |rejection, idx| {
        if (idx != 0) try w.writeByte(',');
        try w.writeAll("{\"account\":");
        try std.json.stringify(rejection.account, .{}, w);
        try w.writeAll(",\"state\":");
        try std.json.stringify(@tagName(rejection.state), .{}, w);
        try w.writeAll(",\"reason\":");
        try std.json.stringify(rejection.reason, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}}\n");

    try writer.writeAll("HTTP/1.1 503 Service Unavailable\r\n");
    try writer.writeAll("Content-Type: application/json\r\n");
    try writer.print("Content-Length: {d}\r\n", .{body.items.len});
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(body.items);
}

/// Write headers that are safe to forward to the client unchanged.
/// Drops hop-by-hop headers (RFC 7230 §6.1) and transfer-coding
/// metadata since we manage framing ourselves below.
fn writeForwardingResponseHeaders(writer: anytype, response: std.http.Client.Response) !void {
    var hi = response.iterateHeaders();
    while (hi.next()) |h| {
        if (asciiEqlIgnoreCase(h.name, "connection")) continue;
        if (asciiEqlIgnoreCase(h.name, "transfer-encoding")) continue;
        if (asciiEqlIgnoreCase(h.name, "keep-alive")) continue;
        if (asciiEqlIgnoreCase(h.name, "content-length")) continue;
        try writer.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
}

fn captureResponseHeaders(a: std.mem.Allocator, response: std.http.Client.Response) !HeaderList {
    var headers = HeaderList.init(a);
    var hi = response.iterateHeaders();
    while (hi.next()) |h| {
        if (asciiEqlIgnoreCase(h.name, "connection")) continue;
        if (asciiEqlIgnoreCase(h.name, "transfer-encoding")) continue;
        if (asciiEqlIgnoreCase(h.name, "keep-alive")) continue;
        if (asciiEqlIgnoreCase(h.name, "content-length")) continue;
        try headers.append(try a.dupe(u8, h.name), try a.dupe(u8, h.value));
    }
    return headers;
}

/// Buffered-error path: write status + headers + Content-Length + body.
fn writeBufferedResponse(
    writer: anytype,
    response: std.http.Client.Response,
    body: []const u8,
) !void {
    try writer.print("HTTP/1.1 {d} \r\n", .{@intFromEnum(response.status)});
    try writeForwardingResponseHeaders(writer, response);
    try writer.print("Content-Length: {d}\r\n", .{body.len});
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(body);
}

fn writeBufferedStoredResponse(writer: anytype, response: BufferedResponse) !void {
    try writer.print("HTTP/1.1 {d} \r\n", .{response.status});
    for (response.headers.items.items) |h| {
        try writer.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try writer.print("Content-Length: {d}\r\n", .{response.body.len});
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(response.body);
}

/// Streaming path: write status + headers (no Content-Length, no
/// Transfer-Encoding) + Connection: close, then pump bytes from
/// upstream reader to client writer in 64 KiB chunks. The client
/// reads-until-EOF per RFC 7230 §3.3.3 case 7. Real-time SSE works.
fn writeStreamedResponse(
    writer: anytype,
    response: std.http.Client.Response,
    upstream_reader: anytype,
) StreamOutcome {
    writer.print("HTTP/1.1 {d} \r\n", .{@intFromEnum(response.status)}) catch |err| {
        return .{ .kind = .client_disconnected, .err = @errorName(err) };
    };
    writeForwardingResponseHeaders(writer, response) catch |err| {
        return .{ .kind = .client_disconnected, .err = @errorName(err) };
    };
    writer.writeAll("Connection: close\r\n\r\n") catch |err| {
        return .{ .kind = .client_disconnected, .err = @errorName(err) };
    };

    return pumpStreamBody(writer, upstream_reader, response.content_length);
}

fn shortReadOutcome(bytes_streamed: usize, expected_content_length: ?u64) ?StreamOutcome {
    const expected = expected_content_length orelse return null;
    const streamed: u64 = @intCast(bytes_streamed);
    if (streamed >= expected) return null;
    return .{
        .kind = .upstream_interrupted,
        .err = "ShortRead",
        .bytes_streamed = bytes_streamed,
    };
}

fn pumpStreamBody(writer: anytype, upstream_reader: anytype, expected_content_length: ?u64) StreamOutcome {
    var buf: [64 * 1024]u8 = undefined;
    var bytes_streamed: usize = 0;
    while (true) {
        const n = upstream_reader.read(&buf) catch |err| switch (err) {
            error.EndOfStream => {
                if (shortReadOutcome(bytes_streamed, expected_content_length)) |outcome| return outcome;
                break;
            },
            else => return .{
                .kind = .upstream_interrupted,
                .err = @errorName(err),
                .bytes_streamed = bytes_streamed,
            },
        };
        if (n == 0) {
            if (shortReadOutcome(bytes_streamed, expected_content_length)) |outcome| return outcome;
            break;
        }
        writer.writeAll(buf[0..n]) catch |err| {
            return .{
                .kind = .client_disconnected,
                .err = @errorName(err),
                .bytes_streamed = bytes_streamed,
            };
        };
        bytes_streamed += n;
    }
    return .{ .kind = .complete, .bytes_streamed = bytes_streamed };
}

// ── Tests ────────────────────────────────────────────────────────────

test "classify 200 OK -> .ok" {
    const c = classify(std.testing.allocator, 200, "");
    try std.testing.expectEqual(broker_types.QuotaKind.ok, c.kind);
}

test "classify 401 -> auth_unauthorized" {
    const c = classify(std.testing.allocator, 401, "{}");
    try std.testing.expectEqual(broker_types.QuotaKind.auth_unauthorized, c.kind);
}

test "pathKind redacts Codex endpoint paths into stable classes" {
    try std.testing.expectEqualStrings("responses", pathKind("/backend-api/codex/responses"));
    try std.testing.expectEqualStrings("responses", pathKind("/backend-api/codex/responses?after=1"));
    try std.testing.expectEqualStrings("responses", pathKind("/backend-api/responses"));
    try std.testing.expectEqualStrings("responses", pathKind("/backend-api/responses?after=1"));
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/codex/responses/compact"));
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/codex/responses/compact?after=1"));
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/responses/compact"));
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/responses/compact?after=1"));
    try std.testing.expectEqualStrings("models", pathKind("/backend-api/models?client_version=0.132.0"));
    try std.testing.expectEqualStrings("models", pathKind("/backend-api/codex/models?client_version=0.132.0"));
    try std.testing.expectEqualStrings("memories_trace_summarize", pathKind("/backend-api/codex/memories/trace_summarize"));
    try std.testing.expectEqualStrings("memories_trace_summarize", pathKind("/backend-api/codex/memories/trace_summarize?after=1"));
    try std.testing.expectEqualStrings("memories_trace_summarize", pathKind("/backend-api/memories/trace_summarize"));
    try std.testing.expectEqualStrings("memories_trace_summarize", pathKind("/backend-api/memories/trace_summarize?after=1"));
    try std.testing.expectEqualStrings("codex_other", pathKind("/backend-api/codex/unknown/shape"));
    try std.testing.expectEqualStrings("unknown", pathKind("/not-codex"));
}

test "upstreamPathForRequest maps built-in openai provider paths to Codex upstream" {
    const responses = try upstreamPathForRequest(std.testing.allocator, "/backend-api/responses?after=1");
    defer std.testing.allocator.free(responses);
    try std.testing.expectEqualStrings("/backend-api/codex/responses?after=1", responses);

    const compact = try upstreamPathForRequest(std.testing.allocator, "/backend-api/responses/compact");
    defer std.testing.allocator.free(compact);
    try std.testing.expectEqualStrings("/backend-api/codex/responses/compact", compact);

    const models = try upstreamPathForRequest(std.testing.allocator, "/backend-api/models?client_version=0.132.0");
    defer std.testing.allocator.free(models);
    try std.testing.expectEqualStrings("/backend-api/codex/models?client_version=0.132.0", models);

    const memory = try upstreamPathForRequest(std.testing.allocator, "/backend-api/memories/trace_summarize?after=1");
    defer std.testing.allocator.free(memory);
    try std.testing.expectEqualStrings("/backend-api/codex/memories/trace_summarize?after=1", memory);

    const already_codex = try upstreamPathForRequest(std.testing.allocator, "/backend-api/codex/responses");
    defer std.testing.allocator.free(already_codex);
    try std.testing.expectEqualStrings("/backend-api/codex/responses", already_codex);

    const adjacent = try upstreamPathForRequest(std.testing.allocator, "/backend-api/responses_websockets");
    defer std.testing.allocator.free(adjacent);
    try std.testing.expectEqualStrings("/backend-api/responses_websockets", adjacent);
}

test "websocket upgrade requests are detected before upstream forwarding" {
    var headers = HeaderList.init(std.testing.allocator);
    defer headers.items.deinit(std.testing.allocator);
    try headers.append("Host", "127.0.0.1:1234");
    try headers.append("Connection", "keep-alive, Upgrade");
    try headers.append("Upgrade", "websocket");
    try headers.append("Sec-WebSocket-Key", "fixture");
    try headers.append("OpenAI-Beta", "responses_websockets=2026-02-06");

    const req = Request{
        .method = "GET",
        .path = "/backend-api/responses",
        .headers = headers,
        .body = &.{},
    };
    try std.testing.expect(isWebSocketUpgradeRequest(&req));
}

test "plain responses GET is not classified as websocket upgrade" {
    var headers = HeaderList.init(std.testing.allocator);
    defer headers.items.deinit(std.testing.allocator);
    try headers.append("Host", "127.0.0.1:1234");

    const req = Request{
        .method = "GET",
        .path = "/backend-api/responses",
        .headers = headers,
        .body = &.{},
    };
    try std.testing.expect(!isWebSocketUpgradeRequest(&req));
}

test "responses GET reconnect requests are contained locally" {
    var headers = HeaderList.init(std.testing.allocator);
    defer headers.items.deinit(std.testing.allocator);
    try headers.append("Host", "127.0.0.1:1234");
    try headers.append("OpenAI-Beta", "responses_websockets=2026-02-06");

    const req = Request{
        .method = "GET",
        .path = "/backend-api/responses",
        .headers = headers,
        .body = &.{},
    };
    try std.testing.expectEqualStrings("responses_get", unsupportedResponsesGetTransport(&req) orelse "none");
}

test "websocket responses GET reports websocket transport" {
    var headers = HeaderList.init(std.testing.allocator);
    defer headers.items.deinit(std.testing.allocator);
    try headers.append("Host", "127.0.0.1:1234");
    try headers.append("Upgrade", "websocket");
    try headers.append("OpenAI-Beta", "responses_websockets=2026-02-06");

    const req = Request{
        .method = "GET",
        .path = "/backend-api/responses",
        .headers = headers,
        .body = &.{},
    };
    try std.testing.expectEqualStrings("websocket", unsupportedResponsesGetTransport(&req) orelse "none");
}

test "non-responses GET requests are still proxyable" {
    var headers = HeaderList.init(std.testing.allocator);
    defer headers.items.deinit(std.testing.allocator);
    try headers.append("Host", "127.0.0.1:1234");

    const req = Request{
        .method = "GET",
        .path = "/backend-api/models",
        .headers = headers,
        .body = &.{},
    };
    try std.testing.expect(unsupportedResponsesGetTransport(&req) == null);
}

test "unsupported websocket response is local and explicit" {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(std.testing.allocator);
    try writeUnsupportedWebSocketResponse(out.writer(std.testing.allocator));
    try std.testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 426 Upgrade Required\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "oauth_mux_unsupported_transport") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "falling back to HTTP Responses transport") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "Connection: close\r\n") != null);
}

const TestSinkWriter = struct {
    bytes: usize = 0,
    fail: bool = false,

    const Error = error{BrokenPipe};
    const Writer = std.io.Writer(*TestSinkWriter, Error, write);

    fn writer(self: *TestSinkWriter) Writer {
        return .{ .context = self };
    }

    fn write(self: *TestSinkWriter, bytes: []const u8) Error!usize {
        if (self.fail) return error.BrokenPipe;
        self.bytes += bytes.len;
        return bytes.len;
    }
};

const TestChunkReader = struct {
    chunk: []const u8,
    emitted: bool = false,
    fail_after_chunk: bool = false,

    const Error = error{ EndOfStream, ConnectionResetByPeer };
    const Reader = std.io.Reader(*TestChunkReader, Error, read);

    fn reader(self: *TestChunkReader) Reader {
        return .{ .context = self };
    }

    fn read(self: *TestChunkReader, buf: []u8) Error!usize {
        if (self.emitted) {
            if (self.fail_after_chunk) return error.ConnectionResetByPeer;
            return error.EndOfStream;
        }
        self.emitted = true;
        const n = @min(buf.len, self.chunk.len);
        @memcpy(buf[0..n], self.chunk[0..n]);
        return n;
    }
};

test "stream body BrokenPipe is classified as downstream disconnect" {
    var writer = TestSinkWriter{ .fail = true };
    var reader = TestChunkReader{ .chunk = "data" };

    const outcome = pumpStreamBody(writer.writer(), reader.reader(), null);

    try std.testing.expectEqual(StreamOutcomeKind.client_disconnected, outcome.kind);
    try std.testing.expectEqualStrings("BrokenPipe", outcome.err.?);
    try std.testing.expectEqual(@as(usize, 0), outcome.bytes_streamed);
}

test "stream body upstream read failure is classified without retrying partial response" {
    var writer = TestSinkWriter{};
    var reader = TestChunkReader{ .chunk = "data", .fail_after_chunk = true };

    const outcome = pumpStreamBody(writer.writer(), reader.reader(), null);

    try std.testing.expectEqual(StreamOutcomeKind.upstream_interrupted, outcome.kind);
    try std.testing.expectEqualStrings("ConnectionResetByPeer", outcome.err.?);
    try std.testing.expectEqual(@as(usize, 4), outcome.bytes_streamed);
    try std.testing.expectEqual(@as(usize, 4), writer.bytes);
}

test "stream body short Content-Length EOF is classified as upstream interrupted" {
    var writer = TestSinkWriter{};
    var reader = TestChunkReader{ .chunk = "data" };

    const outcome = pumpStreamBody(writer.writer(), reader.reader(), 8);

    try std.testing.expectEqual(StreamOutcomeKind.upstream_interrupted, outcome.kind);
    try std.testing.expectEqualStrings("ShortRead", outcome.err.?);
    try std.testing.expectEqual(@as(usize, 4), outcome.bytes_streamed);
    try std.testing.expectEqual(@as(usize, 4), writer.bytes);
}

test "classifyHttpErrorBody identifies Cloudflare 400 without exposing body" {
    const body =
        \\<html>
        \\<head><title>400 Bad Request</title></head>
        \\<body><center><h1>400 Bad Request</h1></center><hr><center>cloudflare</center></body>
        \\</html>
    ;
    try std.testing.expectEqualStrings("cloudflare_bad_request", classifyHttpErrorBody(body));
    try std.testing.expectEqualStrings("json_error", classifyHttpErrorBody("{\"error\":{\"type\":\"x\"}}"));
    try std.testing.expectEqualStrings("empty", classifyHttpErrorBody(""));
}

test "shouldPreserveChildAuth preserves refreshed bearer for same elected account only" {
    try std.testing.expect(shouldPreserveChildAuth("acct-1", "Bearer refreshed", "acct-1"));
    try std.testing.expect(!shouldPreserveChildAuth("acct-1", "Bearer refreshed", "acct-2"));
    try std.testing.expect(!shouldPreserveChildAuth("acct-1", null, "acct-1"));
    try std.testing.expect(!shouldPreserveChildAuth(null, "Bearer refreshed", "acct-1"));
    try std.testing.expect(!shouldPreserveChildAuth("acct-1", "", "acct-1"));
}

test "setOutboundAuthHeaders preserves child auth for same account and substitutes on swap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var inbound = HeaderList.init(a);
    try inbound.append("Authorization", "Bearer child-refreshed");
    try inbound.append("ChatGPT-Account-ID", "acct-1");
    try inbound.append("X-OpenAI-Fedramp", "false");

    var same_out = HeaderList.init(a);
    const same_tokens = broker_types.ChatgptAuthTokens{
        .access_token = "materialized-stale",
        .account_id = "acct-1",
        .fedramp = true,
    };
    const preserved = try setOutboundAuthHeaders(a, &inbound, &same_out, same_tokens);
    try std.testing.expect(preserved);
    try std.testing.expectEqualStrings("Bearer child-refreshed", same_out.find("Authorization").?);
    try std.testing.expectEqualStrings("acct-1", same_out.find("ChatGPT-Account-ID").?);
    try std.testing.expectEqualStrings("false", same_out.find("X-OpenAI-Fedramp").?);

    var swap_out = HeaderList.init(a);
    const swap_tokens = broker_types.ChatgptAuthTokens{
        .access_token = "materialized-next",
        .account_id = "acct-2",
        .fedramp = false,
    };
    const swapped = try setOutboundAuthHeaders(a, &inbound, &swap_out, swap_tokens);
    try std.testing.expect(!swapped);
    try std.testing.expectEqualStrings("Bearer materialized-next", swap_out.find("Authorization").?);
    try std.testing.expectEqualStrings("acct-2", swap_out.find("ChatGPT-Account-ID").?);
}

test "only a cross-account alternate drops Codex turn state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var inbound = HeaderList.init(a);
    try inbound.append("x-codex-turn-state", "turn-state-exact");
    const req = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = inbound,
        .body = "{\"model\":\"gpt-5.3-codex\"}",
    };
    const tokens = broker_types.ChatgptAuthTokens{
        .access_token = "materialized",
        .account_id = "acct-1",
        .fedramp = false,
    };

    var same_route = HeaderList.init(a);
    _ = try buildOutboundHeaders(a, &req, &same_route, tokens, false);
    try std.testing.expectEqualStrings("turn-state-exact", same_route.find("x-codex-turn-state").?);

    var alternate = HeaderList.init(a);
    _ = try buildOutboundHeaders(a, &req, &alternate, tokens, true);
    try std.testing.expect(alternate.find("x-codex-turn-state") == null);
}

test "classify 503 -> provider_5xx" {
    const c = classify(std.testing.allocator, 503, "{}");
    try std.testing.expectEqual(broker_types.QuotaKind.provider_5xx, c.kind);
}

test "provider_5xx passes through without consuming the follow-up" {
    const transition = broker_attempt_policy.reduce(
        .{ .initial = .eligible_reserved },
        .{ .upstream_status = .{ .status = 503, .delivery = .buffered_before_downstream } },
    );
    try std.testing.expectEqual(broker_attempt_policy.Decision.finish_original, transition.decision);
    try std.testing.expectEqual(RouteState.provider_degraded, routeStateFromClassification(.provider_5xx));
}

test "confirmed-not-sent classifier is limited to failures before send is called" {
    try std.testing.expect(isConfirmedNotSentTransportError(error.BrokenPipe));
    try std.testing.expect(isConfirmedNotSentTransportError(error.ConnectionResetByPeer));
    try std.testing.expect(isConfirmedNotSentTransportError(error.ConnectionRefused));
    try std.testing.expect(isConfirmedNotSentTransportError(error.NetworkUnreachable));
    try std.testing.expect(isConfirmedNotSentTransportError(error.UnknownHostName));
    try std.testing.expect(isConfirmedNotSentTransportError(error.UnexpectedWriteFailure));
    try std.testing.expect(isConfirmedNotSentTransportError(error.TlsInitializationFailed));
    try std.testing.expect(isConfirmedNotSentTransportError(error.TlsAlert));
    try std.testing.expect(isConfirmedNotSentTransportError(error.TlsFailure));
    try std.testing.expect(isConfirmedNotSentTransportError(error.TlsConnectionTruncated));
    try std.testing.expect(!isConfirmedNotSentTransportError(error.OutOfMemory));
}

test "classify 429 + usage_limit_reached -> quota_exhausted with resets_at" {
    const body =
        \\{"error":{"type":"usage_limit_reached","plan_type":"pro","resets_at":1788000000}}
    ;
    const c = classify(std.testing.allocator, 429, body);
    try std.testing.expectEqual(broker_types.QuotaKind.quota_exhausted, c.kind);
    try std.testing.expectEqual(@as(?i64, 1788000000), c.resets_at);
}

test "classify 429 + usage_not_included -> tier_insufficient" {
    const body =
        \\{"error":{"type":"usage_not_included","plan_type":"free"}}
    ;
    const c = classify(std.testing.allocator, 429, body);
    try std.testing.expectEqual(broker_types.QuotaKind.tier_insufficient, c.kind);
}

test "classify 403 -> tier_insufficient with exact status" {
    const c = classify(std.testing.allocator, 403, "{}");
    try std.testing.expectEqual(broker_types.QuotaKind.tier_insufficient, c.kind);
    try std.testing.expectEqual(@as(?u16, 403), c.http_status);
}

test "classify 429 with no error.type -> rate_limited" {
    const body = "{\"foo\":1}";
    const c = classify(std.testing.allocator, 429, body);
    try std.testing.expectEqual(broker_types.QuotaKind.rate_limited, c.kind);
}

test "classify 429 with non-JSON body -> rate_limited" {
    const c = classify(std.testing.allocator, 429, "Too Many Requests");
    try std.testing.expectEqual(broker_types.QuotaKind.rate_limited, c.kind);
}

test "provider signal matrix maps to route state and shared attempt policy" {
    const SignalCase = struct {
        name: []const u8,
        status: u16,
        body: []const u8,
        kind: broker_types.QuotaKind,
        route_state: RouteState,
        alternate_expected: bool,
        body_class: ?[]const u8 = null,
    };

    const cases = [_]SignalCase{
        .{
            .name = "200 ok",
            .status = 200,
            .body = "{}",
            .kind = .ok,
            .route_state = .available,
            .alternate_expected = false,
        },
        .{
            .name = "401 auth",
            .status = 401,
            .body = "{}",
            .kind = .auth_unauthorized,
            .route_state = .auth_failed,
            .alternate_expected = true,
        },
        .{
            .name = "403 tier",
            .status = 403,
            .body = "{}",
            .kind = .tier_insufficient,
            .route_state = .tier_insufficient,
            .alternate_expected = true,
        },
        .{
            .name = "429 usage_limit_reached",
            .status = 429,
            .body = "{\"error\":{\"type\":\"usage_limit_reached\",\"resets_at\":1788000000}}",
            .kind = .quota_exhausted,
            .route_state = .quota_exhausted,
            .alternate_expected = true,
            .body_class = "usage_limit_reached",
        },
        .{
            .name = "429 generic rate",
            .status = 429,
            .body = "{\"error\":{\"type\":\"rate_limit_exceeded\"}}",
            .kind = .rate_limited,
            .route_state = .rate_limited,
            .alternate_expected = true,
        },
        .{
            .name = "429 malformed rate",
            .status = 429,
            .body = "Too Many Requests",
            .kind = .rate_limited,
            .route_state = .rate_limited,
            .alternate_expected = true,
        },
        .{
            .name = "429 usage_not_included",
            .status = 429,
            .body = "{\"error\":{\"type\":\"usage_not_included\",\"plan_type\":\"free\"}}",
            .kind = .tier_insufficient,
            .route_state = .tier_insufficient,
            .alternate_expected = true,
            .body_class = "usage_not_included",
        },
        .{
            .name = "provider 5xx",
            .status = 503,
            .body = "Service Unavailable",
            .kind = .provider_5xx,
            .route_state = .provider_degraded,
            .alternate_expected = false,
        },
    };

    for (cases) |tc| {
        const c = classify(std.testing.allocator, tc.status, tc.body);
        try std.testing.expectEqual(tc.kind, c.kind);
        try std.testing.expectEqual(tc.route_state, routeStateFromClassification(c.kind));
        const transition = broker_attempt_policy.reduce(
            .{ .initial = .eligible_reserved },
            .{ .upstream_status = .{ .status = tc.status, .delivery = .buffered_before_downstream } },
        );
        const alternate = switch (transition.decision) {
            .retry_alternate => true,
            .retry_same_route, .finish_original => false,
        };
        try std.testing.expectEqual(tc.alternate_expected, alternate);
        if (tc.body_class) |expected_body_class| {
            try std.testing.expectEqualStrings(expected_body_class, c.body_class orelse "");
        } else {
            try std.testing.expect(c.body_class == null);
        }
    }
}

test "Prompt 85 Codex live mapping admits only one strict exact-model envelope" {
    const headers = HeaderList.init(std.testing.allocator);
    const request = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = headers,
        .body = "{\"model\":\"gpt-exact\",\"input\":\"hello\"}",
    };
    const mapped = mapSharedCoreRequest(request);

    try std.testing.expect(mapped.demand != null);
    try std.testing.expectEqualStrings("gpt-exact", mapped.demand.?.exact_model.bytes());
    try std.testing.expectEqual(broker_lease_state.ProjectionQuality.unavailable, mapped.lease_quality);

    // Mapping failure stays on the launch account and is never alternate-eligible.
    inline for (.{
        "{\"input\":\"missing\"}",
        "{\"model\":7}",
        "{\"model\":\"a\",\"model\":\"b\"}",
        "{\"model\":\"a\"} {}",
        "{\"input\":,\"model\":\"gpt-exact\"}",
        "{\"input\":\"bad\\q\",\"model\":\"gpt-exact\"}",
    }) |body| {
        const absent = mapSharedCoreRequest(.{
            .method = "POST",
            .path = "/backend-api/codex/responses",
            .headers = headers,
            .body = body,
        });
        try std.testing.expect(absent.demand == null);
    }
}

test "Prompt 85 Codex model scan skips large escaped unknown fields before and after model" {
    const allocator = std.testing.allocator;
    const escaped_codepoints = 5 * 1024;
    const escaped_input = try allocator.alloc(u8, escaped_codepoints * "\\u0061".len);
    defer allocator.free(escaped_input);
    for (0..escaped_codepoints) |index| {
        @memcpy(escaped_input[index * "\\u0061".len ..][0.."\\u0061".len], "\\u0061");
    }

    const bodies = .{
        try std.fmt.allocPrint(
            allocator,
            "{{\"input\":\"{s}\",\"model\":\"gpt-5.3-codex\"}}",
            .{escaped_input},
        ),
        try std.fmt.allocPrint(
            allocator,
            "{{\"model\":\"gpt-5.3-codex\",\"input\":\"{s}\"}}",
            .{escaped_input},
        ),
    };
    defer inline for (bodies) |body| allocator.free(body);

    inline for (bodies) |body| {
        const mapped = mapSharedCoreRequest(.{
            .method = "POST",
            .path = "/backend-api/codex/responses",
            .headers = HeaderList.init(allocator),
            .body = body,
        });
        try std.testing.expect(mapped.demand != null);
        try std.testing.expectEqualStrings("gpt-5.3-codex", mapped.demand.?.exact_model.bytes());
    }
}

test "Prompt 85 Codex mapping feeds buffered and started delivery into shared attempt policy" {
    const buffered_headers = HeaderList.init(std.testing.allocator);
    const buffered = StatusAndClassification{
        .status = 503,
        .classification = .{ .kind = .provider_5xx },
        .streamed = false,
        .buffered_response = .{
            .status = 503,
            .headers = buffered_headers,
            .body = "upstream unavailable",
        },
    };
    switch (mapSharedCoreHttpOutcome(buffered)) {
        .upstream_status => |observed| {
            try std.testing.expectEqual(@as(u16, 503), observed.status);
            try std.testing.expectEqual(
                broker_attempt_policy.Delivery.buffered_before_downstream,
                observed.delivery,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    const streamed = StatusAndClassification{
        .status = 200,
        .classification = .{ .kind = .ok },
        .streamed = true,
    };
    switch (mapSharedCoreHttpOutcome(streamed)) {
        .upstream_status => |observed| {
            try std.testing.expectEqual(@as(u16, 200), observed.status);
            try std.testing.expectEqual(
                broker_attempt_policy.Delivery.downstream_started,
                observed.delivery,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

fn addTestCodexRoute(
    pool: *account_pool_mod.AccountPool,
    id: []const u8,
    identity: []const u8,
    availability: account_pool_mod.Availability,
) !void {
    try pool.add(.{
        .id = id,
        .capability = "codex-max",
        .selectable = true,
        .liveness = .live,
        .availability = availability,
        .account_id_hash = identity,
        .health_observed_at = 1_788_000_000,
    });
}

test "live shared election is order invariant where first-match mutates" {
    var forward = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer forward.deinit();
    try addTestCodexRoute(&forward, "codex:launch", "identity-launch", .available);
    try addTestCodexRoute(&forward, "codex:z-route", "identity-z", .available);
    try addTestCodexRoute(&forward, "codex:a-route", "identity-a", .available);

    var reverse = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer reverse.deinit();
    try addTestCodexRoute(&reverse, "codex:launch", "identity-launch", .available);
    try addTestCodexRoute(&reverse, "codex:a-route", "identity-a", .available);
    try addTestCodexRoute(&reverse, "codex:z-route", "identity-z", .available);

    const demand = try broker_model_demand.ModelDemand.init("gpt-5.3-codex");
    const elected_forward = try electSharedPoolRoute(
        std.testing.allocator,
        &forward,
        demand,
        "codex:launch",
        "codex:launch",
        1_788_000_001,
    );
    const elected_reverse = try electSharedPoolRoute(
        std.testing.allocator,
        &reverse,
        demand,
        "codex:launch",
        "codex:launch",
        1_788_000_001,
    );
    try std.testing.expectEqualStrings(elected_forward.id, elected_reverse.id);
    try std.testing.expect(!std.mem.eql(u8, "codex:launch", elected_forward.id));

    // Mutation control: the superseded AccountPool election changes solely
    // because input order changes, so replacing the shared reducer with it
    // makes the order-invariance assertion above fail.
    const excluded = [_][]const u8{"codex:launch"};
    const legacy_forward = try forward.elect(null, null, &excluded);
    const legacy_reverse = try reverse.elect(null, null, &excluded);
    try std.testing.expect(!std.mem.eql(u8, legacy_forward.id, legacy_reverse.id));
}

test "live handler route selection is order invariant where first-match mutates" {
    const allocator = std.testing.allocator;
    var forward = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer forward.deinit();
    try addTestCodexRoute(&forward, "codex:launch", "identity-launch", .available);
    try addTestCodexRoute(&forward, "codex:z-route", "identity-z", .available);
    try addTestCodexRoute(&forward, "codex:a-route", "identity-a", .available);

    var reverse = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer reverse.deinit();
    try addTestCodexRoute(&reverse, "codex:launch", "identity-launch", .available);
    try addTestCodexRoute(&reverse, "codex:a-route", "identity-a", .available);
    try addTestCodexRoute(&reverse, "codex:z-route", "identity-z", .available);

    const observed_now = std.time.timestamp();
    for (forward.accounts.items) |*account| account.health_observed_at = observed_now;
    for (reverse.accounts.items) |*account| account.health_observed_at = observed_now;
    forward.accounts.items[0].selectable = false;
    forward.accounts.items[0].availability = .quota_exhausted;
    forward.accounts.items[0].next_eligible_at = observed_now + 3600;
    reverse.accounts.items[0].selectable = false;
    reverse.accounts.items[0].availability = .quota_exhausted;
    reverse.accounts.items[0].next_eligible_at = observed_now + 3600;

    // Mutation control: a handler that bypasses `electSharedPoolRoute` for the
    // legacy first-match walk chooses a different alternate after pool reversal.
    const excluded = [_][]const u8{"codex:launch"};
    const legacy_forward = try forward.elect(null, null, &excluded);
    const legacy_reverse = try reverse.elect(null, null, &excluded);
    try std.testing.expectEqualStrings("codex:z-route", legacy_forward.id);
    try std.testing.expectEqualStrings("codex:a-route", legacy_reverse.id);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(state_root);
    var overrides = std.process.EnvMap.init(allocator);
    defer overrides.deinit();
    try overrides.put("OMUX_STATE_DIR", state_root);
    const previous_overrides = env.test_overrides;
    defer env.test_overrides = previous_overrides;
    env.test_overrides = &overrides;

    const SelectionMaterializer = struct {
        selected_account: ?[]const u8 = null,

        fn materialize(
            raw_state: *anyopaque,
            _: std.mem.Allocator,
            account_id: []const u8,
        ) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
            const state: *@This() = @ptrCast(@alignCast(raw_state));
            state.selected_account = account_id;
            return error.SecretUnavailable;
        }
    };
    var forward_selection = SelectionMaterializer{};
    var reverse_selection = SelectionMaterializer{};
    const forward_materializer: broker_types.CredentialMaterializer = .{
        .ctx = &forward_selection,
        .materialize_chatgpt = SelectionMaterializer.materialize,
    };
    const reverse_materializer: broker_types.CredentialMaterializer = .{
        .ctx = &reverse_selection,
        .materialize_chatgpt = SelectionMaterializer.materialize,
    };

    var forward_proxy = try Proxy.bind(
        allocator,
        &forward,
        forward_materializer,
        std.io.null_writer.any(),
    );
    defer forward_proxy.deinit();
    forward_proxy.launch_account = "codex:launch";

    var reverse_proxy = try Proxy.bind(
        allocator,
        &reverse,
        reverse_materializer,
        std.io.null_writer.any(),
    );
    defer reverse_proxy.deinit();
    reverse_proxy.launch_account = "codex:launch";

    const body = "{\"model\":\"gpt-5.3-codex\"}";
    const wire = try std.fmt.allocPrint(
        allocator,
        "POST /backend-api/codex/responses HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Content-Length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );
    defer allocator.free(wire);

    var forward_request = std.io.fixedBufferStream(wire);
    var forward_response = std.ArrayList(u8).init(allocator);
    defer forward_response.deinit();
    try forward_proxy.handleRequest(forward_request.reader(), forward_response.writer());

    var reverse_request = std.io.fixedBufferStream(wire);
    var reverse_response = std.ArrayList(u8).init(allocator);
    defer reverse_response.deinit();
    try reverse_proxy.handleRequest(reverse_request.reader(), reverse_response.writer());

    try std.testing.expect(forward_selection.selected_account != null);
    try std.testing.expect(reverse_selection.selected_account != null);
    try std.testing.expectEqualStrings(
        forward_selection.selected_account.?,
        reverse_selection.selected_account.?,
    );
    try std.testing.expect(!std.mem.eql(u8, "codex:launch", forward_selection.selected_account.?));
}

test "live election expires stale availability through route observation" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{
        .id = "codex:a-stale",
        .capability = "codex-max",
        .selectable = true,
        .liveness = .live,
        .availability = .available,
        .account_id_hash = "identity-stale",
        .health_observed_at = 100,
    });
    try pool.add(.{
        .id = "codex:z-fresh",
        .capability = "codex-max",
        .selectable = true,
        .liveness = .live,
        .availability = .available,
        .account_id_hash = "identity-fresh",
        .health_observed_at = 399,
    });

    const stale = broker_route_observation.project(.{
        .route = try broker_route_observation.RouteHandle.parse("route-stale"),
        .identity = broker_route_observation.IdentityEvidence.fromBorrowed("identity-stale"),
        .exact_model = (try broker_model_demand.ModelDemand.init("gpt-5.3-codex")).exact_model,
        .admission = .admitted,
        .reactive = poolReactiveObservation(pool.accounts.items[0]),
    }, 400);
    try std.testing.expectEqual(broker_route_observation.Readiness.unknown, stale.readiness);
    try std.testing.expectEqual(broker_route_observation.EvidenceProvenance.unobserved, stale.provenance);

    const demand = try broker_model_demand.ModelDemand.init("gpt-5.3-codex");
    const elected = try electSharedPoolRoute(
        std.testing.allocator,
        &pool,
        demand,
        null,
        null,
        400,
    );
    try std.testing.expectEqualStrings("codex:z-fresh", elected.id);
}

test "reactive exhaustion outranks advisory availability until reset" {
    const observation: broker_route_observation.RouteObservation = .{
        .route = try broker_route_observation.RouteHandle.parse("route-precedence"),
        .identity = broker_route_observation.IdentityEvidence.fromBorrowed("identity-precedence"),
        .exact_model = (try broker_model_demand.ModelDemand.init("gpt-5.3-codex")).exact_model,
        .admission = .admitted,
        .advisory = .{ .readiness = .available, .resets_at_s = 900 },
        .reactive = .{ .readiness = .exhausted, .resets_at_s = 500 },
    };
    const before_reset = broker_route_observation.project(observation, 400);
    try std.testing.expectEqual(broker_route_observation.Readiness.exhausted, before_reset.readiness);
    try std.testing.expectEqual(broker_route_observation.EvidenceProvenance.proven, before_reset.provenance);
    const after_reset = broker_route_observation.project(observation, 500);
    try std.testing.expectEqual(broker_route_observation.Readiness.available, after_reset.readiness);
    try std.testing.expectEqual(broker_route_observation.EvidenceProvenance.inferred, after_reset.provenance);
}

test "bootstrap traffic stays on the launch account even when pool order differs" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try addTestCodexRoute(&pool, "codex:first", "identity-first", .available);
    try addTestCodexRoute(&pool, "codex:launch", "identity-launch", .available);

    const elected = try launchPoolRoute(&pool, "codex:launch");
    try std.testing.expectEqualStrings("codex:launch", elected.id);

    const headers = HeaderList.init(std.testing.allocator);
    const bootstrap = Request{
        .method = "GET",
        .path = "/backend-api/models",
        .headers = headers,
        .body = &.{},
    };
    var live = LiveRequestState.init(bootstrap, mapSharedCoreRequest(bootstrap).demand);
    _ = try live.beginAttempt(elected.id);
    const transition = live.observe(.{
        .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream },
    });
    try std.testing.expectEqual(broker_attempt_policy.Decision.finish_original, transition.decision);
    try std.testing.expectError(error.AttemptNotAuthorized, live.beginAttempt("codex:first"));
}

test "live request state preserves byte-identical model and body across one distinct alternate" {
    const headers = HeaderList.init(std.testing.allocator);
    const request = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = headers,
        .body = "{\"model\":\"gpt-5.3-codex\",\"input\":[{\"role\":\"user\",\"content\":\"byte-exact\"}]}",
    };
    const mapped = mapSharedCoreRequest(request);
    var live = LiveRequestState.init(request, mapped.demand);

    const first = try live.beginAttempt("codex:account-a");
    try live.acceptMaterializedIdentity("oauth-account-a", false);
    try std.testing.expect(first.body.ptr == request.body.ptr);
    try std.testing.expectEqualStrings(request.body, first.body);
    try std.testing.expectEqualStrings("gpt-5.3-codex", first.demand.?.exact_model.bytes());

    const alternate = live.observe(.{
        .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream },
    });
    switch (alternate.decision) {
        .retry_alternate => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectError(error.AttemptNotAuthorized, live.beginAttempt("codex:account-a"));
    const second = try live.beginAttempt("codex:account-b");
    try live.acceptMaterializedIdentity("oauth-account-b", false);
    try std.testing.expect(second.body.ptr == request.body.ptr);
    try std.testing.expectEqualStrings(first.body, second.body);
    try std.testing.expectEqualStrings(
        first.demand.?.exact_model.bytes(),
        second.demand.?.exact_model.bytes(),
    );

    const terminal = live.observe(.{
        .upstream_status = .{ .status = 401, .delivery = .buffered_before_downstream },
    });
    try std.testing.expectEqual(broker_attempt_policy.Decision.finish_original, terminal.decision);
    try std.testing.expectError(error.AttemptBudgetExceeded, live.beginAttempt("codex:account-c"));
}

test "materialized identity fence rejects stale-hash alternate aliases" {
    const request = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = HeaderList.init(std.testing.allocator),
        .body = "{\"model\":\"gpt-5.3-codex\"}",
    };
    var live = LiveRequestState.init(request, mapSharedCoreRequest(request).demand);
    _ = try live.beginAttempt("codex:pool-hash-a");
    try live.acceptMaterializedIdentity("real-oauth-identity", false);
    const transition = live.observe(.{
        .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream },
    });
    switch (transition.decision) {
        .retry_alternate => {},
        else => return error.TestUnexpectedResult,
    }
    _ = try live.beginAttempt("codex:stale-distinct-pool-hash-b");
    try std.testing.expectError(
        error.SameMaterializedIdentityAlternate,
        live.acceptMaterializedIdentity("real-oauth-identity", false),
    );
}

test "live request state allows only confirmed-not-sent same-route retry" {
    const headers = HeaderList.init(std.testing.allocator);
    const request = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = headers,
        .body = "{\"model\":\"gpt-5.3-codex\",\"input\":\"same-route\"}",
    };
    var live = LiveRequestState.init(request, mapSharedCoreRequest(request).demand);
    _ = try live.beginAttempt("codex:account-a");
    const retry = live.observe(.{ .transport_failure = .confirmed_not_sent });
    try std.testing.expectEqual(broker_attempt_policy.Decision.retry_same_route, retry.decision);
    try std.testing.expectError(error.AttemptNotAuthorized, live.beginAttempt("codex:account-b"));
    const second = try live.beginAttempt("codex:account-a");
    try std.testing.expectEqualStrings(request.body, second.body);
    const terminal = live.observe(.{
        .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream },
    });
    try std.testing.expectEqual(broker_attempt_policy.Decision.finish_original, terminal.decision);
    try std.testing.expectError(error.AttemptBudgetExceeded, live.beginAttempt("codex:account-a"));
}

test "5xx ambiguity cancellation and started bodies cannot authorize another account" {
    const headers = HeaderList.init(std.testing.allocator);
    const request = Request{
        .method = "POST",
        .path = "/backend-api/codex/responses",
        .headers = headers,
        .body = "{\"model\":\"gpt-5.3-codex\"}",
    };
    const demand = mapSharedCoreRequest(request).demand;
    const outcomes = [_]broker_attempt_policy.Outcome{
        .{ .upstream_status = .{ .status = 503, .delivery = .buffered_before_downstream } },
        .{ .transport_failure = .ambiguous },
        .canceled,
        .{ .upstream_status = .{ .status = 429, .delivery = .downstream_started } },
    };
    for (outcomes) |outcome| {
        var live = LiveRequestState.init(request, demand);
        _ = try live.beginAttempt("codex:account-a");
        const transition = live.observe(outcome);
        try std.testing.expectEqual(broker_attempt_policy.Decision.finish_original, transition.decision);
        try std.testing.expectError(error.AttemptNotAuthorized, live.beginAttempt("codex:account-b"));
    }
}

test "quota evidence is recorded before shared alternate election" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try addTestCodexRoute(&pool, "codex:max-1", "identity-max-1", .available);
    try addTestCodexRoute(&pool, "codex:max-2", "identity-max-2", .available);

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    const now: i64 = 1_788_000_000;
    try applyClassificationWithStore(&pool, &store, "codex:max-1", .{
        .kind = .quota_exhausted,
        .resets_at = now + 900,
        .body_class = "usage_limit_reached",
    }, now, null);

    const recorded = store.accounts.get("codex:max-1") orelse {
        return error.ExpectedQuotaEvidence;
    };
    try std.testing.expectEqual(@as(?u16, 429), recorded.last_http_status);
    try std.testing.expectEqual(health_mod.ProbeEvidenceSource.broker_run_live, recorded.last_probe_source.?);
    try std.testing.expectEqual(@as(?u32, 900), recorded.last_probe_retry_after_s);
    try std.testing.expectEqual(health_mod.ProbeHintClass.quota_exhausted, recorded.last_probe_hint_class.?);
    try std.testing.expectEqual(core_types.MuxDecision.try_next_account, recorded.last_probe_decision.?);

    // The shared alternate sees the same in-process observation only after it
    // has been recorded and projected into the pool.
    const demand = try broker_model_demand.ModelDemand.init("gpt-5.3-codex");
    const elected = try electSharedPoolRoute(
        std.testing.allocator,
        &pool,
        demand,
        "codex:max-1",
        "codex:max-1",
        now,
    );
    try std.testing.expectEqualStrings("codex:max-2", elected.id);
}

test "provider 5xx is pass-through telemetry and never account readiness" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try addTestCodexRoute(&pool, "codex:max-1", "identity-max-1", .available);
    try addTestCodexRoute(&pool, "codex:max-2", "identity-max-2", .available);

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    const now: i64 = 1_788_000_000;
    try applyClassificationWithStore(&pool, &store, "codex:max-1", .{
        .kind = .provider_5xx,
    }, now, "codex-max");

    try std.testing.expect(store.accounts.get("codex:max-1#codex-max") == null);

    try std.testing.expect(pool.accounts.items[0].selectable);
    try std.testing.expectEqual(account_pool_mod.Availability.available, pool.accounts.items[0].availability);
    const demand = try broker_model_demand.ModelDemand.init("gpt-5.3-codex");
    const elected = try electSharedPoolRoute(
        std.testing.allocator,
        &pool,
        demand,
        "codex:max-1",
        null,
        now,
    );
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
}

test "shared proxy election consumes refreshed pool state" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{
        .id = "codex:max-1",
        .selectable = false,
        .liveness = .live,
        .availability = .quota_exhausted,
        .next_eligible_at = 1_788_000_000,
        .capability = "codex-max",
        .account_id_hash = "identity-max-1",
        .health_observed_at = 1_787_999_000,
    });
    try pool.add(.{
        .id = "codex:max-2",
        .selectable = false,
        .liveness = .dead,
        .availability = .unknown,
        .capability = "codex-max",
        .account_id_hash = "identity-max-2",
        .health_observed_at = 1_787_999_000,
    });

    pool.refreshTimeBased(1_788_000_060);
    const demand = try broker_model_demand.ModelDemand.init("gpt-5.3-codex");
    const elected = try electSharedPoolRoute(
        std.testing.allocator,
        &pool,
        demand,
        "codex:max-1",
        null,
        1_788_000_060,
    );
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expect(pool.accounts.items[0].selectable);
    try std.testing.expectEqual(account_pool_mod.Availability.available, pool.accounts.items[0].availability);
    try std.testing.expect(pool.accounts.items[0].next_eligible_at == null);
}

test "successful managed proxy turn records capability route health" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    try applyClassificationWithStore(&pool, &store, "codex:max-1", .{
        .kind = .ok,
    }, 1_788_000_000, "codex-max");

    const recorded = store.accounts.get("codex:max-1#codex-max") orelse {
        return error.ExpectedSuccessEvidence;
    };
    try std.testing.expectEqual(@as(?u16, 200), recorded.last_http_status);
    try std.testing.expectEqual(health_mod.ProbeEvidenceSource.broker_run_live, recorded.last_probe_source.?);
    try std.testing.expectEqual(health_mod.ProbeHintClass.none, recorded.last_probe_hint_class.?);
    try std.testing.expectEqual(core_types.MuxDecision.use_this, recorded.last_probe_decision.?);
    switch (recorded.liveness) {
        .live => |live| try std.testing.expectEqual(core_types.Availability.available, live.availability),
        else => return error.ExpectedLiveHealth,
    }
}

test "managed proxy records route health under the account capability" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{
        .id = "codex:max-1",
        .capability = "codex-mini",
        .selectable = true,
        .liveness = .live,
        .availability = .available,
    });

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    const account = pool.accounts.items[0];
    try applyClassificationWithStore(&pool, &store, account.id, .{
        .kind = .quota_exhausted,
        .resets_at = 1_788_000_900,
    }, 1_788_000_000, account.capability);

    try std.testing.expect(store.accounts.get("codex:max-1#codex-max") == null);
    const recorded = store.accounts.get("codex:max-1#codex-mini") orelse {
        return error.ExpectedFallbackCapabilityEvidence;
    };
    try std.testing.expectEqual(@as(?u16, 429), recorded.last_http_status);
    try std.testing.expectEqual(health_mod.ProbeHintClass.quota_exhausted, recorded.last_probe_hint_class.?);
    try std.testing.expectEqual(core_types.MuxDecision.try_next_account, recorded.last_probe_decision.?);
}

test "parseRequest reads start line + headers + content-length body" {
    const wire =
        "POST /backend-api/codex/responses HTTP/1.1\r\n" ++
        "Host: chatgpt.com\r\n" ++
        "Authorization: Bearer XYZ\r\n" ++
        "Content-Length: 5\r\n" ++
        "X-Codex-Turn-State: turn-abc\r\n" ++
        "\r\n" ++
        "hello";
    var fbs = std.io.fixedBufferStream(wire);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var reservation = ReplayReservation{};
    const req = try parseRequest(a, fbs.reader(), &reservation);
    defer reservation.release(req.reserved_bytes);
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/backend-api/codex/responses", req.path);
    try std.testing.expectEqualStrings("Bearer XYZ", req.headers.find("Authorization").?);
    try std.testing.expectEqualStrings("turn-abc", req.headers.find("x-codex-turn-state").?);
    try std.testing.expectEqualStrings("hello", req.body);
    try std.testing.expect(req.replayable());
    try std.testing.expectEqual(@as(usize, 5), req.reserved_bytes);
}

test "replay reservation enforces request sidecar and overflow bounds" {
    try std.testing.expectEqual(@as(usize, 32 * 1024 * 1024), REPLAY_REQUEST_LIMIT_BYTES);
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), REPLAY_SIDECAR_LIMIT_BYTES);
    try std.testing.expectEqual(@as(usize, 256 * 1024 * 1024), REPLAY_HOST_LIMIT_BYTES);

    var reservation = ReplayReservation{};
    try std.testing.expect(reservation.reserve(REPLAY_REQUEST_LIMIT_BYTES));
    try std.testing.expect(reservation.reserve(REPLAY_REQUEST_LIMIT_BYTES));
    try std.testing.expect(!reservation.reserve(1));
    reservation.release(REPLAY_REQUEST_LIMIT_BYTES);
    reservation.release(REPLAY_REQUEST_LIMIT_BYTES);
    try std.testing.expectEqual(@as(usize, 0), reservation.outstanding());

    reservation.budget_bytes = std.math.maxInt(usize);
    try std.testing.expect(reservation.reserve(std.math.maxInt(usize)));
    try std.testing.expect(!reservation.reserve(1));
    reservation.release(std.math.maxInt(usize));
}

test "oversize and unreserved content-length bodies remain unread stream-once" {
    const cases = [_]struct { content_length: usize, budget: usize }{
        .{ .content_length = REPLAY_REQUEST_LIMIT_BYTES + 1, .budget = REPLAY_SIDECAR_LIMIT_BYTES },
        .{ .content_length = 1, .budget = 0 },
    };
    for (cases) |case| {
        var wire_storage: [256]u8 = undefined;
        const wire = try std.fmt.bufPrint(
            &wire_storage,
            "POST /backend-api/codex/responses HTTP/1.1\r\nContent-Length: {d}\r\n\r\nx",
            .{case.content_length},
        );
        var fbs = std.io.fixedBufferStream(wire);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var reservation = ReplayReservation{ .budget_bytes = case.budget };
        const req = try parseRequest(arena.allocator(), fbs.reader(), &reservation);
        switch (req.body_mode) {
            .stream_content_length => |length| try std.testing.expectEqual(case.content_length, length),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expect(!req.replayable());
        try std.testing.expectEqual(@as(usize, 0), req.reserved_bytes);
        try std.testing.expectEqual(@as(u8, 'x'), try fbs.reader().readByte());
        try std.testing.expectEqual(@as(usize, 0), reservation.outstanding());
    }
}

test "parseRequest leaves chunked body bounded and stream-once" {
    const wire =
        "POST /backend-api/codex/responses HTTP/1.1\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "6\r\n world\r\n" ++
        "0\r\n\r\n";
    var fbs = std.io.fixedBufferStream(wire);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var reservation = ReplayReservation{};
    const req = try parseRequest(arena.allocator(), fbs.reader(), &reservation);
    try std.testing.expectEqual(RequestBodyMode.stream_chunked, req.body_mode);
    try std.testing.expectEqual(@as(usize, 0), req.body.len);
    try std.testing.expectEqual(@as(usize, 0), reservation.outstanding());
    var sink_storage: [64]u8 = undefined;
    var sink = std.io.fixedBufferStream(&sink_storage);
    try copyChunkedRequestBody(sink.writer(), fbs.reader());
    try std.testing.expectEqualStrings("hello world", sink.getWritten());
}

test "parseRequest rejects malformed start line" {
    const wire = "BAD\r\n\r\n";
    var fbs = std.io.fixedBufferStream(wire);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var reservation = ReplayReservation{};
    try std.testing.expectError(error.BadRequestLine, parseRequest(arena.allocator(), fbs.reader(), &reservation));
}

test "writeStatus writes a complete HTTP/1.1 status response" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeStatus(fbs.writer(), 503, "No Account Selectable");
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 503 No Account Selectable\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "Content-Length: 0\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "\r\n\r\n"));
}

test "writeNoAccountSelectableResponse emits parseable preflight JSON" {
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const rejections = [_]CandidateRejection{
        .{ .account = "codex:default", .state = .quota_exhausted, .reason = "quota_exhausted" },
        .{ .account = "codex:max-2", .state = .auth_failed, .reason = "auth_unauthorized" },
    };

    try writeNoAccountSelectableResponse(std.testing.allocator, fbs.writer(), "codex-max", &rejections);
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 503 Service Unavailable\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "Content-Type: application/json\r\n") != null);
    const body_start = std.mem.indexOf(u8, out, "\r\n\r\n").?;
    const body = out[body_start + 4 ..];
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    const error_obj = parsed.value.object.get("error").?.object;
    try std.testing.expectEqual(@as(usize, 1), error_obj.get("agent_safe_next_actions").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 1), error_obj.get("spend_confirmed_next_actions").?.array.items.len);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"type\":\"oauth_mux_no_account_selectable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"preflight_command\":\"oauth-mux codex preflight --profile codex-max --json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"spends_provider_calls\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"rejection_summary\":{\"total\":2,\"auth_failed\":1,\"quota_exhausted\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"agent_safe_next_actions\":[{\"kind\":\"codex_preflight\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"command\":\"oauth-mux codex preflight --profile codex-max --json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"agent_safe\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"spend_confirmed_next_actions\":[{\"kind\":\"stay_afloat_execute\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"command\":\"oauth-mux stay-afloat --once --execute --profile codex-max --json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"may_spend_provider_calls\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mutates_route_health\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"account\":\"codex:default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"quota_exhausted\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "]}}\n"));
}

test "writeProviderUnavailableResponse emits provider-degraded JSON" {
    var buf: [1536]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const rejections = [_]CandidateRejection{
        .{ .account = "codex:max-1", .state = .provider_degraded, .reason = "ConnectionResetByPeer" },
    };

    try writeProviderUnavailableResponse(
        std.testing.allocator,
        fbs.writer(),
        "codex:max-1",
        "ConnectionResetByPeer",
        &rejections,
    );
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 503 Service Unavailable\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "\"type\":\"oauth_mux_provider_unavailable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"transport_error\":\"ConnectionResetByPeer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"provider_degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "credential-dead") != null);
}

test "HeaderList.remove drops matching headers, case-insensitive" {
    var hl = HeaderList.init(std.testing.allocator);
    defer hl.items.deinit(std.testing.allocator);
    try hl.append("X-Codex-Turn-State", "abc");
    try hl.append("X-Foo", "1");
    try hl.append("x-codex-turn-state", "def"); // duplicate, different case

    hl.remove("X-Codex-Turn-State");
    try std.testing.expect(hl.find("x-codex-turn-state") == null);
    try std.testing.expectEqualStrings("1", hl.find("X-Foo").?);
    try std.testing.expectEqual(@as(usize, 1), hl.items.items.len);
}

test "HeaderList.set replaces existing values, case-insensitive" {
    var hl = HeaderList.init(std.testing.allocator);
    defer hl.items.deinit(std.testing.allocator);
    try hl.append("Authorization", "Bearer A");
    try hl.append("X-Foo", "1");
    try hl.set("authorization", "Bearer B");

    try std.testing.expectEqualStrings("Bearer B", hl.find("Authorization").?);
    try std.testing.expectEqualStrings("1", hl.find("X-Foo").?);
    try std.testing.expectEqual(@as(usize, 2), hl.items.items.len);
}

test "copyForwardingHeaders property: 50 random header sets preserve load-bearing 8" {
    // PBT: regardless of what other headers are mixed in, the eight
    // load-bearing headers (User-Agent, originator,
    // x-codex-installation-id, x-codex-turn-state, x-codex-turn-metadata,
    // OpenAI-Beta, traceparent, tracestate) MUST always survive
    // copyForwardingHeaders. The three substituted (Authorization,
    // ChatGPT-Account-ID, X-OpenAI-Fedramp), proxy-owned framing
    // headers, and the hop-by-hop set MUST always be dropped. Catches
    // the regression where someone adds a new "drop" rule that
    // accidentally matches a load-bearing header by case-insensitive
    // prefix.
    var prng = std.Random.DefaultPrng.init(0xBEEF1234);
    const r = prng.random();

    const load_bearing = [_][]const u8{
        "User-Agent",
        "originator",
        "x-codex-installation-id",
        "x-codex-turn-state",
        "x-codex-turn-metadata",
        "OpenAI-Beta",
        "traceparent",
        "tracestate",
    };
    const must_drop = [_][]const u8{
        "Authorization",
        "ChatGPT-Account-ID",
        "X-OpenAI-Fedramp",
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
        "Host",
        "Keep-Alive",
        "Upgrade",
    };
    const noise = [_][]const u8{ "X-Random-1", "X-Foo", "Accept", "Cookie" };

    var iter: usize = 0;
    while (iter < 50) : (iter += 1) {
        var in = HeaderList.init(std.testing.allocator);
        defer in.items.deinit(std.testing.allocator);

        // Always include all 8 load-bearing.
        for (load_bearing) |h| try in.append(h, "x");
        // Always include all must-drop headers.
        for (must_drop) |h| try in.append(h, "y");
        // Add 0..3 noise headers.
        const noise_count = r.uintLessThan(usize, noise.len + 1);
        var n: usize = 0;
        while (n < noise_count) : (n += 1) {
            try in.append(noise[r.uintLessThan(usize, noise.len)], "n");
        }

        var out = HeaderList.init(std.testing.allocator);
        defer out.items.deinit(std.testing.allocator);
        try copyForwardingHeaders(&in, &out);

        // Property A: every load-bearing header is preserved.
        for (load_bearing) |h| {
            if (out.find(h) == null) {
                std.debug.print("iter {d}: load-bearing header {s} was dropped\n", .{ iter, h });
                return error.LoadBearingDropped;
            }
        }
        // Property B: every must-drop header is gone.
        for (must_drop) |h| {
            if (out.find(h) != null) {
                std.debug.print("iter {d}: must-drop header {s} survived\n", .{ iter, h });
                return error.MustDropSurvived;
            }
        }
    }
}

test "copyForwardingHeaders preserves the load-bearing 8 + drops hop-by-hop" {
    var in = HeaderList.init(std.testing.allocator);
    defer in.items.deinit(std.testing.allocator);
    try in.append("User-Agent", "codex/1");
    try in.append("originator", "codex_cli_rs");
    try in.append("x-codex-installation-id", "iid");
    try in.append("x-codex-turn-state", "turn");
    try in.append("x-codex-turn-metadata", "meta");
    try in.append("OpenAI-Beta", "responses_websockets=2026-02-06");
    try in.append("traceparent", "tp");
    try in.append("tracestate", "ts");
    try in.append("Authorization", "Bearer leaked");
    try in.append("ChatGPT-Account-ID", "leaked");
    try in.append("X-OpenAI-Fedramp", "true");
    try in.append("Connection", "keep-alive");
    try in.append("Content-Length", "123");
    try in.append("Transfer-Encoding", "chunked");
    try in.append("Host", "example");

    var out = HeaderList.init(std.testing.allocator);
    defer out.items.deinit(std.testing.allocator);
    try copyForwardingHeaders(&in, &out);

    // 8 forward-unchanged survive
    try std.testing.expect(out.find("User-Agent") != null);
    try std.testing.expect(out.find("originator") != null);
    try std.testing.expect(out.find("x-codex-installation-id") != null);
    try std.testing.expect(out.find("x-codex-turn-state") != null);
    try std.testing.expect(out.find("x-codex-turn-metadata") != null);
    try std.testing.expect(out.find("OpenAI-Beta") != null);
    try std.testing.expect(out.find("traceparent") != null);
    try std.testing.expect(out.find("tracestate") != null);

    // 3 substituted-elsewhere are dropped here (proxy adds them back)
    try std.testing.expect(out.find("Authorization") == null);
    try std.testing.expect(out.find("ChatGPT-Account-ID") == null);
    try std.testing.expect(out.find("X-OpenAI-Fedramp") == null);

    // hop-by-hop are dropped
    try std.testing.expect(out.find("Connection") == null);
    try std.testing.expect(out.find("Content-Length") == null);
    try std.testing.expect(out.find("Transfer-Encoding") == null);
    try std.testing.expect(out.find("Host") == null);
}

test "AuthFailureTracker reports unrecovered response 401" {
    var tracker = AuthFailureTracker{};
    defer tracker.deinit(std.testing.allocator);
    tracker.observe(
        std.testing.allocator,
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .auth_unauthorized },
    );

    const observation = tracker.observation();
    try std.testing.expect(observation.unrecovered());
    try std.testing.expectEqualStrings("codex:max-1", observation.account.?);
    try std.testing.expectEqual(@as(usize, 1), observation.auth_unauthorized_turns);
    try std.testing.expectEqual(@as(usize, 1), observation.responses_401_turns);
}

test "AuthFailureTracker treats same-account ok as recovery" {
    var tracker = AuthFailureTracker{};
    defer tracker.deinit(std.testing.allocator);
    tracker.observe(
        std.testing.allocator,
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .auth_unauthorized },
    );
    tracker.observe(
        std.testing.allocator,
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .ok },
    );

    const observation = tracker.observation();
    try std.testing.expect(!observation.unrecovered());
    try std.testing.expect(observation.recovered_after_401);
}

test "AuthFailureTracker does not treat another account ok as recovery" {
    var tracker = AuthFailureTracker{};
    defer tracker.deinit(std.testing.allocator);
    tracker.observe(
        std.testing.allocator,
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .auth_unauthorized },
    );
    tracker.observe(
        std.testing.allocator,
        "codex:max-2",
        "/backend-api/codex/responses",
        .{ .kind = .ok },
    );

    const observation = tracker.observation();
    try std.testing.expect(observation.unrecovered());
    try std.testing.expect(!observation.recovered_after_401);
}

test "AuthFailureTracker keeps unrecovered auth failures per account" {
    var tracker = AuthFailureTracker{};
    defer tracker.deinit(std.testing.allocator);

    tracker.observe(std.testing.allocator, "codex:max-1", "/backend-api/codex/responses", .{ .kind = .auth_unauthorized });
    tracker.observe(std.testing.allocator, "codex:max-2", "/backend-api/codex/responses", .{ .kind = .auth_unauthorized });
    tracker.observe(std.testing.allocator, "codex:max-3", "/backend-api/codex/responses", .{ .kind = .ok });

    const observation = tracker.observation();
    try std.testing.expect(observation.unrecovered());
    try std.testing.expectEqual(@as(usize, 2), observation.accounts.len);
    try std.testing.expectEqual(@as(usize, 2), observation.auth_unauthorized_turns);
    try std.testing.expectEqualStrings("codex:max-1", observation.accounts[0].account);
    try std.testing.expectEqualStrings("codex:max-2", observation.accounts[1].account);
}

test "appendPoolRejections emits complete terminal candidate vector" {
    var pool = account_pool_mod.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = false, .liveness = .live, .availability = .quota_exhausted });
    try pool.add(.{ .id = "codex:max-2", .selectable = false, .liveness = .dead, .availability = .available });
    try pool.add(.{ .id = "codex:max-3", .selectable = true, .liveness = .live, .availability = .rate_limited });
    try pool.add(.{ .id = "codex:max-4", .selectable = false, .liveness = .degraded, .availability = .unknown });
    try pool.add(.{ .id = "codex:max-5", .selectable = true, .liveness = .live, .availability = .available });

    const attempted = [_][]const u8{ "codex:max-1", "codex:max-5" };

    var rejections = std.ArrayListUnmanaged(CandidateRejection){};
    defer rejections.deinit(std.testing.allocator);
    try appendRejection(std.testing.allocator, &rejections, "codex:max-1", .quota_exhausted, "quota_exhausted");
    try appendPoolRejections(std.testing.allocator, &pool, &attempted, &rejections);

    try std.testing.expectEqual(@as(usize, 5), rejections.items.len);
    try std.testing.expectEqual(RouteState.quota_exhausted, rejections.items[0].state);
    try std.testing.expectEqual(RouteState.auth_failed, rejections.items[1].state);
    try std.testing.expectEqual(RouteState.rate_limited, rejections.items[2].state);
    try std.testing.expectEqual(RouteState.provider_degraded, rejections.items[3].state);
    try std.testing.expectEqual(RouteState.credential_unavailable, rejections.items[4].state);
    try std.testing.expectEqualStrings("attempted_without_success", rejections.items[4].reason);
}
