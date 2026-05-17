//! Localhost HTTP/1.1 reverse proxy for Codex's
//! `/backend-api/codex/...` endpoints.
//!
//! Anchor: docs/spec/codex-adapter-contract-2026-05-03.md §4 (Wire-Layer
//! Proxy Spec) + §3 (401-vs-429 Handling Matrix).
//!
//! The proxy is the load-bearing piece that lets account swap happen
//! without restarting the unmodified `codex` child process. It sits at
//! 127.0.0.1:<dynamic-port> with codex's generated
//! `model_provider = "oauth_mux_openai"` / custom model provider block
//! pointed at it (via a generated config.toml in the per-session
//! CODEX_HOME). Codex 0.128+ rejects overriding the reserved built-in
//! `openai` provider id, so the adapter must select a custom provider id.
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
//!   4. Send to chatgpt.com over TLS.
//!   5. Classify the response (200 / 401 / 429+usage_limit_reached /
//!      429+usage_not_included / other-429 / 5xx).
//!   6. Report quota/observe to the broker pool. On
//!      quota_exhausted, mark the current account exhausted, elect a
//!      fallback immediately, drop the sticky turn-state header, and retry
//!      the same request before writing the response to codex. If no fallback
//!      is selectable, return the buffered failure.
//!      On auth_unauthorized, try the same fallback shape before Codex sees
//!      the 401. If fallback is unavailable, return the buffered 401 so Codex
//!      can still run its native refresh loop.
//!      On provider_5xx, try another account before Codex sees the provider
//!      outage. If no fallback is selectable, return the provider failure as
//!      provider-degraded evidence rather than marking credentials dead.
//!   7. Stream the final response body verbatim back to codex (SSE works
//!      because chunked-transfer is forwarded byte-for-byte).
//!
//! Phase 2 scope (honestly labelled limitations):
//!   - Synchronous, single-connection-at-a-time (codex sends one
//!     request per turn). No request pipelining.
//!   - **Streaming for 200/3xx; buffered for 4xx/5xx.** SSE turns
//!     stream byte-for-byte from upstream to codex via Connection:close
//!     framing — the TUI animation moves in real time. Error responses are
//!     small and need a retry decision before any bytes reach Codex, so they
//!     stay buffered (with a 64 KiB cap).
//!   - No WebSocket upgrade support; if codex requests a WS upgrade
//!     we propagate the upstream's response (which on `chatgpt.com`
//!     is HTTP 426 / falls back to chunked). Phase 2.2 adds WS.
//!   - Same-turn retry is attempted for buffered 429 `usage_limit_reached`
//!     responses before any bytes are written to codex. The retry drops
//!     `x-codex-turn-state` because that token is likely tied to the previous
//!     account's server-side state. Synthetic tests prove the structure; live
//!     provider-originated quota proof is still required before promoting the
//!     runtime claim level.

const std = @import("std");
const broker_types = @import("../../broker/types.zig");
const account_pool_mod = @import("../../broker/account_pool.zig");
const health_mod = @import("../../health.zig");
const trace = @import("../../trace.zig");
const core_types = @import("../../types.zig");

const DEFAULT_UPSTREAM_HOST = "chatgpt.com";
const DEFAULT_UPSTREAM_SCHEME = "https";
const UPSTREAM_BASE_PATH = "/backend-api/codex";

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
        try self.handleConnection(conn);
    }

    fn handleConnection(self: *Proxy, conn: std.net.Server.Connection) !void {
        const reader = conn.stream.reader();
        const writer = conn.stream.writer();

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        // ── 1. Parse inbound request ────────────────────────────
        const req = parseRequest(a, reader) catch |err| {
            // EndOfStream on accept is the shutdown tickle from the
            // adapter — silently bail without writing a response.
            if (err == error.EndOfStream) return;
            self.logEvent("proxy_request_parse_error", .{ .err = @errorName(err) });
            try writeStatus(writer, 400, "Bad Request");
            return;
        };

        var attempted = std.ArrayListUnmanaged([]const u8){};
        var rejections = std.ArrayListUnmanaged(CandidateRejection){};
        var final_account: ?[]const u8 = null;
        var pending_buffered: ?BufferedResponse = null;
        var pending_failure_kind: ?broker_types.QuotaKind = null;
        var pending_failure_account: ?[]const u8 = null;
        var pending_transport_error: ?[]const u8 = null;
        var prior_attempt_account: ?[]const u8 = null;

        while (true) {
            // ── 2. Elect an account ─────────────────────────────
            const elected = self.pool.elect(self.profile, null, attempted.items) catch |err| {
                appendPoolRejections(a, self.pool, &attempted, &rejections) catch {};
                const pending_kind = pending_failure_kind;
                if (pending_kind != null and pending_kind.? == .auth_unauthorized and pending_buffered != null) {
                    self.logEvent("proxy_auth_retry_unavailable", .{
                        .from = pending_failure_account orelse "",
                        .err = @errorName(err),
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                    });
                    self.logEvent("proxy_observed_401_codex_handles", .{
                        .account = pending_failure_account orelse "",
                    });
                    try writeBufferedStoredResponse(writer, pending_buffered.?);
                } else if (pending_kind != null and pending_kind.? == .provider_5xx) {
                    self.logEvent("proxy_provider_retry_unavailable", .{
                        .from = pending_failure_account orelse "",
                        .err = pending_transport_error orelse @errorName(err),
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                        .delivered_to_codex = true,
                    });
                    self.traceProviderUnavailable(req, pending_failure_account orelse "", pending_transport_error orelse @errorName(err), rejections.items);
                    if (pending_buffered) |buffered| {
                        try writeBufferedStoredResponse(writer, buffered);
                    } else {
                        try writeProviderUnavailableResponse(
                            a,
                            writer,
                            pending_failure_account orelse "",
                            pending_transport_error orelse @errorName(err),
                            rejections.items,
                        );
                    }
                } else if (pending_kind != null and (pending_kind.? == .quota_exhausted or pending_kind.? == .rate_limited)) {
                    self.logEvent("proxy_same_turn_retry_unavailable", .{
                        .from = pending_failure_account orelse "",
                        .err = @errorName(err),
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                    });
                    self.logEvent("quota_handoff_failed_no_account_selectable", .{
                        .from = pending_failure_account orelse "",
                        .reason = @tagName(pending_kind.?),
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                        .user_visible_failure_likely = true,
                    });
                    self.logEvent("proxy_no_account_selectable", .{
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                    });
                    self.traceNoAccountSelectable(req, pending_kind, attempted.items, rejections.items);
                    try writeNoAccountSelectableResponse(a, writer, self.profile, rejections.items);
                } else {
                    self.logEvent("proxy_no_account_selectable", .{
                        .attempted = attempted.items,
                        .rejections = rejections.items,
                    });
                    self.traceNoAccountSelectable(req, pending_kind, attempted.items, rejections.items);
                    try writeNoAccountSelectableResponse(a, writer, self.profile, rejections.items);
                }
                return;
            };
            appendAttempt(a, &attempted, elected.id) catch {};

            var tokens = self.materializer.materialize_chatgpt(
                self.materializer.ctx,
                a,
                elected.id,
            ) catch |err| {
                appendRejection(a, &rejections, elected.id, .credential_unavailable, @errorName(err)) catch {};
                self.logEvent("proxy_materialize_failed", .{ .account = elected.id, .err = @errorName(err) });
                self.pool.markUnauthorized(elected.id) catch {};
                self.recordDurableRouteState(elected.id, .credential_unavailable, 0, null);
                pending_failure_kind = null;
                pending_failure_account = elected.id;
                pending_transport_error = null;
                prior_attempt_account = elected.id;
                continue;
            };
            // tokens lives in arena `a`; deinit-on-arena-drop.
            _ = &tokens;

            // ── 3. Build outbound request with substituted headers ──
            const retrying_inside_turn = prior_attempt_account != null;
            var out_headers = HeaderList.init(a);
            const preserved_child_auth = try buildOutboundHeaders(a, &req, &out_headers, tokens, retrying_inside_turn);
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
                self.logRetryEvent(prior_attempt_account.?, elected.id, pending_failure_kind orelse .quota_exhausted);
                self.synthetic_swap_seen = true;
            }

            // Inbound body length is preserved; chunked → chunked, fixed →
            // fixed. We don't transform the body.

            // ── 4. Forward to upstream + stream/buffer response ────
            const status_and_class = forwardAndStream(a, req, out_headers, writer) catch |err| {
                appendRejection(a, &rejections, elected.id, .provider_degraded, @errorName(err)) catch {};
                self.logEvent("proxy_upstream_failed", .{ .account = elected.id, .err = @errorName(err) });
                self.traceUpstreamFailure(req, elected.id, @errorName(err));
                self.recordDurableRouteState(elected.id, .provider_degraded, 503, 60);
                pending_failure_kind = .provider_5xx;
                pending_failure_account = elected.id;
                pending_transport_error = @errorName(err);
                prior_attempt_account = elected.id;
                continue;
            };

            // ── 5. Apply classification + log ──────────────────────
            self.applyClassification(elected.id, status_and_class.classification) catch |err| {
                self.logEvent("proxy_apply_classification_failed", .{ .account = elected.id, .err = @errorName(err) });
            };

            const should_retry = shouldRetrySameTurn(status_and_class.classification.kind);
            self.logProxyTurn(elected.id, req, status_and_class, !should_retry);
            final_account = elected.id;

            if (!should_retry) {
                if (status_and_class.buffered_response) |buffered| {
                    try writeBufferedStoredResponse(writer, buffered);
                }
                break;
            }

            const state = routeStateFromClassification(status_and_class.classification.kind);
            appendRejection(a, &rejections, elected.id, state, @tagName(status_and_class.classification.kind)) catch {};
            pending_buffered = status_and_class.buffered_response;
            pending_failure_kind = status_and_class.classification.kind;
            pending_failure_account = elected.id;
            pending_transport_error = null;
            prior_attempt_account = elected.id;
            continue;
        }

        // Track previous_account for next-request swap detection.
        if (final_account) |account| {
            if (self.previous_account) |old| self.allocator.free(old);
            self.previous_account = self.allocator.dupe(u8, account) catch null;
        }
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
        c: Classification,
    ) !void {
        const now_unix = std.time.timestamp();
        self.recordDurableClassification(account_id, c, now_unix);
        switch (c.kind) {
            .ok => self.pool.refreshTimeBased(now_unix),
            .quota_exhausted => {
                const until = c.resets_at orelse (now_unix + 7 * 24 * 60 * 60);
                try self.pool.markQuotaExhausted(account_id, until);
            },
            .rate_limited => {
                const until = c.resets_at orelse (now_unix + 60);
                try self.pool.markRateLimited(account_id, until);
            },
            .auth_unauthorized => try self.pool.markUnauthorized(account_id),
            .tier_insufficient, .provider_5xx => {
                // Recorded for telemetry only; no pool mutation.
            },
        }
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

        if (reason == .provider_5xx) {
            self.logEvent("proxy_provider_same_turn_retry", .{
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

    fn recordDurableClassification(
        self: *Proxy,
        account_id: []const u8,
        c: Classification,
        now_unix: i64,
    ) void {
        if (c.kind == .ok) return;
        const state = routeStateFromClassification(c.kind);
        const status: u16 = switch (c.kind) {
            .ok => 200,
            .auth_unauthorized => 401,
            .quota_exhausted, .rate_limited, .tier_insufficient => 429,
            .provider_5xx => 500,
        };
        const retry_after_s = retryAfterSeconds(now_unix, c.resets_at, c.kind);
        self.recordDurableRouteState(account_id, state, status, retry_after_s);
    }

    fn recordDurableRouteState(
        self: *Proxy,
        account_id: []const u8,
        state: RouteState,
        status: u16,
        retry_after_s: ?u32,
    ) void {
        _ = self;
        const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return;
        if (colon == 0 or colon + 1 >= account_id.len) return;
        const provider = account_id[0..colon];
        const account = account_id[colon + 1 ..];
        const key = health_mod.accountKey(provider, account);

        var store = health_mod.HealthStore.load(std.heap.page_allocator, .{});
        defer store.deinit();

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

        store.recordHttpClassification(key.slice(), status, classification);
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
        store.persist();
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
    ) void {
        trace.append(self.allocator, "codex.proxy.provider_unavailable", .warn, &.{
            trace.string("provider", "codex"),
            trace.string("account_label", accountLabel(account_id)),
            trace.string("method", req.method),
            trace.string("path_kind", pathKind(req.path)),
            trace.string("transport_error", err),
            trace.uint("rejections_total", @intCast(rejections.len)),
            trace.boolean("delivered_to_codex", true),
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

fn shouldRetrySameTurn(kind: broker_types.QuotaKind) bool {
    return switch (kind) {
        .quota_exhausted, .rate_limited, .auth_unauthorized, .provider_5xx => true,
        .ok, .tier_insufficient => false,
    };
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
        else => null,
    };
    if (reset <= now_unix) return 0;
    const delta = reset - now_unix;
    return @intCast(@min(delta, std.math.maxInt(u32)));
}

fn containsAccount(items: []const []const u8, account_id: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, account_id)) return true;
    }
    return false;
}

fn appendAttempt(
    allocator: std.mem.Allocator,
    attempted: *std.ArrayListUnmanaged([]const u8),
    account_id: []const u8,
) !void {
    if (containsAccount(attempted.items, account_id)) return;
    try attempted.append(allocator, account_id);
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
    attempted: *const std.ArrayListUnmanaged([]const u8),
    rejections: *std.ArrayListUnmanaged(CandidateRejection),
) !void {
    for (pool.accounts.items) |account| {
        if (rejectionIndex(rejections.items, account.id) != null) continue;
        if (containsAccount(attempted.items, account.id)) {
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

const Request = struct {
    method: []const u8,
    path: []const u8,
    headers: HeaderList,
    body: []const u8,
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

fn parseRequest(a: std.mem.Allocator, reader: anytype) !Request {
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

    // Body: Content-Length only; chunked-transfer-decoded would require
    // unchunking which we instead pass through unchanged at forward
    // time. For the inbound side we read Content-Length bytes if present.
    var body: []const u8 = &.{};
    if (headers.find("content-length")) |cl_str| {
        const cl = try std.fmt.parseInt(usize, cl_str, 10);
        const body_buf = try a.alloc(u8, cl);
        try reader.readNoEof(body_buf);
        body = body_buf;
    } else if (headers.find("transfer-encoding")) |te| {
        if (asciiEqlIgnoreCase(te, "chunked")) {
            body = try readChunked(a, reader);
        }
    }

    return Request{
        .method = try a.dupe(u8, method),
        .path = try a.dupe(u8, path),
        .headers = headers,
        .body = body,
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

fn readChunked(a: std.mem.Allocator, reader: anytype) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    while (true) {
        const size_line = try readLine(a, reader, 32);
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size = try std.fmt.parseInt(usize, size_line[0..semi], 16);
        if (size == 0) {
            _ = try readLine(a, reader, 8); // trailer line
            break;
        }
        const chunk = try a.alloc(u8, size);
        try reader.readNoEof(chunk);
        try out.appendSlice(a, chunk);
        _ = try readLine(a, reader, 8); // CRLF after chunk
    }
    return try out.toOwnedSlice(a);
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
    /// Present when the response was buffered and has not yet been written to
    /// Codex. The caller may retry first, then write this only if recovery is
    /// unavailable or the retry also fails with a buffered response.
    buffered_response: ?BufferedResponse = null,
};

/// Forward the inbound request to chatgpt.com and write the response
/// directly to the client writer.
///
/// 4xx and 5xx responses are buffered so the proxy can decide whether to
/// retry against a fallback account before any bytes reach Codex. 429 also
/// needs the body to classify usage_limit_reached vs usage_not_included.
///
/// Non-error responses (including 200 streaming SSE) are streamed byte-for-byte
/// from upstream's reader to the client. Connection-close framing is used so we
/// don't have to re-chunk std.http.Client's already-decoded body bytes.
fn forwardAndStream(
    a: std.mem.Allocator,
    req: Request,
    out_headers: HeaderList,
    client_writer: anytype,
) !StatusAndClassification {
    var client = std.http.Client{ .allocator = a };
    defer client.deinit();

    const scheme = upstreamScheme(a);
    defer if (!std.mem.eql(u8, scheme, DEFAULT_UPSTREAM_SCHEME)) a.free(scheme);
    const host = upstreamHost(a);
    defer if (!std.mem.eql(u8, host, DEFAULT_UPSTREAM_HOST)) a.free(host);
    const url = try std.fmt.allocPrint(a, "{s}://{s}{s}", .{ scheme, host, req.path });
    defer a.free(url);
    const uri = try std.Uri.parse(url);

    var extra = std.ArrayListUnmanaged(std.http.Header){};
    defer extra.deinit(a);
    for (out_headers.items.items) |h| {
        try extra.append(a, .{ .name = h.name, .value = h.value });
    }

    var server_header_buf: [16 * 1024]u8 = undefined;
    var http_req = try client.open(parseMethod(req.method), uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = extra.items,
    });
    defer http_req.deinit();

    if (req.body.len > 0) {
        http_req.transfer_encoding = .{ .content_length = req.body.len };
    }
    try http_req.send();
    if (req.body.len > 0) {
        try http_req.writeAll(req.body);
        try http_req.finish();
    }
    try http_req.wait();

    const status_u16: u16 = @intFromEnum(http_req.response.status);

    // Error responses are retry decision points, so they must be buffered
    // before anything is written to Codex.
    if (status_u16 >= 400 and status_u16 < 600) {
        // Cap at 64 KiB — chatgpt.com's error JSON/HTML bodies are small.
        const body = try http_req.reader().readAllAlloc(a, 64 * 1024);
        const classification = classify(a, status_u16, body);
        return .{
            .status = status_u16,
            .classification = classification,
            .body_class = classification.body_class orelse classifyHttpErrorBody(body),
            .streamed = false,
            .buffered_response = .{
                .status = status_u16,
                .headers = try captureResponseHeaders(a, http_req.response),
                .body = body,
            },
        };
    }

    const classification = classify(a, status_u16, &.{});
    try writeStreamedResponse(client_writer, http_req.response, http_req.reader());
    return .{ .status = status_u16, .classification = classification, .streamed = true };
}

fn pathKind(path: []const u8) []const u8 {
    if (std.mem.eql(u8, path, "/backend-api/codex/responses")) return "responses";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/responses?")) return "responses";
    if (std.mem.eql(u8, path, "/backend-api/codex/responses/compact")) return "responses_compact";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/responses/compact?")) return "responses_compact";
    if (std.mem.indexOf(u8, path, "/backend-api/codex/memories/trace_summarize") != null) return "memories_trace_summarize";
    if (std.mem.indexOf(u8, path, "responses_websockets") != null) return "responses_websocket";
    if (std.mem.startsWith(u8, path, "/backend-api/codex/")) return "codex_other";
    return "unknown";
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
///   5xx                                            → provider_5xx
///   2xx / 3xx / 4xx (other)                        → ok
pub fn classify(
    a: std.mem.Allocator,
    status: u16,
    body_preview: []const u8,
) Classification {
    if (status == 401) return .{ .kind = .auth_unauthorized };
    if (status >= 500 and status < 600) return .{ .kind = .provider_5xx };

    if (status == 429) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, body_preview, .{
            .ignore_unknown_fields = true,
        }) catch {
            return .{ .kind = .rate_limited };
        };
        defer parsed.deinit();
        if (parsed.value != .object) return .{ .kind = .rate_limited };
        const err_v = parsed.value.object.get("error") orelse return .{ .kind = .rate_limited };
        if (err_v != .object) return .{ .kind = .rate_limited };
        const type_v = err_v.object.get("type") orelse return .{ .kind = .rate_limited };
        if (type_v != .string) return .{ .kind = .rate_limited };

        if (std.mem.eql(u8, type_v.string, "usage_limit_reached")) {
            var resets: ?i64 = null;
            if (err_v.object.get("resets_at")) |rv| {
                if (rv == .integer) resets = rv.integer;
            }
            return .{ .kind = .quota_exhausted, .resets_at = resets, .body_class = "usage_limit_reached" };
        }
        if (std.mem.eql(u8, type_v.string, "usage_not_included")) {
            return .{ .kind = .tier_insufficient, .body_class = "usage_not_included" };
        }
        return .{ .kind = .rate_limited };
    }

    return .{ .kind = .ok };
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
        .label = "no-spend Codex preflight",
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
        "oauth-mux: provider transport failed and no fallback account was selectable. This is provider-degraded evidence, not credential-dead evidence; inspect the redacted status artifact and retry when the provider recovers.",
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
) !void {
    try writer.print("HTTP/1.1 {d} \r\n", .{@intFromEnum(response.status)});
    try writeForwardingResponseHeaders(writer, response);
    try writer.writeAll("Connection: close\r\n\r\n");

    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = upstream_reader.read(&buf) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        try writer.writeAll(buf[0..n]);
    }
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
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/codex/responses/compact"));
    try std.testing.expectEqualStrings("responses_compact", pathKind("/backend-api/codex/responses/compact?after=1"));
    try std.testing.expectEqualStrings("memories_trace_summarize", pathKind("/backend-api/codex/memories/trace_summarize"));
    try std.testing.expectEqualStrings("codex_other", pathKind("/backend-api/codex/unknown/shape"));
    try std.testing.expectEqualStrings("unknown", pathKind("/not-codex"));
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

test "classify 503 -> provider_5xx" {
    const c = classify(std.testing.allocator, 503, "{}");
    try std.testing.expectEqual(broker_types.QuotaKind.provider_5xx, c.kind);
}

test "provider_5xx retries same turn and records provider-degraded route state" {
    try std.testing.expect(shouldRetrySameTurn(.provider_5xx));
    try std.testing.expectEqual(RouteState.provider_degraded, routeStateFromClassification(.provider_5xx));
}

test "classify 429 + usage_limit_reached -> quota_exhausted with resets_at" {
    const body =
        \\{"error":{"type":"usage_limit_reached","plan_type":"pro","resets_at":1788000000}}
    ;
    const c = classify(std.testing.allocator, 429, body);
    try std.testing.expectEqual(broker_types.QuotaKind.quota_exhausted, c.kind);
    try std.testing.expectEqual(@as(?i64, 1788000000), c.resets_at);
}

test "classify 429 + usage_not_included -> tier_insufficient (NOT swap)" {
    const body =
        \\{"error":{"type":"usage_not_included","plan_type":"free"}}
    ;
    const c = classify(std.testing.allocator, 429, body);
    try std.testing.expectEqual(broker_types.QuotaKind.tier_insufficient, c.kind);
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

test "provider signal matrix maps to route state and same-turn retry policy" {
    const SignalCase = struct {
        name: []const u8,
        status: u16,
        body: []const u8,
        kind: broker_types.QuotaKind,
        route_state: RouteState,
        retry_same_turn: bool,
        body_class: ?[]const u8 = null,
    };

    const cases = [_]SignalCase{
        .{
            .name = "200 ok",
            .status = 200,
            .body = "{}",
            .kind = .ok,
            .route_state = .available,
            .retry_same_turn = false,
        },
        .{
            .name = "401 auth",
            .status = 401,
            .body = "{}",
            .kind = .auth_unauthorized,
            .route_state = .auth_failed,
            .retry_same_turn = true,
        },
        .{
            .name = "429 usage_limit_reached",
            .status = 429,
            .body = "{\"error\":{\"type\":\"usage_limit_reached\",\"resets_at\":1788000000}}",
            .kind = .quota_exhausted,
            .route_state = .quota_exhausted,
            .retry_same_turn = true,
            .body_class = "usage_limit_reached",
        },
        .{
            .name = "429 generic rate",
            .status = 429,
            .body = "{\"error\":{\"type\":\"rate_limit_exceeded\"}}",
            .kind = .rate_limited,
            .route_state = .rate_limited,
            .retry_same_turn = true,
        },
        .{
            .name = "429 malformed rate",
            .status = 429,
            .body = "Too Many Requests",
            .kind = .rate_limited,
            .route_state = .rate_limited,
            .retry_same_turn = true,
        },
        .{
            .name = "429 usage_not_included",
            .status = 429,
            .body = "{\"error\":{\"type\":\"usage_not_included\",\"plan_type\":\"free\"}}",
            .kind = .tier_insufficient,
            .route_state = .tier_insufficient,
            .retry_same_turn = false,
            .body_class = "usage_not_included",
        },
        .{
            .name = "provider 5xx",
            .status = 503,
            .body = "Service Unavailable",
            .kind = .provider_5xx,
            .route_state = .provider_degraded,
            .retry_same_turn = true,
        },
    };

    for (cases) |tc| {
        const c = classify(std.testing.allocator, tc.status, tc.body);
        try std.testing.expectEqual(tc.kind, c.kind);
        try std.testing.expectEqual(tc.route_state, routeStateFromClassification(c.kind));
        try std.testing.expectEqual(tc.retry_same_turn, shouldRetrySameTurn(c.kind));
        if (tc.body_class) |expected_body_class| {
            try std.testing.expectEqualStrings(expected_body_class, c.body_class orelse "");
        } else {
            try std.testing.expect(c.body_class == null);
        }
    }
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

    const req = try parseRequest(a, fbs.reader());
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/backend-api/codex/responses", req.path);
    try std.testing.expectEqualStrings("Bearer XYZ", req.headers.find("Authorization").?);
    try std.testing.expectEqualStrings("turn-abc", req.headers.find("x-codex-turn-state").?);
    try std.testing.expectEqualStrings("hello", req.body);
}

test "parseRequest reads chunked body" {
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
    const req = try parseRequest(arena.allocator(), fbs.reader());
    try std.testing.expectEqualStrings("hello world", req.body);
}

test "parseRequest rejects malformed start line" {
    const wire = "BAD\r\n\r\n";
    var fbs = std.io.fixedBufferStream(wire);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.BadRequestLine, parseRequest(arena.allocator(), fbs.reader()));
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

    var attempted = std.ArrayListUnmanaged([]const u8){};
    defer attempted.deinit(std.testing.allocator);
    try appendAttempt(std.testing.allocator, &attempted, "codex:max-1");
    try appendAttempt(std.testing.allocator, &attempted, "codex:max-5");

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
