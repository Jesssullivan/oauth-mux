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
//!   7. Stream the final response body verbatim back to codex (SSE works
//!      because chunked-transfer is forwarded byte-for-byte).
//!
//! Phase 2 scope (honestly labelled limitations):
//!   - Synchronous, single-connection-at-a-time (codex sends one
//!     request per turn). No request pipelining.
//!   - **Streaming for 200/3xx/5xx; buffered for 401/429.** SSE turns
//!     stream byte-for-byte from upstream to codex via Connection:close
//!     framing — the TUI animation moves in real time. 401 and 429 responses
//!     are small and need a retry decision before any bytes reach Codex, so
//!     they stay buffered (with a 64 KiB cap).
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

const DEFAULT_UPSTREAM_HOST = "chatgpt.com";
const DEFAULT_UPSTREAM_SCHEME = "https";
const UPSTREAM_BASE_PATH = "/backend-api/codex";

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

    /// The strongest claim level this skeleton is allowed to publish.
    /// TIN-948 is synthetic structural evidence only, so the adapter
    /// stays at `.broker_owned`. Live provider-originated acceptance
    /// can promote this in a later slice.
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

        // ── 2. Elect an account ─────────────────────────────────
        const elected = self.pool.elect(self.profile, null, &.{}) catch {
            self.logEvent("proxy_no_account_selectable", .{});
            try writeStatus(writer, 503, "No Account Selectable");
            return;
        };

        var tokens = self.materializer.materialize_chatgpt(
            self.materializer.ctx,
            a,
            elected.id,
        ) catch |err| {
            self.logEvent("proxy_materialize_failed", .{ .account = elected.id, .err = @errorName(err) });
            try writeStatus(writer, 500, "Materialize Failed");
            return;
        };
        // tokens lives in arena `a`; deinit-on-arena-drop.
        _ = &tokens;

        // ── 3. Build outbound request with substituted headers ──
        var out_headers = HeaderList.init(a);
        const preserved_child_auth = try buildOutboundHeaders(a, &req, &out_headers, tokens, false);
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
        // Inbound body length is preserved; chunked → chunked, fixed →
        // fixed. We don't transform the body.

        // ── 4. Forward to upstream + stream/buffer response ────
        var status_and_class = forwardAndStream(a, req, out_headers, writer) catch |err| {
            self.logEvent("proxy_upstream_failed", .{ .account = elected.id, .err = @errorName(err) });
            try writeStatus(writer, 502, "Upstream Error");
            return;
        };

        // ── 5. Apply classification + log ──────────────────────
        self.applyClassification(elected.id, status_and_class.classification) catch |err| {
            self.logEvent("proxy_apply_classification_failed", .{ .err = @errorName(err) });
        };
        self.logProxyTurn(elected.id, req, status_and_class, status_and_class.buffered_response == null);

        var final_account = elected.id;

        if (status_and_class.classification.kind == .quota_exhausted) same_turn_retry: {
            const fallback = self.pool.elect(self.profile, null, &.{elected.id}) catch |err| {
                self.logEvent("proxy_same_turn_retry_unavailable", .{
                    .from = elected.id,
                    .err = @errorName(err),
                });
                break :same_turn_retry;
            };

            var fallback_tokens = self.materializer.materialize_chatgpt(
                self.materializer.ctx,
                a,
                fallback.id,
            ) catch |err| {
                self.logEvent("proxy_same_turn_materialize_failed", .{
                    .from = elected.id,
                    .to = fallback.id,
                    .err = @errorName(err),
                });
                break :same_turn_retry;
            };
            _ = &fallback_tokens;

            var retry_headers = HeaderList.init(a);
            _ = try buildOutboundHeaders(a, &req, &retry_headers, fallback_tokens, true);
            self.logEvent("proxy_same_turn_retry", .{
                .from = elected.id,
                .to = fallback.id,
                .reason = "quota_exhausted",
                .dropped = "x-codex-turn-state",
            });
            self.synthetic_swap_seen = true;

            status_and_class = forwardAndStream(a, req, retry_headers, writer) catch |err| {
                self.logEvent("proxy_upstream_failed", .{ .account = fallback.id, .err = @errorName(err) });
                try writeStatus(writer, 502, "Upstream Error");
                return;
            };
            self.applyClassification(fallback.id, status_and_class.classification) catch |err| {
                self.logEvent("proxy_apply_classification_failed", .{ .err = @errorName(err) });
            };
            self.logProxyTurn(fallback.id, req, status_and_class, status_and_class.buffered_response == null);
            final_account = fallback.id;
        }

        if (status_and_class.classification.kind == .auth_unauthorized) auth_retry: {
            const auth_failed_account = final_account;
            const fallback = self.pool.elect(self.profile, null, &.{auth_failed_account}) catch |err| {
                self.logEvent("proxy_auth_retry_unavailable", .{
                    .from = auth_failed_account,
                    .err = @errorName(err),
                });
                self.logEvent("proxy_observed_401_codex_handles", .{
                    .account = auth_failed_account,
                });
                break :auth_retry;
            };

            var fallback_tokens = self.materializer.materialize_chatgpt(
                self.materializer.ctx,
                a,
                fallback.id,
            ) catch |err| {
                self.logEvent("proxy_auth_materialize_failed", .{
                    .from = auth_failed_account,
                    .to = fallback.id,
                    .err = @errorName(err),
                });
                self.logEvent("proxy_observed_401_codex_handles", .{
                    .account = auth_failed_account,
                });
                break :auth_retry;
            };
            _ = &fallback_tokens;

            self.pool.markUnauthorized(auth_failed_account) catch |err| {
                self.logEvent("proxy_auth_mark_unauthorized_failed", .{
                    .account = auth_failed_account,
                    .err = @errorName(err),
                });
            };

            var retry_headers = HeaderList.init(a);
            _ = try buildOutboundHeaders(a, &req, &retry_headers, fallback_tokens, true);
            self.logEvent("proxy_auth_same_turn_retry", .{
                .from = auth_failed_account,
                .to = fallback.id,
                .reason = "auth_unauthorized",
                .dropped = "x-codex-turn-state",
            });
            self.synthetic_swap_seen = true;

            status_and_class = forwardAndStream(a, req, retry_headers, writer) catch |err| {
                self.logEvent("proxy_upstream_failed", .{ .account = fallback.id, .err = @errorName(err) });
                try writeStatus(writer, 502, "Upstream Error");
                return;
            };
            self.applyClassification(fallback.id, status_and_class.classification) catch |err| {
                self.logEvent("proxy_apply_classification_failed", .{ .err = @errorName(err) });
            };
            self.logProxyTurn(fallback.id, req, status_and_class, status_and_class.buffered_response == null);
            final_account = fallback.id;
        }

        if (status_and_class.buffered_response) |buffered| {
            try writeBufferedStoredResponse(writer, buffered);
        }

        // Track previous_account for next-request swap detection.
        if (self.previous_account) |old| self.allocator.free(old);
        self.previous_account = self.allocator.dupe(u8, final_account) catch null;
    }

    fn logProxyTurn(
        self: *Proxy,
        account_id: []const u8,
        req: Request,
        status_and_class: StatusAndClassification,
        delivered_to_codex: bool,
    ) void {
        self.auth_failure_tracker.observe(account_id, req.path, status_and_class.classification);
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
    }

    fn applyClassification(
        self: *Proxy,
        account_id: []const u8,
        c: Classification,
    ) !void {
        const now_unix = std.time.timestamp();
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
            .auth_unauthorized => {},
            .tier_insufficient, .provider_5xx => {
                // Recorded for telemetry only; no pool mutation.
            },
        }
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

pub const AuthFailureObservation = struct {
    account: ?[]const u8 = null,
    auth_unauthorized_turns: usize = 0,
    responses_401_turns: usize = 0,
    recovered_after_401: bool = false,

    pub fn unrecovered(self: AuthFailureObservation) bool {
        return self.account != null and
            self.auth_unauthorized_turns > 0 and
            !self.recovered_after_401;
    }
};

const AuthFailureTracker = struct {
    account: ?[]const u8 = null,
    auth_unauthorized_turns: usize = 0,
    responses_401_turns: usize = 0,
    recovered_after_401: bool = false,

    fn observe(
        self: *AuthFailureTracker,
        account_id: []const u8,
        path: []const u8,
        classification: Classification,
    ) void {
        switch (classification.kind) {
            .auth_unauthorized => {
                self.account = account_id;
                self.auth_unauthorized_turns += 1;
                self.recovered_after_401 = false;
                if (std.mem.eql(u8, pathKind(path), "responses")) {
                    self.responses_401_turns += 1;
                }
            },
            .ok => {
                if (self.account) |failed_account| {
                    if (std.mem.eql(u8, failed_account, account_id) and self.auth_unauthorized_turns > 0) {
                        self.recovered_after_401 = true;
                    }
                }
            },
            else => {},
        }
    }

    fn observation(self: AuthFailureTracker) AuthFailureObservation {
        return .{
            .account = self.account,
            .auth_unauthorized_turns = self.auth_unauthorized_turns,
            .responses_401_turns = self.responses_401_turns,
            .recovered_after_401 = self.recovered_after_401,
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
    /// false if it was buffered for classification (429 path) or never
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
/// 401 and 429 responses are buffered so the proxy can decide whether to
/// retry against a fallback account before any bytes reach Codex. 429 also
/// needs the body to classify usage_limit_reached vs usage_not_included.
///
/// All other responses (200 streaming SSE, 5xx) are streamed
/// byte-for-byte from upstream's reader to the client. Connection-close
/// framing is used so we don't have to re-chunk std.http.Client's
/// already-decoded body bytes.
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

    // 401 and 429 are retry decision points, so they must be buffered before
    // anything is written to Codex.
    if (status_u16 == 401 or status_u16 == 429) {
        // Cap at 64 KiB — chatgpt.com's 429 JSON bodies are small.
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

    if (status_u16 >= 400 and status_u16 < 500 and status_u16 != 401) {
        const body = try http_req.reader().readAllAlloc(a, 64 * 1024);
        const classification = classify(a, status_u16, body);
        return .{
            .status = status_u16,
            .classification = classification,
            .body_class = classifyHttpErrorBody(body),
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

/// 429 path: write status + headers + Content-Length + buffered body.
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
    tracker.observe(
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
    tracker.observe(
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .auth_unauthorized },
    );
    tracker.observe(
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
    tracker.observe(
        "codex:max-1",
        "/backend-api/codex/responses",
        .{ .kind = .auth_unauthorized },
    );
    tracker.observe(
        "codex:max-2",
        "/backend-api/codex/responses",
        .{ .kind = .ok },
    );

    const observation = tracker.observation();
    try std.testing.expect(observation.unrecovered());
    try std.testing.expect(!observation.recovered_after_401);
}
