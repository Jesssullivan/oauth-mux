//! Authenticated loopback ingress for the unshipped managed Claude broker.
//!
//! This slice only establishes the local HTTP boundary. It does not read or
//! inject provider credentials, select routes, retry requests, or spawn Claude.
//!
//! RESIDENT-ABSENCE INVARIANT (G6 sidecar half; plan §2.1/§2.4, ladder §7/G6):
//! the sidecar consults NO resident/daemon/service state. Every routing, retry,
//! and terminal decision derives solely from the inbound request, the session
//! capability, the injected synthetic routes, and the per-sidecar replay
//! reservation pool. There is no resident hook to read, so resident-service
//! absence or restart cannot change routing, expose a request body, or make the
//! resident the session proxy. This is grep-proof (no `resident`/`daemon`/
//! `keepalive`/`service` symbol appears in this file) and is enforced as a
//! structural test over the listener `State` (see the "resident absence" test).

const std = @import("std");
const builtin = @import("builtin");
const capability_mod = @import("session_capability.zig");
const fake_upstream_mod = @import("fake_upstream.zig");
const advisory_usage = @import("../../quota/advisory_usage.zig");

const SessionCapability = capability_mod.SessionCapability;
const FakeUpstream = fake_upstream_mod.FakeUpstream;

// §8.8 advisory-usage OBSERVATION vocabulary (TIN-2400, observation-only).
//
// The pure `advisory_usage` core validates a SYNTHETIC JSON usage document (its
// own `schema_version`/`usage[]` shape), not a discrete header set — it is
// schema-neutral with respect to wire header NAMES. Per the live-proven reality
// that Anthropic advisory rate-limit metadata rides `anthropic-ratelimit-*`
// headers (NOT the mis-declared `x-ratelimit-*`), the fixture threads the core's
// own authoritative usage document through a single `anthropic-ratelimit-*`
// header. §8.8's real reader fetches that same document from a separate
// `GET /api/oauth/usage` body; this observation-only slice never makes that call,
// so the fixture carries the document inline. wire_proxy does NOT invent a second
// header-derived schema — the pure core stays the sole schema authority, so its
// kill switch, freshness window, negative cache, and provenance cap all apply
// unchanged.
pub const advisory_usage_header = "anthropic-ratelimit-usage";

pub const production_origin = "https://api.anthropic.com";
pub const production_forwarding_enabled = false;
const max_request_head_bytes = 64 * 1024;
const max_request_body_bytes = 32 * 1024 * 1024;
const max_response_head_bytes = 64 * 1024;
const max_response_body_bytes = 32 * 1024 * 1024;
const max_forwarded_response_headers = 25;
// Exact-model admission (program §2.2, ladder §8.2). The request body is already
// bounded by `max_request_body_bytes`, so the complete document is validated.
// This rejects duplicate model keys and trailing JSON before any upstream call.
const max_model_len = 128;

// §2.2 replay-budget accounting. The request body is buffered under
// `max_request_body_bytes` (32 MiB/request), which is also the replay
// eligibility bound. The per-sidecar reservation pool is 64 MiB of retained
// replay bodies. The 256 MiB per-HOST budget is DEFERRED: it requires a
// cross-process shared state view with stale-PID cleanup that does not exist in
// this in-process slice, so only the 32 MiB/request + 64 MiB/sidecar bounds are
// enforced here (see the commit body for the honest deferral).
const default_reservation_budget_bytes: usize = 64 * 1024 * 1024;
const deferred_host_reservation_budget_bytes: usize = 256 * 1024 * 1024; // DEFERRED
// §2.2 / §8.4 bounded single pre-alternate wait.
const default_max_wait_ns: u64 = 30 * std.time.ns_per_s;
const default_request_deadline_ns: u64 = 120 * std.time.ns_per_s;

const Upstream = union(enum) {
    production,
    fake: *FakeUpstream,
    /// Test-seam-only single-alternate retry machine (§2.2). Never reachable in
    /// production: it is constructed exclusively through the `builtin.is_test`
    /// routed seam with synthetic credentials against `FakeUpstream`.
    synthetic: *SyntheticRouting,
};

const State = struct {
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    server: std.net.Server,
    upstream: Upstream,
    event_writer: std.io.AnyWriter,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active: ActiveConnection = .{},
    upstream_active: ActiveConnection = .{},
    observation_mutex: std.Thread.Mutex = .{},
    observation: RequestObservation = .{},
    /// §8.8 advisory-usage OBSERVATION state (TIN-2400). Per-account /
    /// process-lifetime: the freshness window, negative cache, and kill latch
    /// persist ACROSS requests for the one account this sidecar serves. Guarded
    /// by `observation_mutex`. This is read-only advisory OBSERVATION — nothing
    /// here participates in routing, retry, or any terminal decision.
    advisory_cache: advisory_usage.AdvisoryCache = .{},
    /// One redacted kill event per distinct schema fingerprint, process-lifetime
    /// (§8.8). Guarded by `observation_mutex`. Value-free by construction.
    kill_registry: advisory_usage.KillRegistry = .{},
    /// Per-sidecar replay reservation pool (§2.2). Only the synthetic routed
    /// seam reserves against it; the single-attempt `.fake`/`.production` paths
    /// never touch it, so the accounting stays at zero for those.
    reservation: Reservation = .{},
};

pub const RequestOutcome = enum {
    none,
    receiving_head,
    request_head_rejected,
    capability_rejected,
    origin_rejected,
    expectation_rejected,
    request_body_rejected,
    model_admission_rejected,
    upstream_response,
    proxy_error,
};

/// FIRST-ATTEMPT ADMISSION ONLY. Records what model was admitted for the one
/// upstream attempt of the last request. It is exposed to tests through the same
/// snapshot pattern the fake upstream uses. The model bytes are the public model
/// identifier only; no credential or body payload is retained.
///
/// It deliberately makes NO result-side claim. Ladder §8.2 step 3 (the
/// harness-visible successful result reporting the same public model through a
/// trusted local observation) is NOT established here: this slice never inspects
/// the response body for a model, so result-side model evidence does not exist
/// yet. `admittedModel()` describes only what was admitted for the attempt,
/// never what the upstream result reported.
pub const RequestObservation = struct {
    request_id: u64 = 0,
    outcome: RequestOutcome = .none,
    had_body: bool = false,
    /// A top-level request model was present and admitted for the attempt.
    model_present: bool = false,
    admitted_model_buf: [max_model_len]u8 = undefined,
    admitted_model_len: usize = 0,
    upstream_attempted: bool = false,
    upstream_status: u16 = 0,
    model_admission_rejected: bool = false,
    /// §2.2 / §8.4 retry accounting for the request. `attempts_total` counts
    /// upstream attempt STARTS (a proven pre-send failure counts as a started
    /// attempt). At most one of the two consumption forms may fire, so
    /// `same_route_retry_count` and `alternate_count` are each in {0,1} and
    /// never both 1. `third_attempt_count` is structurally unreachable and is
    /// asserted to remain 0.
    same_route_retry_count: usize = 0,
    alternate_count: usize = 0,
    third_attempt_count: usize = 0,
    attempts_total: usize = 0,
    /// Whether the request body was reserved for replay (`replayable`) or the
    /// request irrevocably degraded to a single streamed attempt
    /// (`stream_once`).
    replay_mode: ReplayMode = .replayable,
    /// A configured alternate was refused because it shared the primary's
    /// identity marker (§2.2 distinct-account requirement).
    same_identity_alternate_refused: bool = false,
    /// §8.8 advisory-usage OBSERVATION for this request (TIN-2400). Value-free:
    /// only normalized typed enums/flags — never a token count, limit, or reset
    /// timestamp from the provider. Advisory OBSERVATION is decoupled from every
    /// routing/retry/terminal field above; it records what the pure core made of
    /// the response's advisory signal, and changes no decision.
    advisory: AdvisoryObservation = .{},

    fn admittedModel(self: *const RequestObservation) []const u8 {
        return self.admitted_model_buf[0..self.admitted_model_len];
    }
};

/// The value-free normalized outcome of folding one response's advisory signal
/// through the pure `advisory_usage` core (§8.8). Every field is a typed enum or
/// bool — NO provider payload value (token count, remaining, limit, or reset
/// epoch) is representable here, mirroring the core's own no-raw-persistence
/// invariant. Exposed to tests through the same observation snapshot the routing
/// accounting uses.
pub const AdvisoryObservation = struct {
    /// An `anthropic-ratelimit-usage` header was present on this response.
    present: bool = false,
    /// The per-account cache freshness AT observation time (never/fresh/stale/
    /// negative-active/negative-expired/killed).
    freshness: advisory_usage.Freshness = .never,
    /// The advisory-tier readiness the fresh rows summarized to for the admitted
    /// model (`unknown` when none apply / contradictory / not fresh).
    readiness: advisory_usage.Readiness = .unknown,
    /// The advisory-ONLY election provenance (`elect(advisory, null)`), which the
    /// core caps at `.inferred` — advisory can never mint `.proven`.
    provenance: advisory_usage.Provenance = .unobserved,
    /// The per-account kill switch is latched (this response, or an earlier one).
    killed: bool = false,
    /// Direct request-path (reactive) evidence existed for this response.
    reactive_present: bool = false,
    /// The elected readiness once reactive evidence is allowed to outrank
    /// advisory (`elect(advisory, reactive)`).
    elected_readiness: advisory_usage.Readiness = .unknown,
    /// The elected provenance — `.proven` whenever reactive evidence wins,
    /// proving direct request-path evidence outranks advisory state.
    elected_provenance: advisory_usage.Provenance = .unobserved,
};

/// At most one value-free advisory event per observed response (§8.8).
const AdvisoryEvent = enum { none, observed, stale, schema_rejected };

/// The full advisory observation result: the value-free `AdvisoryObservation`
/// recorded onto the request surface, plus which (if any) value-free event to
/// emit. Kept separate from I/O so the core fold runs under the state lock and
/// the event write happens outside it.
const AdvisoryOutcome = struct {
    obs: AdvisoryObservation = .{},
    event: AdvisoryEvent = .none,
};

const ModelObservationInput = struct {
    had_body: bool = false,
    model_present: bool = false,
    admitted_model: ?[]const u8 = null,
    upstream_attempted: bool = false,
    upstream_status: u16 = 0,
    model_admission_rejected: bool = false,
};

fn recordModelObservation(state: *State, input: ModelObservationInput) void {
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    var obs = RequestObservation{
        .request_id = state.observation.request_id,
        .outcome = if (input.model_admission_rejected)
            .model_admission_rejected
        else
            .upstream_response,
        .had_body = input.had_body,
        .model_present = input.model_present,
        .upstream_attempted = input.upstream_attempted,
        .upstream_status = input.upstream_status,
        .model_admission_rejected = input.model_admission_rejected,
    };
    if (input.admitted_model) |m| {
        const n = @min(m.len, max_model_len);
        @memcpy(obs.admitted_model_buf[0..n], m[0..n]);
        obs.admitted_model_len = n;
    }
    state.observation = obs;
}

fn beginRequestObservation(state: *State) void {
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    var next_id = state.observation.request_id +% 1;
    if (next_id == 0) next_id = 1;
    state.observation = .{
        .request_id = next_id,
        .outcome = .receiving_head,
    };
}

fn markRequestOutcome(state: *State, outcome: RequestOutcome) void {
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    if (state.observation.outcome != .receiving_head) return;
    state.observation.outcome = outcome;
}

/// One authenticated HTTP/1.1 listener bound to an ephemeral IPv4 loopback
/// port. The concrete state is opaque so callers cannot inject an upstream.
pub const Listener = opaque {
    /// Starts the production listener. Its upstream authority is compile-fixed;
    /// no client input or environment variable participates in selection.
    /// Production forwarding remains fail-closed until credential injection is
    /// implemented. The capability and event writer must outlive the listener.
    pub fn start(
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        event_writer: std.io.AnyWriter,
    ) !*Listener {
        return startWithUpstream(allocator, capability, event_writer, .production);
    }

    pub fn address(self: *const Listener) std.net.Address {
        return statePtrConst(self).server.listen_address;
    }

    pub fn port(self: *const Listener) u16 {
        return self.address().getPort();
    }

    /// Interrupts an accepted inbound connection, joins the listener thread,
    /// and only then releases the socket and listener state.
    pub fn deinit(self: *Listener) void {
        _ = teardown(self);
    }
};

/// Tears the listener down and returns the per-sidecar replay reservation still
/// outstanding at teardown. The measurement is taken AFTER the serve thread is
/// joined — so any in-flight request has fully unwound and released its
/// reservation via its `defer guard.release()` — and BEFORE the state is freed.
/// This is the abrupt-death reclamation seam (ladder §9 Stage 2): a live request
/// killed mid-attempt or mid-stream must return the pool to zero.
fn teardown(self: *Listener) usize {
    const state = statePtr(self);
    state.stopping.store(true, .release);
    state.active.interrupt();
    state.upstream_active.interrupt();
    if (state.thread) |thread| thread.join();
    // Post-join: the request path (if any) has run its exactly-once release.
    const outstanding = state.reservation.outstanding();
    state.server.deinit();
    const allocator = state.allocator;
    // The synthetic routing struct is sidecar-owned; its `FakeUpstream`
    // targets and credential slices remain caller-owned and outlive us.
    switch (state.upstream) {
        .synthetic => |routing| allocator.destroy(routing),
        else => {},
    }
    allocator.destroy(state);
    return outstanding;
}

fn statePtr(listener: *Listener) *State {
    return @ptrCast(@alignCast(listener));
}

fn statePtrConst(listener: *const Listener) *const State {
    return @ptrCast(@alignCast(listener));
}

/// File-private: capture the last request's exact-model accounting.
fn observationSnapshot(listener: *Listener) RequestObservation {
    const state = statePtr(listener);
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    return state.observation;
}

fn startWithUpstream(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    event_writer: std.io.AnyWriter,
    upstream: Upstream,
) !*Listener {
    const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try loopback.listen(.{ .reuse_address = true });
    errdefer server.deinit();

    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .allocator = allocator,
        .capability = capability,
        .server = server,
        .upstream = upstream,
        .event_writer = event_writer,
    };
    switch (upstream) {
        .synthetic => |routing| state.reservation.budget_bytes = routing.reservation_budget_bytes,
        else => {},
    }
    state.thread = try std.Thread.spawn(.{}, run, .{state});
    return @ptrCast(state);
}

pub const testing = if (builtin.is_test) struct {
    /// Test-only composition seam. The caller supplies the repository's
    /// deterministic fake explicitly; production upstream selection remains
    /// compile-fixed and unavailable through this API.
    pub fn startWithFake(
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        upstream: *FakeUpstream,
        event_writer: std.io.AnyWriter,
    ) !*Listener {
        return startWithUpstream(
            allocator,
            capability,
            event_writer,
            .{ .fake = upstream },
        );
    }

    pub const Clock = WireClock;

    /// A synthetic route the routed retry machine may target. The bearer is a
    /// synthetic test-only token; `identity` distinguishes accounts;
    /// `presend_faults` injects that many transient pre-send transport faults.
    pub const RoutedRoute = struct {
        upstream: *FakeUpstream,
        bearer: ?[]const u8 = null,
        identity: []const u8,
        presend_faults: usize = 0,
    };

    pub const RoutedConfig = struct {
        primary: RoutedRoute,
        alternate: ?RoutedRoute = null,
        reservation_budget_bytes: usize = default_reservation_budget_bytes,
        request_deadline_ns: u64 = default_request_deadline_ns,
        max_wait_ns: u64 = default_max_wait_ns,
        clock: WireClock = .{},
    };

    /// Test-only routed seam (mirrors `startWithFake` gating). It composes the
    /// §2.2 single-alternate retry machine over caller-supplied synthetic
    /// routes and fakes. Production upstream selection and automatic alternates
    /// remain compile-fixed and unreachable through this API.
    pub fn startWithRoutes(
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        event_writer: std.io.AnyWriter,
        config: RoutedConfig,
    ) !*Listener {
        const routing = try allocator.create(SyntheticRouting);
        errdefer allocator.destroy(routing);
        routing.* = .{
            .primary = .{
                .upstream = config.primary.upstream,
                .bearer = config.primary.bearer,
                .identity = config.primary.identity,
                .presend_faults = config.primary.presend_faults,
            },
            .alternate = if (config.alternate) |a| Route{
                .upstream = a.upstream,
                .bearer = a.bearer,
                .identity = a.identity,
                .presend_faults = a.presend_faults,
            } else null,
            .reservation_budget_bytes = config.reservation_budget_bytes,
            .request_deadline_ns = config.request_deadline_ns,
            .max_wait_ns = config.max_wait_ns,
            .clock = config.clock,
        };
        return startWithUpstream(
            allocator,
            capability,
            event_writer,
            .{ .synthetic = routing },
        );
    }

    pub fn requestObservation(listener: *Listener) RequestObservation {
        return observationSnapshot(listener);
    }
} else struct {};

/// File-private routed test seam over the deterministic fakes, discarding
/// events. Mirrors `startForTest` for the single-attempt path.
fn startRoutedForTest(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    config: testing.RoutedConfig,
) !*Listener {
    return testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        config,
    );
}

/// File-private: outstanding per-sidecar replay reservation bytes.
fn reservedBytes(listener: *Listener) usize {
    return statePtr(listener).reservation.outstanding();
}

/// This file-private seam can only target the repository's deterministic fake.
fn startForTest(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    upstream: *FakeUpstream,
) !*Listener {
    return testing.startWithFake(
        allocator,
        capability,
        upstream,
        std.io.null_writer.any(),
    );
}

const ActiveConnection = struct {
    mutex: std.Thread.Mutex = .{},
    handle: ?std.posix.socket_t = null,

    fn begin(
        self: *ActiveConnection,
        handle: std.posix.socket_t,
        stopping: *std.atomic.Value(bool),
    ) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (stopping.load(.acquire)) return false;
        std.debug.assert(self.handle == null);
        self.handle = handle;
        return true;
    }

    fn end(self: *ActiveConnection, handle: std.posix.socket_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handle == handle) self.handle = null;
    }

    fn interrupt(self: *ActiveConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handle) |handle| std.posix.shutdown(handle, .both) catch {};
    }

    fn isSet(self: *ActiveConnection) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.handle != null;
    }
};

fn run(state: *State) void {
    while (!state.stopping.load(.acquire)) {
        var fds = [_]std.posix.pollfd{.{
            .fd = state.server.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 50) catch return;
        if (ready == 0) continue;
        if (fds[0].revents & std.posix.POLL.IN == 0) continue;

        const connection = state.server.accept() catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return,
        };
        if (!state.active.begin(connection.stream.handle, &state.stopping)) {
            connection.stream.close();
            return;
        }
        serveConnection(state, connection);
        state.active.end(connection.stream.handle);
        connection.stream.close();
    }
}

fn serveConnection(state: *State, connection: std.net.Server.Connection) void {
    beginRequestObservation(state);
    var read_buffer: [max_request_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &read_buffer);
    var server = std.http.Server.init(connection, &read_buffer);
    var request = server.receiveHead() catch |err| {
        markRequestOutcome(state, .request_head_rejected);
        writeHeadError(connection.stream, err) catch {};
        return;
    };
    handleRequest(state, &request) catch {
        markRequestOutcome(state, .proxy_error);
        request.respond("upstream unavailable", .{
            .status = .bad_gateway,
            .keep_alive = false,
        }) catch {};
    };
}

fn writeHeadError(stream: std.net.Stream, err: anyerror) !void {
    if (err == error.HttpConnectionClosing or err == error.HttpRequestTruncated) return;
    if (err == error.HttpHeadersOversize) {
        try stream.writeAll(
            "HTTP/1.1 431 Request Header Fields Too Large\r\n" ++
                "Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    try stream.writeAll(
        "HTTP/1.1 400 Bad Request\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn handleRequest(state: *State, request: *std.http.Server.Request) !void {
    var arena = std.heap.ArenaAllocator.init(state.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var inbound = std.ArrayListUnmanaged(std.http.Header){};
    var iterator = request.iterateHeaders();
    while (iterator.next()) |header| try inbound.append(allocator, header);

    if (!validCapability(state.capability, inbound.items)) {
        markRequestOutcome(state, .capability_rejected);
        emitEvent(state, "claude_proxy_capability_rejected");
        try request.respond("unauthorized", .{
            .status = .unauthorized,
            .keep_alive = false,
        });
        return;
    }

    if (!validRequestOrigin(request, inbound.items, state.server.listen_address.getPort())) {
        markRequestOutcome(state, .origin_rejected);
        try request.respond("bad request", .{
            .status = .bad_request,
            .keep_alive = false,
        });
        return;
    }

    if (request.head.expect != null) {
        markRequestOutcome(state, .expectation_rejected);
        try request.respond("expectation failed", .{
            .status = .expectation_failed,
            .keep_alive = false,
        });
        return;
    }

    var forwarded_headers = std.ArrayListUnmanaged(std.http.Header){};
    try appendForwardingHeaders(allocator, inbound.items, &forwarded_headers);

    const body_reader = try request.reader();
    var body = readAllSensitiveAlloc(allocator, body_reader, max_request_body_bytes) catch |err| {
        if (err == error.StreamTooLong) {
            markRequestOutcome(state, .request_body_rejected);
            try request.respond("request too large", .{
                .status = .payload_too_large,
                .keep_alive = false,
            });
            return;
        }
        return err;
    };
    defer body.deinit();

    const captured_model = peekTopLevelModel(allocator, body.slice()) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            recordModelObservation(state, .{
                .had_body = body.slice().len != 0,
                .model_admission_rejected = true,
            });
            emitEvent(state, "claude_proxy_model_admission_rejected");
            try request.respond("model admission rejected", .{
                .status = .bad_request,
                .keep_alive = false,
            });
            return;
        },
    };

    switch (state.upstream) {
        .synthetic => try forwardRouted(state, request, allocator, forwarded_headers.items, body.slice(), captured_model),
        .production, .fake => try forwardOnce(state, request, allocator, forwarded_headers.items, body.slice(), captured_model),
    }
}

const ModelPeekError = error{
    ModelPeekUnparseable,
    ModelPeekMissing,
    ModelPeekDuplicate,
    ModelPeekNotString,
    ModelPeekTooLong,
    OutOfMemory,
};

fn scanNext(scanner: *std.json.Scanner, alloc: std.mem.Allocator) ModelPeekError!std.json.Token {
    // The scanner is built over the complete request body, already bounded by
    // `max_request_body_bytes`; malformed or truncated input refuses locally.
    return scanner.nextAlloc(alloc, .alloc_if_needed) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ModelPeekUnparseable,
    };
}

fn skipJsonValue(scanner: *std.json.Scanner, alloc: std.mem.Allocator) ModelPeekError!void {
    var depth: usize = 0;
    while (true) {
        switch (try scanNext(scanner, alloc)) {
            .object_begin, .array_begin => depth += 1,
            .object_end, .array_end => {
                if (depth == 0) return error.ModelPeekUnparseable;
                depth -= 1;
            },
            .end_of_document => return error.ModelPeekUnparseable,
            else => {},
        }
        if (depth == 0) return;
    }
}

/// Validates the complete bounded JSON document and returns its unique top-level
/// `model` string (program §2.2, ladder §8.2). Returns null for a bodyless
/// request. No family inference, alias, or substitution is performed.
fn peekTopLevelModel(alloc: std.mem.Allocator, body: []const u8) ModelPeekError!?[]const u8 {
    if (body.len == 0) return null;
    var scanner = std.json.Scanner.initCompleteInput(alloc, body);
    defer scanner.deinit();

    switch (try scanNext(&scanner, alloc)) {
        .object_begin => {},
        else => return error.ModelPeekUnparseable,
    }
    var model: ?[]const u8 = null;
    while (true) {
        const key: []const u8 = switch (try scanNext(&scanner, alloc)) {
            .object_end => {
                switch (try scanNext(&scanner, alloc)) {
                    .end_of_document => return model orelse error.ModelPeekMissing,
                    else => return error.ModelPeekUnparseable,
                }
            },
            .string => |s| s,
            .allocated_string => |s| s,
            else => return error.ModelPeekUnparseable,
        };
        if (std.mem.eql(u8, key, "model")) {
            if (model != null) return error.ModelPeekDuplicate;
            const value: []const u8 = switch (try scanNext(&scanner, alloc)) {
                .string => |s| s,
                .allocated_string => |s| s,
                else => return error.ModelPeekNotString,
            };
            if (value.len == 0) return error.ModelPeekNotString;
            if (value.len > max_model_len) return error.ModelPeekTooLong;
            model = try alloc.dupe(u8, value);
            continue;
        }
        try skipJsonValue(&scanner, alloc);
    }
}

const SensitiveBytes = struct {
    allocator: std.mem.Allocator,
    storage: []u8 = &.{},
    len: usize = 0,

    fn slice(self: *const SensitiveBytes) []const u8 {
        return self.storage[0..self.len];
    }

    fn grow(self: *SensitiveBytes, max_bytes: usize) !void {
        if (self.storage.len >= max_bytes) return error.StreamTooLong;
        const next_capacity = if (self.storage.len == 0)
            @min(max_bytes, 16 * 1024)
        else
            @min(max_bytes, self.storage.len * 2);
        const replacement = try self.allocator.alloc(u8, next_capacity);
        @memcpy(replacement[0..self.len], self.storage[0..self.len]);
        if (self.storage.len != 0) {
            std.crypto.secureZero(u8, self.storage);
            self.allocator.free(self.storage);
        }
        self.storage = replacement;
    }

    fn deinit(self: *SensitiveBytes) void {
        if (self.storage.len != 0) {
            std.crypto.secureZero(u8, self.storage);
            self.allocator.free(self.storage);
        }
        self.* = .{ .allocator = self.allocator };
    }
};

fn readAllSensitiveAlloc(
    allocator: std.mem.Allocator,
    reader: anytype,
    max_bytes: usize,
) !SensitiveBytes {
    var bytes = SensitiveBytes{ .allocator = allocator };
    errdefer bytes.deinit();
    while (true) {
        if (bytes.len == bytes.storage.len) {
            if (bytes.len == max_bytes) {
                var overflow_probe: [1]u8 = undefined;
                defer std.crypto.secureZero(u8, &overflow_probe);
                if (try reader.read(&overflow_probe) != 0) return error.StreamTooLong;
                break;
            }
            try bytes.grow(max_bytes);
        }
        const count = try reader.read(bytes.storage[bytes.len..]);
        if (count == 0) break;
        bytes.len += count;
    }
    return bytes;
}

fn emitEvent(state: *State, kind: []const u8) void {
    state.event_writer.print("{{\"kind\":\"{s}\"}}\n", .{kind}) catch {};
}

// ── §8.8 advisory-usage OBSERVATION (TIN-2400, observation-only) ───────────────
//
// This whole seam is READ-ONLY over the response: it runs AFTER the routing /
// retry / terminal decision is already made and stores only value-free normalized
// state. It can change no routing, election, or delivery — it exists so §8.8
// advisory behaviors are observable and test-pinned, nothing more.

/// The advisory clock in Unix SECONDS (the core's `now_s` grammar). It bridges
/// the injected `WireClock` (nanoseconds) the routed seam already uses, so a test
/// `VirtualClock` deterministically drives the freshness/negative-cache windows;
/// the single-attempt/production paths fall back to the real clock.
fn advisoryNowS(state: *State) i64 {
    const ns: i128 = switch (state.upstream) {
        .synthetic => |routing| routing.clock.now(),
        else => realNowNs(null),
    };
    return @intCast(@divFloor(ns, std.time.ns_per_s));
}

/// The advisory usage document carried by the `anthropic-ratelimit-usage` header,
/// or null when the response carries no advisory signal. Only the first
/// occurrence is considered; the value is the core's own synthetic JSON document.
fn findAdvisoryHeader(headers: []const std.http.Header) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, advisory_usage_header)) return header.value;
    }
    return null;
}

/// Direct request-path (reactive) evidence for the response status. A pre-body
/// 401/403/429 is a PROVEN exhaustion; a 2xx is proven availability. Any other
/// class (redirect, 5xx pass-through) yields no readiness evidence. `resets_at_s`
/// is an internal projection instant only — it is NEVER surfaced on the
/// observation, keeping the value-free rule intact.
fn reactiveFromStatus(status: std.http.Status, now_s: i64) ?advisory_usage.Reactive {
    return switch (@intFromEnum(status)) {
        401, 403, 429 => .{ .readiness = .exhausted, .resets_at_s = now_s +| 1 },
        200...299 => .{ .readiness = .available, .resets_at_s = now_s +| 1 },
        else => null,
    };
}

/// Fold one response's advisory signal through the pure core and produce the
/// value-free observation + at most one event. Mutates the per-account cache and
/// kill registry under `observation_mutex`; performs NO I/O (the caller emits the
/// returned event outside the lock).
fn computeAdvisoryOutcome(
    state: *State,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    status: std.http.Status,
    captured_model: ?[]const u8,
) AdvisoryOutcome {
    const now_s = advisoryNowS(state);
    const model_id = captured_model orelse "";

    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();

    var event: AdvisoryEvent = .none;
    var present = false;
    if (findAdvisoryHeader(headers)) |document| {
        present = true;
        var rows: [advisory_usage.MAX_ROWS]advisory_usage.Row = undefined;
        var excl: [advisory_usage.MAX_ROWS]advisory_usage.ExclusionReason = undefined;
        const parsed = advisory_usage.parseUsage(allocator, document, &rows, &excl);
        if (parsed.killed) {
            // One redacted event per distinct schema fingerprint, process-lifetime
            // — the registry dedupes even after the cache latches killed, so a
            // second DISTINCT shape still gets its own single event.
            if (parsed.fingerprint) |fp| {
                if (state.kill_registry.recordKill(fp) != null) event = .schema_rejected;
            }
        }
        state.advisory_cache.ingest(parsed, now_s);
    }

    // Query the per-account cache at `now_s` REGARDLESS of whether this response
    // carried a header: a fresh normalized window is honored by later requests,
    // and a stale window is rejected, without any re-fetch.
    const freshness = state.advisory_cache.freshness(now_s);
    const fresh_rows = state.advisory_cache.freshRows(now_s);
    const summary = advisory_usage.summarizeModel(fresh_rows, model_id, now_s);
    const advisory: ?advisory_usage.Advisory = switch (summary) {
        .advisory => |a| a,
        else => null, // none / contradiction → degrade to reactive
    };
    const reactive = reactiveFromStatus(status, now_s);

    const advisory_only = advisory_usage.elect(advisory, null, now_s);
    const elected = advisory_usage.elect(advisory, reactive, now_s);

    if (present and event == .none) {
        event = switch (freshness) {
            .populated_fresh => .observed,
            .populated_stale, .negative_active, .negative_expired => .stale,
            .never, .killed => .none,
        };
    }

    return .{
        .obs = .{
            .present = present,
            .freshness = freshness,
            .readiness = switch (summary) {
                .advisory => |a| a.readiness,
                else => .unknown,
            },
            .provenance = advisory_only.provenance,
            .killed = freshness == .killed,
            .reactive_present = reactive != null,
            .elected_readiness = elected.readiness,
            .elected_provenance = elected.provenance,
        },
        .event = event,
    };
}

fn emitAdvisoryEvent(state: *State, event: AdvisoryEvent) void {
    switch (event) {
        .none => {},
        .observed => emitEvent(state, "claude_proxy_advisory_observed"),
        .stale => emitEvent(state, "claude_proxy_advisory_stale"),
        .schema_rejected => emitEvent(state, "claude_proxy_advisory_schema_rejected"),
    }
}

/// Observe the response's advisory signal and write the value-free outcome onto a
/// caller-owned request observation (the routed path's local `obs`), then emit at
/// most one value-free event. Routing has already been decided; this only records.
fn observeAdvisoryOnObs(
    state: *State,
    obs: *RequestObservation,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    status: std.http.Status,
    captured_model: ?[]const u8,
) void {
    const outcome = computeAdvisoryOutcome(state, allocator, headers, status, captured_model);
    obs.advisory = outcome.obs;
    emitAdvisoryEvent(state, outcome.event);
}

/// Observe the response's advisory signal and write the value-free outcome onto
/// the shared `state.observation` (the single-attempt path, whose observation is
/// committed in place by `recordModelObservation`), then emit at most one event.
fn observeAdvisoryOnState(
    state: *State,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    status: std.http.Status,
    captured_model: ?[]const u8,
) void {
    const outcome = computeAdvisoryOutcome(state, allocator, headers, status, captured_model);
    state.observation_mutex.lock();
    state.observation.advisory = outcome.obs;
    state.observation_mutex.unlock();
    emitAdvisoryEvent(state, outcome.event);
}

fn validCapability(capability: *SessionCapability, headers: []const std.http.Header) bool {
    var authorization: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "authorization")) continue;
        if (authorization != null) return false;
        authorization = header.value;
    }
    const value = authorization orelse return false;
    const prefix = "Bearer ";
    if (value.len != prefix.len + capability_mod.carrier_len) return false;
    if (!std.ascii.eqlIgnoreCase(value[0 .. prefix.len - 1], "Bearer")) return false;
    if (value[prefix.len - 1] != ' ') return false;
    return capability.validate(value[prefix.len..]);
}

fn validRequestOrigin(
    request: *const std.http.Server.Request,
    headers: []const std.http.Header,
    port: u16,
) bool {
    if (request.head.version != .@"HTTP/1.1") return false;
    if (request.head.method == .CONNECT) return false;
    if (request.head.target.len == 0 or request.head.target[0] != '/') return false;
    if (std.mem.indexOfScalar(u8, request.head.target, '#') != null) return false;

    var host: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        if (host != null) return false;
        host = header.value;
    }
    const actual = host orelse return false;
    var expected_buffer: [32]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buffer, "127.0.0.1:{d}", .{port}) catch return false;
    return std.mem.eql(u8, actual, expected);
}

fn appendForwardingHeaders(
    allocator: std.mem.Allocator,
    inbound: []const std.http.Header,
    outbound: *std.ArrayListUnmanaged(std.http.Header),
) !void {
    for (inbound) |header| {
        if (stripRequestHeader(header.name, inbound)) continue;
        try outbound.append(allocator, header);
    }
}

fn stripRequestHeader(name: []const u8, headers: []const std.http.Header) bool {
    const fixed = [_][]const u8{
        "authorization",
        "accept-encoding",
        "x-api-key",
        "cookie",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "upgrade",
        "expect",
    };
    for (fixed) |blocked| {
        if (std.ascii.eqlIgnoreCase(name, blocked)) return true;
    }
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (commaSeparatedTokenContains(header.value, name)) return true;
    }
    return false;
}

fn commaSeparatedTokenContains(value: []const u8, wanted: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(token, wanted)) return true;
    }
    return false;
}

fn forwardOnce(
    state: *State,
    downstream: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    body: []const u8,
    captured_model: ?[]const u8,
) !void {
    const origin = switch (state.upstream) {
        .production => return error.ProductionCredentialInjectionNotImplemented,
        .fake => |upstream| upstream.baseUrl(),
        // Routed synthetic requests are dispatched to `forwardRouted`; the
        // single-attempt path is never entered for them.
        .synthetic => unreachable,
    };
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ origin, downstream.head.target });
    defer std.crypto.secureZero(u8, url);
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var response_head_buffer: [max_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_head_buffer);
    var upstream_request = try client.open(downstream.head.method, uri, .{
        .server_header_buffer = &response_head_buffer,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = .omit,
            .accept_encoding = .{ .override = "identity" },
            .connection = .{ .override = "close" },
        },
        .extra_headers = headers,
    });
    defer upstream_request.deinit();

    const upstream_connection = upstream_request.connection orelse return error.UpstreamConnectionMissing;
    const upstream_handle = upstream_connection.stream.handle;
    if (!state.upstream_active.begin(upstream_handle, &state.stopping)) {
        return error.ListenerStopping;
    }
    defer state.upstream_active.end(upstream_handle);

    if (body.len != 0) upstream_request.transfer_encoding = .{ .content_length = body.len };
    try upstream_request.send();
    if (body.len != 0) {
        try upstream_request.writeAll(body);
        try upstream_request.finish();
    }
    try upstream_request.wait();
    const upstream_status = upstream_request.response.status;
    recordModelObservation(state, .{
        .had_body = body.len != 0,
        .model_present = captured_model != null,
        .admitted_model = captured_model,
        .upstream_attempted = true,
        .upstream_status = @intFromEnum(upstream_status),
    });

    var all_response_headers = std.ArrayListUnmanaged(std.http.Header){};
    var response_iterator = upstream_request.response.iterateHeaders();
    while (response_iterator.next()) |header| {
        try all_response_headers.append(allocator, header);
    }

    var response_headers: [max_forwarded_response_headers]std.http.Header = undefined;
    var response_header_count: usize = 0;
    for (all_response_headers.items) |header| {
        if (stripResponseHeader(header.name, all_response_headers.items)) continue;
        if (response_header_count == response_headers.len) return error.ResponseHeadersOverflow;
        response_headers[response_header_count] = header;
        response_header_count += 1;
    }

    // §8.8 advisory-usage OBSERVATION (read-only; changes no routing decision).
    observeAdvisoryOnState(
        state,
        allocator,
        response_headers[0..response_header_count],
        upstream_status,
        captured_model,
    );

    if (upstream_status.class() == .redirect) {
        try downstream.respond("upstream redirect rejected", .{
            .status = .bad_gateway,
            .keep_alive = false,
        });
        return;
    }

    // Error responses remain buffered because 401/403/429 are future
    // pre-response decision points. Provider 5xx passes through unchanged to
    // Claude Code's native retry and never authorizes another account attempt.
    if (upstream_status.class() == .client_error or upstream_status.class() == .server_error) {
        var upstream_body = try readAllSensitiveAlloc(
            allocator,
            upstream_request.reader(),
            max_response_body_bytes,
        );
        defer upstream_body.deinit();
        if (upstream_status.class() == .server_error) {
            emitEvent(state, "claude_proxy_upstream_server_error");
        }
        try downstream.respond(upstream_body.slice(), .{
            .status = upstream_status,
            .keep_alive = false,
            .extra_headers = response_headers[0..response_header_count],
        });
        return;
    }

    if (responseHasNoBody(downstream, upstream_status)) {
        downstream.respond("", .{
            .status = upstream_status,
            .keep_alive = false,
            .extra_headers = response_headers[0..response_header_count],
            .transfer_encoding = .none,
        }) catch {
            emitEvent(state, "claude_proxy_client_disconnected");
        };
        return;
    }

    streamUpstreamResponse(
        state,
        downstream,
        &upstream_request,
        response_headers[0..response_header_count],
    );
}

fn responseHasNoBody(request: *const std.http.Server.Request, status: std.http.Status) bool {
    return request.head.method == .HEAD or switch (@intFromEnum(status)) {
        100...199, 204, 205, 304 => true,
        else => false,
    };
}

fn streamUpstreamResponse(
    state: *State,
    downstream: *std.http.Server.Request,
    upstream: *std.http.Client.Request,
    headers: []const std.http.Header,
) void {
    var send_buffer: [max_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &send_buffer);
    var response = downstream.respondStreaming(.{
        .send_buffer = &send_buffer,
        .content_length = upstream.response.content_length,
        .respond_options = .{
            .status = upstream.response.status,
            .keep_alive = false,
            .extra_headers = headers,
        },
    });
    response.flush() catch {
        emitEvent(state, "claude_proxy_client_disconnected");
        return;
    };

    var body_buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &body_buffer);
    var body_reader = upstream.reader();
    var streamed: u64 = 0;
    while (true) {
        const count = body_reader.read(&body_buffer) catch |err| {
            if (err == error.EndOfStream and
                upstream.response.transfer_encoding == .none and
                upstream.response.content_length == null)
            {
                // Close-delimited upstream framing cannot distinguish a clean
                // EOF from truncation. The fixed Anthropic path requests
                // identity encoding and normally receives length or chunked
                // framing; retain this protocol-compatible fallback without
                // promoting it as completeness evidence.
                response.end() catch {
                    emitEvent(state, "claude_proxy_client_disconnected");
                };
                return;
            }
            emitEvent(state, "claude_proxy_upstream_interrupted");
            return;
        };
        if (count == 0) {
            // Zig 0.14.1 normalizes premature EOF while parsing chunked bodies
            // to a zero-byte read, but leaves the parser in its unfinished
            // chunk state. Only `.finished` proves the terminal chunk/trailers.
            if (upstream.response.transfer_encoding == .chunked and
                upstream.response.parser.state != .finished)
            {
                emitEvent(state, "claude_proxy_upstream_interrupted");
                return;
            }
            if (upstream.response.content_length) |expected| {
                if (streamed != expected) {
                    emitEvent(state, "claude_proxy_upstream_interrupted");
                    return;
                }
            }
            response.end() catch {
                emitEvent(state, "claude_proxy_client_disconnected");
                return;
            };
            return;
        }
        response.writeAll(body_buffer[0..count]) catch {
            emitEvent(state, "claude_proxy_client_disconnected");
            return;
        };
        response.flush() catch {
            emitEvent(state, "claude_proxy_client_disconnected");
            return;
        };
        streamed += count;
    }
}

fn stripResponseHeader(name: []const u8, headers: []const std.http.Header) bool {
    const blocked = [_][]const u8{
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    };
    for (blocked) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (commaSeparatedTokenContains(header.value, name)) return true;
    }
    return false;
}

// ===========================================================================
// §2.2 single-alternate retry state machine (synthetic test seam only).
//
// STRUCTURAL two-attempt bound (why a third attempt cannot execute):
//   * `forwardRouted` calls `performAttempt(.first)` EXACTLY ONCE and has no
//     loop and no recursion.
//   * The single follow-up ALWAYS routes through `attemptSecondTerminal`, which
//     returns `void`, forces role `.second`, and calls `performAttempt(.second)`
//     EXACTLY ONCE. Role `.second` never surfaces `.transport_failed_presend`
//     (a role-`.second` pre-send failure is delivered as a terminal 502); the
//     only disposition it can hand back is `.pre_body_reauth`, which
//     `attemptSecondTerminal` DELIVERS terminally — as the single-identity
//     reauth (same-route form) or the composed all-exhausted 429 (alternate
//     form) — with no re-dispatch.
//   * No path calls `forwardRouted` or `performAttempt` a third time, so control
//     never re-enters the attempt machinery after the second attempt.
//   * The `RetrySlot` value asserts single consumption, and
//     `commitObservation` asserts `attempts_total <= 2`,
//     `third_attempt_count == 0`, and never-both-forms. Breaking the structural
//     bound trips one of these before the wire ever carries a third request.
// ===========================================================================

const ReplayMode = enum { replayable, stream_once };

/// One-way replay-eligibility latch for a single request. It begins
/// `replayable`; the ONLY transition moves it to `stream_once`. No method
/// restores `replayable`, so a request that loses replay eligibility
/// (reservation miss, oversize/length-unknown body over the per-request cap)
/// can never regain it within its lifetime.
const ReplayLatch = struct {
    mode: ReplayMode = .replayable,

    fn latchStreamOnce(self: *ReplayLatch) void {
        self.mode = .stream_once; // monotonic: never assigns `.replayable`
    }

    fn isReplayable(self: ReplayLatch) bool {
        return self.mode == .replayable;
    }
};

/// Per-sidecar replay reservation pool (§2.2). Atomic so the accounting stays
/// coherent under a concurrent sidecar fleet. The 256 MiB per-HOST ceiling is
/// DEFERRED (needs cross-process shared state that does not exist here).
const Reservation = struct {
    reserved: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    budget_bytes: usize = default_reservation_budget_bytes,

    /// Reserves `n` bytes if the pool has room; returns false otherwise. A CAS
    /// loop keeps the invariant `reserved <= budget_bytes` under concurrency.
    fn reserve(self: *Reservation, n: usize) bool {
        var current = self.reserved.load(.monotonic);
        while (true) {
            const next = current + n;
            if (next > self.budget_bytes) return false;
            if (self.reserved.cmpxchgWeak(current, next, .acq_rel, .monotonic)) |actual| {
                current = actual;
            } else {
                return true;
            }
        }
    }

    fn release(self: *Reservation, n: usize) void {
        if (n == 0) return;
        _ = self.reserved.fetchSub(n, .acq_rel);
    }

    fn outstanding(self: *Reservation) usize {
        return self.reserved.load(.acquire);
    }
};

/// Releases a replay reservation EXACTLY ONCE. `release` is idempotent through
/// `released` and is the only site that returns bytes to the pool for a
/// request, so completion, cancellation, error, and teardown all converge on a
/// single release via `defer`.
const ReservationGuard = struct {
    reservation: *Reservation,
    amount: usize,
    released: bool = false,

    fn release(self: *ReservationGuard) void {
        if (self.released) return;
        self.released = true;
        self.reservation.release(self.amount);
    }
};

/// The single retry entitlement for one request. Minted once and consumed at
/// most once; `consume` asserts single use. It cannot be re-armed, so together
/// with the void-returning follow-up it makes a third attempt unrepresentable.
const RetrySlot = struct {
    state: enum { available, consumed } = .available,

    fn consume(self: *RetrySlot) void {
        std.debug.assert(self.state == .available); // double-consume is a bug
        self.state = .consumed;
    }
};

const SecondForm = enum { same_route_retry, alternate };
const AttemptRole = enum { first, second };

/// A completely buffered upstream response captured before any downstream byte.
/// Headers and body are duped into the request arena so they outlive the
/// upstream request that produced them.
const BufferedResponse = struct {
    status: std.http.Status,
    headers: []const std.http.Header,
    body: []const u8,
};

const AttemptResult = union(enum) {
    /// Zero request bytes were written upstream (proven: no socket write ran).
    /// Produced ONLY by role `.first` — the same-route retry entitlement. Role
    /// `.second` delivers a pre-send failure as a terminal 502 instead.
    transport_failed_presend,
    /// A pre-body 401/403/429 buffered in full before any downstream byte. Role
    /// `.first` uses it to elect a distinct-identity alternate. Role `.second`
    /// surfaces it as a TERMINAL hand-back that `attemptSecondTerminal` delivers
    /// without re-dispatch — the composed all-exhausted 429 (alternate form) or
    /// the single-identity reauth (same-route form).
    pre_body_reauth: BufferedResponse,
    /// A 2xx response was delivered/streamed downstream. Terminal.
    delivered_success,
    /// A non-2xx response, or an ambiguous/partial/pre-send failure, was
    /// delivered downstream. Terminal — never replayed.
    delivered_failure,
};

/// A test-seam synthetic route: a distinct-identity credential and its fake
/// upstream target. The bearer is a synthetic test-only token, never a real
/// provider credential.
const Route = struct {
    upstream: *FakeUpstream,
    bearer: ?[]const u8,
    identity: []const u8,
    presend_faults: usize,

    /// Consumes one injected transient pre-send transport fault, if any remain.
    /// Called only from the single listener serve thread (connections are
    /// served sequentially), so the decrement needs no atomic.
    fn takePresendFault(self: *Route) bool {
        if (self.presend_faults == 0) return false;
        self.presend_faults -= 1;
        return true;
    }
};

const SyntheticRouting = struct {
    primary: Route,
    alternate: ?Route,
    reservation_budget_bytes: usize,
    request_deadline_ns: u64,
    max_wait_ns: u64,
    clock: WireClock,
};

/// Injected clock (house style: fn-pointer + opaque ctx, default real). The
/// production alternate path is disabled, so `realSleepNs` never runs in the
/// shipped binary; tests supply a virtual clock that advances without sleeping.
const WireClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i128 = realNowNs,
    sleepFn: *const fn (ctx: ?*anyopaque, ns: u64) void = realSleepNs,

    fn now(self: WireClock) i128 {
        return self.nowFn(self.ctx);
    }

    fn sleep(self: WireClock, ns: u64) void {
        self.sleepFn(self.ctx, ns);
    }
};

fn realNowNs(_: ?*anyopaque) i128 {
    return std.time.nanoTimestamp();
}

fn realSleepNs(_: ?*anyopaque, ns: u64) void {
    std.time.sleep(ns);
}

fn setObsModel(obs: *RequestObservation, model: ?[]const u8) void {
    if (model) |m| {
        const n = @min(m.len, max_model_len);
        @memcpy(obs.admitted_model_buf[0..n], m[0..n]);
        obs.admitted_model_len = n;
    }
}

/// Commits the request observation, asserting the §2.2 invariants that the
/// retry state machine must uphold. A structural break (a third attempt, or
/// both consumption forms firing) trips an assertion here.
fn commitObservation(state: *State, obs: RequestObservation) void {
    std.debug.assert(obs.attempts_total <= 2);
    std.debug.assert(obs.third_attempt_count == 0);
    std.debug.assert(!(obs.same_route_retry_count != 0 and obs.alternate_count != 0));
    var committed = obs;
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    committed.request_id = state.observation.request_id;
    if (committed.outcome == .none) {
        committed.outcome = if (committed.model_admission_rejected)
            .model_admission_rejected
        else if (committed.upstream_attempted)
            .upstream_response
        else
            .proxy_error;
    }
    state.observation = committed;
}

/// Delivers a fully buffered response downstream as-is.
fn deliverBuffered(downstream: *std.http.Server.Request, buffered: BufferedResponse) void {
    downstream.respond(buffered.body, .{
        .status = buffered.status,
        .keep_alive = false,
        .extra_headers = buffered.headers,
    }) catch {};
}

/// Buffers a complete upstream response (status + stripped headers + body) into
/// the request arena so the dispatcher can decide on an alternate before any
/// downstream byte is emitted.
fn bufferResponse(
    allocator: std.mem.Allocator,
    upstream_request: *std.http.Client.Request,
    status: std.http.Status,
) !BufferedResponse {
    var all = std.ArrayListUnmanaged(std.http.Header){};
    var iterator = upstream_request.response.iterateHeaders();
    while (iterator.next()) |header| try all.append(allocator, header);

    var kept = std.ArrayListUnmanaged(std.http.Header){};
    for (all.items) |header| {
        if (stripResponseHeader(header.name, all.items)) continue;
        if (kept.items.len == max_forwarded_response_headers) return error.ResponseHeadersOverflow;
        try kept.append(allocator, .{
            .name = try allocator.dupe(u8, header.name),
            .value = try allocator.dupe(u8, header.value),
        });
    }

    var raw = try readAllSensitiveAlloc(allocator, upstream_request.reader(), max_response_body_bytes);
    const owned = try allocator.dupe(u8, raw.slice());
    raw.deinit();
    return .{ .status = status, .headers = kept.items, .body = owned };
}

fn sendUpstream(upstream_request: *std.http.Client.Request, body: []const u8) !void {
    try upstream_request.send();
    if (body.len != 0) {
        try upstream_request.writeAll(body);
        try upstream_request.finish();
    }
    try upstream_request.wait();
}

/// A pre-send failure means zero request bytes reached the wire. For the first
/// attempt this is the same-route retry entitlement; for the terminal second
/// attempt it is delivered as a failure with no further attempt.
fn presendOutcome(
    downstream: *std.http.Server.Request,
    role: AttemptRole,
) AttemptResult {
    switch (role) {
        .first => return .transport_failed_presend,
        .second => {
            downstream.respond("upstream transport failure", .{
                .status = .bad_gateway,
                .keep_alive = false,
            }) catch {};
            return .delivered_failure;
        },
    }
}

/// An ambiguous/partial send (a request byte may have reached the wire) is
/// TERMINAL for both roles: §2.2 forbids replaying it. It is never surfaced as
/// a retry entitlement.
fn ambiguousOutcome(downstream: *std.http.Server.Request) AttemptResult {
    downstream.respond("upstream send failed", .{
        .status = .bad_gateway,
        .keep_alive = false,
    }) catch {};
    return .delivered_failure;
}

/// One upstream attempt against `route`. Both roles DEFER a pre-body 401/403/429
/// to the dispatcher (returning `.pre_body_reauth` without emitting any
/// downstream byte); role `.first` additionally defers a proven pre-send
/// transport failure (`.transport_failed_presend`). Role `.second` never defers
/// a transport failure — it delivers one as a terminal 502 — and its
/// `.pre_body_reauth` hand-back is delivered terminally by
/// `attemptSecondTerminal` with no re-dispatch, so the request stays bounded to
/// two attempts.
fn performAttempt(
    state: *State,
    downstream: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    route: *Route,
    headers: []const std.http.Header,
    body: []const u8,
    captured_model: ?[]const u8,
    role: AttemptRole,
    obs: *RequestObservation,
) !AttemptResult {
    obs.attempts_total += 1;

    // Injected/real pre-send transport failure. The synthetic fault fires
    // BEFORE any socket operation, so "zero request bytes written upstream" is
    // structurally true, not inferred from an error code. A real connect()
    // failure reaches the identical `presendOutcome` branch below with
    // `wrote_any` still false, so one invariant governs both.
    if (route.takePresendFault()) {
        return presendOutcome(downstream, role);
    }

    const origin = route.upstream.baseUrl();
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ origin, downstream.head.target });
    defer std.crypto.secureZero(u8, url);
    const uri = try std.Uri.parse(url);

    // Synthetic route credential injection. In production this seam is where a
    // real bearer would attach; here it is a synthetic test-only token, and the
    // whole routed machine is unreachable outside `builtin.is_test`.
    const auth_value: ?[]const u8 = if (route.bearer) |bearer|
        try std.fmt.allocPrint(allocator, "Bearer {s}", .{bearer})
    else
        null;
    defer if (auth_value) |v| std.crypto.secureZero(u8, @constCast(v));

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var response_head_buffer: [max_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_head_buffer);

    var upstream_request = client.open(downstream.head.method, uri, .{
        .server_header_buffer = &response_head_buffer,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = if (auth_value) |v| .{ .override = v } else .omit,
            .accept_encoding = .{ .override = "identity" },
            .connection = .{ .override = "close" },
        },
        .extra_headers = headers,
    }) catch {
        // The connection could not be opened: no request byte was written.
        return presendOutcome(downstream, role);
    };
    defer upstream_request.deinit();

    const upstream_connection = upstream_request.connection orelse
        return presendOutcome(downstream, role);
    const upstream_handle = upstream_connection.stream.handle;
    if (!state.upstream_active.begin(upstream_handle, &state.stopping)) {
        // Listener is tearing down; treat as terminal (never a retry).
        return ambiguousOutcome(downstream);
    }
    defer state.upstream_active.end(upstream_handle);

    if (body.len != 0) upstream_request.transfer_encoding = .{ .content_length = body.len };
    // From here a request byte may reach the wire; any failure is ambiguous and
    // is never replayed.
    sendUpstream(&upstream_request, body) catch {
        return ambiguousOutcome(downstream);
    };

    const upstream_status = upstream_request.response.status;
    // Attempt 2 re-runs admission on the SAME bytes: `captured_model` is the
    // byte-identical model already admitted for attempt 1 (same buffer), so no
    // model substitution can occur across the retry.
    obs.had_body = body.len != 0;
    obs.model_present = captured_model != null;
    setObsModel(obs, captured_model);
    obs.upstream_attempted = true;
    obs.upstream_status = @intFromEnum(upstream_status);

    if (upstream_status.class() == .redirect) {
        downstream.respond("upstream redirect rejected", .{
            .status = .bad_gateway,
            .keep_alive = false,
        }) catch {};
        return .delivered_failure;
    }

    const is_reauth = switch (@intFromEnum(upstream_status)) {
        401, 403, 429 => true,
        else => false,
    };

    if (upstream_status.class() == .client_error or upstream_status.class() == .server_error) {
        if (upstream_status.class() == .server_error) {
            emitEvent(state, "claude_proxy_upstream_server_error");
        }
        const buffered = try bufferResponse(allocator, &upstream_request, upstream_status);
        // §8.8 advisory OBSERVATION on the buffered error head. For a pre-body
        // 401/403/429 this is where reactive exhaustion evidence is proven, so the
        // election here demonstrates reactive outranking advisory. Read-only:
        // buffering, the reauth decision, and delivery are all unchanged.
        observeAdvisoryOnObs(state, obs, allocator, buffered.headers, upstream_status, captured_model);
        // A pre-body 401/403/429 is DEFERRED to the dispatcher for BOTH roles,
        // without emitting any downstream byte. Role `.first` uses it to elect a
        // distinct-identity alternate; role `.second` uses it to compose the
        // bounded all-exhausted terminal (both identities failed pre-body) or,
        // for a same-route retry, to deliver the single identity's own reauth.
        // Neither path re-dispatches, so the two-attempt bound holds. Non-reauth
        // 4xx and all 5xx are delivered as-is and never authorize a cross-account
        // attempt.
        if (is_reauth) {
            return .{ .pre_body_reauth = buffered };
        }
        deliverBuffered(downstream, buffered);
        return .delivered_failure;
    }

    // 2xx: stream head-first. Once respondStreaming runs, replay is impossible.
    var all_response_headers = std.ArrayListUnmanaged(std.http.Header){};
    var response_iterator = upstream_request.response.iterateHeaders();
    while (response_iterator.next()) |header| {
        try all_response_headers.append(allocator, header);
    }
    var response_headers: [max_forwarded_response_headers]std.http.Header = undefined;
    var response_header_count: usize = 0;
    for (all_response_headers.items) |header| {
        if (stripResponseHeader(header.name, all_response_headers.items)) continue;
        if (response_header_count == response_headers.len) return error.ResponseHeadersOverflow;
        response_headers[response_header_count] = header;
        response_header_count += 1;
    }

    // §8.8 advisory-usage OBSERVATION on the 2xx head, before any downstream byte
    // (read-only; the streaming/no-body delivery below is unchanged).
    observeAdvisoryOnObs(state, obs, allocator, response_headers[0..response_header_count], upstream_status, captured_model);

    if (responseHasNoBody(downstream, upstream_status)) {
        downstream.respond("", .{
            .status = upstream_status,
            .keep_alive = false,
            .extra_headers = response_headers[0..response_header_count],
            .transfer_encoding = .none,
        }) catch {
            emitEvent(state, "claude_proxy_client_disconnected");
        };
        return .delivered_success;
    }

    streamUpstreamResponse(
        state,
        downstream,
        &upstream_request,
        response_headers[0..response_header_count],
    );
    return .delivered_success;
}

/// The single follow-up attempt. It returns `void`, forces role `.second`, and
/// never re-enters the dispatcher, so a third attempt is unrepresentable. When
/// the second attempt is itself a pre-body reauth, `primary_reauth` (the route-1
/// buffered reauth, supplied only for the `.alternate` form) lets it compose the
/// bounded all-exhausted terminal.
fn attemptSecondTerminal(
    state: *State,
    downstream: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    route: *Route,
    headers: []const std.http.Header,
    body: []const u8,
    captured_model: ?[]const u8,
    form: SecondForm,
    obs: *RequestObservation,
    primary_reauth: ?BufferedResponse,
) void {
    switch (form) {
        .same_route_retry => obs.same_route_retry_count += 1,
        .alternate => obs.alternate_count += 1,
    }
    const result = performAttempt(
        state,
        downstream,
        allocator,
        route,
        headers,
        body,
        captured_model,
        .second,
        obs,
    ) catch {
        downstream.respond("upstream unavailable", .{
            .status = .bad_gateway,
            .keep_alive = false,
        }) catch {};
        emitEvent(state, "claude_proxy_slot_exhausted");
        return;
    };
    switch (form) {
        .same_route_retry => emitEvent(state, "claude_proxy_retry_consumed"),
        .alternate => emitEvent(state, "claude_proxy_alternate_consumed"),
    }
    switch (result) {
        .delivered_success => {},
        .delivered_failure => emitEvent(state, "claude_proxy_slot_exhausted"),
        .pre_body_reauth => |second_buffered| switch (form) {
            // A same-route retry that itself returns a pre-body 401/403/429 means
            // ONE identity was contacted twice: deliver its own response as-is
            // (no cross-account claim). This is a terminal delivery, not a
            // further attempt.
            .same_route_retry => {
                deliverBuffered(downstream, second_buffered);
                emitEvent(state, "claude_proxy_slot_exhausted");
            },
            // BOTH distinct identities failed pre-body: the bounded all-exhausted
            // terminal. It composes the minimum trusted Retry-After across the
            // two routes and DELIVERS ONLY — no re-dispatch, so the two-attempt
            // bound holds.
            .alternate => deliverAllExhausted(
                state,
                downstream,
                if (primary_reauth) |pr| pr.headers else second_buffered.headers,
                second_buffered.headers,
                obs.attempts_total,
            ),
        },
        // Role `.second` never surfaces a same-route transport-retry entitlement:
        // `presendOutcome(.second)` delivers a terminal 502 instead.
        .transport_failed_presend => unreachable,
    }
}

/// Returns the distinct-identity alternate, `null` when none is configured, or
/// a typed refusal when the configured alternate shares the primary identity.
fn selectAlternate(routing: *SyntheticRouting) error{SameIdentityAlternate}!?*Route {
    if (routing.alternate) |*alternate| {
        if (std.mem.eql(u8, alternate.identity, routing.primary.identity)) {
            return error.SameIdentityAlternate;
        }
        return alternate;
    }
    return null;
}

const WaitDecision = enum { proceed, exceeds_bound };

/// §2.2 / §8.4 bounded single pre-alternate wait. Called at most once per
/// request. Waits only when the trusted reset fits BOTH the 30-second maximum
/// and the remaining request deadline; otherwise returns a typed local 429.
fn waitBeforeAlternate(
    routing: *SyntheticRouting,
    start_ns: i128,
    retry_after_ns: u64,
) WaitDecision {
    if (retry_after_ns == 0) return .proceed; // no trusted reset (401/403)
    const now = routing.clock.now();
    const elapsed_raw = now - start_ns;
    const elapsed: u64 = if (elapsed_raw <= 0)
        0
    else
        @intCast(@min(elapsed_raw, @as(i128, std.math.maxInt(u64))));
    const remaining: u64 = if (routing.request_deadline_ns > elapsed)
        routing.request_deadline_ns - elapsed
    else
        0;
    if (retry_after_ns > routing.max_wait_ns) return .exceeds_bound;
    if (retry_after_ns > remaining) return .exceeds_bound;
    routing.clock.sleep(retry_after_ns); // injected; virtual advance in tests
    return .proceed;
}

fn retryAfterNs(headers: []const std.http.Header) u64 {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "retry-after")) continue;
        const trimmed = std.mem.trim(u8, header.value, " \t");
        const seconds = std.fmt.parseInt(u64, trimmed, 10) catch return 0;
        return std.math.mul(u64, seconds, std.time.ns_per_s) catch std.math.maxInt(u64);
    }
    return 0;
}

/// Parses a `Retry-After` value for downstream PROPAGATION in the bounded
/// all-exhausted terminal (ladder G10 "trusted Retry-After where available, no
/// invented capacity"). Returns the delta-seconds ONLY when the provider
/// supplied a well-formed, representable value; returns null for an absent,
/// empty, non-numeric, signed, or arithmetically huge value. A null contributes
/// nothing to the propagated bound, so a malformed reset is never echoed and no
/// capacity is invented. Only the first occurrence is considered.
fn trustedRetryAfterSeconds(headers: []const std.http.Header) ?u64 {
    var raw: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "retry-after")) continue;
        raw = header.value;
        break;
    }
    const value = raw orelse return null;
    const trimmed = std.mem.trim(u8, value, " \t");
    if (trimmed.len == 0) return null;
    // Digits only: rejects a leading sign, an HTTP-date, and embedded spaces.
    for (trimmed) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    const seconds = std.fmt.parseInt(u64, trimmed, 10) catch return null; // > u64 → huge
    // Require nanosecond-representability so "huge" is a principled bound, not an
    // arbitrary business ceiling: a value that cannot be represented is ignored.
    _ = std.math.mul(u64, seconds, std.time.ns_per_s) catch return null;
    return seconds;
}

/// The MINIMUM trusted `Retry-After` across the two exhausted routes, or null
/// when neither supplied a well-formed one. MIN — not MAX — is the honest bound
/// (ladder G10): it is the earliest time at which SOME route may regain
/// capacity. MAX would report the earliest time BOTH routes could be retried,
/// telling the harness to wait longer than any single route requires and
/// inventing scarcity. MIN never tells the harness to retry before any
/// provider's own reset, so it invents no capacity either.
fn minTrustedRetryAfterSeconds(
    a: []const std.http.Header,
    b: []const std.http.Header,
) ?u64 {
    const va = trustedRetryAfterSeconds(a);
    const vb = trustedRetryAfterSeconds(b);
    if (va) |x| {
        if (vb) |y| return @min(x, y);
        return x;
    }
    return vb;
}

/// Emits the typed all-exhausted event with bounded counts only (no bodies,
/// headers, or credential material): the total upstream attempts made and
/// whether a trusted reset was propagated.
fn emitAllExhausted(state: *State, attempts_total: usize, retry_after_present: bool) void {
    state.event_writer.print(
        "{{\"kind\":\"claude_proxy_all_exhausted\",\"attempts_total\":{d},\"retry_after_present\":{}}}\n",
        .{ attempts_total, retry_after_present },
    ) catch {};
}

/// The bounded all-exhausted terminal (plan §7, ladder G10): both distinct
/// identities failed pre-body, so no eligible route can serve. Delivers ONE
/// typed 429 — never a synthetic 200, never a fabricated reset — carrying the
/// minimum trusted `Retry-After` when any route supplied one. It makes ZERO
/// further upstream attempts: it only formats a downstream response and emits
/// the typed event.
fn deliverAllExhausted(
    state: *State,
    downstream: *std.http.Server.Request,
    first_headers: []const std.http.Header,
    second_headers: []const std.http.Header,
    attempts_total: usize,
) void {
    if (minTrustedRetryAfterSeconds(first_headers, second_headers)) |secs| {
        var buffer: [24]u8 = undefined;
        if (std.fmt.bufPrint(&buffer, "{d}", .{secs})) |rendered| {
            downstream.respond("all upstream identities exhausted; retry later", .{
                .status = .too_many_requests,
                .keep_alive = false,
                .extra_headers = &.{.{ .name = "Retry-After", .value = rendered }},
            }) catch {};
            emitAllExhausted(state, attempts_total, true);
            return;
        } else |_| {}
    }
    downstream.respond("all upstream identities exhausted; retry later", .{
        .status = .too_many_requests,
        .keep_alive = false,
    }) catch {};
    emitAllExhausted(state, attempts_total, false);
}

fn deliverLocal429(
    downstream: *std.http.Server.Request,
    source_headers: []const std.http.Header,
) void {
    var retry_after: ?[]const u8 = null;
    for (source_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) retry_after = header.value;
    }
    if (retry_after) |value| {
        downstream.respond("rate limited; retry later", .{
            .status = .too_many_requests,
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "Retry-After", .value = value }},
        }) catch {};
    } else {
        downstream.respond("rate limited; retry later", .{
            .status = .too_many_requests,
            .keep_alive = false,
        }) catch {};
    }
}

/// §2.2 routed forwarding: at most two upstream attempts, one shared retry slot.
fn forwardRouted(
    state: *State,
    downstream: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    body: []const u8,
    captured_model: ?[]const u8,
) !void {
    const routing = switch (state.upstream) {
        .synthetic => |r| r,
        else => unreachable,
    };

    var obs = RequestObservation{
        .had_body = body.len != 0,
        .model_present = captured_model != null,
    };
    setObsModel(&obs, captured_model);

    // §2.2 replay reservation. Reserve the buffered body against the per-sidecar
    // pool BEFORE attempt 1. A reservation miss (pool exhausted, or a body
    // larger than the sidecar budget) IRREVOCABLY latches the request to
    // stream-once: a single attempt with no alternate and no same-route replay.
    var latch = ReplayLatch{};
    const reserved_ok = state.reservation.reserve(body.len);
    if (!reserved_ok) {
        latch.latchStreamOnce();
        emitEvent(state, "claude_proxy_stream_once");
    }
    var guard = ReservationGuard{
        .reservation = &state.reservation,
        .amount = if (reserved_ok) body.len else 0,
    };
    // Exactly-once release on completion, cancellation, error, and teardown.
    defer guard.release();
    obs.replay_mode = latch.mode;

    const start_ns = routing.clock.now();

    // The single retry entitlement for this request.
    var slot = RetrySlot{};

    const first = try performAttempt(
        state,
        downstream,
        allocator,
        &routing.primary,
        headers,
        body,
        captured_model,
        .first,
        &obs,
    );
    commitObservation(state, obs);

    switch (first) {
        .delivered_success, .delivered_failure => return,
        .transport_failed_presend => {
            // §2.2: a proven pre-send transport failure consumes the ONE
            // same-route retry, and ONLY when the body is replayable. It NEVER
            // authorizes a cross-account attempt.
            if (!latch.isReplayable()) {
                emitEvent(state, "claude_proxy_slot_exhausted");
                downstream.respond("upstream transport failure", .{
                    .status = .bad_gateway,
                    .keep_alive = false,
                }) catch {};
                return;
            }
            slot.consume();
            attemptSecondTerminal(
                state,
                downstream,
                allocator,
                &routing.primary,
                headers,
                body,
                captured_model,
                .same_route_retry,
                &obs,
                null,
            );
            commitObservation(state, obs);
            return;
        },
        .pre_body_reauth => |buffered| {
            const alternate = selectAlternate(routing) catch {
                // Same-identity-only pool: no eligible DISTINCT identity exists,
                // so the distinct-identity pool is exhausted. Keep the typed
                // refusal — deliver route 1's own pre-body result, which already
                // carries its own trusted Retry-After — and emit the uniform
                // all-exhausted terminal event.
                obs.same_identity_alternate_refused = true;
                emitEvent(state, "claude_proxy_same_identity_alternate_refused");
                deliverBuffered(downstream, buffered);
                emitAllExhausted(state, obs.attempts_total, trustedRetryAfterSeconds(buffered.headers) != null);
                commitObservation(state, obs);
                return;
            } orelse {
                // No alternate configured: route 1's pre-body result is the
                // single-route bounded terminal. Uniform all-exhausted event.
                deliverBuffered(downstream, buffered);
                emitAllExhausted(state, obs.attempts_total, trustedRetryAfterSeconds(buffered.headers) != null);
                commitObservation(state, obs);
                return;
            };
            if (!latch.isReplayable()) {
                // Stream-once degradation (not identity exhaustion): the body
                // could not be reserved for replay, so the eligible alternate is
                // never contacted. Distinct terminal — NOT all-exhausted.
                emitEvent(state, "claude_proxy_slot_exhausted");
                deliverBuffered(downstream, buffered);
                return;
            }
            switch (waitBeforeAlternate(routing, start_ns, retryAfterNs(buffered.headers))) {
                .proceed => {},
                .exceeds_bound => {
                    emitEvent(state, "claude_proxy_local_rate_limited");
                    deliverLocal429(downstream, buffered.headers);
                    return;
                },
            }
            slot.consume();
            attemptSecondTerminal(
                state,
                downstream,
                allocator,
                alternate,
                headers,
                body,
                captured_model,
                .alternate,
                &obs,
                buffered,
            );
            commitObservation(state, obs);
            return;
        },
    }
}

fn copyCarrier(capability: *SessionCapability) ![capability_mod.carrier_len]u8 {
    var carrier: [capability_mod.carrier_len]u8 = undefined;
    try capability.copyCarrier(&carrier);
    return carrier;
}

fn requestRawAlloc(
    allocator: std.mem.Allocator,
    address: std.net.Address,
    bytes: []const u8,
) ![]u8 {
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(bytes);

    var response = std.ArrayList(u8).init(allocator);
    errdefer response.deinit();
    var buffer: [1024]u8 = undefined;
    while (true) {
        const count = try stream.read(&buffer);
        if (count == 0) break;
        try response.appendSlice(buffer[0..count]);
    }
    return response.toOwnedSlice();
}

fn expectStatus(response: []const u8, status_line: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, response, status_line));
}

test "sensitive reader grows without realloc and rejects overflow" {
    var payload: [20 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var payload_stream = std.io.fixedBufferStream(&payload);
    var bytes = try readAllSensitiveAlloc(
        std.testing.allocator,
        payload_stream.reader(),
        32 * 1024,
    );
    defer bytes.deinit();
    try std.testing.expectEqualSlices(u8, &payload, bytes.slice());

    var overflow_stream = std.io.fixedBufferStream(&payload);
    try std.testing.expectError(
        error.StreamTooLong,
        readAllSensitiveAlloc(std.testing.allocator, overflow_stream.reader(), 16 * 1024),
    );
}

test "valid capability reaches only the fake upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "accepted",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\naccepted"));
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "missing malformed and wrong capabilities return 401 with zero upstream calls" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var wrong = [_]u8{'A'} ** capability_mod.carrier_len;
    defer std.crypto.secureZero(u8, &wrong);
    if (std.mem.eql(u8, &wrong, &carrier)) wrong[0] = 'B';
    var malformed = carrier;
    defer std.crypto.secureZero(u8, &malformed);
    malformed[0] = '=';
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const auth_values = [_]?[]const u8{ null, "", "short", malformed[0..], wrong[0..] };
    for (auth_values) |auth_value| {
        const auth_line = if (auth_value) |value|
            try std.fmt.allocPrint(std.testing.allocator, "Authorization: Bearer {s}\r\n", .{value})
        else
            try std.testing.allocator.dupe(u8, "");
        defer std.testing.allocator.free(auth_line);
        const request = try std.fmt.allocPrint(
            std.testing.allocator,
            "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n{s}Connection: close\r\n\r\n",
            .{ listener.port(), auth_line },
        );
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    }

    const duplicate_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier, carrier },
    );
    defer std.testing.allocator.free(duplicate_request);
    const duplicate_response = try requestRawAlloc(
        std.testing.allocator,
        listener.address(),
        duplicate_request,
    );
    defer std.testing.allocator.free(duplicate_response);
    try expectStatus(duplicate_response, "HTTP/1.1 401 Unauthorized\r\n");

    try std.testing.expect(upstream.snapshot().isZero());
    const expected_event = "{\"kind\":\"claude_proxy_capability_rejected\"}\n";
    try std.testing.expectEqual(
        auth_values.len + 1,
        std.mem.count(u8, event_stream.getWritten(), expected_event),
    );
    try std.testing.expect(std.mem.indexOf(u8, event_stream.getWritten(), &carrier) == null);
}

test "production listener is fixed-origin and fail-closed before credential wiring" {
    try std.testing.expectEqualStrings("https://api.anthropic.com", production_origin);
    try std.testing.expect(!production_forwarding_enabled);

    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const listener = try Listener.start(
        std.testing.allocator,
        capability,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
}

test "origin form Host CONNECT and absolute form fail before upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const requests = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "GET https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (requests) |request| std.testing.allocator.free(request);
    for (requests) |request| {
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 400 Bad Request\r\n");
    }
    try std.testing.expect(upstream.snapshot().isZero());
}

test "forwarded headers strip credentials framing and connection tokens" {
    const inbound = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Bearer local-capability" },
        .{ .name = "Accept-Encoding", .value = "gzip, deflate" },
        .{ .name = "X-Api-Key", .value = "caller-key" },
        .{ .name = "Cookie", .value = "caller-cookie" },
        .{ .name = "Forwarded", .value = "host=caller.invalid" },
        .{ .name = "X-Forwarded-Host", .value = "caller.invalid" },
        .{ .name = "Proxy-Authenticate", .value = "Basic local" },
        .{ .name = "Proxy-Authorization", .value = "Basic caller" },
        .{ .name = "Proxy-Connection", .value = "keep-alive" },
        .{ .name = "Host", .value = "127.0.0.1:1" },
        .{ .name = "Content-Length", .value = "4" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Connection", .value = "X-Private-Hop, keep-alive" },
        .{ .name = "X-Private-Hop", .value = "remove-me" },
        .{ .name = "TE", .value = "trailers" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Anthropic-Version", .value = "2023-06-01" },
    };
    var outbound = std.ArrayListUnmanaged(std.http.Header){};
    defer outbound.deinit(std.testing.allocator);
    try appendForwardingHeaders(std.testing.allocator, &inbound, &outbound);

    try std.testing.expectEqual(@as(usize, 1), outbound.items.len);
    try std.testing.expectEqualStrings("Anthropic-Version", outbound.items[0].name);
    try std.testing.expectEqualStrings("2023-06-01", outbound.items[0].value);
}

test "response headers strip fixed and connection-nominated hop headers" {
    const headers = [_]std.http.Header{
        .{ .name = "Connection", .value = "X-Upstream-Hop, close" },
        .{ .name = "X-Upstream-Hop", .value = "remove-me" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "TE", .value = "trailers" },
        .{ .name = "Trailer", .value = "X-Trailer" },
        .{ .name = "Proxy-Authorization", .value = "Basic upstream" },
        .{ .name = "Proxy-Connection", .value = "keep-alive" },
        .{ .name = "Anthropic-RateLimit-Unified-Status", .value = "allowed" },
    };
    try std.testing.expect(stripResponseHeader(headers[0].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[1].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[2].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[3].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[4].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[5].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[6].name, &headers));
    try std.testing.expect(!stripResponseHeader(headers[7].name, &headers));
}

test "accepted request strips sensitive and hop headers across the wire" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nX-Api-Key: caller-key\r\nCookie: caller-cookie\r\nForwarded: host=caller.invalid\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-Host: caller.invalid\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 192.0.2.2\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic local\r\nProxy-Authorization: Basic caller\r\nProxy-Connection: keep-alive\r\nConnection: {s}, close\r\n{s}: remove\r\nTE: trailers\r\nTrailer: X-Result\r\nTrailers: X-Result\r\nUpgrade: websocket\r\nAnthropic-Version: 2023-06-01\r\n\r\n",
        .{
            listener.port(),
            carrier,
            fake_upstream_mod.connection_nominated_canary,
            fake_upstream_mod.connection_nominated_canary,
        },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 204 No Content\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    try std.testing.expectEqualDeep(
        fake_upstream_mod.RequestHeaderPresence{
            .accept_encoding = true,
            .anthropic_version = true,
        },
        upstream.requestHeaderPresenceSnapshot(),
    );
}

test "upstream redirect is rejected without a second call" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .found,
        .headers = &.{.{ .name = "Location", .value = "https://example.com/steal" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqual(@as(u16, 302), obs.upstream_status);
}

fn postRequestAlloc(
    allocator: std.mem.Allocator,
    port: u16,
    carrier: []const u8,
    body: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\n" ++
            "Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ port, carrier, body.len, body },
    );
}

fn waitForResponsePrefix(upstream: *FakeUpstream) !void {
    var timer = try std.time.Timer.start();
    while (!upstream.responsePrefixWritten()) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn waitForListenerIdle(listener: *Listener) !void {
    var timer = try std.time.Timer.start();
    while (statePtr(listener).active.isSet()) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn readUntilContains(
    stream: *std.net.Stream,
    response: *std.ArrayList(u8),
    needle: []const u8,
) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (std.mem.indexOf(u8, response.items, needle) == null) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return error.EndOfStream;
        try response.appendSlice(buffer[0..count]);
    }
}

fn readResponseRemainder(stream: *std.net.Stream, response: *std.ArrayList(u8)) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (true) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return;
        try response.appendSlice(buffer[0..count]);
    }
}

/// Decodes the chunked transfer-encoded body of a raw HTTP response into its
/// plain bytes, so a test can assert byte-for-byte stream equality.
fn decodeChunkedBody(alloc: std.mem.Allocator, response: []const u8) ![]u8 {
    const head_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.NoHead;
    var body = response[head_end + 4 ..];
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    while (true) {
        const line_end = std.mem.indexOf(u8, body, "\r\n") orelse return error.BadChunk;
        var len_field = body[0..line_end];
        if (std.mem.indexOfScalar(u8, len_field, ';')) |semi| len_field = len_field[0..semi];
        const chunk_len = try std.fmt.parseInt(usize, std.mem.trim(u8, len_field, " \t"), 16);
        body = body[line_end + 2 ..];
        if (chunk_len == 0) break;
        if (body.len < chunk_len + 2) return error.BadChunk;
        try out.appendSlice(body[0..chunk_len]);
        body = body[chunk_len + 2 ..];
    }
    return out.toOwnedSlice();
}

test "exact model is captured and forwarded byte-identically to the fake upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const model = "claude-opus-4-20250514";
    const json = "{\"model\":\"" ++ model ++ "\",\"max_tokens\":16," ++
        "\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n{\"ok\":true}"));
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);

    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_present);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqual(@as(u16, 200), obs.upstream_status);
    try std.testing.expectEqualStrings(model, obs.admittedModel());

    var captured: [256]u8 = undefined;
    const captured_len = upstream.capturedRequestBody(&captured);
    try std.testing.expectEqualStrings(json, captured[0..captured_len]);
    try std.testing.expectEqualDeep(
        fake_upstream_mod.RequestCaptureSnapshot{
            .captured_len = json.len,
            .total_len = json.len,
            .truncated = false,
        },
        upstream.requestCaptureSnapshot(),
    );
}

test "a rejected request cannot inherit a prior successful observation" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const body = "{\"model\":\"claude-opus-4-20250514\",\"max_tokens\":1,\"messages\":[]}";
    const accepted = try postRequestAlloc(
        std.testing.allocator,
        listener.port(),
        &carrier,
        body,
    );
    defer std.testing.allocator.free(accepted);
    const accepted_response = try requestRawAlloc(
        std.testing.allocator,
        listener.address(),
        accepted,
    );
    defer std.testing.allocator.free(accepted_response);
    try expectStatus(accepted_response, "HTTP/1.1 204 No Content\r\n");

    const first = observationSnapshot(listener);
    try std.testing.expectEqual(RequestOutcome.upstream_response, first.outcome);
    try std.testing.expect(first.model_present);
    try std.testing.expect(first.upstream_attempted);

    var wrong = [_]u8{'A'} ** capability_mod.carrier_len;
    defer std.crypto.secureZero(u8, &wrong);
    if (std.mem.eql(u8, &wrong, &carrier)) wrong[0] = 'B';
    const rejected = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), wrong },
    );
    defer std.testing.allocator.free(rejected);
    const rejected_response = try requestRawAlloc(
        std.testing.allocator,
        listener.address(),
        rejected,
    );
    defer std.testing.allocator.free(rejected_response);
    try expectStatus(rejected_response, "HTTP/1.1 401 Unauthorized\r\n");

    const second = observationSnapshot(listener);
    try std.testing.expectEqual(first.request_id + 1, second.request_id);
    try std.testing.expectEqual(RequestOutcome.capability_rejected, second.outcome);
    try std.testing.expect(!second.had_body);
    try std.testing.expect(!second.model_present);
    try std.testing.expect(!second.upstream_attempted);
    try std.testing.expectEqual(@as(u16, 0), second.upstream_status);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "SSE response prefix reaches the client before the upstream completes" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
    const rest =
        "event: content_block_delta\ndata: {\"delta\":{\"text\":\"hi\"}}\n\n" ++
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    const sse = first ++ rest;
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = sse,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .pause_after_bytes = first.len,
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const json = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, first);

    try expectStatus(response.items, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response.items, "Content-Type: text/event-stream\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.items, "transfer-encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.items, rest) == null);

    upstream.releasePausedResponse();
    try readResponseRemainder(&stream, &response);
    // Strict byte-for-byte reassembly: the decoded chunked body must equal the
    // whole dripped stream exactly, not merely contain its segments.
    const decoded = try decodeChunkedBody(std.testing.allocator, response.items);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings(sse, decoded);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "truncated chunked upstream remains detectably incomplete downstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\"}}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .truncate_after_bytes = first.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "transfer-encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, first) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, rest) == null);
    try std.testing.expect(!std.mem.endsWith(u8, response, "0\r\n\r\n"));
    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_upstream_interrupted",
    ) != null);
    try std.testing.expectEqual(
        RequestOutcome.upstream_response,
        observationSnapshot(listener).outcome,
    );
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "truncated content-length upstream remains shorter than its downstream declaration" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "partial-body";
    const rest = "-must-not-arrive";
    const body = first ++ rest;
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = body,
        .truncate_after_bytes = first.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    const expected_length = try std.fmt.allocPrint(
        std.testing.allocator,
        "content-length: {d}\r\n",
        .{body.len},
    );
    defer std.testing.allocator.free(expected_length);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, expected_length) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, first) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, rest) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_upstream_interrupted",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "listener shutdown interrupts a stalled started upstream response" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = "first chunksecond chunk";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = "first chunk".len,
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, "first chunk");

    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);

    // The fake remains paused with the upstream response open. Teardown must
    // interrupt both the downstream socket and the blocked upstream read.
    var shutdown_timer = try std.time.Timer.start();
    listener.deinit();
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "client disconnect after a streamed prefix ends the single upstream attempt" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    upstream.releasePausedResponse();
    try waitForListenerIdle(listener);

    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_client_disconnected",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);
}

test "provider 5xx passes through unchanged as a single classified attempt" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const Case = struct { status: std.http.Status, line: []const u8 };
    const cases = [_]Case{
        .{ .status = .internal_server_error, .line = "HTTP/1.1 500 Internal Server Error\r\n" },
        .{ .status = @enumFromInt(529), .line = "HTTP/1.1 529 " },
    };
    for (cases) |case| {
        var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
            .status = case.status,
            .body = "upstream boom",
            .headers = &.{.{ .name = "X-Trace", .value = "abc123" }},
        }});
        defer upstream.deinit();
        var event_buffer: [512]u8 = undefined;
        var event_stream = std.io.fixedBufferStream(&event_buffer);
        const listener = try startWithUpstream(
            std.testing.allocator,
            capability,
            event_stream.writer().any(),
            .{ .fake = &upstream },
        );
        defer listener.deinit();

        const json = "{\"model\":\"claude-opus-4-20250514\"}";
        const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);

        try expectStatus(response, case.line);
        try std.testing.expect(std.mem.indexOf(u8, response, "X-Trace: abc123\r\n") != null);
        try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nupstream boom"));
        try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
        try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);
        try std.testing.expect(std.mem.indexOf(
            u8,
            event_stream.getWritten(),
            "claude_proxy_upstream_server_error",
        ) != null);

        const obs = observationSnapshot(listener);
        try std.testing.expect(obs.upstream_attempted);
        try std.testing.expectEqual(@as(u16, @intFromEnum(case.status)), obs.upstream_status);
    }
}

test "model after the former peek window is admitted from the complete bounded body" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "accepted",
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const model = "claude-opus-4-20250514";
    const pad = try std.testing.allocator.alloc(u8, 64 * 1024 + 64);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"pad\":\"{s}\",\"model\":\"{s}\"}}",
        .{ pad, model },
    );
    defer std.testing.allocator.free(json);
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);

    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_present);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqualStrings(model, obs.admittedModel());
    const capture = upstream.requestCaptureSnapshot();
    try std.testing.expectEqual(json.len, capture.total_len);
    try std.testing.expect(capture.truncated);
    try std.testing.expect(capture.captured_len < capture.total_len);
}

test "malformed ambiguous and missing model bodies refuse locally with zero upstream calls" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "nope" }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    // Full-document admission (program §2.2, ladder §8.2): the whole buffered
    // body must be one complete JSON object with exactly one top-level `model`
    // string, no trailing non-whitespace, and a model within the length bound.
    const overlong_model = "{\"model\":\"" ++ ("x" ** (max_model_len + 1)) ++ "\"}";
    const bodies = [_][]const u8{
        "not json at all",
        "{\"messages\":[]}",
        "{\"model\":5}",
        "{\"model\":\"\"}",
        "[]",
        overlong_model, // model exceeds the length bound
        "{\"model\":\"claude-opus-4-20250514\",\"model\":\"claude-haiku-4-20250514\"}",
        "{\"model\":\"claude-opus-4-20250514\",\"model\":\"claude-opus-4-20250514\"}",
        "{\"model\":\"claude-opus-4-20250514\"} trailing",
        "{\"model\":\"claude-opus-4-20250514\"}{\"model\":\"claude-haiku-4-20250514\"}",
    };
    for (bodies) |body| {
        const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, body);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 400 Bad Request\r\n");
    }

    try std.testing.expect(upstream.snapshot().isZero());
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_admission_rejected);
    try std.testing.expect(!obs.upstream_attempted);

    // Trailing whitespace after a complete single-model document is tolerated,
    // so a legitimate body with a trailing newline still admits and forwards.
    const trailing_ws = "{\"model\":\"claude-opus-4-20250514\"}\n\n  \t";
    const accept_request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, trailing_ws);
    defer std.testing.allocator.free(accept_request);
    const accept_response = try requestRawAlloc(std.testing.allocator, listener.address(), accept_request);
    defer std.testing.allocator.free(accept_response);
    try expectStatus(accept_response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "shutdown interrupts a partial request within a fixed deadline" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll("GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1");

    var active_timer = try std.time.Timer.start();
    while (!statePtr(listener).active.isSet()) {
        if (active_timer.read() > std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
    var shutdown_timer = try std.time.Timer.start();
    listener.deinit();
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expect(upstream.snapshot().isZero());
}

// ===========================================================================
// §2.2 single-alternate retry state machine tests (synthetic seam only).
// ===========================================================================

/// Virtual clock for the injected-wait tests: `sleep` advances a purely
/// in-memory timestamp and records the wait, so no real time passes.
const VirtualClock = struct {
    now_ns: i128 = 0,
    sleep_calls: usize = 0,
    last_sleep_ns: u64 = 0,

    fn nowNs(ctx: ?*anyopaque) i128 {
        const self: *VirtualClock = @ptrCast(@alignCast(ctx.?));
        return self.now_ns;
    }

    fn sleepNs(ctx: ?*anyopaque, ns: u64) void {
        const self: *VirtualClock = @ptrCast(@alignCast(ctx.?));
        self.sleep_calls += 1;
        self.last_sleep_ns = ns;
        self.now_ns += @intCast(ns);
    }

    fn clock(self: *VirtualClock) WireClock {
        return .{ .ctx = self, .nowFn = nowNs, .sleepFn = sleepNs };
    }
};

const routed_model = "claude-opus-4-20250514";
const routed_json = "{\"model\":\"" ++ routed_model ++ "\",\"max_tokens\":16}";

fn eventBufferContains(buffer: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, buffer, needle) != null;
}

test "the stream-once replay latch never flips back to replayable" {
    var latch = ReplayLatch{};
    try std.testing.expect(latch.isReplayable());
    latch.latchStreamOnce();
    try std.testing.expect(!latch.isReplayable());
    // Idempotent and one-way: repeated latching cannot restore replayability.
    latch.latchStreamOnce();
    try std.testing.expect(!latch.isReplayable());
    try std.testing.expectEqual(ReplayMode.stream_once, latch.mode);
}

test "the replay reservation guard releases the pool exactly once" {
    var pool = Reservation{ .budget_bytes = 1024 };
    try std.testing.expect(pool.reserve(400));
    try std.testing.expectEqual(@as(usize, 400), pool.outstanding());
    var guard = ReservationGuard{ .reservation = &pool, .amount = 400 };
    guard.release();
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());
    // A second release is a no-op: exactly-once accounting cannot underflow.
    guard.release();
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());
}

test "the replay reservation pool stays bounded and coherent under concurrent reservations" {
    const slot = 8 * 1024;
    const capacity = 8;
    var pool = Reservation{ .budget_bytes = slot * capacity };

    const Reserver = struct {
        pool: *Reservation,
        granted: bool = false,
        fn run(self: *@This()) void {
            self.granted = self.pool.reserve(slot);
        }
    };
    var reservers: [capacity * 2]Reserver = undefined;
    var threads: [capacity * 2]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&reservers, 0..) |*reserver, index| {
        reserver.* = .{ .pool = &pool };
        threads[index] = try std.Thread.spawn(.{}, Reserver.run, .{reserver});
        started += 1;
    }
    for (threads) |thread| thread.join();

    var granted: usize = 0;
    for (reservers) |reserver| {
        if (reserver.granted) granted += 1;
    }
    // The pool can never over-commit: at most `capacity` grants, and the
    // outstanding total never exceeds the budget (the concurrent-exhaustion
    // degradation that flips further requests to stream-once).
    try std.testing.expect(granted <= capacity);
    try std.testing.expectEqual(granted * slot, pool.outstanding());
    try std.testing.expect(pool.outstanding() <= pool.budget_bytes);

    for (reservers) |reserver| {
        if (reserver.granted) pool.release(slot);
    }
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());
}

/// Drives one routed POST of `routed_json` and returns the raw response.
fn routedRequest(listener: *Listener, carrier: []const u8) ![]u8 {
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), carrier, routed_json);
    defer std.testing.allocator.free(request);
    return requestRawAlloc(std.testing.allocator, listener.address(), request);
}

test "a pre-body 401 consumes the one alternate and returns the alternate success" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "{\"ok\":true}" }});
    defer alternate.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "route-1-secret", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "route-2-secret", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n{\"ok\":true}"));
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);

    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
    try std.testing.expectEqual(@as(u16, 200), obs.upstream_status);
    try std.testing.expectEqual(ReplayMode.replayable, obs.replay_mode);
    // Attempt 2 re-ran admission on the SAME bytes and preserved the model.
    try std.testing.expectEqualStrings(routed_model, obs.admittedModel());

    // Distinct-identity credential injection: each route saw its own bearer,
    // and the alternate received the byte-identical request body.
    var auth1: [64]u8 = undefined;
    var auth2: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Bearer route-1-secret", auth1[0..primary.capturedAuthorization(&auth1)]);
    try std.testing.expectEqualStrings("Bearer route-2-secret", auth2[0..alternate.capturedAuthorization(&auth2)]);
    var replayed: [128]u8 = undefined;
    try std.testing.expectEqualStrings(routed_json, replayed[0..alternate.capturedRequestBody(&replayed)]);

    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_alternate_consumed"));
}

test "a pre-body 403 consumes the one alternate and returns the alternate success" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .forbidden, .body = "forbidden" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nalt-ok"));
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
}

test "a pre-body 429 waits once within bound then consumes the alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nalt-ok"));
    // At most one wait, bounded to the trusted reset (5s) which fits both the
    // 30s maximum and the 120s deadline.
    try std.testing.expectEqual(@as(usize, 1), vclock.sleep_calls);
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), vclock.last_sleep_ns);
    try std.testing.expect(vclock.last_sleep_ns <= default_max_wait_ns);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
}

test "a proven pre-send transport failure consumes one same-route retry and never crosses accounts" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // The primary suffers one transient pre-send fault, then the same-route
    // retry (the fake's first served call) succeeds.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "retried-ok" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-must-not-run" }});
    defer alternate.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1", .presend_faults = 1 },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nretried-ok"));
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    // The alternate account was never even connected: transport failures never
    // cross accounts.
    try std.testing.expect(alternate.snapshot().isZero());

    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_retry_consumed"));
}

test "an alternate that itself fails delivers that failure with no third attempt" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .internal_server_error, .body = "alt-boom" }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    // The alternate's own failure is delivered as-is; there is no third attempt.
    try expectStatus(response, "HTTP/1.1 500 Internal Server Error\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nalt-boom"));
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
}

test "both forms are impossible: a 401 alternate that transport-fails adds no same-route retry" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    // 401 (order A) consumes the alternate; the alternate then transport-fails.
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2", .presend_faults = 1 },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
    // The slot was consumed by the alternate; NO same-route retry is added, so
    // the primary is contacted exactly once and the alternate never serves.
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expect(alternate.snapshot().isZero());
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
}

test "both forms are impossible: a same-route retry that returns 401 adds no alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Order B: pre-send transport failure consumes the same-route retry; the
    // retry then returns 401, which must NOT escalate to a cross-account attempt.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied-on-retry" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1", .presend_faults = 1 },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\ndenied-on-retry"));
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expect(alternate.snapshot().isZero());
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
}

test "a started 2xx response then upstream truncation is never replayed" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\"}}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .truncate_after_bytes = first.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, first) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, rest) == null);
    // The response head already reached the client, so replay is impossible:
    // no second attempt, alternate untouched.
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_upstream_interrupted"));
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
}

test "client cancellation during a routed stream releases the reservation without replay" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, routed_json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    primary.releasePausedResponse();
    try waitForListenerIdle(listener);

    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_client_disconnected"));
    // Cancellation releases the reservation and never replays to the alternate.
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
}

test "an oversize body relative to the sidecar budget streams once and refuses the alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    // Budget below the request body: the body cannot be reserved for replay.
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 4096,
    });
    defer listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 8 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const body = try std.fmt.allocPrint(std.testing.allocator, "{{\"pad\":\"{s}\",\"model\":\"{s}\"}}", .{ pad, routed_model });
    defer std.testing.allocator.free(body);
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    // Non-replayable: the pre-body 401 is delivered as-is; the alternate is
    // refused, and the request is stream-once.
    try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_stream_once"));
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(ReplayMode.stream_once, obs.replay_mode);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
}

test "replay reservations release exactly once across sequential routed requests" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const iterations = 5;
    const primary_script = [_]fake_upstream_mod.ScriptedResponse{.{ .status = .unauthorized, .body = "denied" }} ** iterations;
    const alternate_script = [_]fake_upstream_mod.ScriptedResponse{.{ .status = .ok, .body = "ok" }} ** iterations;
    var primary = try FakeUpstream.start(std.testing.allocator, &primary_script);
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &alternate_script);
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    var index: usize = 0;
    while (index < iterations) : (index += 1) {
        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 200 OK\r\n");
        // Every request — including the two-attempt alternate path — returns
        // its reservation, so the pool always settles back to zero.
        try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    }
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    try std.testing.expectEqual(@as(usize, iterations), alternate.snapshot().call_count);
}

test "the admitted model is sent byte-exact on the first attempt and on the alternate replay" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 fails pre-body 401, so the SAME buffered bytes are replayed to the
    // distinct-identity alternate. Both fakes capture the request body they
    // received before responding, so the model on the wire of EACH attempt is
    // observable independently of the admission observation.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "{\"ok\":true}" }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 200 OK\r\n");

    // FIRST-ATTEMPT ADMISSION ONLY (#492): the observation records the model
    // admitted for the one attempt and makes no result-side claim.
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_present);
    try std.testing.expectEqualStrings(routed_model, obs.admittedModel());

    // The exact admitted model bytes appear on the body ACTUALLY SENT upstream on
    // BOTH the first attempt (primary) and the §2.2 alternate replay — never a
    // substituted, family-inferred, or re-serialized model. The whole body is
    // byte-identical, and the admitted model is a byte-exact substring of each.
    var first_sent: [256]u8 = undefined;
    const first_len = primary.capturedRequestBody(&first_sent);
    try std.testing.expectEqualStrings(routed_json, first_sent[0..first_len]);
    try std.testing.expect(std.mem.indexOf(u8, first_sent[0..first_len], obs.admittedModel()) != null);

    var replayed_sent: [256]u8 = undefined;
    const replayed_len = alternate.capturedRequestBody(&replayed_sent);
    try std.testing.expectEqualStrings(routed_json, replayed_sent[0..replayed_len]);
    try std.testing.expect(std.mem.indexOf(u8, replayed_sent[0..replayed_len], obs.admittedModel()) != null);

    // The bytes sent on the two attempts are byte-identical to each other.
    try std.testing.expectEqualStrings(first_sent[0..first_len], replayed_sent[0..replayed_len]);
}

test "client cancellation mid stream in a stream-once request keeps the latch latched and releases the reservation" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // A large 2xx that pauses mid-stream so the client can cancel while the pump
    // is running.
    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    // Budget below the request body: it cannot be reserved, so the request is
    // IRREVOCABLY stream-once before the primary is even contacted — distinct
    // from the replayable mid-stream cancellation already covered.
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 4096,
    });
    defer listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 8 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const body = try std.fmt.allocPrint(std.testing.allocator, "{{\"model\":\"{s}\",\"pad\":\"{s}\"}}", .{ routed_model, pad });
    defer std.testing.allocator.free(body);

    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    // Cancel mid-stream, then let the paused upstream resume into a dead client.
    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    primary.releasePausedResponse();
    try waitForListenerIdle(listener);

    // Streaming cancellation is observable as a VALUE-FREE event: the kind is
    // immediately closed, carrying no payload field.
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "{\"kind\":\"claude_proxy_client_disconnected\"}"));
    // The stream-once latch never flipped back to replayable...
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(ReplayMode.stream_once, obs.replay_mode);
    // ...and every reservation for the request returned to zero.
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    // No replay to the alternate; exactly one primary attempt was made.
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
}

test "a replay-budget overflow releases its reservation and the next request is unaffected" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 always fails pre-body 401; the alternate always succeeds.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .unauthorized, .body = "denied" },
        .{ .status = .unauthorized, .body = "denied" },
    });
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "{\"ok\":true}" }});
    defer alternate.deinit();

    // A budget large enough for the small replayable request but far below the
    // padded overflow request.
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 8192,
    });
    defer listener.deinit();

    // Request 1 overflows the pool: it cannot reserve, degrades to stream-once,
    // refuses the alternate, and delivers route 1's own 401.
    const pad = try std.testing.allocator.alloc(u8, 32 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const overflow_body = try std.fmt.allocPrint(std.testing.allocator, "{{\"model\":\"{s}\",\"pad\":\"{s}\"}}", .{ routed_model, pad });
    defer std.testing.allocator.free(overflow_body);
    {
        const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, overflow_body);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    }
    // The overflow request returned every reservation it took (it took none): the
    // pool is back to its prior level and the alternate was never contacted.
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    try std.testing.expect(alternate.snapshot().isZero());

    // Request 2 is small enough to reserve: the pool is uncorrupted, so it takes
    // and releases a reservation and the alternate serves the retry.
    {
        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    }
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 2), primary.snapshot().call_count);
}

test "a same-identity alternate is refused and the original pre-body failure is delivered" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    // The alternate shares the primary's identity marker: refused (typed).
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\ndenied"));
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_same_identity_alternate_refused"));
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.same_identity_alternate_refused);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
}

test "a pre-alternate wait beyond the 30 second bound returns a local 429 without an alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "40" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    // 40s exceeds the 30s maximum: no wait, no alternate, a typed local 429.
    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 40\r\n") != null);
    try std.testing.expectEqual(@as(usize, 0), vclock.sleep_calls);
    try std.testing.expect(alternate.snapshot().isZero());
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
}

test "a pre-alternate wait beyond the request deadline returns a local 429 without an alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    // A 2s deadline cannot fit the 5s reset even though 5s is under the 30s max.
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
        .request_deadline_ns = 2 * std.time.ns_per_s,
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expectEqual(@as(usize, 0), vclock.sleep_calls);
    try std.testing.expect(alternate.snapshot().isZero());
}

test "a routed provider 5xx passes through as a single attempt without an alternate" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .internal_server_error, .body = "boom" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 500 Internal Server Error\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nboom"));
    // 5xx never authorizes a cross-account attempt.
    try std.testing.expect(alternate.snapshot().isZero());
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_upstream_server_error"));
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
}

test "the production path is single-attempt fail-closed and never routes an alternate" {
    // No runtime input can enable production forwarding; the routed retry
    // machine is unreachable in production by construction.
    try std.testing.expect(!production_forwarding_enabled);

    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const listener = try Listener.start(std.testing.allocator, capability, std.io.null_writer.any());
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    // Fail-closed before any upstream attempt: zero attempts, no alternate.
    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 0), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.same_route_retry_count);
    try std.testing.expect(!obs.upstream_attempted);
}

// ===========================================================================
// Bounded all-exhausted terminal tests (plan §7, ladder §9 Stage 2 / G10).
// Both distinct identities fail pre-body → ONE typed bounded 429 carrying the
// MINIMUM trusted Retry-After, zero further upstream attempts, one typed event.
// ===========================================================================

fn responseHasRetryAfter(response: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(response, "retry-after") != null;
}

test "all identities exhausted returns a bounded 429 carrying the minimum trusted Retry-After" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 resets in 10s, route 2 in 30s. Both are pre-body 429, so both
    // distinct identities are exhausted. The honest bound is the MINIMUM (10):
    // route 1 may regain capacity first. MAX (30) would invent scarcity.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "p-limit",
        .headers = &.{.{ .name = "Retry-After", .value = "10" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "a-limit",
        .headers = &.{.{ .name = "Retry-After", .value = "30" }},
    }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    // ONE typed bounded 429; never a synthetic 200. MIN(10,30)=10 propagated.
    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 10\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 30\r\n") == null);
    // Neither upstream's raw body leaks into the composed terminal.
    try std.testing.expect(std.mem.indexOf(u8, response, "p-limit") == null);
    try std.testing.expect(std.mem.indexOf(u8, response, "a-limit") == null);

    // Zero further attempts: exactly the two structural attempts, no third route.
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.same_route_retry_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));

    // Exactly one typed all-exhausted event, marking the propagated reset.
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted"),
    );
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "\"retry_after_present\":true"));
    // The single pre-alternate wait bound still composes: at most one wait ≤ 30s.
    try std.testing.expectEqual(@as(usize, 1), vclock.sleep_calls);
    try std.testing.expect(vclock.last_sleep_ns <= default_max_wait_ns);
}

test "all identities exhausted with no trusted reset returns a bounded 429 without Retry-After" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 401, route 2 403: both pre-body reauth, neither supplies a reset.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .forbidden, .body = "forbidden" }});
    defer alternate.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    // Still ONE typed bounded 429, but no fabricated reset: no Retry-After.
    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(!responseHasRetryAfter(response));
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    try std.testing.expectEqual(@as(usize, 0), obs.third_attempt_count);
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted"),
    );
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "\"retry_after_present\":false"));
}

test "all identities exhausted propagates a single route's trusted reset" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 401 (no reset → no wait), route 2 429 with a 20s reset. The MIN
    // over {none, 20} is 20: the only trusted value is propagated.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "20" }},
    }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 20\r\n") != null);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
}

test "all identities exhausted ignores a malformed Retry-After and never invents capacity" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 is a bare 401 (no reset, no wait). Route 2 is a 429 whose
    // Retry-After is malformed. Every malformed value is ignored, so the bounded
    // terminal carries NO reset: a garbage reset is never propagated.
    const malformed = [_][]const u8{
        "soon", // non-numeric
        "-30", // negative
        "", // empty
        "10 20", // embedded space
        "18446744073709551616", // 2^64, does not fit u64 → huge
        "99999999999", // fits u64 but overflows the nanosecond domain → huge
    };
    for (malformed) |bad| {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
        defer primary.deinit();
        var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .too_many_requests,
            .body = "limit",
            .headers = &.{.{ .name = "Retry-After", .value = bad }},
        }});
        defer alternate.deinit();

        const listener = try startRoutedForTest(std.testing.allocator, capability, .{
            .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
            .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        });
        defer listener.deinit();

        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);

        try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
        try std.testing.expect(!responseHasRetryAfter(response));
        const obs = observationSnapshot(listener);
        try std.testing.expectEqual(@as(usize, 2), obs.attempts_total);
        try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
    }
}

test "all identities exhausted excludes a malformed route reset from the propagated minimum" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 is a 429 whose Retry-After is malformed ("soon"): the wait parser
    // reads no trusted reset, so no wait occurs and the alternate is consumed.
    // Route 2 supplies a valid 15s reset. The MIN excludes the malformed value,
    // so the propagated terminal reset is 15 alone.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "soon" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "15" }},
    }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 15\r\n") != null);
    // The malformed route-1 reset produced no wait.
    try std.testing.expectEqual(@as(usize, 0), vclock.sleep_calls);
}

test "no distinct alternate configured emits the uniform all-exhausted terminal" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // No alternate at all: route 1's own pre-body 429 (reset 9) is the
    // single-route bounded terminal, delivered as-is, plus the uniform event.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "denied",
        .headers = &.{.{ .name = "Retry-After", .value = "9" }},
    }});
    defer primary.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "Retry-After: 9\r\n") != null);
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
    // The uniform terminal event fires exactly once, marking the trusted reset.
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted"),
    );
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "\"retry_after_present\":true"));
}

test "a same-identity-only pool emits the uniform all-exhausted terminal beside the refusal" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // The only configured alternate shares route 1's identity: the
    // distinct-identity pool is exhausted. Route 1's own 401 is delivered as-is
    // (refusal), and the uniform all-exhausted event fires exactly once beside
    // the typed same-identity refusal event.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\ndenied"));
    try std.testing.expect(alternate.snapshot().isZero());
    const written = event_stream.getWritten();
    try std.testing.expect(eventBufferContains(written, "claude_proxy_same_identity_alternate_refused"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, written, "claude_proxy_all_exhausted"));
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.same_identity_alternate_refused);
    try std.testing.expectEqual(@as(usize, 1), obs.attempts_total);
    try std.testing.expectEqual(@as(usize, 0), obs.alternate_count);
}

// ===========================================================================
// Resident-absence invariant (G6 sidecar half; plan §2.1/§2.4, ladder §7/G6).
// ===========================================================================

test "resident absence: the sidecar State carries no resident/daemon/service hook" {
    // G6 sidecar half: the sidecar consults no resident-plane state. This is the
    // structural grep-as-test — it fails the BUILD if a future edit smuggles a
    // resident/daemon/keepalive/service field (by name or type) into `State`.
    // There is no resident hook to inject, so absence cannot change routing.
    const denied = [_][]const u8{ "resident", "daemon", "keepalive", "service" };
    comptime {
        @setEvalBranchQuota(100_000);
        for (@typeInfo(State).@"struct".fields) |field| {
            for (denied) |token| {
                if (std.ascii.indexOfIgnoreCase(field.name, token) != null) {
                    @compileError("wire_proxy State field '" ++ field.name ++ "' references resident-plane state");
                }
                if (std.ascii.indexOfIgnoreCase(@typeName(field.type), token) != null) {
                    @compileError("wire_proxy State field type '" ++ @typeName(field.type) ++ "' references resident-plane state");
                }
            }
        }
    }

    // Behavioral leg: a full routed alternate flow completes with no resident
    // present — there is none to construct or consult — so its absence cannot
    // alter the routing decision or the terminal outcome.
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    const obs = observationSnapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), obs.alternate_count);
}

// ===========================================================================
// Abrupt-death reclamation breadth (ladder §9 Stage 2): kill the listener mid-
// request and prove reservations return to zero, the capability is disposed, no
// upstream call leaks past teardown, and teardown stays bounded.
// ===========================================================================

test "abrupt sidecar death mid routed alternate reclaims the replay reservation to zero" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 fails pre-body 401 (buffered); the alternate is a large 2xx that
    // pauses mid-stream, parking the request in attempt 2 with its replay
    // reservation still outstanding.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    const big = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'y');
    const prefix = "alt-streamed-prefix";
    @memcpy(big[0..prefix.len], prefix);
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = big,
        .pause_after_bytes = prefix.len,
    }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, routed_json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&alternate);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    // The routed body's reservation is outstanding while attempt 2 streams.
    try std.testing.expect(reservedBytes(listener) > 0);

    // Abrupt death mid-stream: teardown joins the serve thread, so the request's
    // exactly-once `defer guard.release()` has run when the pool is measured.
    var shutdown_timer = try std.time.Timer.start();
    const outstanding = teardown(listener);
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    // No upstream call leaked past the two attempts already made.
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), alternate.snapshot().call_count);

    // Compose with session-capability revocation: the managed session disposes
    // the carrier, and the revoked capability admits nothing further.
    capability.revoke();
    try std.testing.expect(capability.isRevoked());
    try std.testing.expect(!capability.validate(&carrier));
}

test "abrupt sidecar death mid routed stream with a stalled upstream stays bounded and reclaims" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // The primary is a large 2xx that pauses mid-stream and never resumes.
    const big = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'y');
    const prefix = "stalled-prefix";
    @memcpy(big[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = big,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, routed_json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    try std.testing.expect(reservedBytes(listener) > 0);

    // Teardown must interrupt the stalled upstream read and stay bounded.
    var shutdown_timer = try std.time.Timer.start();
    const outstanding = teardown(listener);
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    // The alternate was never contacted: no upstream call leaks at teardown.
    try std.testing.expect(alternate.snapshot().isZero());

    capability.revoke();
    try std.testing.expect(capability.isRevoked());
}

test "abrupt sidecar death before the routed capability check stays bounded and reclaims" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{});
    defer alternate.deinit();

    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    // A partial head parks the serve thread in receiveHead — before the
    // capability check and before any reservation is taken.
    try stream.writeAll("POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1");

    var active_timer = try std.time.Timer.start();
    while (!statePtr(listener).active.isSet()) {
        if (active_timer.read() > std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }

    var shutdown_timer = try std.time.Timer.start();
    const outstanding = teardown(listener);
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    // No reservation was ever taken, and no upstream call ran.
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    try std.testing.expect(primary.snapshot().isZero());
    try std.testing.expect(alternate.snapshot().isZero());

    capability.revoke();
    try std.testing.expect(capability.isRevoked());
    try std.testing.expect(!capability.validate(&carrier));
}

test "abrupt sidecar death mid stream in an overflow-origin request stays bounded and reclaims" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // A large 2xx that pauses mid-stream and never resumes.
    const big = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'y');
    const prefix = "overflow-stalled-prefix";
    @memcpy(big[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = big,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    // Budget below the request body: the request is stream-once (overflow origin)
    // and holds NO reservation while it streams — distinct from the replayable
    // mid-stream teardown already covered, which holds a live reservation.
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 4096,
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 8 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const body = try std.fmt.allocPrint(std.testing.allocator, "{{\"model\":\"{s}\",\"pad\":\"{s}\"}}", .{ routed_model, pad });
    defer std.testing.allocator.free(body);

    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    // Overflow origin: the request holds no reservation while it streams.
    try std.testing.expectEqual(@as(usize, 0), reservedBytes(listener));

    // Teardown must interrupt the stalled upstream read, stay bounded, and leave
    // the pool at zero.
    var shutdown_timer = try std.time.Timer.start();
    const outstanding = teardown(listener);
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 0), outstanding);
    try std.testing.expectEqual(@as(usize, 1), primary.snapshot().call_count);
    try std.testing.expect(alternate.snapshot().isZero());

    capability.revoke();
    try std.testing.expect(capability.isRevoked());
    try std.testing.expect(!capability.validate(&carrier));
}

// ===========================================================================
// §8.8 advisory-usage OBSERVATION wiring (TIN-2400, observation-only).
//
// These prove the §8.8 advisory behaviors are OBSERVABLE at the wire boundary,
// folded through the pure `advisory_usage` core. The fixture threads the core's
// own synthetic usage document through the `anthropic-ratelimit-usage` header;
// the sidecar records only value-free normalized state and at most one value-free
// event, and NEVER lets advisory data touch a routing/retry/terminal decision.
// The clock is the injected `WireClock` (VirtualClock) → `now_s`, so the 300 s
// freshness window and negative cache are pinned deterministically.
// ===========================================================================

const advisory_fresh_doc = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400}]}";
const advisory_empty_doc = "{\"schema_version\":1,\"usage\":[]}";
const advisory_v2_doc = "{\"schema_version\":2,\"usage\":[]}";
const advisory_v3_doc = "{\"schema_version\":3,\"usage\":[]}";

fn advisoryHeader(value: []const u8) std.http.Header {
    return .{ .name = advisory_usage_header, .value = value };
}

test "advisory observation: a fresh advisory is admitted, capped at .inferred, never .proven" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advisoryHeader(advisory_fresh_doc)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 200 OK\r\n");

    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.advisory.present);
    try std.testing.expectEqual(advisory_usage.Freshness.populated_fresh, obs.advisory.freshness);
    try std.testing.expectEqual(advisory_usage.Readiness.available, obs.advisory.readiness);
    // A fresh advisory is a classified read: exactly `.inferred`, never `.proven`.
    try std.testing.expectEqual(advisory_usage.Provenance.inferred, obs.advisory.provenance);
    try std.testing.expect(obs.advisory.provenance != .proven);
    try std.testing.expect(!obs.advisory.killed);
    try std.testing.expect(eventBufferContains(event_stream.getWritten(), "claude_proxy_advisory_observed"));
}

test "advisory observation: fresh within 300s, stale at the exact 300s boundary, no re-fetch" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // [0] populates at now_s=1000; [1]/[2] carry NO advisory header and only
    // re-observe the cached window (proving "no re-validation" within the window).
    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advisoryHeader(advisory_fresh_doc)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    // Populate at now_s = 1000.
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    try std.testing.expectEqual(advisory_usage.Freshness.populated_fresh, observationSnapshot(listener).advisory.freshness);

    // now_s = 1299 → still inside the window (age 299 < 300), reused without a header.
    vclock.now_ns = 1299 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const inside = observationSnapshot(listener);
    try std.testing.expect(!inside.advisory.present); // no re-fetch: cache reused
    try std.testing.expectEqual(advisory_usage.Freshness.populated_fresh, inside.advisory.freshness);

    // now_s = 1300 → exactly the boundary (age 300 >= 300) → stale, advisory degrades.
    vclock.now_ns = 1300 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const boundary = observationSnapshot(listener);
    try std.testing.expectEqual(advisory_usage.Freshness.populated_stale, boundary.advisory.freshness);
    try std.testing.expectEqual(advisory_usage.Readiness.unknown, boundary.advisory.readiness);
    try std.testing.expectEqual(advisory_usage.Provenance.unobserved, boundary.advisory.provenance);
}

test "advisory observation: a valid-empty advisory arms the negative cache to the 300s boundary" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advisoryHeader(advisory_empty_doc)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 500 * std.time.ns_per_s };
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    // Arm the negative cache at now_s = 500 with a valid EMPTY result.
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    try std.testing.expectEqual(advisory_usage.Freshness.negative_active, observationSnapshot(listener).advisory.freshness);

    // now_s = 799 → still inside the negative window; refused without re-validation.
    vclock.now_ns = 799 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const inside = observationSnapshot(listener);
    try std.testing.expect(!inside.advisory.present);
    try std.testing.expectEqual(advisory_usage.Freshness.negative_active, inside.advisory.freshness);

    // now_s = 800 → exactly the boundary → the negative cache has expired.
    vclock.now_ns = 800 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    try std.testing.expectEqual(advisory_usage.Freshness.negative_expired, observationSnapshot(listener).advisory.freshness);
}

test "advisory observation: an unknown schema trips the kill switch, one event per fingerprint" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Two distinct unknown schema fingerprints (v2, v3), each seen twice, then a
    // VALID doc that must NOT revive the process-lifetime kill latch.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advisoryHeader(advisory_v2_doc)} },
        .{ .status = .ok, .body = "b", .headers = &.{advisoryHeader(advisory_v2_doc)} },
        .{ .status = .ok, .body = "c", .headers = &.{advisoryHeader(advisory_v3_doc)} },
        .{ .status = .ok, .body = "d", .headers = &.{advisoryHeader(advisory_v3_doc)} },
        .{ .status = .ok, .body = "e", .headers = &.{advisoryHeader(advisory_fresh_doc)} },
    });
    defer primary.deinit();

    var event_buffer: [4096]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
    });
    defer listener.deinit();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        std.testing.allocator.free(try routedRequest(listener, &carrier));
        const obs = observationSnapshot(listener);
        try std.testing.expect(obs.advisory.present);
        try std.testing.expect(obs.advisory.killed); // latched from the first request onward
        try std.testing.expectEqual(advisory_usage.Freshness.killed, obs.advisory.freshness);
    }

    // Exactly ONE redacted event per DISTINCT schema fingerprint (v2, v3) — repeats
    // are deduped, and the later valid doc cannot revive the account.
    const written = event_stream.getWritten();
    try std.testing.expectEqual(
        @as(usize, 2),
        std.mem.count(u8, written, "claude_proxy_advisory_schema_rejected"),
    );

    // A killed account still yields honest reactive evidence (2xx → proven).
    const last = observationSnapshot(listener);
    try std.testing.expect(last.advisory.reactive_present);
    try std.testing.expectEqual(advisory_usage.Provenance.unobserved, last.advisory.provenance); // advisory ignored
    try std.testing.expectEqual(advisory_usage.Provenance.proven, last.advisory.elected_provenance);
}

test "advisory observation: reactive pre-body 429 outranks a fresh advisory" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Primary returns a pre-body 429 (the §2.2 reactive signal) while ALSO carrying
    // a fresh advisory that says "available". No alternate → the 429 is terminal.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{ .{ .name = "Retry-After", .value = "5" }, advisoryHeader(advisory_fresh_doc) },
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 429 Too Many Requests\r\n");

    const obs = observationSnapshot(listener);
    // The advisory itself normalized to available/.inferred ...
    try std.testing.expect(obs.advisory.present);
    try std.testing.expectEqual(advisory_usage.Readiness.available, obs.advisory.readiness);
    try std.testing.expectEqual(advisory_usage.Provenance.inferred, obs.advisory.provenance);
    // ... but the direct request-path (reactive) exhaustion OUTRANKS it: the
    // exposed election is proven-exhausted, not the advisory's available.
    try std.testing.expect(obs.advisory.reactive_present);
    try std.testing.expectEqual(advisory_usage.Readiness.exhausted, obs.advisory.elected_readiness);
    try std.testing.expectEqual(advisory_usage.Provenance.proven, obs.advisory.elected_provenance);
}

test "advisory observation: an advisory header changes no routing decision" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Two otherwise-identical requests: one response carries advisory headers, the
    // other does not. The routing/attempt accounting must be byte-identical.
    var with_adv = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advisoryHeader(advisory_fresh_doc)},
    }});
    defer with_adv.deinit();
    var without_adv = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "ok" }});
    defer without_adv.deinit();

    var vclock_a = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener_a = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &with_adv, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock_a.clock(),
    });
    defer listener_a.deinit();
    var vclock_b = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener_b = try startRoutedForTest(std.testing.allocator, capability, .{
        .primary = .{ .upstream = &without_adv, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock_b.clock(),
    });
    defer listener_b.deinit();

    std.testing.allocator.free(try routedRequest(listener_a, &carrier));
    std.testing.allocator.free(try routedRequest(listener_b, &carrier));

    const a = observationSnapshot(listener_a);
    const b = observationSnapshot(listener_b);

    // Advisory presence differs ...
    try std.testing.expect(a.advisory.present);
    try std.testing.expect(!b.advisory.present);
    // ... but EVERY routing/attempt observation is identical.
    try std.testing.expectEqual(a.attempts_total, b.attempts_total);
    try std.testing.expectEqual(a.alternate_count, b.alternate_count);
    try std.testing.expectEqual(a.same_route_retry_count, b.same_route_retry_count);
    try std.testing.expectEqual(a.third_attempt_count, b.third_attempt_count);
    try std.testing.expectEqual(a.upstream_status, b.upstream_status);
    try std.testing.expectEqual(a.replay_mode, b.replay_mode);
    try std.testing.expectEqualStrings(a.admittedModel(), b.admittedModel());
    try std.testing.expectEqual(with_adv.snapshot().call_count, without_adv.snapshot().call_count);
}

test "advisory observation: the event surface is value-free" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advisoryHeader(advisory_fresh_doc)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));

    const written = event_stream.getWritten();
    try std.testing.expect(eventBufferContains(written, "claude_proxy_advisory_observed"));
    // No provider payload value (limit, remaining, utilization, or reset epoch)
    // and no field name from the parsed document appears in any event.
    try std.testing.expect(!eventBufferContains(written, "1783652400"));
    try std.testing.expect(!eventBufferContains(written, "0.42"));
    try std.testing.expect(!eventBufferContains(written, "utilization"));
    try std.testing.expect(!eventBufferContains(written, "resets_at"));
    try std.testing.expect(!eventBufferContains(written, "schema_version"));
}

test "advisory observation: the observation surface carries no provider payload value" {
    // Structural value-free guarantee: every AdvisoryObservation field is a typed
    // enum or bool — no slice (raw text) and no int/float that could smuggle a
    // token count, limit, or reset epoch onto the surface.
    inline for (@typeInfo(AdvisoryObservation).@"struct".fields) |field| {
        const info = @typeInfo(field.type);
        try std.testing.expect(info == .@"enum" or info == .bool);
    }
}
