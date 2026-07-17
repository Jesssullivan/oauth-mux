//! Typed, value-free observations for the authoritative Claude fake-upstream lane.
//!
//! This test artifact records only fixed fact identifiers and pass/fail states.
//! It never persists request bytes, headers, capability values, model names, paths,
//! account identifiers, or provider data.

const std = @import("std");
const capability_mod = @import("session_capability.zig");
const fake_upstream_mod = @import("fake_upstream.zig");
const wire_proxy = @import("wire_proxy.zig");

const SessionCapability = capability_mod.SessionCapability;
const FakeUpstream = fake_upstream_mod.FakeUpstream;

const Status = enum { pass, fail };

pub const BuildIdentity = struct {
    candidate_sha: []const u8,
    candidate_tree: []const u8,
    workflow_run_id: []const u8,
    workflow_run_attempt: []const u8,
    gf_target_class: []const u8,
};

const FactId = enum {
    listener_bound_ipv4_loopback,
    carrier_is_canonical_256bit_base64url,
    valid_capability_reaches_fake_once,
    invalid_capability_returns_401,
    invalid_capability_adds_zero_fake_calls,
    invalid_capability_observation_is_fresh,
    caller_auth_headers_absent_upstream,
    forwarding_identity_headers_absent_upstream,
    hop_headers_absent_upstream,
    required_safe_headers_present_upstream,
    invalid_origin_requests_return_400,
    forward_proxy_requests_return_400,
    invalid_origin_and_proxy_requests_add_zero_fake_calls,
    redirect_returns_local_502,
    redirect_is_not_followed,
    streaming_prefix_arrives_before_upstream_completion,
    streaming_body_arrives_byte_preserved,
    streaming_uses_one_fake_call,
    provider_5xx_status_and_body_pass_through,
    provider_5xx_uses_one_fake_call,
};

const fact_ids = [_]FactId{
    .listener_bound_ipv4_loopback,
    .carrier_is_canonical_256bit_base64url,
    .valid_capability_reaches_fake_once,
    .invalid_capability_returns_401,
    .invalid_capability_adds_zero_fake_calls,
    .invalid_capability_observation_is_fresh,
    .caller_auth_headers_absent_upstream,
    .forwarding_identity_headers_absent_upstream,
    .hop_headers_absent_upstream,
    .required_safe_headers_present_upstream,
    .invalid_origin_requests_return_400,
    .forward_proxy_requests_return_400,
    .invalid_origin_and_proxy_requests_add_zero_fake_calls,
    .redirect_returns_local_502,
    .redirect_is_not_followed,
    .streaming_prefix_arrives_before_upstream_completion,
    .streaming_body_arrives_byte_preserved,
    .streaming_uses_one_fake_call,
    .provider_5xx_status_and_body_pass_through,
    .provider_5xx_uses_one_fake_call,
};

const Fact = struct {
    id: FactId,
    status: Status,
};

const Artifact = struct {
    schema_version: u8 = 1,
    target: []const u8 = "v02-stage2-conformance",
    candidate_sha: []const u8,
    candidate_tree: []const u8,
    workflow_run_id: u64,
    workflow_run_attempt: u64,
    gf_target_class: []const u8,
    facts: []const Fact,
};

pub fn emit(identity: BuildIdentity) !void {
    try validateBuildIdentity(identity);

    var facts: [fact_ids.len]Fact = undefined;
    for (&facts, fact_ids) |*fact, id| fact.* = .{ .id = id, .status = .fail };

    runCapabilityScenario(&facts) catch {};
    runHeaderBoundaryScenario(&facts) catch {};
    runOriginBoundaryScenario(&facts) catch {};
    runRedirectScenario(&facts) catch {};
    runStreamingScenario(&facts) catch {};
    runProvider5xxScenario(&facts) catch {};

    const artifact = Artifact{
        .candidate_sha = identity.candidate_sha,
        .candidate_tree = identity.candidate_tree,
        .workflow_run_id = try parsePositiveInteger(identity.workflow_run_id),
        .workflow_run_attempt = try parsePositiveInteger(identity.workflow_run_attempt),
        .gf_target_class = identity.gf_target_class,
        .facts = &facts,
    };
    try writeArtifactAtomic(artifact);

    for (facts) |fact| {
        if (fact.status != .pass) return error.Stage2ObservationFailed;
    }
}

fn validateBuildIdentity(identity: BuildIdentity) !void {
    if (!isLowerHexSha(identity.candidate_sha)) return error.InvalidCandidateSha;
    if (!isLowerHexSha(identity.candidate_tree)) return error.InvalidCandidateTree;
    _ = try parsePositiveInteger(identity.workflow_run_id);
    _ = try parsePositiveInteger(identity.workflow_run_attempt);
    if (!std.mem.eql(u8, identity.gf_target_class, "tinyland-nix")) {
        return error.InvalidGfTargetClass;
    }
}

fn isLowerHexSha(value: []const u8) bool {
    if (value.len != 40) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn parsePositiveInteger(value: []const u8) !u64 {
    const parsed = try std.fmt.parseInt(u64, value, 10);
    if (parsed == 0) return error.ExpectedPositiveInteger;
    return parsed;
}

fn setFact(facts: []Fact, id: FactId, passed: bool) void {
    for (facts) |*fact| {
        if (fact.id != id) continue;
        fact.status = if (passed) .pass else .fail;
        return;
    }
    unreachable;
}

fn copyCarrier(capability: *SessionCapability) ![capability_mod.carrier_len]u8 {
    var carrier: [capability_mod.carrier_len]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &carrier);
    try capability.copyCarrier(&carrier);
    return carrier;
}

fn canonicalCarrier(carrier: *const [capability_mod.carrier_len]u8) bool {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(carrier) catch return false;
    if (decoded_len != capability_mod.entropy_len) return false;
    var decoded: [capability_mod.entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    decoder.decode(&decoded, carrier) catch return false;
    var reencoded: [capability_mod.carrier_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &reencoded);
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&reencoded, &decoded);
    return std.mem.eql(u8, carrier, encoded);
}

fn runCapabilityScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const expected = try std.net.Address.parseIp("127.0.0.1", listener.port());
    setFact(facts, .listener_bound_ipv4_loopback, expected.eql(listener.address()));
    setFact(facts, .carrier_is_canonical_256bit_base64url, canonicalCarrier(&carrier));

    const accepted = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(accepted);
    const accepted_response = try requestRawAlloc(listener.address(), accepted);
    defer std.testing.allocator.free(accepted_response);
    setFact(
        facts,
        .valid_capability_reaches_fake_once,
        hasStatus(accepted_response, "204 No Content") and upstream.snapshot().call_count == 1,
    );
    const accepted_observation = wire_proxy.testing.requestObservation(listener);

    var wrong = [_]u8{'A'} ** capability_mod.carrier_len;
    defer std.crypto.secureZero(u8, &wrong);
    if (std.mem.eql(u8, &wrong, &carrier)) wrong[0] = 'B';
    const rejected = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), wrong },
    );
    defer std.testing.allocator.free(rejected);
    const before_rejection_calls = upstream.snapshot().call_count;
    const rejected_response = try requestRawAlloc(listener.address(), rejected);
    defer std.testing.allocator.free(rejected_response);
    const rejected_observation = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .invalid_capability_returns_401, hasStatus(rejected_response, "401 Unauthorized"));
    setFact(
        facts,
        .invalid_capability_adds_zero_fake_calls,
        upstream.snapshot().call_count == before_rejection_calls,
    );
    setFact(
        facts,
        .invalid_capability_observation_is_fresh,
        rejected_observation.request_id == accepted_observation.request_id + 1 and
            rejected_observation.outcome == .capability_rejected and
            !rejected_observation.upstream_attempted,
    );
}

fn runHeaderBoundaryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nX-Api-Key: synthetic\r\nCookie: synthetic\r\nForwarded: host=synthetic.invalid\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-Host: synthetic.invalid\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 192.0.2.2\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic synthetic\r\nProxy-Authorization: Basic synthetic\r\nProxy-Connection: keep-alive\r\nConnection: {s}, close\r\n{s}: remove\r\nTE: trailers\r\nTrailer: X-Result\r\nTrailers: X-Result\r\nUpgrade: websocket\r\nAnthropic-Version: 2023-06-01\r\n\r\n",
        .{
            listener.port(),
            carrier,
            fake_upstream_mod.connection_nominated_canary,
            fake_upstream_mod.connection_nominated_canary,
        },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    if (!hasStatus(response, "204 No Content") or upstream.snapshot().call_count != 1) return;

    const presence = upstream.requestHeaderPresenceSnapshot();
    setFact(
        facts,
        .caller_auth_headers_absent_upstream,
        !presence.authorization and !presence.x_api_key and !presence.cookie,
    );
    setFact(
        facts,
        .forwarding_identity_headers_absent_upstream,
        !presence.forwarded and !presence.x_forwarded_for and
            !presence.x_forwarded_host and !presence.x_forwarded_port and
            !presence.x_forwarded_proto and !presence.x_real_ip,
    );
    setFact(
        facts,
        .hop_headers_absent_upstream,
        !presence.keep_alive and !presence.proxy_authenticate and
            !presence.proxy_authorization and !presence.proxy_connection and
            !presence.x_private_hop_canary and !presence.te and !presence.trailer and
            !presence.trailers and !presence.upgrade and !presence.expect,
    );
    setFact(
        facts,
        .required_safe_headers_present_upstream,
        presence.accept_encoding and presence.anthropic_version,
    );
}

fn runOriginBoundaryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const invalid_origin = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (invalid_origin) |request| std.testing.allocator.free(request);
    var origin_ok = true;
    for (invalid_origin) |request| {
        const response = try requestRawAlloc(listener.address(), request);
        defer std.testing.allocator.free(response);
        origin_ok = origin_ok and hasStatus(response, "400 Bad Request");
    }
    setFact(facts, .invalid_origin_requests_return_400, origin_ok);

    const proxy_forms = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "GET https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (proxy_forms) |request| std.testing.allocator.free(request);
    var proxy_ok = true;
    for (proxy_forms) |request| {
        const response = try requestRawAlloc(listener.address(), request);
        defer std.testing.allocator.free(response);
        proxy_ok = proxy_ok and hasStatus(response, "400 Bad Request");
    }
    setFact(facts, .forward_proxy_requests_return_400, proxy_ok);
    setFact(
        facts,
        .invalid_origin_and_proxy_requests_add_zero_fake_calls,
        upstream.snapshot().isZero(),
    );
}

fn runRedirectScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var redirect_trap = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer redirect_trap.deinit();
    const redirect_location = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/blocked",
        .{redirect_trap.baseUrl()},
    );
    defer std.testing.allocator.free(redirect_location);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .found,
        .headers = &.{.{ .name = "Location", .value = redirect_location }},
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const request = try basicGetRequest(listener.port(), &carrier);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    setFact(facts, .redirect_returns_local_502, hasStatus(response, "502 Bad Gateway"));
    setFact(
        facts,
        .redirect_is_not_followed,
        upstream.snapshot().call_count == 1 and redirect_trap.snapshot().isZero(),
    );
}

fn runStreamingScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const first = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .pause_after_bytes = first.len,
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const body = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequest(listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, first);
    setFact(
        facts,
        .streaming_prefix_arrives_before_upstream_completion,
        hasStatus(response.items, "200 OK") and
            std.mem.indexOf(u8, response.items, first) != null and
            std.mem.indexOf(u8, response.items, rest) == null,
    );
    upstream.releasePausedResponse();
    try readResponseRemainder(&stream, &response);
    const body_start = std.mem.indexOf(u8, response.items, "\r\n\r\n");
    setFact(
        facts,
        .streaming_body_arrives_byte_preserved,
        body_start != null and
            std.mem.eql(u8, response.items[body_start.? + 4 ..], first ++ rest),
    );
    setFact(facts, .streaming_uses_one_fake_call, upstream.snapshot().call_count == 1);
}

fn runProvider5xxScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const body = "{\"type\":\"error\",\"error\":{\"type\":\"api_error\"}}";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .internal_server_error,
        .body = body,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const request_body = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequest(listener.port(), &carrier, request_body);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    setFact(
        facts,
        .provider_5xx_status_and_body_pass_through,
        hasStatus(response, "500 Internal Server Error") and std.mem.endsWith(u8, response, body),
    );
    setFact(facts, .provider_5xx_uses_one_fake_call, upstream.snapshot().call_count == 1);
}

fn basicGetRequest(port: u16, carrier: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ port, carrier },
    );
}

fn postRequest(port: u16, carrier: []const u8, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ port, carrier, body.len, body },
    );
}

fn requestRawAlloc(address: std.net.Address, bytes: []const u8) ![]u8 {
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(bytes);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    errdefer response.deinit();
    var buffer: [1024]u8 = undefined;
    while (true) {
        const count = try stream.read(&buffer);
        if (count == 0) break;
        try response.appendSlice(buffer[0..count]);
    }
    return response.toOwnedSlice();
}

fn hasStatus(response: []const u8, status: []const u8) bool {
    return std.mem.startsWith(u8, response, "HTTP/1.1 ") and
        std.mem.indexOf(u8, response[9..], status) == 0;
}

fn waitForResponsePrefix(upstream: *FakeUpstream) !void {
    var timer = try std.time.Timer.start();
    while (!upstream.responsePrefixWritten()) {
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

fn writeArtifactAtomic(artifact: Artifact) !void {
    const output = "v02-stage2-observations.json";
    const temporary = "v02-stage2-observations.json.tmp";
    const cwd = std.fs.cwd();
    cwd.deleteFile(temporary) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var file = try cwd.createFile(temporary, .{ .exclusive = true });
    var file_open = true;
    errdefer {
        if (file_open) file.close();
        cwd.deleteFile(temporary) catch {};
    }
    var buffered = std.io.bufferedWriter(file.writer());
    try std.json.stringify(artifact, .{}, buffered.writer());
    try buffered.writer().writeByte('\n');
    try buffered.flush();
    try file.sync();
    file.close();
    file_open = false;
    try cwd.rename(temporary, output);
}
