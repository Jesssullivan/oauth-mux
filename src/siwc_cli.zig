//! Typed, redacted owned enrollment client. Provider authority stays in the daemon.
const std = @import("std");
const builtin = @import("builtin");
const daemon = @import("daemon.zig");
const paths = @import("paths.zig");
const control = @import("control.zig");
pub const purpose = "fresh_openai_siwc_oauth_enrollment";
pub const profile = "openai_siwc_responses_v1";

pub const Command = union(enum) {
    descriptor, pending, start: u32, status: []const u8, cancel: []const u8, remove: []const u8,
};
pub fn validOpaqueHandle(value: []const u8) bool {
    if (value.len != 64 or std.mem.allEqual(u8, value, '0')) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    return true;
}
pub fn parse(args: []const []const u8) !Command {
    if (args.len == 1 and std.mem.eql(u8, args[0], "providers")) return .descriptor;
    if (args.len == 1 and std.mem.eql(u8, args[0], "pending")) return .pending;
    if (args.len == 4 and std.mem.eql(u8, args[0], "start") and std.mem.eql(u8, args[1], "--consent-seconds") and std.mem.eql(u8, args[3], "--confirm")) {
        if (args[2].len == 0 or args[2].len > 4) return error.InvalidConsent;
        for (args[2]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidConsent;
        const seconds = std.fmt.parseInt(u32, args[2], 10) catch return error.InvalidConsent;
        if (seconds == 0 or seconds > 3600) return error.InvalidConsent;
        return .{ .start = seconds };
    }
    if (args.len == 2 and validOpaqueHandle(args[1])) {
        if (std.mem.eql(u8, args[0], "status")) return .{ .status = args[1] };
        if (std.mem.eql(u8, args[0], "cancel")) return .{ .cancel = args[1] };
        if (std.mem.eql(u8, args[0], "remove")) return .{ .remove = args[1] };
    }
    return error.InvalidSignInArguments;
}
fn get(value: std.json.Value, key: []const u8) !std.json.Value { return control.get(value, key) orelse error.InvalidEnrollmentReply; }
fn string(value: std.json.Value, key: []const u8) ![]const u8 { return control.string(value, key) catch error.InvalidEnrollmentReply; }
fn is(value: std.json.Value, key: []const u8, expected: []const u8) bool {
    const actual = string(value, key) catch return false;
    return std.mem.eql(u8, actual, expected);
}
fn boolean(value: std.json.Value, key: []const u8, expected: bool) bool {
    const actual = control.get(value, key) orelse return false;
    return actual == .bool and actual.bool == expected;
}
fn unsigned(value: std.json.Value) !u64 {
    if (value != .number_string or value.number_string.len == 0) return error.InvalidEnrollmentReply;
    for (value.number_string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidEnrollmentReply;
    return std.fmt.parseInt(u64, value.number_string, 10) catch error.InvalidEnrollmentReply;
}
fn integer(value: std.json.Value, key: []const u8) !u64 { return unsigned(try get(value, key)); }
fn requestBytes(a: std.mem.Allocator, method: []const u8, params: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = @as(u32, 1), .method = method, .params = params }, .{});
}
fn fetch(io: std.Io, a: std.mem.Allocator, locations: paths.Locations, method: []const u8, params: anytype) !std.json.Parsed(std.json.Value) {
    const payload = try requestBytes(a, method, params);
    defer { std.crypto.secureZero(u8, payload); a.free(payload); }
    const bytes = try daemon.exchange(io, a, locations.control, payload);
    defer { std.crypto.secureZero(u8, bytes); a.free(bytes); }
    const parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .parse_numbers = false, .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    errdefer { control.wipeJson(parsed.value); parsed.deinit(); }
    if (!is(parsed.value, "jsonrpc", "2.0") or try integer(parsed.value, "id") != 1) return error.InvalidEnrollmentReply;
    if (control.get(parsed.value, "error") != null) {
        const failure = try get(parsed.value, "error");
        const message = string(failure, "message") catch return error.EnrollmentRefused;
        if (std.mem.eql(u8, message, "WrappingKeyUnavailable") or std.mem.eql(u8, message, "CustodyLocked") or std.mem.eql(u8, message, "VaultLocked") or std.mem.eql(u8, message, "Locked")) return error.EnrollmentCustodyUnavailable;
        return error.EnrollmentRefused;
    }
    const result_value = try get(parsed.value, "result");
    if (result_value != .object) return error.InvalidEnrollmentReply;
    return parsed;
}
fn finish(parsed: *std.json.Parsed(std.json.Value)) void { control.wipeJson(parsed.value); parsed.deinit(); }
fn result(parsed: std.json.Parsed(std.json.Value)) std.json.Value { return parsed.value.object.get("result").?; }
fn stdout(io: std.Io, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
    try writer.interface.writeAll(bytes); try writer.interface.writeByte('\n'); try writer.interface.flush();
}
fn emit(io: std.Io, a: std.mem.Allocator, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(bytes); try stdout(io, bytes);
}
pub fn descriptorValid(d: std.json.Value) bool {
    if ((integer(d, "schema_version") catch return false) != 1 or !is(d, "profile", profile) or !is(d, "purpose", purpose)
        or !is(d, "provider", "openai_siwc") or !is(d, "issuer", "https://auth.openai.com") or !is(d, "audience", "https://api.openai.com/v1")
        or !is(d, "enrollment_io_policy", "documented_oss_dynamic_registration_v1") or !boolean(d, "experimental", true)
        or !boolean(d, "provider_proof", false) or !boolean(d, "native_support_proven", false) or !boolean(d, "live_handoff_proven", false)) return false;
    const implemented = get(d, "implemented") catch return false;
    const custody = get(d, "custody_available") catch return false;
    if (implemented != .bool or custody != .bool) return false;
    const methods = get(d, "methods") catch return false;
    const flow = get(d, "flow") catch return false;
    return is(methods, "prepare", "oauth.enrollment.prepare.siwc.v1") and is(methods, "authorization", "oauth.enrollment.authorization.v1")
        and is(methods, "status", "oauth.enrollment.status.v1") and is(methods, "pending", "oauth.enrollment.pending.v1") and is(methods, "withdraw", "oauth.enrollment.withdraw.v1")
        and (integer(flow, "minimum_seconds") catch return false) == 1 and (integer(flow, "maximum_seconds") catch return false) == 3600
        and boolean(flow, "minted_once", true) and boolean(flow, "wall_and_awake", true) and boolean(flow, "rpc_deadline_separate", true) and boolean(flow, "reconnect_renews", false)
        and (integer(flow, "authorization_deliveries") catch return false) == 1;
}
/// Produce only the declared public status fields. Never relay a raw result or
/// provider error; even unexpected subject/client/authorization fields are omitted.
pub fn redactedStatus(a: std.mem.Allocator, s: std.json.Value, transaction: []const u8) ![]u8 {
    if ((try integer(s, "schema_version")) != 1 or !is(s, "transaction_id", transaction) or !validOpaqueHandle(transaction)) return error.InvalidEnrollmentReply;
    const state = try string(s, "status");
    var known = false;
    for ([_][]const u8{ "pending", "expired", "cancelled", "unknown", "quarantined", "paired", "retired", "not_retained" }) |name| if (std.mem.eql(u8, state, name)) { known = true; };
    if (!known) return error.InvalidEnrollmentReply;
    const custody = try get(s, "custody_available");
    const paired = try get(s, "paired_committed"); const ready = try get(s, "grant_ready");
    if (custody != .bool or (paired != .bool and paired != .null) or (ready != .bool and ready != .null)) return error.InvalidEnrollmentReply;
    if (!custody.bool and (!std.mem.eql(u8, state, "unknown") or paired != .null or ready != .null)) return error.InvalidEnrollmentReply;
    if (ready == .bool and ready.bool and (paired != .bool or !paired.bool or !std.mem.eql(u8, state, "paired"))) return error.InvalidEnrollmentReply;
    const phase = try get(s, "phase");
    if (phase != .null) {
        if (phase != .string) return error.InvalidEnrollmentReply;
        var phase_known = false;
        for ([_][]const u8{ "prepared", "callback_consumed", "exchange_issued", "verifying", "active", "completion_unknown", "quarantined", "retired" }) |name| if (std.mem.eql(u8, phase.string, name)) { phase_known = true; };
        if (!phase_known) return error.InvalidEnrollmentReply;
    }
    if (paired == .bool and paired.bool and ((!std.mem.eql(u8, state, "paired") and !std.mem.eql(u8, state, "retired"))
        or !is(s, "phase", if (std.mem.eql(u8, state, "paired")) "active" else "retired"))) return error.InvalidEnrollmentReply;
    if (paired == .bool and paired.bool) {
        const retirement = try string(s, "retirement_reason");
        var reason_known = false;
        for ([_][]const u8{ "none", "withdrawn", "source_disconnected", "forgotten" }) |name| if (std.mem.eql(u8, retirement, name)) { reason_known = true; };
        if (!reason_known) return error.InvalidEnrollmentReply;
    }
    if (custody.bool) _ = try integer(s, "revision");
    if (control.get(s, "consent_status")) |consent| {
        if (consent != .string or (!std.mem.eql(u8, consent.string, "recorded") and !std.mem.eql(u8, consent.string, "withdrawn"))) return error.InvalidEnrollmentReply;
    }
    for ([_][]const u8{ "flow_expires_at", "flow_seconds" }) |key| if (control.get(s, key)) |value| {
        const number = try unsigned(value);
        if (number == 0 or (std.mem.eql(u8, key, "flow_seconds") and number > 3600) or number > std.math.maxInt(i64)) return error.InvalidEnrollmentReply;
    };
    if (control.get(s, "flow_expired")) |value| if (value != .bool) return error.InvalidEnrollmentReply;
    var out: std.json.ObjectMap = .empty;
    defer out.deinit(a);
    for ([_][]const u8{ "schema_version", "transaction_id", "revision", "status", "phase", "custody_available", "paired_committed", "grant_ready", "consent_status", "retirement_reason", "flow_expired", "flow_expires_at", "flow_seconds", "source_id", "account_id" }) |key| {
        if (control.get(s, key)) |value| {
            if (std.mem.eql(u8, key, "retirement_reason") and (paired != .bool or !paired.bool)) return error.InvalidEnrollmentReply;
            if (std.mem.eql(u8, key, "source_id") or std.mem.eql(u8, key, "account_id")) {
                if (value != .null and (value != .string or !validOpaqueHandle(value.string))) return error.InvalidEnrollmentReply;
                if (std.mem.eql(u8, key, "account_id") and value != .null and (paired != .bool or !paired.bool)) return error.InvalidEnrollmentReply;
            }
            try out.put(a, key, value);
        }
    }
    try out.put(a, "native_support_proven", .{ .bool = false });
    return std.json.Stringify.valueAlloc(a, std.json.Value{ .object = out }, .{});
}
fn observe(io: std.Io, a: std.mem.Allocator, locations: paths.Locations, transaction: []const u8) !std.json.Parsed(std.json.Value) {
    var reply = try fetch(io, a, locations, "oauth.enrollment.status.v1", .{ .purpose = purpose, .transaction_id = transaction });
    errdefer finish(&reply);
    const safe = try redactedStatus(a, result(reply), transaction);
    defer a.free(safe);
    return reply;
}
pub fn browserHelper(a: std.mem.Allocator, executable: []const u8, install_prefix: ?[]const u8) ![]u8 {
    // The portable launcher replaces inherited OMUX_INSTALL_PREFIX and execs
    // its private loader. Accept only the exact declared loader/root relation;
    // never search PATH or treat an arbitrary prefix as a helper authority.
    if (install_prefix) |root| {
        if (root.len == 0 or root[0] != '/' or root[root.len - 1] == '/') return error.PackagedBrowserControlRequired;
        var parts = std.mem.splitScalar(u8, root[1..], '/');
        while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.PackagedBrowserControlRequired;
        for ([_][]const u8{ "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1" }) |loader| {
            const expected = try std.fmt.allocPrint(a, "{s}/lib/omux/lib/{s}", .{ root, loader });
            defer a.free(expected);
            if (std.mem.eql(u8, executable, expected)) return std.fmt.allocPrint(a, "{s}/bin/omux-control", .{root});
        }
    }
    const suffix = "/lib/omux/libexec/omux.bin";
    if (std.mem.endsWith(u8, executable, suffix)) return std.fmt.allocPrint(a, "{s}/bin/omux-control", .{executable[0 .. executable.len - suffix.len]});
    if (std.mem.endsWith(u8, executable, "/bin/omux")) return std.fs.path.join(a, &.{ std.fs.path.dirname(executable).?, "omux-control" });
    return error.PackagedBrowserControlRequired;
}
fn openBrowser(io: std.Io, a: std.mem.Allocator, url: []const u8, install_prefix: ?[]const u8) !void {
    if (builtin.os.tag != .linux) return error.BrowserControlUnsupported;
    if (url.len == 0 or url.len > 7000) return error.InvalidEnrollmentReply;
    const executable = try std.process.executablePathAlloc(io, a);
    defer a.free(executable);
    const helper = try browserHelper(a, executable, install_prefix);
    defer a.free(helper);
    const frame = try std.json.Stringify.valueAlloc(a, .{ .authorization_url = url, .profile = profile }, .{});
    defer { std.crypto.secureZero(u8, frame); a.free(frame); }
    var child = try std.process.spawn(io, .{ .argv = &.{ helper, "--siwc-open-authorization-stdin" }, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore });
    defer child.kill(io);
    const Wait = struct {
        fn run(wait_io: std.Io, process: *std.process.Child, bytes: []const u8, done: *std.Io.Event, term: *?std.process.Child.Term) std.Io.Cancelable!void {
            defer done.set(wait_io);
            var buffer: [1024]u8 = undefined;
            defer std.crypto.secureZero(u8, &buffer);
            var writer = process.stdin.?.writerStreaming(wait_io, &buffer);
            writer.interface.writeAll(bytes) catch return;
            writer.interface.writeByte('\n') catch return;
            writer.interface.flush() catch return;
            process.stdin.?.close(wait_io); process.stdin = null;
            term.* = process.wait(wait_io) catch null;
        }
    };
    var done: std.Io.Event = .unset;
    var term: ?std.process.Child.Term = null;
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, Wait.run, .{ io, &child, frame, &done, &term });
    done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(15) } }) catch return error.BrowserDeliveryUnknown;
    try group.await(io);
    const outcome = term orelse return error.BrowserDeliveryUnknown;
    switch (outcome) { .exited => |code| if (code != 0) return error.BrowserDeliveryRefused, else => return error.BrowserDeliveryRefused }
}
pub fn run(io: std.Io, a: std.mem.Allocator, locations: paths.Locations, args: []const []const u8, install_prefix: ?[]const u8) !void {
    const command = try parse(args);
    var hello = try fetch(io, a, locations, "system.handshake", .{ .protocol_version = 2, .client = "omux-cli-siwc" });
    defer finish(&hello);
    const handshake = result(hello);
    const capabilities = try get(handshake, "capabilities");
    if ((try integer(handshake, "protocol_version")) != 2 or !boolean(capabilities, "owned_siwc_enrollment_v1", true)) return error.OwnedEnrollmentUpdateRequired;
    var descriptor = try fetch(io, a, locations, "oauth.enrollment.descriptor.v1", @as(?u8, null));
    defer finish(&descriptor);
    const d = result(descriptor);
    if (!descriptorValid(d)) return error.UnsupportedEnrollmentDescriptor;
    switch (command) {
        .descriptor => return emit(io, a, .{ .profile = profile, .experimental = true, .implemented = boolean(d, "implemented", true), .custody_available = boolean(d, "custody_available", true), .provider_proof = false, .native_support_proven = false, .consent_max_seconds = 3600 }),
        .pending => {
            var reply = try fetch(io, a, locations, "oauth.enrollment.pending.v1", @as(?u8, null));
            defer finish(&reply);
            const s = result(reply);
            const custody = try get(s, "custody_available");
            if ((try integer(s, "schema_version")) != 1 or custody != .bool) return error.InvalidEnrollmentReply;
            if (!custody.bool) {
                if (!is(s, "status", "unknown") or (try get(s, "pending")) != .null) return error.InvalidEnrollmentReply;
                return emit(io, a, .{ .status = "unknown", .custody_available = false, .pending = @as(?u8, null) });
            }
            if (!is(s, "status", "current")) return error.InvalidEnrollmentReply;
            const rows = try get(s, "pending");
            if (rows != .array or rows.array.items.len > 16) return error.InvalidEnrollmentReply;
            var safe: std.ArrayList(struct { transaction_id: []const u8, source_id: []const u8, authorization_delivered: bool }) = .empty;
            defer safe.deinit(a);
            for (rows.array.items) |row| {
                const transaction = try string(row, "transaction_id"); const source = try string(row, "source_id");
                const delivered = try get(row, "authorization_delivered");
                if (!validOpaqueHandle(transaction) or !validOpaqueHandle(source) or delivered != .bool) return error.InvalidEnrollmentReply;
                try safe.append(a, .{ .transaction_id = transaction, .source_id = source, .authorization_delivered = delivered.bool });
            }
            return emit(io, a, .{ .status = "current", .pending = safe.items });
        },
        .status => |transaction| {
            var reply = try observe(io, a, locations, transaction); defer finish(&reply);
            const safe = try redactedStatus(a, result(reply), transaction); defer a.free(safe); return stdout(io, safe);
        },
        .cancel, .remove => |transaction| {
            var before = try observe(io, a, locations, transaction); defer finish(&before);
            const s = result(before);
            if (!boolean(s, "custody_available", true)) return error.EnrollmentCustodyUnavailable;
            var random: [32]u8 = undefined; try io.randomSecure(&random);
            const operation = std.fmt.bytesToHex(random, .lower);
            try emit(io, a, .{ .operation_id = operation[0..], .transaction_id = transaction, .action = "withdraw_this_source_only", .upstream_revoked = false });
            var reply = try fetch(io, a, locations, "oauth.enrollment.withdraw.v1", .{ .operation_id = operation[0..], .expected_revision = try get(s, "revision"), .purpose = purpose, .transaction_id = transaction });
            defer finish(&reply);
            if (!boolean(result(reply), "consent_withdrawn", true) or !boolean(result(reply), "upstream_revoked", false)) return error.InvalidEnrollmentReply;
            return emit(io, a, .{ .consent_withdrawn = true, .upstream_revoked = false, .message = "Local source consent withdrawn; any retained paired grants for it retired. Issued work may have occurred; native history is unchanged." });
        },
        .start => |seconds| {
            if (builtin.os.tag != .linux) return error.BrowserControlUnsupported;
            try std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 });
            if (!boolean(d, "implemented", true)) return error.UnsupportedEnrollmentDescriptor;
            if (!boolean(d, "custody_available", true)) return error.EnrollmentCustodyUnavailable;
            var snapshot = try fetch(io, a, locations, "state.snapshot", @as(?u8, null)); defer finish(&snapshot);
            const revision = try get(result(snapshot), "revision"); _ = try unsigned(revision);
            var random: [32]u8 = undefined; try io.randomSecure(&random);
            const operation = std.fmt.bytesToHex(random, .lower);
            try emit(io, a, .{ .operation_id = operation[0..], .status = "consent_submission", .consent_seconds = seconds, .message = "Explicit finite Omux API enrollment; no native Codex or live continuity support claimed. Query this original operation after any unknown reply; never repeat it automatically." });
            var prepared = try fetch(io, a, locations, "oauth.enrollment.prepare.siwc.v1", .{ .operation_id = operation[0..], .expected_revision = revision, .provider = "openai_siwc", .purpose = purpose, .consent_seconds = seconds });
            defer finish(&prepared);
            const r = result(prepared);
            const transaction = try string(r, "transaction_id"); const source = try string(r, "source_id");
            if (!validOpaqueHandle(transaction) or !validOpaqueHandle(source) or !is(r, "phase", "prepared") or !boolean(r, "consent_recorded", true)
                or !is(r, "registration", "enrollment_policy") or !boolean(r, "authorization_available", true)
                or !boolean(r, "provider_request_initiated", false) or !boolean(r, "grant_activated", false)
                or try integer(r, "flow_seconds") != seconds) return error.InvalidEnrollmentReply;
            _ = try integer(r, "flow_expires_at"); _ = try integer(r, "admitted_revision");
            if ((try get(r, "blocked_reason")) != .null) return error.InvalidEnrollmentReply;
            try emit(io, a, .{ .transaction_id = transaction, .source_id = source, .status = "pending", .paired_committed = false, .grant_ready = false, .flow_expires_at = try get(r, "flow_expires_at"), .message = "One-use browser delivery follows. Check sign-in status with this opaque transaction; browser delivery never means enrollment succeeded." });
            var current = try observe(io, a, locations, transaction); defer finish(&current);
            if (!is(result(current), "status", "pending") or !is(result(current), "phase", "prepared")) return error.EnrollmentRefused;
            var authorization = try fetch(io, a, locations, "oauth.enrollment.authorization.v1", .{ .purpose = purpose, .transaction_id = transaction, .expected_revision = try get(result(current), "revision") });
            defer finish(&authorization);
            const delivered = result(authorization);
            if (!boolean(delivered, "provider_request_initiated", false) or !boolean(delivered, "grant_activated", false)) return error.InvalidEnrollmentReply;
            openBrowser(io, a, try string(delivered, "authorization_url"), install_prefix) catch return error.BrowserDeliveryUnknown;
            return emit(io, a, .{ .transaction_id = transaction, .browser_delivery = "accepted_by_default_handler", .status = "pending", .message = "Use sign-in status to inspect actual paired enrollment. Failed/unknown delivery is not retried; cancel before fresh consent." });
        },
    }
}

test "typed consent and source-specific handles do not admit JSON or unsupported duration" {
    const selected = try parse(&.{ "start", "--consent-seconds", "3600", "--confirm" });
    try std.testing.expectEqual(@as(u32, 3600), selected.start);
    for ([_][]const []const u8{ &.{"start"}, &.{ "start", "--consent-seconds", "3601", "--confirm" },
        &.{ "start", "--consent-seconds", "0", "--confirm" }, &.{ "start", "--consent-seconds", "60", "--poll-renew" },
        &.{ "cancel", "descriptive-account-label" }, &.{ "status", "{}" } }) |args| {
        if (parse(args)) |_| return error.UnexpectedAdmission else |_| {}
    }
    const handle = "1111111111111111111111111111111111111111111111111111111111111111";
    try std.testing.expectEqualStrings(handle, (try parse(&.{ "remove", handle })).remove);
}

test "production enrollment request bytes reach the actual daemon parser with null or typed object parameters" {
    const a = std.testing.allocator;
    for ([_][]const u8{ "oauth.enrollment.descriptor.v1", "oauth.enrollment.pending.v1", "state.snapshot" }) |method| {
        const bytes = try requestBytes(a, method, @as(?u8, null));
        defer a.free(bytes);
        var parsed = try control.parse(a, bytes);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(method, parsed.method);
        try std.testing.expect(parsed.params == .null);
    }
    // Retain the actual former wire refusal; do not relax object/null parsing.
    const bad = try requestBytes(a, "oauth.enrollment.descriptor.v1", .{});
    defer a.free(bad);
    try std.testing.expectError(error.InvalidParams, control.parse(a, bad));
    const transaction = "1111111111111111111111111111111111111111111111111111111111111111";
    const bytes = try requestBytes(a, "oauth.enrollment.authorization.v1", .{ .purpose = purpose, .transaction_id = transaction, .expected_revision = @as(u64, 9007199254740993) });
    defer a.free(bytes);
    var selected = try control.parse(a, bytes);
    defer selected.deinit();
    try std.testing.expect(selected.params == .object and selected.params.object.count() == 3);
    try std.testing.expectEqualStrings(transaction, try control.string(selected.params, "transaction_id"));
    try std.testing.expectEqual(@as(u64, 9007199254740993), try control.expectedRevision(selected.params));
}

test "actual redacted status projection preserves exact revision and paired versus usable truth" {
    const a = std.testing.allocator;
    const transaction = "1111111111111111111111111111111111111111111111111111111111111111";
    const source = "2222222222222222222222222222222222222222222222222222222222222222";
    const account = "3333333333333333333333333333333333333333333333333333333333333333";
    const bytes = try std.json.Stringify.valueAlloc(a, .{
        .schema_version = 1, .transaction_id = transaction, .revision = @as(u64, 9007199254740993), .status = "paired", .phase = "active",
        .custody_available = true, .paired_committed = true, .grant_ready = false, .source_id = source, .account_id = account,
        .consent_status = "recorded", .retirement_reason = "none", .subject = "excluded-fixture", .issued_client_id = "excluded-fixture", .authorization_url = "excluded-fixture",
    }, .{});
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .parse_numbers = false, .allocate = .alloc_always });
    defer parsed.deinit();
    const safe = try redactedStatus(a, parsed.value, transaction);
    defer a.free(safe);
    try std.testing.expect(std.mem.indexOf(u8, safe, "\"revision\":9007199254740993") != null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "\"grant_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "excluded-fixture") == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "authorization_url") == null);
    try parsed.value.object.put(a, "phase", .{ .string = "unsupported-phase" });
    try std.testing.expectError(error.InvalidEnrollmentReply, redactedStatus(a, parsed.value, transaction));
}

test "unloaded custody is unknown rather than zero or usable and browser locator is package-bound" {
    const a = std.testing.allocator;
    const transaction = "1111111111111111111111111111111111111111111111111111111111111111";
    const bytes = try std.json.Stringify.valueAlloc(a, .{ .schema_version = 1, .transaction_id = transaction, .status = "unknown", .phase = @as(?u8, null),
        .custody_available = false, .paired_committed = @as(?bool, null), .grant_ready = @as(?bool, null), .reason = "custody_unavailable" }, .{});
    defer a.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .parse_numbers = false });
    defer parsed.deinit();
    const safe = try redactedStatus(a, parsed.value, transaction); defer a.free(safe);
    try std.testing.expect(std.mem.indexOf(u8, safe, "\"paired_committed\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "\"grant_ready\":null") != null);
    const helper = try browserHelper(a, "/selected/package/lib/omux/libexec/omux.bin", null); defer a.free(helper);
    try std.testing.expectEqualStrings("/selected/package/bin/omux-control", helper);
    try std.testing.expectError(error.PackagedBrowserControlRequired, browserHelper(a, "/unpackaged/omux", null));
    // Actual launcher carrier: /proc/self/exe is the declared loader, while the
    // launcher-owned prefix identifies its sibling public control launcher.
    for ([_][]const u8{ "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1" }) |loader| {
        const executable = try std.fmt.allocPrint(a, "/selected/package/lib/omux/lib/{s}", .{loader}); defer a.free(executable);
        const packaged = try browserHelper(a, executable, "/selected/package"); defer a.free(packaged);
        try std.testing.expectEqualStrings("/selected/package/bin/omux-control", packaged);
        try std.testing.expectError(error.PackagedBrowserControlRequired, browserHelper(a, executable, null));
        try std.testing.expectError(error.PackagedBrowserControlRequired, browserHelper(a, executable, "/different/package"));
    }
    try std.testing.expectError(error.PackagedBrowserControlRequired, browserHelper(a, "/unpackaged/omux", "/selected/package"));
    try std.testing.expectError(error.PackagedBrowserControlRequired, browserHelper(a, "/selected/package/lib/omux/lib/ld-fixture.so", "/selected/package"));
}
