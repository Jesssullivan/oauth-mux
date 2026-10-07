//! Actual actor diagnostics: retained synthetic authority is not native-launch,
//! provider enrollment, installation-success or seamless-handoff evidence.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const control = @import("control.zig");
const engine = @import("engine.zig");
const readiness = @import("application_readiness.zig");
const native_fixture = @import("native_owner_fixture.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;
const Demand = struct {
    provider: []const u8 = "codex",
    audience: []const u8 = "https://chatgpt.com",
    resource: struct { kind: []const u8 = "model", target: []const u8 = "generated-fixture-model" } = .{},
    purpose: []const u8 = "request",
    required: f64 = 1,
    scopes: []const []const u8 = &.{},
};
const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    method: RpcMethod,
    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
    fn result(self: *const Reply) !std.json.Value {
        return control.get(self.parsed.value, "result") orelse {
            const failure = control.get(self.parsed.value, "error");
            const message = if (failure) |value| control.string(value, "message") catch "" else "";
            const category = std.meta.stringToEnum(RpcFailure, message) orelse .unclassified;
            // Only fixed method/error labels enter diagnostics. Never print
            // the response, request, private references or provider data.
            std.debug.print("application-readiness actor RPC {s}: {s}\n", .{ @tagName(self.method), @tagName(category) });
            return error.UnexpectedRpcFailure;
        };
    }
    fn expectError(self: *const Reply, category: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.ExpectedRpcFailure;
        try std.testing.expectEqualStrings(category, try control.string(failure, "message"));
    }
};
const RpcFailure = enum { InvalidParams, InvalidApplicationContext, UnknownField, MissingField, InvalidPurpose, NoEligibleAccount, SnapshotTooLarge, InvalidNativeOperation, CustodyUnavailable, InvalidSnapshotCreditAuthority, OutOfMemory, UnsupportedPolicy, InvalidMaintenanceReservation, DatabaseFailure, RevisionConflict, InvalidMutationResult, SyntaxError, unclassified };
const RpcMethod = enum { health, policy_set, source_connect, enrollment, readiness, stored, provider_submissions, poisoned, other };
fn rpcMethod(method: []const u8) RpcMethod {
    const names = [_][]const u8{ "system.health", "policy.set", "source.connect", "fixture.enroll", readiness.method, "fixture.snapshotStored", "fixture.providerSubmissions", "fixture.applicationReadinessPoisoned" };
    const values = [_]RpcMethod{ .health, .policy_set, .source_connect, .enrollment, .readiness, .stored, .provider_submissions, .poisoned };
    for (names, values) |name, value| if (std.mem.eql(u8, name, method)) return value;
    return .other;
}
fn rpc(actor: *engine.Engine, channel: engine.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(payload);
    const bytes = try actor.dispatch(allocator, payload, channel);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}), .method = rpcMethod(method) };
}
fn query(actor: *engine.Engine, demand: Demand, expected: u64) !Reply {
    return rpc(actor, .control, readiness.method, .{ .application = "codex", .expected_revision = expected, .demand = demand });
}
fn revision(actor: *engine.Engine) !u64 {
    var reply = try rpc(actor, .control, "system.health", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "revision") orelse return error.MissingRevision;
    if (value != .integer or value.integer < 0) return error.InvalidRevision;
    return @intCast(value.integer);
}
fn disablePolling(actor: *engine.Engine) !void {
    // No source-path acquisition or observation work exists in this fixture.
    const operation = try hex();
    var reply = try rpc(actor, .control, "policy.set", .{ .operation_id = operation[0..], .expected_revision = try revision(actor), .warm_alternatives = false });
    defer reply.deinit();
    _ = try reply.result();
}
fn hex() ![64]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    return std.fmt.bytesToHex(random, .lower);
}
const Enrollment = struct {
    source: []u8,
    account: []u8,
    grant: []u8,
    subject: [64]u8,
    token: [64]u8,
    fn create(actor: *engine.Engine) !Enrollment {
        const operation = try hex();
        var connected = try rpc(actor, .control, "source.connect", .{ .operation_id = operation[0..], .expected_revision = try revision(actor), .kind = "explicit", .provider = "codex", .label = "generated readiness fixture" });
        defer connected.deinit();
        const source = try allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
        errdefer allocator.free(source);
        const subject = try hex();
        const token = try hex();
        const capability = try actor.capabilityForTest("enrollment");
        var enrolled = try rpc(actor, .adapter, "fixture.enroll", .{ .application = "enrollment", .capability = &capability, .source_id = source, .provider = "codex", .subject = &subject, .access_token = &token, .audience = "https://chatgpt.com" });
        defer enrolled.deinit();
        const value = try enrolled.result();
        const account = try allocator.dupe(u8, try control.string(value, "account_id"));
        errdefer allocator.free(account);
        return .{ .source = source, .account = account, .grant = try allocator.dupe(u8, try control.string(value, "grant_id")), .subject = subject, .token = token };
    }
    fn deinit(self: *Enrollment) void {
        allocator.free(self.source);
        allocator.free(self.account);
        allocator.free(self.grant);
        std.crypto.secureZero(u8, &self.subject);
        std.crypto.secureZero(u8, &self.token);
    }
};
const Stored = struct {
    bytes: []u8,
    seal: [32]u8,
    methods: [6]usize,
    fn capture(actor: *native_fixture.ActorFixture, enrollment: ?*const Enrollment) !Stored {
        const capability = try actor.engine.?.capabilityForTest("enrollment");
        var grants: [1]struct { account_id: []const u8, grant_id: []const u8 } = undefined;
        if (enrollment) |value| grants[0] = .{ .account_id = value.account, .grant_id = value.grant };
        var reply = try rpc(actor.engine.?, .adapter, "fixture.snapshotStored", .{ .application = "enrollment", .capability = &capability, .grants = grants[0..@as(usize, if (enrollment != null) 1 else 0)] });
        defer reply.deinit();
        _ = try reply.result();
        const bytes = try allocator.dupe(u8, reply.bytes);
        errdefer allocator.free(bytes);
        const path = try std.fmt.allocPrint(allocator, "{s}/state.sqlite.authority", .{actor.state});
        defer allocator.free(path);
        const seal = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024));
        defer {
            std.crypto.secureZero(u8, seal);
            allocator.free(seal);
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(seal, &digest, .{});
        return .{ .bytes = bytes, .seal = digest, .methods = .{ actor.producer.methodCount(.identify), actor.producer.methodCount(.register), actor.producer.methodCount(.unregister), actor.producer.methodCount(.announce), actor.producer.methodCount(.capabilities), actor.producer.methodCount(.threads) } };
    }
    fn deinit(self: *Stored) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
    fn expectSame(self: *const Stored, actor: *native_fixture.ActorFixture, enrollment: ?*const Enrollment) !void {
        var actual = try capture(actor, enrollment);
        defer actual.deinit();
        // Boolean comparisons keep private metadata/custody out of diagnostics.
        try expectPredicate(.stored_snapshot_same, std.mem.eql(u8, self.bytes, actual.bytes));
        try expectPredicate(.stored_seal_same, std.mem.eql(u8, &self.seal, &actual.seal));
        try std.testing.expectEqualDeep(self.methods, actual.methods);
    }
};
fn expectNoProviderWork(actor: *engine.Engine) !void {
    const capability = try actor.capabilityForTest("enrollment");
    var reply = try rpc(actor, .adapter, "fixture.providerSubmissions", .{ .application = "enrollment", .capability = &capability });
    defer reply.deinit();
    const value = try reply.result();
    inline for (.{ "identity_submissions", "observation_submissions" }) |name| try std.testing.expectEqual(@as(i64, 0), control.get(value, name).?.integer);
}
fn expectPhase(value: std.json.Value, phase: []const u8, state: []const u8) !void {
    try std.testing.expectEqualStrings(state, try control.string(control.get(value, phase) orelse return error.MissingPhase, "state"));
}
fn context(value: std.json.Value) ![64]u8 {
    const reference = try control.string(value, "context_ref");
    try std.testing.expect(readiness.validContextRef(reference));
    var result: [64]u8 = undefined;
    @memcpy(&result, reference);
    return result;
}
const Predicate = enum { stored_snapshot_same, stored_seal_same, no_native_readiness_claim, response_bounded, private_values_redacted, private_fields_redacted, metadata_read_observed, no_ciphertext_read };
fn expectPredicate(predicate: Predicate, satisfied: bool) !void {
    if (!satisfied) std.debug.print("application-readiness actor predicate: {s}\n", .{@tagName(predicate)});
    try std.testing.expect(satisfied);
}
fn privateFieldPresent(value: std.json.Value) bool {
    switch (value) {
        .object => |object| {
            var fields = object.iterator();
            while (fields.next()) |field| {
                inline for (.{ "account_id", "grant_id", "source_id", "native_ref", "access_token", "capability", "config_path" }) |private_field| if (std.mem.eql(u8, field.key_ptr.*, private_field)) return true;
                if (privateFieldPresent(field.value_ptr.*)) return true;
            }
        },
        .array => |array| {
            for (array.items) |item| if (privateFieldPresent(item)) return true;
        },
        else => {},
    }
    return false;
}

test "application readiness actor control boundary and bounded exact params leave custody unchanged" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    try disablePolling(actor.engine.?);
    var saved = try Stored.capture(actor, null);
    defer saved.deinit();
    var wrong_channel = try rpc(actor.engine.?, .adapter, readiness.method, .{ .application = "codex" });
    defer wrong_channel.deinit();
    try wrong_channel.expectError("WrongChannel");
    var extra = try rpc(actor.engine.?, .control, readiness.method, .{ .application = "codex", .native_ref = "not-authority" });
    defer extra.deinit();
    try extra.expectError("InvalidParams");
    var unknown = try rpc(actor.engine.?, .control, readiness.method, .{ .application = "future" });
    defer unknown.deinit();
    try unknown.expectError("UnknownAdapter");
    var null_params = try rpc(actor.engine.?, .control, readiness.method, @as(?u8, null));
    defer null_params.deinit();
    try null_params.expectError("InvalidParams");
    var extra_demand = try rpc(actor.engine.?, .control, readiness.method, .{ .application = "codex", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = .{ .kind = "model" }, .now = 1 } });
    defer extra_demand.deinit();
    try extra_demand.expectError("InvalidParams");
    const rev = try revision(actor.engine.?);
    var invalid = Demand{};
    invalid.purpose = "account_read";
    var purpose = try query(actor.engine.?, invalid, rev);
    defer purpose.deinit();
    try purpose.expectError("InvalidParams");
    invalid = .{ .required = -1 };
    var negative = try query(actor.engine.?, invalid, rev);
    defer negative.deinit();
    try negative.expectError("InvalidParams");
    invalid = .{ .required = 1e15 + 1 };
    var excessive = try query(actor.engine.?, invalid, rev);
    defer excessive.deinit();
    try excessive.expectError("InvalidParams");
    const long: [257]u8 = @splat('x');
    invalid = .{ .resource = .{ .target = &long } };
    var oversized = try query(actor.engine.?, invalid, rev);
    defer oversized.deinit();
    try oversized.expectError("InvalidParams");
    invalid = .{ .scopes = &.{ "repeated", "repeated" } };
    var duplicate = try query(actor.engine.?, invalid, rev);
    defer duplicate.deinit();
    try duplicate.expectError("InvalidParams");
    const scopes: [65][]const u8 = @splat("scope");
    invalid = .{ .scopes = &scopes };
    var too_many = try query(actor.engine.?, invalid, rev);
    defer too_many.deinit();
    try too_many.expectError("InvalidParams");
    var escaped_scopes: [64][256]u8 = undefined;
    var escaped: [64][]const u8 = undefined;
    for (&escaped_scopes, 0..) |*scope, index| {
        @memset(scope, '\\');
        scope[0] = @intCast('!' + index);
        escaped[index] = scope;
    }
    var oversized_encoding = try query(actor.engine.?, .{ .scopes = &escaped }, rev);
    defer oversized_encoding.deinit();
    try oversized_encoding.expectError("InvalidParams");
    const boundary_target: [256]u8 = @splat('x');
    var boundary = try query(actor.engine.?, .{ .resource = .{ .target = &boundary_target } }, rev);
    defer boundary.deinit();
    _ = try boundary.result();
    var absent = try rpc(actor.engine.?, .control, readiness.method, .{ .application = "codex" });
    defer absent.deinit();
    const value = try absent.result();
    try std.testing.expectEqualStrings("context_required", try control.string(value, "reason"));
    try std.testing.expect(control.get(value, "context_ref").? == .null);
    try std.testing.expect(!(try control.boolean(value, "ready", true)));
    try saved.expectSame(actor, null);
    try expectNoProviderWork(actor.engine.?);
}

test "application readiness joins actual retained custody without materializing or promoting ordinary native launch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    try disablePolling(actor.engine.?);
    try actor.install();
    var enrolled = try Enrollment.create(actor.engine.?);
    defer enrolled.deinit();
    var saved = try Stored.capture(actor, &enrolled);
    defer saved.deinit();
    var witness: SqlWitness = .{};
    try witness.install(actor.engine.?);
    defer if (actor.engine) |current| witness.remove(current);
    var reply = try query(actor.engine.?, .{}, try revision(actor.engine.?));
    defer reply.deinit();
    const value = try reply.result();
    try expectPhase(value, "source", "ready");
    try expectPhase(value, "identity", "ready");
    try expectPhase(value, "authority", "ready");
    try expectPhase(value, "ordinary_launch", "unknown");
    try std.testing.expectEqualStrings("external", try control.string(value, "renewal_owner"));
    inline for (.{ "ready", "provider_access", "enrollment_success_proven", "seamless_handoff_proven" }) |name| try expectPredicate(.no_native_readiness_claim, !(try control.boolean(value, name, true)));
    _ = try context(value);
    try expectPredicate(.response_bounded, reply.bytes.len <= 8192);
    for ([_][]const u8{ enrolled.source, enrolled.account, enrolled.grant, &enrolled.subject, &enrolled.token, actor.config, producer.endpoint }) |private| try expectPredicate(.private_values_redacted, std.mem.indexOf(u8, reply.bytes, private) == null);
    // Inspect exact keys recursively. The valid diagnostic action
    // verify_native_capability contains the word capability but no credential.
    try expectPredicate(.private_fields_redacted, !privateFieldPresent(value));
    try expectPredicate(.metadata_read_observed, witness.grant_reads > 0);
    try expectPredicate(.no_ciphertext_read, witness.ciphertext_reads == 0);
    witness.remove(actor.engine.?);
    try saved.expectSame(actor, &enrolled);
    try expectNoProviderWork(actor.engine.?);
    // Reopen actual sealed SQLite, then bracket the diagnostic independently
    // of the legitimate startup checkpoint. No registration is performed.
    try actor.restart();
    var restored = try Stored.capture(actor, &enrolled);
    defer restored.deinit();
    try witness.install(actor.engine.?);
    var after_restart = try query(actor.engine.?, .{}, try revision(actor.engine.?));
    defer after_restart.deinit();
    try expectPhase(try after_restart.result(), "authority", "ready");
    try expectPhase(try after_restart.result(), "ordinary_launch", "unknown");
    try std.testing.expect(!(try control.boolean(try after_restart.result(), "ready", true)));
    try std.testing.expectEqual(@as(usize, 0), witness.ciphertext_reads);
    witness.remove(actor.engine.?);
    try restored.expectSame(actor, &enrolled);
    try expectNoProviderWork(actor.engine.?);
}

test "application readiness opaque context canonicalizes scopes and binds application demand revision and installation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    try disablePolling(actor.engine.?);
    const rev = try revision(actor.engine.?);
    var first = try query(actor.engine.?, .{ .scopes = &.{ "b", "a" } }, rev);
    defer first.deinit();
    var reordered = try query(actor.engine.?, .{ .scopes = &.{ "a", "b" } }, rev);
    defer reordered.deinit();
    const first_ref = try context(try first.result());
    try std.testing.expect(std.mem.eql(u8, &first_ref, &(try context(try reordered.result()))));
    var changed = try query(actor.engine.?, .{ .scopes = &.{ "a", "c" } }, rev);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first_ref, &(try context(try changed.result()))));
    var git = try rpc(actor.engine.?, .control, readiness.method, .{ .application = "git", .expected_revision = rev, .demand = .{ .provider = "github", .audience = "https://github.com", .resource = .{ .kind = "repository" } } });
    defer git.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first_ref, &(try context(try git.result()))));
    try std.testing.expectEqual(rev, try revision(actor.engine.?));
    const operation = try hex();
    var mutation = try rpc(actor.engine.?, .control, "source.connect", .{ .operation_id = operation[0..], .expected_revision = rev, .kind = "explicit", .provider = "codex", .label = "generated revision boundary" });
    defer mutation.deinit();
    _ = try mutation.result();
    const new_revision = try revision(actor.engine.?);
    try std.testing.expect(new_revision > rev);
    var later = try query(actor.engine.?, .{ .scopes = &.{ "a", "b" } }, new_revision);
    defer later.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first_ref, &(try context(try later.result()))));
    const other_producer = try native_fixture.Fixture.create(io, allocator);
    defer other_producer.destroy();
    const other = try native_fixture.ActorFixture.create(io, allocator, other_producer);
    defer other.destroy();
    try disablePolling(other.engine.?);
    try std.testing.expectEqual(rev, try revision(other.engine.?));
    var other_reply = try query(other.engine.?, .{ .scopes = &.{ "a", "b" } }, rev);
    defer other_reply.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first_ref, &(try context(try other_reply.result()))));
    try expectNoProviderWork(actor.engine.?);
    try expectNoProviderWork(other.engine.?);
}

const SqlWitness = struct {
    grant_reads: usize = 0,
    ciphertext_reads: usize = 0,
    sql_reads: usize = 0,
    deny_all_reads: bool = false,
    active: bool = false,
    fn authorize(raw: ?*anyopaque, action: c_int, table: [*c]const u8, column: [*c]const u8, _: [*c]const u8, _: [*c]const u8) callconv(.c) c_int {
        const self: *SqlWitness = @ptrCast(@alignCast(raw.?));
        if (action != c.SQLITE_READ) return c.SQLITE_OK;
        self.sql_reads += 1;
        if (table != null and std.mem.eql(u8, std.mem.span(table), "grants")) {
            self.grant_reads += 1;
            if (column != null and std.mem.eql(u8, std.mem.span(column), "ciphertext")) {
                self.ciphertext_reads += 1;
                return c.SQLITE_DENY;
            }
        }
        return if (self.deny_all_reads) c.SQLITE_DENY else c.SQLITE_OK;
    }
    fn install(self: *SqlWitness, actor: *engine.Engine) !void {
        // Synchronous fixture dispatch has drained all owned work. Polling is
        // disabled and grants do not expire during this bounded query bracket.
        if (c.sqlite3_set_authorizer(actor.db.?.db, authorize, self) != c.SQLITE_OK) return error.AuthorizerFixtureFailed;
        self.active = true;
    }
    fn remove(self: *SqlWitness, actor: *engine.Engine) void {
        if (self.active) {
            if (c.sqlite3_set_authorizer(actor.db.?.db, null, null) != c.SQLITE_OK) @panic("authorizer fixture cleanup failed");
            self.active = false;
        }
    }
};

test "application readiness stale and poisoned actor diagnostics skip denied custody SQL" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    try disablePolling(actor.engine.?);
    var enrolled = try Enrollment.create(actor.engine.?);
    defer enrolled.deinit();
    const rev = try revision(actor.engine.?);
    try std.testing.expect(rev > 0);
    var saved = try Stored.capture(actor, &enrolled);
    defer saved.deinit();
    var witness: SqlWitness = .{ .deny_all_reads = true };
    try witness.install(actor.engine.?);
    defer witness.remove(actor.engine.?);
    var stale = try query(actor.engine.?, .{}, rev - 1);
    defer stale.deinit();
    const stale_value = try stale.result();
    try std.testing.expectEqualStrings("revision_changed", try control.string(stale_value, "reason"));
    try expectPhase(stale_value, "authority", "unknown");
    try std.testing.expectEqual(@as(usize, 0), witness.sql_reads);
    // The test-only actor hook owns the temporary fault and routes the same
    // parameters through the real poisoned execute/readiness path. A caller
    // thread never writes flags concurrently with actor maintenance.
    var poisoned = try rpc(actor.engine.?, .control, "fixture.applicationReadinessPoisoned", .{ .application = "codex", .expected_revision = rev, .demand = Demand{} });
    defer poisoned.deinit();
    const unavailable = try poisoned.result();
    try std.testing.expectEqualStrings("custody_unavailable", try control.string(unavailable, "reason"));
    try expectPhase(unavailable, "authority", "unknown");
    try std.testing.expect(!(try control.boolean(unavailable, "ready", true)));
    try std.testing.expectEqual(@as(usize, 0), witness.sql_reads);
    witness.remove(actor.engine.?);
    try saved.expectSame(actor, &enrolled);
    try expectNoProviderWork(actor.engine.?);
}
