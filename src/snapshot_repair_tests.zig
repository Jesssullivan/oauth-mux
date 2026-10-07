//! R-N13: real multi-source repair result admission before identity submission.
//! Private source files and custody credentials are generated locally. The actor's
//! test-only provider tripwire forbids HTTP even if result admission regresses.
const std = @import("std");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const mutation_authority = @import("mutation_authority.zig");
const owner_fixture = @import("native_owner_fixture.zig");
// Source/enrollment authority remains distinct from native request authority.
// The scoped fixture supplies actual packet provenance without registering a
// Codex owner or admitting an application request.
var active_transport: ?*owner_fixture.Fixture = null;

const allocator = std.testing.allocator;
const io = std.testing.io;
const source_count = 16;

const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }

    fn result(self: *const Reply) !std.json.Value {
        return control.get(self.parsed.value, "result") orelse error.ExpectedRpcSuccess;
    }

    fn expectError(self: *const Reply, expected: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.ExpectedRpcFailure;
        try std.testing.expectEqualStrings(expected, try control.string(failure, "message"));
    }
};

fn rpc(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const initial = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = 1,
        .method = method,
        .params = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params,
    }, .{});
    defer {
        std.crypto.secureZero(u8, initial);
        allocator.free(initial);
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, initial, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(parsed.value);
        parsed.deinit();
    }
    var operation_id: ?[]u8 = null;
    defer if (operation_id) |value| allocator.free(value);
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const params_value = parsed.value.object.getPtr("params").?;
        if (!params_value.object.contains("operation_id")) {
            operation_id = try generatedValue();
            // The parsed request's scrubbing owns its strings. Keep this copy in
            // that arena so freeing the generated input cannot leave a dangling
            // value for the later recursive wipe.
            const owned_operation = try parsed.arena.allocator().dupe(u8, operation_id.?);
            const operation_key = try parsed.arena.allocator().dupe(u8, "operation_id");
            try params_value.object.put(parsed.arena.allocator(), operation_key, .{ .string = owned_operation });
        }
        if (!params_value.object.contains("expected_revision")) {
            var health = try rpc(engine, .control, "system.health", .{});
            defer health.deinit();
            const revision_key = try parsed.arena.allocator().dupe(u8, "expected_revision");
            try params_value.object.put(parsed.arena.allocator(), revision_key, control.get(try health.result(), "revision").?);
        }
    }
    const payload = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    }
    const bytes = if (channel == .adapter) try (active_transport orelse return error.FixtureTransportMissing).dispatch(engine, allocator, payload, channel) else try engine.dispatch(allocator, payload, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}

fn generatedValue() ![]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    const hexadecimal = std.fmt.bytesToHex(random, .lower);
    return allocator.dupe(u8, &hexadecimal);
}

fn privateFile(directory: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try directory.createFile(io, name, .{ .exclusive = true });
    defer file.close(io);
    if (std.c.fchmod(file.handle, 0o600) != 0) return error.FixturePermissionFailed;
    try file.writeStreamingAll(io, bytes);
}

fn enrollmentQuery(engine: *engine_module.Engine, method: []const u8) !Reply {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    return rpc(engine, .adapter, method, .{ .application = "enrollment", .capability = capability[0..] });
}

const HeldGrant = struct { account_id: []const u8, grant_id: []const u8 };

fn storedQuery(engine: *engine_module.Engine, grants: []const HeldGrant) !Reply {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    return rpc(engine, .adapter, "fixture.snapshotStored", .{
        .application = "enrollment",
        .capability = capability[0..],
        .grants = grants,
    });
}

fn expectSameField(first: std.json.Value, second: std.json.Value, field: []const u8) !void {
    const a = try std.json.Stringify.valueAlloc(allocator, control.get(first, field).?, .{});
    defer allocator.free(a);
    const b = try std.json.Stringify.valueAlloc(allocator, control.get(second, field).?, .{});
    defer allocator.free(b);
    try std.testing.expect(std.mem.eql(u8, a, b));
}

test "actual sixteen-source repair result overflow refuses before identity submission and retains custody" {
    const producer = try owner_fixture.Fixture.create(io, allocator);
    active_transport = producer;
    defer {
        active_transport = null;
        producer.destroy();
    }
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixturePermissionFailed;
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: [32]u8 = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
    defer {
        producer.pause();
        engine.deinit();
    }
    const subject = try generatedValue();
    defer {
        std.crypto.secureZero(u8, subject);
        allocator.free(subject);
    }
    var sources: std.ArrayList([]u8) = .empty;
    defer {
        for (sources.items) |source| allocator.free(source);
        sources.deinit(allocator);
    }
    var jobs: std.ArrayList([]u8) = .empty;
    defer {
        for (jobs.items) |job| allocator.free(job);
        jobs.deinit(allocator);
    }
    var account_id: ?[]u8 = null;
    defer if (account_id) |value| allocator.free(value);
    for (0..source_count) |index| {
        const name = try std.fmt.allocPrint(allocator, "generated-native-credential-{d}.json", .{index});
        defer allocator.free(name);
        const native_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, name });
        defer allocator.free(native_path);
        const native_token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, native_token);
            allocator.free(native_token);
        }
        const grant_token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, grant_token);
            allocator.free(grant_token);
        }
        try std.testing.expect(!std.mem.eql(u8, native_token, grant_token));
        const document = try std.json.Stringify.valueAlloc(allocator, .{ .tokens = .{ .access_token = native_token } }, .{});
        defer {
            std.crypto.secureZero(u8, document);
            allocator.free(document);
        }
        try privateFile(directory.dir, name, document);
        var connected = try rpc(engine, .control, "source.connect", .{
            .kind = "native_store",
            .provider = "codex",
            .source_path = native_path,
            .label = "generated authorized native source",
        });
        defer connected.deinit();
        const source = try allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
        sources.append(allocator, source) catch |err| {
            allocator.free(source);
            return err;
        };
        try std.testing.expect(source.len == 64);
        const job = try std.fmt.allocPrint(allocator, "reconcile-{s}", .{source});
        jobs.append(allocator, job) catch |err| {
            allocator.free(job);
            return err;
        };
        var capability = try engine.capabilityForTest("enrollment");
        defer std.crypto.secureZero(u8, &capability);
        var enrolled = try rpc(engine, .adapter, "fixture.enroll", .{
            .application = "enrollment",
            .capability = capability[0..],
            .source_id = source,
            .provider = "codex",
            .subject = subject,
            .audience = "https://chatgpt.com",
            .access_token = grant_token,
            .label = "generated verified account",
        });
        defer enrolled.deinit();
        const enrolled_id = try control.string(try enrolled.result(), "account_id");
        if (account_id) |expected| try std.testing.expect(std.mem.eql(u8, expected, enrolled_id)) else account_id = try allocator.dupe(u8, enrolled_id);
    }
    const predicted = try std.json.Stringify.valueAlloc(allocator, .{
        .operation_id = jobs.items[0],
        .operation_ids = jobs.items,
        .status = "verifying_identity",
        .reconciled_sources = source_count,
    }, .{});
    defer allocator.free(predicted);
    try std.testing.expect(predicted.len > mutation_authority.max_result_bytes);
    var submissions_before = try enrollmentQuery(engine, "fixture.providerSubmissions");
    defer submissions_before.deinit();
    try std.testing.expectEqual(@as(i64, 0), control.get(try submissions_before.result(), "identity_submissions").?.integer);
    var before = try rpc(engine, .control, "state.snapshot", .{});
    defer before.deinit();
    const state_before = try before.result();
    const accounts = control.get(state_before, "accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqual(@as(usize, source_count), control.get(accounts[0], "source_ids").?.array.items.len);
    const grants = control.get(state_before, "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, source_count), grants.len);
    var held_grants: [source_count]HeldGrant = undefined;
    for (grants, &held_grants) |grant, *held| held.* = .{
        .account_id = try control.string(grant, "account_id"),
        .grant_id = try control.string(grant, "id"),
    };
    var budget_before = try enrollmentQuery(engine, "fixture.snapshotBudget");
    defer budget_before.deinit();
    var stored_before = try storedQuery(engine, &held_grants);
    defer stored_before.deinit();
    for (control.get(try stored_before.result(), "ciphertext_sha256").?.array.items) |digest|
        try std.testing.expect(digest == .string);
    var rejected = try rpc(engine, .control, "repair.start", .{ .operation_id = "native-repair-result-overflow", .account_id = account_id.? });
    defer rejected.deinit();
    try rejected.expectError("ResultTooLarge");
    var submissions_after = try enrollmentQuery(engine, "fixture.providerSubmissions");
    defer submissions_after.deinit();
    try expectSameField(try submissions_before.result(), try submissions_after.result(), "identity_submissions");
    var after = try rpc(engine, .control, "state.snapshot", .{});
    defer after.deinit();
    for ([_][]const u8{ "revision", "custody_available", "accounts", "sources", "source_descriptions", "grants", "jobs", "bindings", "leases", "observations" }) |field|
        try expectSameField(state_before, try after.result(), field);
    var budget_after = try enrollmentQuery(engine, "fixture.snapshotBudget");
    defer budget_after.deinit();
    for ([_][]const u8{ "exact_snapshot_bytes", "reserved_bytes", "credits_bytes", "credit_count", "remaining_bytes" }) |field|
        try expectSameField(try budget_before.result(), try budget_after.result(), field);
    var stored_after = try storedQuery(engine, &held_grants);
    defer stored_after.deinit();
    for ([_][]const u8{ "revision", "snapshot_bytes", "snapshot_sha256", "ciphertext_sha256", "tombstone_count", "tombstone_sha256" }) |field|
        try expectSameField(try stored_before.result(), try stored_after.result(), field);
    var status = try rpc(engine, .control, "operation.status", .{ .operation_id = "native-repair-result-overflow" });
    defer status.deinit();
    try status.expectError("UnknownOperation");
    // Positive control follows every preservation assertion. Valid discovery
    // reaches the actual submission tripwire; the test actor still forbids HTTP.
    var single = try rpc(engine, .control, "source.reconcile", .{ .source_id = sources.items[0] });
    defer single.deinit();
    try single.expectError("TestProviderEffectDisabled");
    var attempted = try enrollmentQuery(engine, "fixture.providerSubmissions");
    defer attempted.deinit();
    try std.testing.expectEqual(@as(i64, 1), control.get(try attempted.result(), "identity_submissions").?.integer);
}
