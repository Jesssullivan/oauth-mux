//! Whole-snapshot import admission through the actual single-writer actor.
//! R-N13: scoped test work in the October 4 five-hour snapshot sprint.
//! Identity responses and credentials are generated locally. No provider,
//! personal vault, installed service or live-continuity proof is involved.
const std = @import("std");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const storage = @import("storage.zig");
const snapshot_admission = @import("snapshot_admission.zig");
const transport = @import("transport.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;

fn enrollmentCounts(engine: *engine_module.Engine) ![2]u64 {
    var reply = try rpc(engine, .control, "reliability.lifecycle", .{});
    defer reply.deinit();
    const measurements = control.get(try reply.result(), "measurements") orelse return error.MissingMeasurements;
    if (measurements == .null) return .{ 0, 0 };
    var counts: [2]u64 = .{ 0, 0 };
    for (control.get(measurements, "days").?.array.items) |day| {
        const outcomes = control.get(day, "cells").?.array.items[1].array.items;
        counts[0] += @intCast(control.get(outcomes[0], "count").?.integer);
        counts[1] += @intCast(control.get(outcomes[2], "count").?.integer);
    }
    return counts;
}

test "native import terminal measurements survive restart without counting start or retry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const response = try identityResponse();
    defer allocator.free(response);
    var held = try holdImport(fixture.engine.?, source, token, false);
    defer held.deinit();
    var coalesced = try holdImport(fixture.engine.?, source, token, false);
    defer coalesced.deinit();
    try std.testing.expectEqual(held.generation, coalesced.generation);
    try std.testing.expectEqual([2]u64{ 0, 0 }, try enrollmentCounts(fixture.engine.?));
    try completeImport(fixture.engine.?, source, held, response, null);
    try expectOldImportAbsent(fixture.engine.?, source, held, response);
    try std.testing.expectEqual([2]u64{ 1, 0 }, try enrollmentCounts(fixture.engine.?));
    try fixture.restart();
    try std.testing.expectEqual([2]u64{ 1, 0 }, try enrollmentCounts(fixture.engine.?));
    var failing = try holdImport(fixture.engine.?, source, token, false);
    defer failing.deinit();
    const capability = try fixture.engine.?.capabilityForTest("enrollment");
    var failed = try rpc(fixture.engine.?, .adapter, "fixture.importComplete", .{ .application = "enrollment", .capability = capability[0..], .source_id = source, .generation = failing.generation, .response = "{}" });
    defer failed.deinit();
    try std.testing.expect(!try control.boolean(try failed.result(), "admitted", true));
    try expectOldImportAbsent(fixture.engine.?, source, failing, "{}");
    try std.testing.expectEqual([2]u64{ 1, 1 }, try enrollmentCounts(fixture.engine.?));
    try fixture.restart();
    try std.testing.expectEqual([2]u64{ 1, 1 }, try enrollmentCounts(fixture.engine.?));
}

test "CLI enrollment selection observes only the committed original generation across restart" {
    const wait = @import("enrollment_wait.zig");
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const capability = try fixture.engine.?.capabilityForTest("enrollment");
    var admitted = try rpc(fixture.engine.?, .adapter, "fixture.importStart", .{
        .application = "enrollment",
        .capability = capability[0..],
        .source_id = source,
        .provider = "github",
        .access_token = token,
        .include_operation_generation = true,
    });
    defer admitted.deinit();
    const selected = try wait.selection(admitted.parsed.value);
    var held: HeldImport = .{ .operation_id = try allocator.dupe(u8, selected.operation_id), .generation = @intCast(selected.operation_generation) };
    defer held.deinit();
    {
        var pending = try rpc(fixture.engine.?, .control, "state.snapshot", .{});
        defer pending.deinit();
        try std.testing.expectEqual(wait.State.pending, try wait.observe(selected, pending.parsed.value));
    }
    const response = try identityResponse();
    defer allocator.free(response);
    try completeImport(fixture.engine.?, source, held, response, null);
    {
        var committed = try rpc(fixture.engine.?, .control, "state.snapshot", .{});
        defer committed.deinit();
        try std.testing.expectEqual(wait.State.completed, try wait.observe(selected, committed.parsed.value));
        const accounts = control.get(try committed.result(), "accounts").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), accounts.len);
        try std.testing.expect(try control.boolean(control.get(accounts[0], "identity").?, "verified", false));
        try std.testing.expectEqual([2]u64{ 1, 0 }, try enrollmentCounts(fixture.engine.?));
    }
    try fixture.restart();
    {
        var restored = try rpc(fixture.engine.?, .control, "state.snapshot", .{});
        defer restored.deinit();
        try std.testing.expectEqual(wait.State.completed, try wait.observe(selected, restored.parsed.value));
        try std.testing.expectEqual([2]u64{ 1, 0 }, try enrollmentCounts(fixture.engine.?));
    }
    var replacement = try holdImport(fixture.engine.?, source, token, false);
    defer replacement.deinit();
    {
        var superseded = try rpc(fixture.engine.?, .control, "state.snapshot", .{});
        defer superseded.deinit();
        try std.testing.expectError(error.EnrollmentSuperseded, wait.observe(selected, superseded.parsed.value));
    }
}

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
        return control.get(self.parsed.value, "result") orelse error.UnexpectedRpcFailure;
    }

    fn expectError(self: *const Reply, expected: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.MissingRpcError;
        try std.testing.expectEqualStrings(expected, try control.string(failure, "message"));
    }
};

fn generatedValue() ![]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    return std.fmt.allocPrint(allocator, "synthetic-{s}", .{std.fmt.bytesToHex(random, .lower)});
}

fn rpc(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) !Reply {
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const initial = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = normalized }, .{});
    defer {
        std.crypto.secureZero(u8, initial);
        allocator.free(initial);
    }
    var enriched = try std.json.parseFromSlice(std.json.Value, allocator, initial, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(enriched.value);
        enriched.deinit();
    }
    var operation_id: ?[]u8 = null;
    defer if (operation_id) |value| allocator.free(value);
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const target = enriched.value.object.getPtr("params").?;
        if (target.* == .null) target.* = .{ .object = .empty };
        if (!target.object.contains("operation_id")) {
            operation_id = try generatedValue();
            const arena = enriched.arena.allocator();
            const owned_key = try arena.dupe(u8, "operation_id");
            const owned_value = try arena.dupe(u8, operation_id.?[0..64]);
            try target.object.put(arena, owned_key, .{ .string = owned_value });
        }
        if (!target.object.contains("expected_revision")) {
            var health = try rpc(engine, .control, "system.health", .{});
            defer health.deinit();
            const current_revision = control.get(try health.result(), "revision") orelse return error.InvalidReply;
            const arena = enriched.arena.allocator();
            const owned_key = try arena.dupe(u8, "expected_revision");
            try target.object.put(arena, owned_key, current_revision);
        }
    }
    const request = try std.json.Stringify.valueAlloc(allocator, enriched.value, .{});
    defer {
        std.crypto.secureZero(u8, request);
        allocator.free(request);
    }
    const bytes = try engine.dispatch(allocator, request, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}

fn success(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) !void {
    var reply = try rpc(engine, channel, method, params);
    defer reply.deinit();
    _ = try reply.result();
}

const Fixture = struct {
    directory: std.testing.TmpDir,
    path: [:0]u8,
    engine: ?*engine_module.Engine,
    key: [32]u8 = @splat(67),

    fn init() !Fixture {
        var directory = std.testing.tmpDir(.{});
        errdefer directory.cleanup();
        if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.PermissionChangeFailed;
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        errdefer allocator.free(path);
        return .{ .directory = directory, .path = path, .engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(67)) };
    }

    fn close(self: *Fixture) void {
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
    }

    fn restart(self: *Fixture) !void {
        self.close();
        self.engine = try engine_module.Engine.openWithKey(io, allocator, self.path, self.key);
    }

    fn deinit(self: *Fixture) void {
        self.close();
        allocator.free(self.path);
        self.directory.cleanup();
        std.crypto.secureZero(u8, &self.key);
    }

    fn connect(self: *Fixture) ![]u8 {
        return self.connectProvider("github");
    }

    fn connectProvider(self: *Fixture, provider: []const u8) ![]u8 {
        var reply = try rpc(self.engine.?, .control, "source.connect", .{ .kind = "explicit", .provider = provider, .label = "snapshot fixture" });
        defer reply.deinit();
        return allocator.dupe(u8, try control.string(try reply.result(), "source_id"));
    }
};

const HeldImport = struct {
    operation_id: []u8,
    generation: i64,

    fn deinit(self: *HeldImport) void {
        allocator.free(self.operation_id);
    }
};

fn holdImport(engine: *engine_module.Engine, source_id: []const u8, token: []const u8, reenroll: bool) !HeldImport {
    return holdImportLabel(engine, source_id, token, reenroll, "");
}

fn holdImportLabel(engine: *engine_module.Engine, source_id: []const u8, token: []const u8, reenroll: bool, label: []const u8) !HeldImport {
    return holdProviderImport(engine, source_id, "github", token, reenroll, label);
}

fn holdProviderImport(engine: *engine_module.Engine, source_id: []const u8, provider: []const u8, token: []const u8, reenroll: bool, label: []const u8) !HeldImport {
    const capability = try engine.capabilityForTest("enrollment");
    const supplied_label: ?[]const u8 = if (label.len == 0) null else label;
    var reply = try rpc(engine, .adapter, "fixture.importStart", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .provider = provider, .access_token = token, .allow_reenrollment = reenroll, .label = supplied_label });
    defer reply.deinit();
    const result = try reply.result();
    return .{ .operation_id = try allocator.dupe(u8, try control.string(result, "operation_id")), .generation = control.get(result, "generation").?.integer };
}

fn completeImport(engine: *engine_module.Engine, source_id: []const u8, held: HeldImport, response: []const u8, expected_error: ?[]const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importComplete", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .generation = held.generation, .response = response });
    defer reply.deinit();
    const result = try reply.result();
    try std.testing.expectEqual(expected_error == null, try control.boolean(result, "admitted", false));
    if (expected_error) |name| try std.testing.expectEqualStrings(name, try control.string(result, "reason"));
}

fn sourceTransition(engine: *engine_module.Engine, source_id: []const u8, transition: []const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.importSource", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .transition = transition });
}

fn identityResponse() ![]u8 {
    var random: [8]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    const username = try generatedValue();
    defer allocator.free(username);
    return std.json.Stringify.valueAlloc(allocator, .{ .id = std.mem.readInt(u64, &random, .little) | 1, .login = username, .type = "User" }, .{});
}

fn assertNoPlaintext(fixture: *Fixture, token: []const u8) !void {
    for ([_][]const u8{ "state.sqlite", "state.sqlite-wal", "state.sqlite-journal" }) |filename| {
        const bytes = fixture.directory.dir.readFileAlloc(io, filename, allocator, .limited(64 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer allocator.free(bytes);
        try std.testing.expect(std.mem.indexOf(u8, bytes, token) == null);
    }
}

fn openStored(fixture: *Fixture) !storage.Store {
    try std.testing.expect(fixture.engine == null);
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{fixture.path}, 0);
    defer allocator.free(path);
    const root = try storage.Store.readRootId(allocator, path);
    defer allocator.free(root);
    return storage.Store.openRoot(io, allocator, path, root, fixture.key);
}

const Budget = struct {
    exact_snapshot_bytes: usize,
    reserved_bytes: usize,
    credits_bytes: usize,
    remaining_bytes: usize,
    credit_count: usize,
};

fn budget(engine: *engine_module.Engine) !Budget {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
    defer reply.deinit();
    const result = try reply.result();
    var value: Budget = undefined;
    inline for (@typeInfo(Budget).@"struct".field_names) |name| {
        const encoded = control.get(result, name) orelse return error.MissingBudgetField;
        if (encoded != .integer or encoded.integer < 0) return error.InvalidBudgetField;
        @field(value, name) = @intCast(encoded.integer);
    }
    try std.testing.expect(value.exact_snapshot_bytes <= value.reserved_bytes);
    try std.testing.expectEqual(snapshot_admission.maximum_snapshot_bytes, value.reserved_bytes + value.remaining_bytes);
    return value;
}

fn saturate(engine: *engine_module.Engine) !void {
    return saturateWithObservations(engine, false);
}

fn saturateWithObservations(engine: *engine_module.Engine, fill_observations: bool) !void {
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = capability[0..], .spare_bytes = 0, .fill_observations = fill_observations });
    try std.testing.expect((try budget(engine)).remaining_bytes <= 64);
}

fn revision(engine: *engine_module.Engine) !i64 {
    var reply = try rpc(engine, .control, "system.health", .{});
    defer reply.deinit();
    const result = try reply.result();
    try std.testing.expect(try control.boolean(result, "custody_available", false));
    return control.get(result, "revision").?.integer;
}

fn maximumIdentityResponse() ![]u8 {
    const username: [256]u8 = @splat('u');
    const kind: [128]u8 = @splat('U');
    return std.json.Stringify.valueAlloc(allocator, .{ .id = std.math.maxInt(u64), .login = username[0..], .type = kind[0..] }, .{});
}

fn maximumCodexUsageResponse(identity: transport.CodexIdentity) ![]u8 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    const window: transport.CodexUsage.Window = .{
        .used_percent = 25,
        .limit_window_seconds = std.math.maxInt(i32),
        .reset_after_seconds = std.math.maxInt(i32),
        .reset_at = try std.math.add(i64, now, 3600),
    };
    const limit: transport.CodexUsage.RateLimit = .{
        .allowed = true,
        .limit_reached = false,
        .primary_window = window,
        .secondary_window = window,
    };
    var features: [32][256]u8 = undefined;
    var additional: [32]transport.CodexUsage.Additional = undefined;
    for (&features, &additional, 0..) |*feature, *entry, index| {
        @memset(feature, 'f');
        const suffix = std.fmt.bytesToHex([_]u8{@intCast(index)}, .lower);
        @memcpy(feature[254..], &suffix);
        entry.* = .{ .limit_name = "generated feature", .metered_feature = feature[0..], .rate_limit = limit };
    }
    return std.json.Stringify.valueAlloc(allocator, transport.CodexUsage{
        .account_id = identity.account_id,
        .user_id = identity.user_id,
        .plan_type = identity.plan_type,
        .rate_limit = limit,
        .additional_rate_limits = &additional,
        .spend_control = .{ .reached = false },
    }, .{});
}

fn reservedCounts(engine: *engine_module.Engine) !snapshot_admission.Counts {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
    defer reply.deinit();
    const encoded = control.get(try reply.result(), "counts_reserved") orelse return error.MissingBudgetField;
    var value: snapshot_admission.Counts = undefined;
    inline for (@typeInfo(snapshot_admission.Counts).@"struct".field_names) |name| {
        const count = control.get(encoded, name) orelse return error.MissingBudgetField;
        if (count != .integer or count.integer < 0) return error.InvalidBudgetField;
        @field(value, name) = @intCast(count.integer);
    }
    return value;
}

const StoredFingerprint = struct {
    revision: i64,
    sha256: [64]u8,
};

fn storedFingerprint(engine: *engine_module.Engine) !StoredFingerprint {
    const capability = try engine.capabilityForTest("enrollment");
    const no_grants = [_]struct { account_id: []const u8, grant_id: []const u8 }{};
    var reply = try rpc(engine, .adapter, "fixture.snapshotStored", .{ .application = "enrollment", .capability = capability[0..], .grants = no_grants });
    defer reply.deinit();
    const result = try reply.result();
    const digest = try control.string(result, "snapshot_sha256");
    if (digest.len != 64) return error.InvalidReply;
    var fingerprint: StoredFingerprint = .{ .revision = control.get(result, "revision").?.integer, .sha256 = undefined };
    @memcpy(&fingerprint.sha256, digest);
    return fingerprint;
}

fn expectZeroProviderSubmissions(engine: *engine_module.Engine, method: []const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, method, .{ .application = "enrollment", .capability = capability[0..] });
    defer reply.deinit();
    const result = try reply.result();
    try std.testing.expectEqual(@as(i64, 0), control.get(result, "identity_submissions").?.integer);
    try std.testing.expectEqual(@as(i64, 0), control.get(result, "observation_submissions").?.integer);
}

test "saturated background observation rollback preserves subsequent grants and held import authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    try success(engine, .control, "policy.set", .{ .warm_alternatives = true });
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    var responses: [2][]u8 = undefined;
    responses[0] = try identityResponse();
    defer allocator.free(responses[0]);
    responses[1] = try identityResponse();
    defer allocator.free(responses[1]);
    {
        // A separate roomy actor proves that these two identity/grant fixtures
        // reach both observation submission boundaries. Test transport disables
        // provider effects there; the saturated actor below must reach neither.
        var positive = try Fixture.init();
        defer positive.deinit();
        try success(positive.engine.?, .control, "policy.set", .{ .warm_alternatives = true });
        for (responses) |identity_response| {
            const positive_source = try positive.connect();
            defer allocator.free(positive_source);
            var positive_import = try holdImport(positive.engine.?, positive_source, token, false);
            defer positive_import.deinit();
            try completeImport(positive.engine.?, positive_source, positive_import, identity_response, null);
        }
        const capability = try positive.engine.?.capabilityForTest("enrollment");
        var polled = try rpc(positive.engine.?, .adapter, "fixture.pollSources", .{ .application = "enrollment", .capability = capability[0..] });
        defer polled.deinit();
        const submitted = try polled.result();
        try std.testing.expectEqual(@as(i64, 0), control.get(submitted, "identity_submissions").?.integer);
        try std.testing.expectEqual(@as(i64, 2), control.get(submitted, "observation_submissions").?.integer);
        try std.testing.expectEqual(@as(usize, 0), (try budget(positive.engine.?)).credit_count);
        try assertNoPlaintext(&positive, token);
    }
    for (responses) |response| {
        const source = try fixture.connect();
        defer allocator.free(source);
        var held = try holdImport(engine, source, token, false);
        defer held.deinit();
        try completeImport(engine, source, held, response, null);
    }
    var initial = try rpc(engine, .control, "state.snapshot", .{});
    defer initial.deinit();
    const initial_state = try initial.result();
    try std.testing.expectEqual(@as(usize, 2), control.get(initial_state, "accounts").?.array.items.len);
    const grants = control.get(initial_state, "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), grants.len);
    try std.testing.expectEqual(@as(usize, 0), control.get(initial_state, "observations").?.array.items.len);
    try std.testing.expect(!std.mem.eql(u8, try control.string(grants[0], "account_id"), try control.string(grants[1], "account_id")));

    const source = try fixture.connect();
    defer allocator.free(source);
    const response = try identityResponse();
    defer allocator.free(response);
    var held = try holdImport(engine, source, token, false);
    defer held.deinit();
    try saturate(engine);
    const before = try budget(engine);
    const counts = try reservedCounts(engine);
    const stored = try storedFingerprint(engine);
    const before_revision = try revision(engine);
    try std.testing.expectEqual(@as(usize, 1), before.credit_count);
    try std.testing.expectEqual(@as(usize, 0), counts.observations);
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");

    // The first failed observer admission restores the entire committed state.
    // A second grant then forces the poller to resolve owned IDs in that new
    // state, rather than continue across the freed original grants array.
    for (0..2) |_| {
        try expectZeroProviderSubmissions(engine, "fixture.pollSources");
        try std.testing.expectEqual(before_revision, try revision(engine));
        try std.testing.expectEqualDeep(before, try budget(engine));
        try std.testing.expectEqualDeep(counts, try reservedCounts(engine));
        // This digest covers metadata, credits, their exact keys/intents,
        // operation generations and both replay-authority ledgers.
        try std.testing.expectEqualDeep(stored, try storedFingerprint(engine));
    }
    try assertNoPlaintext(&fixture, token);
    try completeImport(engine, source, held, response, null);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    try std.testing.expectEqualDeep(snapshot_admission.Counts{}, try reservedCounts(engine));
    try assertNoPlaintext(&fixture, token);

    fixture.close();
    var store = try openStored(&fixture);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state").?;
    const saved_grants = control.get(state, "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), saved_grants.len);
    for (grants) |grant| {
        const expected_id = try control.string(grant, "id");
        var found = false;
        for (saved_grants) |saved_grant| if (std.mem.eql(u8, expected_id, try control.string(saved_grant, "id"))) {
            found = true;
            try std.testing.expectEqualStrings(try control.string(grant, "account_id"), try control.string(saved_grant, "account_id"));
            try std.testing.expectEqual(control.get(grant, "generation").?.integer, control.get(saved_grant, "generation").?.integer);
        };
        try std.testing.expect(found);
    }
}

test "held Codex maximum usage completion preserves source-link and observation slots under saturation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const generated_id = try generatedValue();
    defer allocator.free(generated_id);
    var subject: [256]u8 = @splat('s');
    var tenant: [256]u8 = @splat('t');
    @memcpy(subject[0..generated_id.len], generated_id);
    @memcpy(tenant[0..generated_id.len], generated_id);
    const plan: [64]u8 = @splat('p');
    const identity: transport.CodexIdentity = .{ .account_id = &tenant, .user_id = &subject, .plan_type = &plan };
    const identity_only = try std.json.Stringify.valueAlloc(allocator, identity, .{});
    defer allocator.free(identity_only);
    const response = try maximumCodexUsageResponse(identity);
    defer allocator.free(response);
    const escaped_label: [4096]u8 = @splat('\\');

    // Establish the real maximum-minus-one association count through the
    // ordinary enrollment/credential commit path, without adding quota data.
    for (0..snapshot_admission.maximum_account_sources - 1) |_| {
        const prior_source = try fixture.connectProvider("codex");
        defer allocator.free(prior_source);
        var prior = try holdProviderImport(engine, prior_source, "codex", token, false, &escaped_label);
        defer prior.deinit();
        try completeImport(engine, prior_source, prior, identity_only, null);
    }
    var linked = try rpc(engine, .control, "state.snapshot", .{});
    defer linked.deinit();
    const linked_accounts = control.get(try linked.result(), "accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), linked_accounts.len);
    try std.testing.expectEqual(snapshot_admission.maximum_account_sources - 1, control.get(linked_accounts[0], "source_ids").?.array.items.len);
    const account_id = try allocator.dupe(u8, try control.string(linked_accounts[0], "id"));
    defer allocator.free(account_id);

    const source = try fixture.connectProvider("codex");
    defer allocator.free(source);
    var held = try holdProviderImport(engine, source, "codex", token, false, &escaped_label);
    defer held.deinit();
    const promised = try budget(engine);
    try std.testing.expectEqual(@as(usize, 1), promised.credit_count);
    try std.testing.expect(promised.credits_bytes > 0);
    const counts = try reservedCounts(engine);
    try std.testing.expectEqual(@as(usize, 100), counts.observations);
    try std.testing.expectEqual(@as(usize, 1), counts.source_links);
    try std.testing.expectEqual(@as(usize, 1), counts.accounts);
    try std.testing.expectEqual(@as(usize, 1), counts.grants);

    try saturateWithObservations(engine, true);
    const full = try budget(engine);
    try std.testing.expectEqual(promised.credits_bytes, full.credits_bytes);
    try std.testing.expectEqualDeep(counts, try reservedCounts(engine));
    const committed_revision = try revision(engine);
    var unrelated = try rpc(engine, .control, "source.connect", .{ .kind = "explicit", .provider = "github", .label = "unrelated fixture" });
    defer unrelated.deinit();
    try unrelated.expectError("SnapshotTooLarge");
    try std.testing.expectEqual(committed_revision, try revision(engine));
    try std.testing.expectEqual(full.reserved_bytes, (try budget(engine)).reserved_bytes);
    try std.testing.expectEqualDeep(counts, try reservedCounts(engine));

    try completeImport(engine, source, held, response, null);
    const completed = try budget(engine);
    try std.testing.expectEqual(@as(usize, 0), completed.credit_count);
    try std.testing.expectEqual(@as(usize, 0), completed.credits_bytes);
    try std.testing.expectEqualDeep(snapshot_admission.Counts{}, try reservedCounts(engine));
    try std.testing.expect(completed.exact_snapshot_bytes > full.exact_snapshot_bytes);
    try assertNoPlaintext(&fixture, token);

    fixture.close();
    var store = try openStored(&fixture);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    try std.testing.expectEqual(completed.exact_snapshot_bytes, saved.json.len);
    try std.testing.expect(std.mem.indexOf(u8, saved.json, token) == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state").?;
    const accounts = control.get(state, "accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqualStrings(account_id, try control.string(accounts[0], "id"));
    const saved_identity = control.get(accounts[0], "identity").?;
    try std.testing.expectEqualStrings(&subject, try control.string(saved_identity, "subject"));
    try std.testing.expectEqualStrings(&tenant, try control.string(saved_identity, "tenant"));
    try std.testing.expectEqualStrings(&plan, try control.string(accounts[0], "account_type"));
    const source_ids = control.get(accounts[0], "source_ids").?.array.items;
    try std.testing.expectEqual(snapshot_admission.maximum_account_sources, source_ids.len);
    try std.testing.expectEqualStrings(source, source_ids[source_ids.len - 1].string);
    const observations = control.get(state, "observations").?.array.items;
    try std.testing.expectEqual(snapshot_admission.maximum_domain_records, observations.len);
    var provider_observations: usize = 0;
    var fixture_observations: usize = 0;
    for (observations) |observation| {
        try std.testing.expectEqualStrings(account_id, try control.string(observation, "account_id"));
        const provenance = try control.string(observation, "provenance");
        if (std.mem.eql(u8, provenance, "provider_api")) {
            provider_observations += 1;
        } else {
            try std.testing.expectEqualStrings("fixture", provenance);
            fixture_observations += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 100), provider_observations);
    try std.testing.expectEqual(snapshot_admission.maximum_domain_records - 100, fixture_observations);
    const jobs = control.get(state, "jobs").?.array.items;
    for (jobs) |job| try std.testing.expectEqualStrings("completed", try control.string(job, "status"));
    const grants = control.get(state, "grants").?.array.items;
    try std.testing.expectEqual(snapshot_admission.maximum_account_sources, grants.len);
    var found_grant = false;
    for (grants) |grant| {
        if (!std.mem.eql(u8, source, try control.string(grant, "source_id"))) continue;
        found_grant = true;
        var secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = account_id, .grant_id = try control.string(grant, "id"), .generation = @intCast(control.get(grant, "generation").?.integer), .purpose = "request", .scope = "https://chatgpt.com" });
        defer secret.deinit();
        var credential = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{});
        defer {
            control.wipeJson(credential.value);
            credential.deinit();
        }
        try std.testing.expect(std.mem.eql(u8, token, try control.string(credential.value, "access_token")));
        try std.testing.expectEqualStrings(&tenant, try control.string(credential.value, "provider_account_id"));
    }
    try std.testing.expect(found_grant);
}

test "held import protects maximum legal completion from unrelated whole-state saturation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const response = try maximumIdentityResponse();
    defer allocator.free(response);
    const escaped_label: [4096]u8 = @splat('\\');
    const before = try budget(engine);
    var held = try holdImportLabel(engine, source, token, false, &escaped_label);
    defer held.deinit();
    const promised = try budget(engine);
    try std.testing.expectEqual(before.credit_count + 1, promised.credit_count);
    try std.testing.expect(promised.credits_bytes > before.credits_bytes);
    try assertNoPlaintext(&fixture, token);

    try saturate(engine);
    const full = try budget(engine);
    const committed_revision = try revision(engine);
    var unrelated = try rpc(engine, .control, "source.connect", .{ .kind = "explicit", .provider = "github", .label = "unrelated fixture" });
    defer unrelated.deinit();
    try unrelated.expectError("SnapshotTooLarge");
    try std.testing.expectEqual(committed_revision, try revision(engine));
    const refused = try budget(engine);
    try std.testing.expectEqual(full.credit_count, refused.credit_count);
    try std.testing.expectEqual(full.credits_bytes, refused.credits_bytes);
    try std.testing.expectEqual(full.reserved_bytes, refused.reserved_bytes);

    try completeImport(engine, source, held, response, null);
    const completed = try budget(engine);
    try std.testing.expectEqual(@as(usize, 0), completed.credit_count);
    try std.testing.expectEqual(@as(usize, 0), completed.credits_bytes);
    // The completed account retains the label while its admission intent is
    // removed. Physical snapshot size may shrink during a valid atomic commit.
    try std.testing.expect((try revision(engine)) > committed_revision);
    try std.testing.expect(completed.reserved_bytes <= full.reserved_bytes);
    try assertNoPlaintext(&fixture, token);

    fixture.close();
    var store = try openStored(&fixture);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    try std.testing.expectEqual(completed.exact_snapshot_bytes, saved.json.len);
    try std.testing.expect(std.mem.indexOf(u8, saved.json, token) == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state").?;
    const accounts = control.get(state, "accounts").?.array.items;
    const grants = control.get(state, "grants").?.array.items;
    const jobs = control.get(state, "jobs").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(@as(usize, 1), jobs.len);
    try std.testing.expectEqualStrings(&escaped_label, try control.string(accounts[0], "label"));
    try std.testing.expectEqualStrings("completed", try control.string(jobs[0], "status"));
    const account_id = try control.string(accounts[0], "id");
    const grant_id = try control.string(grants[0], "id");
    var secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = account_id, .grant_id = grant_id, .generation = @intCast(control.get(grants[0], "generation").?.integer), .purpose = "request", .scope = "https://github.com" });
    defer secret.deinit();
    var credential = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{});
    defer {
        control.wipeJson(credential.value);
        credential.deinit();
    }
    try std.testing.expect(std.mem.eql(u8, token, try control.string(credential.value, "access_token")));
}

test "import saturation refuses admission before creating verification authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    try saturate(engine);
    const before = try budget(engine);
    const before_revision = try revision(engine);
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importStart", .{ .application = "enrollment", .capability = capability[0..], .source_id = source, .provider = "github", .access_token = token });
    defer reply.deinit();
    try reply.expectError("SnapshotTooLarge");
    try std.testing.expectEqual(before_revision, try revision(engine));
    const after = try budget(engine);
    try std.testing.expectEqual(before.reserved_bytes, after.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), after.credit_count);
    try assertNoPlaintext(&fixture, token);
    fixture.close();
    var store = try openStored(&fixture);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state").?;
    try std.testing.expectEqual(@as(usize, 0), control.get(state, "jobs").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), control.get(state, "accounts").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), control.get(state, "grants").?.array.items.len);
}

fn expectOldImportAbsent(engine: *engine_module.Engine, source_id: []const u8, held: HeldImport, response: []const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importComplete", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .generation = held.generation, .response = response });
    defer reply.deinit();
    try reply.expectError("NotFound");
}

fn nativeEnrollmentSource(fixture: *Fixture, token: []const u8) ![]u8 {
    const document = try std.json.Stringify.valueAlloc(allocator, .{ .access_token = token }, .{});
    defer {
        std.crypto.secureZero(u8, document);
        allocator.free(document);
    }
    const file = try fixture.directory.dir.createFile(io, "explicit-enrollment.json", .{ .exclusive = true });
    defer file.close(io);
    if (std.c.fchmod(file.handle, 0o600) != 0) return error.FixturePermissionFailed;
    try file.writeStreamingAll(io, document);
    const path = try std.fmt.allocPrint(allocator, "{s}/explicit-enrollment.json", .{fixture.path});
    defer allocator.free(path);
    var connected = try rpc(fixture.engine.?, .control, "source.connect", .{ .kind = "native_store", .provider = "github", .label = "generated explicit enrollment fixture", .source_path = path });
    defer connected.deinit();
    return allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
}

fn holdEnrollmentStart(engine: *engine_module.Engine) !void {
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.importEnrollmentHold", .{ .application = "enrollment", .capability = capability[0..] });
}

test "ordinary explicit enrollment fences only stranded generation while mutation replay and live ownership stay unchanged" {
    const wait = @import("enrollment_wait.zig");
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const source = try nativeEnrollmentSource(&fixture, token);
    defer allocator.free(source);
    const response = try identityResponse();
    defer allocator.free(response);
    var old = try holdImport(fixture.engine.?, source, token, false);
    defer old.deinit();
    try holdEnrollmentStart(fixture.engine.?);
    const original_id = try generatedValue();
    defer allocator.free(original_id);
    const original_revision = try revision(fixture.engine.?);
    const original_params = .{ .source_id = source, .include_operation_generation = true, .operation_id = original_id[0..64], .expected_revision = original_revision };
    var admitted = try rpc(fixture.engine.?, .control, "enrollment.start", original_params);
    defer admitted.deinit();
    const original = try wait.selection(admitted.parsed.value);
    try std.testing.expectEqual(@as(u64, @intCast(old.generation)), original.operation_generation);
    try std.testing.expectEqualStrings(old.operation_id, original.operation_id);
    try std.testing.expectEqual(@as(usize, 1), (try budget(fixture.engine.?)).credit_count);
    const acknowledged_revision = try revision(fixture.engine.?);
    var duplicate = try rpc(fixture.engine.?, .control, "enrollment.start", original_params);
    defer duplicate.deinit();
    try std.testing.expectEqualStrings(admitted.bytes, duplicate.bytes);
    try std.testing.expectEqual(acknowledged_revision, try revision(fixture.engine.?));
    var conflicting = try rpc(fixture.engine.?, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = false, .operation_id = original_id[0..64], .expected_revision = original_revision });
    defer conflicting.deinit();
    try conflicting.expectError("OperationIdConflict");
    try expectJob(fixture.engine.?, old, "running");

    try fixture.restart();
    const engine = fixture.engine.?;
    try holdEnrollmentStart(engine);
    var replayed = try rpc(engine, .control, "enrollment.start", original_params);
    defer replayed.deinit();
    try std.testing.expectEqualStrings(admitted.bytes, replayed.bytes);
    try expectJob(engine, old, "running");
    const retained = try budget(engine);
    // Legacy source reconciliation and background fixture polling retain the
    // missing-transport owner; an original explicit mutation replay also does.
    var automatic = try rpc(engine, .control, "source.reconcile", .{ .source_id = source, .include_operation_generation = true });
    defer automatic.deinit();
    try std.testing.expectEqual(old.generation, control.get(try automatic.result(), "operation_generation").?.integer);
    try expectZeroProviderSubmissions(engine, "fixture.pollSources");
    try expectJob(engine, old, "running");
    try std.testing.expectEqual(retained.credits_bytes, (try budget(engine)).credits_bytes);
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");

    const fresh_id = try generatedValue();
    defer allocator.free(fresh_id);
    const fresh_params = .{ .source_id = source, .include_operation_generation = true, .operation_id = fresh_id[0..64], .expected_revision = try revision(engine) };
    var fresh_reply = try rpc(engine, .control, "enrollment.start", fresh_params);
    defer fresh_reply.deinit();
    const selected = try wait.selection(fresh_reply.parsed.value);
    try std.testing.expectEqual(original.operation_generation + 1, selected.operation_generation);
    try std.testing.expectEqualStrings(original.operation_id, selected.operation_id);
    var fresh: HeldImport = .{ .operation_id = try allocator.dupe(u8, selected.operation_id), .generation = @intCast(selected.operation_generation) };
    defer fresh.deinit();
    try expectJob(engine, fresh, "running");
    try std.testing.expectEqual(@as(usize, 1), (try budget(engine)).credit_count);
    var fresh_duplicate = try rpc(engine, .control, "enrollment.start", fresh_params);
    defer fresh_duplicate.deinit();
    try std.testing.expectEqualStrings(fresh_reply.bytes, fresh_duplicate.bytes);
    var coalesced = try rpc(engine, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = true });
    defer coalesced.deinit();
    try std.testing.expectEqual(fresh.generation, control.get(try coalesced.result(), "operation_generation").?.integer);
    var original_again = try rpc(engine, .control, "enrollment.start", original_params);
    defer original_again.deinit();
    try std.testing.expectEqualStrings(admitted.bytes, original_again.bytes);
    var state = try rpc(engine, .control, "state.snapshot", .{});
    defer state.deinit();
    try std.testing.expectError(error.EnrollmentSuperseded, wait.observe(original, state.parsed.value));
    try expectOldImportAbsent(engine, source, old, response);
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");
    try completeImport(engine, source, fresh, response, null);
    try expectJob(engine, fresh, "completed");
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    try assertNoPlaintext(&fixture, token);
}

test "ordinary explicit enrollment retains source disconnect and identity forget fences" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const source = try nativeEnrollmentSource(&fixture, token);
    defer allocator.free(source);
    const engine = fixture.engine.?;
    try holdEnrollmentStart(engine);
    const response = try identityResponse();
    defer allocator.free(response);
    var started = try rpc(engine, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = true });
    defer started.deinit();
    const selected = try @import("enrollment_wait.zig").selection(started.parsed.value);
    var held: HeldImport = .{ .operation_id = try allocator.dupe(u8, selected.operation_id), .generation = @intCast(selected.operation_generation) };
    defer held.deinit();
    try completeImport(engine, source, held, response, null);
    const account = try firstAccount(engine);
    defer allocator.free(account);
    try success(engine, .control, "account.forget", .{ .account_id = account });
    var forgotten = try rpc(engine, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = true });
    defer forgotten.deinit();
    const next = try @import("enrollment_wait.zig").selection(forgotten.parsed.value);
    var attempted: HeldImport = .{ .operation_id = try allocator.dupe(u8, next.operation_id), .generation = @intCast(next.operation_generation) };
    defer attempted.deinit();
    try std.testing.expect(attempted.generation > held.generation);
    // Explicit authorization to verify is not permission to clear tombstones.
    try completeImport(engine, source, attempted, response, "IdentityNotAdmitted");
    var state = try rpc(engine, .control, "state.snapshot", .{});
    defer state.deinit();
    try std.testing.expectEqual(@as(usize, 0), control.get(try state.result(), "accounts").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    try success(engine, .control, "source.disconnect", .{ .source_id = source });
    var disconnected = try rpc(engine, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = true });
    defer disconnected.deinit();
    try disconnected.expectError("SourceUnauthorized");
    try expectJob(engine, attempted, "failed");
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");
    try assertNoPlaintext(&fixture, token);
}

fn firstAccount(engine: *engine_module.Engine) ![]u8 {
    var reply = try rpc(engine, .control, "state.snapshot", .{});
    defer reply.deinit();
    const accounts = control.get(try reply.result(), "accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    return allocator.dupe(u8, try control.string(accounts[0], "id"));
}

test "fresh explicit enrollment reverifies identical ready grant with immutable original mutation and live coalescing" {
    const wait = @import("enrollment_wait.zig");
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const source = try nativeEnrollmentSource(&fixture, token);
    defer allocator.free(source);
    const engine = fixture.engine.?;
    try holdEnrollmentStart(engine);
    const response = try identityResponse();
    defer allocator.free(response);
    const original_id = try generatedValue();
    defer allocator.free(original_id);
    const original_params = .{ .source_id = source, .include_operation_generation = true, .operation_id = original_id[0..64], .expected_revision = try revision(engine) };
    var initial = try rpc(engine, .control, "enrollment.start", original_params);
    defer initial.deinit();
    const original = try wait.selection(initial.parsed.value);
    var completed: HeldImport = .{ .operation_id = try allocator.dupe(u8, original.operation_id), .generation = @intCast(original.operation_generation) };
    defer completed.deinit();
    try completeImport(engine, source, completed, response, null);
    try expectJob(engine, completed, "completed");
    var automatic = try rpc(engine, .control, "source.reconcile", .{ .source_id = source, .include_operation_generation = true });
    defer automatic.deinit();
    try std.testing.expect(control.get(try automatic.result(), "operation_id").? == .null);
    try std.testing.expect(control.get(try automatic.result(), "operation_generation").? == .null);
    try std.testing.expectEqualStrings("reconciled", try control.string(try automatic.result(), "status"));
    {
        const capability = try engine.capabilityForTest("enrollment");
        var polled = try rpc(engine, .adapter, "fixture.pollSources", .{ .application = "enrollment", .capability = capability[0..] });
        defer polled.deinit();
        const submitted = try polled.result();
        // The completed ready grant is eligible for a test-only capacity
        // observation; implicit polling must not submit identity verification.
        try std.testing.expectEqual(@as(i64, 0), control.get(submitted, "identity_submissions").?.integer);
        try std.testing.expectEqual(@as(i64, 1), control.get(submitted, "observation_submissions").?.integer);
    }
    try expectJob(engine, completed, "completed");
    const fresh_id = try generatedValue();
    defer allocator.free(fresh_id);
    const fresh_params = .{ .source_id = source, .include_operation_generation = true, .operation_id = fresh_id[0..64], .expected_revision = try revision(engine) };
    var admitted = try rpc(engine, .control, "enrollment.start", fresh_params);
    defer admitted.deinit();
    const selected = try wait.selection(admitted.parsed.value);
    try std.testing.expectEqual(original.operation_generation + 1, selected.operation_generation);
    try std.testing.expectEqualStrings(original.operation_id, selected.operation_id);
    var fresh: HeldImport = .{ .operation_id = try allocator.dupe(u8, selected.operation_id), .generation = @intCast(selected.operation_generation) };
    defer fresh.deinit();
    var coalesced = try rpc(engine, .control, "enrollment.start", .{ .source_id = source, .include_operation_generation = true });
    defer coalesced.deinit();
    try std.testing.expectEqual(fresh.generation, control.get(try coalesced.result(), "operation_generation").?.integer);
    try std.testing.expectEqual(@as(usize, 1), (try budget(engine)).credit_count);
    const before_replays = try revision(engine);
    var new_replay = try rpc(engine, .control, "enrollment.start", fresh_params);
    defer new_replay.deinit();
    try std.testing.expectEqualStrings(admitted.bytes, new_replay.bytes);
    var old_replay = try rpc(engine, .control, "enrollment.start", original_params);
    defer old_replay.deinit();
    try std.testing.expectEqualStrings(initial.bytes, old_replay.bytes);
    try std.testing.expectEqual(before_replays, try revision(engine));
    try expectJob(engine, fresh, "running");
    var pending = try rpc(engine, .control, "state.snapshot", .{});
    defer pending.deinit();
    try std.testing.expectError(error.EnrollmentSuperseded, wait.observe(original, pending.parsed.value));
    try std.testing.expectEqual(wait.State.pending, try wait.observe(selected, pending.parsed.value));
    {
        const capability = try engine.capabilityForTest("enrollment");
        var counters = try rpc(engine, .adapter, "fixture.providerSubmissions", .{ .application = "enrollment", .capability = capability[0..] });
        defer counters.deinit();
        const submitted = try counters.result();
        try std.testing.expectEqual(@as(i64, 0), control.get(submitted, "identity_submissions").?.integer);
        try std.testing.expectEqual(@as(i64, 1), control.get(submitted, "observation_submissions").?.integer);
    }
    try completeImport(engine, source, fresh, response, null);
    try expectJob(engine, fresh, "completed");
    const account = try firstAccount(engine);
    defer allocator.free(account);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    try assertNoPlaintext(&fixture, token);
}

fn expectJob(engine: *engine_module.Engine, held: HeldImport, status: []const u8) !void {
    var reply = try rpc(engine, .control, "state.snapshot", .{});
    defer reply.deinit();
    const jobs = control.get(try reply.result(), "jobs").?.array.items;
    for (jobs) |job| if (std.mem.eql(u8, held.operation_id, try control.string(job, "id"))) {
        try std.testing.expectEqual(held.generation, control.get(job, "operation_generation").?.integer);
        try std.testing.expectEqualStrings(status, try control.string(job, "status"));
        return;
    };
    return error.MissingImportJob;
}

test "issued cancellation preserves import credit and explicit pending cancellation fences release" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const response = try identityResponse();
    defer allocator.free(response);
    var old = try holdImport(engine, source, token, false);
    defer old.deinit();
    const issued = try budget(engine);
    var cancellation = try rpc(engine, .control, "operation.cancel", .{ .target_operation_id = old.operation_id });
    defer cancellation.deinit();
    try cancellation.expectError("AlreadyIssued");
    const unchanged = try budget(engine);
    try std.testing.expectEqual(issued.credit_count, unchanged.credit_count);
    try std.testing.expectEqual(issued.credits_bytes, unchanged.credits_bytes);
    try expectJob(engine, old, "running");

    // A pending job is explicitly cancellable. Keep the held old response so
    // the actor must enforce its durable cancellation, rather than infer that
    // transport disappearance made the completion harmless.
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.importJob", .{ .application = "enrollment", .capability = capability[0..], .target_operation_id = old.operation_id, .status = "pending" });
    try success(engine, .control, "operation.cancel", .{ .target_operation_id = old.operation_id });
    try expectJob(engine, old, "failed");
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    var fresh = try holdImport(engine, source, token, false);
    defer fresh.deinit();
    try std.testing.expect(fresh.generation > old.generation);
    const fresh_promise = try budget(engine);
    try completeImport(engine, source, old, response, "ImportSuperseded");
    const after_old = try budget(engine);
    try std.testing.expectEqual(fresh_promise.credit_count, after_old.credit_count);
    try std.testing.expectEqual(fresh_promise.credits_bytes, after_old.credits_bytes);
    try expectJob(engine, fresh, "running");
    try completeImport(engine, source, fresh, response, null);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
}

test "expired identity completions durably fail and release only their matching credit" {
    for ([_][]const u8{ "source", "provider", "custody" }) |kind| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const engine = fixture.engine.?;
        const source = try fixture.connect();
        defer allocator.free(source);
        const other_source = try fixture.connect();
        defer allocator.free(other_source);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        const response = try identityResponse();
        defer allocator.free(response);
        var expiring = try holdImport(engine, source, token, false);
        defer expiring.deinit();
        const expiring_promise = try budget(engine);
        var independent = try holdImport(engine, other_source, token, false);
        defer independent.deinit();
        const both = try budget(engine);
        const independent_bytes = both.credits_bytes - expiring_promise.credits_bytes;
        try std.testing.expect(independent_bytes > 0);
        if (std.mem.eql(u8, kind, "source")) {
            try sourceTransition(engine, source, "expire");
        } else {
            const capability = try engine.capabilityForTest("enrollment");
            try success(engine, .adapter, "fixture.importExpire", .{ .application = "enrollment", .capability = capability[0..], .source_id = source, .kind = kind });
        }
        try completeImport(engine, source, expiring, response, if (std.mem.eql(u8, kind, "source")) "SourceUnauthorized" else if (std.mem.eql(u8, kind, "provider")) "ExpiredCredential" else "InvalidCustodyLease");
        const remaining = try budget(engine);
        try std.testing.expectEqual(@as(usize, 1), remaining.credit_count);
        try std.testing.expectEqual(independent_bytes, remaining.credits_bytes);
        try expectJob(engine, expiring, "failed");
        try expectJob(engine, independent, "running");
        try expectOldImportAbsent(engine, source, expiring, response);
        try std.testing.expectEqual(independent_bytes, (try budget(engine)).credits_bytes);
        try completeImport(engine, other_source, independent, response, null);
        try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
        try assertNoPlaintext(&fixture, token);
    }
}

test "source detach and disconnect ABA cannot spend a newer completion reservation" {
    for ([_][]const u8{ "detach", "disconnect" }) |transition| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const engine = fixture.engine.?;
        const source = try fixture.connect();
        defer allocator.free(source);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        const response = try identityResponse();
        defer allocator.free(response);
        var old = try holdImport(engine, source, token, false);
        defer old.deinit();
        if (std.mem.eql(u8, transition, "disconnect")) try success(engine, .control, "source.disconnect", .{ .source_id = source }) else try sourceTransition(engine, source, transition);
        try expectJob(engine, old, "failed");
        try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
        try sourceTransition(engine, source, "connect");
        var fresh = try holdImport(engine, source, token, false);
        defer fresh.deinit();
        try std.testing.expect(fresh.generation > old.generation);
        const promised = try budget(engine);
        try completeImport(engine, source, old, response, "ImportSuperseded");
        const protected = try budget(engine);
        try std.testing.expectEqual(promised.credit_count, protected.credit_count);
        try std.testing.expectEqual(promised.credits_bytes, protected.credits_bytes);
        try expectJob(engine, fresh, "running");
        try completeImport(engine, source, fresh, response, null);
        try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    }
}

test "forget supersession cannot consume fresh explicit re-enrollment credit" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const engine = fixture.engine.?;
    const source = try fixture.connect();
    defer allocator.free(source);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const response = try identityResponse();
    defer allocator.free(response);
    var initial = try holdImport(engine, source, token, false);
    defer initial.deinit();
    try completeImport(engine, source, initial, response, null);
    const account = try firstAccount(engine);
    defer allocator.free(account);
    var old = try holdImport(engine, source, token, true);
    defer old.deinit();
    try success(engine, .control, "account.forget", .{ .account_id = account });
    var fresh = try holdImport(engine, source, token, true);
    defer fresh.deinit();
    try std.testing.expect(fresh.generation > old.generation);
    const promised = try budget(engine);
    try std.testing.expectEqual(@as(usize, 1), promised.credit_count);
    try completeImport(engine, source, old, response, "ImportSuperseded");
    try std.testing.expectEqual(promised.credits_bytes, (try budget(engine)).credits_bytes);
    try expectJob(engine, fresh, "running");
    try completeImport(engine, source, fresh, response, null);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    const reenrolled = try firstAccount(engine);
    defer allocator.free(reenrolled);
    try assertNoPlaintext(&fixture, token);
}

test "restart preserves unresolved import reservation until explicit new generation fences it" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    const native_document = try std.json.Stringify.valueAlloc(allocator, .{ .access_token = token }, .{});
    defer {
        std.crypto.secureZero(u8, native_document);
        allocator.free(native_document);
    }
    {
        const file = try fixture.directory.dir.createFile(io, "native-account.json", .{ .exclusive = true });
        defer file.close(io);
        if (std.c.fchmod(file.handle, 0o600) != 0) return error.FixturePermissionFailed;
        try file.writeStreamingAll(io, native_document);
    }
    const native_path = try std.fmt.allocPrint(allocator, "{s}/native-account.json", .{fixture.path});
    defer allocator.free(native_path);
    var connected = try rpc(fixture.engine.?, .control, "source.connect", .{ .kind = "native_store", .provider = "github", .label = "private native fixture", .source_path = native_path });
    defer connected.deinit();
    const source = try allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
    defer allocator.free(source);
    const response = try identityResponse();
    defer allocator.free(response);
    var old = try holdImport(fixture.engine.?, source, token, false);
    defer old.deinit();
    const before = try budget(fixture.engine.?);
    try fixture.restart();
    const engine = fixture.engine.?;
    const restarted = try budget(engine);
    try std.testing.expectEqual(before.credit_count, restarted.credit_count);
    try std.testing.expectEqual(before.credits_bytes, restarted.credits_bytes);
    try expectJob(engine, old, "running");
    // No process-local transport callback survived. Absence alone neither
    // retires the old job nor returns its promised bytes to general admission.
    try expectOldImportAbsent(engine, source, old, response);
    try std.testing.expectEqual(before.credits_bytes, (try budget(engine)).credits_bytes);
    const retained = try storedFingerprint(engine);
    const retained_counts = try reservedCounts(engine);
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");
    const capability = try engine.capabilityForTest("enrollment");
    var reconciled = try rpc(engine, .adapter, "fixture.importReconcile", .{ .application = "enrollment", .capability = capability[0..], .source_id = source });
    defer reconciled.deinit();
    const retained_owner = try reconciled.result();
    try std.testing.expectEqualStrings(old.operation_id, try control.string(retained_owner, "operation_id"));
    try std.testing.expectEqual(old.generation, control.get(retained_owner, "generation").?.integer);
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");
    try std.testing.expectEqualDeep(restarted, try budget(engine));
    try std.testing.expectEqualDeep(retained_counts, try reservedCounts(engine));
    try std.testing.expectEqualDeep(retained, try storedFingerprint(engine));
    try expectJob(engine, old, "running");
    try expectOldImportAbsent(engine, source, old, response);

    // A larger explicit successor stages an old-generation fence, but that
    // fence and credit retirement must roll back if its new promise cannot fit.
    try saturate(engine);
    const saturated = try budget(engine);
    const saturated_counts = try reservedCounts(engine);
    const saturated_stored = try storedFingerprint(engine);
    const saturated_revision = try revision(engine);
    const escaped_label: [4096]u8 = @splat('\\');
    var refused = try rpc(engine, .adapter, "fixture.importStart", .{ .application = "enrollment", .capability = capability[0..], .source_id = source, .provider = "github", .access_token = token, .label = &escaped_label });
    defer refused.deinit();
    try refused.expectError("SnapshotTooLarge");
    try std.testing.expectEqual(saturated_revision, try revision(engine));
    try std.testing.expectEqualDeep(saturated, try budget(engine));
    try std.testing.expectEqualDeep(saturated_counts, try reservedCounts(engine));
    try std.testing.expectEqualDeep(saturated_stored, try storedFingerprint(engine));
    try expectZeroProviderSubmissions(engine, "fixture.providerSubmissions");
    try expectJob(engine, old, "running");
    try expectOldImportAbsent(engine, source, old, response);

    var fresh = try holdImport(engine, source, token, false);
    defer fresh.deinit();
    try std.testing.expect(fresh.generation > old.generation);
    const replacement = try budget(engine);
    try std.testing.expectEqual(@as(usize, 1), replacement.credit_count);
    try expectOldImportAbsent(engine, source, old, response);
    try std.testing.expectEqual(replacement.credits_bytes, (try budget(engine)).credits_bytes);
    try expectJob(engine, fresh, "running");
    try completeImport(engine, source, fresh, response, null);
    try std.testing.expectEqual(@as(usize, 0), (try budget(engine)).credit_count);
    try expectJob(engine, fresh, "completed");
    try assertNoPlaintext(&fixture, token);

    fixture.close();
    var store = try openStored(&fixture);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    try std.testing.expect(std.mem.indexOf(u8, saved.json, token) == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state").?;
    const grants = control.get(state, "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualStrings(source, try control.string(grants[0], "source_id"));
    const grant = grants[0];
    var secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = try control.string(grant, "account_id"), .grant_id = try control.string(grant, "id"), .generation = @intCast(control.get(grant, "generation").?.integer), .purpose = "request", .scope = "https://github.com" });
    defer secret.deinit();
    var credential = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{});
    defer {
        control.wipeJson(credential.value);
        credential.deinit();
    }
    try std.testing.expect(std.mem.eql(u8, token, try control.string(credential.value, "access_token")));
}
