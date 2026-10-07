//! Configuration acknowledgments are retained operation outcomes, never an
//! installation/activation denominator or a successful native application.
const std = @import("std");
const builtin = @import("builtin");
const projection = @import("terminal_adapter_setup.zig");
const mutation = @import("mutation_authority.zig");
const engine = @import("engine.zig");
const control = @import("control.zig");
const native_fixture = @import("native_owner_fixture.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;

fn complete(ledger: *mutation.Ledger, id: []const u8, method: []const u8, kind: mutation.Kind, bytes: []const u8) !usize {
    const slot = (try ledger.begin(id, method, @splat(8), 0, 0, kind)).execute;
    try ledger.complete(slot, bytes);
    return slot;
}
const changed_git = "{\"installed\":true,\"adapter\":\"git\",\"config_path\":\"generated-private-path\",\"changed\":true}";
const unchanged_git = "{\"installed\":true,\"adapter\":\"git\",\"config_path\":\"generated-private-path\",\"changed\":false}";
const changed_codex = "{\"installed\":true,\"adapter\":\"codex\",\"config_path\":\"generated-private-path\",\"changed\":true}";

test "retained adapter configuration completions separate changed unchanged and historical removal" {
    var ledger = try mutation.Ledger.init(allocator, 8);
    defer ledger.deinit();
    _ = try complete(&ledger, "changed-git", projection.method, .external, changed_git);
    _ = try complete(&ledger, "unchanged-git", projection.method, .external, unchanged_git);
    _ = try complete(&ledger, "changed-codex", projection.method, .external, changed_codex);
    const before = try projection.summarize(allocator, ledger.snapshot());
    _ = try complete(&ledger, "later-removal", "integrations.remove", .external, "{\"removed\":true,\"adapter\":\"git\",\"config_path\":\"generated-private-path\",\"changed\":true}");
    const after = try projection.summarize(allocator, ledger.snapshot());
    try std.testing.expectEqualDeep(before, after);
    try std.testing.expectEqual(@as(u64, 1), after.setup_completed_changed.git);
    try std.testing.expectEqual(@as(u64, 1), after.setup_completed_changed.codex);
    try std.testing.expectEqual(@as(u64, 1), after.setup_completed_unchanged.git);
    try std.testing.expectEqual(@as(u64, 3), after.retained_relevant_records);
    try std.testing.expect(!after.installation_success_measured and !after.activation_measured and !after.complete_user_demand_denominator and !after.complete_lifecycle_coverage and !after.achieved_slo and !after.end_to_end_latency_measured);
    const encoded = try std.json.Stringify.valueAlloc(allocator, after, .{});
    defer allocator.free(encoded);
    inline for (.{ "config_path", "generated-private-path", "changed-git", "changed-codex", "fingerprint" }) |forbidden| try std.testing.expect(std.mem.indexOf(u8, encoded, forbidden) == null);
}

test "started and indeterminate authority never imply adapter configuration completion" {
    var ledger = try mutation.Ledger.init(allocator, 4);
    defer ledger.deinit();
    _ = try ledger.begin("started", projection.method, @splat(8), 0, 0, .external);
    const uncertain = (try ledger.begin("uncertain", projection.method, @splat(8), 0, 0, .external)).execute;
    try ledger.markIndeterminate(uncertain);
    const before = try projection.summarize(allocator, ledger.snapshot());
    try std.testing.expectEqual(@as(u64, 1), before.unresolved_started);
    try std.testing.expectEqual(@as(u64, 1), before.unresolved_indeterminate);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, before.setup_completed_changed);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, before.setup_completed_unchanged);
    ledger.recoverAfterRestart();
    const after = try projection.summarize(allocator, ledger.snapshot());
    try std.testing.expectEqual(@as(u64, 2), after.unresolved_indeterminate);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, after.setup_completed_changed);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, after.setup_completed_unchanged);
}

test "current configuration result exact shape kind and correlation refuse malformed optimistic facts" {
    const invalid = [_][]const u8{
        "{\"installed\":false,\"adapter\":\"git\",\"config_path\":\"generated\",\"changed\":true}",
        "{\"installed\":true,\"adapter\":\"git\",\"changed\":true}",
        "{\"installed\":true,\"adapter\":\"future\",\"config_path\":\"generated\",\"changed\":true}",
        "{\"installed\":true,\"adapter\":\"git\",\"config_path\":null,\"changed\":true}",
        "{\"installed\":true,\"adapter\":\"git\",\"config_path\":\"generated\",\"changed\":1}",
        "{\"installed\":true,\"adapter\":\"git\",\"config_path\":\"generated\",\"changed\":true,\"activated\":true}",
        "{\"installed\":true,\"installed\":false,\"adapter\":\"git\",\"config_path\":\"generated\",\"changed\":true}",
    };
    for (invalid) |bytes| {
        var ledger = try mutation.Ledger.init(allocator, 1);
        defer ledger.deinit();
        _ = try complete(&ledger, "invalid", projection.method, .external, bytes);
        try std.testing.expectError(error.InvalidTerminalAdapterSetupResult, projection.summarize(allocator, ledger.snapshot()));
    }
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const wrong_kind = try complete(&ledger, "wrong-kind", projection.method, .local_atomic, changed_git);
    try std.testing.expectError(error.InvalidTerminalAdapterSetupRecord, projection.classifyCompleted(allocator, ledger.data.records[wrong_kind]));
    const other_method = try complete(&ledger, "wrong-method", "source.connect", .external, changed_git);
    try std.testing.expectError(error.UnsupportedTerminalAdapterSetupMethod, projection.classifyCompleted(allocator, ledger.data.records[other_method]));
    var corrupted = ledger.data.records[wrong_kind];
    corrupted.kind = .external;
    corrupted.id[corrupted.id_len] = 'x';
    try std.testing.expectError(error.InvalidTerminalAdapterSetupRecord, projection.classifyCompleted(allocator, corrupted));
    corrupted = ledger.data.records[wrong_kind];
    corrupted.kind = .external;
    corrupted.result_len -= 1;
    try std.testing.expectError(error.InvalidTerminalAdapterSetupRecord, projection.classifyCompleted(allocator, corrupted));
}

test "original IDs replay restore once and distant duplicates cannot inflate configuration completions" {
    var ledger = try mutation.Ledger.init(allocator, 8);
    defer ledger.deinit();
    for ([_][]const u8{ "first", "second", "third", "fourth" }) |id| _ = try complete(&ledger, id, projection.method, .external, changed_git);
    const before = try projection.summarize(allocator, ledger.snapshot());
    _ = (try ledger.begin("second", projection.method, @splat(8), 0, 1, .external)).replay;
    const bytes = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(mutation.Snapshot, allocator, bytes, .{});
    defer parsed.deinit();
    var restored = try mutation.Ledger.fromSnapshot(allocator, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqualDeep(before, try projection.summarize(allocator, restored.snapshot()));
    const rows = [_]mutation.Record{ ledger.data.records[0], ledger.data.records[1], ledger.data.records[2], ledger.data.records[3], ledger.data.records[1] };
    try std.testing.expectError(error.InvalidTerminalAdapterSetupSnapshot, projection.summarize(allocator, .{ .capacity = 8, .count = rows.len, .records = &rows }));
    try std.testing.expectError(error.InvalidTerminalAdapterSetupSnapshot, projection.summarize(allocator, .{ .capacity = mutation.max_records + 1 }));
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
    fn expectError(self: *const Reply, category: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.ExpectedRpcFailure;
        try std.testing.expectEqualStrings(category, try control.string(failure, "message"));
    }
};
fn rpc(actor: *engine.Engine, channel: engine.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(payload);
    const bytes = try actor.dispatch(allocator, payload, channel);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) };
}
fn exported(actor: *engine.Engine) !projection.Summary {
    var reply = try rpc(actor, .control, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "terminal_adapter_setup") orelse return error.MissingAdapterSetupSummary;
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(projection.Summary, allocator, bytes, .{});
    defer parsed.deinit();
    return parsed.value;
}
fn revision(actor: *engine.Engine) !u64 {
    var reply = try rpc(actor, .control, "system.health", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "revision") orelse return error.MissingRevision;
    if (value != .integer or value.integer < 0) return error.InvalidRevision;
    return @intCast(value.integer);
}
fn operation() ![64]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    return std.fmt.bytesToHex(random, .lower);
}
const Saved = struct {
    config: []u8,
    capability: []u8,
    registry: []u8,
    fn capture(actor: *native_fixture.ActorFixture, adapter: []const u8, config_path: []const u8) !Saved {
        const config = try std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1024 * 1024 + 1));
        errdefer allocator.free(config);
        const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/{s}.capability", .{ actor.state, adapter });
        defer allocator.free(capability_path);
        const capability = try std.Io.Dir.cwd().readFileAlloc(io, capability_path, allocator, .limited(65));
        errdefer {
            std.crypto.secureZero(u8, capability);
            allocator.free(capability);
        }
        const registry_path = try std.fmt.allocPrint(allocator, "{s}/integrations/{s}.registry", .{ actor.state, adapter });
        defer allocator.free(registry_path);
        return .{ .config = config, .capability = capability, .registry = try std.Io.Dir.cwd().readFileAlloc(io, registry_path, allocator, .limited(5 * 1024 * 1024)) };
    }
    fn deinit(self: *Saved) void {
        inline for (.{ "config", "capability", "registry" }) |field| {
            std.crypto.secureZero(u8, @field(self, field));
            allocator.free(@field(self, field));
        }
    }
    fn expectSame(self: *const Saved, actor: *native_fixture.ActorFixture, adapter: []const u8, config_path: []const u8) !void {
        var actual = try capture(actor, adapter, config_path);
        defer actual.deinit();
        // Do not expose configuration, capability or custody ciphertext in a
        // failing diagnostic; equality is the stated predicate.
        inline for (.{ "config", "capability", "registry" }) |field| try std.testing.expect(std.mem.eql(u8, @field(self, field), @field(actual, field)));
    }
};

test "actual native configuration completion replay and SQLite restart retain one original outcome without second action" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const id = try operation();
    const params = .{ .adapter = "codex", .operation_id = id[0..], .expected_revision = try revision(actor.engine.?), .config_path = actor.config, .native_socket = producer.endpoint };
    var installed = try rpc(actor.engine.?, .control, projection.method, params);
    defer installed.deinit();
    try std.testing.expect(try control.boolean(try installed.result(), "installed", false));
    try std.testing.expect(try control.boolean(try installed.result(), "changed", false));
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.setup_completed_changed.codex);
    try std.testing.expectEqual(@as(u64, 1), summary.retained_relevant_records);
    try std.testing.expect(!summary.installation_success_measured and !summary.activation_measured and !summary.achieved_slo);
    var saved = try Saved.capture(actor, "codex", actor.config);
    defer saved.deinit();
    const capabilities = producer.methodCount(.capabilities);
    const threads = producer.methodCount(.threads);
    const after_completion = try revision(actor.engine.?);
    var replay = try rpc(actor.engine.?, .control, projection.method, params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, installed.bytes, replay.bytes));
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try std.testing.expectEqual(after_completion, try revision(actor.engine.?));
    try saved.expectSame(actor, "codex", actor.config);
    try actor.restart();
    const after_restart = try revision(actor.engine.?);
    var restarted_replay = try rpc(actor.engine.?, .control, projection.method, params);
    defer restarted_replay.deinit();
    try std.testing.expect(std.mem.eql(u8, installed.bytes, restarted_replay.bytes));
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try std.testing.expectEqual(after_restart, try revision(actor.engine.?));
    try saved.expectSame(actor, "codex", actor.config);
    try std.testing.expectEqual(capabilities, producer.methodCount(.capabilities));
    try std.testing.expectEqual(threads, producer.methodCount(.threads));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.announce));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    try std.testing.expect(producer.failure() == null);
}

test "actual Git unchanged owned setup is distinct from replay and historical configuration survives removal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const config_path = try std.fmt.allocPrint(allocator, "{s}/git-fixture.conf", .{actor.home});
    defer allocator.free(config_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = "# generated original Git fixture\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    defer std.Io.Dir.cwd().deleteFile(io, config_path) catch @panic("Git fixture cleanup failed");
    const first_id = try operation();
    var first = try rpc(actor.engine.?, .control, projection.method, .{ .adapter = "git", .operation_id = first_id[0..], .expected_revision = try revision(actor.engine.?), .config_path = config_path });
    defer first.deinit();
    try std.testing.expect(try control.boolean(try first.result(), "changed", false));
    var saved = try Saved.capture(actor, "git", config_path);
    defer saved.deinit();
    const second_id = try operation();
    var second = try rpc(actor.engine.?, .control, projection.method, .{ .adapter = "git", .operation_id = second_id[0..], .expected_revision = try revision(actor.engine.?), .config_path = config_path });
    defer second.deinit();
    try std.testing.expect(!(try control.boolean(try second.result(), "changed", true)));
    try saved.expectSame(actor, "git", config_path);
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.setup_completed_changed.git);
    try std.testing.expectEqual(@as(u64, 1), summary.setup_completed_unchanged.git);
    const remove_id = try operation();
    var removed = try rpc(actor.engine.?, .control, "integrations.remove", .{ .adapter = "git", .operation_id = remove_id[0..], .expected_revision = try revision(actor.engine.?), .config_path = config_path });
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try actor.restart();
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.register));
}

test "actual unsupported native hook refusal remains unresolved authority and never counts configuration success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.createWithOptions(io, allocator, .{ .mode = .stock_capabilities });
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const original = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(4096));
    defer allocator.free(original);
    const id = try operation();
    const params = .{ .adapter = "codex", .operation_id = id[0..], .expected_revision = try revision(actor.engine.?), .config_path = actor.config, .native_socket = producer.endpoint };
    var refused = try rpc(actor.engine.?, .control, projection.method, params);
    defer refused.deinit();
    try refused.expectError("NativeHookRequired");
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_indeterminate);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, summary.setup_completed_changed);
    try std.testing.expectEqualDeep(projection.AdapterCounts{}, summary.setup_completed_unchanged);
    const retained_config = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(4096));
    defer allocator.free(retained_config);
    try std.testing.expect(std.mem.eql(u8, original, retained_config));
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
    defer allocator.free(capability_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, capability_path, .{ .follow_symlinks = false }));
    const capabilities = producer.methodCount(.capabilities);
    const before_replay = try revision(actor.engine.?);
    var replay = try rpc(actor.engine.?, .control, projection.method, params);
    defer replay.deinit();
    try replay.expectError("OperationIndeterminate");
    try std.testing.expectEqual(before_replay, try revision(actor.engine.?));
    try actor.restart();
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    var restarted_replay = try rpc(actor.engine.?, .control, projection.method, params);
    defer restarted_replay.deinit();
    try restarted_replay.expectError("OperationIndeterminate");
    try std.testing.expectEqual(capabilities, producer.methodCount(.capabilities));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.announce));
}
