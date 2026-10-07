//! Synthetic real-engine admission boundaries. No provider, personal vault or
//! application process is used; these predicates do not prove live continuity.
const std = @import("std");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const setup = @import("integrations/setup.zig");
const owner_fixture = @import("native_owner_fixture.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;

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
    fn expectError(self: *const Reply, name: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.MissingRpcError;
        // Error names are public predicates. Never print credential fixtures.
        try std.testing.expectEqualStrings(name, try control.string(failure, "message"));
    }
};

fn rpc(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const initial = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = normalized }, .{});
    defer {
        std.crypto.secureZero(u8, initial);
        allocator.free(initial);
    }
    var request = try std.json.parseFromSlice(std.json.Value, allocator, initial, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(request.value);
        request.deinit();
    }
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const target = request.value.object.getPtr("params").?;
        if (target.* == .null) target.* = .{ .object = .empty };
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        const operation_id = std.fmt.bytesToHex(random, .lower);
        // wipeJson also erases object keys. Hash-map insertion borrows keys,
        // so dynamically added keys must be writable arena-owned copies.
        try target.object.put(request.arena.allocator(), try request.arena.allocator().dupe(u8, "operation_id"), .{ .string = try request.arena.allocator().dupe(u8, &operation_id) });
        var snapshot = try rpc(engine, .control, "state.snapshot", .{});
        defer snapshot.deinit();
        const revision = control.get(try snapshot.result(), "revision") orelse return error.InvalidReply;
        try target.object.put(request.arena.allocator(), try request.arena.allocator().dupe(u8, "expected_revision"), revision);
    }
    const encoded = try std.json.Stringify.valueAlloc(allocator, request.value, .{});
    defer {
        std.crypto.secureZero(u8, encoded);
        allocator.free(encoded);
    }
    const bytes = try engine.dispatch(allocator, encoded, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}

const methods = [_]owner_fixture.Method{ .identify, .register, .unregister, .announce, .capabilities, .threads };
const Fixture = struct {
    endpoint: *owner_fixture.Fixture,
    actor: *owner_fixture.ActorFixture,
    state: []const u8,
    config: []const u8,
    requested_config: []u8,
    engine: *engine_module.Engine,
    enrollment: [64]u8,
    fn create(installed: bool, escaped: bool) !Fixture {
        const endpoint = try owner_fixture.Fixture.create(io, allocator);
        errdefer endpoint.destroy();
        const actor = try owner_fixture.ActorFixture.create(io, allocator, endpoint);
        errdefer actor.deinit();
        // Admission to install always goes through the genuine V2 control RPC.
        // An oversized remove *request* must preserve that real retained setup.
        if (installed) try actor.install();
        const component: [180]u8 = @splat('"');
        const requested_config = if (escaped) try std.fmt.allocPrint(allocator, "{s}/{s}/{s}/{s}/{s}/config.toml", .{ actor.home, component, component, component, component }) else try allocator.dupe(u8, actor.config);
        errdefer allocator.free(requested_config);
        return .{ .endpoint = endpoint, .actor = actor, .state = actor.state, .config = actor.config, .requested_config = requested_config, .engine = actor.engine.?, .enrollment = try actor.engine.?.capabilityForTest("enrollment") };
    }
    fn deinit(self: *Fixture) void {
        self.actor.deinit();
        std.crypto.secureZero(u8, &self.enrollment);
        allocator.free(self.requested_config);
        self.endpoint.destroy();
    }
    fn counts(self: *const Fixture) [methods.len]usize {
        var result: [methods.len]usize = undefined;
        for (methods, &result) |method, *count| count.* = self.endpoint.methodCount(method);
        return result;
    }
    fn expectNoRequests(self: *const Fixture, before: [methods.len]usize) !void {
        const after = self.counts();
        try std.testing.expectEqualSlices(usize, &before, &after);
    }
    fn saturate(self: *Fixture) !void {
        var filled = try rpc(self.engine, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = self.enrollment[0..], .spare_bytes = @as(u64, 0) });
        defer filled.deinit();
        const result = try filled.result();
        const remaining = control.get(result, "remaining_bytes") orelse return error.InvalidReply;
        try std.testing.expect(remaining == .integer and remaining.integer >= 0 and remaining.integer <= 64);
    }
    fn expectInstalled(self: *Fixture, installed: bool) !void {
        var reply = try rpc(self.engine, .control, "integrations.status", .{});
        defer reply.deinit();
        const names = control.get(try reply.result(), "installed") orelse return error.InvalidReply;
        try std.testing.expect(names == .array);
        try std.testing.expectEqual(@as(usize, if (installed) 1 else 0), names.array.items.len);
        if (installed) try std.testing.expectEqualStrings("codex", names.array.items[0].string);
    }
};

const Files = struct {
    config: ?[]u8,
    capability: ?[]u8,
    registry: ?[]u8,
    fn read(path: []const u8, limit: usize) !?[]u8 {
        // readFileAlloc refuses when its exclusive bound is reached, before
        // probing EOF. Preserve the inclusive fixture cap with one probe byte.
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(try std.math.add(usize, limit, 1))) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        if (bytes.len > limit) {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
            return error.StreamTooLong;
        }
        return bytes;
    }
    fn capture(fixture: *Fixture) !Files {
        const config = try read(fixture.config, setup.maximum_config);
        errdefer if (config) |bytes| allocator.free(bytes);
        const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{fixture.state});
        defer allocator.free(capability_path);
        const capability = try read(capability_path, 64);
        errdefer if (capability) |bytes| allocator.free(bytes);
        const registry_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.registry", .{fixture.state});
        defer allocator.free(registry_path);
        return .{ .config = config, .capability = capability, .registry = try read(registry_path, 5 * setup.maximum_config) };
    }
    fn deinit(self: Files) void {
        for ([_]?[]u8{ self.config, self.capability, self.registry }) |item| if (item) |bytes| {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        };
    }
    fn expectUnchanged(self: Files, fixture: *Fixture) !void {
        const after = try capture(fixture);
        defer after.deinit();
        for ([_]?[]u8{ self.config, self.capability, self.registry }, [_]?[]u8{ after.config, after.capability, after.registry }) |before, current| {
            try std.testing.expect((before == null) == (current == null));
            if (before) |bytes| try std.testing.expect(std.mem.eql(u8, bytes, current.?));
        }
    }
};

test "native fixture file capture accepts its exact cap and refuses one byte beyond" {
    const endpoint = try owner_fixture.Fixture.create(io, allocator);
    defer {
        for ([_][]const u8{ "bounded-63", "bounded-64", "bounded-65" }) |name| {
            const file_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ endpoint.root, name }) catch @panic("Fixture cleanup allocation");
            defer allocator.free(file_path);
            std.Io.Dir.cwd().deleteFile(io, file_path) catch @panic("Fixture capture cleanup");
        }
        endpoint.destroy();
    }
    for ([_]usize{ 63, 64, 65 }) |length| {
        const path = try std.fmt.allocPrint(allocator, "{s}/bounded-{d}", .{ endpoint.root, length });
        defer allocator.free(path);
        const bytes: [65]u8 = @splat('f');
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true });
        {
            defer file.close(io);
            if (std.c.fchmod(file.handle, 0o600) != 0) return error.FixturePermissions;
            try file.writeStreamingAll(io, bytes[0..length]);
        }
        if (length > 64) {
            try std.testing.expectError(error.StreamTooLong, Files.read(path, 64));
        } else {
            const captured = (try Files.read(path, 64)) orelse return error.MissingFixtureFile;
            defer {
                std.crypto.secureZero(u8, captured);
                allocator.free(captured);
            }
            try std.testing.expectEqual(length, captured.len);
            try std.testing.expect(std.mem.eql(u8, bytes[0..length], captured));
        }
    }
}

test "real engine oversized install completion refuses before native or configuration effects" {
    var fixture = try Fixture.create(false, true);
    defer fixture.deinit();
    const before = try Files.capture(&fixture);
    defer before.deinit();
    try std.testing.expect(before.config != null and before.capability == null and before.registry == null);
    const counts = fixture.counts();
    var reply = try rpc(fixture.engine, .control, "integrations.install", .{ .adapter = "codex", .config_path = fixture.requested_config, .native_socket = fixture.endpoint.endpoint });
    defer reply.deinit();
    try reply.expectError("ResultTooLarge");
    try fixture.expectNoRequests(counts);
    try before.expectUnchanged(&fixture);
    try fixture.expectInstalled(false);
}

test "real installed removal refuses oversized conflicting context and restores original custody path" {
    var fixture = try Fixture.create(true, true);
    defer fixture.deinit();
    const before = try Files.capture(&fixture);
    defer before.deinit();
    try std.testing.expect(before.config != null and before.capability != null and before.registry != null);
    const original_registry = fixture.engine.native_registry orelse return error.MissingRegistryWitness;
    try std.testing.expect((try Files.read(fixture.requested_config, setup.maximum_config)) == null);
    const counts = fixture.counts();
    const original_revision = fixture.engine.revision;
    var refused = try rpc(fixture.engine, .control, "integrations.remove", .{ .adapter = "codex", .config_path = fixture.requested_config, .native_socket = fixture.endpoint.endpoint });
    defer refused.deinit();
    try refused.expectError("IntegrationPathConflict");
    try std.testing.expectEqual(original_revision, fixture.engine.revision);
    try std.testing.expectEqualDeep(original_registry, fixture.engine.native_registry orelse return error.MissingRegistryWitness);
    try before.expectUnchanged(&fixture);
    try fixture.expectNoRequests(counts);
    try fixture.expectInstalled(true);
    // The retained installation remains authoritative after refusal.
    // A matching request must still execute genuine removal/restoration.
    var reply = try rpc(fixture.engine, .control, "integrations.remove", .{ .adapter = "codex", .config_path = fixture.config, .native_socket = fixture.endpoint.endpoint });
    defer reply.deinit();
    try std.testing.expect(try control.boolean(try reply.result(), "removed", false));
    try std.testing.expect(std.mem.eql(u8, fixture.config, try control.string(try reply.result(), "config_path")));
    try fixture.expectNoRequests(counts);
    const after = try Files.capture(&fixture);
    defer after.deinit();
    // Removal retains the encrypted, authenticated retired registry witness;
    // deleting it would discard the installation's generation history.
    try std.testing.expect(after.config != null and after.capability == null and after.registry != null);
    const retired_registry = fixture.engine.native_registry orelse return error.MissingRegistryWitness;
    try std.testing.expectEqual(setup.RegistryPhase.removed, retired_registry.phase);
    try std.testing.expect(std.mem.eql(u8, &original_registry.transaction, &retired_registry.transaction));
    try std.testing.expect(std.mem.eql(u8, &original_registry.capability_digest, &retired_registry.capability_digest));
    try std.testing.expect(std.mem.eql(u8, "# synthetic original native configuration\n", after.config.?));
    try std.testing.expect((try Files.read(fixture.requested_config, setup.maximum_config)) == null);
    try fixture.expectInstalled(false);
}

test "real engine bounded V2 discovery refuses oversized packets before owner registration" {
    var fixture = try Fixture.create(true, false);
    defer fixture.deinit();
    const before = try Files.capture(&fixture);
    defer before.deinit();
    fixture.endpoint.setMethodMode(.threads, .threads_oversized_packet);
    var reply = try rpc(fixture.engine, .control, "integrations.discover", .{ .adapter = "codex", .native_socket = fixture.endpoint.endpoint });
    defer reply.deinit();
    try reply.expectError("PeerMessageTruncated");
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoint.methodCount(.threads));
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoint.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoint.methodCount(.announce));
    try before.expectUnchanged(&fixture);
    try fixture.expectInstalled(true);
    // V2 attach names one bounded thread; oversized labels cannot advance even
    // to identify. This replaces the historical escaped WebSocket list seam.
    const oversized_thread: [257]u8 = @splat('"');
    const counts = fixture.counts();
    var attach = try rpc(fixture.engine, .control, "integrations.attach", .{ .adapter = "codex", .native_socket = fixture.endpoint.endpoint, .thread_id = oversized_thread[0..] });
    defer attach.deinit();
    try attach.expectError("InvalidNativeOwnerThread");
    try fixture.expectNoRequests(counts);
    try before.expectUnchanged(&fixture);
}

test "real engine insufficient whole snapshot space refuses native install remove and attach before effects" {
    for ([_][]const u8{ "integrations.install", "integrations.remove", "integrations.attach" }) |method| {
        const installed = !std.mem.eql(u8, method, "integrations.install");
        var fixture = try Fixture.create(installed, false);
        defer fixture.deinit();
        try fixture.saturate();
        const before = try Files.capture(&fixture);
        defer before.deinit();
        const counts = fixture.counts();
        var reply = try rpc(fixture.engine, .control, method, .{ .adapter = "codex", .config_path = fixture.requested_config, .native_socket = fixture.endpoint.endpoint, .thread_id = "fixture-thread" });
        defer reply.deinit();
        try reply.expectError("SnapshotTooLarge");
        try fixture.expectNoRequests(counts);
        try before.expectUnchanged(&fixture);
        try fixture.expectInstalled(installed);
    }
}
