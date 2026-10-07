//! Native attribution never creates a new work namespace or replay budget.
//! Ledger cases prove persisted predicates; actual actor/peer cases below must
//! separately establish current writer authority. No provider calls are used.
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const file_metadata = @import("platform/file_metadata.zig");
const authority = @import("request_authority.zig");
const native_owner = @import("native_owner.zig");
const engine_module = @import("engine.zig");
const native_fixture = @import("native_owner_fixture.zig");
const control = @import("control.zig");

const allocator = std.testing.allocator;
const handle_a: [64]u8 = @splat('a');
const handle_b: [64]u8 = @splat('b');
const handle_c: [64]u8 = @splat('c');
const fingerprint: [64]u8 = @splat('1');
const original: native_owner.NativeRef = .{
    .owner_id = @splat(71),
    .adapter_epoch = 1,
    .endpoint_generation = 1,
    .thread_instance_generation = 1,
    .attachment_generation = 1,
};
const intent: authority.Intent = .{
    .key = .{ .application = "codex", .session_id = "same-native-thread", .request_id = "same-work-uuid" },
    .binding_id = "native-binding",
    .demand_fingerprint = &fingerprint,
    .native_ref = original,
};
const rejection: authority.Report = .{ .event = .rejected, .pre_acceptance = true, .response_started = false, .status = 429 };

fn foreign(index: usize) native_owner.NativeRef {
    var changed = original;
    switch (index) {
        0 => changed.owner_id[0] += 1,
        1 => changed.adapter_epoch += 1,
        2 => changed.endpoint_generation += 1,
        3 => changed.thread_instance_generation += 1,
        4 => changed.attachment_generation += 1,
        else => unreachable,
    }
    return changed;
}

test "owner substitution cannot consume a safe alternate or reset the original two attempts" {
    var ledger = authority.Ledger.init(allocator, 8);
    defer ledger.deinit();
    _ = try ledger.issue(intent, &handle_a, "fixture-account-a", 1);
    try std.testing.expect(try ledger.reportForOwner("codex", &handle_a, original, rejection));
    const reserved = ledger.reservedSnapshotBytes();
    for (0..5) |index| {
        var substituted = intent;
        substituted.native_ref = foreign(index);
        try std.testing.expectError(error.NativeOwnerMismatch, ledger.checkIssue(substituted));
        try std.testing.expectError(error.NativeOwnerMismatch, ledger.rejectedAccount(substituted));
        try std.testing.expectError(error.NativeOwnerMismatch, ledger.issue(substituted, &handle_b, "fixture-account-b", 2));
        try std.testing.expectError(error.NativeOwnerMismatch, ledger.checkReportForOwner("codex", &handle_a, substituted.native_ref.?, rejection));
        try std.testing.expectError(error.NativeOwnerMismatch, ledger.reportForOwner("codex", &handle_a, substituted.native_ref.?, rejection));
    }
    try std.testing.expectEqual(@as(usize, 1), ledger.records.items.len);
    try std.testing.expect(ledger.records.items[0].alternate == null);
    try std.testing.expectEqual(reserved, ledger.reservedSnapshotBytes());
    try std.testing.expectEqual(@as(u8, 2), try ledger.issue(intent, &handle_b, "fixture-account-b", 2));
    _ = try ledger.reportForOwner("codex", &handle_b, original, rejection);
    try std.testing.expectError(error.AttemptBudgetExhausted, ledger.issue(intent, &handle_c, "fixture-account-c", 3));
    var substituted = intent;
    substituted.native_ref = foreign(0);
    // Mismatch wins even after both attempts have reached terminal rejection.
    try std.testing.expectError(error.NativeOwnerMismatch, ledger.checkIssue(substituted));
}

test "accepted restart completion retains exact attribution before terminal and duplicate shortcuts" {
    var ledger = authority.Ledger.init(allocator, 2);
    defer ledger.deinit();
    _ = try ledger.issue(intent, &handle_a, "fixture-account-a", 1);
    _ = try ledger.reportForOwner("codex", &handle_a, original, .{ .event = .accepted });
    const json = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(authority.Snapshot, allocator, json, .{});
    defer parsed.deinit();
    var restored = try authority.Ledger.fromSnapshot(allocator, 2, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectEqual(authority.Status.unknown, restored.attempt("codex", &handle_a).?.state);
    try std.testing.expect(restored.intentForHandle("codex", &handle_a).?.native_ref.?.same(original));
    try std.testing.expect(restored.intentForHandle("another-app", &handle_a) == null);
    for (0..5) |index| {
        try std.testing.expectError(error.NativeOwnerMismatch, restored.checkReportForOwner("codex", &handle_a, foreign(index), .{ .event = .accepted }));
        try std.testing.expectError(error.NativeOwnerMismatch, restored.reportForOwner("codex", &handle_a, foreign(index), .{ .event = .completed }));
    }
    try std.testing.expectError(error.NativeOwnerMismatch, restored.checkReport("codex", &handle_a, .{ .event = .accepted }));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.report(&handle_a, .{ .event = .completed }));
    try std.testing.expect(try restored.reportForOwner("codex", &handle_a, original, .{ .event = .completed }));
    try std.testing.expect(!(try restored.checkReportForOwner("codex", &handle_a, original, .{ .event = .accepted })));
    try std.testing.expect(!(try restored.reportForOwner("codex", &handle_a, original, .{ .event = .completed })));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.checkReportForOwner("codex", &handle_a, foreign(0), .{ .event = .completed }));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.reportForOwner("codex", &handle_a, foreign(0), .{ .event = .accepted }));
    try std.testing.expectError(error.AttemptBudgetExhausted, restored.checkIssue(intent));
}

test "legacy ownerless fences cannot acquire new native attribution or grant report authority" {
    var legacy = intent;
    legacy.native_ref = null;
    var ledger = authority.Ledger.init(allocator, 1);
    defer ledger.deinit();
    _ = try ledger.issue(legacy, &handle_a, "fixture-account-a", 1);
    _ = try ledger.report(&handle_a, rejection);
    var restored = try authority.Ledger.fromSnapshot(allocator, 1, ledger.snapshot());
    defer restored.deinit();
    restored.recoverAfterRestart();
    try std.testing.expectError(error.NativeOwnerMismatch, restored.checkIssue(intent));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.issue(intent, &handle_b, "fixture-account-b", 2));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.checkReportForOwner("codex", &handle_a, original, rejection));
    try std.testing.expectError(error.NativeOwnerMismatch, restored.reportForOwner("codex", &handle_a, original, rejection));
    try std.testing.expectEqual(@as(usize, 1), restored.records.items.len);
    try std.testing.expect(restored.records.items[0].intent.native_ref == null);
}

test "opaque owner bytes and full u64 generations fit immutable request reservations on restore" {
    var wide = intent;
    wide.native_ref = .{
        .owner_id = @splat(255),
        .adapter_epoch = std.math.maxInt(u64),
        .endpoint_generation = std.math.maxInt(u64),
        .thread_instance_generation = std.math.maxInt(u64),
        .attachment_generation = std.math.maxInt(u64),
    };
    var ledger = authority.Ledger.init(allocator, 1);
    defer ledger.deinit();
    _ = try ledger.issue(wide, &handle_a, "fixture-account-a", std.math.minInt(i64));
    _ = try ledger.reportForOwner("codex", &handle_a, wide.native_ref.?, .{ .event = .accepted, .status = std.math.maxInt(u16) });
    _ = try ledger.reportForOwner("codex", &handle_a, wide.native_ref.?, .{ .event = .completed, .status = std.math.maxInt(u16) });
    const json = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(json);
    try std.testing.expect(json.len <= ledger.reservedSnapshotBytes());
    const parsed = try std.json.parseFromSlice(authority.Snapshot, allocator, json, .{});
    defer parsed.deinit();
    var restored = try authority.Ledger.fromSnapshot(allocator, 1, parsed.value);
    defer restored.deinit();
    try std.testing.expectEqual(ledger.reservedSnapshotBytes(), restored.reservedSnapshotBytes());
    try std.testing.expect(restored.intentForHandle("codex", &handle_a).?.native_ref.?.same(wide.native_ref.?));
    try std.testing.expect(!(try restored.reportForOwner("codex", &handle_a, wide.native_ref.?, .{ .event = .completed, .status = std.math.maxInt(u16) })));
}

const io = std.testing.io;
const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    method: []const u8,

    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
    fn result(self: *const Reply) !std.json.Value {
        if (control.get(self.parsed.value, "result")) |value| return value;
        if (control.get(self.parsed.value, "error")) |failure| {
            const name = control.string(failure, "message") catch "InvalidRpcError";
            var canonical = name.len <= 128;
            for (name) |byte| {
                if (!std.ascii.isAlphanumeric(byte) and byte != '_') canonical = false;
            }
            std.debug.print("native owner RPC {s} failed: {s}\n", .{ self.method, if (canonical) name else "NoncanonicalRpcError" });
        }
        return error.UnexpectedRpcFailure;
    }
    fn expectError(self: *const Reply, name: []const u8) !void {
        try self.expectFailure();
        const failure = control.get(self.parsed.value, "error").?;
        try std.testing.expectEqualStrings(name, try control.string(failure, "message"));
    }
    fn expectFailure(self: *const Reply) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        try std.testing.expect(control.get(self.parsed.value, "error") != null);
    }
};

fn randomHex() ![64]u8 {
    var bytes: [32]u8 = undefined;
    try io.randomSecure(&bytes);
    defer std.crypto.secureZero(u8, &bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn rpc(engine: *engine_module.Engine, owner: ?*native_fixture.Fixture, channel: engine_module.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const initial = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = normalized }, .{});
    defer {
        std.crypto.secureZero(u8, initial);
        allocator.free(initial);
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, initial, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(parsed.value);
        parsed.deinit();
    }
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const target = parsed.value.object.getPtr("params").?;
        if (target.* == .null) target.* = .{ .object = .empty };
        const arena = parsed.arena.allocator();
        if (!target.object.contains("operation_id")) {
            const operation = try randomHex();
            try target.object.put(arena, try arena.dupe(u8, "operation_id"), .{ .string = try arena.dupe(u8, &operation) });
        }
        if (!target.object.contains("expected_revision")) {
            var health = try rpc(engine, null, .control, "system.health", .{});
            defer health.deinit();
            const current_revision = control.get(try health.result(), "revision") orelse return error.InvalidReply;
            try target.object.put(arena, try arena.dupe(u8, "expected_revision"), current_revision);
        }
    }
    const payload = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    }
    // The shared fixture sends this exact payload through its real private
    // seqpacket pair and authenticates the received packet before dispatch.
    const bytes = if (owner) |held| try held.dispatch(engine, allocator, payload, channel) else try engine.dispatch(allocator, payload, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }), .method = method };
}

const WireRef = struct {
    owner_id: [64]u8,
    adapter_epoch: []u8,
    endpoint_generation: []u8,
    thread_instance_generation: []u8,
    attachment_generation: []u8,

    fn init(ref: native_owner.NativeRef) !WireRef {
        const epoch = try std.fmt.allocPrint(allocator, "{d}", .{ref.adapter_epoch});
        errdefer allocator.free(epoch);
        const endpoint = try std.fmt.allocPrint(allocator, "{d}", .{ref.endpoint_generation});
        errdefer allocator.free(endpoint);
        const thread = try std.fmt.allocPrint(allocator, "{d}", .{ref.thread_instance_generation});
        errdefer allocator.free(thread);
        return .{
            .owner_id = std.fmt.bytesToHex(ref.owner_id, .lower),
            .adapter_epoch = epoch,
            .endpoint_generation = endpoint,
            .thread_instance_generation = thread,
            .attachment_generation = try std.fmt.allocPrint(allocator, "{d}", .{ref.attachment_generation}),
        };
    }
    fn deinit(self: *WireRef) void {
        allocator.free(self.adapter_epoch);
        allocator.free(self.endpoint_generation);
        allocator.free(self.thread_instance_generation);
        allocator.free(self.attachment_generation);
    }
};

const PrivateDirectory = struct {
    dir: std.Io.Dir,
    path: [:0]u8,

    fn cleanup(self: *PrivateDirectory) void {
        const current_fd = paths.openPrivateRoot(allocator, self.path, false) catch @panic("Fixture root custody changed");
        defer _ = std.c.close(current_fd);
        const original_identity = file_metadata.statFd(self.dir.handle) catch @panic("Fixture root identity unavailable");
        const current_identity = file_metadata.statFd(current_fd) catch @panic("Fixture root identity unavailable");
        if (original_identity.dev != current_identity.dev or original_identity.ino != current_identity.ino) @panic("Fixture root identity changed");
        std.Io.Dir.cwd().deleteTree(io, self.path) catch @panic("Fixture root cleanup failed");
        self.dir.close(io);
        allocator.free(self.path);
        self.* = undefined;
    }
};

fn privateDirectory() !PrivateDirectory {
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const root = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-request-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) }, 0);
    errdefer allocator.free(root);
    if (std.c.mkdir(root.ptr, 0o700) != 0) return error.FixtureDirectoryCreationFailed;
    errdefer _ = std.c.rmdir(root.ptr);
    const fd = try paths.openPrivateRoot(allocator, root, false);
    return .{ .dir = .{ .handle = fd }, .path = root };
}

const Actor = struct {
    directory: PrivateDirectory,
    path: [:0]u8,
    engine: ?*engine_module.Engine,
    const key: [32]u8 = @splat(93);

    fn init() !Actor {
        var directory = try privateDirectory();
        errdefer directory.cleanup();
        // The exclusive root is already absolute and alias-checked. Preserve
        // its real short path; no alternate runtime path or socket bypass.
        const path = try allocator.dupeSentinel(u8, directory.path, 0);
        errdefer allocator.free(path);
        return .{ .directory = directory, .path = path, .engine = try engine_module.Engine.openWithKey(io, allocator, path, key) };
    }
    fn restart(self: *Actor) !void {
        const engine = self.engine orelse return error.FixtureEngineUnavailable;
        self.engine = null;
        engine.deinit();
        self.engine = try engine_module.Engine.openWithKey(io, allocator, self.path, key);
    }
    fn deinit(self: *Actor) void {
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
        allocator.free(self.path);
        self.directory.cleanup();
    }
    fn enroll(self: *Actor, token: []const u8) !void {
        return enrollActor(self.engine.?, token);
    }
};

fn enrollActor(engine: *engine_module.Engine, token: []const u8) !void {
    var connected = try rpc(engine, null, .control, "source.connect", .{ .kind = "explicit", .provider = "codex", .label = "native owner request fixture" });
    defer connected.deinit();
    const source = try control.string(try connected.result(), "source_id");
    const subject = try randomHex();
    const capability = try engine.capabilityForTest("enrollment");
    var enrolled = try rpc(engine, null, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = &capability,
        .source_id = source,
        .provider = "codex",
        .subject = &subject,
        .access_token = token,
        .audience = "https://chatgpt.com",
    });
    defer enrolled.deinit();
    _ = try enrolled.result();
}

const Acquisition = struct {
    handle: []u8,
    account: []u8,
    fn deinit(self: *Acquisition) void {
        allocator.free(self.handle);
        allocator.free(self.account);
    }
};

fn acquireRpc(engine: *engine_module.Engine, owner: *native_fixture.Fixture, ref: native_owner.NativeRef, request_id: []const u8) !Reply {
    const capability = try engine.capabilityForTest("codex");
    var wire = try WireRef.init(ref);
    defer wire.deinit();
    return rpc(engine, owner, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = &capability,
        .native_ref = wire,
        .session_id = "same-native-thread",
        .request_id = request_id,
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .purpose = "request", .required = 1, .resource = .{ .kind = "model", .target = "fixture-model", .unit = "tokens" } },
    });
}

fn acquireActor(engine: *engine_module.Engine, owner: *native_fixture.Fixture, ref: native_owner.NativeRef, request_id: []const u8) !Acquisition {
    var reply = try acquireRpc(engine, owner, ref, request_id);
    defer reply.deinit();
    const result = try reply.result();
    const handle = try allocator.dupe(u8, try control.string(result, "lease_handle"));
    errdefer allocator.free(handle);
    return .{ .handle = handle, .account = try allocator.dupe(u8, try control.string(result, "account_id")) };
}

fn reportRpc(engine: *engine_module.Engine, owner: *native_fixture.Fixture, ref: native_owner.NativeRef, handle: []const u8, event: []const u8) !Reply {
    const capability = try engine.capabilityForTest("codex");
    var wire = try WireRef.init(ref);
    defer wire.deinit();
    return rpc(engine, owner, .adapter, "adapter.report", .{
        .application = "codex",
        .capability = &capability,
        .native_ref = wire,
        .lease_handle = handle,
        .event = event,
        .pre_acceptance = std.mem.eql(u8, event, "rejected"),
        .response_started = !std.mem.eql(u8, event, "rejected"),
        .status = @as(u16, if (std.mem.eql(u8, event, "rejected")) 429 else 0),
    });
}

fn reportActor(engine: *engine_module.Engine, owner: *native_fixture.Fixture, ref: native_owner.NativeRef, handle: []const u8, event: []const u8) !void {
    var reply = try reportRpc(engine, owner, ref, handle, event);
    defer reply.deinit();
    _ = try reply.result();
}

const Stored = struct { revision: i64, sha256: [64]u8 };
fn stored(engine: *engine_module.Engine) !Stored {
    const capability = try engine.capabilityForTest("enrollment");
    const no_grants = [_]struct { account_id: []const u8, grant_id: []const u8 }{};
    var reply = try rpc(engine, null, .adapter, "fixture.snapshotStored", .{ .application = "enrollment", .capability = &capability, .grants = no_grants });
    defer reply.deinit();
    const result = try reply.result();
    const digest = try control.string(result, "snapshot_sha256");
    if (digest.len != 64) return error.InvalidReply;
    var value: Stored = .{ .revision = control.get(result, "revision").?.integer, .sha256 = undefined };
    @memcpy(&value.sha256, digest);
    return value;
}

const QualifiedSelection = struct {
    owner_id: [32]u8,
    nonce: [32]u8,
    endpoint_generation: u64,
    thread_generation: u64,

    fn producer(value: *const native_fixture.Fixture) QualifiedSelection {
        return .{ .owner_id = value.owner_id, .nonce = value.native_nonce, .endpoint_generation = value.options.endpoint_generation, .thread_generation = value.options.thread_instance_generation };
    }
};

fn qualifiedAttach(actor: *native_fixture.ActorFixture, producer: *native_fixture.Fixture, selection: QualifiedSelection, operation: [64]u8) !Reply {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const owner_hex = std.fmt.bytesToHex(selection.owner_id, .lower);
    const nonce_hex = std.fmt.bytesToHex(selection.nonce, .lower);
    return rpc(actor.engine.?, null, .control, "integrations.attach", .{
        .adapter = "codex",
        .operation_id = operation[0..],
        .owner_endpoint = producer.endpoint,
        .owner_id = owner_hex[0..],
        .process_nonce = nonce_hex[0..],
        .endpoint_generation = try std.fmt.allocPrint(a, "{d}", .{selection.endpoint_generation}),
        .thread_id = "qualified-native-thread",
        .thread_instance_generation = try std.fmt.allocPrint(a, "{d}", .{selection.thread_generation}),
    });
}

const QualifiedCustody = struct {
    saved: Stored,
    seal_sha256: [32]u8,
    register_count: usize,
    unregister_count: usize,
    announce_count: usize,

    fn read(actor: *native_fixture.ActorFixture) !QualifiedCustody {
        const seal_path = try std.fmt.allocPrint(allocator, "{s}/state.sqlite.authority", .{actor.state});
        defer allocator.free(seal_path);
        const seal = try std.Io.Dir.cwd().readFileAlloc(io, seal_path, allocator, .limited(1024));
        defer {
            std.crypto.secureZero(u8, seal);
            allocator.free(seal);
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(seal, &digest, .{});
        return .{ .saved = try stored(actor.engine.?), .seal_sha256 = digest, .register_count = actor.producer.methodCount(.register), .unregister_count = actor.producer.methodCount(.unregister), .announce_count = actor.producer.methodCount(.announce) };
    }

    fn expectSame(self: QualifiedCustody, actual: QualifiedCustody) !void {
        try std.testing.expectEqual(self.saved.revision, actual.saved.revision);
        try std.testing.expectEqualSlices(u8, &self.saved.sha256, &actual.saved.sha256);
        try std.testing.expectEqualSlices(u8, &self.seal_sha256, &actual.seal_sha256);
        try std.testing.expectEqual(self.register_count, actual.register_count);
        try std.testing.expectEqual(self.unregister_count, actual.unregister_count);
        try std.testing.expectEqual(self.announce_count, actual.announce_count);
    }
};

test "qualified attach verifies installed inventory context and exact producer before admitting any mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    const outside = try native_fixture.Fixture.create(io, allocator);
    defer outside.destroy();
    outside.setAnnouncementEngine(actor.engine.?);
    const original_selection = QualifiedSelection.producer(producer);
    const before = try QualifiedCustody.read(actor);
    for (0..4) |variant| {
        var changed = original_selection;
        switch (variant) {
            // Preserve the publication prefix, so actual identify must reject
            // this wrong complete owner ID rather than its pathname alone.
            0 => changed.owner_id[31] ^= 1,
            1 => changed.nonce[31] ^= 1,
            2 => changed.endpoint_generation += 1,
            3 => changed.thread_generation += 1,
            else => unreachable,
        }
        const identify_before = producer.methodCount(.identify);
        var refused = try qualifiedAttach(actor, producer, changed, try randomHex());
        defer refused.deinit();
        try refused.expectError("NativeOwnerMismatch");
        try std.testing.expectEqual(identify_before + 1, producer.methodCount(.identify));
        try before.expectSame(try QualifiedCustody.read(actor));
    }
    var out_of_context = try qualifiedAttach(actor, outside, QualifiedSelection.producer(outside), try randomHex());
    defer out_of_context.deinit();
    try out_of_context.expectError("NativeEndpointOutsideContext");
    try std.testing.expectEqual(@as(usize, 0), outside.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 0), outside.methodCount(.announce));
    try std.testing.expectEqual(@as(usize, 0), outside.methodCount(.register));
    try before.expectSame(try QualifiedCustody.read(actor));

    const operation = try randomHex();
    var attached = try qualifiedAttach(actor, producer, original_selection, operation);
    defer attached.deinit();
    const result = try attached.result();
    try std.testing.expect(try control.boolean(result, "registered", false));
    try std.testing.expectEqualStrings(&operation, try control.string(result, "operation_id"));
    const wire = control.get(result, "native_ref") orelse return error.InvalidReply;
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(producer.owner_id, .lower), try control.string(wire, "owner_id"));
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.announce));
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 1), actor.engine.?.native_owners.attachments.items.len);
    const row = actor.engine.?.native_owners.attachments.items[0];
    try std.testing.expectEqual(native_owner.AttachmentPhase.attached, row.phase);
    try std.testing.expectEqualStrings("qualified-native-thread", row.thread_id);
    try std.testing.expectEqualSlices(u8, &operation, &row.registration_operation);
    try std.testing.expectEqual(original_selection.endpoint_generation, row.reference.endpoint_generation);
    try std.testing.expectEqual(original_selection.thread_generation, row.reference.thread_instance_generation);
    const after = try QualifiedCustody.read(actor);
    try std.testing.expect(after.saved.revision > before.saved.revision);
    try std.testing.expect(!std.mem.eql(u8, &before.saved.sha256, &after.saved.sha256));
    try std.testing.expect(!std.mem.eql(u8, &before.seal_sha256, &after.seal_sha256));
    try std.testing.expect(producer.failure() == null);
    try std.testing.expect(outside.failure() == null);
}

test "actual actor accepted restart reports require original owner before duplicate and terminal fallbacks" {
    var actor = try Actor.init();
    defer actor.deinit();
    var token = try randomHex();
    defer std.crypto.secureZero(u8, &token);
    try actor.enroll(&token);
    const owner_a = try native_fixture.Fixture.create(io, allocator);
    defer owner_a.destroy();
    const owner_b = try native_fixture.Fixture.create(io, allocator);
    defer owner_b.destroy();
    const ref_a = try owner_a.register(actor.engine.?, "same-native-thread");
    const ref_b = try owner_b.register(actor.engine.?, "same-native-thread");
    try std.testing.expect(!ref_a.same(ref_b));
    var accepted = try acquireActor(actor.engine.?, owner_a, ref_a, "accepted-owner-work");
    defer accepted.deinit();
    const capability = try actor.engine.?.capabilityForTest("codex");
    var wire = try WireRef.init(ref_a);
    defer wire.deinit();
    const materialize = .{ .application = "codex", .capability = &capability, .native_ref = wire, .lease_handle = accepted.handle };
    var positive = try rpc(actor.engine.?, owner_a, .adapter, "adapter.materialize", materialize);
    defer positive.deinit();
    try std.testing.expect(std.mem.eql(u8, &token, try control.string(try positive.result(), "access_token")));
    const before_no_peer = try stored(actor.engine.?);
    var no_peer = try rpc(actor.engine.?, null, .adapter, "adapter.materialize", materialize);
    defer no_peer.deinit();
    try no_peer.expectError("NativePeerRequired");
    try std.testing.expectEqualDeep(before_no_peer, try stored(actor.engine.?));
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "accepted");
    try actor.restart();
    const before = try stored(actor.engine.?);
    var foreign_duplicate = try reportRpc(actor.engine.?, owner_b, ref_b, accepted.handle, "accepted");
    defer foreign_duplicate.deinit();
    try foreign_duplicate.expectError("NativeOwnerMismatch");
    var foreign_terminal = try reportRpc(actor.engine.?, owner_b, ref_b, accepted.handle, "completed");
    defer foreign_terminal.deinit();
    try foreign_terminal.expectError("NativeOwnerMismatch");
    try std.testing.expectEqualDeep(before, try stored(actor.engine.?));
    // No registration, new acquire or replay is used to restore report custody.
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "completed");
    const completed = try stored(actor.engine.?);
    try std.testing.expect(completed.revision > before.revision);
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "accepted");
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "completed");
    try std.testing.expectEqualDeep(completed, try stored(actor.engine.?));
    var wrong_completed = try reportRpc(actor.engine.?, owner_b, ref_b, accepted.handle, "completed");
    defer wrong_completed.deinit();
    try wrong_completed.expectError("NativeOwnerMismatch");
    var no_replay = try acquireRpc(actor.engine.?, owner_a, ref_a, "accepted-owner-work");
    defer no_replay.deinit();
    try no_replay.expectFailure();
    try std.testing.expectEqualDeep(completed, try stored(actor.engine.?));
}

test "actual actor owner changes cannot rekey rejected work or receive a third attempt" {
    var actor = try Actor.init();
    defer actor.deinit();
    var token_a = try randomHex();
    defer std.crypto.secureZero(u8, &token_a);
    var token_b = try randomHex();
    defer std.crypto.secureZero(u8, &token_b);
    try actor.enroll(&token_a);
    try actor.enroll(&token_b);
    const owner_a = try native_fixture.Fixture.create(io, allocator);
    defer owner_a.destroy();
    const owner_b = try native_fixture.Fixture.create(io, allocator);
    defer owner_b.destroy();
    const ref_a = try owner_a.register(actor.engine.?, "same-native-thread");
    const ref_b = try owner_b.register(actor.engine.?, "same-native-thread");
    var first = try acquireActor(actor.engine.?, owner_a, ref_a, "rejected-owner-work");
    defer first.deinit();
    try reportActor(actor.engine.?, owner_a, ref_a, first.handle, "rejected");
    const rejected = try stored(actor.engine.?);
    var alternate_owner = try acquireRpc(actor.engine.?, owner_b, ref_b, "rejected-owner-work");
    defer alternate_owner.deinit();
    try alternate_owner.expectError("NativeOwnerMismatch");
    var foreign_ack = try reportRpc(actor.engine.?, owner_b, ref_b, first.handle, "rejected");
    defer foreign_ack.deinit();
    try foreign_ack.expectError("NativeOwnerMismatch");
    try std.testing.expectEqualDeep(rejected, try stored(actor.engine.?));
    var second = try acquireActor(actor.engine.?, owner_a, ref_a, "rejected-owner-work");
    defer second.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.account, second.account));
    try reportActor(actor.engine.?, owner_a, ref_a, second.handle, "accepted");
    try reportActor(actor.engine.?, owner_a, ref_a, second.handle, "completed");
    const completed = try stored(actor.engine.?);
    var third = try acquireRpc(actor.engine.?, owner_a, ref_a, "rejected-owner-work");
    defer third.deinit();
    try third.expectError("AttemptBudgetExhausted");
    var third_owner = try acquireRpc(actor.engine.?, owner_b, ref_b, "rejected-owner-work");
    defer third_owner.deinit();
    try third_owner.expectError("NativeOwnerMismatch");
    try std.testing.expectEqualDeep(completed, try stored(actor.engine.?));
}

test "actual removal closes new work while original owner retains accepted terminal report custody" {
    const owner_a = try native_fixture.Fixture.create(io, allocator);
    defer owner_a.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, owner_a);
    defer actor.destroy();
    try actor.install();
    var token = try randomHex();
    defer std.crypto.secureZero(u8, &token);
    try enrollActor(actor.engine.?, &token);
    const owner_b = try native_fixture.Fixture.create(io, allocator);
    defer owner_b.destroy();
    const ref_a = try owner_a.register(actor.engine.?, "same-native-thread");
    const ref_b = try owner_b.register(actor.engine.?, "same-native-thread");
    var accepted = try acquireActor(actor.engine.?, owner_a, ref_a, "closing-owner-work");
    defer accepted.deinit();
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "accepted");
    const capability_before = try actor.engine.?.capabilityForTest("codex");
    const config_before = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(1024 * 1024));
    defer allocator.free(config_before);
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
    defer allocator.free(capability_path);
    const capability_file_before = try std.Io.Dir.cwd().readFileAlloc(io, capability_path, allocator, .limited(1024));
    defer {
        std.crypto.secureZero(u8, capability_file_before);
        allocator.free(capability_file_before);
    }
    const before_removal = try stored(actor.engine.?);
    var removal = try rpc(actor.engine.?, null, .control, "integrations.remove", .{ .adapter = "codex", .config_path = actor.config, .native_socket = owner_a.endpoint });
    defer removal.deinit();
    const pending = try removal.result();
    try std.testing.expect(!try control.boolean(pending, "removed", true));
    try std.testing.expect(try control.boolean(pending, "installed", false));
    try std.testing.expect(try control.boolean(pending, "pending_safe_detach", false));
    try std.testing.expectEqualStrings("NativeRequestsPending", try control.string(pending, "reason"));
    const closing = try stored(actor.engine.?);
    try std.testing.expect(closing.revision > before_removal.revision);
    try std.testing.expectEqual(@as(usize, 0), owner_a.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 0), owner_b.methodCount(.unregister));
    const capability_closing = try actor.engine.?.capabilityForTest("codex");
    try std.testing.expect(std.mem.eql(u8, &capability_before, &capability_closing));
    var fresh = try acquireRpc(actor.engine.?, owner_a, ref_a, "new-work-after-closing");
    defer fresh.deinit();
    try fresh.expectError("NativeRemovalPending");
    var foreign_terminal = try reportRpc(actor.engine.?, owner_b, ref_b, accepted.handle, "completed");
    defer foreign_terminal.deinit();
    try foreign_terminal.expectError("NativeOwnerMismatch");
    var wire = try WireRef.init(ref_a);
    defer wire.deinit();
    const report_params = .{ .application = "codex", .capability = &capability_before, .native_ref = wire, .lease_handle = accepted.handle, .event = "completed" };
    var no_peer = try rpc(actor.engine.?, null, .adapter, "adapter.report", report_params);
    defer no_peer.deinit();
    try no_peer.expectError("NativePeerRequired");
    try std.testing.expectEqualDeep(closing, try stored(actor.engine.?));
    // The same complete request succeeds with its authenticated original owner
    // even though removal has fenced new work and retained the configuration.
    var terminal = try rpc(actor.engine.?, owner_a, .adapter, "adapter.report", report_params);
    defer terminal.deinit();
    _ = try terminal.result();
    const completed = try stored(actor.engine.?);
    try std.testing.expect(completed.revision > closing.revision);
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "accepted");
    try reportActor(actor.engine.?, owner_a, ref_a, accepted.handle, "completed");
    var replay = try acquireRpc(actor.engine.?, owner_a, ref_a, "closing-owner-work");
    defer replay.deinit();
    try replay.expectError("NativeRemovalPending");
    try std.testing.expectEqualDeep(completed, try stored(actor.engine.?));
    const config_after = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(1024 * 1024));
    defer allocator.free(config_after);
    try std.testing.expect(std.mem.eql(u8, config_before, config_after));
    const capability_file_after = try std.Io.Dir.cwd().readFileAlloc(io, capability_path, allocator, .limited(1024));
    defer {
        std.crypto.secureZero(u8, capability_file_after);
        allocator.free(capability_file_after);
    }
    try std.testing.expect(std.mem.eql(u8, capability_file_before, capability_file_after));
    const capability_after = try actor.engine.?.capabilityForTest("codex");
    try std.testing.expect(std.mem.eql(u8, &capability_before, &capability_after));
    try std.testing.expectEqual(@as(usize, 0), owner_a.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 0), owner_b.methodCount(.unregister));
    try std.testing.expect(owner_a.failure() == null);
    try std.testing.expect(owner_b.failure() == null);
}
