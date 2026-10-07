//! R-N13: actual actor removal fences for genuine, never-acquired owners.
//! Synthetic native producers use real Linux packet/peer evidence and private
//! reversible configuration; these cases do not prove live native continuity.
const std = @import("std");
const builtin = @import("builtin");
const engine_module = @import("engine.zig");
const native_fixture = @import("native_owner_fixture.zig");
const native_owner = @import("native_owner.zig");
const control = @import("control.zig");
const setup = @import("integrations/setup.zig");
const snapshot_admission = @import("snapshot_admission.zig");
const allocator = std.testing.allocator;
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
            std.debug.print("native removal RPC {s} failed: {s}\n", .{ self.method, if (canonical) name else "NoncanonicalRpcError" });
        }
        return error.UnexpectedRpcFailure;
    }
    fn expectFailure(self: *const Reply) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        try std.testing.expect(control.get(self.parsed.value, "error") != null);
    }
    fn expectError(self: *const Reply, name: []const u8) !void {
        try self.expectFailure();
        try std.testing.expectEqualStrings(name, try control.string(control.get(self.parsed.value, "error").?, "message"));
    }
};

fn randomHex() !native_owner.OperationId {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    return std.fmt.bytesToHex(random, .lower);
}

fn rpc(engine: *engine_module.Engine, method: []const u8, params: anytype) anyerror!Reply {
    return rpcChannel(engine, null, .control, method, params);
}

fn rpcChannel(engine: *engine_module.Engine, owner: ?*native_fixture.Fixture, channel: engine_module.Channel, method: []const u8, params: anytype) anyerror!Reply {
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
        const params_value = parsed.value.object.getPtr("params").?;
        if (params_value.* == .null) params_value.* = .{ .object = .empty };
        const arena = parsed.arena.allocator();
        if (!params_value.object.contains("operation_id")) {
            const operation = try randomHex();
            try params_value.object.put(arena, try arena.dupe(u8, "operation_id"), .{ .string = try arena.dupe(u8, &operation) });
        }
        if (!params_value.object.contains("expected_revision")) {
            var health = try rpc(engine, "system.health", .{});
            defer health.deinit();
            const revision = control.get(try health.result(), "revision") orelse return error.InvalidReply;
            try params_value.object.put(arena, try arena.dupe(u8, "expected_revision"), revision);
        }
    }
    const payload = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    }
    const bytes = if (owner) |producer| try producer.dispatch(engine, allocator, payload, channel) else try engine.dispatch(allocator, payload, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }), .method = method };
}

const Saved = struct {
    config: []u8,
    capability: []u8,
    registry: []u8,

    fn read(path: []const u8, maximum: usize) ![]u8 {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(try std.math.add(usize, maximum, 1)));
        errdefer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        if (bytes.len > maximum) return error.FixtureFileTooLarge;
        return bytes;
    }
    fn capture(actor: *const native_fixture.ActorFixture) !Saved {
        const config = try read(actor.config, setup.maximum_config);
        errdefer allocator.free(config);
        const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
        defer allocator.free(capability_path);
        const capability = try read(capability_path, 64);
        errdefer {
            std.crypto.secureZero(u8, capability);
            allocator.free(capability);
        }
        const registry_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.registry", .{actor.state});
        defer allocator.free(registry_path);
        return .{ .config = config, .capability = capability, .registry = try read(registry_path, 5 * setup.maximum_config + 16384) };
    }
    fn deinit(self: *Saved) void {
        inline for (.{ "config", "capability", "registry" }) |field| {
            std.crypto.secureZero(u8, @field(self, field));
            allocator.free(@field(self, field));
        }
    }
    fn expectUnchanged(self: *const Saved, actor: *const native_fixture.ActorFixture) !void {
        var after = try capture(actor);
        defer after.deinit();
        // Comparing booleans avoids exposing capabilities, configuration or
        // sealed/ciphertext custody bytes in a failing test diagnostic.
        inline for (.{ "config", "capability", "registry" }) |field| try std.testing.expect(std.mem.eql(u8, @field(self, field), @field(after, field)));
    }
};

fn expectNeverAcquired(engine: *const engine_module.Engine) !void {
    try std.testing.expectEqual(@as(usize, 0), engine.state.bindings.items.len);
    try std.testing.expectEqual(@as(usize, 0), engine.state.leases.items.len);
    try std.testing.expectEqual(@as(usize, 0), engine.requests.records.items.len);
}

fn remove(actor: *native_fixture.ActorFixture, operation: native_owner.OperationId) !Reply {
    return removeAtRevision(actor, operation, actor.engine.?.revision);
}

fn removeAtRevision(actor: *native_fixture.ActorFixture, operation: native_owner.OperationId, expected_revision: u64) !Reply {
    return rpc(actor.engine.?, "integrations.remove", .{ .adapter = "codex", .config_path = actor.config, .operation_id = operation[0..], .expected_revision = expected_revision });
}

fn expectPending(reply: *const Reply) !void {
    const value = try reply.result();
    try std.testing.expect(!(try control.boolean(value, "removed", true)));
    try std.testing.expect(try control.boolean(value, "installed", false));
    try std.testing.expect(try control.boolean(value, "pending_safe_detach", false));
}

fn registerRpc(actor: *native_fixture.ActorFixture, owner: *native_fixture.Fixture) !Reply {
    var capability = try actor.engine.?.capabilityForTest("codex");
    defer std.crypto.secureZero(u8, &capability);
    const operation = try randomHex();
    const owner_id = std.fmt.bytesToHex(owner.owner_id, .lower);
    const nonce = std.fmt.bytesToHex(owner.native_nonce, .lower);
    return rpcChannel(actor.engine.?, owner, .adapter, "adapter.owner.register", .{
        .application = "codex",
        .capability = capability[0..],
        .operation_id = operation[0..],
        .owner_id = owner_id[0..],
        .process_nonce = nonce[0..],
        .owner_endpoint = owner.endpoint,
        .thread_id = "never-acquired-native-thread",
        .endpoint_generation = "1",
        .thread_instance_generation = "1",
    });
}

fn expectOriginalFence(actor: *const native_fixture.ActorFixture, epoch: u64, operation: native_owner.OperationId) !void {
    const fence = actor.engine.?.native_owners.applicationRemoval("codex", epoch) orelse return error.MissingRemovalFence;
    try std.testing.expectEqual(@as(@TypeOf(fence.phase), .pending), fence.phase);
    try std.testing.expect(std.mem.eql(u8, &operation, &fence.operation));
    try std.testing.expectEqual(epoch, actor.engine.?.adapter_epochs[0]);
}

fn expectInstallHeld(actor: *native_fixture.ActorFixture) !void {
    var attempted = try rpc(actor.engine.?, "integrations.install", .{ .adapter = "codex", .config_path = actor.config, .native_socket = actor.producer.endpoint });
    defer attempted.deinit();
    // R-N13: the actor's durable application fence refuses installation before
    // the lower-level setup permit boundary, which retains its custody error.
    try attempted.expectError("NativeRemovalPending");
}

fn expectRecoveryHeld(actor: *native_fixture.ActorFixture) !void {
    var attempted = try recoveryRpc(actor);
    defer attempted.deinit();
    try attempted.expectError("NativeCustodyPending");
}

fn recoveryRpc(actor: *native_fixture.ActorFixture) !Reply {
    var capability = try actor.engine.?.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    return rpcChannel(actor.engine.?, null, .adapter, "fixture.integrationRecover", .{
        .application = "enrollment",
        .capability = capability[0..],
        .adapter = "codex",
        .config_path = actor.config,
    });
}

fn detachCredit(engine: *const engine_module.Engine, reference: native_owner.NativeRef) !snapshot_admission.Credit {
    const row = engine.native_owners.lookupAttachment(reference) orelse return error.MissingAttachment;
    const operation = row.detach_operation orelse return error.MissingDetachOperation;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&operation, &digest, .{});
    for (engine.admission.credits.items) |credit| {
        if (credit.key.kind == .native_detach and credit.key.generation == reference.attachment_generation and std.mem.eql(u8, &credit.key.id, &digest)) {
            try std.testing.expect(credit.bytes > 0);
            return credit;
        }
    }
    return error.MissingDetachCredit;
}

test "R-N13 actual never-acquired owner is acknowledged before reversible configuration removal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Linux profile failures propagate. A missing profile cannot become a skip
    // or a fabricated saved witness on a Linux execution host.
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.deinit();
    const original = try Saved.read(actor.config, setup.maximum_config);
    defer allocator.free(original);
    try actor.install();
    const installed_witness = actor.engine.?.native_registry orelse return error.MissingRegistryWitness;
    const reference = try producer.register(actor.engine.?, "never-acquired-native-thread");
    try std.testing.expectEqual(native_owner.AttachmentPhase.attached, actor.engine.?.native_owners.lookupAttachment(reference).?.phase);
    try expectNeverAcquired(actor.engine.?);

    const operation = try randomHex();
    var removed = try remove(actor, operation);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
    const attachment = actor.engine.?.native_owners.lookupAttachment(reference).?;
    try std.testing.expectEqual(native_owner.AttachmentPhase.retired, attachment.phase);
    try std.testing.expectEqual(native_owner.Retirement.verified_detach, attachment.retirement);
    try std.testing.expectEqual(native_owner.OwnerPhase.retired, actor.engine.?.native_owners.lookupOwnerForRef(reference).?.phase);
    const fence = actor.engine.?.native_owners.applicationRemoval("codex", reference.adapter_epoch).?;
    try std.testing.expectEqual(@as(@TypeOf(fence.phase), .retired), fence.phase);
    try std.testing.expect(std.mem.eql(u8, &operation, &fence.operation));
    try std.testing.expectEqual(reference.adapter_epoch + 1, actor.engine.?.adapter_epochs[0]);
    const registry = actor.engine.?.native_registry orelse return error.MissingRegistryWitness;
    try std.testing.expectEqual(setup.RegistryPhase.removed, registry.phase);
    try std.testing.expect(std.mem.eql(u8, &installed_witness.transaction, &registry.transaction));
    try std.testing.expectEqual(@as(usize, 0), actor.engine.?.installed.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.engine.?.admission.credits.items.len);
    try expectNeverAcquired(actor.engine.?);
    const restored = try Saved.read(actor.config, setup.maximum_config);
    defer allocator.free(restored);
    try std.testing.expect(std.mem.eql(u8, original, restored));
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
    defer allocator.free(capability_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, capability_path, .{ .follow_symlinks = false }));
    try actor.restart();
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
    try std.testing.expectEqual(native_owner.AttachmentPhase.retired, actor.engine.?.native_owners.lookupAttachment(reference).?.phase);
}

test "R-N13 actual partial detach lost ACK retains original owner fence custody and credit across restart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const first = try native_fixture.Fixture.create(io, allocator);
    defer first.destroy();
    const second = try native_fixture.Fixture.create(io, allocator);
    defer second.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, first);
    defer actor.deinit();
    try actor.install();
    const first_ref = try first.register(actor.engine.?, "never-acquired-native-thread");
    const second_ref = try second.register(actor.engine.?, "never-acquired-native-thread");
    try expectNeverAcquired(actor.engine.?);
    second.setMethodMode(.unregister, .drop_reply);
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    const operation = try randomHex();
    const original_revision = actor.engine.?.revision;
    var removed = try remove(actor, operation);
    defer removed.deinit();
    try removed.expectFailure();
    try saved.expectUnchanged(actor);
    try expectOriginalFence(actor, first_ref.adapter_epoch, operation);
    try std.testing.expectEqual(@as(usize, 1), first.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 1), second.methodCount(.unregister));
    try std.testing.expectEqual(native_owner.AttachmentPhase.retired, actor.engine.?.native_owners.lookupAttachment(first_ref).?.phase);
    const unresolved = actor.engine.?.native_owners.lookupAttachment(second_ref).?;
    try std.testing.expectEqual(native_owner.AttachmentPhase.unresolved, unresolved.phase);
    try std.testing.expectEqual(native_owner.UnresolvedFrom.detachment, unresolved.unresolved_from);
    try std.testing.expectEqual(native_owner.Retirement.none, unresolved.retirement);
    const held = try detachCredit(actor.engine.?, second_ref);
    try actor.restart();
    try saved.expectUnchanged(actor);
    try expectOriginalFence(actor, second_ref.adapter_epoch, operation);
    const restored_credit = try detachCredit(actor.engine.?, second_ref);
    try std.testing.expect(std.meta.eql(held.key, restored_credit.key));
    try std.testing.expectEqual(held.bytes, restored_credit.bytes);
    try std.testing.expectEqual(@as(usize, 1), first.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 1), second.methodCount(.unregister));
    try expectInstallHeld(actor);
    try expectRecoveryHeld(actor);
    var repeated = try removeAtRevision(actor, operation, original_revision);
    defer repeated.deinit();
    try repeated.expectError("OperationIndeterminate");
    var fresh = try remove(actor, try randomHex());
    defer fresh.deinit();
    try expectPending(&fresh);
    try saved.expectUnchanged(actor);
    try expectOriginalFence(actor, first_ref.adapter_epoch, operation);
    try std.testing.expectEqual(@as(usize, 1), second.methodCount(.unregister));
    try expectNeverAcquired(actor.engine.?);
}

test "R-N13 actual unreachable never-acquired owner cannot be retired or redispatched after restart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.deinit();
    try actor.install();
    const reference = try producer.register(actor.engine.?, "never-acquired-native-thread");
    try expectNeverAcquired(actor.engine.?);
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    producer.stopEndpoint();
    const operation = try randomHex();
    var removed = try remove(actor, operation);
    defer removed.deinit();
    try removed.expectFailure();
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    try saved.expectUnchanged(actor);
    try expectOriginalFence(actor, reference.adapter_epoch, operation);
    const row = actor.engine.?.native_owners.lookupAttachment(reference).?;
    try std.testing.expectEqual(native_owner.AttachmentPhase.unresolved, row.phase);
    try std.testing.expectEqual(native_owner.UnresolvedFrom.detachment, row.unresolved_from);
    const held = try detachCredit(actor.engine.?, reference);
    try actor.restart();
    try expectInstallHeld(actor);
    try expectRecoveryHeld(actor);
    const after = try detachCredit(actor.engine.?, reference);
    try std.testing.expect(std.meta.eql(held.key, after.key));
    try std.testing.expectEqual(held.bytes, after.bytes);
    try saved.expectUnchanged(actor);
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    try expectOriginalFence(actor, reference.adapter_epoch, operation);
    try expectNeverAcquired(actor.engine.?);
}

test "R-N13 actual zero-owner removal fence blocks new same-epoch registration and preserves conflicting configuration" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(io, allocator, producer);
    defer actor.deinit();
    try actor.install();
    try std.testing.expectEqual(@as(usize, 0), actor.engine.?.native_owners.owners.items.len);
    const epoch = actor.engine.?.adapter_epochs[0];
    // This independently changed private fixture file deliberately conflicts
    // with the installed broker block. Removal must preserve it as owned now.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = actor.config, .data = "# independently changed synthetic configuration\n[fixture]\nchanged = true\n", .flags = .{ .permissions = .fromMode(0o600) } });
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    const operation = try randomHex();
    var removed = try remove(actor, operation);
    defer removed.deinit();
    try removed.expectError("NotInstalled");
    try expectOriginalFence(actor, epoch, operation);
    try saved.expectUnchanged(actor);
    const identified = producer.methodCount(.identify);
    var registration = try registerRpc(actor, producer);
    defer registration.deinit();
    try registration.expectError("NativeRemovalPending");
    try std.testing.expectEqual(identified, producer.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    try actor.restart();
    try expectOriginalFence(actor, epoch, operation);
    try expectInstallHeld(actor);
    // All-owner custody is ready here, so recovery can read and report this
    // configuration conflict. It cannot restore it or retire the global fence.
    var recovered = try recoveryRpc(actor);
    defer recovered.deinit();
    try std.testing.expect(try control.boolean(try recovered.result(), "installed", false));
    var after_restart = try registerRpc(actor, producer);
    defer after_restart.deinit();
    try after_restart.expectError("NativeRemovalPending");
    try saved.expectUnchanged(actor);
    try std.testing.expectEqual(identified, producer.methodCount(.identify));
    try std.testing.expectEqual(@as(usize, 0), actor.engine.?.native_owners.owners.items.len);
    try expectNeverAcquired(actor.engine.?);
}
