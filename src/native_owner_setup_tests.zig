//! R-N13: actual encrypted setup custody survives pending native-owner removal.
//! These internal-permit fixtures test filesystem fences, not OS peer admission.
const std = @import("std");
const builtin = @import("builtin");
const setup = @import("integrations/setup.zig");
const owners = @import("native_owner.zig");
const paths = @import("paths.zig");
const envelope = @import("envelope.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;

const original = "# synthetic reversible native configuration\n";
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    base: [:0]u8,
    options: setup.Options,

    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        const base = try std.fmt.allocPrintSentinel(scratch, "{s}/omux-owner-setup-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(random[0..16].*, .lower) }, 0);
        if (std.c.mkdir(base.ptr, 0o700) != 0) return error.FixtureDirectoryFailed;
        errdefer std.Io.Dir.cwd().deleteTree(io, base) catch {};
        const home = try std.fmt.allocPrint(scratch, "{s}/home", .{base});
        const home_fd = try paths.openPrivateRoot(scratch, home, true);
        _ = std.c.close(home_fd);
        const state = try std.fmt.allocPrint(scratch, "{s}/state", .{base});
        const config = try std.fmt.allocPrint(scratch, "{s}/config.toml", .{home});
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = config, .data = original, .flags = .{ .permissions = .fromMode(0o600) } });
        try io.randomSecure(&random);
        const capability = std.fmt.bytesToHex(random, .lower);
        var key: envelope.Key = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        const options: setup.Options = .{ .state_dir = state, .home = home, .codex_home = home, .codex_home_explicit = true, .config_path = config, .adapter = .codex, .capability = capability, .broker_socket = try std.fmt.allocPrint(scratch, "{s}/adapter.sock", .{state}), .omux_version = "synthetic-owner-setup", .key = key };
        return .{ .arena = arena, .base = base, .options = options };
    }

    fn deinit(self: *Fixture) void {
        std.Io.Dir.cwd().deleteTree(io, self.base) catch {};
        std.crypto.secureZero(u8, &self.options.key);
        std.crypto.secureZero(u8, &self.options.capability);
        self.arena.deinit();
    }

    fn seed(self: *Fixture, pending_remove: bool) !void {
        const installed = try setup.LegacyCustodyForTest.seedInstalled(io, allocator, self.options);
        defer installed.deinit(allocator);
        if (pending_remove) try setup.LegacyCustodyForTest.seedPendingRemoval(io, allocator, self.options);
    }

    fn expectAllPending(self: *Fixture) !void {
        try std.testing.expectError(error.NativeCustodyPending, setup.install(io, allocator, self.options));
        try std.testing.expectError(error.NativeCustodyPending, setup.remove(io, allocator, self.options));
        try std.testing.expectError(error.NativeCustodyPending, setup.recover(io, allocator, self.options));
    }
};

const Saved = struct {
    config: []u8,
    capability: []u8,
    registry: []u8,

    fn capture(fixture: *const Fixture) !Saved {
        var directory = try std.Io.Dir.openDirAbsolute(io, fixture.base, .{});
        defer directory.close(io);
        const config = try directory.readFileAlloc(io, "home/config.toml", allocator, .limited(setup.maximum_config));
        errdefer allocator.free(config);
        const capability = try directory.readFileAlloc(io, "state/integrations/codex.capability", allocator, .limited(128));
        errdefer {
            std.crypto.secureZero(u8, capability);
            allocator.free(capability);
        }
        return .{ .config = config, .capability = capability, .registry = try directory.readFileAlloc(io, "state/integrations/codex.registry", allocator, .limited(4 * setup.maximum_config + 16384)) };
    }
    fn deinit(self: *Saved) void {
        std.crypto.secureZero(u8, self.config);
        std.crypto.secureZero(u8, self.capability);
        std.crypto.secureZero(u8, self.registry);
        allocator.free(self.config);
        allocator.free(self.capability);
        allocator.free(self.registry);
    }
    fn expectUnchanged(self: *const Saved, fixture: *const Fixture) !void {
        var after = try capture(fixture);
        defer after.deinit();
        // No raw capability, configuration or registry bytes on failure.
        try std.testing.expect(std.mem.eql(u8, self.config, after.config));
        try std.testing.expect(std.mem.eql(u8, self.capability, after.capability));
        try std.testing.expect(std.mem.eql(u8, self.registry, after.registry));
    }
};

fn addAttachment(ledger: *owners.Ledger, marker: u8, registration: owners.OperationId) !owners.NativeRef {
    var id: [32]u8 = undefined;
    try io.randomSecure(&id);
    var nonce: [32]u8 = undefined;
    try io.randomSecure(&nonce);
    var boot: [16]u8 = undefined;
    try io.randomSecure(&boot);
    const endpoint = try std.fmt.allocPrint(allocator, "/tmp/synthetic-native-owner-{d}.sock", .{marker});
    defer allocator.free(endpoint);
    try ledger.admitOwner(.{ .id = id, .application = "codex", .adapter_epoch = 1, .endpoint_generation = 1, .endpoint_path = endpoint, .native_nonce = nonce, .witness = .{ .profile = .linux_pidfs64_v1, .boot_id = boot, .pidfs_device = 0, .pidfs_inode = marker, .user_namespace = .{ .device = 0, .inode = 1 }, .pid_namespace = .{ .device = 0, .inode = 1 }, .uid = @intCast(std.c.getuid()), .gid = @intCast(std.c.getgid()) } });
    const ref: owners.NativeRef = .{ .owner_id = id, .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    try ledger.admitAttachment(.{ .reference = ref, .thread_id = "same-native-thread", .registration_operation = registration });
    return ref;
}

fn permit(options: setup.Options, ledger: *const owners.Ledger, state: setup.NativeCustodyState, operation: ?owners.OperationId) !setup.NativeCustody {
    const bytes = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(bytes);
    var result: setup.NativeCustody = .{ .adapter_epoch = 1, .capability_digest = undefined, .snapshot_digest = undefined, .state = state };
    std.crypto.hash.sha2.Sha256.hash(&options.capability, &result.capability_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(bytes, &result.snapshot_digest, .{});
    if (try setup.registryWitness(io, allocator, options)) |witness| {
        result.registry_transaction = witness.transaction;
        result.registry_capability_digest = witness.capability_digest;
    }
    if (operation) |op| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&op, &digest, .{});
        result.removal_operation = digest;
    }
    return result;
}

test "R-N13 selected encrypted installation context refuses explicit rebinding before effects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.seed(false);
    var before = try Saved.capture(&fixture);
    defer before.deinit();
    var ledger = owners.Ledger.init(allocator);
    defer ledger.deinit();
    fixture.options.native_custody = try permit(fixture.options, &ledger, .install_ready, null);
    var fallback = fixture.options;
    fallback.config_path = null;
    fallback.codex_home = "/fixture/changed-daemon-environment";
    fallback.codex_home_explicit = false;
    const selected = try setup.selectedCodexHome(io, allocator, fallback);
    defer allocator.free(selected);
    try std.testing.expectEqualStrings(fixture.options.codex_home.?, selected);

    const foreign = try std.fmt.allocPrint(allocator, "{s}/uncreated-context/custom.toml", .{fixture.base});
    defer allocator.free(foreign);
    var conflict = fixture.options;
    conflict.config_path = foreign;
    try std.testing.expectError(error.IntegrationPathConflict, setup.preflightResult(io, allocator, conflict, .install));
    try std.testing.expectError(error.IntegrationPathConflict, setup.install(io, allocator, conflict));
    try before.expectUnchanged(&fixture);
    const foreign_home = std.fs.path.dirname(foreign).?;
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, foreign_home, false));
    conflict = fallback;
    conflict.codex_home_explicit = true;
    try std.testing.expectError(error.IntegrationPathConflict, setup.selectedCodexHome(io, allocator, conflict));
    try std.testing.expectError(error.IntegrationPathConflict, setup.recover(io, allocator, conflict));
    try before.expectUnchanged(&fixture);
}

test "R-N13 default installation with no running owner refuses before configuration or custody writes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var ledger = owners.Ledger.init(allocator);
    defer ledger.deinit();
    // Structural permit only: this fixture deliberately supplies no native peer.
    fixture.options.native_custody = try permit(fixture.options, &ledger, .install_ready, null);
    const refused = if (builtin.os.tag == .linux) error.NativeHookRequired else error.UnsupportedPeerProfile;
    try std.testing.expectError(refused, setup.install(io, allocator, fixture.options));
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, fixture.options.state_dir, false));
    const config = try std.Io.Dir.cwd().readFileAlloc(io, fixture.options.config_path.?, allocator, .limited(setup.maximum_config));
    defer allocator.free(config);
    try std.testing.expect(std.mem.eql(u8, original, config));
}

test "R-N13 never-acquired pending native owner blocks every setup entrypoint before effects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.expectAllPending();
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, fixture.options.state_dir, false));
    var ledger = owners.Ledger.init(allocator);
    defer ledger.deinit();
    const registration: owners.OperationId = @splat('a');
    const operation: owners.OperationId = @splat('b');
    const ref = try addAttachment(&ledger, 1, registration);
    try ledger.beginApplicationRemoval("codex", 1, operation);
    try ledger.beginRemoval(ref.owner_id, operation);
    try std.testing.expect(!ledger.removalReady("codex", 1, operation));
    fixture.options.native_custody = try permit(fixture.options, &ledger, .removal_pending, operation);
    try fixture.expectAllPending();
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, fixture.options.state_dir, false));
    // Real encrypted historical custody is deliberately seeded, without treating
    // its configuration or this structural owner as live peer authority.
    try fixture.seed(false);
    var before = try Saved.capture(&fixture);
    defer before.deinit();
    for (0..2) |_| {
        try fixture.expectAllPending();
        try before.expectUnchanged(&fixture);
    }
}

test "R-N13 partial native detach retains pending-remove configuration and capability until final ready permit" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.seed(true);
    var before = try Saved.capture(&fixture);
    defer before.deinit();
    var ledger = owners.Ledger.init(allocator);
    defer ledger.deinit();
    const registration: owners.OperationId = @splat('a');
    const operation: owners.OperationId = @splat('b');
    const left = try addAttachment(&ledger, 1, registration);
    const right = try addAttachment(&ledger, 2, registration);
    for ([_]owners.NativeRef{ left, right }) |ref| try ledger.completeRegistration(ref, registration);
    try ledger.beginApplicationRemoval("codex", 1, operation);
    for ([_]owners.NativeRef{ left, right }) |ref| {
        try ledger.beginRemoval(ref.owner_id, operation);
    }
    try ledger.beginDetach(left, operation);
    try ledger.completeDetach(left, operation);
    try ledger.retireOwner(left.owner_id, operation);
    try std.testing.expect(!ledger.removalReady("codex", 1, operation));
    fixture.options.native_custody = try permit(fixture.options, &ledger, .removal_pending, operation);
    try fixture.expectAllPending();
    try before.expectUnchanged(&fixture);
    try ledger.markUnresolved(right);
    ledger.recoverAfterRestart();
    fixture.options.native_custody = try permit(fixture.options, &ledger, .removal_pending, operation);
    try fixture.expectAllPending();
    try before.expectUnchanged(&fixture);
    try std.testing.expect(ledger.lookupAttachment(left).?.phase == .retired);
    // Simulate fresh matching safe ACKs at the trusted actor boundary. This
    // fixture does not manufacture a peer Context or claim peer verification.
    try ledger.beginDetach(right, operation);
    try ledger.completeDetach(right, operation);
    try ledger.retireOwner(right.owner_id, operation);
    try std.testing.expect(ledger.removalReady("codex", 1, operation));
    fixture.options.native_custody = try permit(fixture.options, &ledger, .removal_ready, operation);
    // A ready structural ledger cannot bless an unknown/replaced registry.
    const ready = fixture.options.native_custody.?;
    fixture.options.native_custody.?.registry_transaction = null;
    fixture.options.native_custody.?.registry_capability_digest = null;
    try fixture.expectAllPending();
    try before.expectUnchanged(&fixture);
    fixture.options.native_custody = ready;
    const current = fixture.options.native_custody.?.registry_transaction.?;
    fixture.options.native_custody.?.registry_transaction.?[0] = if (current[0] == 'a') 'b' else 'a';
    try std.testing.expectError(error.NativeCustodyGenerationMismatch, setup.recover(io, allocator, fixture.options));
    try std.testing.expectError(error.NativeCustodyGenerationMismatch, setup.remove(io, allocator, fixture.options));
    try before.expectUnchanged(&fixture);
    fixture.options.native_custody = ready;
    try std.testing.expectEqual(setup.Recovery.removed, try setup.recover(io, allocator, fixture.options));
    const after_witness = (try setup.registryWitness(io, allocator, fixture.options)).?;
    try std.testing.expect(std.mem.eql(u8, &ready.registry_transaction.?, &after_witness.transaction));
    try ledger.completeApplicationRemoval("codex", 1, operation);
    const restored = try std.Io.Dir.cwd().readFileAlloc(io, fixture.options.config_path.?, allocator, .limited(setup.maximum_config));
    defer allocator.free(restored);
    try std.testing.expect(std.mem.eql(u8, original, restored));
    // R-N13: ordinary clients cannot read native Codex capabilities. Separately
    // assert removal of the actual owned capability file after the safe fence.
    try std.testing.expectError(error.UnsupportedAdapter, paths.readCapability(allocator, fixture.options.state_dir, "codex"));
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{fixture.options.state_dir});
    defer allocator.free(capability_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, capability_path, .{ .follow_symlinks = false }));
}

test "R-N13 Codex removal retains installation witness and retired recovery cannot revoke a new epoch capability" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.seed(false);
    const installed_witness = (try setup.registryWitness(io, allocator, fixture.options)).?;
    var ledger = owners.Ledger.init(allocator);
    defer ledger.deinit();
    const operation: owners.OperationId = @splat('b');
    try ledger.beginApplicationRemoval("codex", 1, operation);
    try std.testing.expect(ledger.removalReady("codex", 1, operation));
    const ready = try permit(fixture.options, &ledger, .removal_ready, operation);
    fixture.options.native_custody = ready;
    const removed = try setup.remove(io, allocator, fixture.options);
    defer removed.deinit(allocator);
    const retired_witness = (try setup.registryWitness(io, allocator, fixture.options)).?;
    try std.testing.expect(retired_witness.phase == .removed);
    try std.testing.expect(std.mem.eql(u8, &installed_witness.transaction, &retired_witness.transaction));
    try ledger.completeApplicationRemoval("codex", 1, operation);

    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    fixture.options.capability = std.fmt.bytesToHex(random, .lower);
    // The next epoch's capability is placed only in this owned private fixture;
    // this exercises restoration guards, not native admission or installation.
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{fixture.options.state_dir});
    defer allocator.free(capability_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = capability_path, .data = &fixture.options.capability, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    fixture.options.native_custody = try permit(fixture.options, &ledger, .install_ready, null);
    fixture.options.native_custody.?.adapter_epoch = 2;
    var before = try Saved.capture(&fixture);
    defer before.deinit();
    try std.testing.expectEqual(setup.Recovery.removed, try setup.recover(io, allocator, fixture.options));
    try before.expectUnchanged(&fixture);
    fixture.options.native_socket = "/tmp/../unsupported-owner-hook.sock";
    try std.testing.expectError(error.UnsafePath, setup.install(io, allocator, fixture.options));
    try before.expectUnchanged(&fixture);
    fixture.options.native_custody = ready;
    try std.testing.expectError(error.NativeCustodyGenerationMismatch, setup.remove(io, allocator, fixture.options));
    try before.expectUnchanged(&fixture);
}
