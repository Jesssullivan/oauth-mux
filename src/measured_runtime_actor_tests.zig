//! Actual actor/SQLite/Supervisor measurement predicates using private tiny
//! filesystem members and the existing genuine native socket fixture. No
//! provider, installed application, package provenance or continuity proof.
const std = @import("std");
const builtin = @import("builtin");
const engine = @import("engine.zig");
const native_fixture = @import("native_owner_fixture.zig");
const measured = @import("integrations/measured_runtime_selection.zig");
const setup = @import("integrations/setup.zig");
const paths = @import("paths.zig");
const metadata = @import("platform/file_metadata.zig");
const control = @import("control.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;
const members = [_][]const u8{ "bin/codex", "lib/codex/libexec/codex.bin", "lib/codex/lib/ld-linux-x86-64.so.2", "lib/codex/share/ca-bundle.crt" };
const Entry = struct { sha256: [64]u8, bytes: u64, mode: u32, device: u64, inode: u64, mtime_ns: i128, ctime_ns: i128, state: [9]i128 };
fn writeMember(path: []const u8, bytes: []const u8, mode: std.c.mode_t) !void {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    const descriptor = std.c.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, mode);
    if (descriptor < 0) return error.FixtureOpenFailed;
    defer _ = std.c.close(descriptor);
    if (std.c.fchmod(descriptor, mode) != 0) return error.FixtureModeFailed;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = std.c.write(descriptor, bytes[offset..].ptr, bytes.len - offset);
        if (count <= 0) return error.FixtureWriteFailed;
        offset += @intCast(count);
    }
}
fn memberEntry(path: []const u8, bytes: []const u8) !Entry {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    const descriptor = std.c.open(name.ptr, .{ .CLOEXEC = true, .NOFOLLOW = true });
    if (descriptor < 0) return error.FixtureOpenFailed;
    defer _ = std.c.close(descriptor);
    const status = try metadata.statFd(descriptor);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha, .{});
    return .{ .sha256 = std.fmt.bytesToHex(sha, .lower), .bytes = @intCast(status.size), .mode = status.mode & 0o7777, .device = status.dev, .inode = status.ino, .mtime_ns = status.mtime_ns, .ctime_ns = status.ctime_ns, .state = .{ status.dev, status.ino, status.uid, status.gid, status.mode & 0o7777, status.nlink, status.size, status.mtime_ns, status.ctime_ns } };
}
fn runtimeRoot(base: []const u8) ![]u8 {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    const root = try std.fmt.allocPrint(allocator, "{s}/measured-runtime", .{base});
    errdefer allocator.free(root);
    const descriptor = try paths.openPrivateRoot(allocator, root, true);
    defer _ = std.c.close(descriptor);
    var entries: [4]Entry = undefined;
    for (members, 0..) |member, index| {
        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, member });
        defer allocator.free(full);
        const parent = try paths.openPrivateRoot(allocator, std.fs.path.dirname(full).?, true);
        _ = std.c.close(parent);
        try writeMember(full, member, if (index == 3) 0o644 else 0o755);
        entries[index] = try memberEntry(full, member);
    }
    const status = try metadata.statFd(descriptor);
    // Non-ELF bytes are intentional: this schema is measured local facts only.
    const receipt = try std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = 1,
        .kind = "omux-codex-installed-direct-exec",
        .launch_profile = "linux-installed-direct-exec-v1",
        .target = "x86_64-linux",
        .native_support = false,
        .actor_selection = "uncommitted",
        .executable_attribution = "unproved",
        .installation = .{ .directory_device = status.dev, .directory_inode = status.ino, .uid = status.uid, .gid = status.gid, .mode = 0o700 },
        .files = .{ .@"bin/codex" = entries[0], .@"lib/codex/libexec/codex.bin" = entries[1], .@"lib/codex/lib/ld-linux-x86-64.so.2" = entries[2], .@"lib/codex/share/ca-bundle.crt" = entries[3] },
    }, .{});
    defer allocator.free(receipt);
    const path = try std.fmt.allocPrint(allocator, "{s}/codex-installed-runtime.json", .{root});
    defer allocator.free(path);
    try writeMember(path, receipt, 0o600);
    return root;
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
        return control.get(self.parsed.value, "result") orelse error.FixtureRpcRefused;
    }
    fn expectError(self: *const Reply, name: []const u8) !void {
        const value = control.get(self.parsed.value, "error") orelse return error.ExpectedFixtureRefusal;
        try std.testing.expectEqualStrings(name, try control.string(value, "message"));
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
    }
};
fn rpc(actor: *engine.Engine, method: []const u8, params: anytype) !Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(payload);
    const bytes = try actor.dispatch(allocator, payload, .control);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) };
}
const Inspection = struct { selected: ?measured.Committed, registry: ?setup.RegistryWitness, pending: bool, failed: bool, poisoned: bool, removal_pending: bool, epoch: u64, revision: u64 };
fn inspect(actor: *engine.Engine) !Inspection {
    var reply = try rpc(actor, "fixture.measuredRuntime", .{ .mode = "inspect" });
    defer reply.deinit();
    const value = try reply.result();
    const selection_bytes = try std.json.Stringify.valueAlloc(allocator, control.get(value, "selected") orelse return error.InvalidFixtureReply, .{});
    defer allocator.free(selection_bytes);
    const selection = try std.json.parseFromSlice(?measured.Committed, allocator, selection_bytes, .{});
    defer selection.deinit();
    const registry_bytes = try std.json.Stringify.valueAlloc(allocator, control.get(value, "registry") orelse return error.InvalidFixtureReply, .{});
    defer allocator.free(registry_bytes);
    const registry = try std.json.parseFromSlice(?setup.RegistryWitness, allocator, registry_bytes, .{});
    defer registry.deinit();
    const epoch = control.get(value, "epoch") orelse return error.InvalidFixtureReply;
    const revision = control.get(value, "revision") orelse return error.InvalidFixtureReply;
    if (epoch != .integer or epoch.integer <= 0 or revision != .integer or revision.integer < 0) return error.InvalidFixtureReply;
    return .{ .selected = selection.value, .registry = registry.value, .pending = try control.boolean(value, "pending", false), .failed = (control.get(value, "failure") orelse return error.InvalidFixtureReply) != .null, .poisoned = try control.boolean(value, "poisoned", true), .removal_pending = try control.boolean(value, "removal_pending", true), .epoch = @intCast(epoch.integer), .revision = @intCast(revision.integer) };
}
fn committed(actor: *engine.Engine) !Inspection {
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) });
    while (deadline.durationFromNow(io).raw.toMilliseconds() > 0) {
        const state = try inspect(actor);
        if (state.failed or state.poisoned) return error.MeasuredActorFixtureFailed;
        if (!state.pending and state.selected != null) return state;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.MeasuredActorFixtureTimedOut;
}
fn operation() ![64]u8 {
    var bytes: [32]u8 = undefined;
    try io.randomSecure(&bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}
const Saved = struct {
    config: []u8,
    registry: []u8,
    capability: []u8,
    fn capture(actor: *native_fixture.ActorFixture) !Saved {
        const config = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(setup.maximum_config));
        errdefer allocator.free(config);
        const path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.registry", .{actor.state});
        defer allocator.free(path);
        const registry = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(5 * setup.maximum_config));
        errdefer allocator.free(registry);
        const cap = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
        defer allocator.free(cap);
        return .{ .config = config, .registry = registry, .capability = try std.Io.Dir.cwd().readFileAlloc(io, cap, allocator, .limited(65)) };
    }
    fn deinit(self: *Saved) void {
        inline for (.{ "config", "registry", "capability" }) |name| {
            std.crypto.secureZero(u8, @field(self, name));
            allocator.free(@field(self, name));
        }
    }
    fn expectSame(self: *const Saved, actor: *native_fixture.ActorFixture) !void {
        var after = try capture(actor);
        defer after.deinit();
        inline for (.{ "config", "registry", "capability" }) |name| try std.testing.expect(std.mem.eql(u8, @field(self, name), @field(after, name)));
    }
};
test "actual install schedules bounded measurement and SQLite restart and rollback preserve original selection" {
    const owner = try native_fixture.Fixture.create(io, allocator);
    defer owner.deinit();
    const root = try runtimeRoot(owner.root);
    defer allocator.free(root);
    const actor = try native_fixture.ActorFixture.createWithMeasuredRoot(io, allocator, owner, root);
    defer actor.deinit();
    try std.testing.expect((try inspect(actor.engine.?)).selected == null);
    try actor.install();
    const before = try committed(actor.engine.?);
    try before.selected.?.validate(allocator, before.registry, before.epoch, before.revision);
    try std.testing.expect(!before.selected.?.record.native_support);
    try std.testing.expectEqual(@as(usize, 0), owner.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), owner.methodCount(.announce));
    var restored = try rpc(actor.engine.?, "fixture.measuredRuntime", .{ .mode = "restore" });
    defer restored.deinit();
    try std.testing.expect(try control.boolean(try restored.result(), "preserved", false));
    try actor.restartWithMeasuredRoot(root);
    const after = try committed(actor.engine.?);
    try std.testing.expect(std.meta.eql(before.selected.?, after.selected.?));
    try std.testing.expectEqual(before.epoch, after.epoch);
    try std.testing.expect(after.selected.?.committed_revision < after.revision);
}
test "actual snapshot digest channel restore and registry recovery guards preserve original native custody" {
    const owner = try native_fixture.Fixture.create(io, allocator);
    defer owner.deinit();
    const root = try runtimeRoot(owner.root);
    defer allocator.free(root);
    const actor = try native_fixture.ActorFixture.createWithMeasuredRoot(io, allocator, owner, root);
    defer actor.deinit();
    try actor.install();
    const before = try committed(actor.engine.?);
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    for ([_][]const u8{ "digest_refusal", "channel_restore", "recover_wrong_transaction", "install_wrong_transaction" }) |mode| {
        var reply = try rpc(actor.engine.?, "fixture.measuredRuntime", .{ .mode = mode });
        defer reply.deinit();
        const result = try reply.result();
        try std.testing.expect(try control.boolean(result, "refused", false));
        if (control.get(result, "preserved") != null) try std.testing.expect(try control.boolean(result, "preserved", false));
        try saved.expectSame(actor);
        const state = try inspect(actor.engine.?);
        try std.testing.expect(std.meta.eql(before.selected.?, state.selected.?));
        try std.testing.expect(!state.poisoned and !state.removal_pending);
    }
}
test "actual removal rejects another selected transaction then clears only its owned selection across restart" {
    const owner = try native_fixture.Fixture.create(io, allocator);
    defer owner.deinit();
    const root = try runtimeRoot(owner.root);
    defer allocator.free(root);
    const actor = try native_fixture.ActorFixture.createWithMeasuredRoot(io, allocator, owner, root);
    defer actor.deinit();
    try actor.install();
    const before = try committed(actor.engine.?);
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    var arm = try rpc(actor.engine.?, "fixture.measuredRuntime", .{ .mode = "wrong_transaction" });
    arm.deinit();
    const first_op = try operation();
    var rejected = try rpc(actor.engine.?, "integrations.remove", .{ .adapter = "codex", .operation_id = first_op[0..], .expected_revision = before.revision });
    defer rejected.deinit();
    try rejected.expectError("RuntimeSelectionDrift");
    try saved.expectSame(actor);
    const unchanged = try inspect(actor.engine.?);
    try std.testing.expect(std.meta.eql(before.selected.?, unchanged.selected.?));
    try std.testing.expect(!unchanged.removal_pending and !unchanged.poisoned);
    const next_op = try operation();
    var removed = try rpc(actor.engine.?, "integrations.remove", .{ .adapter = "codex", .operation_id = next_op[0..], .expected_revision = unchanged.revision });
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    const after = try inspect(actor.engine.?);
    try std.testing.expect(after.selected == null);
    try std.testing.expectEqual(before.epoch + 1, after.epoch);
    try std.testing.expectEqual(setup.RegistryPhase.removed, after.registry.?.phase);
    try actor.restartWithMeasuredRoot(root);
    const reopened = try inspect(actor.engine.?);
    try std.testing.expect(reopened.selected == null and !reopened.pending and !reopened.poisoned);
}
test "actual snapshot capacity refusal cannot publish measured carrier or alter native configuration" {
    const owner = try native_fixture.Fixture.create(io, allocator);
    defer owner.deinit();
    const root = try runtimeRoot(owner.root);
    defer allocator.free(root);
    const actor = try native_fixture.ActorFixture.createWithMeasuredRoot(io, allocator, owner, root);
    defer actor.deinit();
    try actor.install();
    _ = try committed(actor.engine.?);
    var saved = try Saved.capture(actor);
    defer saved.deinit();
    var failed = try rpc(actor.engine.?, "fixture.measuredRuntime", .{ .mode = "capacity_refusal" });
    defer failed.deinit();
    const result = try failed.result();
    try std.testing.expect(try control.boolean(result, "refused", false));
    try std.testing.expect(try control.boolean(result, "memory_unselected", false));
    try std.testing.expect(try control.boolean(result, "stored_unselected", false));
    try std.testing.expect(!(try control.boolean(result, "poisoned", true)));
    try saved.expectSame(actor);
}
