//! Actual owned filesystem/socket boundary predicates, not native peer or
//! application-support proof. All sockets below are publication hints only.
const std = @import("std");
const builtin = @import("builtin");
const inventory = @import("integrations/native_inventory.zig");
const paths = @import("paths.zig");
const metadata = @import("platform/file_metadata.zig");
const c = std.c;
const allocator = std.testing.allocator;
const io = std.testing.io;
extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) c.fd_t;

const first = "omux-owner-1111111111111111";
const second = "omux-owner-2222222222222222";
const stale_name = "omux-owner-3333333333333333";

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    root: [:0]u8,
    descriptor: c.fd_t,
    identity: metadata.Metadata,

    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        var nonce: [8]u8 = undefined;
        try io.randomSecure(&nonce);
        const root = try std.fmt.allocPrintSentinel(scratch, "/tmp/omux-inv-{s}", .{std.fmt.bytesToHex(nonce, .lower)}, 0);
        if (c.mkdir(root.ptr, 0o700) != 0) return error.FixtureDirectoryFailed;
        errdefer std.Io.Dir.cwd().deleteTree(io, root) catch @panic("owned inventory fixture cleanup failed");
        const descriptor = try paths.openPrivateRoot(scratch, root, false);
        errdefer _ = c.close(descriptor);
        const identity = try metadata.statFd(descriptor);
        // Construct all arena-owned values before copying the arena itself.
        return .{ .arena = arena, .root = root, .descriptor = descriptor, .identity = identity };
    }

    fn deinit(self: *Fixture) void {
        // Restore only our retained generated root, then refuse aliases or
        // replacement before deleting the exact exclusively created tree.
        if (c.fchmod(self.descriptor, 0o700) != 0) @panic("owned inventory fixture permission restore failed");
        const current = paths.openPrivateRoot(allocator, self.root, false) catch @panic("owned inventory fixture root changed");
        defer _ = c.close(current);
        const status = metadata.statFd(current) catch @panic("owned inventory fixture metadata failed");
        if (status.dev != self.identity.dev or status.ino != self.identity.ino) @panic("owned inventory fixture replacement refused");
        std.Io.Dir.cwd().deleteTree(io, self.root) catch @panic("owned inventory fixture cleanup failed");
        _ = c.close(self.descriptor);
        self.arena.deinit();
    }

    fn directory(self: *Fixture, name: []const u8) !c.fd_t {
        const terminated = try allocator.dupeSentinel(u8, name, 0);
        defer allocator.free(terminated);
        if (c.mkdirat(self.descriptor, terminated.ptr, 0o700) != 0) return error.FixtureDirectoryFailed;
        const descriptor = c.openat(self.descriptor, terminated.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (descriptor < 0) return error.FixtureOpenFailed;
        return descriptor;
    }

    fn endpointPath(self: *Fixture, name: []const u8) ![:0]u8 {
        return std.fmt.allocPrintSentinel(allocator, "{s}/{s}/owner.sock", .{ self.root, name }, 0);
    }

    fn bindSocket(self: *Fixture, name: []const u8) !void {
        const endpoint = try self.endpointPath(name);
        defer allocator.free(endpoint);
        const descriptor = socket(c.AF.UNIX, c.SOCK.SEQPACKET, 0);
        if (descriptor < 0) return error.FixtureSocketFailed;
        defer _ = c.close(descriptor);
        var address: c.sockaddr.un = .{ .path = @splat(0) };
        if (endpoint.len >= address.path.len) return error.FixtureSocketPathTooLong;
        @memcpy(address.path[0..endpoint.len], endpoint);
        if (c.bind(descriptor, @ptrCast(&address), @intCast(@offsetOf(c.sockaddr.un, "path") + endpoint.len + 1)) != 0) return error.FixtureBindFailed;
        if (c.fchmodat(c.AT.FDCWD, endpoint.ptr, 0o600, 0) != 0) return error.FixturePermissionFailed;
    }

    fn publish(self: *Fixture, name: []const u8) !void {
        const descriptor = try self.directory(name);
        defer _ = c.close(descriptor);
        try self.bindSocket(name);
    }

    fn ordinaryFile(self: *Fixture, name: []const u8) !void {
        const terminated = try allocator.dupeSentinel(u8, name, 0);
        defer allocator.free(terminated);
        const descriptor = c.openat(self.descriptor, terminated.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
        if (descriptor < 0) return error.FixtureFileFailed;
        _ = c.close(descriptor);
    }
};

fn collect(fixture: *Fixture) !inventory.Inventory {
    var budget = try inventory.Budget.init(io, null);
    return inventory.collect(io, allocator, fixture.root, &budget);
}

fn openFdCount() !usize {
    var directory = try std.Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |_| count += 1;
    return count;
}

test "native inventory accepts only exact lowercase immediate publication names" {
    try std.testing.expect(inventory.isOwnerDirectory(first));
    for ([_][]const u8{
        "omux-owner-111111111111111",             "omux-owner-11111111111111111",
        "omux-owner-aaaaaaaaaaaaaaaA",            "omux-owner-gggggggggggggggg",
        "other-owner-1111111111111111",           "../omux-owner-1111111111111111",
        "omux-owner-1111111111111111/owner.sock", "omux-owner-111111111111111\x00",
    }) |name| try std.testing.expect(!inventory.isOwnerDirectory(name));
}

test "native inventory retains sorted real socket hints without transport or chmod" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.publish(second);
    try fixture.publish(first);
    try fixture.ordinaryFile("ordinary-history-metadata");
    if (c.symlinkat(first, fixture.descriptor, "omux-owner-AAAAAAAAAAAAAAAA") != 0) return error.FixtureSymlinkFailed;
    const baseline = try metadata.statFd(fixture.descriptor);
    var result = try collect(&fixture);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), result.scanned_entries);
    try std.testing.expectEqual(@as(usize, 2), result.candidates.len);
    try std.testing.expectEqual(@as(usize, 0), result.ignored_stale_entries);
    try std.testing.expectEqualStrings(first, result.candidates[0].directory_name);
    try std.testing.expectEqualStrings(second, result.candidates[1].directory_name);
    try std.testing.expect(result.candidates[0].matchesOwner(@splat(0x11)));
    try std.testing.expect(!result.candidates[0].matchesOwner(@splat(0x22)));
    try result.verify(allocator);
    const after = try metadata.statFd(fixture.descriptor);
    try std.testing.expectEqual(baseline.mode, after.mode);
    try std.testing.expectEqual(baseline.mtime_ns, after.mtime_ns);
    try std.testing.expectEqual(baseline.ctime_ns, after.ctime_ns);
}

test "selected native home may be readable but writable home or ancestor refuses" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.publish(first);
    if (c.fchmod(fixture.descriptor, 0o755) != 0) return error.FixturePermissionFailed;
    var readable = try collect(&fixture);
    defer readable.deinit();
    try readable.verify(allocator);
    try std.testing.expectEqual(@as(u32, 0o755), (try metadata.statFd(fixture.descriptor)).mode & 0o777);
    if (c.fchmod(fixture.descriptor, 0o775) != 0) return error.FixturePermissionFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
    try std.testing.expectError(error.UnsafeNativeInventory, readable.candidates[0].verify(allocator));
    const nested = try fixture.directory("nested");
    defer _ = c.close(nested);
    const path = try std.fmt.allocPrint(allocator, "{s}/nested", .{fixture.root});
    defer allocator.free(path);
    var budget = try inventory.Budget.init(io, null);
    try std.testing.expectError(error.UnsafePathPermissions, inventory.collect(io, allocator, path, &budget));
}

test "native inventory refuses selected-root and matching-parent symlinks" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    if (c.symlinkat(".", fixture.descriptor, "alias") != 0) return error.FixtureSymlinkFailed;
    const path = try std.fmt.allocPrint(allocator, "{s}/alias", .{fixture.root});
    defer allocator.free(path);
    var budget = try inventory.Budget.init(io, null);
    try std.testing.expectError(error.PathOpenFailed, inventory.collect(io, allocator, path, &budget));
    const target = try fixture.directory("private-target");
    defer _ = c.close(target);
    if (c.symlinkat("private-target", fixture.descriptor, first) != 0) return error.FixtureSymlinkFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
}

test "native inventory refuses permissive parent and non-socket or aliased publications" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parent = try fixture.directory(first);
    defer _ = c.close(parent);
    if (c.fchmod(parent, 0o755) != 0) return error.FixturePermissionFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
    if (c.fchmod(parent, 0o700) != 0) return error.FixturePermissionFailed;
    const file = c.openat(parent, "owner.sock", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (file < 0) return error.FixtureFileFailed;
    _ = c.close(file);
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
    if (c.unlinkat(parent, "owner.sock", 0) != 0) return error.FixtureRemoveFailed;
    if (c.symlinkat("missing", parent, "owner.sock") != 0) return error.FixtureSymlinkFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
    if (c.unlinkat(parent, "owner.sock", 0) != 0) return error.FixtureRemoveFailed;
    try fixture.bindSocket(first);
    if (c.fchmodat(parent, "owner.sock", 0o666, 0) != 0) return error.FixturePermissionFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
    if (c.fchmodat(parent, "owner.sock", 0o600, 0) != 0) return error.FixturePermissionFailed;
    if (c.linkat(parent, "owner.sock", parent, "alias.sock", 0) != 0) return error.FixtureLinkFailed;
    try std.testing.expectError(error.UnsafeNativeInventory, collect(&fixture));
}

test "retained native socket and directory replacements refuse without touching old objects" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.publish(first);
    var result = try collect(&fixture);
    defer result.deinit();
    const candidate = &result.candidates[0];
    const pinned = try metadata.statFd(candidate.socket_fd);
    if (c.unlinkat(candidate.directory_fd, "owner.sock", 0) != 0) return error.FixtureRemoveFailed;
    try fixture.bindSocket(first);
    try std.testing.expectError(error.NativeInventoryChanged, candidate.verify(allocator));
    try std.testing.expectEqual(pinned.ino, (try metadata.statFd(candidate.socket_fd)).ino);
    if (c.renameat(fixture.descriptor, first, fixture.descriptor, "moved-original") != 0) return error.FixtureRenameFailed;
    try fixture.publish(first);
    try std.testing.expectError(error.NativeInventoryChanged, candidate.verify(allocator));
    try std.testing.expectEqual(pinned.ino, (try metadata.statFd(candidate.socket_fd)).ino);
}

test "retained selected-root replacement refuses even when new root is private" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.publish(first);
    var result = try collect(&fixture);
    defer result.deinit();
    const moved = try std.fmt.allocPrintSentinel(allocator, "{s}-moved", .{fixture.root}, 0);
    defer allocator.free(moved);
    if (c.rename(fixture.root.ptr, moved.ptr) != 0) return error.FixtureRenameFailed;
    var replacement_created = false;
    defer {
        if (replacement_created and c.unlinkat(c.AT.FDCWD, fixture.root.ptr, c.AT.REMOVEDIR) != 0) @panic("owned empty replacement cleanup failed");
        if (c.rename(moved.ptr, fixture.root.ptr) != 0) @panic("owned original root restore failed");
    }
    if (c.mkdir(fixture.root.ptr, 0o700) != 0) return error.FixtureDirectoryFailed;
    replacement_created = true;
    try std.testing.expectError(error.NativeInventoryChanged, result.candidates[0].verify(allocator));
    try std.testing.expectError(error.NativeInventoryChanged, result.verify(allocator));
}

test "stale socket appearance and new root publication invalidate observations" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parent = try fixture.directory(stale_name);
    defer _ = c.close(parent);
    var stale = try collect(&fixture);
    defer stale.deinit();
    try std.testing.expectEqual(@as(usize, 0), stale.candidates.len);
    try std.testing.expectEqual(@as(usize, 1), stale.ignored_stale_entries);
    try stale.verify(allocator);
    try fixture.bindSocket(stale_name);
    try std.testing.expectError(error.NativeInventoryChanged, stale.verify(allocator));
    var live = try collect(&fixture);
    defer live.deinit();
    try live.verify(allocator);
    try fixture.publish(first);
    try std.testing.expectError(error.NativeInventoryChanged, live.verify(allocator));
}

test "native inventory counts every irrelevant entry and closes partial admission on overflow" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.publish(first);
    for (0..inventory.maximum_scanned_entries) |index| {
        var buffer: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "ordinary-{d}", .{index});
        try fixture.ordinaryFile(name);
    }
    const descriptor_count = try openFdCount();
    try std.testing.expectError(error.NativeInventoryCapacity, collect(&fixture));
    try std.testing.expectEqual(descriptor_count, try openFdCount());
}

test "native inventory retains at most 256 live and stale hints across shared budget" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for (0..inventory.maximum_retained_hints) |index| {
        var buffer: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "omux-owner-{x:0>16}", .{index});
        const descriptor = try fixture.directory(name);
        _ = c.close(descriptor);
    }
    var budget = try inventory.Budget.init(io, null);
    var stale = try inventory.collect(io, allocator, fixture.root, &budget);
    defer stale.deinit();
    try std.testing.expectEqual(@as(usize, inventory.maximum_retained_hints), stale.ignored_stale_entries);
    try std.testing.expectEqual(@as(usize, inventory.maximum_retained_hints), budget.retained_hints);
    const descriptor_count = try openFdCount();
    try std.testing.expectError(error.NativeInventoryCapacity, inventory.collect(io, allocator, fixture.root, &budget));
    try std.testing.expectEqual(descriptor_count, try openFdCount());
    try fixture.publish(first);
    try std.testing.expectError(error.NativeInventoryCapacity, collect(&fixture));
}

test "native inventory expired shared deadline refuses before path effects or budget renewal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const expired = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.NativeTimeout, inventory.Budget.init(io, expired));
    var budget: inventory.Budget = .{ .until = expired };
    try std.testing.expectError(error.NativeTimeout, inventory.collect(io, allocator, "/tmp/../unread-context", &budget));
    try std.testing.expectEqual(@as(usize, 0), budget.scanned_entries);
    try std.testing.expectEqual(@as(usize, 0), budget.retained_hints);
}

const source_context = @import("integrations/native_source_context.zig");
const context_name = "4444444444444444444444444444444444444444444444444444444444444444.json";
const next_context_name = "5555555555555555555555555555555555555555555555555555555555555555.json";

fn contextDocument(fixture: *Fixture, context_id: []const u8) ![]u8 {
    const endpoint = try fixture.endpointPath(first);
    defer allocator.free(endpoint);
    return std.json.Stringify.valueAlloc(allocator, .{ .protocolVersion = 1,
        .contextId = context_id, .contextGeneration = "1", .ownerId = "11" ** 32,
        .processNonce = "22" ** 32, .endpointGeneration = "1", .ownerEndpoint = endpoint[0..endpoint.len] }, .{});
}
fn writeContext(registry: c.fd_t, name: []const u8, document: []const u8) !void {
    const terminated = try allocator.dupeSentinel(u8, name, 0);
    defer allocator.free(terminated);
    const descriptor = c.openat(registry, terminated.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (descriptor < 0) return error.FixtureFileFailed;
    defer _ = c.close(descriptor);
    if (c.write(descriptor, document.ptr, document.len) != @as(isize, @intCast(document.len))) return error.FixtureWriteFailed;
}

test "native context registry retains exact opaque hint without auth or consent" {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const registry = try fixture.directory(source_context.registry_name);
    defer _ = c.close(registry);
    const raw = try contextDocument(&fixture, context_name[0..64]);
    defer allocator.free(raw);
    try writeContext(registry, context_name, raw);
    // This unrelated file is neither required nor opened by metadata collection.
    try fixture.ordinaryFile("auth.json");
    var budget = try inventory.Budget.init(io, null);
    var result = (try source_context.collect(io, allocator, fixture.root, &budget)).?;
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.hints.len);
    try std.testing.expectEqual(@as(u64, 1), result.hints[0].context_generation);
    try std.testing.expectEqualStrings(fixture.root, result.hints[0].endpointHome());
    try std.testing.expectEqual(@as(usize, 1), budget.scanned_entries);
    try std.testing.expectEqual(@as(usize, 1), budget.candidate_count);
    try result.verify(io, &budget);
    try std.testing.expectEqual(@as(u32, 0o600), (try metadata.statFd(result.hints[0].descriptor)).mode & 0o777);
}

test "native context registry absent is unpublished and expired budget reads nothing" {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var budget = try inventory.Budget.init(io, null);
    try std.testing.expect((try source_context.collect(io, allocator, fixture.root, &budget)) == null);
    const expired = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    var closed: inventory.Budget = .{ .until = expired };
    try std.testing.expectError(error.NativeTimeout, source_context.collect(io, allocator, "/tmp/../unread-runtime", &closed));
    try std.testing.expectEqual(@as(usize, 0), closed.scanned_entries);
    try std.testing.expectEqual(@as(usize, 0), closed.retained_hints);
}

test "native context registry refuses aliases unsafe modes oversized and malformed fields" {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const registry = try fixture.directory(source_context.registry_name);
    defer _ = c.close(registry);
    const raw = try contextDocument(&fixture, context_name[0..64]);
    defer allocator.free(raw);
    if (c.symlinkat("../auth.json", registry, context_name) != 0) return error.FixtureSymlinkFailed;
    var budget = try inventory.Budget.init(io, null);
    try std.testing.expectError(error.NativeSourceContextChanged, source_context.collect(io, allocator, fixture.root, &budget));
    if (c.unlinkat(registry, context_name, 0) != 0) return error.FixtureUnlinkFailed;
    const variants = [_][]const u8{ "{}", "{\"protocolVersion\":1,\"protocolVersion\":1}", "{\"sourcePath\":\"/forbidden\"}" };
    for (variants) |document| {
        try writeContext(registry, context_name, document);
        budget = try inventory.Budget.init(io, null);
        const before = try openFdCount();
        if (source_context.collect(io, allocator, fixture.root, &budget)) |unexpected| {
            if (unexpected) |value| { var owned = value; owned.deinit(); }
            return error.FixtureExpectedRefusal;
        } else |_| {}
        try std.testing.expectEqual(before, try openFdCount());
        if (c.unlinkat(registry, context_name, 0) != 0) return error.FixtureUnlinkFailed;
    }
    const oversized: [source_context.maximum_hint_bytes + 1]u8 = @splat('x');
    try writeContext(registry, context_name, &oversized);
    budget = try inventory.Budget.init(io, null);
    try std.testing.expectError(error.UnsafeNativeSourceContext, source_context.collect(io, allocator, fixture.root, &budget));
    if (c.unlinkat(registry, context_name, 0) != 0) return error.FixtureUnlinkFailed;
    try writeContext(registry, context_name, raw);
    if (c.fchmod(registry, 0o755) != 0) return error.FixturePermissionFailed;
    budget = try inventory.Budget.init(io, null);
    try std.testing.expectError(error.UnsafeNativeSourceContext, source_context.collect(io, allocator, fixture.root, &budget));
    if (c.fchmod(registry, 0o700) != 0) return error.FixturePermissionFailed;
}

test "native context held hint refuses replacement and file mode drift without deleting either" {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const registry = try fixture.directory(source_context.registry_name);
    defer _ = c.close(registry);
    const raw = try contextDocument(&fixture, context_name[0..64]);
    defer allocator.free(raw);
    try writeContext(registry, context_name, raw);
    var budget = try inventory.Budget.init(io, null);
    var result = (try source_context.collect(io, allocator, fixture.root, &budget)).?;
    defer result.deinit();
    if (c.fchmod(result.hints[0].descriptor, 0o644) != 0) return error.FixturePermissionFailed;
    try std.testing.expectError(error.UnsafeNativeSourceContext, result.hints[0].verify());
    if (c.fchmod(result.hints[0].descriptor, 0o600) != 0) return error.FixturePermissionFailed;
    if (c.renameat(registry, context_name, registry, "retained-old") != 0) return error.FixtureRenameFailed;
    try writeContext(registry, context_name, raw);
    try std.testing.expectError(error.NativeSourceContextChanged, result.hints[0].verify());
    _ = try metadata.statAt(registry, context_name, c.AT.SYMLINK_NOFOLLOW);
    _ = try metadata.statAt(registry, "retained-old", c.AT.SYMLINK_NOFOLLOW);
}

test "native context duplicate owner and shared retained capacity refuse with FD cleanup" {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const registry = try fixture.directory(source_context.registry_name);
    defer _ = c.close(registry);
    const raw = try contextDocument(&fixture, context_name[0..64]);
    defer allocator.free(raw);
    const next = try contextDocument(&fixture, next_context_name[0..64]);
    defer allocator.free(next);
    try writeContext(registry, context_name, raw);
    try writeContext(registry, next_context_name, next);
    var budget = try inventory.Budget.init(io, null);
    const before = try openFdCount();
    try std.testing.expectError(error.NativeOwnerAmbiguous, source_context.collect(io, allocator, fixture.root, &budget));
    try std.testing.expectEqual(before, try openFdCount());
    if (c.unlinkat(registry, next_context_name, 0) != 0) return error.FixtureUnlinkFailed;
    budget = try inventory.Budget.init(io, null);
    budget.candidate_count = inventory.maximum_candidates;
    try std.testing.expectError(error.NativeInventoryCapacity, source_context.collect(io, allocator, fixture.root, &budget));
    try std.testing.expectEqual(before, try openFdCount());
}
