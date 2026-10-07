//! Synthetic local-byte predicates. No application launch or provider access.
const std = @import("std");
const builtin = @import("builtin");
const producer = @import("measured_runtime_selection.zig");
const setup = @import("setup.zig");
const paths = @import("../paths.zig");
const metadata = @import("../platform/file_metadata.zig");
const io = std.testing.io;
const allocator = std.testing.allocator;
const members = [_][]const u8{ "bin/codex", "lib/codex/libexec/codex.bin", "lib/codex/lib/ld-linux-x86-64.so.2", "lib/codex/share/ca-bundle.crt" };
const Entry = struct { sha256: [64]u8, bytes: u64, mode: u32, device: u64, inode: u64, mtime_ns: i128, ctime_ns: i128, state: [9]i128 };
fn entry(fd: std.c.fd_t, name: []const u8) !Entry {
    const full = try allocator.dupeSentinel(u8, name, 0);
    defer allocator.free(full);
    const file = std.c.openat(fd, full.ptr, .{ .CLOEXEC = true, .NOFOLLOW = true });
    if (file < 0) return error.FixtureOpenFailed;
    defer _ = std.c.close(file);
    const status = try metadata.statFd(file);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &hash, .{});
    return .{ .sha256 = std.fmt.bytesToHex(hash, .lower), .bytes = @intCast(status.size), .mode = status.mode & 0o7777, .device = status.dev, .inode = status.ino, .mtime_ns = status.mtime_ns, .ctime_ns = status.ctime_ns, .state = .{ status.dev, status.ino, status.uid, status.gid, status.mode & 0o7777, status.nlink, status.size, status.mtime_ns, status.ctime_ns } };
}
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    root: [:0]u8,
    installed: []const u8,
    directory: std.c.fd_t,
    context: producer.Context,
    fn init() !Fixture {
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var nonce: [16]u8 = undefined;
        try io.randomSecure(&nonce);
        const root = try std.fmt.allocPrintSentinel(a, "/tmp/omux-measured-native-{s}", .{std.fmt.bytesToHex(nonce, .lower)}, 0);
        if (std.c.mkdir(root.ptr, 0o700) != 0) return error.FixtureSetupFailed;
        errdefer std.Io.Dir.cwd().deleteTree(io, root) catch {};
        const home = try std.fmt.allocPrint(a, "{s}/home", .{root});
        const home_fd = try paths.openPrivateRoot(a, home, true);
        _ = std.c.close(home_fd);
        var options: setup.Options = .{ .adapter = .codex, .home = home, .state_dir = try std.fmt.allocPrint(a, "{s}/state", .{root}), .config_path = try std.fmt.allocPrint(a, "{s}/config.toml", .{home}), .capability = @splat('a'), .key = @splat(42), .broker_socket = try std.fmt.allocPrint(a, "{s}/adapter.sock", .{root}), .omux_version = "synthetic-measured-byte-test" };
        const seeded = try setup.LegacyCustodyForTest.seedInstalled(io, allocator, options);
        defer seeded.deinit(allocator);
        const witness = (try setup.registryWitness(io, allocator, options)).?;
        options.native_custody = .{ .adapter_epoch = 3, .state = .retain_ready, .snapshot_digest = @splat(8), .capability_digest = witness.capability_digest, .registry_transaction = witness.transaction, .registry_capability_digest = witness.capability_digest };
        const installed = try std.fmt.allocPrint(a, "{s}/installed", .{root});
        const directory = try paths.openPrivateRoot(a, installed, true);
        errdefer _ = std.c.close(directory);
        for (members, 0..) |name, index| {
            const full = try std.fmt.allocPrint(a, "{s}/{s}", .{ installed, name });
            const parent = try paths.openPrivateRoot(a, std.fs.path.dirname(full).?, true);
            _ = std.c.close(parent);
            try write(full, name, if (index == 3) 0o644 else 0o755);
        }
        const status = try metadata.statFd(directory);
        // Deliberately arbitrary non-ELF bytes. The measured contract grants no
        // ELF/direct-exec/provenance assertion from this receipt's labels.
        const receipt = try std.json.Stringify.valueAlloc(a, .{
            .schema_version = 1,
            .kind = "omux-codex-installed-direct-exec",
            .launch_profile = "linux-installed-direct-exec-v1",
            .target = "x86_64-linux",
            .native_support = false,
            .actor_selection = "uncommitted",
            .executable_attribution = "unproved",
            .installation = .{ .directory_device = status.dev, .directory_inode = status.ino, .uid = status.uid, .gid = status.gid, .mode = 0o700 },
            .files = .{ .@"bin/codex" = try entry(directory, members[0]), .@"lib/codex/libexec/codex.bin" = try entry(directory, members[1]), .@"lib/codex/lib/ld-linux-x86-64.so.2" = try entry(directory, members[2]), .@"lib/codex/share/ca-bundle.crt" = try entry(directory, members[3]) },
        }, .{});
        try write(try std.fmt.allocPrint(a, "{s}/codex-installed-runtime.json", .{installed}), receipt, 0o600);
        return .{ .arena = arena, .root = root, .installed = installed, .directory = directory, .context = .{ .options = options, .selection = .dev, .revision = 10, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) }), .installation_path = installed } };
    }
    fn deinit(self: *Fixture) void {
        if (self.directory >= 0) _ = std.c.close(self.directory);
        std.Io.Dir.cwd().deleteTree(io, self.root) catch {};
        self.arena.deinit();
    }
    fn observe(self: *Fixture) !*producer.MeasuredInstalledRuntime {
        return producer.observe(io, allocator, self.context, self.directory);
    }
};
fn write(path: []const u8, bytes: []const u8, mode: std.c.mode_t) !void {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    const fd = std.c.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true }, mode);
    if (fd < 0) return error.FixtureOpenFailed;
    defer _ = std.c.close(fd);
    if (std.c.fchmod(fd, mode) != 0) return error.FixtureModeFailed;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = std.c.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (count <= 0) return error.FixtureWriteFailed;
        offset += @intCast(count);
    }
}
test "local measurement owns root descriptor and never establishes artifact or ELF authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    _ = std.c.close(fixture.directory);
    fixture.directory = -1;
    const committed = try observed.prepareCommit(io, allocator, fixture.context);
    const witness = (try setup.registryWitness(io, allocator, fixture.context.options)).?;
    try committed.validate(allocator, witness, 3, 11);
    try std.testing.expectEqual(@as(u64, 11), committed.committed_revision);
    try std.testing.expectEqual(setup.RuntimeChannel.development, committed.record.channel);
    try std.testing.expect(!committed.record.native_support);
    try std.testing.expect(!std.meta.eql(committed.record.roles[1].sha256, committed.record.roles[2].sha256));
}
test "actor record digest revision epoch channel and exact removal ownership are independent fences" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    const committed = try observed.prepareCommit(io, allocator, fixture.context);
    const witness = (try setup.registryWitness(io, allocator, fixture.context.options)).?;
    try std.testing.expectError(error.InvalidMeasuredRuntimeSelection, committed.validate(allocator, witness, 3, 10));
    try std.testing.expectError(error.InvalidMeasuredRuntimeSelection, committed.validate(allocator, witness, 4, 11));
    try std.testing.expect(committed.ownedBy(witness, 3));
    try std.testing.expect(!committed.ownedBy(witness, 4));
    var wrong = witness;
    wrong.transaction[0] = if (wrong.transaction[0] == 'a') 'b' else 'a';
    try std.testing.expect(!committed.ownedBy(wrong, 3));
    try std.testing.expectError(error.InvalidMeasuredRuntimeSelection, committed.validate(allocator, wrong, 3, 11));
    wrong = witness;
    wrong.phase = .removed;
    try std.testing.expectError(error.InvalidMeasuredRuntimeSelection, committed.validate(allocator, wrong, 3, 11));
    var forged = committed;
    forged.record.native_support = true;
    forged.record_sha256 = try producer.digest(allocator, forged.record);
    try std.testing.expectError(error.InvalidMeasuredRuntimeSelection, forged.validate(allocator, witness, 3, 11));
    var drifted = fixture.context;
    drifted.revision += 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.prepareCommit(io, allocator, drifted));
    drifted = fixture.context;
    drifted.selection = .default;
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.prepareCommit(io, allocator, drifted));
}
test "post-worker CA byte write refuses actor commit without deleting prior custody" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    const original = (try setup.registryWitness(io, allocator, fixture.context.options)).?;
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture.installed, members[3] });
    defer allocator.free(path);
    try write(path, "changed fixture CA bytes", 0o644);
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.prepareCommit(io, allocator, fixture.context));
    try std.testing.expect(std.meta.eql(original, (try setup.registryWitness(io, allocator, fixture.context.options)).?));
}
test "published installation replacement refuses actor commit despite held old root" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    const old = try allocator.dupeSentinel(u8, fixture.installed, 0);
    defer allocator.free(old);
    const detached = try std.fmt.allocPrintSentinel(allocator, "{s}/detached", .{fixture.root}, 0);
    defer allocator.free(detached);
    if (std.c.rename(old.ptr, detached.ptr) != 0 or std.c.mkdir(old.ptr, 0o700) != 0) return error.FixtureSetupFailed;
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.prepareCommit(io, allocator, fixture.context));
}
test "removal custody and expired deadline cannot produce local selection" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.context.options.native_custody.?.state = .removal_pending;
    fixture.context.options.native_custody.?.removal_operation = @splat(1);
    try std.testing.expectError(error.NativeCustodyPending, fixture.observe());
    fixture.context.options.native_custody.?.state = .retain_ready;
    fixture.context.options.native_custody.?.removal_operation = null;
    fixture.context.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.Timeout, fixture.observe());
}
