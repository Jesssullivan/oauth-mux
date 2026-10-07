//! Synthetic retained-FD acquisition predicates. No archive/ELF/build validity,
//! actor commit, executable attribution, native history or continuity proof.
const std = @import("std");
const builtin = @import("builtin");
const producer = @import("runtime_selection_producer.zig");
const setup = @import("setup.zig");
const paths = @import("../paths.zig");
const io = std.testing.io;
const allocator = std.testing.allocator;
const members = [_][]const u8{
    "bin/codex",               "lib/codex/libexec/codex.bin",   "lib/codex/lib/ld-linux-x86-64.so.2",
    "lib/codex/lib/libc.so.6", "lib/codex/share/ca-bundle.crt",
};

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn entry(bytes: []const u8, mode: u32) struct { sha256: [64]u8, bytes: usize, mode: u32 } {
    return .{ .sha256 = std.fmt.bytesToHex(digest(bytes), .lower), .bytes = bytes.len, .mode = mode };
}

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    root: [:0]u8,
    descriptors: [6]std.c.fd_t,
    context: producer.ActorContext,
    inputs: producer.Inputs,

    fn init() !Fixture {
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var nonce: [16]u8 = undefined;
        try io.randomSecure(&nonce);
        const root = try std.fmt.allocPrintSentinel(a, "/tmp/omux-runtime-producer-{s}", .{std.fmt.bytesToHex(nonce, .lower)}, 0);
        if (std.c.mkdir(root.ptr, 0o700) != 0) return error.FixtureSetupFailed;
        errdefer std.Io.Dir.cwd().deleteTree(io, root) catch {};
        const home = try std.fmt.allocPrint(a, "{s}/home", .{root});
        const home_fd = try paths.openPrivateRoot(a, home, true);
        _ = std.c.close(home_fd);
        const state = try std.fmt.allocPrint(a, "{s}/state", .{root});
        const options: setup.Options = .{
            .adapter = .codex,
            .home = home,
            .state_dir = state,
            .config_path = try std.fmt.allocPrint(a, "{s}/config.toml", .{home}),
            .capability = @splat('a'),
            .key = @splat(42),
            .broker_socket = try std.fmt.allocPrint(a, "{s}/adapter.sock", .{state}),
            .omux_version = "synthetic-runtime-producer",
        };
        const seeded = try setup.LegacyCustodyForTest.seedInstalled(io, allocator, options);
        defer seeded.deinit(allocator);
        const witness = (try setup.registryWitness(io, allocator, options)).?;
        var context: producer.ActorContext = .{ .options = options, .selection = .dev, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
        context.options.native_custody = .{
            .adapter_epoch = 3,
            .state = .retain_ready,
            .snapshot_digest = @splat(8),
            .capability_digest = witness.capability_digest,
            .registry_transaction = witness.transaction,
            .registry_capability_digest = witness.capability_digest,
        };
        const directory = try paths.openPrivateRoot(a, try std.fmt.allocPrint(a, "{s}/installed", .{root}), true);
        errdefer _ = std.c.close(directory);
        for (members, 0..) |member, index| {
            const full = try std.fmt.allocPrint(a, "{s}/installed/{s}", .{ root, member });
            const parent = try paths.openPrivateRoot(a, std.fs.path.dirname(full).?, true);
            _ = std.c.close(parent);
            try write(full, member, if (index == 4) 0o644 else 0o755);
        }
        const archive = "synthetic archive bytes; deliberately not gzip or ELF";
        const source = try std.json.Stringify.valueAlloc(a, .{ .commit = @as([40]u8, @splat('a')) }, .{});
        const source_hash = std.fmt.bytesToHex(digest(source), .lower);
        const compile_receipt = try std.json.Stringify.valueAlloc(a, .{ .upstream_commit = @as([40]u8, @splat('a')), .current_source_receipt_sha256 = source_hash }, .{});
        const manifest = try std.json.Stringify.valueAlloc(a, .{
            .schema_version = 1,
            .status = "native-owner-runtime-proof-candidate",
            .native_support = false,
            .target = "x86_64-linux",
            .candidate = .{ .upstream_commit = @as([40]u8, @splat('a')), .current_source_receipt_sha256 = source_hash },
            .transformations = .{ .source_receipt_sha256 = source_hash, .producer_receipt_sha256 = std.fmt.bytesToHex(digest(compile_receipt), .lower) },
            .runtime = .{ .loader = members[2], .caBundle = members[4], .dependencies = [_][]const u8{ members[2], members[3] } },
            .files = .{
                .@"bin/codex" = entry(members[0], 0o755),
                .@"lib/codex/libexec/codex.bin" = entry(members[1], 0o755),
                .@"lib/codex/lib/ld-linux-x86-64.so.2" = entry(members[2], 0o755),
                .@"lib/codex/lib/libc.so.6" = entry(members[3], 0o755),
                .@"lib/codex/share/ca-bundle.crt" = entry(members[4], 0o644),
            },
        }, .{});
        const receipt = try std.json.Stringify.valueAlloc(a, .{
            .schema_version = 1,
            .status = "native-owner-runtime-proof-candidate",
            .native_support = false,
            .archive_sha256 = std.fmt.bytesToHex(digest(archive), .lower),
            .archive_bytes = archive.len,
            .manifest_sha256 = std.fmt.bytesToHex(digest(manifest), .lower),
        }, .{});
        var selected: [5]producer.Input = undefined;
        var opened: usize = 0;
        errdefer for (selected[0..opened]) |input| {
            _ = std.c.close(input.descriptor);
        };
        for ([_][]const u8{ archive, manifest, receipt, source, compile_receipt }, &selected, 0..) |bytes, *input, index| {
            const input_path = try std.fmt.allocPrintSentinel(a, "{s}/input-{d}", .{ root, index }, 0);
            try write(input_path, bytes, 0o600);
            const descriptor = std.c.open(input_path.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
            if (descriptor < 0) return error.FixtureSetupFailed;
            input.* = .{ .descriptor = descriptor, .sha256 = digest(bytes), .bytes = bytes.len };
            opened += 1;
        }
        return .{
            .arena = arena,
            .root = root,
            .context = context,
            .descriptors = .{ selected[0].descriptor, selected[1].descriptor, selected[2].descriptor, selected[3].descriptor, selected[4].descriptor, directory },
            .inputs = .{ .archive = selected[0], .manifest = selected[1], .runtime_receipt = selected[2], .source_receipt = selected[3], .producer_receipt = selected[4], .installation_directory = directory },
        };
    }

    fn deinit(self: *Fixture) void {
        for (self.descriptors) |descriptor| _ = std.c.close(descriptor);
        std.Io.Dir.cwd().deleteTree(io, self.root) catch {};
        std.crypto.secureZero(u8, &self.context.options.key);
        std.crypto.secureZero(u8, &self.context.options.capability);
        self.arena.deinit();
    }
    fn observe(self: *Fixture) !*producer.Observation {
        return producer.observe(io, allocator, self.context, self.inputs);
    }
    fn path(self: *Fixture, member: []const u8) ![:0]u8 {
        return std.fmt.allocPrintSentinel(self.arena.allocator(), "{s}/installed/{s}", .{ self.root, member }, 0);
    }
};

fn write(path: []const u8, bytes: []const u8, mode: u32) !void {
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes, .flags = .{ .permissions = .fromMode(mode) } });
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    if (std.c.chmod(name.ptr, mode) != 0) return error.FixtureSetupFailed;
}

test "retained descriptor observation covers shared libraries and CA without granting artifact authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    try std.testing.expectEqual(@as(usize, 5), observed.fileCount());
    var total: u64 = 0;
    for (members) |member| total += member.len;
    try std.testing.expectEqual(total, observed.payloadBytes());
    try observed.recheck(io, fixture.context);
    for (fixture.descriptors[0..5]) |descriptor| try std.testing.expectEqual(@as(std.c.off_t, 0), std.c.lseek(descriptor, 0, std.c.SEEK.CUR));
    // These bytes are not an archive or ELF. Passing observations MUST NOT
    // manufacture an opaque validated selection or make seal/write available.
    try std.testing.expectError(error.NativeArtifactVerifierUnavailable, producer.acquire(io, allocator, fixture.context, fixture.inputs));
}

test "installed library and CA tampering refuse on acquisition and original observation recheck" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    for (members[3..]) |member| {
        const selected = try fixture.path(member);
        const changed = try allocator.dupe(u8, member);
        defer allocator.free(changed);
        changed[0] ^= 1;
        try write(selected, changed, if (std.mem.eql(u8, member, members[4])) 0o644 else 0o755);
        try std.testing.expectError(error.RuntimeSelectionDrift, fixture.observe());
        try std.testing.expectError(error.RuntimeSelectionDrift, observed.recheck(io, fixture.context));
        try write(selected, member, if (std.mem.eql(u8, member, members[4])) 0o644 else 0o755);
    }
}

test "retained observation refuses same bytes on replacement inode and symlink paths" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    const library = try fixture.path(members[3]);
    if (std.c.unlink(library.ptr) != 0) return error.FixtureSetupFailed;
    try write(library, members[3], 0o755);
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.recheck(io, fixture.context));
    if (std.c.unlink(library.ptr) != 0 or std.c.symlink("/unselected-library", library.ptr) != 0) return error.FixtureSetupFailed;
    try std.testing.expectError(error.UnsafeRuntimeInput, fixture.observe());
}

test "actor instance epoch transaction and pending recovery fences survive observed bytes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const observed = try fixture.observe();
    defer observed.deinit();
    const saved = fixture.context;
    fixture.context.selection = .default;
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.recheck(io, fixture.context));
    fixture.context = saved;
    fixture.context.options.native_custody.?.adapter_epoch += 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, observed.recheck(io, fixture.context));
    fixture.context = saved;
    const original = fixture.context.options.native_custody.?.registry_transaction.?[0];
    fixture.context.options.native_custody.?.registry_transaction.?[0] = if (original == 'a') 'b' else 'a';
    try std.testing.expectError(error.RuntimeSelectionDrift, fixture.observe());
    fixture.context = saved;
    try setup.LegacyCustodyForTest.seedPendingRemoval(io, allocator, fixture.context.options);
    try std.testing.expectError(error.NativeCustodyPending, fixture.observe());
    try std.testing.expectError(error.NativeCustodyPending, observed.recheck(io, fixture.context));
}

test "input independent digest size and deadline bounds refuse before authority acquisition" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const saved = fixture.inputs;
    fixture.inputs.manifest.sha256[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, fixture.observe());
    fixture.inputs = saved;
    fixture.inputs.source_receipt.bytes = producer.maximum_metadata_bytes + 1;
    try std.testing.expectError(error.RuntimeInputLimit, fixture.observe());
    fixture.inputs = saved;
    fixture.context.deadline = std.Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, fixture.observe());
    fixture.context.deadline = std.Io.Clock.Timestamp.now(io, .real);
    try std.testing.expectError(error.InvalidDeadline, fixture.observe());
}

test "unqualified immutable mode normalization remains a safe refusal" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const library = try fixture.path(members[3]);
    if (std.c.chmod(library.ptr, 0o555) != 0) return error.FixtureSetupFailed;
    try std.testing.expectError(error.UnsafeRuntimeInput, fixture.observe());
}
