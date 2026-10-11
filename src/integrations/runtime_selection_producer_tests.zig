//! Synthetic retained-FD and real artifact-parser predicates. No actual build,
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
    // These receipts lack complete provenance and bytes are not archive/ELF.
    // Passing observations must not manufacture a validated selection.
    try std.testing.expectError(error.InvalidRuntimeProvenance, producer.acquire(io, allocator, fixture.context, fixture.inputs));
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
    try std.testing.expectError(error.Timeout, producer.acquire(io, allocator, fixture.context, fixture.inputs));
    fixture.context.deadline = std.Io.Clock.Timestamp.now(io, .real);
    try std.testing.expectError(error.InvalidDeadline, fixture.observe());
    try std.testing.expectError(error.InvalidDeadline, producer.acquire(io, allocator, fixture.context, fixture.inputs));
}

test "unqualified immutable mode normalization remains a safe refusal" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const library = try fixture.path(members[3]);
    if (std.c.chmod(library.ptr, 0o555) != 0) return error.FixtureSetupFailed;
    try std.testing.expectError(error.UnsafeRuntimeInput, fixture.observe());
}

const artifact = @import("runtime_artifact_verifier.zig");
const writer = @import("runtime_selection_writer.zig");
const ca_bytes = "# Synthetic public certificate fixture only\n-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
const ProofFixture = struct {
    fixture: Fixture,
    payloads: [5][]const u8,
    manifest: []const u8,
    source: []const u8,
    producer_receipt: []const u8,
    receipt: []const u8,
    archive: []const u8,

    fn init() !ProofFixture {
        var fixture = try Fixture.init();
        errdefer fixture.deinit();
        const a = fixture.arena.allocator();
        const backend_elf = try modelElf(a, true, "libc.so.6");
        const library_elf = try modelElf(a, false, null);
        const payloads: [5][]const u8 = .{ artifact.launcher_bytes, backend_elf, library_elf, library_elf, ca_bytes };
        for (members, payloads, 0..) |member, value, index| try write(try fixture.path(member), value, if (index == 4) 0o644 else 0o755);
        const inventory = .{ .@"codex-rs/core/src/auth_broker.rs" = .{ .mode = "100644", .sha256 = std.fmt.bytesToHex(digest("synthetic source fixture"), .lower) } };
        // Python's pinned source receipt hashes this exact default-spaced JSON.
        const canonical_inventory = try std.fmt.allocPrint(a, "{{\"codex-rs/core/src/auth_broker.rs\": {{\"mode\": \"100644\", \"sha256\": \"{s}\"}}}}", .{std.fmt.bytesToHex(digest("synthetic source fixture"), .lower)});
        const patch_hash = std.fmt.bytesToHex(digest("synthetic patch"), .lower);
        const source = try std.json.Stringify.valueAlloc(a, .{ .phase = "verify-prepared", .commit = artifact.upstream_commit, .patch_sha256 = patch_hash, .complete_inventory_sha256 = std.fmt.bytesToHex(digest(canonical_inventory), .lower), .tracked_files = 1, .bazel_configuration = "owner-linux-fastbuild", .files = inventory }, .{});
        const candidate = .{ .upstream_commit = artifact.upstream_commit, .patch_sha256 = patch_hash, .base_sha256 = std.fmt.bytesToHex(digest("synthetic base"), .lower), .binary_overlay_sha256 = std.fmt.bytesToHex(digest("synthetic overlay"), .lower), .validation_sha256 = std.fmt.bytesToHex(digest("synthetic validation"), .lower), .complete_source_inventory_sha256 = std.fmt.bytesToHex(digest(canonical_inventory), .lower), .current_source_receipt_sha256 = std.fmt.bytesToHex(digest(source), .lower), .compile_invocation_id = "12345678-1234-1234-1234-123456789abc", .source_verification_invocation_id = "22345678-1234-1234-1234-123456789abc", .current_compile_invocation_id = "32345678-1234-1234-1234-123456789abc", .current_source_verification_invocation_id = "42345678-1234-1234-1234-123456789abc", .current_configuration = "owner-linux-fastbuild" };
        const candidate_value = try std.json.Stringify.valueAlloc(a, candidate, .{});
        const parsed = try std.json.parseFromSlice(std.json.Value, a, candidate_value, .{});
        defer parsed.deinit();
        var producer_value = parsed.value;
        try producer_value.object.put(a, "target", .{ .string = "//codex-rs/cli:codex" });
        try producer_value.object.put(a, "configuration", .{ .string = "owner-linux-fastbuild" });
        try producer_value.object.put(a, "original_sha256", .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(digest(backend_elf), .lower)) });
        try producer_value.object.put(a, "original_bytes", .{ .integer = @intCast(backend_elf.len) });
        // The producer receipt omits current_configuration; package candidate
        // projects producer.configuration into that distinct field.
        _ = producer_value.object.swapRemove("current_configuration");
        const producer_receipt = try std.json.Stringify.valueAlloc(a, producer_value, .{});
        const executable = .{ .backend_max_bytes = 512 * 1024 * 1024, .original_sha256 = std.fmt.bytesToHex(digest(backend_elf), .lower), .original_bytes = backend_elf.len, .stripped_sha256 = std.fmt.bytesToHex(digest(backend_elf), .lower), .stripped_bytes = backend_elf.len, .packaged_sha256 = std.fmt.bytesToHex(digest(backend_elf), .lower), .packaged_bytes = backend_elf.len };
        const manifest = try std.json.Stringify.valueAlloc(a, .{ .schema_version = 1, .status = "native-owner-runtime-proof-candidate", .native_support = false, .target = "x86_64-linux", .candidate = candidate, .executable = executable, .transformations = .{ .source_receipt_sha256 = std.fmt.bytesToHex(digest(source), .lower), .producer_receipt_sha256 = std.fmt.bytesToHex(digest(producer_receipt), .lower), .strip_tool_sha256 = std.fmt.bytesToHex(digest("synthetic strip"), .lower), .patchelf_tool_sha256 = std.fmt.bytesToHex(digest("synthetic patchelf"), .lower) }, .runtime = .{ .loader = members[2], .caBundle = members[4], .dependencies = [_][]const u8{ members[2], members[3] }, .backendInterpreter = artifact.interpreter, .backend_max_bytes = 512 * 1024 * 1024 }, .files = .{ .@"bin/codex" = entry(payloads[0], 0o755), .@"lib/codex/libexec/codex.bin" = entry(payloads[1], 0o755), .@"lib/codex/lib/ld-linux-x86-64.so.2" = entry(payloads[2], 0o755), .@"lib/codex/lib/libc.so.6" = entry(payloads[3], 0o755), .@"lib/codex/share/ca-bundle.crt" = entry(payloads[4], 0o644) } }, .{});
        const archive = try modelArchive(a, payloads, manifest);
        const receipt = try std.json.Stringify.valueAlloc(a, .{ .schema_version = 1, .status = "native-owner-runtime-proof-candidate", .native_support = false, .candidate = candidate, .executable = executable, .archive_sha256 = std.fmt.bytesToHex(digest(archive), .lower), .archive_bytes = archive.len, .manifest_sha256 = std.fmt.bytesToHex(digest(manifest), .lower) }, .{});
        var result: ProofFixture = .{ .fixture = fixture, .payloads = payloads, .manifest = manifest, .source = source, .producer_receipt = producer_receipt, .receipt = receipt, .archive = archive };
        for ([_][]const u8{ archive, manifest, receipt, source, producer_receipt }, 0..) |value, index| try result.replaceInput(index, value);
        return result;
    }
    fn replaceInput(self: *ProofFixture, index: usize, bytes: []const u8) !void {
        const a = self.fixture.arena.allocator();
        const path = try std.fmt.allocPrint(a, "{s}/input-{d}", .{ self.fixture.root, index });
        try write(path, bytes, 0o600);
        const input: producer.Input = .{ .descriptor = self.fixture.descriptors[index], .bytes = bytes.len, .sha256 = digest(bytes) };
        switch (index) {
            0 => self.fixture.inputs.archive = input,
            1 => self.fixture.inputs.manifest = input,
            2 => self.fixture.inputs.runtime_receipt = input,
            3 => self.fixture.inputs.source_receipt = input,
            4 => self.fixture.inputs.producer_receipt = input,
            else => unreachable,
        }
    }
    fn acquire(self: *ProofFixture) !*producer.ValidatedSelection {
        return producer.acquire(io, allocator, self.fixture.context, self.fixture.inputs);
    }
};

fn put16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}
fn put32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}
fn put64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}
/// Synthetic ELF bytes, parsed by the actual production verifier, never run.
fn modelElf(a: std.mem.Allocator, backend: bool, needed: ?[]const u8) ![]u8 {
    const bytes = try a.alloc(u8, 1024);
    @memset(bytes, 0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    put16(bytes, 16, 3);
    put16(bytes, 18, 62);
    put32(bytes, 20, 1);
    put64(bytes, 32, 64);
    put16(bytes, 52, 64);
    put16(bytes, 54, 56);
    put16(bytes, 56, if (backend) 3 else 1);
    put32(bytes, 64, 1);
    put64(bytes, 64 + 32, bytes.len);
    put64(bytes, 64 + 40, bytes.len);
    if (backend) {
        put32(bytes, 120, 3);
        put64(bytes, 128, 256);
        put64(bytes, 152, artifact.interpreter.len + 1);
        put64(bytes, 160, artifact.interpreter.len + 1);
        @memcpy(bytes[256..][0..artifact.interpreter.len], artifact.interpreter);
        put32(bytes, 176, 2);
        put64(bytes, 184, 320);
        put64(bytes, 192, 320);
        put64(bytes, 208, 80);
        put64(bytes, 216, 80);
        put64(bytes, 320, 5);
        put64(bytes, 328, 512);
        put64(bytes, 336, 10);
        put64(bytes, 344, 128);
        put64(bytes, 352, 29);
        put64(bytes, 360, 1);
        @memcpy(bytes[513..][0.."$ORIGIN/../lib".len], "$ORIGIN/../lib");
        if (needed) |name| {
            put64(bytes, 368, 1);
            put64(bytes, 376, 32);
            @memcpy(bytes[544..][0..name.len], name);
        }
    }
    return bytes;
}
fn tarNumber(bytes: []u8, value: u64) void {
    @memset(bytes, '0');
    bytes[bytes.len - 1] = 0;
    var x = value;
    var i = bytes.len - 1;
    while (x != 0) {
        i -= 1;
        bytes[i] = @intCast('0' + x % 8);
        x /= 8;
    }
}
fn tarMember(a: std.mem.Allocator, raw: *std.ArrayList(u8), path: []const u8, bytes: []const u8, mode: u32) !void {
    var header: [512]u8 = @splat(0);
    @memcpy(header[0..path.len], path);
    tarNumber(header[100..108], mode);
    tarNumber(header[108..116], 0);
    tarNumber(header[116..124], 0);
    tarNumber(header[124..136], bytes.len);
    tarNumber(header[136..148], 0);
    @memset(header[148..156], ' ');
    header[156] = '0';
    @memcpy(header[257..265], "ustar\x0000");
    var sum: u64 = 0;
    for (header) |b| sum += b;
    tarNumber(header[148..156], sum);
    try raw.appendSlice(a, &header);
    try raw.appendSlice(a, bytes);
    const padding = (512 - bytes.len % 512) % 512;
    try raw.appendNTimes(a, 0, padding);
}
fn modelArchive(a: std.mem.Allocator, payloads: [5][]const u8, manifest: []const u8) ![]const u8 {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(a);
    // Byte-sorted exact producer member order (lib before libexec).
    for ([_]usize{ 0, 2, 3, 1, 4 }) |index| try tarMember(a, &raw, members[index], payloads[index], if (index == 4) 0o644 else 0o755);
    try tarMember(a, &raw, "runtime-manifest.json", manifest, 0o644);
    try raw.appendNTimes(a, 0, 1024);
    try raw.appendNTimes(a, 0, (10240 - raw.items.len % 10240) % 10240);
    var gzip: std.ArrayList(u8) = .empty;
    errdefer gzip.deinit(a);
    try gzip.appendSlice(a, &.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 });
    var offset: usize = 0;
    while (offset < raw.items.len) {
        const count: u16 = @intCast(@min(65535, raw.items.len - offset));
        try gzip.append(a, if (offset + count == raw.items.len) 1 else 0);
        var lengths: [4]u8 = undefined;
        put16(&lengths, 0, count);
        put16(&lengths, 2, ~count);
        try gzip.appendSlice(a, &lengths);
        try gzip.appendSlice(a, raw.items[offset..][0..count]);
        offset += count;
    }
    var footer: [8]u8 = undefined;
    put32(&footer, 0, std.hash.Crc32.hash(raw.items));
    put32(&footer, 4, @intCast(raw.items.len));
    try gzip.appendSlice(a, &footer);
    return gzip.toOwnedSlice(a);
}

test "genuine bounded constructor joins raw archive ELF receipts installation and actual writer" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const selected = try proof.acquire();
    defer selected.deinit();
    try selected.recheck(io, proof.fixture.context);
    const record = selected.runtimeRecord();
    try std.testing.expectEqual(setup.RuntimeChannel.development, record.channel);
    try std.testing.expectEqualSlices(u8, artifact.upstream_commit, &record.upstream_commit);
    try std.testing.expectEqualDeep(proof.fixture.inputs.archive.sha256, record.archive_sha256);
    try std.testing.expectEqualDeep(proof.fixture.inputs.producer_receipt.sha256, record.producer_receipt_sha256);
    try std.testing.expectEqualDeep(digest(proof.payloads[1]), record.backend.sha256);
    const prepared = try writer.prepare(io, allocator, proof.fixture.context, selected);
    defer prepared.deinit(allocator);
    var options = proof.fixture.context.options;
    options.deadline = proof.fixture.context.deadline;
    const expected = prepared.expectation();
    const decoded = try setup.verifyRetainedRuntimeSelection(io, allocator, options, expected, prepared.evidence());
    defer decoded.deinit(allocator);
    try decoded.recheck(io, allocator, options, expected);
    // Evidence preparation is not an actor commit or an execution proof.
    for (proof.fixture.descriptors[0..5]) |fd| try std.testing.expectEqual(@as(std.c.off_t, 0), std.c.lseek(fd, 0, std.c.SEEK.CUR));
    // The carrier owns duplicates and is independent of borrowed-FD lifetime.
    _ = std.c.close(proof.fixture.descriptors[4]);
    proof.fixture.descriptors[4] = -1;
    try selected.recheck(io, proof.fixture.context);
}

test "qualified carrier and writer refuse changed receipts files actor snapshot and deadline" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const selected = try proof.acquire();
    defer selected.deinit();
    const saved = proof.fixture.context;
    proof.fixture.context.options.native_custody.?.snapshot_digest[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, selected.recheck(io, proof.fixture.context));
    proof.fixture.context = saved;
    proof.fixture.context.deadline = saved.deadline.addDuration(.{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.RuntimeSelectionDrift, writer.prepare(io, allocator, proof.fixture.context, selected));
    proof.fixture.context = saved;
    try write(try proof.fixture.path(members[3]), "same role, different installed bytes", 0o755);
    try std.testing.expectError(error.RuntimeSelectionDrift, writer.prepare(io, allocator, proof.fixture.context, selected));
}

test "constructor rejects concrete archive corruption ELF lookup and receipt inventory mismatch" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const a = proof.fixture.arena.allocator();
    const damaged = try a.dupe(u8, proof.archive);
    damaged[damaged.len - 8] ^= 1;
    try proof.replaceInput(0, damaged);
    // Rebind only the externally selected archive reference in a synthetic
    // fixture so the real archive parser, not the earlier digest, refuses CRC.
    var receipt = try std.json.parseFromSlice(std.json.Value, a, proof.receipt, .{});
    defer receipt.deinit();
    try receipt.value.object.put(a, "archive_sha256", .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(digest(damaged), .lower)) });
    try proof.replaceInput(2, try std.json.Stringify.valueAlloc(a, receipt.value, .{}));
    try std.testing.expectError(error.InvalidRuntimeArchive, proof.acquire());
    // Actual ELF parser rejects a foreign DT_NEEDED, independent of file hash.
    const foreign = try modelElf(a, true, "foreign.so");
    const path = try std.fmt.allocPrintSentinel(a, "{s}/foreign-elf", .{proof.fixture.root}, 0);
    try write(path, foreign, 0o600);
    const fd = std.c.open(path.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.FixtureSetupFailed;
    defer _ = std.c.close(fd);
    const manifest = try std.json.parseFromSlice(std.json.Value, a, proof.manifest, .{});
    defer manifest.deinit();
    const deps = (manifest.value.object.get("runtime").?).object.get("dependencies").?;
    try std.testing.expectError(error.InvalidRuntimeElf, artifact.elf(allocator, .{ .io = io, .deadline = proof.fixture.context.deadline }, fd, foreign.len, true, deps));
    var source = try std.json.parseFromSlice(std.json.Value, a, proof.source, .{});
    defer source.deinit();
    try source.value.object.put(a, "tracked_files", .{ .integer = 2 });
    const producer_receipt = try std.json.parseFromSlice(std.json.Value, a, proof.producer_receipt, .{});
    defer producer_receipt.deinit();
    const good_receipt = try std.json.parseFromSlice(std.json.Value, a, proof.receipt, .{});
    defer good_receipt.deinit();
    try std.testing.expectError(error.InvalidRuntimeProvenance, artifact.provenance(allocator, .{ .io = io, .deadline = proof.fixture.context.deadline }, manifest.value, good_receipt.value, source.value, producer_receipt.value, digest(proof.source), digest(proof.producer_receipt)));
}

test "raw verifier refuses real unsafe tar members and concatenated gzip despite valid CRC" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const a = proof.fixture.arena.allocator();
    const manifest = try std.json.parseFromSlice(std.json.Value, a, proof.manifest, .{});
    defer manifest.deinit();
    const budget: artifact.Budget = .{ .io = io, .deadline = proof.fixture.context.deadline };
    // Fixture gzip is one actual stored block; mutate uncompressed tar bytes
    // then recompute its CRC, so refusal tests tar predicates rather than CRC.
    for ([_]u8{ 0, 1, 2, 3 }) |case| {
        const bytes = try a.dupe(u8, proof.archive);
        const raw = bytes[15 .. bytes.len - 8];
        switch (case) {
            0 => raw[156] = '2', // forbidden symlink member
            1 => {
                @memset(raw[0..100], 0);
                @memcpy(raw[0..7], "../evil");
            },
            2 => tarNumber(raw[100..108], 0o644), // launcher mode must be 755
            3 => raw[512] ^= 1, // actual member content differs
            else => unreachable,
        }
        if (case != 3) {
            @memset(raw[148..156], ' ');
            var sum: u64 = 0;
            for (raw[0..512]) |b| sum += b;
            tarNumber(raw[148..156], sum);
        }
        put32(bytes, bytes.len - 8, std.hash.Crc32.hash(raw));
        try std.testing.expectError(error.InvalidRuntimeArchive, artifact.archive(budget, bytes, manifest.value, digest(proof.manifest), proof.manifest.len));
    }
    const concatenated = try std.mem.concat(a, u8, &.{ proof.archive, proof.archive });
    try std.testing.expectError(error.InvalidRuntimeArchive, artifact.archive(budget, concatenated, manifest.value, digest(proof.manifest), proof.manifest.len));
}

test "receipt producer configuration invocation inventory and executable joins are actual refusal predicates" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const a = proof.fixture.arena.allocator();
    for (0..5) |case| {
        const manifest = try std.json.parseFromSlice(std.json.Value, a, proof.manifest, .{});
        defer manifest.deinit();
        const receipt = try std.json.parseFromSlice(std.json.Value, a, proof.receipt, .{});
        defer receipt.deinit();
        const source = try std.json.parseFromSlice(std.json.Value, a, proof.source, .{});
        defer source.deinit();
        var compiled = try std.json.parseFromSlice(std.json.Value, a, proof.producer_receipt, .{});
        defer compiled.deinit();
        switch (case) {
            0 => try compiled.value.object.put(a, "target", .{ .string = "//foreign:binary" }),
            1 => try compiled.value.object.put(a, "configuration", .{ .string = "owner-linux-dbg" }),
            2 => try compiled.value.object.put(a, "current_compile_invocation_id", .{ .string = "52345678-1234-1234-1234-123456789abc" }),
            3 => {
                const inventory = source.value.object.get("files").?;
                var record = inventory.object.get("codex-rs/core/src/auth_broker.rs").?;
                try record.object.put(a, "mode", .{ .string = "100755" });
            },
            4 => try compiled.value.object.put(a, "original_bytes", .{ .integer = 1 }),
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidRuntimeProvenance, artifact.provenance(allocator, .{ .io = io, .deadline = proof.fixture.context.deadline }, manifest.value, receipt.value, source.value, compiled.value, digest(proof.source), digest(proof.producer_receipt)));
    }
}

test "genuine qualified recheck retains independently selected raw receipts rather than wire rebinding" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const selected = try proof.acquire();
    defer selected.deinit();
    const changed = try proof.fixture.arena.allocator().dupe(u8, proof.producer_receipt);
    changed[changed.len - 2] ^= 1;
    try proof.replaceInput(4, changed);
    // Updating a caller input digest cannot rebind an existing genuine carrier.
    try std.testing.expectError(error.RuntimeSelectionDrift, selected.recheck(io, proof.fixture.context));
}

// Actual parser seam: fixture ELF bytes are written and read through retained
// descriptors. These models do not construct Nix deployment authority.
test "ELF dynamic virtual mapping must uniquely agree with physical offset" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const a = fixture.arena.allocator();
    const path = try std.fmt.allocPrintSentinel(a, "{s}/dynamic-map-model", .{fixture.root}, 0);
    const bytes = try modelElf(a, true, "libc.so.6");
    try write(path, bytes, 0o600);
    const fd = std.c.open(path.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
    try std.testing.expect(fd >= 0);
    defer _ = std.c.close(fd);
    const budget: artifact.Budget = .{ .io = io, .deadline = fixture.context.deadline };
    var parsed = try artifact.elfDescription(a, budget, fd, bytes.len, bytes.len);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("libc.so.6", parsed.needed.items[0]);
    // Same p_offset/table bytes, different p_vaddr: interpreting the physical
    // table alone would accept this malformed native image.
    put64(bytes, 192, 0);
    try write(path, bytes, 0o600);
    try std.testing.expectError(error.InvalidRuntimeElf, artifact.elfDescription(a, budget, fd, bytes.len, bytes.len));
    put64(bytes, 192, 320);
    put64(bytes, 64 + 16, std.math.maxInt(u64) - 1);
    try write(path, bytes, 0o600);
    try std.testing.expectError(error.InvalidRuntimeElf, artifact.elfDescription(a, budget, fd, bytes.len, bytes.len));
}

const nix_artifact = @import("runtime_nix_artifact_verifier.zig");
const nix_closure = @import("nix_runtime_closure.zig");
test "parsed actual ELF graph selects ordered declared Nix edges and refuses unsupported lookup" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const a = fixture.arena.allocator();
    const root = "/nix/store/00000000000000000000000000000000-synthetic-parser-model";
    const interpreter_path = root ++ "/lib/ld-linux-x86-64.so.2";
    const libc_path = root ++ "/lib/libc.so.6";
    const backend_bytes = try modelElf(a, true, "libc.so.6");
    // Actual parser bytes contain Nix strings, but this test never calls the
    // physical closure constructor or treats the synthetic names as custody.
    put64(backend_bytes, 128, 700);
    put64(backend_bytes, 152, interpreter_path.len + 1);
    put64(backend_bytes, 160, interpreter_path.len + 1);
    @memcpy(backend_bytes[700..][0..interpreter_path.len], interpreter_path);
    @memset(backend_bytes[512..640], 0);
    @memcpy(backend_bytes[513..][0..(root ++ "/lib").len], root ++ "/lib");
    put64(backend_bytes, 376, 100);
    @memcpy(backend_bytes[612..][0.."libc.so.6".len], "libc.so.6");
    const loader_bytes = try modelElf(a, false, null);
    const library_bytes = try modelElf(a, false, null);
    put16(library_bytes, 56, 2);
    put32(library_bytes, 120, 2);
    put64(library_bytes, 128, 320);
    put64(library_bytes, 136, 320);
    put64(library_bytes, 152, 64);
    put64(library_bytes, 160, 64);
    put64(library_bytes, 320, 5);
    put64(library_bytes, 328, 512);
    put64(library_bytes, 336, 10);
    put64(library_bytes, 344, 64);
    put64(library_bytes, 352, 14);
    put64(library_bytes, 360, 1);
    @memcpy(library_bytes[513..][0.."libc.so.6".len], "libc.so.6");
    var descriptions: [3]artifact.ElfDescription = undefined;
    var owned: usize = 0;
    defer for (descriptions[0..owned]) |*description| description.deinit();
    const budget: artifact.Budget = .{ .io = io, .deadline = fixture.context.deadline };
    for ([_][]const u8{ backend_bytes, loader_bytes, library_bytes }, 0..) |bytes, i| {
        const path = try std.fmt.allocPrintSentinel(a, "{s}/graph-model-{d}", .{ fixture.root, i }, 0);
        try write(path, bytes, 0o600);
        const fd = std.c.open(path.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
        try std.testing.expect(fd >= 0);
        defer _ = std.c.close(fd);
        descriptions[i] = try artifact.elfDescription(a, budget, fd, bytes.len, bytes.len);
        owned += 1;
    }
    const status: @import("../platform/file_metadata.zig").Metadata = std.mem.zeroes(@import("../platform/file_metadata.zig").Metadata);
    const roots = [_]nix_closure.Root{.{ .path = root, .status = status }};
    const files = [_]nix_closure.File{ .{ .path = interpreter_path, .status = status, .bytes = loader_bytes.len, .sha256 = digest(loader_bytes) }, .{ .path = libc_path, .status = status, .bytes = library_bytes.len, .sha256 = digest(library_bytes) } };
    var edges = [_]nix_closure.Edge{.{ .source_index = 255, .needed = "libc.so.6", .target_index = 1 }};
    var record: nix_closure.Record = .{ .registration_receipt_sha256 = digest("synthetic graph only"), .original_interpreter = interpreter_path, .interpreter_file_index = 0, .roots = &roots, .files = &files, .aliases = &.{}, .edges = &edges };
    try nix_artifact.validateElfGraph(a, budget, record, &descriptions[0], descriptions[1..]);
    edges[0].target_index = 0;
    try std.testing.expectError(error.InvalidNixRuntimeProvenance, nix_artifact.validateElfGraph(a, budget, record, &descriptions[0], descriptions[1..]));
    edges[0].target_index = 1;
    record.edges = &.{};
    try std.testing.expectError(error.InvalidNixRuntimeProvenance, nix_artifact.validateElfGraph(a, budget, record, &descriptions[0], descriptions[1..]));
    record.edges = &edges;
    try descriptions[0].rpath.append(a, try a.dupe(u8, root ++ "/lib"));
    try std.testing.expectError(error.InvalidNixRuntimeProvenance, nix_artifact.validateElfGraph(a, budget, record, &descriptions[0], descriptions[1..]));
}

test "same archive parser validates before private staging and never replaces members" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const a = proof.fixture.arena.allocator();
    const path = try std.fmt.allocPrintSentinel(a, "{s}/staging-model", .{proof.fixture.root}, 0);
    try std.testing.expectEqual(@as(c_int, 0), std.c.mkdir(path.ptr, 0o700));
    const stage = std.c.open(path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    try std.testing.expect(stage >= 0);
    defer _ = std.c.close(stage);
    const manifest = try std.json.parseFromSlice(std.json.Value, a, proof.manifest, .{});
    defer manifest.deinit();
    const budget: artifact.Budget = .{ .io = io, .deadline = proof.fixture.context.deadline };
    var ledger = artifact.StagingLedger.init(a);
    defer ledger.deinit();
    const corrupt = try a.dupe(u8, proof.archive);
    corrupt[corrupt.len - 8] ^= 1;
    try std.testing.expectError(error.InvalidRuntimeArchive, artifact.materializeArchive(budget, corrupt, manifest.value, digest(proof.manifest), proof.manifest.len, stage, &ledger));
    const absent = std.c.openat(stage, "bin", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (absent >= 0) _ = std.c.close(absent);
    try std.testing.expect(absent < 0 and std.c.errno(absent) == .NOENT);
    try artifact.materializeArchive(budget, proof.archive, manifest.value, digest(proof.manifest), proof.manifest.len, stage, &ledger);
    for (members, proof.payloads, 0..) |member, expected, i| {
        const copied = try std.fmt.allocPrintSentinel(a, "{s}/{s}", .{ path, member }, 0);
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, copied, a, .limited(512 * 1024 * 1024));
        try std.testing.expectEqualSlices(u8, expected, bytes);
        const fd = std.c.open(copied.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
        try std.testing.expect(fd >= 0);
        defer _ = std.c.close(fd);
        const status = try @import("../platform/file_metadata.zig").statFd(fd);
        try std.testing.expectEqual(@as(u32, if (i == 4) 0o644 else 0o755), status.mode & 0o777);
    }
    try std.testing.expectError(error.UnsafeRuntimeStaging, artifact.materializeArchive(budget, proof.archive, manifest.value, digest(proof.manifest), proof.manifest.len, stage, &ledger));
    const copied_backend = try std.fmt.allocPrint(a, "{s}/{s}", .{ path, members[1] });
    const again = try std.Io.Dir.cwd().readFileAlloc(io, copied_backend, a, .limited(512 * 1024 * 1024));
    try std.testing.expectEqualSlices(u8, proof.payloads[1], again);
    // Production path streams the selected compressed descriptor rather than
    // allocating either compressed archive or full backend bytes.
    try artifact.archiveSelected(budget, proof.fixture.inputs.archive, manifest.value, digest(proof.manifest), proof.manifest.len);
    const fd = std.c.open((try proof.fixture.path(members[1])).ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
    try std.testing.expect(fd >= 0);
    defer _ = std.c.close(fd);
    var backend = try artifact.elfDescription(a, budget, fd, proof.payloads[1].len, 512 * 1024 * 1024);
    defer backend.deinit();
    try std.testing.expectEqualStrings("libc.so.6", backend.needed.items[0]);
}

test "production staging refuses oversized metadata and foreign layout before destination work" {
    var proof = try ProofFixture.init();
    defer proof.fixture.deinit();
    const a = proof.fixture.arena.allocator();
    const path = try std.fmt.allocPrintSentinel(a, "{s}/bounded-staging-model", .{proof.fixture.root}, 0);
    try std.testing.expectEqual(@as(c_int, 0), std.c.mkdir(path.ptr, 0o700));
    const stage = std.c.open(path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    try std.testing.expect(stage >= 0);
    defer _ = std.c.close(stage);
    var ledger = artifact.StagingLedger.init(a);
    defer ledger.deinit();
    var oversized = proof.fixture.inputs;
    oversized.manifest.bytes = producer.maximum_direct_manifest_bytes + 1;
    oversized.manifest.descriptor = -1;
    // The missing FD cannot become an allocation or a metadata probe: size is
    // refused before reading it or creating any staging entry.
    try std.testing.expectError(error.RuntimeInputLimit, producer.materializeSelectedArchive(io, a, proof.fixture.context, oversized, stage, &ledger));
    try std.testing.expectEqual(@as(usize, 0), ledger.entries.items.len);
    // The real selected legacy five-file archive remains artifact-only and
    // cannot be copied through the direct four-file production factory.
    try std.testing.expectError(error.InvalidRuntimeManifest, producer.materializeSelectedArchive(io, a, proof.fixture.context, proof.fixture.inputs, stage, &ledger));
    try std.testing.expectEqual(@as(usize, 0), ledger.entries.items.len);
    const bin = std.c.openat(stage, "bin", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (bin >= 0) _ = std.c.close(bin);
    try std.testing.expect(bin < 0 and std.c.errno(bin) == .NOENT);
}

test "ELF targeted string table disk size never becomes resident allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const a = fixture.arena.allocator();
    const bytes = try modelElf(a, true, "libc.so.6");
    // This size is structurally refused before allocating the advertised table
    // or trying to read a huge payload from a tiny held fixture file.
    put64(bytes, 344, 8 * 1024 * 1024 + 1);
    const path = try std.fmt.allocPrintSentinel(a, "{s}/oversized-elf-metadata", .{fixture.root}, 0);
    try write(path, bytes, 0o600);
    const fd = std.c.open(path.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
    try std.testing.expect(fd >= 0);
    defer _ = std.c.close(fd);
    try std.testing.expectError(error.InvalidRuntimeElf, artifact.elfDescription(a, .{ .io = io, .deadline = fixture.context.deadline }, fd, bytes.len, 512 * 1024 * 1024));
}
