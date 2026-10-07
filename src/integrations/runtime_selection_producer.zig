//! R-HOOK-CONVERGENCE-20261004 / R-N13: retained-descriptor acquisition.
//! This is an unwired internal foundation, never an RPC assertion or install
//! writer. Observation verifies independently selected bytes and all declared
//! installed files. It cannot authenticate package/source producer provenance,
//! tar membership or ELF lookup edges. acquire therefore refuses authority.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const setup = @import("setup.zig");
const instance = @import("../instance.zig");
const metadata = @import("../platform/file_metadata.zig");

pub const maximum_archive_bytes = 256 * 1024 * 1024;
pub const maximum_metadata_bytes = 16 * 1024 * 1024;
pub const maximum_files = 4096;
pub const maximum_payload_bytes = 512 * 1024 * 1024;
const maximum_backend_bytes = 512 * 1024 * 1024;
const maximum_library_bytes = 128 * 1024 * 1024;
const launcher = "bin/codex";
const backend = "lib/codex/libexec/codex.bin";
const loader = "lib/codex/lib/ld-linux-x86-64.so.2";
const ca_bundle = "lib/codex/share/ca-bundle.crt";

/// Borrowed descriptor, selected digest and exact byte count from independent
/// actor/deployment authority. A digest computed from the incoming input is not
/// a selection. Descriptor offsets are never consumed or changed by this API.
pub const Input = struct { descriptor: c.fd_t, sha256: [32]u8, bytes: u64 };
pub const Inputs = struct {
    archive: Input,
    manifest: Input,
    runtime_receipt: Input,
    source_receipt: Input,
    producer_receipt: Input,
    /// Retained installation root, supplied explicitly; no PATH or cwd search.
    installation_directory: c.fd_t,
};

/// In-process actor input only. Derive instance, custody, epoch, transaction and
/// capability from Engine's committed state. Never deserialize this from wire.
pub const ActorContext = struct {
    options: setup.Options,
    selection: instance.Selection,
    deadline: std.Io.Clock.Timestamp,
};

/// Complete production authority still needs a trusted raw package/source
/// verifier and an actor persistence boundary. No constructor exists here.
pub const ValidatedSelection = opaque {};

const FileObservation = struct {
    path: []const u8,
    sha256: [32]u8,
    bytes: u64,
    mode: u32,
    status: metadata.Metadata,
};
const Retained = struct {
    allocator: std.mem.Allocator,
    inputs: Inputs,
    statuses: [5]metadata.Metadata,
    registry: setup.RegistryWitness,
    context_digest: [32]u8,
    directory: metadata.Metadata,
    files: []FileObservation,
    payload_bytes: u64,
};

/// An opaque observation, explicitly excluded from selection authority. Its
/// contents are diagnostic installation facts; no credential or native state
/// is materialized. This object must never be serialized as a control reply.
pub const Observation = opaque {
    pub fn deinit(self: *Observation) void {
        const retained: *Retained = @ptrCast(@alignCast(self));
        for (retained.files) |file| retained.allocator.free(file.path);
        retained.allocator.free(retained.files);
        retained.allocator.destroy(retained);
    }

    pub fn fileCount(self: *const Observation) usize {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        return retained.files.len;
    }

    pub fn payloadBytes(self: *const Observation) u64 {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        return retained.payload_bytes;
    }

    /// Rehash every raw input and installed member under the original actor
    /// context. Same digest on a replacement inode is still selection drift.
    pub fn recheck(self: *const Observation, io: std.Io, context: ActorContext) !void {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        const budget: Budget = .{ .io = io, .deadline = context.deadline };
        const registry = try actorWitness(io, retained.allocator, context);
        if (!std.meta.eql(registry, retained.registry) or !std.meta.eql(try contextDigest(context), retained.context_digest)) return error.RuntimeSelectionDrift;
        const directory = try metadata.statFd(retained.inputs.installation_directory);
        if (!std.meta.eql(directory, retained.directory)) return error.RuntimeSelectionDrift;
        const selected = inputArray(retained.inputs);
        for (selected, retained.statuses, 0..) |input, status, index| {
            const after = try hashInput(budget, input, inputLimit(index));
            if (!std.meta.eql(status, after)) return error.RuntimeSelectionDrift;
        }
        for (retained.files) |file| {
            const after = try inspectFile(budget, retained.inputs.installation_directory, directory, file);
            if (!std.meta.eql(file.status, after)) return error.RuntimeSelectionDrift;
        }
        if (!std.meta.eql(directory, try metadata.statFd(retained.inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, retained.allocator, context))) return error.RuntimeSelectionDrift;
    }
};

/// Deliberate fail-closed production entrypoint. It collects real observations
/// but cannot turn them into producer provenance or actor-owned selection. A
/// future implementation must validate raw archive membership/ELF/source and
/// producer evidence before constructing ValidatedSelection; no success stub,
/// boolean verifier callback or caller-created token bypasses this boundary.
pub fn acquire(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs) !*ValidatedSelection {
    const observed = try observe(io, allocator, context, inputs);
    defer observed.deinit();
    return error.NativeArtifactVerifierUnavailable;
}

/// Bounded read-only acquisition of exact inputs and full declared installed
/// closure. This does not validate archive semantics, ELF dependency edges,
/// source inventories or build receipts; acquire remains unavailable.
pub fn observe(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs) !*Observation {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedRuntimeSelection;
    const budget: Budget = .{ .io = io, .deadline = context.deadline };
    try budget.check();
    const registry = try actorWitness(io, allocator, context);
    const directory = try metadata.statFd(inputs.installation_directory);
    try validateDirectory(directory);
    var statuses: [5]metadata.Metadata = undefined;
    for (inputArray(inputs), &statuses, 0..) |input, *status, index| status.* = try hashInput(budget, input, inputLimit(index));
    // Raw metadata is read only after digest/descriptor bounds pass. At most
    // four finite buffers are live, and each subsequent pass checks identity.
    const manifest_bytes = try readMetadata(allocator, budget, inputs.manifest, statuses[1]);
    defer allocator.free(manifest_bytes);
    const receipt_bytes = try readMetadata(allocator, budget, inputs.runtime_receipt, statuses[2]);
    defer allocator.free(receipt_bytes);
    const source_bytes = try readMetadata(allocator, budget, inputs.source_receipt, statuses[3]);
    defer allocator.free(source_bytes);
    const producer_bytes = try readMetadata(allocator, budget, inputs.producer_receipt, statuses[4]);
    defer allocator.free(producer_bytes);
    const manifest = try parse(allocator, manifest_bytes);
    defer manifest.deinit();
    const receipt = try parse(allocator, receipt_bytes);
    defer receipt.deinit();
    const source = try parse(allocator, source_bytes);
    defer source.deinit();
    const producer = try parse(allocator, producer_bytes);
    defer producer.deinit();
    try references(manifest.value, receipt.value, source.value, producer.value, inputs);
    const records = try objectField(manifest.value, "files");
    if (records.object.count() == 0 or records.object.count() > maximum_files) return error.RuntimeInputLimit;
    const files = try allocator.alloc(FileObservation, records.object.count());
    var owned: usize = 0;
    errdefer {
        for (files[0..owned]) |file| allocator.free(file.path);
        allocator.free(files);
    }
    var total: u64 = 0;
    var iterator = records.object.iterator();
    while (iterator.next()) |entry| {
        try budget.check();
        const path = entry.key_ptr.*;
        const mode: u32 = if (std.mem.eql(u8, path, ca_bundle)) 0o644 else 0o755;
        const limit = try pathLimit(path);
        const record = entry.value_ptr.*;
        if (record != .object or record.object.count() != 3) return error.InvalidRuntimeManifest;
        const bytes = try positiveInteger(record, "bytes");
        if (bytes > limit or bytes > maximum_payload_bytes - total or try positiveInteger(record, "mode") != mode) return error.RuntimeInputLimit;
        total += bytes;
        const digest = try digestField(record, "sha256");
        files[owned] = .{ .path = try allocator.dupe(u8, path), .sha256 = digest, .bytes = bytes, .mode = mode, .status = undefined };
        owned += 1;
        files[owned - 1].status = try inspectFile(budget, inputs.installation_directory, directory, files[owned - 1]);
    }
    try declaredMembership(manifest.value, files);
    if (!std.meta.eql(directory, try metadata.statFd(inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
    // Rehash raw evidence once more to reject replacement during collection.
    for (inputArray(inputs), statuses, 0..) |input, status, index| if (!std.meta.eql(status, try hashInput(budget, input, inputLimit(index)))) return error.RuntimeSelectionDrift;
    // Earlier members may change while later members or raw evidence are read.
    // Rewalk and rehash all retained member identities before returning facts.
    for (files) |file| if (!std.meta.eql(file.status, try inspectFile(budget, inputs.installation_directory, directory, file))) return error.RuntimeSelectionDrift;
    if (!std.meta.eql(directory, try metadata.statFd(inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
    try budget.check();
    const context_digest = try contextDigest(context);
    const retained = try allocator.create(Retained);
    retained.* = .{ .allocator = allocator, .inputs = inputs, .statuses = statuses, .registry = registry, .context_digest = context_digest, .directory = directory, .files = files, .payload_bytes = total };
    return @ptrCast(retained);
}

const Budget = struct {
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    fn check(self: Budget) !void {
        try self.io.checkCancel();
        if (self.deadline.clock != .awake) return error.InvalidDeadline;
        if (self.deadline.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
    }
};

fn actorWitness(io: std.Io, allocator: std.mem.Allocator, context: ActorContext) !setup.RegistryWitness {
    if (context.options.adapter != .codex) return error.UnsupportedAdapter;
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    try custody.validate();
    if (custody.state != .retain_ready and custody.state != .install_ready) return error.NativeCustodyPending;
    const transaction = custody.registry_transaction orelse return error.NativeCustodyPending;
    const capability = custody.registry_capability_digest orelse return error.NativeCustodyPending;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&context.options.capability, &digest, .{});
    if (!std.meta.eql(capability, digest) or !std.meta.eql(custody.capability_digest, digest)) return error.NativeCustodyGenerationMismatch;
    var options = context.options;
    options.deadline = context.deadline;
    const witness = (try setup.registryWitness(io, allocator, options)) orelse return error.NativeCustodyPending;
    if (witness.phase != .installed) return error.NativeCustodyPending;
    if (!std.meta.eql(witness.transaction, transaction) or !std.meta.eql(witness.capability_digest, capability)) return error.RuntimeSelectionDrift;
    return witness;
}

fn contextDigest(context: ActorContext) ![32]u8 {
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux-runtime-acquisition-v1\x00");
    hash.update(@tagName(context.selection));
    hash.update("\x00");
    hash.update(context.options.state_dir);
    var epoch: [8]u8 = undefined;
    std.mem.writeInt(u64, &epoch, custody.adapter_epoch, .little);
    hash.update(&epoch);
    hash.update(&custody.capability_digest);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn inputArray(inputs: Inputs) [5]Input {
    return .{ inputs.archive, inputs.manifest, inputs.runtime_receipt, inputs.source_receipt, inputs.producer_receipt };
}
fn inputLimit(index: usize) u64 {
    return if (index == 0) maximum_archive_bytes else maximum_metadata_bytes;
}
fn validateDirectory(status: metadata.Metadata) !void {
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.mode & 0o7022 != 0 or (status.uid != 0 and status.uid != c.getuid())) return error.UnsafeRuntimeInput;
}
fn regular(status: metadata.Metadata) !void {
    if (status.mode & c.S.IFMT != c.S.IFREG or status.mode & 0o7022 != 0 or status.nlink != 1 or status.size <= 0 or (status.uid != 0 and status.uid != c.getuid())) return error.UnsafeRuntimeInput;
}
fn readAt(budget: Budget, descriptor: c.fd_t, bytes: []u8, offset: u64) !usize {
    while (true) {
        try budget.check();
        const count = c.pread(descriptor, bytes.ptr, bytes.len, @intCast(offset));
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.RuntimeInputReadFailed;
        }
        return @intCast(count);
    }
}
fn hashInput(budget: Budget, input: Input, limit: u64) !metadata.Metadata {
    if (std.mem.allEqual(u8, &input.sha256, 0) or input.bytes == 0 or input.bytes > limit) return error.RuntimeInputLimit;
    const before = try metadata.statFd(input.descriptor);
    try regular(before);
    if (@as(u64, @intCast(before.size)) != input.bytes) return error.RuntimeSelectionDrift;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < input.bytes) {
        const length = try readAt(budget, input.descriptor, buffer[0..@intCast(@min(buffer.len, input.bytes - offset))], offset);
        if (length == 0) return error.RuntimeSelectionDrift;
        hash.update(buffer[0..length]);
        offset += length;
    }
    var extra: [1]u8 = undefined;
    if (try readAt(budget, input.descriptor, &extra, offset) != 0) return error.RuntimeSelectionDrift;
    const after = try metadata.statFd(input.descriptor);
    if (!std.meta.eql(before, after)) return error.RuntimeSelectionDrift;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    if (!std.meta.eql(digest, input.sha256)) return error.RuntimeSelectionDrift;
    return after;
}
fn readMetadata(allocator: std.mem.Allocator, budget: Budget, input: Input, status: metadata.Metadata) ![]u8 {
    const bytes = try allocator.alloc(u8, @intCast(input.bytes));
    errdefer allocator.free(bytes);
    var offset: usize = 0;
    while (offset < bytes.len) {
        const length = try readAt(budget, input.descriptor, bytes[offset..@min(bytes.len, offset + 64 * 1024)], offset);
        if (length == 0) return error.RuntimeSelectionDrift;
        offset += length;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.meta.eql(digest, input.sha256) or !std.meta.eql(status, try metadata.statFd(input.descriptor))) return error.RuntimeSelectionDrift;
    return bytes;
}
fn openMember(budget: Budget, directory: c.fd_t, owner: metadata.Metadata, path: []const u8) !c.fd_t {
    _ = try pathLimit(path);
    var parent = c.openat(directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (parent < 0) return error.UnsafeRuntimeInput;
    defer _ = c.close(parent);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try budget.check();
        const status = try metadata.statFd(parent);
        try validateDirectory(status);
        if (status.uid != owner.uid or status.gid != owner.gid) return error.UnsafeRuntimeInput;
        var name: [256:0]u8 = @splat(0);
        if (part.len >= name.len) return error.InvalidRuntimeManifest;
        @memcpy(name[0..part.len], part);
        if (parts.peek() != null) {
            const next = c.openat(parent, &name, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
            if (next < 0) return error.UnsafeRuntimeInput;
            _ = c.close(parent);
            parent = next;
        } else {
            const file = c.openat(parent, &name, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
            if (file < 0) return error.UnsafeRuntimeInput;
            return file;
        }
    }
    return error.InvalidRuntimeManifest;
}
fn inspectFile(budget: Budget, directory: c.fd_t, owner: metadata.Metadata, file: FileObservation) !metadata.Metadata {
    const descriptor = try openMember(budget, directory, owner, file.path);
    defer _ = c.close(descriptor);
    const after = try hashInput(budget, .{ .descriptor = descriptor, .sha256 = file.sha256, .bytes = file.bytes }, try pathLimit(file.path));
    // Immutable Nix mode normalization is not qualified by this foundation.
    if (after.mode & 0o7777 != file.mode or after.uid != owner.uid or after.gid != owner.gid) return error.UnsafeRuntimeInput;
    const reopened = try openMember(budget, directory, owner, file.path);
    defer _ = c.close(reopened);
    if (!std.meta.eql(after, try metadata.statFd(reopened))) return error.RuntimeSelectionDrift;
    return after;
}

fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .duplicate_field_behavior = .@"error", .max_value_len = maximum_metadata_bytes });
}
fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidRuntimeManifest;
    return value.object.get(name) orelse error.InvalidRuntimeManifest;
}
fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    const child = try field(value, name);
    if (child != .object) return error.InvalidRuntimeManifest;
    return child;
}
fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const child = try field(value, name);
    if (child != .string) return error.InvalidRuntimeManifest;
    return child.string;
}
fn positiveInteger(value: std.json.Value, name: []const u8) !u64 {
    const child = try field(value, name);
    if (child != .integer or child.integer <= 0) return error.InvalidRuntimeManifest;
    return @intCast(child.integer);
}
fn digestField(value: std.json.Value, name: []const u8) ![32]u8 {
    const text = try stringField(value, name);
    if (text.len != 64) return error.InvalidRuntimeManifest;
    for (text) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeManifest;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, text);
    if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidRuntimeManifest;
    return digest;
}
fn pathLimit(path: []const u8) !u64 {
    if (std.mem.eql(u8, path, launcher)) return 16 * 1024;
    if (std.mem.eql(u8, path, backend)) return maximum_backend_bytes;
    if (std.mem.eql(u8, path, ca_bundle)) return 16 * 1024 * 1024;
    const prefix = "lib/codex/lib/";
    if (!std.mem.startsWith(u8, path, prefix) or path.len <= prefix.len or path.len > prefix.len + 255) return error.InvalidRuntimeManifest;
    const basename = path[prefix.len..];
    if (std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidRuntimeManifest;
    for (basename) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '+' and byte != '-') return error.InvalidRuntimeManifest;
    return maximum_library_bytes;
}
fn references(manifest: std.json.Value, receipt: std.json.Value, source: std.json.Value, producer: std.json.Value, inputs: Inputs) !void {
    for ([_]std.json.Value{ manifest, receipt }) |value| {
        if (try positiveInteger(value, "schema_version") != 1 or !std.mem.eql(u8, try stringField(value, "status"), "native-owner-runtime-proof-candidate")) return error.InvalidRuntimeManifest;
        const support = try field(value, "native_support");
        if (support != .bool or support.bool) return error.InvalidRuntimeManifest;
    }
    if (!std.mem.eql(u8, try stringField(manifest, "target"), "x86_64-linux") or !std.meta.eql(try digestField(receipt, "archive_sha256"), inputs.archive.sha256) or try positiveInteger(receipt, "archive_bytes") != inputs.archive.bytes or !std.meta.eql(try digestField(receipt, "manifest_sha256"), inputs.manifest.sha256)) return error.RuntimeSelectionDrift;
    const transform = try objectField(manifest, "transformations");
    const candidate = try objectField(manifest, "candidate");
    if (!std.meta.eql(try digestField(transform, "source_receipt_sha256"), inputs.source_receipt.sha256) or !std.meta.eql(try digestField(transform, "producer_receipt_sha256"), inputs.producer_receipt.sha256) or !std.meta.eql(try digestField(candidate, "current_source_receipt_sha256"), inputs.source_receipt.sha256)) return error.RuntimeSelectionDrift;
    // Structural cross-references only; these do not establish a build result.
    const commit = try stringField(candidate, "upstream_commit");
    if (commit.len != 40 or !std.mem.eql(u8, commit, try stringField(source, "commit")) or !std.mem.eql(u8, commit, try stringField(producer, "upstream_commit")) or !std.meta.eql(try digestField(producer, "current_source_receipt_sha256"), inputs.source_receipt.sha256)) return error.RuntimeSelectionDrift;
    const runtime = try objectField(manifest, "runtime");
    if (!std.mem.eql(u8, try stringField(runtime, "loader"), loader) or !std.mem.eql(u8, try stringField(runtime, "caBundle"), ca_bundle)) return error.InvalidRuntimeManifest;
}
fn declaredMembership(manifest: std.json.Value, files: []const FileObservation) !void {
    const runtime = try objectField(manifest, "runtime");
    const dependencies = try field(runtime, "dependencies");
    if (dependencies != .array or dependencies.array.items.len == 0 or dependencies.array.items.len + 3 != files.len) return error.InvalidRuntimeManifest;
    const records = try objectField(manifest, "files");
    for ([_][]const u8{ launcher, backend, ca_bundle, loader }) |name| if (!records.object.contains(name)) return error.InvalidRuntimeManifest;
    var previous: ?[]const u8 = null;
    for (dependencies.array.items) |dependency| {
        if (dependency != .string or !std.mem.startsWith(u8, dependency.string, "lib/codex/lib/") or !records.object.contains(dependency.string)) return error.InvalidRuntimeManifest;
        _ = try pathLimit(dependency.string);
        if (previous) |name| if (std.mem.order(u8, name, dependency.string) != .lt) return error.InvalidRuntimeManifest;
        previous = dependency.string;
    }
}
