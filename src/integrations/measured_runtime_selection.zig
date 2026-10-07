//! Local installed-byte selection only. R-HOOK-CONVERGENCE-20261004 / R-N13.
//! This does not verify original package/source provenance, execute an adapter,
//! attribute a process, grant credential access or establish native support.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const setup = @import("setup.zig");
const metadata = @import("../platform/file_metadata.zig");
const instance = @import("../instance.zig");
const paths = @import("../paths.zig");

pub const maximum_manifest_bytes = 256 * 1024;
pub const maximum_files = 4096;
pub const maximum_payload_bytes = 512 * 1024 * 1024;
pub const maximum_committed_bytes = 16 * 1024;
const receipt_path = "codex-installed-runtime.json";
const role_paths = [_][]const u8{
    "bin/codex", "lib/codex/libexec/codex.bin", "lib/codex/lib/ld-linux-x86-64.so.2",
};
pub const File = struct { sha256: [32]u8, bytes: u64, status: metadata.Metadata };
pub const Record = struct {
    schema_version: u8 = 1,
    qualification: enum { measured_installed_bytes_only } = .measured_installed_bytes_only,
    native_support: bool = false,
    channel: setup.RuntimeChannel,
    installation: setup.RuntimeInstallation,
    root: metadata.Metadata,
    manifest: File,
    roles: [3]File,
    file_count: u32,
    payload_bytes: u64,
};
pub const Committed = struct {
    record: Record,
    record_sha256: [32]u8,
    /// The actor snapshot revision that first selected these bytes.
    committed_revision: u64,

    pub fn validate(self: Committed, allocator: std.mem.Allocator, registry: ?setup.RegistryWitness, epoch: u64, revision: u64) !void {
        const encoded = try std.json.Stringify.valueAlloc(allocator, self, .{});
        defer allocator.free(encoded);
        if (encoded.len > maximum_committed_bytes) return error.InvalidMeasuredRuntimeSelection;
        const witness = registry orelse return error.InvalidMeasuredRuntimeSelection;
        const owned = self.record.installation;
        if (self.record.schema_version != 1 or self.record.native_support or
            self.committed_revision == 0 or self.committed_revision > revision or
            witness.phase != .installed or owned.adapter_epoch != epoch or
            !std.meta.eql(owned.transaction, witness.transaction) or
            !std.meta.eql(owned.capability_digest, witness.capability_digest) or
            owned.directory_device != self.record.root.dev or owned.directory_inode != self.record.root.ino or
            owned.uid != self.record.root.uid or owned.gid != self.record.root.gid or
            self.record.file_count < 4 or self.record.file_count > maximum_files or
            self.record.payload_bytes == 0 or self.record.payload_bytes > maximum_payload_bytes)
            return error.InvalidMeasuredRuntimeSelection;
        try directory(self.record.root, owned.uid, owned.gid, true);
        try validateFile(self.record.manifest, owned.uid, owned.gid, 0o600, maximum_manifest_bytes);
        for (self.record.roles, role_paths) |role, path| try validateFile(role, owned.uid, owned.gid, 0o755, try limit(path));
        if (!std.crypto.timing_safe.eql([32]u8, self.record_sha256, try digest(allocator, self.record))) return error.InvalidMeasuredRuntimeSelection;
    }

    /// Only an actor-owned completed removal may clear its exact selection.
    pub fn ownedBy(self: Committed, original: setup.RegistryWitness, epoch: u64) bool {
        const owned = self.record.installation;
        return original.phase == .installed and owned.adapter_epoch == epoch and
            std.meta.eql(owned.transaction, original.transaction) and
            std.meta.eql(owned.capability_digest, original.capability_digest);
    }
};
pub const Context = struct {
    options: setup.Options,
    selection: instance.Selection,
    revision: u64,
    deadline: std.Io.Clock.Timestamp,
    /// Immutable daemon-launch selector, explicitly not package provenance.
    installation_path: []const u8,
};
const HeldFile = struct { path: []u8, descriptor: c.fd_t, status: metadata.Metadata };
const Retained = struct {
    allocator: std.mem.Allocator,
    directory: c.fd_t,
    record: Record,
    revision: u64,
    snapshot_digest: [32]u8,
    files: []HeldFile,
};

/// Owns its duplicated root FD. No expected digest or client-authored record
/// can construct this carrier; observe measures real OS-held inputs.
pub const MeasuredInstalledRuntime = opaque {
    pub fn deinit(self: *MeasuredInstalledRuntime) void {
        const held: *Retained = @ptrCast(@alignCast(self));
        for (held.files) |held_file| {
            _ = c.close(held_file.descriptor);
            held.allocator.free(held_file.path);
        }
        held.allocator.free(held.files);
        _ = c.close(held.directory);
        held.allocator.destroy(held);
    }

    /// Called only by the serialized actor after its bounded worker completes.
    /// Rechecking is bounded and cancellation-aware; no perpetual authority.
    pub fn prepareCommit(self: *const MeasuredInstalledRuntime, io: std.Io, allocator: std.mem.Allocator, context: Context) !Committed {
        const held: *const Retained = @ptrCast(@alignCast(self));
        const custody = context.options.native_custody orelse return error.NativeCustodyPending;
        if (context.revision != held.revision or !std.meta.eql(custody.snapshot_digest, held.snapshot_digest)) return error.RuntimeSelectionDrift;
        const selected = try registryWitness(io, allocator, context);
        const owned = held.record.installation;
        if (owned.adapter_epoch != custody.adapter_epoch or
            held.record.channel != (if (context.selection == .dev) setup.RuntimeChannel.development else setup.RuntimeChannel.release) or
            !std.meta.eql(selected.transaction, owned.transaction) or !std.meta.eql(selected.capability_digest, owned.capability_digest)) return error.RuntimeSelectionDrift;
        try publishedRoot(allocator, context, held.directory, held.record.root);
        // Hashing ran on the bounded worker. At the actor commit boundary,
        // every OS-held descriptor and the published namespace are checked.
        // A same-user byte write changes ctime even if mtime is restored.
        for (held.files) |held_file| {
            try check(io, context);
            const current = try open(held.directory, held.record.root, held_file.path);
            defer _ = c.close(current);
            if (!std.meta.eql(held_file.status, try metadata.statFd(held_file.descriptor)) or
                !std.meta.eql(held_file.status, try metadata.statFd(current))) return error.RuntimeSelectionDrift;
        }
        try publishedRoot(allocator, context, held.directory, held.record.root);
        if (!std.meta.eql(selected, try registryWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
        return .{ .record = held.record, .record_sha256 = try digest(allocator, held.record), .committed_revision = try std.math.add(u64, context.revision, 1) };
    }
};

pub fn digest(allocator: std.mem.Allocator, record: Record) ![32]u8 {
    const encoded = try std.json.Stringify.valueAlloc(allocator, record, .{});
    defer allocator.free(encoded);
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &value, .{});
    return value;
}

/// The root comes from a user-authorized, Omux-owned installation operation,
/// never RPC/SCM_RIGHTS/PATH, argv, process maps or a peer self-description.
/// This observation cannot enter runtime_selection_producer.acquire or the
/// historical full-provenance setup.VerifiedRuntimeSelection contract.
pub fn observe(io: std.Io, allocator: std.mem.Allocator, context: Context, installation_directory: c.fd_t) !*MeasuredInstalledRuntime {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedRuntimeSelection;
    const duplicate = c.openat(installation_directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (duplicate < 0) return error.RuntimeInstallationUnavailable;
    errdefer _ = c.close(duplicate);
    var files: std.ArrayList(HeldFile) = .empty;
    errdefer {
        for (files.items) |held_file| {
            _ = c.close(held_file.descriptor);
            allocator.free(held_file.path);
        }
        files.deinit(allocator);
    }
    const record = try measure(io, allocator, context, duplicate, &files);
    const held = try allocator.create(Retained);
    errdefer allocator.destroy(held);
    held.* = .{ .allocator = allocator, .directory = duplicate, .record = record, .revision = context.revision, .snapshot_digest = context.options.native_custody.?.snapshot_digest, .files = try files.toOwnedSlice(allocator) };
    return @ptrCast(held);
}

fn check(io: std.Io, context: Context) !void {
    try io.checkCancel();
    if (context.deadline.clock != .awake) return error.InvalidDeadline;
    if (context.deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
}
fn registryWitness(io: std.Io, allocator: std.mem.Allocator, context: Context) !setup.RegistryWitness {
    try check(io, context);
    if (context.options.adapter != .codex) return error.UnsupportedAdapter;
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    try custody.validate();
    if (custody.state != .retain_ready or custody.registry_transaction == null or custody.registry_capability_digest == null) return error.NativeCustodyPending;
    var options = context.options;
    options.deadline = context.deadline;
    const selected = (try setup.registryWitness(io, allocator, options)) orelse return error.NativeCustodyPending;
    var capability: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&options.capability, &capability, .{});
    if (selected.phase != .installed or !std.meta.eql(selected.transaction, custody.registry_transaction.?) or
        !std.meta.eql(selected.capability_digest, custody.registry_capability_digest.?) or
        !std.meta.eql(selected.capability_digest, custody.capability_digest) or !std.meta.eql(capability, custody.capability_digest)) return error.RuntimeSelectionDrift;
    return selected;
}
fn directory(status: metadata.Metadata, uid: u32, gid: u32, root: bool) !void {
    if (uid != c.getuid() or status.uid != uid or status.gid != gid or
        status.mode & c.S.IFMT != c.S.IFDIR or status.mode & 0o7022 != 0 or
        (root and status.mode & 0o7777 != 0o700)) return error.RuntimeInstallationOwnershipMismatch;
}
fn validateFile(measured: File, uid: u32, gid: u32, mode: u32, maximum: u64) !void {
    // Both installed files and their held descriptors stay privately owned.
    const status = measured.status;
    if (measured.bytes == 0 or measured.bytes > maximum or std.mem.allEqual(u8, &measured.sha256, 0) or
        status.mode & c.S.IFMT != c.S.IFREG or status.mode & 0o7777 != mode or status.nlink != 1 or
        status.uid != uid or status.gid != gid or status.size <= 0 or @as(u64, @intCast(status.size)) != measured.bytes)
        return error.RuntimeInstallationOwnershipMismatch;
}
fn limit(path: []const u8) !u64 {
    // Paths are declared local payload members, never receipt-nominated roots.
    if (std.mem.eql(u8, path, receipt_path)) return maximum_manifest_bytes;
    if (std.mem.eql(u8, path, role_paths[0])) return 16 * 1024;
    if (std.mem.eql(u8, path, role_paths[1])) return maximum_payload_bytes;
    if (std.mem.eql(u8, path, "lib/codex/share/ca-bundle.crt")) return 16 * 1024 * 1024;
    if (std.mem.startsWith(u8, path, "lib/codex/lib/") and path.len > "lib/codex/lib/".len) {
        const name = path["lib/codex/lib/".len..];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidRuntimeManifest;
        for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-' and byte != '+') return error.InvalidRuntimeManifest;
        return 128 * 1024 * 1024;
    }
    return error.InvalidRuntimeManifest;
}
fn open(directory_fd: c.fd_t, root: metadata.Metadata, path: []const u8) !c.fd_t {
    _ = try limit(path);
    var parent = c.openat(directory_fd, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (parent < 0) return error.RuntimeInstallationUnavailable;
    defer _ = c.close(parent);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try directory(try metadata.statFd(parent), root.uid, root.gid, false);
        var name: [256:0]u8 = @splat(0);
        if (part.len == 0 or part.len >= name.len) return error.InvalidRuntimeManifest;
        @memcpy(name[0..part.len], part);
        const next = c.openat(parent, &name, if (parts.peek() == null) .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true } else .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0) return error.RuntimeInstallationUnavailable;
        if (parts.peek() == null) return next;
        _ = c.close(parent);
        parent = next;
    }
    return error.InvalidRuntimeManifest;
}
fn file(io: std.Io, context: Context, directory_fd: c.fd_t, root: metadata.Metadata, path: []const u8, mode: u32) !File {
    try check(io, context);
    const fd = try open(directory_fd, root, path);
    defer _ = c.close(fd);
    const before = try metadata.statFd(fd);
    if (before.size <= 0) return error.RuntimeInstallationOwnershipMismatch;
    var result: File = .{ .sha256 = @splat(1), .bytes = @intCast(before.size), .status = before };
    try validateFile(result, root.uid, root.gid, mode, try limit(path));
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < result.bytes) {
        try check(io, context);
        const count = c.pread(fd, &buffer, @intCast(@min(buffer.len, result.bytes - offset)), @intCast(offset));
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.RuntimeInstallationUnavailable;
        }
        if (count == 0) return error.RuntimeSelectionDrift;
        const length: usize = @intCast(count);
        hash.update(buffer[0..length]);
        offset += length;
    }
    var extra: [1]u8 = undefined;
    if (c.pread(fd, &extra, 1, @intCast(offset)) != 0) return error.RuntimeSelectionDrift;
    hash.final(&result.sha256);
    const reopened = try open(directory_fd, root, path);
    defer _ = c.close(reopened);
    if (!std.meta.eql(before, try metadata.statFd(fd)) or !std.meta.eql(before, try metadata.statFd(reopened))) return error.RuntimeSelectionDrift;
    return result;
}
fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidRuntimeManifest;
    return value.object.get(key) orelse error.InvalidRuntimeManifest;
}
fn equalString(value: std.json.Value, key: []const u8, expected: []const u8) !void {
    const actual = try get(value, key);
    if (actual != .string or !std.mem.eql(u8, actual.string, expected)) return error.InvalidRuntimeManifest;
}
fn integer(value: std.json.Value, key: []const u8, expected: i128) !void {
    const actual = try get(value, key);
    if (actual != .integer or @as(i128, actual.integer) != expected) return error.RuntimeSelectionDrift;
}
fn member(value: std.json.Value, measured: File) !void {
    if (value != .object or value.object.count() != 8) return error.InvalidRuntimeManifest;
    try equalString(value, "sha256", &std.fmt.bytesToHex(measured.sha256, .lower));
    try integer(value, "bytes", measured.bytes);
    try integer(value, "mode", measured.status.mode & 0o7777);
    try integer(value, "device", measured.status.dev);
    try integer(value, "inode", measured.status.ino);
    try integer(value, "mtime_ns", measured.status.mtime_ns);
    try integer(value, "ctime_ns", measured.status.ctime_ns);
    const state = try get(value, "state");
    if (state != .array or state.array.items.len != 9) return error.InvalidRuntimeManifest;
    const status = measured.status;
    const fields = [_]i128{ status.dev, status.ino, status.uid, status.gid, status.mode & 0o7777, status.nlink, status.size, status.mtime_ns, status.ctime_ns };
    for (state.array.items, fields) |actual, expected| if (actual != .integer or @as(i128, actual.integer) != expected) return error.RuntimeSelectionDrift;
}
fn publishedRoot(allocator: std.mem.Allocator, context: Context, descriptor: c.fd_t, expected: metadata.Metadata) !void {
    const published = try paths.openPrivateRoot(allocator, context.installation_path, false);
    defer _ = c.close(published);
    if (!std.meta.eql(expected, try metadata.statFd(descriptor)) or
        !std.meta.eql(expected, try metadata.statFd(published))) return error.RuntimeSelectionDrift;
}
fn retain(allocator: std.mem.Allocator, held_files: *std.ArrayList(HeldFile), directory_fd: c.fd_t, root: metadata.Metadata, path: []const u8, expected: metadata.Metadata) !void {
    const fd = try open(directory_fd, root, path);
    errdefer _ = c.close(fd);
    if (!std.meta.eql(expected, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try held_files.append(allocator, .{ .path = owned_path, .descriptor = fd, .status = expected });
}
fn measure(io: std.Io, allocator: std.mem.Allocator, context: Context, directory_fd: c.fd_t, held_files: *std.ArrayList(HeldFile)) !Record {
    const selected = try registryWitness(io, allocator, context);
    const root = try metadata.statFd(directory_fd);
    try directory(root, c.getuid(), root.gid, true);
    try publishedRoot(allocator, context, directory_fd, root);
    const manifest = try file(io, context, directory_fd, root, receipt_path, 0o600);
    try retain(allocator, held_files, directory_fd, root, receipt_path, manifest.status);
    const fd = try open(directory_fd, root, receipt_path);
    defer _ = c.close(fd);
    if (!std.meta.eql(manifest.status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    const bytes = try allocator.alloc(u8, @intCast(manifest.bytes));
    defer allocator.free(bytes);
    var offset: usize = 0;
    while (offset < bytes.len) {
        try check(io, context);
        const count = c.pread(fd, bytes[offset..].ptr, bytes.len - offset, @intCast(offset));
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.RuntimeInstallationUnavailable;
        }
        if (count == 0) return error.RuntimeSelectionDrift;
        offset += @intCast(count);
    }
    var encoded_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &encoded_digest, .{});
    if (!std.meta.eql(encoded_digest, manifest.sha256) or !std.meta.eql(manifest.status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .duplicate_field_behavior = .@"error", .max_value_len = maximum_manifest_bytes });
    defer parsed.deinit();
    const value = parsed.value;
    try integer(value, "schema_version", 1);
    try equalString(value, "kind", "omux-codex-installed-direct-exec");
    try equalString(value, "launch_profile", "linux-installed-direct-exec-v1");
    try equalString(value, "target", "x86_64-linux");
    try equalString(value, "actor_selection", "uncommitted");
    try equalString(value, "executable_attribution", "unproved");
    const support = try get(value, "native_support");
    if (support != .bool or support.bool) return error.InvalidRuntimeManifest;
    const installation = try get(value, "installation");
    try integer(installation, "directory_device", root.dev);
    try integer(installation, "directory_inode", root.ino);
    try integer(installation, "uid", root.uid);
    try integer(installation, "gid", root.gid);
    try integer(installation, "mode", 0o700);
    const files = try get(value, "files");
    if (files != .object or files.object.count() < 4 or files.object.count() > maximum_files) return error.InvalidRuntimeManifest;
    var roles: [3]File = undefined;
    var found: [3]bool = @splat(false);
    var total: u64 = 0;
    var iterator = files.object.iterator();
    while (iterator.next()) |entry| {
        const path = entry.key_ptr.*;
        if (std.mem.eql(u8, path, receipt_path)) return error.InvalidRuntimeManifest;
        const mode: u32 = if (std.mem.eql(u8, path, "lib/codex/share/ca-bundle.crt")) 0o644 else 0o755;
        const expected_bytes = try get(entry.value_ptr.*, "bytes");
        if (expected_bytes != .integer or expected_bytes.integer <= 0 or
            @as(u64, @intCast(expected_bytes.integer)) > maximum_payload_bytes - total) return error.RuntimeInputLimit;
        const measured = try file(io, context, directory_fd, root, path, mode);
        try member(entry.value_ptr.*, measured);
        try retain(allocator, held_files, directory_fd, root, path, measured.status);
        if (measured.bytes > maximum_payload_bytes - total) return error.RuntimeInputLimit;
        total += measured.bytes;
        for (role_paths, 0..) |role, index| if (std.mem.eql(u8, path, role)) {
            roles[index] = measured;
            found[index] = true;
        };
    }
    if (!std.mem.allEqual(bool, &found, true) or !files.object.contains("lib/codex/share/ca-bundle.crt")) return error.InvalidRuntimeManifest;
    // A second complete pass rejects a member replaced while a later member
    // was measured. Manifest bytes pin the complete declared membership.
    iterator = files.object.iterator();
    while (iterator.next()) |entry| {
        const path = entry.key_ptr.*;
        try member(entry.value_ptr.*, try file(io, context, directory_fd, root, path, if (std.mem.eql(u8, path, "lib/codex/share/ca-bundle.crt")) 0o644 else 0o755));
    }
    if (!std.meta.eql(manifest, try file(io, context, directory_fd, root, receipt_path, 0o600)) or
        !std.meta.eql(root, try metadata.statFd(directory_fd)) or !std.meta.eql(selected, try registryWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
    try check(io, context);
    const custody = context.options.native_custody.?;
    try publishedRoot(allocator, context, directory_fd, root);
    return .{
        .channel = if (context.selection == .dev) .development else .release,
        .installation = .{ .transaction = selected.transaction, .adapter_epoch = custody.adapter_epoch, .capability_digest = selected.capability_digest, .directory_device = root.dev, .directory_inode = root.ino, .uid = root.uid, .gid = root.gid },
        .root = root,
        .manifest = manifest,
        .roles = roles,
        .file_count = @intCast(files.object.count()),
        .payload_bytes = total,
    };
}
