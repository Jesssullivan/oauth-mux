//! Read-only, bounded receipt collector. No shell or service activation.
//! A receipt is local ownership authority, not release provenance. Legacy
//! install.json without artifact metadata retains unknown channel. Home Manager
//! uses an explicit immutable digest-bound ownership witness;
//! neither a /nix/store path nor an environment variable substitutes for one.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const paths = @import("paths.zig");
const metadata = @import("platform/file_metadata.zig");
const evidence = @import("setup_evidence.zig");
const onboarding = @import("onboarding.zig");
const self_image = @import("self_image.zig");

pub const max_receipt_bytes = 256 * 1024;
// Portable bundle members plus Home Manager's independently hashed manifest.
pub const max_files = 257;
pub const max_file_bytes = 128 * 1024 * 1024;
pub const max_payload_bytes = 512 * 1024 * 1024;
pub const max_path_bytes = 4096;
pub const max_collection_ms = 2000;
pub const InstallationHints = struct { prefix: []const u8, receipt_path: []const u8 };

/// A packaged launcher may name its prefix before the user has installed an
/// ownership receipt. A supplied receipt is an explicit selector and requires
/// its matching prefix. Neither case discovers or establishes ownership.
pub fn selectInstallationHints(prefix: ?[]const u8, record: ?[]const u8) error{InvalidInstallationSelection}!?InstallationHints {
    const receipt_path = record orelse return null;
    const selected_prefix = prefix orelse return error.InvalidInstallationSelection;
    if (selected_prefix.len > max_path_bytes or receipt_path.len > max_path_bytes) return error.InvalidInstallationSelection;
    paths.validateAbsolute(selected_prefix) catch return error.InvalidInstallationSelection;
    paths.validateAbsolute(receipt_path) catch return error.InvalidInstallationSelection;
    return .{ .prefix = selected_prefix, .receipt_path = receipt_path };
}
pub const Options = struct {
    /// Explicit installation ownership-record root, not inferred daemon state.
    receipt_path: []const u8,
    prefix: []const u8,
    /// Caller-selected definition location; receipt cannot nominate arbitrary
    /// paths outside the prefix without this exact independent selection.
    service_path: ?[]const u8 = null,
    /// Optional immutable Home Manager service record selector. It conveys no
    /// ownership until the bounded record and actual final links are verified.
    service_record_path: ?[]const u8 = null,
    deadline: std.Io.Clock.Timestamp,
};
pub const Failure = enum { none, receipt_absent, invalid_receipt, unsafe_path, unsafe_file, changed_file, limit_exceeded, read_failed, metadata_unavailable, timed_out, cancelled, resource_exhausted, invalid_deadline };

pub fn failureForError(err: anyerror) Failure {
    return switch (err) {
        error.Timeout => .timed_out,
        error.Canceled => .cancelled,
        error.OutOfMemory => .resource_exhausted,
        error.InvalidDeadline => .invalid_deadline,
        else => .read_failed,
    };
}
pub const Collected = struct {
    artifact: evidence.Artifact = .{},
    service: evidence.Service = .{},
    failure: Failure = .none,
    self_image_status: self_image.Status = .unobserved,
    /// Internal verified custody, excluded from every JSON control response.
    service_witness: ?ServiceWitness = null,

    pub fn jsonStringify(self: Collected, writer: anytype) !void {
        try writer.write(.{ .artifact = self.artifact, .service = self.service, .failure = self.failure, .self_image_status = self.self_image_status });
    }
};

/// A later observation of the same backing inode replaces earlier acceptance.
/// Unrelated receipt roles never enter this boundary or erase its diagnostic.
pub fn applySelfImageRecheck(result: *Collected, prefix: []const u8, path: []const u8, before: self_image.Witness, current: self_image.Observation, file: metadata.Metadata, hashed: metadata.Metadata, reopened: metadata.Metadata, bytes_match: bool) void {
    result.artifact.running_executable = .unknown;
    result.self_image_status = current.status;
    if (current.witness) |latest| {
        if (self_image.acceptsReceiptImage(prefix, path, before, latest, file, hashed, reopened)) {
            result.artifact.running_executable = if (bytes_match) .matches else .differs;
            result.self_image_status = if (bytes_match) .bound else .image_bytes_mismatch;
        } else result.self_image_status = .mapping_changed;
    }
}

fn noteSelfImageRolePathChanged(result: *Collected) void {
    if (result.self_image_status == .observed or result.self_image_status == .role_identity_mismatch) result.self_image_status = .role_path_changed;
}
pub const ServiceWitness = struct {
    path_buffer: [max_path_bytes + 1]u8 = @splat(0),
    path_len: u16,
    sha256: [32]u8,
    file: metadata.Metadata,
    login_link: evidence.Probe = .unknown,
    source_buffer: [max_path_bytes + 1]u8 = @splat(0),
    source_len: u16 = 0,
    installed_link: ?metadata.Metadata = null,
    // Exact immutable Home Manager leaf custody, never serialized to clients.
    managed: ?ManagedWitness = null,

    pub fn fragment(self: *const ServiceWitness) [:0]const u8 {
        return self.path_buffer[0..self.path_len :0];
    }
    fn source(self: *const ServiceWitness) [:0]const u8 {
        return if (self.source_len == 0) self.fragment() else self.source_buffer[0..self.source_len :0];
    }

    pub fn jsonStringify(self: ServiceWitness, writer: anytype) !void {
        try writer.write(.{ .kind = "internal_definition_witness", .login_link = self.login_link });
    }
};
pub const Entry = struct { path: []const u8, sha256: []const u8, mode: u32 };
pub const ArtifactMetadata = struct {
    channel: ?[]const u8 = null,
    manifestSha256: ?[]const u8 = null,
    archiveSha256: ?[]const u8 = null,
};
pub const Receipt = struct {
    schemaVersion: u32,
    prefix: []const u8,
    userService: ?[]const u8 = null,
    serviceActivated: bool = false,
    owner: ?[]const u8 = null,
    artifact: ?ArtifactMetadata = null,
    files: []const Entry,
};
pub const ServiceRecord = struct {
    schemaVersion: u32,
    owner: []const u8,
    channel: []const u8,
    instance: []const u8,
    artifactManifestSha256: []const u8,
    unit: struct {
        name: []const u8,
        installedPath: []const u8,
        sourcePath: []const u8,
        sha256: []const u8,
        mode: u32,
    },
    login: struct { installedPath: []const u8, sourcePath: []const u8 },
    scope: []const u8,
};

pub fn receiptOwnership(receipt: Receipt) !onboarding.Ownership {
    const owner = receipt.owner orelse return .installation_receipt;
    if (std.mem.eql(u8, owner, "home-manager")) return .home_manager;
    if (std.mem.eql(u8, owner, "installation-receipt")) return .installation_receipt;
    return error.InvalidReceipt;
}

pub fn receiptChannel(receipt: Receipt) !onboarding.Channel {
    const artifact = receipt.artifact orelse return .unknown;
    if (artifact.manifestSha256) |digest| try validateDigest(digest);
    if (artifact.archiveSha256) |digest| try validateDigest(digest);
    const channel = artifact.channel orelse return .unknown;
    if (artifact.manifestSha256 == null) return error.InvalidReceipt;
    if (std.mem.eql(u8, channel, "development") or std.mem.eql(u8, channel, "dev")) return .development;
    if (std.mem.eql(u8, channel, "release")) return .release;
    if (std.mem.eql(u8, channel, "unknown")) return .unknown;
    return error.InvalidReceipt;
}

fn validateDigest(digest: []const u8) !void {
    if (digest.len != 64) return error.InvalidReceipt;
    for (digest) |digit| if (!std.ascii.isHex(digit)) return error.InvalidReceipt;
}

/// Evidence is monotone within one collection: a later absence cannot hide a
/// previously observed mismatch. Unknown never upgrades a verified absence.
pub fn mergeProbe(previous: evidence.Probe, next: evidence.Probe) evidence.Probe {
    if (previous == .differs or next == .differs) return .differs;
    if (previous == .absent or next == .absent) return .absent;
    if (previous == .unknown or next == .unknown) return .unknown;
    return .matches;
}

/// Pure validation, also used before any receipt-nominated payload is opened.
pub fn validateReceipt(receipt: Receipt, prefix: []const u8, service_path: ?[]const u8) !void {
    if (prefix.len > max_path_bytes) return error.InvalidReceipt;
    paths.validateAbsolute(prefix) catch return error.InvalidReceipt;
    const ownership = try receiptOwnership(receipt);
    _ = try receiptChannel(receipt);
    if (ownership == .home_manager and !std.mem.startsWith(u8, prefix, "/nix/store/")) return error.InvalidReceipt;
    if (receipt.schemaVersion != 1 or !std.mem.eql(u8, receipt.prefix, prefix) or receipt.files.len == 0 or receipt.files.len > max_files) return error.InvalidReceipt;
    if (receipt.userService) |service| {
        if (service_path == null or !std.mem.eql(u8, service, service_path.?)) return error.InvalidReceipt;
    }
    var required = [_]bool{ false, false, false };
    for (receipt.files, 0..) |entry, index| {
        if (entry.path.len > max_path_bytes) return error.InvalidReceipt;
        paths.validateAbsolute(entry.path) catch return error.InvalidReceipt;
        if (entry.mode != 0o600 and entry.mode != 0o644 and entry.mode != 0o755) return error.InvalidReceipt;
        try validateDigest(entry.sha256);
        const inside = entry.path.len > prefix.len + 1 and std.mem.startsWith(u8, entry.path, prefix) and entry.path[prefix.len] == '/';
        const selected_service = if (service_path) |selected| std.mem.eql(u8, entry.path, selected) else false;
        if (!inside and !selected_service) return error.InvalidReceipt;
        for (receipt.files[0..index]) |earlier| if (std.mem.eql(u8, entry.path, earlier.path)) return error.InvalidReceipt;
        if (inside) {
            const relative = entry.path[prefix.len + 1 ..];
            for ([_][]const u8{ "bin/omux", "bin/omuxd", "bin/omux-native-host" }, 0..) |name, required_index| {
                if (std.mem.eql(u8, relative, name) and entry.mode == 0o755) required[required_index] = true;
            }
        }
    }
    for (required) |present| if (!present) return error.InvalidReceipt;
}

pub fn collect(io: std.Io, allocator: std.mem.Allocator, options: Options) !Collected {
    try check(io, options.deadline);
    var bounded = options;
    if (options.deadline.durationFromNow(io).raw.toMilliseconds() > max_collection_ms) bounded.deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(max_collection_ms) });
    return collectInner(io, allocator, bounded) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
        else => .{ .artifact = if (err == error.FileNotFound) .{ .ownership_record = .absent, .freshness = .current } else .{}, .failure = switch (err) {
            error.FileNotFound => .receipt_absent,
            error.InvalidReceipt => .invalid_receipt,
            error.UnsafePath => .unsafe_path,
            error.UnsafeFile => .unsafe_file,
            error.ChangedFile => .changed_file,
            error.LimitExceeded => .limit_exceeded,
            error.ReadFailed => .read_failed,
            else => .metadata_unavailable,
        } },
    };
}

fn check(io: std.Io, deadline: std.Io.Clock.Timestamp) !void {
    try io.checkCancel();
    if (deadline.clock != .awake) return error.InvalidDeadline;
    if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
}

fn collectInner(io: std.Io, allocator: std.mem.Allocator, options: Options) !Collected {
    try check(io, options.deadline);
    const receipt_opened = try openReceipt(io, allocator, options.receipt_path, .{}, options.deadline);
    const receipt_fd = receipt_opened.fd;
    defer _ = c.close(receipt_fd);
    const before = try metadata.statFd(receipt_fd);
    if (before.nlink < 1 or (receipt_opened.managed == null and before.nlink != 1)) return error.UnsafeFile;
    if (before.size < 0 or before.size > max_receipt_bytes) return error.LimitExceeded;
    const bytes = try allocator.alloc(u8, @intCast(before.size));
    defer allocator.free(bytes);
    try readExact(io, options.deadline, receipt_fd, bytes);
    if (!std.meta.eql(before, try metadata.statFd(receipt_fd))) return error.ChangedFile;
    const parsed = std.json.parseFromSlice(Receipt, allocator, bytes, .{ .ignore_unknown_fields = true, .max_value_len = max_receipt_bytes }) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidReceipt;
    };
    defer parsed.deinit();
    const receipt = parsed.value;
    try validateReceipt(receipt, options.prefix, options.service_path);
    const ownership = try receiptOwnership(receipt);
    if (ownership == .home_manager) {
        if (receipt_opened.managed == null or before.uid != 0 or before.mode & 0o222 != 0) return error.UnsafeFile;
    } else if (receipt_opened.managed != null or before.uid != c.getuid() or before.mode & 0o777 != 0o600 or before.nlink != 1) return error.UnsafeFile;
    var result: Collected = .{ .artifact = .{ .channel = try receiptChannel(receipt), .ownership = ownership, .ownership_record = .matches, .freshness = .current, .payload = .matches }, .service = .{ .freshness = .current } };
    // The known code address identifies our backing image even when portable
    // launch executes a loader. Neither /proc/self/exe nor any library receipt
    // entry can substitute for an exact daemon-role image binding.
    const anchor = @intFromPtr(&collect);
    const self_observation = try self_image.observeDetailed(io, allocator, options.deadline, anchor);
    const self_mapping = self_observation.witness;
    result.self_image_status = self_observation.status;
    var daemon_role_seen = false;
    var total_bytes: u64 = 0;
    for (receipt.files) |entry| {
        try check(io, options.deadline);
        const fd = openRegular(allocator, entry.path) catch |err| {
            if (err == error.OutOfMemory) return err;
            if (err != error.FileNotFound) return err;
            result.artifact.payload = mergeProbe(result.artifact.payload, .absent);
            if (options.service_path) |service| {
                if (std.mem.eql(u8, service, entry.path)) result.service.definition = .absent;
            }
            continue;
        };
        defer _ = c.close(fd);
        const status = try metadata.statFd(fd);
        if (self_image.daemonRole(options.prefix, entry.path)) {
            daemon_role_seen = true;
            if (self_mapping != null and result.self_image_status == .observed) result.self_image_status = .role_identity_mismatch;
        }
        if (ownership == .home_manager and (status.uid != 0 or status.mode & 0o222 != 0)) return error.UnsafeFile;
        if (status.size < 0 or status.size > max_file_bytes) return error.LimitExceeded;
        total_bytes += @intCast(status.size);
        if (total_bytes > max_payload_bytes) return error.LimitExceeded;
        const digest = try hashFile(io, options.deadline, fd, status);
        const hex = std.fmt.bytesToHex(digest, .lower);
        const expected_mode = if (ownership == .home_manager) entry.mode & ~@as(u32, 0o222) else entry.mode;
        const matches = std.ascii.eqlIgnoreCase(&hex, entry.sha256) and status.mode & 0o777 == expected_mode;
        result.artifact.payload = mergeProbe(result.artifact.payload, if (matches) .matches else .differs);
        if (options.service_path) |service| {
            if (std.mem.eql(u8, service, entry.path)) {
                result.service.definition = if (matches) .matches else .differs;
                if (matches) {
                    var witness: ServiceWitness = .{ .path_len = @intCast(service.len), .sha256 = digest, .file = status };
                    @memcpy(witness.path_buffer[0..service.len], service);
                    witness.login_link = try inspectLoginLink(io, allocator, &witness, options.deadline);
                    result.service_witness = witness;
                }
            }
        }
        if (self_mapping) |running| {
            if (self_image.daemonRole(options.prefix, entry.path) and running.matchesFile(status)) {
                const current_fd = openRegular(allocator, entry.path) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {
                        noteSelfImageRolePathChanged(&result);
                        continue;
                    },
                };
                defer _ = c.close(current_fd);
                const current_file = metadata.statFd(current_fd) catch {
                    noteSelfImageRolePathChanged(&result);
                    continue;
                };
                const hashed_file = try metadata.statFd(fd);
                if (!std.meta.eql(status, hashed_file) or !std.meta.eql(status, current_file)) {
                    noteSelfImageRolePathChanged(&result);
                    continue;
                }
                const current_mapping = try self_image.observeDetailed(io, allocator, options.deadline, anchor);
                applySelfImageRecheck(&result, options.prefix, entry.path, running, current_mapping, status, hashed_file, current_file, matches);
            }
        }
    }
    if (self_mapping != null and !daemon_role_seen) result.self_image_status = .role_missing;
    // Receipt serviceActivated is deliberately ignored. Login startup and
    // service-manager PID/instance binding need independent live native probes.
    if (ownership == .home_manager and result.artifact.payload == .matches and result.artifact.running_executable == .matches and options.service_record_path != null) {
        const witness = collectHomeManagerService(io, allocator, receipt, options) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
            else => null,
        };
        if (witness) |verified| {
            result.service.definition = .matches;
            result.service_witness = verified;
        }
    }
    try check(io, options.deadline);
    if (!std.meta.eql(before, try metadata.statFd(receipt_fd))) return error.ChangedFile;
    if (receipt_opened.managed) |*proof| {
        var receipt_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &receipt_digest, .{});
        if ((try recheckManagedPath(io, allocator, proof, .{}, &receipt_digest, options.deadline)) != .matches) return error.ChangedFile;
    }
    return result;
}

/// Recheck after service-manager observation before publishing any binding.
/// Metadata and bytes must still match the independently selected definition.
pub fn recheckServiceWitness(io: std.Io, allocator: std.mem.Allocator, witness: *const ServiceWitness, deadline: std.Io.Clock.Timestamp) !evidence.Probe {
    try check(io, deadline);
    if (witness.managed) |*managed| {
        const record = try recheckManagedPath(io, allocator, &managed.record, managed.policy(), &managed.record_sha256, deadline);
        if (record != .matches) return record;
        return recheckManagedPath(io, allocator, &managed.unit, managed.policy(), &witness.sha256, deadline);
    }
    if (witness.installed_link) |original| {
        const link = readOwnedLink(allocator, witness.fragment()) catch |err| {
            if (err == error.OutOfMemory) return err;
            return if (err == error.FileNotFound) .absent else .differs;
        };
        defer link.deinit(allocator);
        if (!std.meta.eql(original, link.file) or !std.mem.eql(u8, link.target, witness.source())) return .differs;
    }
    const fd = openRegular(allocator, witness.source()) catch |err| {
        if (err == error.OutOfMemory) return err;
        return if (err == error.FileNotFound) .absent else .differs;
    };
    defer _ = c.close(fd);
    const status = try metadata.statFd(fd);
    if (!std.meta.eql(status, witness.file)) return .differs;
    const digest = try hashFile(io, deadline, fd, status);
    return if (std.mem.eql(u8, &digest, &witness.sha256)) .matches else .differs;
}

pub fn recheckLoginLink(io: std.Io, allocator: std.mem.Allocator, witness: *const ServiceWitness, deadline: std.Io.Clock.Timestamp) !evidence.Probe {
    return inspectLoginLink(io, allocator, witness, deadline);
}

fn inspectLoginLink(io: std.Io, allocator: std.mem.Allocator, witness: *const ServiceWitness, deadline: std.Io.Clock.Timestamp) !evidence.Probe {
    try check(io, deadline);
    if (witness.managed) |*managed| {
        if (managed.login) |*login| return recheckManagedPath(io, allocator, login, managed.policy(), &witness.sha256, deadline);
        // A managed generation cannot silently fall back to another spelling.
        if (managed.unit.generation_len != 0) return .differs;
    }
    const fragment = witness.fragment();
    const directory = std.fs.path.dirname(fragment) orelse return .unknown;
    const link_path = try std.fmt.allocPrint(allocator, "{s}/default.target.wants/{s}", .{ directory, std.fs.path.basename(fragment) });
    defer allocator.free(link_path);
    const parent = openParent(allocator, link_path) catch |err| {
        if (err == error.OutOfMemory) return err;
        return if (err == error.FileNotFound) .absent else .unknown;
    };
    defer parent.deinit(allocator);
    const before = metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW) catch |err| {
        return if (err == error.FileNotFound) .absent else .unknown;
    };
    if (before.mode & c.S.IFMT != c.S.IFLNK or before.uid != c.getuid() or before.nlink != 1) return .differs;
    var target: [max_path_bytes]u8 = undefined;
    const length = c.readlinkat(parent.fd, parent.name.ptr, &target, target.len);
    if (length <= 0 or length >= target.len) return .unknown;
    const after = try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW);
    if (!std.meta.eql(before, after)) return .differs;
    // Accept only the two exact link spellings we can bind by descriptor.
    // Lexical normalization of alias/../unit does not describe kernel lookup
    // when alias is a symlink, absent, or a nondirectory.
    const expected_relative = try std.fmt.allocPrint(allocator, "../{s}", .{std.fs.path.basename(fragment)});
    defer allocator.free(expected_relative);
    const actual = target[0..@intCast(length)];
    try check(io, deadline);
    const absolute_target = if (witness.installed_link != null) witness.source() else fragment;
    return if (std.mem.eql(u8, actual, absolute_target) or std.mem.eql(u8, actual, expected_relative)) .matches else .differs;
}

const OwnedLink = struct {
    target: []u8,
    file: metadata.Metadata,
    fn deinit(self: OwnedLink, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
    }
};

/// Only the final component may be a symlink; all parents are opened NOFOLLOW.
fn readOwnedLink(allocator: std.mem.Allocator, path: []const u8) !OwnedLink {
    const parent = try openParent(allocator, path);
    defer parent.deinit(allocator);
    return readLinkAt(allocator, parent, c.getuid());
}

fn readLinkAt(allocator: std.mem.Allocator, parent: Parent, uid: u32) !OwnedLink {
    const before = try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW);
    if (before.mode & c.S.IFMT != c.S.IFLNK or before.uid != uid or before.nlink != 1) return error.UnsafeFile;
    var buffer: [max_path_bytes]u8 = undefined;
    const length = c.readlinkat(parent.fd, parent.name.ptr, &buffer, buffer.len);
    if (length <= 0 or length >= buffer.len) return error.UnsafeFile;
    if (!std.meta.eql(before, try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW))) return error.ChangedFile;
    return .{ .target = try allocator.dupe(u8, buffer[0..@intCast(length)]), .file = before };
}

const ManagedStore = struct { root: []const u8 = "/nix/store", uid: u32 = 0 };
fn immutableStorePath(path: []const u8, store: ManagedStore) bool {
    paths.validateAbsolute(path) catch return false;
    return path.len <= max_path_bytes and path.len > store.root.len + 1 and std.mem.startsWith(u8, path, store.root) and path[store.root.len] == '/';
}

// One generation leaf is the pinned Home Manager topology, not permission to
// resolve arbitrary symlink chains. All path buffers and parent walks are bounded.
const max_managed_parents = 32;
const ManagedPath = struct {
    selected_buffer: [max_path_bytes + 1]u8 = @splat(0),
    selected_len: u16 = 0,
    source_buffer: [max_path_bytes + 1]u8 = @splat(0),
    source_len: u16 = 0,
    generation_buffer: [max_path_bytes + 1]u8 = @splat(0),
    generation_len: u16 = 0,
    selected_link: ?metadata.Metadata = null,
    generation_link: ?metadata.Metadata = null,
    generation_parents: [32]u8 = @splat(0),
    source_parents: [32]u8 = @splat(0),
    file: metadata.Metadata,

    fn selected(self: *const ManagedPath) [:0]const u8 {
        return self.selected_buffer[0..self.selected_len :0];
    }
    fn source(self: *const ManagedPath) [:0]const u8 {
        return self.source_buffer[0..self.source_len :0];
    }
    fn generation(self: *const ManagedPath) []const u8 {
        return self.generation_buffer[0..self.generation_len];
    }
};
const ManagedWitness = struct {
    store_buffer: [max_path_bytes + 1]u8 = @splat(0),
    store_len: u16 = 0,
    store_uid: u32,
    record: ManagedPath,
    record_sha256: [32]u8,
    unit: ManagedPath,
    login: ?ManagedPath = null,

    fn policy(self: *const ManagedWitness) ManagedStore {
        return .{ .root = self.store_buffer[0..self.store_len], .uid = self.store_uid };
    }
};
const ManagedOpened = struct { fd: c.fd_t, proof: ManagedPath };
const GenerationLeaf = struct { root: []const u8, relative: []const u8, home: []const u8 };

fn generationLeaf(path: []const u8, selected: []const u8, store: ManagedStore) !?GenerationLeaf {
    if (!immutableStorePath(path, store)) return error.UnsafePath;
    const relative = path[store.root.len + 1 ..];
    const slash = std.mem.indexOfScalar(u8, relative, '/') orelse return null;
    const name = relative[0..slash];
    const suffix = "-home-manager-files";
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    if (name.len != 32 + suffix.len) return error.UnsafePath;
    for (name[0..32]) |byte| if (std.mem.indexOfScalar(u8, "0123456789abcdfghijklmnpqrsvwxyz", byte) == null) return error.UnsafePath;
    const leaf = relative[slash + 1 ..];
    if (leaf.len == 0 or selected.len <= leaf.len + 1 or !std.mem.endsWith(u8, selected, leaf)) return error.UnsafePath;
    const separator = selected.len - leaf.len - 1;
    if (selected[separator] != '/') return error.UnsafePath;
    const home = selected[0..separator];
    try paths.validateAbsolute(home);
    return .{ .root = path[0 .. store.root.len + 1 + slash], .relative = leaf, .home = home };
}

fn hashParent(hash: *std.crypto.hash.sha2.Sha256, status: metadata.Metadata, immutable: bool) void {
    // Hash fields rather than struct padding. The store root is mutable/sticky;
    // unrelated store additions must not invalidate immutable child snapshots.
    inline for (.{ "mode", "uid", "gid", "ino", "dev" }) |field| {
        const value = @field(status, field);
        hash.update(std.mem.asBytes(&value));
    }
    if (immutable) {
        inline for (.{ "nlink", "size", "mtime_ns", "ctime_ns" }) |field| {
            const value = @field(status, field);
            hash.update(std.mem.asBytes(&value));
        }
    }
}

fn openManagedParent(io: std.Io, allocator: std.mem.Allocator, path: []const u8, store: ManagedStore, deadline: std.Io.Clock.Timestamp, digest: *[32]u8) !Parent {
    try check(io, deadline);
    if (!immutableStorePath(path, store)) return error.UnsafePath;
    const root_parent = try openParent(allocator, store.root);
    defer root_parent.deinit(allocator);
    var parent = c.openat(root_parent.fd, root_parent.name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (parent < 0) return error.UnsafePath;
    errdefer _ = c.close(parent);
    const root_stat = try metadata.statFd(parent);
    const sticky_root = root_stat.uid == 0 and root_stat.mode & 0o1000 != 0;
    if (root_stat.uid != store.uid or (root_stat.mode & 0o022 != 0 and !sticky_root)) return error.UnsafePath;
    if (!std.meta.eql(root_stat, try metadata.statAt(root_parent.fd, root_parent.name.ptr, c.AT.SYMLINK_NOFOLLOW))) return error.ChangedFile;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(path);
    hashParent(&hash, root_stat, false);
    var parts = std.mem.splitScalar(u8, path[store.root.len + 1 ..], '/');
    var component = parts.next() orelse return error.UnsafePath;
    var count: usize = 0;
    while (parts.next()) |next| {
        try check(io, deadline);
        count += 1;
        if (count > max_managed_parents) return error.LimitExceeded;
        const name = try allocator.dupeSentinel(u8, component, 0);
        defer allocator.free(name);
        const before = try metadata.statFd(parent);
        const child = c.openat(parent, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (child < 0) return if (c.errno(child) == .NOENT) error.FileNotFound else error.UnsafePath;
        errdefer _ = c.close(child);
        const status = try metadata.statFd(child);
        if (status.uid != store.uid or status.mode & 0o222 != 0) return error.UnsafePath;
        if (!std.meta.eql(status, try metadata.statAt(parent, name.ptr, c.AT.SYMLINK_NOFOLLOW))) return error.ChangedFile;
        if (count > 1 and !std.meta.eql(before, try metadata.statFd(parent))) return error.ChangedFile;
        hashParent(&hash, status, true);
        _ = c.close(parent);
        parent = child;
        component = next;
    }
    const name = try allocator.dupeSentinel(u8, component, 0);
    hash.final(digest);
    return .{ .fd = parent, .name = name };
}

fn openManagedPath(io: std.Io, allocator: std.mem.Allocator, selected: []const u8, store: ManagedStore, deadline: std.Io.Clock.Timestamp) !ManagedOpened {
    try check(io, deadline);
    if (selected.len > max_path_bytes) return error.UnsafePath;
    try paths.validateAbsolute(selected);
    var proof: ManagedPath = .{ .file = undefined, .selected_len = @intCast(selected.len) };
    @memcpy(proof.selected_buffer[0..selected.len], selected);
    var source = selected;
    const installed = if (!immutableStorePath(selected, store)) try readOwnedLink(allocator, selected) else null;
    defer if (installed) |link| link.deinit(allocator);
    if (installed) |link| {
        proof.selected_link = link.file;
        source = link.target;
    }
    if (!immutableStorePath(source, store)) return error.UnsafePath;
    var generation_target: ?OwnedLink = null;
    defer if (generation_target) |link| link.deinit(allocator);
    if (try generationLeaf(source, selected, store)) |_| {
        // The only accepted extra hop is the exact root-owned generation leaf.
        const parent = try openManagedParent(io, allocator, source, store, deadline, &proof.generation_parents);
        defer parent.deinit(allocator);
        generation_target = try readLinkAt(allocator, parent, store.uid);
        proof.generation_link = generation_target.?.file;
        proof.generation_len = @intCast(source.len);
        @memcpy(proof.generation_buffer[0..source.len], source);
        source = generation_target.?.target;
        if (!immutableStorePath(source, store)) return error.UnsafePath;
        // A second generation or arbitrary intermediary is never followed.
        if ((try generationLeaf(source, selected, store)) != null) return error.UnsafePath;
    }
    proof.source_len = @intCast(source.len);
    @memcpy(proof.source_buffer[0..source.len], source);
    const parent = try openManagedParent(io, allocator, source, store, deadline, &proof.source_parents);
    defer parent.deinit(allocator);
    const before = try metadata.statFd(parent.fd);
    const fd = c.openat(parent.fd, parent.name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return if (c.errno(fd) == .NOENT) error.FileNotFound else error.UnsafeFile;
    errdefer _ = c.close(fd);
    proof.file = try metadata.statFd(fd);
    // Nix optimization may hardlink identical immutable regular files. This
    // exception follows the complete store/parent/source descriptor proof;
    // mutable private files and every symlink still require one link.
    if (proof.file.mode & c.S.IFMT != c.S.IFREG or proof.file.uid != store.uid or proof.file.mode & 0o7222 != 0 or proof.file.nlink < 1) return error.UnsafeFile;
    if (!std.meta.eql(proof.file, try metadata.statAt(parent.fd, parent.name.ptr, c.AT.SYMLINK_NOFOLLOW))) return error.ChangedFile;
    // Only parents below the mutable store root are immutable snapshots.
    if (std.mem.indexOfScalar(u8, source[store.root.len + 1 ..], '/') != null and !std.meta.eql(before, try metadata.statFd(parent.fd))) return error.ChangedFile;
    return .{ .fd = fd, .proof = proof };
}

fn recheckManagedPath(io: std.Io, allocator: std.mem.Allocator, original: *const ManagedPath, store: ManagedStore, digest: *const [32]u8, deadline: std.Io.Clock.Timestamp) !evidence.Probe {
    const opened = openManagedPath(io, allocator, original.selected(), store, deadline) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
        error.FileNotFound => return .absent,
        else => return .differs,
    };
    defer _ = c.close(opened.fd);
    if (!std.meta.eql(original.*, opened.proof)) return .differs;
    const actual = try hashFile(io, deadline, opened.fd, opened.proof.file);
    if (!std.mem.eql(u8, &actual, digest)) return .differs;
    // Hashing a still-open file cannot detect replacement of an installed or
    // generation link. Bind the complete path again after reading its bytes.
    const after = openManagedPath(io, allocator, original.selected(), store, deadline) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
        error.FileNotFound => return .absent,
        else => return .differs,
    };
    defer _ = c.close(after.fd);
    return if (std.meta.eql(original.*, after.proof)) .matches else .differs;
}

fn sameGeneration(left: *const ManagedPath, right: *const ManagedPath, store: ManagedStore) !bool {
    const l = (try generationLeaf(left.generation(), left.selected(), store)) orelse return false;
    const r = (try generationLeaf(right.generation(), right.selected(), store)) orelse return false;
    return std.mem.eql(u8, l.root, r.root) and std.mem.eql(u8, l.home, r.home);
}

/// Definition-only inspection. Pinned Home Manager generation leaves add one
/// exact immutable hop; live service activation remains independent evidence.
fn collectHomeManagerService(io: std.Io, allocator: std.mem.Allocator, artifact_receipt: Receipt, options: Options) !?ServiceWitness {
    return collectManagedDefinition(io, allocator, artifact_receipt, options, .{});
}

/// Synthetic filesystem predicate fixture only. The production entry point
/// always uses root custody in /nix/store; production selectors cannot supply
/// this policy. This helper is unavailable in non-test compilation.
pub fn managedDefinitionFixture(io: std.Io, allocator: std.mem.Allocator, artifact_receipt: Receipt, options: Options, fixture_store_root: []const u8) !?ServiceWitness {
    if (!builtin.is_test) @compileError("managedDefinitionFixture is test-only");
    return collectManagedDefinition(io, allocator, artifact_receipt, options, .{ .root = fixture_store_root, .uid = c.getuid() }) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
        else => null,
    };
}

fn collectManagedDefinition(io: std.Io, allocator: std.mem.Allocator, artifact_receipt: Receipt, options: Options, store: ManagedStore) !?ServiceWitness {
    try check(io, options.deadline);
    const selected = options.service_path orelse return null;
    if (selected.len > max_path_bytes) return error.InvalidReceipt;
    const artifact_metadata = artifact_receipt.artifact orelse return null;
    const manifest_sha = artifact_metadata.manifestSha256 orelse return null;
    const record_opened = try openManagedPath(io, allocator, options.service_record_path.?, store, options.deadline);
    const fd = record_opened.fd;
    defer _ = c.close(fd);
    const before = try metadata.statFd(fd);
    if (before.uid != store.uid or before.mode & 0o222 != 0 or before.nlink < 1) return error.UnsafeFile;
    if (before.size < 0 or before.size > 64 * 1024) return error.LimitExceeded;
    const bytes = try allocator.alloc(u8, @intCast(before.size));
    defer allocator.free(bytes);
    try readExact(io, options.deadline, fd, bytes);
    if (!std.meta.eql(before, try metadata.statFd(fd))) return error.ChangedFile;
    const parsed = std.json.parseFromSlice(ServiceRecord, allocator, bytes, .{ .ignore_unknown_fields = true, .max_value_len = 64 * 1024 }) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidReceipt;
    };
    defer parsed.deinit();
    const record = parsed.value;
    const channel = try receiptChannel(artifact_receipt);
    const expected_instance: []const u8 = switch (channel) {
        .development => "dev",
        .release => "default",
        .unknown => return null,
    };
    const expected_channel: []const u8 = if (channel == .development) "development" else "release";
    const expected_unit: []const u8 = if (channel == .development) "ai.xoxd.omux.dev.service" else "ai.xoxd.omux.service";
    if (record.schemaVersion != 1 or !std.mem.eql(u8, record.owner, "home-manager") or !std.mem.eql(u8, record.scope, "definition-only-not-activation") or !std.mem.eql(u8, record.channel, expected_channel) or !std.mem.eql(u8, record.instance, expected_instance) or !std.ascii.eqlIgnoreCase(record.artifactManifestSha256, manifest_sha)) return error.InvalidReceipt;
    if (!std.mem.eql(u8, record.unit.name, expected_unit) or !std.mem.eql(u8, record.unit.installedPath, selected) or !std.mem.eql(u8, std.fs.path.basename(selected), expected_unit) or !immutableStorePath(record.unit.sourcePath, store) or record.unit.mode != 0o644) return error.InvalidReceipt;
    try validateDigest(record.unit.sha256);
    try paths.validateAbsolute(selected);
    const directory = std.fs.path.dirname(selected) orelse return error.InvalidReceipt;
    if (!std.mem.endsWith(u8, directory, "/systemd/user")) return error.InvalidReceipt;
    const expected_login = try std.fmt.allocPrint(allocator, "{s}/default.target.wants/{s}", .{ directory, expected_unit });
    defer allocator.free(expected_login);
    if (!std.mem.eql(u8, record.login.installedPath, expected_login) or !std.mem.eql(u8, record.login.sourcePath, record.unit.sourcePath)) return error.InvalidReceipt;
    const config_home = directory[0 .. directory.len - "/systemd/user".len];
    const expected_record = try std.fmt.allocPrint(allocator, "{s}/omux/instances/{s}/service.json", .{ config_home, expected_channel });
    defer allocator.free(expected_record);
    if (record_opened.proof.selected_link != null and !std.mem.eql(u8, record_opened.proof.selected(), expected_record)) return error.InvalidReceipt;
    const unit_opened = try openManagedPath(io, allocator, selected, store, options.deadline);
    const source_fd = unit_opened.fd;
    defer _ = c.close(source_fd);
    if (unit_opened.proof.selected_link == null or !std.mem.eql(u8, unit_opened.proof.source(), record.unit.sourcePath)) return null;
    if (record_opened.proof.generation_len != 0) {
        if (unit_opened.proof.generation_len == 0 or !(try sameGeneration(&record_opened.proof, &unit_opened.proof, store))) return null;
    }
    const source_stat = unit_opened.proof.file;
    if (source_stat.uid != store.uid or source_stat.mode & 0o777 != 0o444 or source_stat.nlink < 1) return error.UnsafeFile;
    if (source_stat.size < 0 or source_stat.size > 64 * 1024) return error.LimitExceeded;
    const digest = try hashFile(io, options.deadline, source_fd, source_stat);
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.ascii.eqlIgnoreCase(&hex, record.unit.sha256)) return null;
    var record_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &record_digest, .{});
    var managed: ManagedWitness = .{ .store_len = @intCast(store.root.len), .store_uid = store.uid, .record = record_opened.proof, .record_sha256 = record_digest, .unit = unit_opened.proof };
    @memcpy(managed.store_buffer[0..store.root.len], store.root);
    var witness: ServiceWitness = .{ .path_len = @intCast(selected.len), .source_len = @intCast(record.unit.sourcePath.len), .sha256 = digest, .file = source_stat, .installed_link = unit_opened.proof.selected_link };
    @memcpy(witness.path_buffer[0..selected.len], selected);
    @memcpy(witness.source_buffer[0..record.unit.sourcePath.len], record.unit.sourcePath);
    if (unit_opened.proof.generation_len != 0) {
        const login = openManagedPath(io, allocator, expected_login, store, options.deadline) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidDeadline => return err,
            else => null,
        };
        if (login) |opened| {
            defer _ = c.close(opened.fd);
            if (opened.proof.generation_len != 0 and (try sameGeneration(&unit_opened.proof, &opened.proof, store)) and std.mem.eql(u8, opened.proof.source(), record.unit.sourcePath) and std.meta.eql(opened.proof.file, source_stat)) {
                managed.login = opened.proof;
                witness.login_link = .matches;
            } else witness.login_link = .differs;
        } else witness.login_link = .differs;
    } else witness.login_link = try inspectLoginLink(io, allocator, &witness, options.deadline);
    witness.managed = managed;
    try check(io, options.deadline);
    if (!std.meta.eql(before, try metadata.statFd(fd)) or (try recheckServiceWitness(io, allocator, &witness, options.deadline)) != .matches) return null;
    if (managed.login != null) witness.login_link = try inspectLoginLink(io, allocator, &witness, options.deadline);
    return witness;
}

fn readExact(io: std.Io, deadline: std.Io.Clock.Timestamp, fd: c.fd_t, bytes: []u8) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        try check(io, deadline);
        const count = c.read(fd, bytes[cursor..].ptr, bytes.len - cursor);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.ReadFailed;
        }
        if (count == 0) return error.ChangedFile;
        cursor += @intCast(count);
    }
    var extra: [1]u8 = undefined;
    if (c.read(fd, &extra, 1) != 0) return error.ChangedFile;
}

fn hashFile(io: std.Io, deadline: std.Io.Clock.Timestamp, fd: c.fd_t, before: metadata.Metadata) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [16 * 1024]u8 = undefined;
    var remaining: u64 = @intCast(before.size);
    while (remaining > 0) {
        try check(io, deadline);
        const length: usize = @intCast(@min(remaining, buffer.len));
        const count = c.read(fd, &buffer, length);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.ReadFailed;
        }
        if (count == 0) return error.ChangedFile;
        const size: usize = @intCast(count);
        hash.update(buffer[0..size]);
        remaining -= size;
    }
    var extra: [1]u8 = undefined;
    if (c.read(fd, &extra, 1) != 0 or !std.meta.eql(before, try metadata.statFd(fd))) return error.ChangedFile;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

const ReceiptOpened = struct { fd: c.fd_t, managed: ?ManagedPath = null };
fn openReceipt(io: std.Io, allocator: std.mem.Allocator, path: []const u8, store: ManagedStore, deadline: std.Io.Clock.Timestamp) !ReceiptOpened {
    // Home Manager launchers supply its direct immutable writeText store path.
    // The convenient XDG inspection symlink is not an ownership selector.
    if (immutableStorePath(path, store)) {
        const opened = try openManagedPath(io, allocator, path, store, deadline);
        errdefer _ = c.close(opened.fd);
        // Installation records select the immutable source directly. Installed
        // aliases and generation hops belong only to separate service proofs.
        if (opened.proof.selected_link != null or opened.proof.generation_len != 0 or !std.mem.eql(u8, opened.proof.source(), path)) return error.UnsafePath;
        return .{ .fd = opened.fd, .managed = opened.proof };
    }
    const fd = try openRegular(allocator, path);
    errdefer _ = c.close(fd);
    if ((try metadata.statFd(fd)).nlink != 1) return error.UnsafeFile;
    return .{ .fd = fd };
}

/// Walk every parent by descriptor; no symlink intermediates, FIFO reads or
/// writable foreign directories. Nix symlink ownership needs its own witness.
const Parent = struct {
    fd: c.fd_t,
    name: [:0]u8,
    fn deinit(self: Parent, allocator: std.mem.Allocator) void {
        _ = c.close(self.fd);
        allocator.free(self.name);
    }
};
fn openParent(allocator: std.mem.Allocator, path: []const u8) !Parent {
    if (path.len > max_path_bytes) return error.UnsafePath;
    try paths.validateAbsolute(path);
    var parent = c.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (parent < 0) return error.UnsafePath;
    errdefer _ = c.close(parent);
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    var component = parts.next() orelse return error.UnsafePath;
    while (parts.next()) |next| {
        const name = try allocator.dupeSentinel(u8, component, 0);
        defer allocator.free(name);
        const child = c.openat(parent, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (child < 0) return if (c.errno(child) == .NOENT) error.FileNotFound else error.UnsafePath;
        const status = metadata.statFd(child) catch |err| {
            _ = c.close(child);
            return err;
        };
        // Same ancestor rule as paths.openPrivateRoot: a root-owned sticky
        // directory protects existing entries, which we open without following
        // symlinks. Other writable ancestors remain unsafe.
        const protected_sticky = status.uid == 0 and status.mode & 0o1000 != 0;
        if ((status.uid != 0 and status.uid != c.getuid()) or (status.mode & 0o022 != 0 and !protected_sticky)) {
            _ = c.close(child);
            return error.UnsafePath;
        }
        _ = c.close(parent);
        parent = child;
        component = next;
    }
    const name = try allocator.dupeSentinel(u8, component, 0);
    return .{ .fd = parent, .name = name };
}
fn openRegular(allocator: std.mem.Allocator, path: []const u8) !c.fd_t {
    const parent = try openParent(allocator, path);
    defer parent.deinit(allocator);
    const fd = c.openat(parent.fd, parent.name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return if (c.errno(fd) == .NOENT) error.FileNotFound else error.UnsafeFile;
    errdefer _ = c.close(fd);
    const status = try metadata.statFd(fd);
    if (status.mode & c.S.IFMT != c.S.IFREG or (status.uid != 0 and status.uid != c.getuid()) or status.mode & 0o7022 != 0) return error.UnsafeFile;
    return fd;
}

test "immutable receipt descriptor proof accepts optimization and rejects link drift and unsafe custody" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const base = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    if (c.mkdirat(directory.dir.handle, "store", 0o700) != 0) return error.FixtureWriteFailed;
    const file = c.openat(directory.dir.handle, "store/installation.json", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (file < 0) return error.FixtureWriteFailed;
    const payload = "{\"synthetic\":\"immutable receipt predicate\"}\n";
    const count = c.write(file, payload.ptr, payload.len);
    const written = count >= 0 and @as(usize, @intCast(count)) == payload.len;
    const permissions = c.fchmod(file, 0o444);
    _ = c.close(file);
    if (!written or permissions != 0) return error.FixtureWriteFailed;
    if (c.linkat(directory.dir.handle, "store/installation.json", directory.dir.handle, "store/optimized-alias", 0) != 0) return error.FixtureWriteFailed;
    const store_root = try std.fmt.allocPrint(allocator, "{s}/store", .{base});
    defer allocator.free(store_root);
    const selected = try std.fmt.allocPrint(allocator, "{s}/installation.json", .{store_root});
    defer allocator.free(selected);
    // Private fixture policy only: production passes the fixed root-owned
    // /nix/store policy. This test establishes no installed HM authority.
    const store: ManagedStore = .{ .root = store_root, .uid = c.getuid() };
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    const opened = try openReceipt(io, allocator, selected, store, deadline);
    defer _ = c.close(opened.fd);
    const proof = opened.managed orelse return error.MissingReceiptProof;
    try std.testing.expectEqual(@as(u64, 2), proof.file.nlink);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    try std.testing.expectEqual(evidence.Probe.matches, try recheckManagedPath(io, allocator, &proof, store, &digest, deadline));
    if (c.linkat(directory.dir.handle, "store/installation.json", directory.dir.handle, "store/later-alias", 0) != 0) return error.FixtureWriteFailed;
    try std.testing.expectEqual(evidence.Probe.differs, try recheckManagedPath(io, allocator, &proof, store, &digest, deadline));
    const outside = try std.fmt.allocPrint(allocator, "{s}/private-alias", .{base});
    defer allocator.free(outside);
    if (c.linkat(directory.dir.handle, "store/installation.json", directory.dir.handle, "private-alias", 0) != 0) return error.FixtureWriteFailed;
    try std.testing.expectError(error.UnsafeFile, openReceipt(io, allocator, outside, store, deadline));
    try std.testing.expectError(error.UnsafePath, openReceipt(io, allocator, selected, .{ .root = store_root, .uid = c.getuid() ^ 1 }, deadline));
    if (c.fchmodat(directory.dir.handle, "store/optimized-alias", 0o644, 0) != 0) return error.FixtureWriteFailed;
    try std.testing.expectError(error.UnsafeFile, openReceipt(io, allocator, selected, store, deadline));
    if (c.fchmodat(directory.dir.handle, "store/optimized-alias", 0o444, 0) != 0) return error.FixtureWriteFailed;
    if (c.unlinkat(directory.dir.handle, "store/installation.json", 0) != 0 or c.symlinkat("optimized-alias", directory.dir.handle, "store/installation.json") != 0) return error.FixtureWriteFailed;
    try std.testing.expectError(error.UnsafeFile, openReceipt(io, allocator, selected, store, deadline));
}
