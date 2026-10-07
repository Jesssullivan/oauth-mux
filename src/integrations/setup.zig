//! Reversible native configuration custody. The encrypted registry is the
//! write-ahead record; recovery never overwrites an independently edited file.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const paths = @import("../paths.zig");
const envelope = @import("../envelope.zig");
const git = @import("git.zig");
const codex = @import("codex.zig");
const native_probe = @import("native_probe.zig");
const inventory = @import("native_inventory.zig");
const metadata = @import("../platform/file_metadata.zig");
const mutation_authority = @import("../mutation_authority.zig");
extern "c" fn flock(fd: c.fd_t, operation: c_int) c_int;

pub const maximum_config = 1024 * 1024;
const maximum_registry = 4 * maximum_config + 8192;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const magic = "OMUXI001";
const header_size = magic.len + Aead.nonce_length + Aead.tag_length;
const record_header = 4 + 3 * 4 + 64 + 32 + 5 * 4;

pub const Adapter = enum { git, codex };
// R-N13: this is an internal actor-derived permit, never an RPC assertion.
// The actor verifies the sealed owner ledger and every request/lease fence.
pub const NativeCustodyState = enum { install_ready, retain_ready, removal_pending, removal_ready };
pub const NativeCustody = struct {
    adapter_epoch: u64,
    capability_digest: [32]u8,
    snapshot_digest: [32]u8,
    state: NativeCustodyState,
    removal_operation: ?[32]u8 = null,
    /// R-N13: stable Codex installation transaction, sealed by the actor.
    /// Null permits only first installation with no existing registry.
    registry_transaction: ?[32]u8 = null,
    /// The sealed registry may belong to the retired generation during reinstall.
    registry_capability_digest: ?[32]u8 = null,

    pub fn validate(self: NativeCustody) !void {
        if (self.adapter_epoch == 0 or zeroDigest(self.capability_digest) or zeroDigest(self.snapshot_digest)) return error.InvalidNativeCustody;
        switch (self.state) {
            .install_ready, .retain_ready => if (self.removal_operation != null) return error.InvalidNativeCustody,
            .removal_pending, .removal_ready => if (self.removal_operation == null or zeroDigest(self.removal_operation.?)) return error.InvalidNativeCustody,
        }
        if (self.registry_transaction) |transaction| {
            for (transaction) |byte| if (!std.ascii.isHex(byte)) return error.InvalidNativeCustody;
        }
        if ((self.registry_transaction == null) != (self.registry_capability_digest == null)) return error.InvalidNativeCustody;
        if (self.registry_capability_digest) |digest| if (zeroDigest(digest)) return error.InvalidNativeCustody;
    }
};
pub const Options = struct {
    state_dir: []const u8,
    home: []const u8,
    xdg_config_home: ?[]const u8 = null,
    codex_home: ?[]const u8 = null,
    /// R-N13: distinguishes an explicit control context from daemon fallback.
    codex_home_explicit: bool = false,
    config_path: ?[]const u8 = null,
    adapter: Adapter,
    capability: [64]u8,
    broker_socket: []const u8,
    native_socket: ?[]const u8 = null,
    omux_version: []const u8,
    key: envelope.Key,
    native_custody: ?NativeCustody = null,
    /// The engine supplies its already reply-reserved operation deadline.
    deadline: ?std.Io.Clock.Timestamp = null,
};

fn zeroDigest(value: [32]u8) bool {
    for (value) |byte| if (byte != 0) return false;
    return true;
}

fn requireNativeCustody(options: Options, operation: ?Operation) !void {
    if (options.adapter != .codex) return;
    const permit = options.native_custody orelse return error.NativeCustodyPending;
    try permit.validate();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&options.capability, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, permit.capability_digest)) return error.NativeCustodyGenerationMismatch;
    if (permit.state == .removal_pending) return error.NativeCustodyPending;
    if (operation) |requested| switch (requested) {
        .install => if (permit.state != .install_ready) return error.NativeCustodyPending,
        .remove => if (permit.state != .removal_ready) return error.NativeCustodyPending,
    };
}
pub const Outcome = struct {
    changed: bool,
    config_path: []u8,
    capability_path: []u8,
    pub fn deinit(self: Outcome, allocator: std.mem.Allocator) void {
        allocator.free(self.config_path);
        allocator.free(self.capability_path);
    }
};
pub const Operation = enum { install, remove };
pub const InstallResult = struct { installed: bool = true, adapter: []const u8, config_path: []const u8, changed: bool };
pub const RemoveResult = struct { removed: bool = true, adapter: []const u8, config_path: []const u8, changed: bool };

pub fn installResult(adapter: Adapter, value: Outcome) InstallResult {
    return .{ .adapter = @tagName(adapter), .config_path = value.config_path, .changed = value.changed };
}
pub fn removeResult(adapter: Adapter, value: Outcome) RemoveResult {
    return .{ .adapter = @tagName(adapter), .config_path = value.config_path, .changed = value.changed };
}

/// Use the production serializer and the same parsed-value serialization used
/// by the mutation ledger. Raw string lengths do not account for JSON escapes.
pub fn requireResultFits(allocator: std.mem.Allocator, result: anytype) !void {
    const encoded = try std.json.Stringify.valueAlloc(allocator, result, .{});
    defer allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const cached = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(cached);
    if (cached.len > mutation_authority.max_result_bytes) return error.ResultTooLarge;
}

fn checkCompletion(allocator: std.mem.Allocator, adapter: Adapter, operation: Operation, config_path: []const u8) !void {
    // Both results are possible after recovery; do not guess changed beforehand.
    for ([_]bool{ false, true }) |changed| switch (operation) {
        .install => try requireResultFits(allocator, InstallResult{ .adapter = @tagName(adapter), .config_path = config_path, .changed = changed }),
        .remove => try requireResultFits(allocator, RemoveResult{ .adapter = @tagName(adapter), .config_path = config_path, .changed = changed }),
    };
}
pub const Recovery = enum { none, installed, removed, conflict };
pub const RegistryPhase = enum(u8) { pending_install, installed, pending_remove, removed };
const Phase = RegistryPhase;
pub const RegistryWitness = struct { phase: RegistryPhase, transaction: [32]u8, capability_digest: [32]u8 };

/// Internal retained-evidence format, not a control request or native claim.
/// A future trusted installation producer must first validate the exact package
/// and its independent source/producer receipts, collect installed ownership,
/// then seal these facts and commit their plaintext digest with actor authority.
/// No producer, record writer, wire method or registry migration exists yet.
pub const RuntimeSelectionRecord = struct {
    schema_version: u8,
    channel: RuntimeChannel,
    target: RuntimeTarget,
    launch_profile: RuntimeLaunchProfile,
    upstream_commit: [40]u8,
    artifact_selection_sha256: [32]u8,
    archive_sha256: [32]u8,
    manifest_sha256: [32]u8,
    runtime_receipt_sha256: [32]u8,
    source_receipt_sha256: [32]u8,
    producer_receipt_sha256: [32]u8,
    installation: RuntimeInstallation,
    launcher: RuntimeRole,
    backend: RuntimeRole,
    loader: RuntimeRole,
};
pub const RuntimeChannel = enum { release, development };
pub const RuntimeTarget = enum { x86_64_linux };
pub const RuntimeLaunchProfile = enum { linux_explicit_bundled_loader_v1 };
pub const RuntimeRole = struct { sha256: [32]u8, bytes: u64 };
pub const RuntimeInstallation = struct {
    transaction: [32]u8,
    adapter_epoch: u64,
    capability_digest: [32]u8,
    directory_device: u64,
    directory_inode: u64,
    uid: u32,
    gid: u32,
};
pub const RuntimeSelectionExpectation = struct {
    /// Previously committed actor digest; never copied from a control request
    /// or computed from the supplied evidence as an admission shortcut.
    record_sha256: [32]u8,
    channel: RuntimeChannel,
    target: RuntimeTarget,
    /// Explicit retained installation descriptor, not PATH/current-path lookup.
    /// The caller keeps it open through verification and subsequent rechecking.
    directory: c.fd_t,
};

const runtime_selection_maximum = 16 * 1024;
const runtime_role_paths = [_][:0]const u8{
    "bin/codex", "lib/codex/libexec/codex.bin", "lib/codex/lib/ld-linux-x86-64.so.2",
};
const runtime_role_limits = [_]u64{ 16 * 1024, 512 * 1024 * 1024, 128 * 1024 * 1024 };
const RuntimeSelectionVerified = struct {
    record: RuntimeSelectionRecord,
    digest: [32]u8,
    context_digest: [32]u8,
};

/// Only authenticated retained evidence can construct this carrier. Selection
/// establishes installed artifact facts; it supplies no process executable
/// attribution, attachment permission or continuity capability. In particular,
/// the bundled loader is distinct from the backend and /proc/PID/exe is unused.
pub const VerifiedRuntimeSelection = opaque {
    pub fn deinit(self: *VerifiedRuntimeSelection, allocator: std.mem.Allocator) void {
        const retained: *RuntimeSelectionVerified = @ptrCast(@alignCast(self));
        allocator.destroy(retained);
    }

    /// Recheck at the mutation/recovery boundary under the caller's custody
    /// serialization. A previously verified carrier is not a perpetual permit.
    pub fn recheck(self: *const VerifiedRuntimeSelection, io: std.Io, allocator: std.mem.Allocator, options: Options, expected: RuntimeSelectionExpectation) !void {
        const retained: *const RuntimeSelectionVerified = @ptrCast(@alignCast(self));
        if (!std.crypto.timing_safe.eql([32]u8, retained.digest, expected.record_sha256)) return error.RuntimeSelectionDrift;
        if (!std.crypto.timing_safe.eql([32]u8, retained.context_digest, try runtimeSelectionContextDigest(allocator, options, expected))) return error.RuntimeSelectionDrift;
        try validateRuntimeInstallation(io, allocator, options, expected, retained.record);
    }
};

fn runtimeSelectionContext(options: Options, expected: RuntimeSelectionExpectation) !envelope.Context {
    if (options.adapter != .codex) return error.UnsupportedAdapter;
    const custody = options.native_custody orelse return error.NativeCustodyPending;
    try custody.validate();
    if (zeroDigest(expected.record_sha256)) return error.InvalidRuntimeSelection;
    return .{
        .key_id = switch (expected.channel) {
            .release => "installation-v1",
            .development => "installation-dev-v1",
        },
        // Reuse the authenticated envelope encoding with a dedicated namespace;
        // these are installation context fields, never fabricated account IDs.
        .account_id = options.state_dir,
        .grant_id = "codex-installed-runtime-selection-v1",
        .generation = custody.adapter_epoch,
        .purpose = "verified-installation-selection",
        .scope = switch (expected.target) {
            .x86_64_linux => "x86_64-linux/linux-explicit-bundled-loader-v1",
        },
    };
}

fn runtimeSelectionContextDigest(allocator: std.mem.Allocator, options: Options, expected: RuntimeSelectionExpectation) ![32]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, try runtimeSelectionContext(options, expected), .{});
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// Source-only foundation. The raw evidence must be supplied by the trusted
/// installation producer described above, authenticated before decoding, and
/// its digest independently retained by the actor. This does not acquire that
/// authority or accept client booleans claiming verification. No files change.
pub fn verifyRetainedRuntimeSelection(io: std.Io, allocator: std.mem.Allocator, options: Options, expected: RuntimeSelectionExpectation, evidence: []const u8) !*VerifiedRuntimeSelection {
    try Budget.from(io, options).check();
    if (evidence.len > runtime_selection_maximum + 128) return error.InvalidRuntimeSelection;
    var plaintext = try envelope.open(allocator, options.key, try runtimeSelectionContext(options, expected), evidence);
    defer plaintext.deinit();
    if (plaintext.bytes.len == 0 or plaintext.bytes.len > runtime_selection_maximum) return error.InvalidRuntimeSelection;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext.bytes, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, expected.record_sha256)) return error.RuntimeSelectionDrift;
    const parsed = try std.json.parseFromSlice(RuntimeSelectionRecord, allocator, plaintext.bytes, .{ .duplicate_field_behavior = .@"error", .ignore_unknown_fields = false });
    defer parsed.deinit();
    try validateRuntimeInstallation(io, allocator, options, expected, parsed.value);
    const retained = try allocator.create(RuntimeSelectionVerified);
    errdefer allocator.destroy(retained);
    retained.* = .{ .record = parsed.value, .digest = digest, .context_digest = try runtimeSelectionContextDigest(allocator, options, expected) };
    return @ptrCast(retained);
}

fn runtimeDirectory(status: metadata.Metadata, uid: u32, gid: u32) !void {
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.mode & 0o7022 != 0 or status.uid != uid or status.gid != gid) return error.RuntimeInstallationOwnershipMismatch;
}

fn openRuntimeRole(budget: Budget, directory: c.fd_t, installation: RuntimeInstallation, path: [:0]const u8) !c.fd_t {
    const duplicate = c.openat(directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (duplicate < 0) return error.RuntimeInstallationUnavailable;
    var parent = duplicate;
    defer close(parent);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try budget.check();
        try runtimeDirectory(try statFile(parent), installation.uid, installation.gid);
        var name: [64:0]u8 = @splat(0);
        if (part.len == 0 or part.len >= name.len) return error.InvalidRuntimeSelection;
        @memcpy(name[0..part.len], part);
        if (parts.peek() != null) {
            const next = c.openat(parent, &name, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
            if (next < 0) return error.RuntimeInstallationUnavailable;
            close(parent);
            parent = next;
            continue;
        }
        const file = c.openat(parent, &name, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
        if (file < 0) return error.RuntimeInstallationUnavailable;
        return file;
    }
    return error.InvalidRuntimeSelection;
}

fn validateRuntimeRole(budget: Budget, directory: c.fd_t, installation: RuntimeInstallation, path: [:0]const u8, role: RuntimeRole, limit: u64) !void {
    if (zeroDigest(role.sha256) or role.bytes == 0 or role.bytes > limit) return error.InvalidRuntimeSelection;
    const file = try openRuntimeRole(budget, directory, installation, path);
    defer close(file);
    const before = try statFile(file);
    if (before.mode & c.S.IFMT != c.S.IFREG or before.mode & 0o7777 != 0o755 or before.uid != installation.uid or before.gid != installation.gid or before.nlink != 1 or before.size < 0 or @as(u64, @intCast(before.size)) != role.bytes) return error.RuntimeInstallationOwnershipMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var consumed: u64 = 0;
    while (true) {
        try budget.check();
        const count = c.read(file, &buffer, buffer.len);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.RuntimeInstallationUnavailable;
        }
        if (count == 0) break;
        const length: usize = @intCast(count);
        if (length > role.bytes - consumed) return error.RuntimeSelectionDrift;
        consumed += length;
        hash.update(buffer[0..length]);
    }
    const after = try statFile(file);
    // Rewalk from the retained root, detecting replacement of intermediate
    // directories as well as the final file while its descriptor was read.
    const current = try openRuntimeRole(budget, directory, installation, path);
    defer close(current);
    if (consumed != role.bytes or !std.meta.eql(before, after) or !std.meta.eql(after, try statFile(current))) return error.RuntimeSelectionDrift;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    if (!std.crypto.timing_safe.eql([32]u8, digest, role.sha256)) return error.RuntimeSelectionDrift;
}

fn validateRuntimeInstallation(io: std.Io, allocator: std.mem.Allocator, options: Options, expected: RuntimeSelectionExpectation, record: RuntimeSelectionRecord) !void {
    const budget = Budget.from(io, options);
    try budget.check();
    try requireNativeCustody(options, null);
    if (options.adapter != .codex) return error.UnsupportedAdapter;
    if (record.schema_version != 1) return error.InvalidRuntimeSelection;
    if (record.channel != expected.channel or record.target != expected.target) return error.RuntimeSelectionDrift;
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedRuntimeSelection;
    switch (record.launch_profile) {
        .linux_explicit_bundled_loader_v1 => {},
    }
    if (std.mem.allEqual(u8, &record.upstream_commit, '0')) return error.InvalidRuntimeSelection;
    for (record.upstream_commit) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeSelection;
    for ([_][32]u8{ record.artifact_selection_sha256, record.archive_sha256, record.manifest_sha256, record.runtime_receipt_sha256, record.source_receipt_sha256, record.producer_receipt_sha256 }) |digest| if (zeroDigest(digest)) return error.InvalidRuntimeSelection;
    const custody = options.native_custody.?;
    if (custody.state != .install_ready and custody.state != .retain_ready) return error.NativeCustodyPending;
    const witness = (try registryWitness(io, allocator, options)) orelse return error.NativeCustodyPending;
    if (witness.phase != .installed) return error.NativeCustodyPending;
    const home = try selectedCodexHome(io, allocator, options);
    defer allocator.free(home);
    const loaded = (try inspectRegistry(allocator, options, budget)) orelse return error.NativeCustodyPending;
    defer loaded.deinit(allocator);
    if (loaded.record.phase != .installed or !std.meta.eql(loaded.record.transaction, witness.transaction)) return error.NativeCustodyPending;
    try verifyInstalled(allocator, options, loaded.record, budget);
    const installation = record.installation;
    if (installation.adapter_epoch != custody.adapter_epoch or !std.meta.eql(installation.transaction, witness.transaction) or !std.meta.eql(installation.capability_digest, witness.capability_digest)) return error.RuntimeSelectionDrift;
    if (custody.registry_transaction == null or custody.registry_capability_digest == null) return error.NativeCustodyPending;
    if (!std.meta.eql(installation.transaction, custody.registry_transaction.?) or !std.meta.eql(installation.capability_digest, custody.registry_capability_digest.?) or !std.meta.eql(installation.capability_digest, custody.capability_digest)) return error.RuntimeSelectionDrift;
    if (installation.uid != 0 and installation.uid != c.getuid()) return error.RuntimeInstallationOwnershipMismatch;
    const before = try statFile(expected.directory);
    try runtimeDirectory(before, installation.uid, installation.gid);
    if (before.dev != installation.directory_device or before.ino != installation.directory_inode) return error.RuntimeSelectionDrift;
    for (runtime_role_paths, [_]RuntimeRole{ record.launcher, record.backend, record.loader }, runtime_role_limits) |path, role, limit| try validateRuntimeRole(budget, expected.directory, installation, path, role, limit);
    if (!std.meta.eql(before, try statFile(expected.directory))) return error.RuntimeSelectionDrift;
    const after_witness = (try registryWitness(io, allocator, options)) orelse return error.NativeCustodyPending;
    if (!std.meta.eql(witness, after_witness)) return error.RuntimeSelectionDrift;
    try budget.check();
}

const Budget = struct {
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp,
    fn from(io: std.Io, options: Options) Budget {
        return .{ .io = io, .deadline = options.deadline };
    }
    fn check(self: Budget) !void {
        try self.io.checkCancel();
        if (self.deadline) |until| {
            if (until.clock != .awake) return error.InvalidDeadline;
            if (until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
        }
    }
};

fn checkBudget(budget: ?Budget) !void {
    if (budget) |value| try value.check();
}

const Snapshot = struct {
    existed: bool = false,
    mode: c.mode_t = 0o600,
    gid: ?c.gid_t = null,
    bytes: []u8,
    pub fn deinit(self: Snapshot, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
    fn matches(self: Snapshot, existed: bool, mode: c.mode_t, bytes: []const u8) bool {
        return self.existed == existed and (!existed or self.mode == mode) and std.mem.eql(u8, self.bytes, bytes);
    }
};

const Record = struct {
    phase: Phase,
    original_existed: bool,
    before_existed: bool,
    after_existed: bool,
    original_mode: c.mode_t,
    before_mode: c.mode_t,
    after_mode: c.mode_t,
    capability: [64]u8,
    transaction: [32]u8,
    config_path: []const u8,
    original: []const u8,
    installed: []const u8,
    before: []const u8 = "",
    after: []const u8 = "",
};
const Loaded = struct {
    bytes: []u8,
    record: Record,
    pub fn deinit(self: Loaded, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
};

fn close(fd: c.fd_t) void {
    _ = c.close(fd);
}
fn statFile(fd: c.fd_t) !metadata.Metadata {
    return metadata.statFd(fd);
}
fn safeDirectory(fd: c.fd_t, final: bool) !void {
    const status = try statFile(fd);
    const sticky_root = status.uid == 0 and status.mode & 0o1000 != 0;
    if (status.mode & c.S.IFMT != c.S.IFDIR or (status.uid != c.getuid() and status.uid != 0) or (status.mode & 0o022 != 0 and !sticky_root)) return error.UnsafeConfigParent;
    if (final and status.uid != c.getuid()) return error.UnsafeConfigOwner;
}

/// Native configs need not have private modes, but must be owned and immutable
/// by other users. Every path component is walked with NOFOLLOW.
fn openParent(allocator: std.mem.Allocator, path: []const u8, create: bool) !c.fd_t {
    return openParentWithBudget(allocator, path, create, null);
}

fn openParentWithBudget(allocator: std.mem.Allocator, path: []const u8, create: bool, budget: ?Budget) !c.fd_t {
    try checkBudget(budget);
    try paths.validateAbsolute(path);
    if (path.len > 4096) return error.UnsafePath;
    const parent = std.fs.path.dirname(path) orelse return error.UnsafePath;
    var fd = c.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.PathOpenFailed;
    errdefer close(fd);
    var components = std.mem.splitScalar(u8, parent[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        try checkBudget(budget);
        try safeDirectory(fd, false);
        const name = try allocator.dupeSentinel(u8, component, 0);
        defer allocator.free(name);
        var next = c.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0 and c.errno(next) == .NOENT) {
            if (!create) return error.ParentMissing;
            try checkBudget(budget);
            if (c.mkdirat(fd, name.ptr, 0o700) != 0 and c.errno(-1) != .EXIST) return error.PathCreateFailed;
            next = c.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        }
        if (next < 0) return error.UnsafeConfigParent;
        close(fd);
        fd = next;
    }
    try safeDirectory(fd, true);
    return fd;
}

fn validateFile(status: metadata.Metadata, private: bool) !void {
    if (status.mode & c.S.IFMT != c.S.IFREG or status.uid != c.getuid() or status.nlink != 1 or status.mode & 0o7022 != 0) return error.UnsafeConfigFile;
    if (private and status.mode & 0o777 != 0o600) return error.UnsafePrivatePath;
    if (status.size < 0) return error.InvalidConfigSize;
}

fn readAt(allocator: std.mem.Allocator, directory: c.fd_t, name: [:0]const u8, private: bool, limit: usize) !Snapshot {
    return readAtWithBudget(allocator, directory, name, private, limit, null);
}

fn readAtWithBudget(allocator: std.mem.Allocator, directory: c.fd_t, name: [:0]const u8, private: bool, limit: usize, budget: ?Budget) !Snapshot {
    try checkBudget(budget);
    const fd = c.openat(directory, name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) {
        if (c.errno(fd) == .NOENT) return .{ .bytes = try allocator.alloc(u8, 0) };
        return error.UnsafeConfigFile;
    }
    defer close(fd);
    const before = try statFile(fd);
    try validateFile(before, private);
    const length = std.math.cast(usize, before.size) orelse return error.ConfigTooLarge;
    if (length > limit) return error.ConfigTooLarge;
    const data = try allocator.alloc(u8, length);
    errdefer {
        std.crypto.secureZero(u8, data);
        allocator.free(data);
    }
    var cursor: usize = 0;
    while (cursor < data.len) {
        try checkBudget(budget);
        const count = c.read(fd, data[cursor..].ptr, data.len - cursor);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.ConfigReadFailed;
        }
        if (count == 0) return error.ConfigChanged;
        cursor += @intCast(count);
    }
    try checkBudget(budget);
    const after = try statFile(fd);
    if (after.size != before.size or after.ino != before.ino or after.dev != before.dev or after.uid != before.uid or after.gid != before.gid or after.nlink != before.nlink or after.mode != before.mode or after.mtime_ns != before.mtime_ns or after.ctime_ns != before.ctime_ns) return error.ConfigChanged;
    var extra: [1]u8 = undefined;
    if (c.read(fd, &extra, 1) != 0) return error.ConfigChanged;
    return .{ .existed = true, .mode = @intCast(before.mode & 0o777), .gid = @intCast(before.gid), .bytes = data };
}

fn readConfig(allocator: std.mem.Allocator, path: []const u8, create_parent: bool) !Snapshot {
    return readConfigWithBudget(allocator, path, create_parent, null);
}

fn readConfigWithBudget(allocator: std.mem.Allocator, path: []const u8, create_parent: bool, budget: ?Budget) !Snapshot {
    const parent = openParentWithBudget(allocator, path, create_parent, budget) catch |err| switch (err) {
        error.ParentMissing => return .{ .bytes = try allocator.alloc(u8, 0) },
        else => return err,
    };
    defer close(parent);
    const name = try allocator.dupeSentinel(u8, std.fs.path.basename(path), 0);
    defer allocator.free(name);
    return readAtWithBudget(allocator, parent, name, false, maximum_config, budget);
}

fn chooseConfig(allocator: std.mem.Allocator, options: Options) ![]u8 {
    return chooseConfigWithBudget(allocator, options, null);
}

fn chooseConfigWithBudget(allocator: std.mem.Allocator, options: Options, budget: ?Budget) ![]u8 {
    try checkBudget(budget);
    if (options.adapter == .codex) {
        const home = try codex.selectedHome(allocator, options.home, options.codex_home, options.codex_home_explicit, options.config_path, null);
        defer allocator.free(home);
        return if (options.config_path) |path| allocator.dupe(u8, path) else std.fmt.allocPrint(allocator, "{s}/config.toml", .{home});
    }
    if (options.config_path) |path| {
        try paths.validateAbsolute(path);
        return allocator.dupe(u8, path);
    }
    try paths.validateAbsolute(options.home);
    switch (options.adapter) {
        .codex => {
            if (options.codex_home) |home| {
                try paths.validateAbsolute(home);
                return std.fmt.allocPrint(allocator, "{s}/config.toml", .{home});
            }
            return std.fmt.allocPrint(allocator, "{s}/.codex/config.toml", .{options.home});
        },
        .git => {
            const conventional = try std.fmt.allocPrint(allocator, "{s}/.gitconfig", .{options.home});
            errdefer allocator.free(conventional);
            const current = try readConfigWithBudget(allocator, conventional, false, budget);
            defer current.deinit(allocator);
            if (current.existed) return conventional;
            const xdg = if (options.xdg_config_home) |base| blk: {
                try paths.validateAbsolute(base);
                break :blk try std.fmt.allocPrint(allocator, "{s}/git/config", .{base});
            } else try std.fmt.allocPrint(allocator, "{s}/.config/git/config", .{options.home});
            errdefer allocator.free(xdg);
            const alternate = try readConfigWithBudget(allocator, xdg, false, budget);
            defer alternate.deinit(allocator);
            if (alternate.existed) {
                allocator.free(conventional);
                return xdg;
            }
            allocator.free(xdg);
            return conventional;
        },
    }
}

const Custody = struct {
    directory: c.fd_t,
    lock: c.fd_t,
    pub fn acquire(allocator: std.mem.Allocator, options: Options) !Custody {
        return acquireWithBudget(allocator, options, null);
    }
    fn acquireWithBudget(allocator: std.mem.Allocator, options: Options, budget: ?Budget) !Custody {
        try checkBudget(budget);
        const root = try paths.openPrivateRoot(allocator, options.state_dir, true);
        defer close(root);
        try checkBudget(budget);
        if (c.mkdirat(root, "integrations", 0o700) != 0 and c.errno(-1) != .EXIST) return error.PathCreateFailed;
        const directory = c.openat(root, "integrations", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (directory < 0) return error.PathOpenFailed;
        errdefer close(directory);
        try paths.verifyPrivateFd(directory, c.S.IFDIR, 0o700);
        const name = try std.fmt.allocPrintSentinel(allocator, "{s}.lock", .{@tagName(options.adapter)}, 0);
        defer allocator.free(name);
        try checkBudget(budget);
        const lock = c.openat(directory, name.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(c.mode_t, 0o600));
        if (lock < 0) return error.LockOpenFailed;
        errdefer close(lock);
        try paths.verifyPrivateFd(lock, c.S.IFREG, 0o600);
        try validateFile(try statFile(lock), true);
        if (flock(lock, c.LOCK.EX | c.LOCK.NB) != 0) return error.IntegrationBusy;
        if (c.fsync(root) != 0) return error.ConfigSyncFailed;
        return .{ .directory = directory, .lock = lock };
    }
    pub fn deinit(self: Custody) void {
        close(self.lock);
        close(self.directory);
    }
};

fn writeAll(fd: c.fd_t, bytes: []const u8) !void {
    return writeAllWithBudget(fd, bytes, null);
}

fn writeAllWithBudget(fd: c.fd_t, bytes: []const u8, budget: ?Budget) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        try checkBudget(budget);
        const count = c.write(fd, bytes[cursor..].ptr, bytes.len - cursor);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.ConfigWriteFailed;
        }
        if (count == 0) return error.ConfigWriteFailed;
        cursor += @intCast(count);
    }
}

fn transactionId(io: std.Io) ![32]u8 {
    var random: [16]u8 = undefined;
    try io.randomSecure(&random);
    return std.fmt.bytesToHex(random, .lower);
}

fn temporaryName(allocator: std.mem.Allocator, name: []const u8, transaction: [32]u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(allocator, ".{s}.omux-{s}.tmp", .{ name[0..@min(name.len, 64)], transaction }, 0);
}

/// Registry writes have no plaintext temporary file. Existing destinations are
/// inspected before replacement; crash remnants carry ciphertext only.
fn privateWrite(io: std.Io, allocator: std.mem.Allocator, directory: c.fd_t, name: [:0]const u8, bytes: []const u8, budget: ?Budget) !void {
    try checkBudget(budget);
    const previous = try readAtWithBudget(allocator, directory, name, true, maximum_registry + header_size, budget);
    defer previous.deinit(allocator);
    const temporary = try temporaryName(allocator, name, try transactionId(io));
    defer allocator.free(temporary);
    try checkBudget(budget);
    const fd = c.openat(directory, temporary.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (fd < 0) return error.ConfigWriteFailed;
    defer close(fd);
    defer _ = c.unlinkat(directory, temporary.ptr, 0);
    if (c.fchmod(fd, 0o600) != 0) return error.PermissionChangeFailed;
    try writeAllWithBudget(fd, bytes, budget);
    try checkBudget(budget);
    if (c.fsync(fd) != 0) return error.ConfigSyncFailed;
    const check = try readAtWithBudget(allocator, directory, name, true, maximum_registry + header_size, budget);
    defer check.deinit(allocator);
    if (!check.matches(previous.existed, previous.mode, previous.bytes)) return error.ConfigChanged;
    try checkBudget(budget);
    if (c.renameat(directory, temporary.ptr, directory, name.ptr) != 0) return error.ConfigWriteFailed;
    if (c.fsync(directory) != 0) return error.ConfigSyncFailed;
}

fn encodedRecord(allocator: std.mem.Allocator, record: Record) ![]u8 {
    const fields = [_][]const u8{ record.config_path, record.original, record.installed, record.before, record.after };
    var length: usize = record_header;
    for (fields) |field| length += field.len;
    if (length > maximum_registry) return error.ConfigTooLarge;
    const bytes = try allocator.alloc(u8, length);
    bytes[0] = @backingInt(record.phase);
    bytes[1] = @intFromBool(record.original_existed);
    bytes[2] = @intFromBool(record.before_existed);
    bytes[3] = @intFromBool(record.after_existed);
    var cursor: usize = 4;
    for ([_]c.mode_t{ record.original_mode, record.before_mode, record.after_mode }) |mode| {
        std.mem.writeInt(u32, bytes[cursor..][0..4], @intCast(mode), .little);
        cursor += 4;
    }
    @memcpy(bytes[cursor..][0..64], &record.capability);
    cursor += 64;
    @memcpy(bytes[cursor..][0..32], &record.transaction);
    cursor += 32;
    for (fields) |field| {
        std.mem.writeInt(u32, bytes[cursor..][0..4], @intCast(field.len), .little);
        cursor += 4;
    }
    for (fields) |field| {
        @memcpy(bytes[cursor..][0..field.len], field);
        cursor += field.len;
    }
    return bytes;
}

fn decodedRecord(bytes: []const u8) !Record {
    if (bytes.len < record_header or bytes.len > maximum_registry) return error.CorruptIntegration;
    const phase = std.enums.fromInt(Phase, bytes[0]) orelse return error.CorruptIntegration;
    if (bytes[1] > 1 or bytes[2] > 1 or bytes[3] > 1) return error.CorruptIntegration;
    var modes: [3]c.mode_t = undefined;
    var cursor: usize = 4;
    for (&modes) |*mode| {
        const value = std.mem.readInt(u32, bytes[cursor..][0..4], .little);
        if (value > 0o777 or value & 0o022 != 0) return error.CorruptIntegration;
        mode.* = @intCast(value);
        cursor += 4;
    }
    const capability = bytes[cursor..][0..64].*;
    cursor += 64;
    const transaction = bytes[cursor..][0..32].*;
    cursor += 32;
    for (capability) |byte| if (!std.ascii.isHex(byte)) return error.CorruptIntegration;
    for (transaction) |byte| if (!std.ascii.isHex(byte)) return error.CorruptIntegration;
    var lengths: [5]usize = undefined;
    for (&lengths) |*length| {
        length.* = std.mem.readInt(u32, bytes[cursor..][0..4], .little);
        cursor += 4;
    }
    if (lengths[0] > 4096) return error.CorruptIntegration;
    var fields: [5][]const u8 = undefined;
    for (&fields, lengths, 0..) |*field, length, index| {
        if ((index != 0 and length > maximum_config) or length > bytes.len - cursor) return error.CorruptIntegration;
        field.* = bytes[cursor..][0..length];
        cursor += length;
    }
    if (cursor != bytes.len) return error.CorruptIntegration;
    try paths.validateAbsolute(fields[0]);
    return .{ .phase = phase, .original_existed = bytes[1] == 1, .before_existed = bytes[2] == 1, .after_existed = bytes[3] == 1, .original_mode = modes[0], .before_mode = modes[1], .after_mode = modes[2], .capability = capability, .transaction = transaction, .config_path = fields[0], .original = fields[1], .installed = fields[2], .before = fields[3], .after = fields[4] };
}

fn associatedData(allocator: std.mem.Allocator, options: Options) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}:{s}", .{ magic, @tagName(options.adapter), options.state_dir });
}
fn registryName(allocator: std.mem.Allocator, options: Options) ![:0]u8 {
    return std.fmt.allocPrintSentinel(allocator, "{s}.registry", .{@tagName(options.adapter)}, 0);
}
fn save(io: std.Io, allocator: std.mem.Allocator, directory: c.fd_t, options: Options, record: Record) !void {
    const budget = Budget.from(io, options);
    try budget.check();
    const plaintext = try encodedRecord(allocator, record);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    const ad = try associatedData(allocator, options);
    defer allocator.free(ad);
    try budget.check();
    var nonce: [Aead.nonce_length]u8 = undefined;
    try io.randomSecure(&nonce);
    const ciphertext = try allocator.alloc(u8, header_size + plaintext.len);
    defer allocator.free(ciphertext);
    @memcpy(ciphertext[0..magic.len], magic);
    @memcpy(ciphertext[magic.len..][0..Aead.nonce_length], &nonce);
    const tag: *[Aead.tag_length]u8 = ciphertext[magic.len + Aead.nonce_length ..][0..Aead.tag_length];
    Aead.encrypt(ciphertext[header_size..], tag, plaintext, ad, nonce, options.key);
    try budget.check();
    const name = try registryName(allocator, options);
    defer allocator.free(name);
    try privateWrite(io, allocator, directory, name, ciphertext, budget);
}
fn load(allocator: std.mem.Allocator, directory: c.fd_t, options: Options) !?Loaded {
    return loadWithBudget(allocator, directory, options, null);
}

fn loadWithBudget(allocator: std.mem.Allocator, directory: c.fd_t, options: Options, budget: ?Budget) !?Loaded {
    try checkBudget(budget);
    const name = try registryName(allocator, options);
    defer allocator.free(name);
    const current = try readAtWithBudget(allocator, directory, name, true, maximum_registry + header_size, budget);
    defer current.deinit(allocator);
    if (!current.existed) return null;
    if (current.bytes.len < header_size or !std.mem.eql(u8, current.bytes[0..magic.len], magic)) return error.CorruptIntegration;
    const plaintext = try allocator.alloc(u8, current.bytes.len - header_size);
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    const ad = try associatedData(allocator, options);
    defer allocator.free(ad);
    const nonce = current.bytes[magic.len..][0..Aead.nonce_length].*;
    const tag = current.bytes[magic.len + Aead.nonce_length ..][0..Aead.tag_length].*;
    try checkBudget(budget);
    try Aead.decrypt(plaintext, current.bytes[header_size..], tag, ad, nonce, options.key);
    try checkBudget(budget);
    return .{ .bytes = plaintext, .record = try decodedRecord(plaintext) };
}

fn capabilityName(allocator: std.mem.Allocator, options: Options) ![:0]u8 {
    return std.fmt.allocPrintSentinel(allocator, "{s}.capability", .{@tagName(options.adapter)}, 0);
}
fn ensureCapability(io: std.Io, allocator: std.mem.Allocator, directory: c.fd_t, options: Options, capability: [64]u8) !void {
    const budget = Budget.from(io, options);
    try budget.check();
    const name = try capabilityName(allocator, options);
    defer allocator.free(name);
    const current = try readAtWithBudget(allocator, directory, name, true, 64, budget);
    defer current.deinit(allocator);
    if (current.existed) {
        if (!std.mem.eql(u8, current.bytes, &capability)) return error.CapabilityConflict;
        return;
    }
    try privateWrite(io, allocator, directory, name, &capability, budget);
}
fn revokeCapability(allocator: std.mem.Allocator, directory: c.fd_t, options: Options, capability: [64]u8) !void {
    return revokeCapabilityWithBudget(allocator, directory, options, capability, null);
}

fn revokeCapabilityWithBudget(allocator: std.mem.Allocator, directory: c.fd_t, options: Options, capability: [64]u8, budget: ?Budget) !void {
    try checkBudget(budget);
    const name = try capabilityName(allocator, options);
    defer allocator.free(name);
    const current = try readAtWithBudget(allocator, directory, name, true, 64, budget);
    defer current.deinit(allocator);
    if (current.existed) {
        if (!std.mem.eql(u8, current.bytes, &capability)) return error.CapabilityConflict;
        try checkBudget(budget);
        if (c.unlinkat(directory, name.ptr, 0) != 0) return error.ConfigRemoveFailed;
        if (c.fsync(directory) != 0) return error.ConfigSyncFailed;
    }
}

fn cleanTemporary(allocator: std.mem.Allocator, record: Record, budget: ?Budget) !void {
    try checkBudget(budget);
    const parent = try openParentWithBudget(allocator, record.config_path, false, budget);
    defer close(parent);
    const name = try temporaryName(allocator, std.fs.path.basename(record.config_path), record.transaction);
    defer allocator.free(name);
    const current = try readAtWithBudget(allocator, parent, name, false, maximum_config, budget);
    defer current.deinit(allocator);
    if (current.existed) {
        try checkBudget(budget);
        if (c.unlinkat(parent, name.ptr, 0) != 0) return error.ConfigRemoveFailed;
        if (c.fsync(parent) != 0) return error.ConfigSyncFailed;
    }
}

/// Durable same-directory replacement with a final content/mode comparison.
/// The transaction-named temporary is recorded before creation and recoverable.
/// A noncooperating editor can race the final comparison and rename. Retained
/// encrypted before/after states support inspection and conflict recovery.
fn applyConfig(allocator: std.mem.Allocator, record: Record) !void {
    return applyConfigWithBudget(allocator, record, null);
}

fn applyConfigWithBudget(allocator: std.mem.Allocator, record: Record, budget: ?Budget) !void {
    try checkBudget(budget);
    const parent = try openParentWithBudget(allocator, record.config_path, true, budget);
    defer close(parent);
    const name = try allocator.dupeSentinel(u8, std.fs.path.basename(record.config_path), 0);
    defer allocator.free(name);
    const current = try readAtWithBudget(allocator, parent, name, false, maximum_config, budget);
    defer current.deinit(allocator);
    if (current.matches(record.after_existed, record.after_mode, record.after)) return;
    if (!current.matches(record.before_existed, record.before_mode, record.before)) return error.IntegrationConflict;
    if (!record.after_existed) {
        const check = try readAtWithBudget(allocator, parent, name, false, maximum_config, budget);
        defer check.deinit(allocator);
        if (!check.matches(record.before_existed, record.before_mode, record.before) or check.gid != current.gid) return error.IntegrationConflict;
        try checkBudget(budget);
        if (c.unlinkat(parent, name.ptr, 0) != 0) return error.ConfigRemoveFailed;
        if (c.fsync(parent) != 0) return error.ConfigSyncFailed;
        return;
    }
    const temporary = try temporaryName(allocator, name, record.transaction);
    defer allocator.free(temporary);
    try checkBudget(budget);
    var fd = c.openat(parent, temporary.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (fd < 0 and c.errno(fd) == .EXIST) {
        // A crash can leave the temporary with the original read-only mode.
        // Validate its descriptor before widening only this recorded file.
        const previous = c.openat(parent, temporary.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
        if (previous < 0) return error.ConfigWriteFailed;
        const status = statFile(previous) catch |err| {
            close(previous);
            return err;
        };
        validateFile(status, false) catch |err| {
            close(previous);
            return err;
        };
        checkBudget(budget) catch |err| {
            close(previous);
            return err;
        };
        if (c.fchmod(previous, 0o600) != 0) {
            close(previous);
            return error.ConfigWriteFailed;
        }
        close(previous);
        fd = c.openat(parent, temporary.ptr, .{ .ACCMODE = .RDWR, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
        if (fd >= 0) {
            const reopened = statFile(fd) catch |err| {
                close(fd);
                return err;
            };
            if (reopened.ino != status.ino or reopened.dev != status.dev) {
                close(fd);
                return error.IntegrationConflict;
            }
        }
    }
    if (fd < 0) return error.ConfigWriteFailed;
    defer close(fd);
    try validateFile(try statFile(fd), false);
    try checkBudget(budget);
    if (c.ftruncate(fd, 0) != 0 or c.fchmod(fd, 0o600) != 0) return error.ConfigWriteFailed;
    try writeAllWithBudget(fd, record.after, budget);
    try checkBudget(budget);
    if (c.fsync(fd) != 0) return error.ConfigSyncFailed;
    const check = try readAtWithBudget(allocator, parent, name, false, maximum_config, budget);
    defer check.deinit(allocator);
    if (!check.matches(record.before_existed, record.before_mode, record.before) or check.gid != current.gid) return error.IntegrationConflict;
    try checkBudget(budget);
    if (current.gid) |group| {
        if ((try statFile(fd)).gid != group and c.fchown(fd, std.math.maxInt(c.uid_t), group) != 0) return error.PermissionChangeFailed;
    }
    if (c.fchmod(fd, record.after_mode) != 0 or c.fsync(fd) != 0) return error.ConfigSyncFailed;
    try checkBudget(budget);
    if (c.renameat(parent, temporary.ptr, parent, name.ptr) != 0) return error.ConfigWriteFailed;
    if (c.fsync(parent) != 0) return error.ConfigSyncFailed;
}

fn complete(io: std.Io, allocator: std.mem.Allocator, directory: c.fd_t, options: Options, record: Record) !Recovery {
    return completeWithNativeCustody(io, allocator, directory, options, record, true);
}

fn requireNativeRecordCustody(options: Options, record: Record) !void {
    if (options.adapter != .codex) return;
    try requireNativeCustody(options, null);
    const transaction = options.native_custody.?.registry_transaction orelse return error.NativeCustodyPending;
    if (!std.mem.eql(u8, &transaction, &record.transaction)) return error.NativeCustodyGenerationMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&record.capability, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, options.native_custody.?.registry_capability_digest.?)) return error.NativeCustodyGenerationMismatch;
    if (record.phase != .removed and !std.crypto.timing_safe.eql([64]u8, record.capability, options.capability)) return error.NativeCustodyGenerationMismatch;
    // R-N13: repeat context fences at the locked record boundary, after the
    // original transaction/capability fence, before recovery or config writes.
    if (record.phase != .removed) {
        if (options.config_path) |requested| if (!std.mem.eql(u8, requested, record.config_path)) return error.IntegrationPathConflict;
        if (options.codex_home_explicit) {
            const home = options.codex_home orelse return error.InvalidHome;
            const parent = std.fs.path.dirname(record.config_path) orelse return error.InvalidHome;
            if (!std.mem.eql(u8, home, parent)) return error.IntegrationPathConflict;
        }
    }
    switch (record.phase) {
        .pending_install => try requireNativeCustody(options, .install),
        .pending_remove => try requireNativeCustody(options, .remove),
        .removed => if (options.native_custody.?.state != .install_ready) try requireNativeCustody(options, .remove),
        .installed => try requireNativeCustody(options, null),
    }
}

fn inspectNativeCustody(allocator: std.mem.Allocator, options: Options, budget: Budget) !void {
    if (options.adapter != .codex) return;
    if (try inspectRegistry(allocator, options, budget)) |loaded| {
        defer loaded.deinit(allocator);
        try requireNativeRecordCustody(options, loaded.record);
    } else if (options.native_custody.?.registry_transaction != null) return error.NativeCustodyPending;
}

fn completeWithNativeCustody(io: std.Io, allocator: std.mem.Allocator, directory: c.fd_t, options: Options, record: Record, comptime enforce_native_custody: bool) !Recovery {
    if (!enforce_native_custody and !builtin.is_test) @compileError("legacy native custody seeding is test-only");
    const budget = Budget.from(io, options);
    try budget.check();
    if (enforce_native_custody) try requireNativeRecordCustody(options, record);
    const current = try readConfigWithBudget(allocator, record.config_path, false, budget);
    defer current.deinit(allocator);
    if (!current.matches(record.before_existed, record.before_mode, record.before) and !current.matches(record.after_existed, record.after_mode, record.after)) return .conflict;
    var final = record;
    switch (record.phase) {
        .pending_install => {
            if (enforce_native_custody) try requireNativeCustody(options, .install);
            if (!std.crypto.timing_safe.eql([64]u8, record.capability, options.capability)) return .conflict;
            try ensureCapability(io, allocator, directory, options, record.capability);
            try applyConfigWithBudget(allocator, record, budget);
            final.phase = .installed;
        },
        .pending_remove => {
            if (enforce_native_custody) try requireNativeCustody(options, .remove);
            // A historical authenticated registry can still describe the same
            // native bytes after reinstall. Refuse its retired authority before
            // changing configuration, rather than discovering the conflict only
            // when revoking the current generation's capability afterward.
            if (!std.crypto.timing_safe.eql([64]u8, record.capability, options.capability)) return .conflict;
            try applyConfigWithBudget(allocator, record, budget);
            try revokeCapabilityWithBudget(allocator, directory, options, record.capability, budget);
            final.phase = .removed;
            final.original = "";
            final.installed = "";
        },
        .installed => return .installed,
        .removed => return .removed,
    }
    try cleanTemporary(allocator, record, budget);
    final.before = "";
    final.after = "";
    try save(io, allocator, directory, options, final);
    return if (final.phase == .installed) .installed else .removed;
}

fn verifyInstalled(allocator: std.mem.Allocator, options: Options, record: Record, budget: ?Budget) !void {
    try checkBudget(budget);
    const current = try readConfigWithBudget(allocator, record.config_path, false, budget);
    defer current.deinit(allocator);
    if (!current.existed) return error.IntegrationConflict;
    const removed = switch (options.adapter) {
        .git => try git.removeConfig(allocator, current.bytes, record.installed, record.original),
        .codex => try codex.removeConfig(allocator, current.bytes, record.installed, record.original),
    };
    defer {
        std.crypto.secureZero(u8, removed);
        allocator.free(removed);
    }
}

pub fn recover(io: std.Io, allocator: std.mem.Allocator, options: Options) !Recovery {
    const budget = Budget.from(io, options);
    try budget.check();
    try requireNativeCustody(options, null);
    try inspectNativeCustody(allocator, options, budget);
    if (options.adapter == .codex) {
        const home = try selectedCodexHome(io, allocator, options);
        allocator.free(home);
    }
    const custody = try Custody.acquireWithBudget(allocator, options, budget);
    defer custody.deinit();
    const loaded = (try loadWithBudget(allocator, custody.directory, options, budget)) orelse return .none;
    defer loaded.deinit(allocator);
    try requireNativeRecordCustody(options, loaded.record);
    switch (loaded.record.phase) {
        .installed => {
            if (!std.crypto.timing_safe.eql([64]u8, loaded.record.capability, options.capability)) return .conflict;
            verifyInstalled(allocator, options, loaded.record, budget) catch |err| switch (err) {
                error.IntegrationConflict, error.IntegrationModified, error.NotInstalled => return .conflict,
                else => return err,
            };
            try ensureCapability(io, allocator, custody.directory, options, loaded.record.capability);
            return .installed;
        },
        .removed => {
            // A sealed retired registry may be observed before reinstalling a
            // new epoch. Reading it must not revoke that new capability.
            if (options.adapter == .codex and options.native_custody.?.state == .install_ready) return .removed;
            try requireNativeCustody(options, .remove);
            try revokeCapabilityWithBudget(allocator, custody.directory, options, loaded.record.capability, budget);
            return .removed;
        },
        .pending_install, .pending_remove => return complete(io, allocator, custody.directory, options, loaded.record),
    }
}

fn outcome(allocator: std.mem.Allocator, options: Options, changed: bool, config_path: []const u8) !Outcome {
    const path = try allocator.dupe(u8, config_path);
    errdefer allocator.free(path);
    return .{ .changed = changed, .config_path = path, .capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/{s}.capability", .{ options.state_dir, @tagName(options.adapter) }) };
}

fn requireCodexHook(io: std.Io, allocator: std.mem.Allocator, options: Options) !void {
    try Budget.from(io, options).check();
    if (options.adapter != .codex) return;
    const home = try selectedCodexHome(io, allocator, options);
    defer allocator.free(home);
    if (options.native_socket) |socket| try paths.validateAbsolute(socket);
    var budget = try inventory.Budget.init(io, options.deadline);
    var found = try inventory.collect(io, allocator, home, &budget);
    defer found.deinit();
    var compatible = false;
    var explicit_found = false;
    // R-N13: publication is only a hint. Every eligible candidate is checked
    // against its retained filesystem identity and actual V2 peer credentials.
    // Several processes may prove compatible; setup selects no owner authority.
    for (found.candidates) |*candidate| {
        if (options.native_socket) |socket| {
            if (!std.mem.eql(u8, socket, candidate.endpoint_path)) continue;
            explicit_found = true;
        }
        const info = native_probe.inspectAutomaticOwnerWithDeadline(io, allocator, candidate, options.omux_version, budget.until) catch |err| switch (err) {
            error.NativeUnavailable => continue,
            else => return err,
        };
        defer info.deinit(allocator);
        compatible = compatible or info.support == .compatible_hook;
    }
    if (options.native_socket != null and !explicit_found) return error.NativeContextMismatch;
    if (!compatible) return error.NativeHookRequired;
    try budget.check(io);
    try found.verify(allocator);
    try budget.check(io);
}

/// R-N13: read-only context selection. An existing active registry fixes its
/// original config; explicit context changes refuse before custody effects.
pub fn selectedCodexHome(io: std.Io, allocator: std.mem.Allocator, options: Options) ![]u8 {
    if (options.adapter != .codex) return error.UnsupportedAdapter;
    if (try inspectRegistry(allocator, options, Budget.from(io, options))) |loaded| {
        defer loaded.deinit(allocator);
        if (loaded.record.phase != .removed) return codex.selectedHome(allocator, options.home, options.codex_home, options.codex_home_explicit, options.config_path, loaded.record.config_path);
    }
    return codex.selectedHome(allocator, options.home, options.codex_home, options.codex_home_explicit, options.config_path, null);
}

/// Read existing custody without creating directories, locks or capabilities.
/// A missing ancestor is distinct from an unsafe existing path.
fn inspectRegistry(allocator: std.mem.Allocator, options: Options, budget: Budget) !?Loaded {
    try budget.check();
    const anchor = try std.fmt.allocPrint(allocator, "{s}/.preflight", .{options.state_dir});
    defer allocator.free(anchor);
    const root = openParentWithBudget(allocator, anchor, false, budget) catch |err| switch (err) {
        error.ParentMissing => return null,
        else => return err,
    };
    defer close(root);
    try paths.verifyPrivateFd(root, c.S.IFDIR, 0o700);
    const directory = c.openat(root, "integrations", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return if (c.errno(directory) == .NOENT) null else error.UnsafePrivatePath;
    defer close(directory);
    try paths.verifyPrivateFd(directory, c.S.IFDIR, 0o700);
    return loadWithBudget(allocator, directory, options, budget);
}

/// Read-only original encrypted registry witness. Reading does not authorize
/// adoption: only the actor's previously sealed transaction may grant effects.
pub fn registryWitness(io: std.Io, allocator: std.mem.Allocator, options: Options) !?RegistryWitness {
    const loaded = (try inspectRegistry(allocator, options, Budget.from(io, options))) orelse return null;
    defer loaded.deinit(allocator);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&loaded.record.capability, &digest, .{});
    return .{ .phase = loaded.record.phase, .transaction = loaded.record.transaction, .capability_digest = digest };
}

/// Engine calls this before any removal detach. Setup repeats the check at its
/// locked write boundary; this read-only preflight does not authorize a hook or
/// reserve lifecycle state, and never changes native configuration.
pub fn preflightResult(io: std.Io, allocator: std.mem.Allocator, options: Options, operation: Operation) !void {
    const budget = Budget.from(io, options);
    try budget.check();
    if (options.adapter == .codex) {
        const home = try selectedCodexHome(io, allocator, options);
        allocator.free(home);
    }
    if (try inspectRegistry(allocator, options, budget)) |loaded| {
        defer loaded.deinit(allocator);
        if (operation == .remove or loaded.record.phase == .installed or loaded.record.phase == .pending_install or loaded.record.phase == .pending_remove)
            try checkCompletion(allocator, options.adapter, operation, loaded.record.config_path);
        if (operation == .remove or loaded.record.phase == .installed or loaded.record.phase == .pending_install) return;
    } else if (operation == .remove) return error.NotInstalled;
    const config_path = try chooseConfigWithBudget(allocator, options, budget);
    defer allocator.free(config_path);
    try checkCompletion(allocator, options.adapter, operation, config_path);
}

pub fn install(io: std.Io, allocator: std.mem.Allocator, requested_options: Options) !Outcome {
    const budget = Budget.from(io, requested_options);
    try budget.check();
    try requireNativeCustody(requested_options, .install);
    try inspectNativeCustody(allocator, requested_options, budget);
    var options = requested_options;
    const selected_home = if (options.adapter == .codex) try selectedCodexHome(io, allocator, options) else null;
    defer if (selected_home) |home| allocator.free(home);
    if (selected_home) |home| {
        // Pin exactly the probed context through the subsequent locked writes.
        options.codex_home = home;
        options.codex_home_explicit = true;
    }
    try preflightResult(io, allocator, options, .install);
    // Capability negotiation precedes even directory/config creation.
    try requireCodexHook(io, allocator, options);
    for (options.capability) |byte| if (!std.ascii.isHex(byte)) return error.InvalidAdapterCapability;
    const custody = try Custody.acquireWithBudget(allocator, options, budget);
    defer custody.deinit();
    if (try loadWithBudget(allocator, custody.directory, options, budget)) |loaded| {
        defer loaded.deinit(allocator);
        try requireNativeRecordCustody(options, loaded.record);
        if (loaded.record.phase != .removed) try checkCompletion(allocator, options.adapter, .install, loaded.record.config_path);
        switch (loaded.record.phase) {
            .installed => {
                if (!std.crypto.timing_safe.eql([64]u8, loaded.record.capability, options.capability)) return error.CapabilityGenerationMismatch;
                if (options.config_path) |requested| if (!std.mem.eql(u8, requested, loaded.record.config_path)) return error.IntegrationPathConflict;
                try verifyInstalled(allocator, options, loaded.record, budget);
                try ensureCapability(io, allocator, custody.directory, options, loaded.record.capability);
                return outcome(allocator, options, false, loaded.record.config_path);
            },
            .pending_install => {
                if (try complete(io, allocator, custody.directory, options, loaded.record) == .conflict) return error.IntegrationConflict;
                return outcome(allocator, options, true, loaded.record.config_path);
            },
            .pending_remove => {
                if (try complete(io, allocator, custody.directory, options, loaded.record) == .conflict) return error.IntegrationConflict;
            },
            .removed => {},
        }
    }
    const config_path = try chooseConfigWithBudget(allocator, options, budget);
    defer allocator.free(config_path);
    try checkCompletion(allocator, options.adapter, .install, config_path);
    const before = try readConfigWithBudget(allocator, config_path, false, budget);
    defer before.deinit(allocator);
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/{s}.capability", .{ options.state_dir, @tagName(options.adapter) });
    defer allocator.free(capability_path);
    const installed = switch (options.adapter) {
        .git => try git.installConfig(allocator, before.bytes, "omux"),
        .codex => try codex.installConfig(allocator, before.bytes, .{ .broker_socket = options.broker_socket, .capability_path = capability_path }),
    };
    defer {
        std.crypto.secureZero(u8, installed);
        allocator.free(installed);
    }
    if (installed.len > maximum_config) return error.ConfigTooLarge;
    try budget.check();
    const record: Record = .{ .phase = .pending_install, .original_existed = before.existed, .before_existed = before.existed, .after_existed = true, .original_mode = before.mode, .before_mode = before.mode, .after_mode = before.mode, .capability = options.capability, .transaction = try transactionId(io), .config_path = config_path, .original = before.bytes, .installed = installed, .before = before.bytes, .after = installed };
    try save(io, allocator, custody.directory, options, record);
    var completion_options = options;
    if (options.adapter == .codex) {
        // Same-call creation grants only this exclusively saved transaction.
        // A crash before actor sealing leaves no restart adoption permission.
        completion_options.native_custody.?.registry_transaction = record.transaction;
        completion_options.native_custody.?.registry_capability_digest = completion_options.native_custody.?.capability_digest;
    }
    if (try complete(io, allocator, custody.directory, completion_options, record) == .conflict) return error.IntegrationConflict;
    return outcome(allocator, options, true, config_path);
}

pub fn remove(io: std.Io, allocator: std.mem.Allocator, options: Options) !Outcome {
    const budget = Budget.from(io, options);
    try budget.check();
    try requireNativeCustody(options, .remove);
    try inspectNativeCustody(allocator, options, budget);
    try preflightResult(io, allocator, options, .remove);
    const custody = try Custody.acquireWithBudget(allocator, options, budget);
    defer custody.deinit();
    const loaded = (try loadWithBudget(allocator, custody.directory, options, budget)) orelse return error.NotInstalled;
    defer loaded.deinit(allocator);
    try requireNativeRecordCustody(options, loaded.record);
    try checkCompletion(allocator, options.adapter, .remove, loaded.record.config_path);
    if (loaded.record.phase != .removed and !std.crypto.timing_safe.eql([64]u8, loaded.record.capability, options.capability)) return error.CapabilityGenerationMismatch;
    switch (loaded.record.phase) {
        .removed => {
            try revokeCapabilityWithBudget(allocator, custody.directory, options, loaded.record.capability, budget);
            return outcome(allocator, options, false, loaded.record.config_path);
        },
        .pending_remove => {
            if (try complete(io, allocator, custody.directory, options, loaded.record) == .conflict) return error.IntegrationConflict;
            return outcome(allocator, options, true, loaded.record.config_path);
        },
        .pending_install => {
            if (try complete(io, allocator, custody.directory, options, loaded.record) == .conflict) return error.IntegrationConflict;
        },
        .installed => {},
    }
    const before = try readConfigWithBudget(allocator, loaded.record.config_path, false, budget);
    defer before.deinit(allocator);
    const restored = switch (options.adapter) {
        .git => try git.removeConfig(allocator, before.bytes, loaded.record.installed, loaded.record.original),
        .codex => try codex.removeConfig(allocator, before.bytes, loaded.record.installed, loaded.record.original),
    };
    defer {
        std.crypto.secureZero(u8, restored);
        allocator.free(restored);
    }
    var record = loaded.record;
    record.phase = .pending_remove;
    // Codex's original installation transaction is a durable actor witness;
    // removal intent has its own sealed global operation and capability epoch.
    if (options.adapter != .codex) record.transaction = try transactionId(io);
    record.before_existed = before.existed;
    record.before_mode = before.mode;
    record.before = before.bytes;
    record.after_existed = record.original_existed or restored.len != 0;
    record.after_mode = before.mode;
    record.after = restored;
    try save(io, allocator, custody.directory, options, record);
    if (try complete(io, allocator, custody.directory, options, record) == .conflict) return error.IntegrationConflict;
    return outcome(allocator, options, true, record.config_path);
}

/// Synthetic acceptance fixtures can represent custody written before the
/// completion bound existed. There is no non-test seeding entrypoint. This
/// bypasses completion preflight, hook negotiation and the newly required native
/// owner permit to represent legacy custody. Filesystem custody, encryption,
/// capability generation and transactional config writes are real.
pub const LegacyCustodyForTest = if (builtin.is_test) struct {
    pub fn seedInstalled(io: std.Io, allocator: std.mem.Allocator, options: Options) !Outcome {
        const config_path = options.config_path orelse return error.FixtureConfigPathRequired;
        try paths.validateAbsolute(config_path);
        const budget = Budget.from(io, options);
        try budget.check();
        for (options.capability) |byte| if (!std.ascii.isHex(byte)) return error.InvalidAdapterCapability;
        const custody = try Custody.acquireWithBudget(allocator, options, budget);
        defer custody.deinit();
        if (try loadWithBudget(allocator, custody.directory, options, budget)) |existing| {
            existing.deinit(allocator);
            return error.FixtureCustodyAlreadyPresent;
        }
        const before = try readConfigWithBudget(allocator, config_path, false, budget);
        defer before.deinit(allocator);
        const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/{s}.capability", .{ options.state_dir, @tagName(options.adapter) });
        defer allocator.free(capability_path);
        const installed = switch (options.adapter) {
            .git => try git.installConfig(allocator, before.bytes, "omux"),
            .codex => try codex.installConfig(allocator, before.bytes, .{ .broker_socket = options.broker_socket, .capability_path = capability_path }),
        };
        defer {
            std.crypto.secureZero(u8, installed);
            allocator.free(installed);
        }
        if (installed.len > maximum_config) return error.ConfigTooLarge;
        const record: Record = .{ .phase = .pending_install, .original_existed = before.existed, .before_existed = before.existed, .after_existed = true, .original_mode = before.mode, .before_mode = before.mode, .after_mode = before.mode, .capability = options.capability, .transaction = try transactionId(io), .config_path = config_path, .original = before.bytes, .installed = installed, .before = before.bytes, .after = installed };
        try save(io, allocator, custody.directory, options, record);
        if (try completeWithNativeCustody(io, allocator, custody.directory, options, record, false) != .installed) return error.FixtureCustodyConflict;
        return outcome(allocator, options, true, config_path);
    }

    /// R-N13: represent a legacy crash after encrypted pending_remove was saved,
    /// without granting a reviewed owner completion permit or restoring config.
    pub fn seedPendingRemoval(io: std.Io, allocator: std.mem.Allocator, options: Options) !void {
        const custody = try Custody.acquire(allocator, options);
        defer custody.deinit();
        const loaded = (try load(allocator, custody.directory, options)) orelse return error.NotInstalled;
        defer loaded.deinit(allocator);
        if (loaded.record.phase != .installed) return error.FixtureCustodyConflict;
        const before = try readConfig(allocator, loaded.record.config_path, false);
        defer before.deinit(allocator);
        const restored = switch (options.adapter) {
            .git => try git.removeConfig(allocator, before.bytes, loaded.record.installed, loaded.record.original),
            .codex => try codex.removeConfig(allocator, before.bytes, loaded.record.installed, loaded.record.original),
        };
        defer {
            std.crypto.secureZero(u8, restored);
            allocator.free(restored);
        }
        var record = loaded.record;
        record.phase = .pending_remove;
        record.transaction = try transactionId(io);
        record.before_existed = before.existed;
        record.before_mode = before.mode;
        record.before = before.bytes;
        record.after_existed = record.original_existed or restored.len != 0;
        record.after_mode = before.mode;
        record.after = restored;
        try save(io, allocator, custody.directory, options, record);
    }
} else struct {};

const Fixture = struct {
    base: []const u8,
    arena: std.heap.ArenaAllocator,
    options: Options,
    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        // Bazel's fake-username sandbox can have a foreign-owned workspace
        // ancestor. Test custody in an owned directory under the system's
        // canonical sticky temporary root, preserving production validation.
        var random: [16]u8 = undefined;
        std.testing.io.random(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const base = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-setup-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", suffix }, 0);
        if (c.mkdir(base.ptr, 0o700) != 0) return error.FixtureSetupFailed;
        errdefer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch {};
        const home = try std.fmt.allocPrint(allocator, "{s}/home", .{base});
        const home_fd = try paths.openPrivateRoot(allocator, home, true);
        close(home_fd);
        // Finish allocations while this arena is their owner. Copying it into
        // the return value before a later allocation can lose a backing node.
        const options: Options = .{ .state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{base}), .home = home, .adapter = .git, .capability = @splat('a'), .broker_socket = try std.fmt.allocPrint(allocator, "{s}/state/run/adapter.sock", .{base}), .omux_version = "fixture", .key = @splat(42) };
        return .{ .base = base, .arena = arena, .options = options };
    }
    fn deinit(self: *Fixture) void {
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.base) catch {};
        self.arena.deinit();
    }
    fn write(self: *Fixture, path: []const u8, bytes: []const u8, mode: c.mode_t) !void {
        const allocator = self.arena.allocator();
        const parent = try openParent(allocator, path, true);
        defer close(parent);
        const name = try allocator.dupeSentinel(u8, std.fs.path.basename(path), 0);
        const fd = c.openat(parent, name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true }, mode);
        if (fd < 0) return error.ConfigWriteFailed;
        defer close(fd);
        try writeAll(fd, bytes);
        if (c.fchmod(fd, mode) != 0) return error.PermissionChangeFailed;
    }
};

// Synthetic producer fixtures deliberately seal finite dummy role bytes. They
// exercise retained evidence/installed filesystem fences only: package producer
// acquisition, ELF validity, process attribution and native support are unproved.
const RuntimeSelectionFixture = struct {
    fixture: Fixture,
    directory: c.fd_t,
    record: RuntimeSelectionRecord,
    expected: RuntimeSelectionExpectation,
    evidence: []u8,

    fn init() !RuntimeSelectionFixture {
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.SkipZigTest;
        var fixture = try Fixture.init();
        errdefer fixture.deinit();
        const allocator = std.testing.allocator;
        fixture.options.adapter = .codex;
        fixture.options.config_path = try std.fmt.allocPrint(fixture.arena.allocator(), "{s}/.codex/config.toml", .{fixture.options.home});
        const installed = try LegacyCustodyForTest.seedInstalled(std.testing.io, allocator, fixture.options);
        defer installed.deinit(allocator);
        const witness = (try registryWitness(std.testing.io, allocator, fixture.options)).?;
        fixture.options.native_custody = .{
            .adapter_epoch = 7,
            .capability_digest = witness.capability_digest,
            .snapshot_digest = @splat(9),
            .state = .retain_ready,
            .registry_transaction = witness.transaction,
            .registry_capability_digest = witness.capability_digest,
        };
        const root = try std.fmt.allocPrint(allocator, "{s}/runtime", .{fixture.base});
        defer allocator.free(root);
        const directory = try paths.openPrivateRoot(allocator, root, true);
        errdefer close(directory);
        for (runtime_role_paths) |relative| {
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, relative });
            defer allocator.free(path);
            try fixture.write(path, relative, 0o755);
        }
        const status = try statFile(directory);
        var roles: [3]RuntimeRole = undefined;
        for (&roles, runtime_role_paths) |*role, bytes| {
            role.bytes = bytes.len;
            std.crypto.hash.sha2.Sha256.hash(bytes, &role.sha256, .{});
        }
        var result: RuntimeSelectionFixture = .{
            .fixture = fixture,
            .directory = directory,
            .record = .{
                .schema_version = 1,
                .channel = .development,
                .target = .x86_64_linux,
                .launch_profile = .linux_explicit_bundled_loader_v1,
                .upstream_commit = @splat('a'),
                .artifact_selection_sha256 = @splat(1),
                .archive_sha256 = @splat(2),
                .manifest_sha256 = @splat(3),
                .runtime_receipt_sha256 = @splat(4),
                .source_receipt_sha256 = @splat(5),
                .producer_receipt_sha256 = @splat(6),
                .installation = .{
                    .transaction = witness.transaction,
                    .adapter_epoch = 7,
                    .capability_digest = witness.capability_digest,
                    .directory_device = status.dev,
                    .directory_inode = status.ino,
                    .uid = status.uid,
                    .gid = status.gid,
                },
                .launcher = roles[0],
                .backend = roles[1],
                .loader = roles[2],
            },
            .expected = .{ .record_sha256 = @splat(1), .channel = .development, .target = .x86_64_linux, .directory = directory },
            .evidence = undefined,
        };
        result.evidence = try result.sealRecord();
        return result;
    }

    fn sealRecord(self: *RuntimeSelectionFixture) ![]u8 {
        const allocator = std.testing.allocator;
        const bytes = try std.json.Stringify.valueAlloc(allocator, self.record, .{});
        defer allocator.free(bytes);
        return self.sealBytes(bytes);
    }

    fn sealBytes(self: *RuntimeSelectionFixture, bytes: []const u8) ![]u8 {
        std.crypto.hash.sha2.Sha256.hash(bytes, &self.expected.record_sha256, .{});
        return envelope.seal(std.testing.io, std.testing.allocator, self.fixture.options.key, try runtimeSelectionContext(self.fixture.options, self.expected), bytes);
    }

    fn verify(self: *RuntimeSelectionFixture) !*VerifiedRuntimeSelection {
        return verifyRetainedRuntimeSelection(std.testing.io, std.testing.allocator, self.fixture.options, self.expected, self.evidence);
    }

    fn deinit(self: *RuntimeSelectionFixture) void {
        std.testing.allocator.free(self.evidence);
        close(self.directory);
        self.fixture.deinit();
    }
};

test "R-N13 retained runtime selection authenticates bytes and keeps backend distinct from loader" {
    var fixture = try RuntimeSelectionFixture.init();
    defer fixture.deinit();
    const verified = try fixture.verify();
    defer verified.deinit(std.testing.allocator);
    try verified.recheck(std.testing.io, std.testing.allocator, fixture.fixture.options, fixture.expected);
    try std.testing.expect(!std.meta.eql(fixture.record.backend.sha256, fixture.record.loader.sha256));
    fixture.evidence[fixture.evidence.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, fixture.verify());
    fixture.evidence[fixture.evidence.len - 1] ^= 1;
    fixture.fixture.options.key[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, fixture.verify());
}

test "R-N13 retained runtime selection refuses channel epoch digest and actor custody drift" {
    var fixture = try RuntimeSelectionFixture.init();
    defer fixture.deinit();
    const verified = try fixture.verify();
    defer verified.deinit(std.testing.allocator);
    const saved = fixture.expected;
    fixture.expected.channel = .release;
    try std.testing.expectError(error.AuthenticationFailed, fixture.verify());
    try std.testing.expectError(error.RuntimeSelectionDrift, verified.recheck(std.testing.io, std.testing.allocator, fixture.fixture.options, fixture.expected));
    fixture.expected = saved;
    fixture.expected.record_sha256[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, fixture.verify());
    try std.testing.expectError(error.RuntimeSelectionDrift, verified.recheck(std.testing.io, std.testing.allocator, fixture.fixture.options, fixture.expected));
    fixture.expected = saved;
    const state_dir = fixture.fixture.options.state_dir;
    fixture.fixture.options.state_dir = "/unselected-installation-custody";
    try std.testing.expectError(error.AuthenticationFailed, fixture.verify());
    try std.testing.expectError(error.RuntimeSelectionDrift, verified.recheck(std.testing.io, std.testing.allocator, fixture.fixture.options, fixture.expected));
    fixture.fixture.options.state_dir = state_dir;
    const custody = fixture.fixture.options.native_custody.?;
    fixture.fixture.options.native_custody.?.adapter_epoch += 1;
    try std.testing.expectError(error.AuthenticationFailed, fixture.verify());
    try std.testing.expectError(error.RuntimeSelectionDrift, verified.recheck(std.testing.io, std.testing.allocator, fixture.fixture.options, fixture.expected));
    fixture.fixture.options.native_custody = custody;
    fixture.fixture.options.native_custody.?.registry_transaction.?[0] = if (custody.registry_transaction.?[0] == 'a') 'b' else 'a';
    try std.testing.expectError(error.RuntimeSelectionDrift, fixture.verify());
    fixture.fixture.options.native_custody = custody;
    fixture.fixture.options.native_custody.?.registry_transaction = null;
    fixture.fixture.options.native_custody.?.registry_capability_digest = null;
    try std.testing.expectError(error.NativeCustodyPending, fixture.verify());
    fixture.fixture.options.native_custody = custody;
    fixture.fixture.options.capability[0] = 'b';
    try std.testing.expectError(error.NativeCustodyGenerationMismatch, fixture.verify());
}

test "R-N13 installed runtime role changes unsafe permissions and symlink substitution refuse" {
    var fixture = try RuntimeSelectionFixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const verified = try fixture.verify();
    defer verified.deinit(allocator);
    for (runtime_role_paths) |relative| {
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/runtime/{s}", .{ fixture.fixture.base, relative }, 0);
        defer allocator.free(path);
        const changed = try allocator.dupe(u8, relative);
        defer allocator.free(changed);
        changed[0] ^= 1;
        try fixture.fixture.write(path, changed, 0o755);
        try std.testing.expectError(error.RuntimeSelectionDrift, fixture.verify());
        try std.testing.expectError(error.RuntimeSelectionDrift, verified.recheck(std.testing.io, allocator, fixture.fixture.options, fixture.expected));
        try fixture.fixture.write(path, relative, 0o644);
        try std.testing.expectError(error.RuntimeInstallationOwnershipMismatch, fixture.verify());
        if (c.unlink(path.ptr) != 0 or c.symlink("/unselected-runtime", path.ptr) != 0) return error.FixtureSetupFailed;
        try std.testing.expectError(error.RuntimeInstallationUnavailable, fixture.verify());
        if (c.unlink(path.ptr) != 0) return error.FixtureSetupFailed;
        try fixture.fixture.write(path, relative, 0o755);
    }
    try verified.recheck(std.testing.io, allocator, fixture.fixture.options, fixture.expected);
    const foreign = try paths.openPrivateRoot(allocator, fixture.fixture.options.home, false);
    defer close(foreign);
    fixture.expected.directory = foreign;
    try std.testing.expectError(error.RuntimeSelectionDrift, fixture.verify());
}

test "R-N13 pending recovery cannot reuse retained installed runtime authority or mutate configuration" {
    var fixture = try RuntimeSelectionFixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const verified = try fixture.verify();
    defer verified.deinit(allocator);
    try LegacyCustodyForTest.seedPendingRemoval(std.testing.io, allocator, fixture.fixture.options);
    const witness = (try registryWitness(std.testing.io, allocator, fixture.fixture.options)).?;
    try std.testing.expectEqual(RegistryPhase.pending_remove, witness.phase);
    const config = try chooseConfig(allocator, fixture.fixture.options);
    defer allocator.free(config);
    const before = try readConfig(allocator, config, false);
    defer before.deinit(allocator);
    try std.testing.expectError(error.NativeCustodyPending, fixture.verify());
    try std.testing.expectError(error.NativeCustodyPending, verified.recheck(std.testing.io, allocator, fixture.fixture.options, fixture.expected));
    const after = try readConfig(allocator, config, false);
    defer after.deinit(allocator);
    try std.testing.expect(std.meta.eql(witness, (try registryWitness(std.testing.io, allocator, fixture.fixture.options)).?));
    try std.testing.expect(std.mem.eql(u8, before.bytes, after.bytes));
}

test "R-N13 authenticated runtime record still rejects malformed facts bounds and unknown capability claims" {
    var fixture = try RuntimeSelectionFixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const saved = fixture.record;
    fixture.record.backend.bytes = runtime_role_limits[1] + 1;
    const evidence = try fixture.sealRecord();
    defer allocator.free(evidence);
    try std.testing.expectError(error.InvalidRuntimeSelection, verifyRetainedRuntimeSelection(std.testing.io, allocator, fixture.fixture.options, fixture.expected, evidence));
    fixture.record = saved;
    fixture.record.source_receipt_sha256 = @splat(0);
    const no_source = try fixture.sealRecord();
    defer allocator.free(no_source);
    try std.testing.expectError(error.InvalidRuntimeSelection, verifyRetainedRuntimeSelection(std.testing.io, allocator, fixture.fixture.options, fixture.expected, no_source));
    fixture.record = saved;
    const bytes = try std.json.Stringify.valueAlloc(allocator, fixture.record, .{});
    defer allocator.free(bytes);
    const claimed = try std.fmt.allocPrint(allocator, "{{\"native_support\":true,{s}", .{bytes[1..]});
    defer allocator.free(claimed);
    const claimed_evidence = try fixture.sealBytes(claimed);
    defer allocator.free(claimed_evidence);
    try std.testing.expectError(error.UnknownField, verifyRetainedRuntimeSelection(std.testing.io, allocator, fixture.fixture.options, fixture.expected, claimed_evidence));
    const duplicate = try std.fmt.allocPrint(allocator, "{{\"schema_version\":1,{s}", .{bytes[1..]});
    defer allocator.free(duplicate);
    const duplicate_evidence = try fixture.sealBytes(duplicate);
    defer allocator.free(duplicate_evidence);
    try std.testing.expectError(error.DuplicateField, verifyRetainedRuntimeSelection(std.testing.io, allocator, fixture.fixture.options, fixture.expected, duplicate_evidence));
}

test "native config installation preserves permissions, encrypts backups and removes only its block" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try chooseConfig(allocator, fixture.options);
    defer allocator.free(config);
    const original = "[credential]\n helper = fixture-native\n[user]\n name = Fixture\n# confidential-fixture-value\n";
    try fixture.write(config, original, 0o640);
    const installed = try install(std.testing.io, allocator, fixture.options);
    defer installed.deinit(allocator);
    const after = try readConfig(allocator, config, false);
    defer after.deinit(allocator);
    try std.testing.expectEqual(@as(c.mode_t, 0o640), after.mode);
    try std.testing.expect(std.mem.indexOf(u8, after.bytes, "fixture-native") != null);
    const custody = try Custody.acquire(allocator, fixture.options);
    const registry_name = try registryName(allocator, fixture.options);
    defer allocator.free(registry_name);
    const encrypted = try readAt(allocator, custody.directory, registry_name, true, maximum_registry + header_size);
    defer encrypted.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, encrypted.bytes, "confidential-fixture-value") == null);
    custody.deinit();
    const edited = try std.mem.concat(allocator, u8, &.{ after.bytes, "[core]\n editor = fixture-editor\n" });
    defer allocator.free(edited);
    try fixture.write(config, edited, 0o640);
    const removed = try remove(std.testing.io, allocator, fixture.options);
    defer removed.deinit(allocator);
    const restored = try readConfig(allocator, config, false);
    defer restored.deinit(allocator);
    try std.testing.expectEqualStrings(original ++ "[core]\n editor = fixture-editor\n", restored.bytes);
    try std.testing.expectEqual(@as(c.mode_t, 0o640), restored.mode);
    try std.testing.expectError(error.AdapterNotInstalled, paths.readCapability(allocator, fixture.options.state_dir, "git"));
}

test "missing native config is deleted on removal and XDG existing configuration is honored" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const installed = try install(std.testing.io, allocator, fixture.options);
    defer installed.deinit(allocator);
    const removed = try remove(std.testing.io, allocator, fixture.options);
    defer removed.deinit(allocator);
    const current = try readConfig(allocator, installed.config_path, false);
    defer current.deinit(allocator);
    try std.testing.expect(!current.existed);
    const xdg = try std.fmt.allocPrint(allocator, "{s}/.config/git/config", .{fixture.options.home});
    defer allocator.free(xdg);
    try fixture.write(xdg, "# xdg fixture\n", 0o600);
    const chosen = try chooseConfig(allocator, fixture.options);
    defer allocator.free(chosen);
    try std.testing.expectEqualStrings(xdg, chosen);
}

test "pending operation recovery finishes exact states and refuses intervening edits" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try chooseConfig(allocator, fixture.options);
    defer allocator.free(config);
    const installed = try git.installConfig(allocator, "# original\n", "omux");
    defer allocator.free(installed);
    const record: Record = .{ .phase = .pending_install, .original_existed = true, .before_existed = true, .after_existed = true, .original_mode = 0o600, .before_mode = 0o600, .after_mode = 0o600, .capability = fixture.options.capability, .transaction = try transactionId(std.testing.io), .config_path = config, .original = "# original\n", .installed = installed, .before = "# original\n", .after = installed };
    const custody = try Custody.acquire(allocator, fixture.options);
    try save(std.testing.io, allocator, custody.directory, fixture.options, record);
    custody.deinit();
    try fixture.write(config, "# independent edit\n", 0o600);
    try std.testing.expectEqual(Recovery.conflict, try recover(std.testing.io, allocator, fixture.options));
    const untouched = try readConfig(allocator, config, false);
    defer untouched.deinit(allocator);
    try std.testing.expectEqualStrings("# independent edit\n", untouched.bytes);
    try fixture.write(config, "# original\n", 0o600);
    try std.testing.expectEqual(Recovery.installed, try recover(std.testing.io, allocator, fixture.options));
    const completed = try readConfig(allocator, config, false);
    defer completed.deinit(allocator);
    try std.testing.expectEqualStrings(installed, completed.bytes);
    var wrong_key = fixture.options;
    wrong_key.key = @splat(1);
    try std.testing.expectError(error.AuthenticationFailed, recover(std.testing.io, allocator, wrong_key));
}

test "native config symlinks, foreign writes, modified integration and private-root widening fail closed" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try chooseConfig(allocator, fixture.options);
    defer allocator.free(config);
    try fixture.write(config, "# fixture\n", 0o666);
    try std.testing.expectError(error.UnsafeConfigFile, install(std.testing.io, allocator, fixture.options));
    try fixture.write(config, "# fixture\n", 0o600);
    const parent = try openParent(allocator, config, false);
    defer close(parent);
    const name = try allocator.dupeSentinel(u8, std.fs.path.basename(config), 0);
    defer allocator.free(name);
    if (c.unlinkat(parent, name.ptr, 0) != 0 or c.symlinkat("other-config", parent, name.ptr) != 0) return error.FixtureSetupFailed;
    try std.testing.expectError(error.UnsafeConfigFile, install(std.testing.io, allocator, fixture.options));
    if (c.unlinkat(parent, name.ptr, 0) != 0) return error.FixtureSetupFailed;
    const installed = try install(std.testing.io, allocator, fixture.options);
    defer installed.deinit(allocator);
    try fixture.write(config, "# BEGIN OMUX GIT INTEGRATION v1\n# edited\n# END OMUX GIT INTEGRATION v1\n", 0o600);
    try std.testing.expectError(error.IntegrationModified, remove(std.testing.io, allocator, fixture.options));
    const state = try paths.openPrivateRoot(allocator, fixture.options.state_dir, false);
    defer close(state);
    if (c.fchmod(state, 0o755) != 0) return error.PermissionChangeFailed;
    try std.testing.expectError(error.UnsafePrivatePath, install(std.testing.io, allocator, fixture.options));
}

test "recovery completes removal after configuration was replaced and erases retained backup plaintext" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try chooseConfig(allocator, fixture.options);
    defer allocator.free(config);
    const original = "# native fixture\n";
    try fixture.write(config, original, 0o600);
    const result = try install(std.testing.io, allocator, fixture.options);
    defer result.deinit(allocator);
    const custody = try Custody.acquire(allocator, fixture.options);
    const loaded = (try load(allocator, custody.directory, fixture.options)).?;
    defer loaded.deinit(allocator);
    var record = loaded.record;
    record.phase = .pending_remove;
    record.transaction = try transactionId(std.testing.io);
    record.before_existed = true;
    record.after_existed = true;
    record.before = record.installed;
    record.after = record.original;
    try save(std.testing.io, allocator, custody.directory, fixture.options, record);
    try applyConfig(allocator, record);
    custody.deinit();
    // Simulate a crash after native replacement and before capability revoke.
    const capability = try paths.readCapability(allocator, fixture.options.state_dir, "git");
    defer allocator.free(capability);
    try std.testing.expectEqual(Recovery.removed, try recover(std.testing.io, allocator, fixture.options));
    try std.testing.expectError(error.AdapterNotInstalled, paths.readCapability(allocator, fixture.options.state_dir, "git"));
    const check_custody = try Custody.acquire(allocator, fixture.options);
    defer check_custody.deinit();
    const removed = (try load(allocator, check_custody.directory, fixture.options)).?;
    defer removed.deinit(allocator);
    try std.testing.expectEqual(Phase.removed, removed.record.phase);
    try std.testing.expectEqual(@as(usize, 0), removed.record.original.len + removed.record.installed.len + removed.record.before.len + removed.record.after.len);
    const restored = try readConfig(allocator, config, false);
    defer restored.deinit(allocator);
    try std.testing.expectEqualStrings(original, restored.bytes);
}

test "registry decoding rejects invalid mode and unbounded lengths without narrowing traps" {
    const allocator = std.testing.allocator;
    const record: Record = .{ .phase = .removed, .original_existed = false, .before_existed = false, .after_existed = false, .original_mode = 0o600, .before_mode = 0o600, .after_mode = 0o600, .capability = @splat('a'), .transaction = @splat('b'), .config_path = "/fixture/config", .original = "", .installed = "" };
    const bytes = try encodedRecord(allocator, record);
    defer allocator.free(bytes);
    std.mem.writeInt(u32, bytes[4..][0..4], 0xffffffff, .little);
    try std.testing.expectError(error.CorruptIntegration, decodedRecord(bytes));
    std.mem.writeInt(u32, bytes[4..][0..4], 0o600, .little);
    std.mem.writeInt(u32, bytes[4 + 12 + 64 + 32 ..][0..4], 0xffffffff, .little);
    try std.testing.expectError(error.CorruptIntegration, decodedRecord(bytes));
}

test "Codex native verification precedes configuration and capability creation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    var options = fixture.options;
    options.adapter = .codex;
    // R-N13: this constructed internal permit reaches the unsafe-socket
    // predicate only; it proves neither peer attribution nor snapshot sealing.
    const owner_bytes = try std.json.Stringify.valueAlloc(allocator, @import("../native_owner.zig").Snapshot{}, .{});
    defer allocator.free(owner_bytes);
    var permit: NativeCustody = .{ .adapter_epoch = 1, .capability_digest = undefined, .snapshot_digest = undefined, .state = .install_ready };
    std.crypto.hash.sha2.Sha256.hash(&options.capability, &permit.capability_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(owner_bytes, &permit.snapshot_digest, .{});
    options.native_custody = permit;
    options.native_socket = "/tmp/../unsupported-native.sock";
    try std.testing.expectError(error.UnsafePath, install(std.testing.io, allocator, options));
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, options.state_dir, false));
    const config = try chooseConfig(allocator, options);
    defer allocator.free(config);
    const untouched = try readConfig(allocator, config, false);
    defer untouched.deinit(allocator);
    try std.testing.expect(!untouched.existed);
}

test "retired adapter capability generation cannot be republished by recovery" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const installed = try install(std.testing.io, allocator, fixture.options);
    defer installed.deinit(allocator);
    const custody = try Custody.acquire(allocator, fixture.options);
    try revokeCapability(allocator, custody.directory, fixture.options, fixture.options.capability);
    custody.deinit();
    var next_generation = fixture.options;
    next_generation.capability = @splat('b');
    try std.testing.expectEqual(Recovery.conflict, try recover(std.testing.io, allocator, next_generation));
    try std.testing.expectError(error.AdapterNotInstalled, paths.readCapability(allocator, fixture.options.state_dir, "git"));
    try std.testing.expectError(error.CapabilityGenerationMismatch, install(std.testing.io, allocator, next_generation));
    try std.testing.expectEqual(Recovery.installed, try recover(std.testing.io, allocator, fixture.options));
    const current = try paths.readCapability(allocator, fixture.options.state_dir, "git");
    defer allocator.free(current);
    try std.testing.expectEqualStrings(&fixture.options.capability, current);
}

test "replayed removal registries cannot alter a reinstalled generation's native config or capability" {
    for ([_]Phase{ .installed, .pending_remove }) |historical_phase| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const allocator = std.testing.allocator;
        const config = try chooseConfig(allocator, fixture.options);
        defer allocator.free(config);
        try fixture.write(config, "# retained native fixture\n", 0o640);
        const first = try install(std.testing.io, allocator, fixture.options);
        defer first.deinit(allocator);
        const registry_path = try std.fmt.allocPrint(allocator, "{s}/integrations/git.registry", .{fixture.options.state_dir});
        defer allocator.free(registry_path);
        const historical = blk: {
            const custody = try Custody.acquire(allocator, fixture.options);
            defer custody.deinit();
            const loaded = (try load(allocator, custody.directory, fixture.options)).?;
            defer loaded.deinit(allocator);
            if (historical_phase == .pending_remove) {
                var record = loaded.record;
                record.phase = .pending_remove;
                record.transaction = try transactionId(std.testing.io);
                record.before_existed = true;
                record.after_existed = record.original_existed;
                record.before_mode = record.original_mode;
                record.after_mode = record.original_mode;
                record.before = record.installed;
                record.after = record.original;
                try save(std.testing.io, allocator, custody.directory, fixture.options, record);
            }
            break :blk try readAt(allocator, custody.directory, "git.registry", true, maximum_registry + header_size);
        };
        defer historical.deinit(allocator);
        const removed = try remove(std.testing.io, allocator, fixture.options);
        defer removed.deinit(allocator);
        var next_generation = fixture.options;
        next_generation.capability = @splat('b');
        const second = try install(std.testing.io, allocator, next_generation);
        defer second.deinit(allocator);
        const before = try readConfig(allocator, config, false);
        defer before.deinit(allocator);
        // The current native configuration uses an unchanged capability path.
        // Old encrypted custody is authentic, but its generation is retired.
        try fixture.write(registry_path, historical.bytes, 0o600);
        try std.testing.expectError(error.CapabilityGenerationMismatch, remove(std.testing.io, allocator, next_generation));
        try std.testing.expectEqual(Recovery.conflict, try recover(std.testing.io, allocator, next_generation));
        const after = try readConfig(allocator, config, false);
        defer after.deinit(allocator);
        try std.testing.expectEqualStrings(before.bytes, after.bytes);
        try std.testing.expectEqual(before.mode, after.mode);
        try std.testing.expectEqual(before.existed, after.existed);
        const current = try paths.readCapability(allocator, fixture.options.state_dir, "git");
        defer allocator.free(current);
        try std.testing.expectEqualStrings(&next_generation.capability, current);
        const custody = try Custody.acquire(allocator, next_generation);
        defer custody.deinit();
        const refused = try readAt(allocator, custody.directory, "git.registry", true, maximum_registry + header_size);
        defer refused.deinit(allocator);
        try std.testing.expectEqualStrings(historical.bytes, refused.bytes);
    }
}

test "recovery safely resumes a recorded read-only native temporary" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try chooseConfig(allocator, fixture.options);
    defer allocator.free(config);
    const original = "# read-only fixture\n";
    try fixture.write(config, original, 0o400);
    const installed = try git.installConfig(allocator, original, "omux");
    defer allocator.free(installed);
    const record: Record = .{ .phase = .pending_install, .original_existed = true, .before_existed = true, .after_existed = true, .original_mode = 0o400, .before_mode = 0o400, .after_mode = 0o400, .capability = fixture.options.capability, .transaction = try transactionId(std.testing.io), .config_path = config, .original = original, .installed = installed, .before = original, .after = installed };
    const custody = try Custody.acquire(allocator, fixture.options);
    try save(std.testing.io, allocator, custody.directory, fixture.options, record);
    custody.deinit();
    const name = try temporaryName(allocator, std.fs.path.basename(config), record.transaction);
    defer allocator.free(name);
    const temporary = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ std.fs.path.dirname(config).?, name });
    defer allocator.free(temporary);
    try fixture.write(temporary, installed, 0o400);
    try std.testing.expectEqual(Recovery.installed, try recover(std.testing.io, allocator, fixture.options));
    const completed = try readConfig(allocator, config, false);
    defer completed.deinit(allocator);
    try std.testing.expectEqualStrings(installed, completed.bytes);
    try std.testing.expectEqual(@as(c.mode_t, 0o400), completed.mode);
    const removed = try remove(std.testing.io, allocator, fixture.options);
    defer removed.deinit(allocator);
    const restored = try readConfig(allocator, config, false);
    defer restored.deinit(allocator);
    try std.testing.expectEqualStrings(original, restored.bytes);
    try std.testing.expectEqual(@as(c.mode_t, 0o400), restored.mode);
}

test "expired setup deadlines leave native configuration and capability custody untouched" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    var expired = fixture.options;
    expired.deadline = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    try std.testing.expectError(error.Timeout, install(std.testing.io, allocator, expired));
    var wrong_clock = fixture.options;
    wrong_clock.deadline = std.Io.Clock.Timestamp.now(std.testing.io, .real);
    try std.testing.expectError(error.InvalidDeadline, install(std.testing.io, allocator, wrong_clock));
    try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, fixture.options.state_dir, false));
    const installed = try install(std.testing.io, allocator, fixture.options);
    defer installed.deinit(allocator);
    const before = try readConfig(allocator, installed.config_path, false);
    defer before.deinit(allocator);
    expired.deadline = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    try std.testing.expectError(error.Timeout, remove(std.testing.io, allocator, expired));
    try std.testing.expectError(error.Timeout, recover(std.testing.io, allocator, expired));
    const after = try readConfig(allocator, installed.config_path, false);
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings(before.bytes, after.bytes);
    const capability = try paths.readCapability(allocator, fixture.options.state_dir, "git");
    defer allocator.free(capability);
    try std.testing.expectEqualStrings(&fixture.options.capability, capability);
}

fn escapedFixturePath(allocator: std.mem.Allocator, base: []const u8) ![]u8 {
    const component: [180]u8 = @splat('"');
    return std.fmt.allocPrint(allocator, "{s}/{s}/{s}/{s}/{s}/config", .{ base, component, component, component, component });
}

test "completion preflight uses actual cached JSON bytes including escapes and the exact limit" {
    const allocator = std.testing.allocator;
    const empty = try std.json.Stringify.valueAlloc(allocator, InstallResult{ .adapter = "git", .config_path = "", .changed = false }, .{});
    defer allocator.free(empty);
    const path = try allocator.alloc(u8, mutation_authority.max_result_bytes - empty.len + 1);
    defer allocator.free(path);
    @memset(path, 'x');
    try requireResultFits(allocator, InstallResult{ .adapter = "git", .config_path = path[0 .. path.len - 1], .changed = false });
    try std.testing.expectError(error.ResultTooLarge, requireResultFits(allocator, InstallResult{ .adapter = "git", .config_path = path, .changed = false }));
    const escaped = try escapedFixturePath(allocator, "/fixture");
    defer allocator.free(escaped);
    try std.testing.expect(escaped.len < mutation_authority.max_result_bytes);
    try std.testing.expectError(error.ResultTooLarge, requireResultFits(allocator, InstallResult{ .adapter = "git", .config_path = escaped, .changed = false }));
}

test "oversized encoded install completion refuses before hook configuration or capability custody" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try escapedFixturePath(allocator, fixture.options.home);
    defer allocator.free(config);
    try fixture.write(config, "# unchanged\n", 0o600);
    var options = fixture.options;
    options.config_path = config;
    for ([_]Adapter{ .git, .codex }) |adapter| {
        options.adapter = adapter;
        options.native_socket = "/tmp/../must-not-negotiate.sock";
        if (adapter == .codex) {
            // R-N13: missing custody refuses before any preflight. A constructed
            // internal permit then exercises only this encoded-result boundary;
            // it supplies neither actual peer proof nor sealed actor authority.
            try std.testing.expectError(error.NativeCustodyPending, install(std.testing.io, allocator, options));
            const owner_bytes = try std.json.Stringify.valueAlloc(allocator, @import("../native_owner.zig").Snapshot{}, .{});
            defer allocator.free(owner_bytes);
            var permit: NativeCustody = .{ .adapter_epoch = 1, .capability_digest = undefined, .snapshot_digest = undefined, .state = .install_ready };
            std.crypto.hash.sha2.Sha256.hash(&options.capability, &permit.capability_digest, .{});
            std.crypto.hash.sha2.Sha256.hash(owner_bytes, &permit.snapshot_digest, .{});
            options.native_custody = permit;
        }
        try std.testing.expectError(error.ResultTooLarge, install(std.testing.io, allocator, options));
        try std.testing.expectError(error.PathOpenFailed, paths.openPrivateRoot(allocator, options.state_dir, false));
        const current = try readConfig(allocator, config, false);
        defer current.deinit(allocator);
        try std.testing.expectEqualStrings("# unchanged\n", current.bytes);
    }
}

test "oversized retained remove completion preserves configuration capability and encrypted registry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = std.testing.allocator;
    const config = try escapedFixturePath(allocator, fixture.options.home);
    defer allocator.free(config);
    const installed = try git.installConfig(allocator, "# original\n", "omux");
    defer allocator.free(installed);
    try fixture.write(config, "# original\n", 0o600);
    var options = fixture.options;
    options.config_path = config;
    const seeded = try LegacyCustodyForTest.seedInstalled(std.testing.io, allocator, options);
    defer seeded.deinit(allocator);
    const custody = try Custody.acquire(allocator, fixture.options);
    defer custody.deinit();
    const before_registry = try readAt(allocator, custody.directory, "git.registry", true, maximum_registry + header_size);
    defer before_registry.deinit(allocator);
    const before_capability = try readAt(allocator, custody.directory, "git.capability", true, 64);
    defer before_capability.deinit(allocator);
    try std.testing.expectError(error.ResultTooLarge, preflightResult(std.testing.io, allocator, options, .remove));
    try std.testing.expectError(error.ResultTooLarge, remove(std.testing.io, allocator, options));
    const current = try readConfig(allocator, config, false);
    defer current.deinit(allocator);
    try std.testing.expectEqualStrings(installed, current.bytes);
    const after_registry = try readAt(allocator, custody.directory, "git.registry", true, maximum_registry + header_size);
    defer after_registry.deinit(allocator);
    try std.testing.expectEqualSlices(u8, before_registry.bytes, after_registry.bytes);
    const after_capability = try readAt(allocator, custody.directory, "git.capability", true, 64);
    defer after_capability.deinit(allocator);
    try std.testing.expectEqualSlices(u8, before_capability.bytes, after_capability.bytes);
}
