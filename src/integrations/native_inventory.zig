//! Bounded read-only publication hints in one explicitly selected owned home.
//! A pathname, inode or directory suffix never authenticates a native process.
//! The caller must retain Inventory through fresh credential-aware peer probing.
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("../paths.zig");
const metadata = @import("../platform/file_metadata.zig");
const c = std.c;

pub const maximum_scanned_entries = 4096;
pub const maximum_candidates = 256;
pub const maximum_retained_hints = 256;
pub const maximum_endpoint_bytes = 107;
pub const directory_prefix = "omux-owner-";
pub const directory_name_bytes = directory_prefix.len + 16;
pub const socket_name = "owner.sock";
pub const maximum_context_bytes = maximum_endpoint_bytes - directory_name_bytes - socket_name.len - 2;
pub const timeout_ms = 3000;

/// Share this object across contexts and probes; never renew it per endpoint.
pub const Budget = struct {
    until: std.Io.Clock.Timestamp,
    scanned_entries: usize = 0,
    candidate_count: usize = 0,
    retained_hints: usize = 0,

    pub fn init(io: std.Io, caller: ?std.Io.Clock.Timestamp) !Budget {
        var until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(timeout_ms) });
        if (caller) |deadline| {
            if (deadline.clock != .awake) return error.InvalidDeadline;
            if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
            if (deadline.durationFromNow(io).raw.toMilliseconds() < until.durationFromNow(io).raw.toMilliseconds()) until = deadline;
        }
        return .{ .until = until };
    }

    pub fn check(self: *const Budget, io: std.Io) !void {
        try io.checkCancel();
        if (self.until.clock != .awake) return error.InvalidDeadline;
        if (self.until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
    }

    fn scan(self: *Budget, io: std.Io) !void {
        try self.check(io);
        if (self.scanned_entries >= maximum_scanned_entries) return error.NativeInventoryCapacity;
        self.scanned_entries += 1;
    }

    fn admit(self: *Budget, io: std.Io) !void {
        try self.check(io);
        if (self.candidate_count >= maximum_candidates) return error.NativeInventoryCapacity;
        self.candidate_count += 1;
    }

    fn retain(self: *Budget, io: std.Io) !void {
        try self.check(io);
        if (self.retained_hints >= maximum_retained_hints) return error.NativeInventoryCapacity;
        self.retained_hints += 1;
    }
};

const ChangeStamp = struct {
    mtime_ns: i128,
    ctime_ns: i128,

    fn from(status: metadata.Metadata) ChangeStamp {
        return .{ .mtime_ns = status.mtime_ns, .ctime_ns = status.ctime_ns };
    }

    fn matches(self: ChangeStamp, status: metadata.Metadata) bool {
        return self.mtime_ns == status.mtime_ns and self.ctime_ns == status.ctime_ns;
    }
};

pub const Identity = struct {
    device: u64,
    inode: u64,

    fn from(status: metadata.Metadata) Identity {
        return .{ .device = status.dev, .inode = status.ino };
    }

    fn matches(self: Identity, status: metadata.Metadata) bool {
        return self.device == status.dev and self.inode == status.ino;
    }
};

/// Retained filesystem evidence only, never a saved/reconstructed peer Context.
/// root_path/root_fd borrow Inventory. The directory and O_PATH socket handles
/// pin their inodes; callers must not copy this object beyond Inventory lifetime.
pub const Candidate = struct {
    endpoint_path: []u8,
    root_path: []const u8,
    root_fd: c.fd_t,
    directory_name: [:0]u8,
    directory_fd: c.fd_t,
    socket_fd: c.fd_t,
    root_identity: Identity,
    directory_identity: Identity,
    socket_identity: Identity,

    pub fn verify(self: *const Candidate, allocator: std.mem.Allocator) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedPeerProfile;
        try verifyRoot(allocator, self.root_path, self.root_fd, self.root_identity);
        const retained_parent = try metadata.statFd(self.directory_fd);
        try requirePrivate(retained_parent, c.S.IFDIR, 0o700);
        if (!self.directory_identity.matches(retained_parent)) return error.NativeInventoryChanged;
        const published_parent = metadata.statAt(self.root_fd, self.directory_name.ptr, c.AT.SYMLINK_NOFOLLOW) catch return error.NativeInventoryChanged;
        try requirePrivate(published_parent, c.S.IFDIR, 0o700);
        if (!self.directory_identity.matches(published_parent)) return error.NativeInventoryChanged;
        const retained_socket = try metadata.statFd(self.socket_fd);
        try requirePrivate(retained_socket, c.S.IFSOCK, 0o600);
        // The O_PATH pin survives unlink. That is changed publication, never a
        // reason to trust the new pathname or discard the old inode silently.
        if (retained_socket.nlink != 1) return error.NativeInventoryChanged;
        if (!self.socket_identity.matches(retained_socket)) return error.NativeInventoryChanged;
        const published_socket = metadata.statAt(self.directory_fd, socket_name, c.AT.SYMLINK_NOFOLLOW) catch return error.NativeInventoryChanged;
        try requireSocket(published_socket);
        if (!self.socket_identity.matches(published_socket)) return error.NativeInventoryChanged;
    }

    /// Correlate the producer's advertised handle with its publication hint.
    /// Fresh kernel peer evidence and protocol identity remain independently
    /// required; this comparison confers no process or credential authority.
    pub fn matchesOwner(self: *const Candidate, owner_id: [32]u8) bool {
        const prefix = std.fmt.bytesToHex(owner_id[0..8].*, .lower);
        return std.mem.eql(u8, self.directory_name[directory_prefix.len..], &prefix);
    }

    fn deinit(self: Candidate, allocator: std.mem.Allocator) void {
        _ = c.close(self.socket_fd);
        _ = c.close(self.directory_fd);
        allocator.free(self.directory_name);
        allocator.free(self.endpoint_path);
    }
};

pub const Inventory = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    root_fd: c.fd_t,
    root_identity: Identity,
    root_stamp: ChangeStamp,
    candidates: []Candidate,
    stale_directories: []StaleDirectory,
    scanned_entries: usize,
    /// Safe matching directories lacking owner.sock are stale hints, not proof
    /// that an owner exited or that its durable obligations can be released.
    ignored_stale_entries: usize,

    /// Detect observed filesystem publication changes. This is not a universal
    /// process census or authority to conclude there are no unresolved owners.
    pub fn verify(self: *const Inventory, allocator: std.mem.Allocator) !void {
        try verifyRoot(allocator, self.root_path, self.root_fd, self.root_identity);
        if (!self.root_stamp.matches(try metadata.statFd(self.root_fd))) return error.NativeInventoryChanged;
        for (self.candidates) |*candidate| try candidate.verify(allocator);
        for (self.stale_directories) |*stale| try stale.verify(self.root_fd);
        try verifyRoot(allocator, self.root_path, self.root_fd, self.root_identity);
        if (!self.root_stamp.matches(try metadata.statFd(self.root_fd))) return error.NativeInventoryChanged;
    }

    pub fn deinit(self: *Inventory) void {
        for (self.candidates) |candidate| candidate.deinit(self.allocator);
        self.allocator.free(self.candidates);
        for (self.stale_directories) |stale| stale.deinit(self.allocator);
        self.allocator.free(self.stale_directories);
        _ = c.close(self.root_fd);
        self.allocator.free(self.root_path);
        self.* = undefined;
    }
};

const StaleDirectory = struct {
    directory_name: [:0]u8,
    directory_fd: c.fd_t,
    identity: Identity,
    stamp: ChangeStamp,

    fn verify(self: *const StaleDirectory, root_fd: c.fd_t) !void {
        const retained = try metadata.statFd(self.directory_fd);
        try requirePrivate(retained, c.S.IFDIR, 0o700);
        if (!self.identity.matches(retained) or !self.stamp.matches(retained)) return error.NativeInventoryChanged;
        const published = metadata.statAt(root_fd, self.directory_name.ptr, c.AT.SYMLINK_NOFOLLOW) catch return error.NativeInventoryChanged;
        try requirePrivate(published, c.S.IFDIR, 0o700);
        if (!self.identity.matches(published)) return error.NativeInventoryChanged;
        _ = metadata.statAt(self.directory_fd, socket_name, c.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        return error.NativeInventoryChanged;
    }

    fn deinit(self: StaleDirectory, allocator: std.mem.Allocator) void {
        _ = c.close(self.directory_fd);
        allocator.free(self.directory_name);
    }
};

fn requirePrivate(status: metadata.Metadata, kind: c.mode_t, permissions: c.mode_t) !void {
    if (status.mode & c.S.IFMT != kind or status.uid != c.getuid() or status.mode & 0o777 != permissions) return error.UnsafeNativeInventory;
}

fn requireSocket(status: metadata.Metadata) !void {
    try requirePrivate(status, c.S.IFSOCK, 0o600);
    if (status.nlink != 1) return error.UnsafeNativeInventory;
}

fn requireContext(status: metadata.Metadata) !void {
    // Native homes can be readable (0755). Only each published endpoint's
    // immediate directory must be private; never chmod an ordinary native home.
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.uid != c.getuid() or status.mode & 0o022 != 0) return error.UnsafeNativeInventory;
}

fn openContext(allocator: std.mem.Allocator, path: []const u8) !c.fd_t {
    try paths.validateAbsolute(path);
    var descriptor = c.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (descriptor < 0) return error.PathOpenFailed;
    errdefer _ = c.close(descriptor);
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        const ancestor = try metadata.statFd(descriptor);
        if (ancestor.mode & c.S.IFMT != c.S.IFDIR or (ancestor.uid != c.getuid() and ancestor.uid != 0)) return error.UnsafePathOwner;
        // Match paths' ancestor policy, including root-owned sticky /tmp.
        if (ancestor.mode & 0o022 != 0 and !(ancestor.uid == 0 and ancestor.mode & 0o1000 != 0)) return error.UnsafePathPermissions;
        const component = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(component);
        const next = c.openat(descriptor, component.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0) return error.PathOpenFailed;
        _ = c.close(descriptor);
        descriptor = next;
    }
    try requireContext(try metadata.statFd(descriptor));
    return descriptor;
}

fn verifyRoot(allocator: std.mem.Allocator, path: []const u8, retained_fd: c.fd_t, identity: Identity) !void {
    const retained = try metadata.statFd(retained_fd);
    try requireContext(retained);
    if (!identity.matches(retained)) return error.NativeInventoryChanged;
    const current_fd = openContext(allocator, path) catch return error.NativeInventoryChanged;
    defer _ = c.close(current_fd);
    if (!identity.matches(try metadata.statFd(current_fd))) return error.NativeInventoryChanged;
}

pub fn isOwnerDirectory(name: []const u8) bool {
    if (name.len != directory_name_bytes or !std.mem.startsWith(u8, name, directory_prefix)) return false;
    for (name[directory_prefix.len..]) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    return true;
}

const Hint = union(enum) { candidate: Candidate, stale: StaleDirectory };

fn openCandidate(allocator: std.mem.Allocator, root_path: []const u8, root_fd: c.fd_t, root_identity: Identity, name: []const u8) !Hint {
    const directory_name = try allocator.dupeSentinel(u8, name, 0);
    errdefer allocator.free(directory_name);
    const published_parent = metadata.statAt(root_fd, directory_name.ptr, c.AT.SYMLINK_NOFOLLOW) catch return error.NativeInventoryChanged;
    try requirePrivate(published_parent, c.S.IFDIR, 0o700);
    const directory_fd = c.openat(root_fd, directory_name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory_fd < 0) return error.NativeInventoryChanged;
    errdefer _ = c.close(directory_fd);
    const parent = try metadata.statFd(directory_fd);
    try requirePrivate(parent, c.S.IFDIR, 0o700);
    if (!Identity.from(published_parent).matches(parent)) return error.NativeInventoryChanged;
    const socket_status = metadata.statAt(directory_fd, socket_name, c.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.FileNotFound => {
            return .{ .stale = .{ .directory_name = directory_name, .directory_fd = directory_fd, .identity = Identity.from(parent), .stamp = ChangeStamp.from(parent) } };
        },
        else => return err,
    };
    try requireSocket(socket_status);
    const socket_fd = c.openat(directory_fd, socket_name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (socket_fd < 0) return error.NativeInventoryChanged;
    errdefer _ = c.close(socket_fd);
    const pinned_socket = try metadata.statFd(socket_fd);
    try requireSocket(pinned_socket);
    if (!Identity.from(socket_status).matches(pinned_socket)) return error.NativeInventoryChanged;
    const endpoint_path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ root_path, name, socket_name });
    errdefer allocator.free(endpoint_path);
    if (endpoint_path.len > maximum_endpoint_bytes) return error.SocketPathTooLong;
    const candidate: Candidate = .{ .endpoint_path = endpoint_path, .root_path = root_path, .root_fd = root_fd, .directory_name = directory_name, .directory_fd = directory_fd, .socket_fd = socket_fd, .root_identity = root_identity, .directory_identity = Identity.from(parent), .socket_identity = Identity.from(pinned_socket) };
    try candidate.verify(allocator);
    return .{ .candidate = candidate };
}

fn lessThan(_: void, left: Candidate, right: Candidate) bool {
    return std.mem.lessThan(u8, left.endpoint_path, right.endpoint_path);
}

/// Enumerate only the selected owned root's immediate entries. No environment lookup,
/// directory creation, capability/credential read, transport, chmod or deletion.
/// Unsafe matching publications and any limit failure refuse the whole result.
pub fn collect(io: std.Io, allocator: std.mem.Allocator, selected_home: []const u8, budget: *Budget) !Inventory {
    if (builtin.os.tag != .linux) return error.UnsupportedPeerProfile;
    try budget.check(io);
    try paths.validateAbsolute(selected_home);
    if (selected_home.len > maximum_context_bytes) return error.SocketPathTooLong;
    for (selected_home) |byte| if (byte < 32 or byte == 127) return error.UnsafePath;
    const root_path = try allocator.dupe(u8, selected_home);
    errdefer allocator.free(root_path);
    const root_fd = try openContext(allocator, root_path);
    errdefer _ = c.close(root_fd);
    const root_status = try metadata.statFd(root_fd);
    const root_identity = Identity.from(root_status);
    const root_stamp = ChangeStamp.from(root_status);
    try budget.check(io);
    var candidates: std.ArrayList(Candidate) = .empty;
    errdefer {
        for (candidates.items) |candidate| candidate.deinit(allocator);
        candidates.deinit(allocator);
    }
    var stale_directories: std.ArrayList(StaleDirectory) = .empty;
    errdefer {
        for (stale_directories.items) |stale| stale.deinit(allocator);
        stale_directories.deinit(allocator);
    }
    const scanned_before = budget.scanned_entries;
    var iterator = (std.Io.Dir{ .handle = root_fd }).iterate();
    while (true) {
        try budget.check(io);
        const entry = try iterator.next(io) orelse break;
        try budget.scan(io);
        if (!isOwnerDirectory(entry.name)) continue;
        try budget.retain(io);
        switch (try openCandidate(allocator, root_path, root_fd, root_identity, entry.name)) {
            .candidate => |candidate| {
                errdefer candidate.deinit(allocator);
                try budget.admit(io);
                try candidates.append(allocator, candidate);
            },
            .stale => |stale| {
                errdefer stale.deinit(allocator);
                try stale_directories.append(allocator, stale);
            },
        }
    }
    try budget.check(io);
    try verifyRoot(allocator, root_path, root_fd, root_identity);
    if (!root_stamp.matches(try metadata.statFd(root_fd))) return error.NativeInventoryChanged;
    // Check retained hints and stale absence. These bounded observations are
    // neither a universal process census nor a native retirement admission.
    for (candidates.items) |*candidate| {
        try budget.check(io);
        try candidate.verify(allocator);
    }
    for (stale_directories.items) |*stale| {
        try budget.check(io);
        try stale.verify(root_fd);
    }
    if (!root_stamp.matches(try metadata.statFd(root_fd))) return error.NativeInventoryChanged;
    try budget.check(io);
    std.mem.sort(Candidate, candidates.items, {}, lessThan);
    const owned_candidates = try candidates.toOwnedSlice(allocator);
    errdefer {
        for (owned_candidates) |candidate| candidate.deinit(allocator);
        allocator.free(owned_candidates);
    }
    const owned_stale = try stale_directories.toOwnedSlice(allocator);
    return .{ .allocator = allocator, .root_path = root_path, .root_fd = root_fd, .root_identity = root_identity, .root_stamp = root_stamp, .candidates = owned_candidates, .stale_directories = owned_stale, .scanned_entries = budget.scanned_entries - scanned_before, .ignored_stale_entries = owned_stale.len };
}
