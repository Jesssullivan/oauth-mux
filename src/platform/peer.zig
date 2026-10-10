//! Private Linux process-incarnation and per-segment writer evidence.
//! Saved Witness is original attribution only; Context is fresh OS evidence.
const std = @import("std");

pub const maximum_packet = 64 * 1024;
pub const Profile = enum { linux_pidfs64_v1 };
pub const NamespaceWitness = struct { device: u64, inode: u64 };
pub const Witness = struct {
    profile: Profile,
    boot_id: [16]u8,
    pidfs_device: u64,
    pidfs_inode: u64,
    user_namespace: NamespaceWitness,
    pid_namespace: NamespaceWitness,
    uid: u32,
    gid: u32,

    pub fn validate(self: Witness) !void {
        return validateSavedWitness(self);
    }
    pub fn sameOriginal(self: Witness, other: Witness) bool {
        return witnessEqual(self, other);
    }
};

pub fn validateSavedWitness(witness: Witness) !void {
    switch (witness.profile) {
        .linux_pidfs64_v1 => {},
    }
    if (std.mem.allEqual(u8, &witness.boot_id, 0) or witness.pidfs_inode == 0 or
        witness.user_namespace.inode == 0 or witness.pid_namespace.inode == 0) return error.InvalidPeerWitness;
}

pub fn sameOriginal(a: Witness, b: Witness) bool {
    return witnessEqual(a, b);
}

fn witnessEqual(a: Witness, b: Witness) bool {
    return a.profile == b.profile and std.mem.eql(u8, &a.boot_id, &b.boot_id) and
        a.pidfs_device == b.pidfs_device and a.pidfs_inode == b.pidfs_inode and
        a.user_namespace.device == b.user_namespace.device and a.user_namespace.inode == b.user_namespace.inode and
        a.pid_namespace.device == b.pid_namespace.device and a.pid_namespace.inode == b.pid_namespace.inode and
        a.uid == b.uid and a.gid == b.gid;
}

const RawNamespace = extern struct { device: u64, inode: u64 };
const RawWitness = extern struct {
    profile: u32,
    boot_id: [16]u8,
    pidfs_device: u64,
    pidfs_inode: u64,
    user_namespace: RawNamespace,
    pid_namespace: RawNamespace,
    uid: u32,
    gid: u32,
};
const RawContext = extern struct { socket_fd: c_int, pidfd: c_int, owns_socket: c_int, witness: RawWitness };
extern "c" fn omux_peer_enable(c_int) c_int;
extern "c" fn omux_peer_capture(c_int, u32, *RawContext) c_int;
extern "c" fn omux_peer_receive(*RawContext, [*]u8, usize, c_int, *usize) c_int;
extern "c" fn omux_peer_receive_descriptor(*RawContext, [*]u8, usize, *usize, *c_int) c_int;
extern "c" fn omux_peer_alive(*const RawContext) c_int;
extern "c" fn omux_peer_verify_bundled_image(*const RawContext, c_int, c_int) c_int;
extern "c" fn omux_peer_inspect_bundled_mappings(*const RawContext, c_int, c_int) c_int;
extern "c" fn omux_peer_verify_executable_image(*const RawContext, c_int) c_int;
extern "c" fn omux_peer_duplicate(*const RawContext, *RawContext) c_int;
extern "c" fn omux_peer_close(*RawContext) void;

fn check(status: c_int) !void {
    return switch (status) {
        0 => {},
        1 => error.UnsupportedPeerProfile,
        2 => error.PeerPermissionDenied,
        3 => error.InvalidPeerEvidence,
        4 => error.PeerRejected,
        5 => error.PeerNamespaceMismatch,
        6 => error.PeerIncarnationChanged,
        7 => error.PeerDeparted,
        8 => error.PeerMessageTruncated,
        9 => error.PeerUnexpectedRights,
        10 => error.WouldBlock,
        11 => error.Interrupted,
        12 => error.PeerSystemFailure,
        13 => error.PeerConnectionClosed,
        14 => error.PeerImageMismatch,
        15 => error.PeerImageMalformed,
        16 => error.PeerImageUnavailable,
        else => error.InvalidPeerEvidence,
    };
}

/// Runtime state has a single owner. capture borrows the caller's socket;
/// duplicate owns an independent descriptor. All variants own their pidfd.
/// No raw-fields constructor or conversion from a saved witness is exported.
pub const Context = struct {
    raw: RawContext,

    pub fn enable(fd: std.c.fd_t) !void {
        try check(omux_peer_enable(fd));
    }
    pub fn capture(fd: std.c.fd_t, expected_uid: u32) !Context {
        var raw: RawContext = undefined;
        try check(omux_peer_capture(fd, expected_uid, &raw));
        var context: Context = .{ .raw = raw };
        errdefer context.deinit();
        try validateSavedWitness(context.witness());
        return context;
    }
    pub fn duplicate(self: *const Context) !Context {
        var raw: RawContext = undefined;
        try check(omux_peer_duplicate(&self.raw, &raw));
        return .{ .raw = raw };
    }
    pub fn deinit(self: *Context) void {
        omux_peer_close(&self.raw);
    }
    pub fn alive(self: *const Context) !void {
        try check(omux_peer_alive(&self.raw));
    }
    /// Retired boundary. Backend executable mappings can be decoys; this API
    /// always refuses and cannot qualify source acquisition.
    pub fn verifyBundledImage(self: *const Context, loader_fd: std.c.fd_t, backend_fd: std.c.fd_t) !void {
        try check(omux_peer_verify_bundled_image(&self.raw, loader_fd, backend_fd));
    }
    /// Mapping diagnostics only; never grants acquisition/source authority.
    pub fn inspectBundledMappings(self: *const Context, loader_fd: std.c.fd_t, backend_fd: std.c.fd_t) !void {
        try check(omux_peer_inspect_bundled_mappings(&self.raw, loader_fd, backend_fd));
    }
    /// Actual primary executable must be the held authenticated backend role.
    /// Caller also authenticates a supported direct-main launch profile,
    /// selection, consent and original deadline before/after every exchange.
    pub fn verifyExecutableImage(self: *const Context, backend_fd: std.c.fd_t) !void {
        try check(omux_peer_verify_executable_image(&self.raw, backend_fd));
    }
    pub fn witness(self: *const Context) Witness {
        const raw = self.raw.witness;
        return .{
            .profile = .linux_pidfs64_v1,
            .boot_id = raw.boot_id,
            .pidfs_device = raw.pidfs_device,
            .pidfs_inode = raw.pidfs_inode,
            .user_namespace = .{ .device = raw.user_namespace.device, .inode = raw.user_namespace.inode },
            .pid_namespace = .{ .device = raw.pid_namespace.device, .inode = raw.pid_namespace.inode },
            .uid = raw.uid,
            .gid = raw.gid,
        };
    }
    pub fn receivePacket(self: *Context, buffer: []u8) !usize {
        return self.receive(buffer, true);
    }
    /// Only the authenticated opt-in acquisition response uses this boundary.
    /// Caller owns descriptor on success and must close on every later refusal.
    /// Sealing authenticates immutable container shape, not credential authority.
    pub fn receivePacketDescriptor(self: *Context, buffer: []u8) !struct { bytes: usize, descriptor: c_int } {
        if (buffer.len == 0 or buffer.len > maximum_packet) {
            @memset(buffer, 0);
            return error.InvalidPeerMessageSize;
        }
        var count: usize = 0;
        var descriptor: c_int = -1;
        try check(omux_peer_receive_descriptor(&self.raw, buffer.ptr, buffer.len, &count, &descriptor));
        return .{ .bytes = count, .descriptor = descriptor };
    }
    pub fn receiveSegment(self: *Context, buffer: []u8) !usize {
        return self.receive(buffer, false);
    }
    fn receive(self: *Context, buffer: []u8, packet: bool) !usize {
        if (buffer.len == 0 or buffer.len > maximum_packet) return error.InvalidPeerMessageSize;
        var count: usize = 0;
        try check(omux_peer_receive(&self.raw, buffer.ptr, buffer.len, @intFromBool(packet), &count));
        return count;
    }
};

test "saved witness validates structure without providing live context" {
    const good: Witness = .{ .profile = .linux_pidfs64_v1, .boot_id = @splat(1), .pidfs_device = 0, .pidfs_inode = 2, .user_namespace = .{ .device = 0, .inode = 3 }, .pid_namespace = .{ .device = 0, .inode = 4 }, .uid = 0, .gid = 0 };
    try validateSavedWitness(good);
    var changed = good;
    changed.pidfs_inode += 1;
    try std.testing.expect(!sameOriginal(good, changed));
    changed = good;
    changed.boot_id = @splat(0);
    try std.testing.expectError(error.InvalidPeerWitness, validateSavedWitness(changed));
}

test "native image refusals remain distinct at the Zig boundary" {
    try std.testing.expectError(error.PeerImageMismatch, check(14));
    try std.testing.expectError(error.PeerImageMalformed, check(15));
    try std.testing.expectError(error.PeerImageUnavailable, check(16));
}
