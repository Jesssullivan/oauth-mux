//! Read-only ff7e Linux x86_64 source-context publication hints. No auth reads,
//! source consent, identity admission, provider I/O or credential authority.
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("../paths.zig");
const metadata = @import("../platform/file_metadata.zig");
const inventory = @import("native_inventory.zig");
const c = std.c;
pub const registry_name = "omux-native-owners";
pub const maximum_hint_bytes = 8192;
pub const maximum_runtime_bytes = 4096;
pub const maximum_registry_entries = 1024;

const Document = struct {
    protocolVersion: u32,
    contextId: []const u8,
    contextGeneration: []const u8,
    ownerId: []const u8,
    processNonce: []const u8,
    endpointGeneration: []const u8,
    ownerEndpoint: []const u8,
};

fn same(a: metadata.Metadata, b: metadata.Metadata) bool {
    return a.dev == b.dev and a.ino == b.ino and a.mode == b.mode and a.uid == b.uid and
        a.gid == b.gid and a.nlink == b.nlink and a.size == b.size and
        a.mtime_ns == b.mtime_ns and a.ctime_ns == b.ctime_ns;
}
fn private(status: metadata.Metadata, kind: c.mode_t, mode: c.mode_t) !void {
    if (status.mode & c.S.IFMT != kind or status.uid != c.getuid() or status.mode & 0o777 != mode) return error.UnsafeNativeSourceContext;
}
fn hintFile(status: metadata.Metadata) !void {
    try private(status, c.S.IFREG, 0o600);
    if (status.nlink != 1 or status.size <= 0 or status.size > maximum_hint_bytes) return error.UnsafeNativeSourceContext;
}
fn hex(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidNativeSourceContext;
    for (value) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidNativeSourceContext;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidNativeSourceContext;
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidNativeSourceContext;
    return result;
}
fn generation(value: []const u8) !u64 {
    if (value.len == 0 or value.len > 20 or value[0] == '0') return error.InvalidNativeSourceContext;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidNativeSourceContext;
    return std.fmt.parseInt(u64, value, 10) catch return error.InvalidNativeSourceContext;
}
pub fn isHintName(name: []const u8) bool {
    if (name.len != 69 or !std.mem.endsWith(u8, name, ".json")) return false;
    _ = hex(name[0..64]) catch return false;
    return true;
}

pub const Hint = struct {
    context_id: [32]u8,
    context_generation: u64,
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    endpoint_path: []u8,
    name: [:0]u8,
    descriptor: c.fd_t,
    original: metadata.Metadata,
    registry_fd: c.fd_t,

    pub fn verify(self: *const Hint) !void {
        const retained = try metadata.statFd(self.descriptor);
        try hintFile(retained);
        const named = metadata.statAt(self.registry_fd, self.name.ptr, c.AT.SYMLINK_NOFOLLOW) catch return error.NativeSourceContextChanged;
        try hintFile(named);
        if (!same(self.original, retained) or !same(self.original, named)) return error.NativeSourceContextChanged;
    }
    /// Endpoint's home is a metadata-only locator, never auth-file authority.
    pub fn endpointHome(self: *const Hint) []const u8 {
        return self.endpoint_path[0 .. self.endpoint_path.len - 1 - inventory.directory_name_bytes - 1 - inventory.socket_name.len];
    }
    fn deinit(self: Hint, allocator: std.mem.Allocator) void {
        _ = c.close(self.descriptor);
        allocator.free(self.name);
        allocator.free(self.endpoint_path);
    }
};

pub const Inventory = struct {
    allocator: std.mem.Allocator,
    runtime_path: []u8,
    runtime_fd: c.fd_t,
    registry_fd: c.fd_t,
    runtime_original: metadata.Metadata,
    registry_original: metadata.Metadata,
    hints: []Hint,

    pub fn verify(self: *const Inventory, io: std.Io, budget: *const inventory.Budget) !void {
        try budget.check(io);
        const runtime = try metadata.statFd(self.runtime_fd);
        try private(runtime, c.S.IFDIR, 0o700);
        const named = try paths.openPrivateRoot(self.allocator, self.runtime_path, false);
        defer _ = c.close(named);
        if (!same(self.runtime_original, runtime) or !same(self.runtime_original, try metadata.statFd(named))) return error.NativeSourceContextChanged;
        const registry = try metadata.statFd(self.registry_fd);
        try private(registry, c.S.IFDIR, 0o700);
        const published = try metadata.statAt(self.runtime_fd, registry_name, c.AT.SYMLINK_NOFOLLOW);
        try private(published, c.S.IFDIR, 0o700);
        if (!same(self.registry_original, registry) or !same(self.registry_original, published)) return error.NativeSourceContextChanged;
        for (self.hints) |*hint| {
            try budget.check(io);
            try hint.verify();
        }
        try budget.check(io);
    }
    pub fn deinit(self: *Inventory) void {
        for (self.hints) |hint| hint.deinit(self.allocator);
        self.allocator.free(self.hints);
        _ = c.close(self.registry_fd);
        _ = c.close(self.runtime_fd);
        self.allocator.free(self.runtime_path);
        self.* = undefined;
    }
};

fn readHint(io: std.Io, allocator: std.mem.Allocator, registry: c.fd_t, name: []const u8, budget: *inventory.Budget) !Hint {
    const terminated = try allocator.dupeSentinel(u8, name, 0);
    errdefer allocator.free(terminated);
    const descriptor = c.openat(registry, terminated.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (descriptor < 0) return error.NativeSourceContextChanged;
    errdefer _ = c.close(descriptor);
    const original = try metadata.statFd(descriptor);
    try hintFile(original);
    var buffer: [maximum_hint_bytes + 1]u8 = undefined;
    var count: usize = 0;
    var interrupts: usize = 0;
    while (count < buffer.len) {
        try budget.check(io);
        const received = c.read(descriptor, buffer[count..].ptr, buffer.len - count);
        if (received < 0) {
            if (c.errno(received) == .INTR and interrupts < 16) {
                interrupts += 1;
                continue;
            }
            return error.NativeSourceContextReadFailed;
        }
        if (received == 0) break;
        count += @intCast(received);
    }
    if (count != @as(usize, @intCast(original.size)) or count > maximum_hint_bytes) return error.NativeSourceContextChanged;
    if (!same(original, try metadata.statFd(descriptor))) return error.NativeSourceContextChanged;
    var parsed = try std.json.parseFromSlice(Document, allocator, buffer[0..count], .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = maximum_hint_bytes });
    defer parsed.deinit();
    const value = parsed.value;
    if (value.protocolVersion != 1) return error.InvalidNativeSourceContext;
    const context = try hex(value.contextId);
    if (!std.mem.eql(u8, name[0..64], value.contextId)) return error.InvalidNativeSourceContext;
    const owner = try hex(value.ownerId);
    const endpoint = value.ownerEndpoint;
    try paths.validateAbsolute(endpoint);
    if (endpoint.len > inventory.maximum_endpoint_bytes) return error.InvalidNativeSourceContext;
    for (endpoint) |byte| if (byte < 32 or byte == 127) return error.InvalidNativeSourceContext;
    var suffix_buffer: [inventory.directory_name_bytes + inventory.socket_name.len + 2]u8 = undefined;
    const suffix = try std.fmt.bufPrint(&suffix_buffer, "/{s}{s}/{s}", .{ inventory.directory_prefix, std.fmt.bytesToHex(owner[0..8].*, .lower), inventory.socket_name });
    if (endpoint.len <= suffix.len or !std.mem.endsWith(u8, endpoint, suffix)) return error.InvalidNativeSourceContext;
    const owned_endpoint = try allocator.dupe(u8, endpoint);
    errdefer allocator.free(owned_endpoint);
    const result: Hint = .{ .context_id = context, .context_generation = try generation(value.contextGeneration), .owner_id = owner, .native_nonce = try hex(value.processNonce), .endpoint_generation = try generation(value.endpointGeneration), .endpoint_path = owned_endpoint, .name = terminated, .descriptor = descriptor, .original = original, .registry_fd = registry };
    try result.verify();
    try budget.check(io);
    return result;
}

/// Select only the daemon's declared normal-user runtime. No environment or
/// credential read here; caller supplies its runtime, never a control raw path.
/// Absent registry is unsupported/unpublished, not evidence of zero accounts.
pub fn collect(io: std.Io, allocator: std.mem.Allocator, runtime_path: []const u8, budget: *inventory.Budget) !?Inventory {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedPeerProfile;
    try budget.check(io);
    if (runtime_path.len > maximum_runtime_bytes) return error.InvalidNativeSourceContext;
    for (runtime_path) |byte| if (byte < 32 or byte == 127) return error.InvalidNativeSourceContext;
    const root = try allocator.dupe(u8, runtime_path);
    var transfer = false;
    defer if (!transfer) allocator.free(root);
    const runtime = try paths.openPrivateRoot(allocator, runtime_path, false);
    defer {
        if (!transfer) _ = c.close(runtime);
    }
    const runtime_original = try metadata.statFd(runtime);
    try private(runtime_original, c.S.IFDIR, 0o700);
    const registry = c.openat(runtime, registry_name, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (registry < 0) return if (c.errno(registry) == .NOENT) null else error.UnsafeNativeSourceContext;
    defer {
        if (!transfer) _ = c.close(registry);
    }
    const registry_original = try metadata.statFd(registry);
    try private(registry_original, c.S.IFDIR, 0o700);
    var hints: std.ArrayList(Hint) = .empty;
    errdefer {
        for (hints.items) |hint| hint.deinit(allocator);
        hints.deinit(allocator);
    }
    var iterator = (std.Io.Dir{ .handle = registry }).iterate();
    var scanned: usize = 0;
    while (true) {
        try budget.check(io);
        const entry = try iterator.next(io) orelse break;
        if (scanned >= maximum_registry_entries) return error.NativeInventoryCapacity;
        scanned += 1;
        try budget.scan(io);
        if (!isHintName(entry.name)) return error.InvalidNativeSourceContext;
        try budget.retain(io);
        const hint = try readHint(io, allocator, registry, entry.name, budget);
        errdefer hint.deinit(allocator);
        for (hints.items) |previous| if (std.mem.eql(u8, &previous.owner_id, &hint.owner_id)) return error.NativeOwnerAmbiguous;
        try budget.admit(io);
        try hints.append(allocator, hint);
    }
    const owned = try hints.toOwnedSlice(allocator);
    errdefer {
        for (owned) |hint| hint.deinit(allocator);
        allocator.free(owned);
    }
    const result: Inventory = .{ .allocator = allocator, .runtime_path = root, .runtime_fd = runtime, .registry_fd = registry, .runtime_original = runtime_original, .registry_original = registry_original, .hints = owned };
    try result.verify(io, budget);
    transfer = true;
    return result;
}
