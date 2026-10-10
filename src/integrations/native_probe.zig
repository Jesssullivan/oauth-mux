//! Credential-aware native owner discovery and explicit legacy WebSocket inspection.
//! No provider traffic, token transfer, native login or transcript mutation.
const std = @import("std");
const source_acquisition = @import("../native_source_acquisition.zig");
const source_consent = @import("../native_source_consent.zig");
const setup = @import("setup.zig");
const builtin = @import("builtin");
const curl = @import("c");
const posix = std.c;
const paths = @import("../paths.zig");
const metadata = @import("../platform/file_metadata.zig");
const codex = @import("codex.zig");
const peer = @import("../platform/peer.zig");
const native_owner = @import("../native_owner.zig");
const inventory = @import("native_inventory.zig");
extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) posix.fd_t;
extern "c" fn getpeereid(fd: posix.fd_t, uid: *posix.uid_t, gid: *posix.gid_t) c_int;

pub const max_message = 1024 * 1024;
pub const timeout_ms = 3000;
pub const maximum_native_version_bytes = 256;
pub const maximum_loaded_result_bytes = 64 * 1024;
pub const maximum_owner_packet = 64 * 1024;
pub const owner_protocol_version: u32 = 2;
pub const maximum_owner_threads = 1024;

pub const SourceContextIdentity = struct { id: [32]u8, generation: u64 };
pub const SourceContextSelector = struct {
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    context: ?SourceContextIdentity = null,

    pub fn validate(self: SourceContextSelector) !void {
        if (std.mem.allEqual(u8, &self.owner_id, 0) or std.mem.allEqual(u8, &self.native_nonce, 0) or self.endpoint_generation == 0) return error.InvalidNativeSourceContext;
        if (self.context) |context| if (std.mem.allEqual(u8, &context.id, 0) or context.generation == 0) return error.InvalidNativeSourceContext;
    }
};
pub const SourceContextDeclaration = struct {
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    witness: peer.Witness,
    status: enum { available, unavailable },
    context: ?SourceContextIdentity,
    store_present: ?bool,
    credential_acquisition_authorized: bool = false,
};

/// Opaque installed evidence and a previously actor-committed digest are
/// mandatory. Neither a discovery declaration nor an HMAC proof selects an
/// executable image. The caller retains both carrier and installation FD.
pub const SourceImage = struct {
    selection: *const setup.VerifiedRuntimeSelection,
    options: setup.Options,
    expected: setup.RuntimeSelectionExpectation,
    pub fn verify(self: SourceImage, connection: *OwnerConnection) !void {
        try source_acquisition.deadline(connection.io, connection.until);
        // A mapped backend can be a decoy. Only the separately qualified Nix
        // direct-main profile exposes the actual primary executable identity.
        // Portable explicit-loader packages remain metadata-only here.
        if (self.selection.launchProfile() != .linux_nix_direct_main_v1) return error.NativeImageUnavailable;
        if (self.selection.acquisitionContract() != .omux_native_source_acquire_v1) return error.NativeImageUnavailable;
        var options = self.options;
        options.deadline = connection.until;
        var roles = try self.selection.recheckAndOpenRoles(connection.io, connection.allocator, options, self.expected);
        defer roles.deinit();
        try connection.context.verifyExecutableImage(roles.backend);
        try self.selection.recheck(connection.io, connection.allocator, options, self.expected);
        _ = try connection.verifiedWitness();
        try source_acquisition.deadline(connection.io, connection.until);
    }
};

fn decodeSourceContext(result: std.json.Value, selector: SourceContextSelector, witness: peer.Witness) !SourceContextDeclaration {
    try selector.validate();
    try requireOwnerKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "status", "sourceContextId", "sourceContextGeneration", "storePresent", "credentialAcquisitionAuthorized" });
    const owner_id = try ownerHex(result, "ownerId");
    const nonce = try ownerHex(result, "processNonce");
    const generation = try parseOwnerGeneration(result.object.get("endpointGeneration").?);
    if (!std.mem.eql(u8, &owner_id, &selector.owner_id) or !std.mem.eql(u8, &nonce, &selector.native_nonce) or generation != selector.endpoint_generation) return error.NativeOwnerIdentityMismatch;
    const acquisition = result.object.get("credentialAcquisitionAuthorized").?;
    if (acquisition != .bool or acquisition.bool) return error.InvalidNativeSourceContext;
    const status = try requiredOwnerString(result, "status");
    const id = result.object.get("sourceContextId").?;
    const context_generation = result.object.get("sourceContextGeneration").?;
    const store = result.object.get("storePresent").?;
    if (std.mem.eql(u8, status, "unavailable")) {
        if (id != .null or context_generation != .null or store != .null) return error.InvalidNativeSourceContext;
        return .{ .owner_id = owner_id, .native_nonce = nonce, .endpoint_generation = generation, .witness = witness, .status = .unavailable, .context = null, .store_present = null };
    }
    if (!std.mem.eql(u8, status, "available") or store != .bool) return error.InvalidNativeSourceContext;
    const context: SourceContextIdentity = .{ .id = try ownerHex(result, "sourceContextId"), .generation = try parseOwnerGeneration(context_generation) };
    if (selector.context) |expected| if (!std.mem.eql(u8, &context.id, &expected.id) or context.generation != expected.generation) return error.NativeSourceContextMismatch;
    return .{ .owner_id = owner_id, .native_nonce = nonce, .endpoint_generation = generation, .witness = witness, .status = .available, .context = context, .store_present = store.bool };
}

/// Captured read-only process metadata, not an owner admission or live hook
/// proof. Capabilities describe compatibility; the actor grants custody.
pub const OwnerNativeInfo = struct {
    native_version: []u8,
    native_discovery: bool = true,
    support: codex.Support,
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    witness: peer.Witness,

    pub fn deinit(self: OwnerNativeInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.native_version);
    }
};

pub const OwnerThread = struct {
    thread_id: []u8,
    thread_instance_generation: u64,
    attachment_generation: u64,
};

pub const OwnerThreadSnapshot = struct {
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    witness: peer.Witness,
    threads: []OwnerThread,

    pub fn deinit(self: OwnerThreadSnapshot, allocator: std.mem.Allocator) void {
        for (self.threads) |row| allocator.free(row.thread_id);
        allocator.free(self.threads);
    }
};

pub const OwnerLoadedThreads = struct {
    native_version: []u8,
    socket_path: []u8,
    support: codex.Support,
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    witness: peer.Witness,
    threads: []OwnerThread,
    // These strings borrow the owned thread rows. Only the array is separate.
    thread_ids: [][]u8,

    pub fn deinit(self: OwnerLoadedThreads, allocator: std.mem.Allocator) void {
        allocator.free(self.native_version);
        allocator.free(self.socket_path);
        allocator.free(self.thread_ids);
        for (self.threads) |row| allocator.free(row.thread_id);
        allocator.free(self.threads);
    }
};

pub const OwnerRequest = struct {
    reference: native_owner.NativeRef,
    thread_id: []const u8,
    native_nonce: [32]u8,
    operation_id: native_owner.OperationId,
    broker_socket: ?[]const u8 = null,
    capability_path: ?[]const u8 = null,

    pub fn validate(self: OwnerRequest) !void {
        try self.reference.validate();
        try native_owner.validateOperation(self.operation_id);
        try requireOwnerThread(self.thread_id);
        if (std.mem.allEqual(u8, &self.native_nonce, 0)) return error.InvalidNativeOwnerNonce;
    }
};

pub const OwnerIdentity = struct {
    owner_id: [32]u8,
    native_nonce: [32]u8,
    endpoint_generation: u64,
    thread_instance_generation: u64,
    thread_id: []u8,
    witness: peer.Witness,

    pub fn deinit(self: *OwnerIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.thread_id);
        self.* = undefined;
    }
};

pub const OwnerAction = enum { announce, register, detach };
pub const OwnerAck = struct {
    reference: native_owner.NativeRef,
    native_nonce: [32]u8,
    operation_id: native_owner.OperationId,
    thread_id: []u8,
    witness: peer.Witness,
    action: OwnerAction,

    pub fn deinit(self: *OwnerAck, allocator: std.mem.Allocator) void {
        allocator.free(self.thread_id);
        self.* = undefined;
    }
};

fn requireOwnerThread(thread_id: []const u8) !void {
    if (thread_id.len == 0 or thread_id.len > native_owner.maximum_thread_bytes or !std.unicode.utf8ValidateSlice(thread_id)) return error.InvalidNativeOwnerThread;
    for (thread_id) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidNativeOwnerThread;
}

fn parseOwnerThreadRows(allocator: std.mem.Allocator, entries: std.json.Value) ![]OwnerThread {
    if (entries != .array) return error.InvalidThreadList;
    if (entries.array.items.len > maximum_owner_threads) return error.NativeThreadLimit;
    var rows: std.ArrayList(OwnerThread) = .empty;
    errdefer {
        for (rows.items) |row| allocator.free(row.thread_id);
        rows.deinit(allocator);
    }
    for (entries.array.items) |entry| {
        try requireOwnerKeys(entry, &.{ "threadId", "threadInstanceGeneration", "attachmentGeneration" });
        const thread_id = try requiredOwnerString(entry, "threadId");
        try requireOwnerThread(thread_id);
        const thread_generation = try parseOwnerGeneration(entry.object.get("threadInstanceGeneration").?);
        const attachment_generation = try parseOwnerGeneration(entry.object.get("attachmentGeneration").?);
        // NativeRef does not contain threadId: distinct names cannot share a
        // process-local instance identity. Refuse the entire ambiguous list.
        for (rows.items) |row| if (std.mem.eql(u8, row.thread_id, thread_id) or row.thread_instance_generation == thread_generation) return error.InvalidThreadList;
        const owned_thread = try allocator.dupe(u8, thread_id);
        errdefer allocator.free(owned_thread);
        try rows.append(allocator, .{ .thread_id = owned_thread, .thread_instance_generation = thread_generation, .attachment_generation = attachment_generation });
    }
    return rows.toOwnedSlice(allocator);
}

fn requireOwnerPath(path: []const u8) !void {
    if (path.len == 0 or path.len > 4096) return error.InvalidNativeOwnerPath;
    for (path) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidNativeOwnerPath;
    try paths.validateAbsolute(path);
}

/// Wire validation only. A canonical generation never establishes peer or
/// attachment authority. Numeric JSON and alternate decimal spellings refuse.
pub fn parseOwnerGeneration(value: std.json.Value) !u64 {
    if (value != .string or value.string.len == 0 or value.string.len > 20 or value.string[0] < '1' or value.string[0] > '9') return error.InvalidNativeOwnerGeneration;
    for (value.string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidNativeOwnerGeneration;
    return std.fmt.parseInt(u64, value.string, 10) catch error.InvalidNativeOwnerGeneration;
}

fn requiredOwnerString(value: std.json.Value, name: []const u8) ![]const u8 {
    if (value != .object) return error.InvalidNativeOwnerAck;
    const field = value.object.get(name) orelse return error.InvalidNativeOwnerAck;
    if (field != .string) return error.InvalidNativeOwnerAck;
    return field.string;
}

fn ownerHex(value: std.json.Value, name: []const u8) ![32]u8 {
    const encoded = try requiredOwnerString(value, name);
    if (encoded.len != 64) return error.InvalidNativeOwnerHex;
    for (encoded) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidNativeOwnerHex;
    var decoded: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch return error.InvalidNativeOwnerHex;
    if (std.mem.allEqual(u8, &decoded, 0)) return error.InvalidNativeOwnerHex;
    return decoded;
}

fn ownerOperation(value: std.json.Value) !native_owner.OperationId {
    const encoded = try requiredOwnerString(value, "operationId");
    if (encoded.len != 64) return error.InvalidNativeOperation;
    var operation: native_owner.OperationId = undefined;
    @memcpy(&operation, encoded);
    try native_owner.validateOperation(operation);
    return operation;
}

/// Structural decoding is distinct from an acknowledged operation. Only an
/// OwnerConnection can combine this reference with fresh captured peer proof.
pub fn decodeOwnerReference(value: std.json.Value) !native_owner.NativeRef {
    if (value != .object) return error.InvalidNativeOwnerAck;
    const reference: native_owner.NativeRef = .{
        .owner_id = try ownerHex(value, "ownerId"),
        .adapter_epoch = try parseOwnerGeneration(value.object.get("adapterEpoch") orelse return error.InvalidNativeOwnerAck),
        .endpoint_generation = try parseOwnerGeneration(value.object.get("endpointGeneration") orelse return error.InvalidNativeOwnerAck),
        .thread_instance_generation = try parseOwnerGeneration(value.object.get("threadInstanceGeneration") orelse return error.InvalidNativeOwnerAck),
        .attachment_generation = try parseOwnerGeneration(value.object.get("attachmentGeneration") orelse return error.InvalidNativeOwnerAck),
    };
    try reference.validate();
    return reference;
}

fn requireOwnerKeys(value: std.json.Value, keys: []const []const u8) !void {
    if (value != .object or value.object.count() != keys.len) return error.InvalidNativeOwnerAck;
    for (keys) |name| if (!value.object.contains(name)) return error.InvalidNativeOwnerAck;
}

fn parseOwnerEnvelope(allocator: std.mem.Allocator, encoded: []const u8, operation: native_owner.OperationId) !std.json.Parsed(std.json.Value) {
    if (encoded.len == 0 or encoded.len > maximum_owner_packet) return error.NativeOwnerPacketTooLarge;
    // Reuse the native parser's quote-aware depth scan, then own every field
    // before wipeJson cleanup. The separate 64 KiB packet bound is stricter.
    var scanned = try codex.parseNativeReply(allocator, encoded);
    defer scanned.deinit();
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    errdefer {
        @import("../control.zig").wipeJson(parsed.value);
        parsed.deinit();
    }
    const root = parsed.value;
    if (root != .object) return error.InvalidNativeOwnerAck;
    const jsonrpc = try requiredOwnerString(root, "jsonrpc");
    const identifier = try requiredOwnerString(root, "id");
    if (!std.mem.eql(u8, jsonrpc, "2.0") or !std.mem.eql(u8, identifier, &operation)) return error.InvalidNativeOwnerAck;
    if (root.object.contains("error")) {
        try requireOwnerKeys(root, &.{ "jsonrpc", "id", "error" });
        const failure = root.object.get("error").?;
        if (failure != .object) return error.InvalidNativeOwnerAck;
        const code = failure.object.get("code") orelse return error.InvalidNativeOwnerAck;
        const message = failure.object.get("message") orelse return error.InvalidNativeOwnerAck;
        if (code != .integer or message != .string or message.string.len > 256) return error.InvalidNativeOwnerAck;
        return error.NativeOwnerRejected;
    }
    try requireOwnerKeys(root, &.{ "jsonrpc", "id", "result" });
    const result = root.object.get("result").?;
    if (result != .object) return error.InvalidNativeOwnerAck;
    const version = result.object.get("protocolVersion") orelse return error.InvalidNativeOwnerAck;
    if (version != .integer or version.integer != owner_protocol_version) return error.NativeOwnerProtocolRequired;
    return parsed;
}

fn wipeOwnerPacket(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

const owner_ack_keys = [_][]const u8{ "protocolVersion", "ownerId", "processNonce", "adapterEpoch", "endpointGeneration", "threadInstanceGeneration", "attachmentGeneration", "threadId", "operationId" };

fn parseOwnerAck(allocator: std.mem.Allocator, encoded: []const u8, operation: native_owner.OperationId, thread_id: []const u8, action: OwnerAction, witness: peer.Witness) !OwnerAck {
    var parsed = try parseOwnerEnvelope(allocator, encoded, operation);
    defer {
        @import("../control.zig").wipeJson(parsed.value);
        parsed.deinit();
    }
    const result = parsed.value.object.get("result").?;
    if (result.object.count() != owner_ack_keys.len + 1) return error.InvalidNativeOwnerAck;
    for (owner_ack_keys) |name| if (!result.object.contains(name)) return error.InvalidNativeOwnerAck;
    const success_name = if (action == .detach) "unregistered" else "registered";
    const success = result.object.get(success_name) orelse return error.InvalidNativeOwnerAck;
    if (success != .bool or !success.bool) return error.NativeOwnerRejected;
    const returned_thread = try requiredOwnerString(result, "threadId");
    try requireOwnerThread(returned_thread);
    if (!std.mem.eql(u8, returned_thread, thread_id)) return error.NativeOwnerThreadMismatch;
    const returned_operation = try ownerOperation(result);
    if (!std.mem.eql(u8, &returned_operation, &operation)) return error.NativeOwnerOperationMismatch;
    return .{
        .reference = try decodeOwnerReference(result),
        .native_nonce = try ownerHex(result, "processNonce"),
        .operation_id = returned_operation,
        .thread_id = try allocator.dupe(u8, returned_thread),
        .witness = witness,
        .action = action,
    };
}

fn ownerDeadline(io: std.Io, caller: ?std.Io.Clock.Timestamp) !std.Io.Clock.Timestamp {
    var until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(timeout_ms) });
    if (caller) |deadline| {
        if (deadline.clock != .awake) return error.InvalidDeadline;
        if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
        if (deadline.durationFromNow(io).raw.toMilliseconds() < until.durationFromNow(io).raw.toMilliseconds()) until = deadline;
    }
    return until;
}

/// One native worker owns this connection, its captured context and arguments.
/// Keep it across identity and effect stages; no actor or libcurl callback may
/// borrow it. Saved witnesses are compared, never converted into live contexts.
pub const OwnerConnection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    context: peer.Context,
    endpoint_path: []u8,
    until: std.Io.Clock.Timestamp,
    failed: bool = false,

    pub fn open(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, expected: ?peer.Witness, deadline: ?std.Io.Clock.Timestamp) !OwnerConnection {
        if (builtin.os.tag != .linux) return error.UnsupportedPeerProfile;
        const until = try ownerDeadline(io, deadline);
        try io.checkCancel();
        if (expected) |witness| try witness.validate();
        const endpoint_path = try resolveSocket(allocator, endpoint);
        errdefer allocator.free(endpoint_path);
        return openResolved(io, allocator, endpoint_path, expected, until);
    }

    /// Automatic discovery retains the inventory's root/parent descriptors for
    /// the entire exchange. An endpoint alias or changed publication refuses.
    /// This captures a live channel; filesystem metadata never creates custody.
    pub fn openAutomatic(io: std.Io, allocator: std.mem.Allocator, candidate: *const inventory.Candidate, deadline: ?std.Io.Clock.Timestamp) !OwnerConnection {
        if (builtin.os.tag != .linux) return error.UnsupportedPeerProfile;
        const until = try ownerDeadline(io, deadline);
        try io.checkCancel();
        try candidate.verify(allocator);
        const endpoint_path = try allocator.dupe(u8, candidate.endpoint_path);
        var transferred = false;
        defer if (!transferred) allocator.free(endpoint_path);
        var connection = openResolved(io, allocator, endpoint_path, null, until) catch |err| switch (err) {
            error.NativeUnavailable => {
                // A refused stale endpoint is different from a publication
                // replaced during connect. Never downgrade the latter to stale.
                try candidate.verify(allocator);
                if (until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
                return err;
            },
            else => return err,
        };
        transferred = true;
        errdefer connection.deinit();
        try verifyAutomaticPublication(&connection, candidate);
        return connection;
    }

    // The caller retains path custody on failure; a successful connection owns
    // the allocated path. Automatic inventory never uses alias resolution.
    fn openResolved(io: std.Io, allocator: std.mem.Allocator, endpoint_path: []u8, expected: ?peer.Witness, until: std.Io.Clock.Timestamp) !OwnerConnection {
        if (endpoint_path.len >= @as(posix.sockaddr.un, undefined).path.len) return error.SocketPathTooLong;
        const fd = socket(posix.AF.UNIX, posix.SOCK.SEQPACKET, 0);
        if (fd < 0) return error.NativeOwnerSocketFailed;
        errdefer _ = posix.close(fd);
        const flags = posix.fcntl(fd, posix.F.GETFL);
        if (flags < 0 or posix.fcntl(fd, posix.F.SETFL, flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true }))) != 0 or
            posix.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) != 0) return error.NativeOwnerSocketFailed;
        // Required before connect: every received packet must identify its
        // actual writer, including inherited or transferred socket descriptors.
        try peer.Context.enable(fd);
        var address: posix.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(address.path[0..endpoint_path.len], endpoint_path);
        const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + endpoint_path.len + 1);
        if (posix.connect(fd, @ptrCast(&address), length) != 0) {
            switch (posix.errno(-1)) {
                .INPROGRESS, .AGAIN => {},
                .NOENT, .CONNREFUSED => return error.NativeUnavailable,
                else => return error.NativeOwnerSocketFailed,
            }
            try waitOwnerReady(io, fd, posix.POLL.OUT, until);
            var failure: c_int = 0;
            var failure_size: posix.socklen_t = @sizeOf(c_int);
            if (posix.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, &failure, &failure_size) != 0 or failure_size != @sizeOf(c_int) or failure != 0) return error.NativeUnavailable;
        }
        // Capture occurs before the first protocol byte is sent or consumed.
        var context = try peer.Context.capture(fd, @intCast(posix.getuid()));
        errdefer context.deinit();
        try context.alive();
        if (expected) |witness| if (!peer.sameOriginal(witness, context.witness())) return error.NativeOwnerPeerMismatch;
        return .{ .io = io, .allocator = allocator, .fd = fd, .context = context, .endpoint_path = endpoint_path, .until = until };
    }

    pub fn deinit(self: *OwnerConnection) void {
        self.context.deinit();
        _ = posix.close(self.fd);
        self.allocator.free(self.endpoint_path);
        self.* = undefined;
    }

    pub fn verifiedWitness(self: *const OwnerConnection) !peer.Witness {
        if (self.failed) return error.NativeOwnerConnectionFailed;
        try self.context.alive();
        return self.context.witness();
    }

    pub fn identify(self: *OwnerConnection, thread_id: []const u8, operation_id: native_owner.OperationId) !OwnerIdentity {
        try requireOwnerThread(thread_id);
        try native_owner.validateOperation(operation_id);
        errdefer self.failed = true;
        const request = try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = operation_id[0..], .method = "owner/identify", .params = .{ .protocolVersion = owner_protocol_version, .threadId = thread_id } }, .{});
        defer wipeOwnerPacket(self.allocator, request);
        const response = try self.exchange(request);
        defer wipeOwnerPacket(self.allocator, response);
        var parsed = try parseOwnerEnvelope(self.allocator, response, operation_id);
        defer {
            @import("../control.zig").wipeJson(parsed.value);
            parsed.deinit();
        }
        const result = parsed.value.object.get("result").?;
        try requireOwnerKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "threadInstanceGeneration", "threadId" });
        const returned_thread = try requiredOwnerString(result, "threadId");
        try requireOwnerThread(returned_thread);
        if (!std.mem.eql(u8, returned_thread, thread_id)) return error.NativeOwnerThreadMismatch;
        const witness = try self.verifiedWitness();
        return .{
            .owner_id = try ownerHex(result, "ownerId"),
            .native_nonce = try ownerHex(result, "processNonce"),
            .endpoint_generation = try parseOwnerGeneration(result.object.get("endpointGeneration").?),
            .thread_instance_generation = try parseOwnerGeneration(result.object.get("threadInstanceGeneration").?),
            .thread_id = try self.allocator.dupe(u8, returned_thread),
            .witness = witness,
        };
    }

    pub fn capabilities(self: *OwnerConnection, operation_id: native_owner.OperationId) !OwnerNativeInfo {
        try native_owner.validateOperation(operation_id);
        errdefer self.failed = true;
        const request = try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = operation_id[0..], .method = "owner/capabilities", .params = .{ .protocolVersion = owner_protocol_version } }, .{});
        defer wipeOwnerPacket(self.allocator, request);
        const response = try self.exchange(request);
        defer wipeOwnerPacket(self.allocator, response);
        var parsed = try parseOwnerEnvelope(self.allocator, response, operation_id);
        defer {
            @import("../control.zig").wipeJson(parsed.value);
            parsed.deinit();
        }
        const result = parsed.value.object.get("result").?;
        try requireOwnerKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "nativeVersion", "capabilities" });
        const native_version = try requiredOwnerString(result, "nativeVersion");
        try requireNativeVersion(native_version);
        const capabilities_value = result.object.get("capabilities").?;
        try requireOwnerKeys(capabilities_value, &.{ "protocol_version", "late_thread_binding", "per_request_auth", "exclusive_refresh_owner", "preacceptance_failure", "account_transport_invalidation", "native_context_reconstruction" });
        const version = capabilities_value.object.get("protocol_version").?;
        if (version != .integer or version.integer != codex.protocol_version) return error.InvalidNativeOwnerCapabilities;
        var hook: codex.HookCapabilities = .{ .protocol_version = codex.protocol_version };
        inline for (.{ "late_thread_binding", "per_request_auth", "exclusive_refresh_owner", "preacceptance_failure", "account_transport_invalidation", "native_context_reconstruction" }) |name| {
            const flag = capabilities_value.object.get(name).?;
            if (flag != .bool) return error.InvalidNativeOwnerCapabilities;
            @field(hook, name) = flag.bool;
        }
        const owner_id = try ownerHex(result, "ownerId");
        const nonce = try ownerHex(result, "processNonce");
        const generation = try parseOwnerGeneration(result.object.get("endpointGeneration").?);
        const witness = try self.verifiedWitness();
        return .{ .native_version = try self.allocator.dupe(u8, native_version), .support = codex.support(hook), .owner_id = owner_id, .native_nonce = nonce, .endpoint_generation = generation, .witness = witness };
    }

    pub fn threads(self: *OwnerConnection, operation_id: native_owner.OperationId) !OwnerThreadSnapshot {
        try native_owner.validateOperation(operation_id);
        errdefer self.failed = true;
        const request = try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = operation_id[0..], .method = "owner/threads", .params = .{ .protocolVersion = owner_protocol_version } }, .{});
        defer wipeOwnerPacket(self.allocator, request);
        const response = try self.exchange(request);
        defer wipeOwnerPacket(self.allocator, response);
        var parsed = try parseOwnerEnvelope(self.allocator, response, operation_id);
        defer {
            @import("../control.zig").wipeJson(parsed.value);
            parsed.deinit();
        }
        const result = parsed.value.object.get("result").?;
        try requireOwnerKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "threads" });
        const owner_id = try ownerHex(result, "ownerId");
        const nonce = try ownerHex(result, "processNonce");
        const generation = try parseOwnerGeneration(result.object.get("endpointGeneration").?);
        const rows = try parseOwnerThreadRows(self.allocator, result.object.get("threads").?);
        errdefer {
            for (rows) |row| self.allocator.free(row.thread_id);
            self.allocator.free(rows);
        }
        const witness = try self.verifiedWitness();
        return .{ .owner_id = owner_id, .native_nonce = nonce, .endpoint_generation = generation, .witness = witness, .threads = rows };
    }

    /// ff7e read-only declaration: hint context is compared locally, never sent
    /// as a field unsupported by the version-bound native request schema.
    pub fn sourceContext(self: *OwnerConnection, operation_id: native_owner.OperationId, selector: SourceContextSelector) !SourceContextDeclaration {
        errdefer self.failed = true;
        try selector.validate();
        try native_owner.validateOperation(operation_id);
        try self.io.checkCancel();
        if (self.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
        const original = try self.verifiedWitness();
        const owner = std.fmt.bytesToHex(selector.owner_id, .lower);
        const nonce = std.fmt.bytesToHex(selector.native_nonce, .lower);
        var generation_buffer: [20]u8 = undefined;
        const generation = try std.fmt.bufPrint(&generation_buffer, "{d}", .{selector.endpoint_generation});
        const request = try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = operation_id[0..], .method = "owner/source/context", .params = .{
            .protocolVersion = owner_protocol_version, .ownerId = owner[0..], .processNonce = nonce[0..], .endpointGeneration = generation,
        } }, .{});
        defer wipeOwnerPacket(self.allocator, request);
        const response = try self.exchange(request);
        defer wipeOwnerPacket(self.allocator, response);
        var parsed = try parseOwnerEnvelope(self.allocator, response, operation_id);
        defer { @import("../control.zig").wipeJson(parsed.value); parsed.deinit(); }
        const result = try decodeSourceContext(parsed.value.object.get("result").?, selector, original);
        if (!peer.sameOriginal(original, try self.verifiedWitness())) return error.NativeOwnerPeerMismatch;
        try self.io.checkCancel();
        if (self.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
        return result;
    }

    pub fn register(self: *OwnerConnection, request: OwnerRequest, expected: peer.Witness) !OwnerAck {
        try request.validate();
        const broker_socket = request.broker_socket orelse return error.NativeOwnerBrokerConfigRequired;
        const capability_path = request.capability_path orelse return error.NativeOwnerBrokerConfigRequired;
        try requireOwnerPath(broker_socket);
        try requireOwnerPath(capability_path);
        return self.effect(request, expected, .register);
    }

    pub fn detach(self: *OwnerConnection, request: OwnerRequest, expected: peer.Witness) !OwnerAck {
        try request.validate();
        return self.effect(request, expected, .detach);
    }

    pub fn announce(self: *OwnerConnection, thread_id: []const u8, operation_id: native_owner.OperationId, config: codex.BrokerConfig) !OwnerAck {
        try requireOwnerPath(config.broker_socket);
        try requireOwnerPath(config.capability_path);
        errdefer self.failed = true;
        // This path invokes the real native producer. The incoming CLI peer is
        // never assigned as the native owner. Root verifies the persisted inner
        // registration row before completing its outer control mutation.
        var identity = try self.identify(thread_id, operation_id);
        defer identity.deinit(self.allocator);
        const request = try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = operation_id[0..], .method = "owner/announce", .params = .{ .protocolVersion = owner_protocol_version, .threadId = thread_id, .operationId = operation_id[0..], .brokerSocket = config.broker_socket, .capabilityPath = config.capability_path } }, .{});
        defer wipeOwnerPacket(self.allocator, request);
        const response = try self.exchange(request);
        defer wipeOwnerPacket(self.allocator, response);
        var ack = try parseOwnerAck(self.allocator, response, operation_id, thread_id, .announce, try self.verifiedWitness());
        errdefer ack.deinit(self.allocator);
        if (!std.mem.eql(u8, &ack.reference.owner_id, &identity.owner_id) or !std.mem.eql(u8, &ack.native_nonce, &identity.native_nonce) or
            ack.reference.endpoint_generation != identity.endpoint_generation or ack.reference.thread_instance_generation != identity.thread_instance_generation or
            !peer.sameOriginal(ack.witness, identity.witness)) return error.NativeOwnerIdentityMismatch;
        return ack;
    }

    fn effect(self: *OwnerConnection, request: OwnerRequest, expected: peer.Witness, action: OwnerAction) !OwnerAck {
        errdefer self.failed = true;
        try expected.validate();
        if (!peer.sameOriginal(try self.verifiedWitness(), expected)) return error.NativeOwnerPeerMismatch;
        const owner_id = std.fmt.bytesToHex(request.reference.owner_id, .lower);
        const nonce = std.fmt.bytesToHex(request.native_nonce, .lower);
        var adapter_buffer: [20]u8 = undefined;
        var endpoint_buffer: [20]u8 = undefined;
        var thread_buffer: [20]u8 = undefined;
        var attachment_buffer: [20]u8 = undefined;
        const adapter = try std.fmt.bufPrint(&adapter_buffer, "{d}", .{request.reference.adapter_epoch});
        const endpoint = try std.fmt.bufPrint(&endpoint_buffer, "{d}", .{request.reference.endpoint_generation});
        const thread = try std.fmt.bufPrint(&thread_buffer, "{d}", .{request.reference.thread_instance_generation});
        const attachment = try std.fmt.bufPrint(&attachment_buffer, "{d}", .{request.reference.attachment_generation});
        const params = .{ .protocolVersion = owner_protocol_version, .ownerId = owner_id[0..], .processNonce = nonce[0..], .adapterEpoch = adapter, .endpointGeneration = endpoint, .threadInstanceGeneration = thread, .attachmentGeneration = attachment, .threadId = request.thread_id, .operationId = request.operation_id[0..] };
        const payload = if (action == .register)
            try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = request.operation_id[0..], .method = "owner/register", .params = .{
                .protocolVersion = params.protocolVersion,
                .ownerId = params.ownerId,
                .processNonce = params.processNonce,
                .adapterEpoch = params.adapterEpoch,
                .endpointGeneration = params.endpointGeneration,
                .threadInstanceGeneration = params.threadInstanceGeneration,
                .attachmentGeneration = params.attachmentGeneration,
                .threadId = params.threadId,
                .operationId = params.operationId,
                .brokerSocket = request.broker_socket.?,
                .capabilityPath = request.capability_path.?,
            } }, .{})
        else
            try std.json.Stringify.valueAlloc(self.allocator, .{ .jsonrpc = "2.0", .id = request.operation_id[0..], .method = "owner/unregister", .params = params }, .{});
        defer wipeOwnerPacket(self.allocator, payload);
        const response = try self.exchange(payload);
        defer wipeOwnerPacket(self.allocator, response);
        var ack = try parseOwnerAck(self.allocator, response, request.operation_id, request.thread_id, action, try self.verifiedWitness());
        errdefer ack.deinit(self.allocator);
        if (!ack.reference.same(request.reference) or !std.mem.eql(u8, &ack.native_nonce, &request.native_nonce)) return error.NativeOwnerReferenceMismatch;
        if (!peer.sameOriginal(ack.witness, expected)) return error.NativeOwnerPeerMismatch;
        return ack;
    }

    pub fn sourceOrigin(self: *OwnerConnection, operation: native_owner.OperationId, selector: SourceContextSelector, key: [32]u8, image: SourceImage) !source_consent.Handle {
        errdefer self.failed = true;
        try image.verify(self);
        const expected = selector.context orelse return error.NativeSourceContextRequired;
        const before = try self.sourceContext(operation, selector);
        if (before.status != .available) return error.NativeSourceUnavailable;
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const owner_id = std.fmt.bytesToHex(selector.owner_id, .lower);
        const nonce = std.fmt.bytesToHex(selector.native_nonce, .lower);
        const context_id = std.fmt.bytesToHex(expected.id, .lower);
        const payload = try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = operation[0..], .method = "owner/source/origin", .params = .{
            .protocolVersion = owner_protocol_version, .ownerId = owner_id[0..], .processNonce = nonce[0..],
            .endpointGeneration = try std.fmt.allocPrint(a, "{d}", .{selector.endpoint_generation}),
            .sourceContextId = context_id[0..], .sourceContextGeneration = try std.fmt.allocPrint(a, "{d}", .{expected.generation}) } }, .{});
        const response = try self.exchange(payload);
        defer wipeOwnerPacket(self.allocator, response);
        var parsed = try parseOwnerEnvelope(self.allocator, response, operation);
        defer { @import("../control.zig").wipeJson(parsed.value); parsed.deinit(); }
        const result = parsed.value.object.get("result") orelse return error.InvalidNativeSourcePayload;
        const owner: source_consent.Owner = .{ .id = selector.owner_id, .nonce = selector.native_nonce,
            .endpoint_generation = selector.endpoint_generation, .witness = before.witness };
        const origin = try source_acquisition.verifyOrigin(a, result, owner, .{ .id = expected.id, .generation = expected.generation }, key);
        const after = try self.sourceContext(operation, selector);
        if (after.status != .available or !peer.sameOriginal(before.witness, after.witness)) return error.NativeSourceUnavailable;
        try source_acquisition.deadline(self.io, self.until);
        try image.verify(self);
        return origin;
    }

    pub const AccessCopy = struct {
        candidate: @import("../discovery.zig").OwnedCandidate,
        binding: source_consent.MaterializedBinding,
        origin: source_consent.Handle,
        pub fn deinit(self: *AccessCopy) void { self.candidate.deinit(); self.* = undefined; }
    };
    pub fn acquireSource(self: *OwnerConnection, request: source_acquisition.Request, key: [32]u8, now: i64, image: SourceImage) !AccessCopy {
        errdefer self.failed = true;
        try image.verify(self);
        try request.validate();
        if (now >= request.consent_expires_at) return error.NativeSourceUnauthorized;
        const selected: SourceContextSelector = .{ .owner_id = request.admission.owner.id, .native_nonce = request.admission.owner.nonce,
            .endpoint_generation = request.admission.owner.endpoint_generation,
            .context = .{ .id = request.admission.context.id, .generation = request.admission.context.generation } };
        if (!peer.sameOriginal(try self.verifiedWitness(), request.admission.owner.witness)) return error.NativeOwnerPeerMismatch;
        const initial = try self.sourceContext(request.operation, selected);
        if (initial.status != .available or initial.store_present != true) return error.NativeSourceUnavailable;
        const actual_origin = try self.sourceOrigin(request.operation, selected, key, image);
        if (!std.mem.eql(u8, &actual_origin, &request.origin)) return error.NativeSourceOriginChanged;
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const payload = try source_acquisition.encodeRequest(a, request, key);
        const packet = try self.exchangeDescriptor(payload);
        defer wipeOwnerPacket(self.allocator, packet.bytes);
        // readDescriptor consumes the transferred fd even on expiry/cancel/error.
        const bytes = try source_acquisition.readDescriptor(self.io, self.allocator, packet.descriptor, self.until);
        defer { std.crypto.secureZero(u8, bytes); self.allocator.free(bytes); }
        var parsed = try parseOwnerEnvelope(self.allocator, packet.bytes, request.operation);
        defer { @import("../control.zig").wipeJson(parsed.value); parsed.deinit(); }
        try source_acquisition.verifyReply(a, parsed.value.object.get("result") orelse return error.InvalidNativeSourcePayload, request, key, bytes);
        const source_id = std.fmt.bytesToHex(request.admission.source_id, .lower);
        var candidate = try source_acquisition.parsePayload(self.allocator, &source_id, bytes, now, request.custody_seconds);
        errdefer candidate.deinit();
        const after = try self.sourceContext(request.operation, selected);
        if (after.status != .available or after.store_present != true or !peer.sameOriginal(after.witness, request.admission.owner.witness)) return error.NativeSourceUnavailable;
        try source_acquisition.deadline(self.io, self.until);
        try image.verify(self);
        return .{ .candidate = candidate, .binding = .{ .owner = request.admission.owner, .context = request.admission.context }, .origin = request.origin };
    }

    const DescriptorPacket = struct { bytes: []u8, descriptor: posix.fd_t };
    fn exchangeDescriptor(self: *OwnerConnection, payload: []const u8) !DescriptorPacket {
        if (self.failed) return error.NativeOwnerConnectionFailed;
        if (payload.len == 0 or payload.len > maximum_owner_packet) return error.NativeOwnerPacketTooLarge;
        errdefer self.failed = true;
        try self.context.alive();
        while (true) {
            try waitOwnerReady(self.io, self.fd, posix.POLL.OUT, self.until);
            const sent = posix.send(self.fd, payload.ptr, payload.len, posix.MSG.NOSIGNAL);
            if (sent < 0) {
                switch (posix.errno(sent)) { .INTR, .AGAIN => continue, else => return error.NativeDisconnected }
            }
            if (sent != payload.len) return error.NativeOwnerInvalidPacket;
            break;
        }
        var buffer: [maximum_owner_packet]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        while (true) {
            try waitOwnerReady(self.io, self.fd, posix.POLL.IN, self.until);
            const received = self.context.receivePacketDescriptor(&buffer) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => continue, else => return err,
            };
            errdefer _ = posix.close(received.descriptor);
            if (received.bytes == 0) return error.NativeDisconnected;
            try self.context.alive();
            try source_acquisition.deadline(self.io, self.until);
            return .{ .bytes = try self.allocator.dupe(u8, buffer[0..received.bytes]), .descriptor = received.descriptor };
        }
    }

    fn exchange(self: *OwnerConnection, payload: []const u8) ![]u8 {
        if (self.failed) return error.NativeOwnerConnectionFailed;
        if (payload.len == 0 or payload.len > maximum_owner_packet) return error.NativeOwnerPacketTooLarge;
        errdefer self.failed = true;
        try self.context.alive();
        while (true) {
            try waitOwnerReady(self.io, self.fd, posix.POLL.OUT, self.until);
            const sent = posix.send(self.fd, payload.ptr, payload.len, if (builtin.os.tag == .linux) posix.MSG.NOSIGNAL else 0);
            if (sent < 0) {
                switch (posix.errno(sent)) {
                    .INTR, .AGAIN => continue,
                    else => return error.NativeDisconnected,
                }
            }
            // A packet is indivisible. Never resend a partially issued effect.
            if (sent != payload.len) return error.NativeOwnerInvalidPacket;
            break;
        }
        var buffer: [maximum_owner_packet]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        while (true) {
            try waitOwnerReady(self.io, self.fd, posix.POLL.IN, self.until);
            const received = self.context.receivePacket(&buffer) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => continue,
                else => return err,
            };
            if (received == 0) return error.NativeDisconnected;
            try self.context.alive();
            return self.allocator.dupe(u8, buffer[0..received]);
        }
    }
};

fn waitOwnerReady(io: std.Io, fd: posix.fd_t, events: i16, until: std.Io.Clock.Timestamp) !void {
    var descriptors = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    while (true) {
        try io.checkCancel();
        const remaining = until.durationFromNow(io).raw.toMilliseconds();
        if (remaining <= 0) return error.NativeTimeout;
        const count = posix.poll(&descriptors, 1, @intCast(@min(remaining, 100)));
        if (count < 0) {
            if (posix.errno(count) == .INTR) continue;
            return error.NativeDisconnected;
        }
        if (count == 0) continue;
        if (descriptors[0].revents & events != 0) return;
        if (descriptors[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return error.NativeDisconnected;
    }
}

fn requireNativeVersion(version: []const u8) !void {
    if (version.len == 0 or version.len > maximum_native_version_bytes) return error.InvalidNativeVersion;
}

fn requireLoadedResult(allocator: std.mem.Allocator, version: []const u8, socket_path: []const u8, support: codex.Support, thread_ids: []const []const u8) !void {
    // Match the public discovery result shape, including string escaping. The
    // longer installed=false variant bounds either installed state. Mutation
    // callers must additionally preflight their exact selected result at 1 KiB.
    const encoded = try std.json.Stringify.valueAlloc(allocator, .{ .adapter = "codex", .installed = false, .native_socket = socket_path, .native_version = version, .support = support, .thread_ids = thread_ids }, .{});
    defer allocator.free(encoded);
    if (encoded.len > maximum_loaded_result_bytes) return error.NativeResultTooLarge;
}

fn normalizeSystemPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (builtin.os.tag == .macos) {
        const Alias = struct { prefix: [:0]const u8, target: []const u8 };
        const aliases = [_]Alias{ .{ .prefix = "/tmp", .target = "/private/tmp" }, .{ .prefix = "/var", .target = "/private/var" } };
        for (aliases) |alias| {
            if (std.mem.startsWith(u8, path, alias.prefix) and path.len > alias.prefix.len and path[alias.prefix.len] == '/') {
                const status = metadata.statAt(posix.AT.FDCWD, alias.prefix.ptr, posix.AT.SYMLINK_NOFOLLOW) catch return error.UnsafeSystemAlias;
                if (status.uid != 0 or status.mode & posix.S.IFMT != posix.S.IFLNK) return error.UnsafeSystemAlias;
                var destination: [64]u8 = undefined;
                const count = posix.readlinkat(posix.AT.FDCWD, alias.prefix.ptr, &destination, destination.len);
                if (count <= 0 or count == destination.len) return error.UnsafeSystemAlias;
                const target = destination[0..@intCast(count)];
                if (!std.mem.eql(u8, target, alias.target) and !std.mem.eql(u8, target, alias.target[1..])) return error.UnsafeSystemAlias;
                return std.mem.concat(allocator, u8, &.{ alias.target, path[alias.prefix.len..] });
            }
        }
    }
    return allocator.dupe(u8, path);
}

fn verifyPeer(fd: posix.fd_t) !void {
    switch (builtin.os.tag) {
        .linux => {
            const Credentials = extern struct { pid: posix.pid_t, uid: posix.uid_t, gid: posix.gid_t };
            var credentials: Credentials = undefined;
            var length: posix.socklen_t = @sizeOf(Credentials);
            if (posix.getsockopt(fd, posix.SOL.SOCKET, posix.SO.PEERCRED, &credentials, &length) != 0 or length != @sizeOf(Credentials) or credentials.uid != posix.getuid()) return error.PeerRejected;
        },
        .macos => {
            var uid: posix.uid_t = undefined;
            var gid: posix.gid_t = undefined;
            if (getpeereid(fd, &uid, &gid) != 0 or uid != posix.getuid()) return error.PeerRejected;
        },
        else => return error.UnsupportedPlatform,
    }
}

fn safeParent(allocator: std.mem.Allocator, path: []const u8) !posix.fd_t {
    try paths.validateAbsolute(path);
    var fd = posix.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.PathOpenFailed;
    errdefer _ = posix.close(fd);
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        const status = try metadata.statFd(fd);
        const root_sticky = status.uid == 0 and status.mode & 0o1000 != 0;
        if (status.mode & posix.S.IFMT != posix.S.IFDIR or (status.uid != 0 and status.uid != posix.getuid()) or (status.mode & 0o022 != 0 and !root_sticky)) return error.UnsafeSocketParent;
        const name = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(name);
        const next = posix.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0) return error.PathOpenFailed;
        _ = posix.close(fd);
        fd = next;
    }
    const status = try metadata.statFd(fd);
    if (status.mode & posix.S.IFMT != posix.S.IFDIR or status.uid != posix.getuid() or status.mode & 0o022 != 0) return error.UnsafeSocketParent;
    return fd;
}

/// Native Codex advertises a symlink to its protected /tmp socket. Resolve only
/// that final, user-owned link; every ancestor of the destination is NOFOLLOW.
fn resolveSocket(allocator: std.mem.Allocator, advertised: []const u8) ![]u8 {
    const canonical = try normalizeSystemPath(allocator, advertised);
    defer allocator.free(canonical);
    try paths.validateAbsolute(canonical);
    const separator = std.mem.lastIndexOfScalar(u8, canonical, '/') orelse return error.InvalidSocketPath;
    if (separator == 0) return error.InvalidSocketPath;
    const parent = try safeParent(allocator, canonical[0..separator]);
    defer _ = posix.close(parent);
    const basename = try allocator.dupeSentinel(u8, canonical[separator + 1 ..], 0);
    defer allocator.free(basename);
    const status = metadata.statAt(parent, basename.ptr, posix.AT.SYMLINK_NOFOLLOW) catch return error.NativeUnavailable;
    if (status.uid != posix.getuid()) return error.UnsafeSocketOwner;
    if (status.mode & posix.S.IFMT == posix.S.IFLNK) {
        var target: [4096]u8 = undefined;
        const count = posix.readlinkat(parent, basename.ptr, &target, target.len);
        if (count <= 0 or count == target.len) return error.InvalidSocketPath;
        const destination = try normalizeSystemPath(allocator, target[0..@intCast(count)]);
        defer allocator.free(destination);
        try verifySocketPath(allocator, destination);
        return allocator.dupe(u8, destination);
    }
    try verifySocketPath(allocator, canonical);
    return allocator.dupe(u8, canonical);
}

fn verifySocketPath(allocator: std.mem.Allocator, path: []const u8) !void {
    try paths.validateAbsolute(path);
    const separator = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidSocketPath;
    if (separator == 0) return error.InvalidSocketPath;
    const parent = try paths.openPrivateRoot(allocator, path[0..separator], false);
    defer _ = posix.close(parent);
    const basename = try allocator.dupeSentinel(u8, path[separator + 1 ..], 0);
    defer allocator.free(basename);
    const status = metadata.statAt(parent, basename.ptr, posix.AT.SYMLINK_NOFOLLOW) catch return error.NativeUnavailable;
    if (status.mode & posix.S.IFMT != posix.S.IFSOCK or status.uid != posix.getuid() or status.mode & 0o777 != 0o600) return error.UnsafeSocketPath;
}

fn setLong(easy: *curl.CURL, option: curl.CURLoption, value: c_long) !void {
    if (curl.curl_easy_setopt(easy, option, value) != curl.CURLE_OK) return error.CurlOption;
}
fn setString(easy: *curl.CURL, option: curl.CURLoption, value: [*:0]const u8) !void {
    if (curl.curl_easy_setopt(easy, option, value) != curl.CURLE_OK) return error.CurlOption;
}

fn headerLimit(_: [*c]u8, size: usize, count: usize, context: ?*anyopaque) callconv(.c) usize {
    const length = std.math.mul(usize, size, count) catch return 0;
    const used: *usize = @ptrCast(@alignCast(context.?));
    if (length > 8192 -| used.*) return 0;
    used.* += length;
    return length;
}

const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    easy: *curl.CURL,
    fd: posix.fd_t,
    socket_path: []u8,
    header_bytes: *usize,
    until: std.Io.Clock.Timestamp,

    fn wait(self: Connection, events: i16) !void {
        var pollfds = [_]posix.pollfd{.{ .fd = self.fd, .events = events, .revents = 0 }};
        while (true) {
            try self.io.checkCancel();
            const remaining = self.until.durationFromNow(self.io).raw.toMilliseconds();
            if (remaining <= 0) return error.NativeTimeout;
            const rc = posix.poll(&pollfds, 1, @intCast(@min(remaining, 100)));
            if (rc < 0) {
                if (posix.errno(rc) == .INTR) continue;
                return error.NativeDisconnected;
            }
            if (rc == 0) continue;
            if (pollfds[0].revents & events != 0) return;
            if (pollfds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return error.NativeDisconnected;
        }
    }

    fn send(self: Connection, payload: []const u8) !void {
        if (payload.len > max_message) return error.MessageTooLarge;
        var offset: usize = 0;
        while (offset < payload.len) {
            try self.io.checkCancel();
            if (self.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
            var sent: usize = 0;
            const result = curl.curl_ws_send(self.easy, payload[offset..].ptr, payload.len - offset, &sent, 0, curl.CURLWS_TEXT);
            if (sent > payload.len - offset) return error.InvalidFrame;
            offset += sent;
            if (result == curl.CURLE_AGAIN or (result == curl.CURLE_OK and sent == 0)) {
                try self.wait(posix.POLL.OUT);
            } else if (result != curl.CURLE_OK) return error.NativeDisconnected;
        }
    }

    fn receive(self: Connection) ![]u8 {
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var frame_count: usize = 0;
        var buffer: [8192]u8 = undefined;
        while (frame_count < 256) {
            try self.io.checkCancel();
            if (self.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
            var count: usize = 0;
            var frame_metadata: [*c]const curl.struct_curl_ws_frame = null;
            const result = curl.curl_ws_recv(self.easy, &buffer, buffer.len, &count, &frame_metadata);
            if (result == curl.CURLE_AGAIN) {
                try self.wait(posix.POLL.IN);
                continue;
            }
            if (result != curl.CURLE_OK or frame_metadata == null) return error.NativeDisconnected;
            frame_count += 1;
            if (count > buffer.len or frame_metadata.*.bytesleft < 0) return error.InvalidFrame;
            if (frame_metadata.*.flags & curl.CURLWS_CLOSE != 0) return error.NativeDisconnected;
            if (frame_metadata.*.flags & (curl.CURLWS_PING | curl.CURLWS_PONG) != 0) continue;
            if (frame_metadata.*.flags & curl.CURLWS_TEXT == 0) return error.UnsupportedFrame;
            if (count > max_message -| body.items.len or @as(u64, @intCast(frame_metadata.*.bytesleft)) > max_message -| body.items.len -| count) return error.MessageTooLarge;
            try body.appendSlice(self.allocator, buffer[0..count]);
            if (frame_metadata.*.bytesleft == 0 and frame_metadata.*.flags & curl.CURLWS_CONT == 0) return body.toOwnedSlice(self.allocator);
        }
        return error.NativeMessageLimit;
    }

    fn reply(self: Connection, expected_id: i64) ![]u8 {
        var attempts: usize = 0;
        while (attempts < 32) : (attempts += 1) {
            const bytes = try self.receive();
            errdefer self.allocator.free(bytes);
            const parsed = try codex.parseNativeReply(self.allocator, bytes);
            defer parsed.deinit();
            if (parsed.value != .object) return error.InvalidHandshake;
            if (parsed.value.object.get("id")) |id| {
                if (id == .integer and id.integer == expected_id) {
                    try codex.validateResponseEnvelope(parsed.value);
                    return bytes;
                }
            }
            self.allocator.free(bytes);
        }
        return error.NativeMessageLimit;
    }
};

fn openConnection(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, deadline: ?std.Io.Clock.Timestamp) !Connection {
    var until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(timeout_ms) });
    if (deadline) |caller| {
        if (caller.clock != .awake) return error.InvalidDeadline;
        const remaining = caller.durationFromNow(io).raw.toMilliseconds();
        if (remaining <= 0) return error.NativeTimeout;
        if (remaining < until.durationFromNow(io).raw.toMilliseconds()) until = caller;
    }
    try io.checkCancel();
    const socket_path = try resolveSocket(allocator, advertised_socket);
    errdefer allocator.free(socket_path);
    const socket_z = try allocator.dupeSentinel(u8, socket_path, 0);
    defer allocator.free(socket_z);
    const header_bytes = try allocator.create(usize);
    errdefer allocator.destroy(header_bytes);
    header_bytes.* = 0;
    if (curl.curl_global_init(curl.CURL_GLOBAL_DEFAULT) != curl.CURLE_OK) return error.CurlInit;
    errdefer curl.curl_global_cleanup();
    const easy = curl.curl_easy_init() orelse return error.CurlInit;
    errdefer curl.curl_easy_cleanup(easy);
    try setString(easy, curl.CURLOPT_URL, "ws://localhost/");
    try setString(easy, curl.CURLOPT_PROTOCOLS_STR, "ws");
    try setString(easy, curl.CURLOPT_UNIX_SOCKET_PATH, socket_z.ptr);
    try setString(easy, curl.CURLOPT_PROXY, "");
    try setString(easy, curl.CURLOPT_NOPROXY, "*");
    try setLong(easy, curl.CURLOPT_NETRC, curl.CURL_NETRC_IGNORED);
    try setLong(easy, curl.CURLOPT_FOLLOWLOCATION, 0);
    try setLong(easy, curl.CURLOPT_NOSIGNAL, 1);
    try setLong(easy, curl.CURLOPT_CONNECT_ONLY, 2);
    const connect_remaining = until.durationFromNow(io).raw.toMilliseconds();
    if (connect_remaining <= 0) return error.NativeTimeout;
    try setLong(easy, curl.CURLOPT_CONNECTTIMEOUT_MS, @intCast(@min(connect_remaining, timeout_ms)));
    try setLong(easy, curl.CURLOPT_TIMEOUT_MS, @intCast(@min(connect_remaining, timeout_ms)));
    if (curl.curl_easy_setopt(easy, curl.CURLOPT_HEADERDATA, @as(*anyopaque, @ptrCast(header_bytes))) != curl.CURLE_OK or curl.curl_easy_setopt(easy, curl.CURLOPT_HEADERFUNCTION, @as(*const fn ([*c]u8, usize, usize, ?*anyopaque) callconv(.c) usize, headerLimit)) != curl.CURLE_OK) return error.CurlOption;
    const performed = curl.curl_easy_perform(easy);
    if (until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
    if (performed != curl.CURLE_OK) return error.NativeUnavailable;
    var fd: curl.curl_socket_t = -1;
    if (curl.curl_easy_getinfo(easy, curl.CURLINFO_ACTIVESOCKET, &fd) != curl.CURLE_OK or fd < 0) return error.NativeUnavailable;
    try verifyPeer(fd);
    return .{ .io = io, .allocator = allocator, .easy = easy, .fd = fd, .socket_path = socket_path, .header_bytes = header_bytes, .until = until };
}

fn closeConnection(connection: Connection) void {
    curl.curl_easy_cleanup(connection.easy);
    curl.curl_global_cleanup();
    connection.allocator.free(connection.socket_path);
    connection.allocator.destroy(connection.header_bytes);
}

fn initializeConnection(connection: Connection, omux_version: []const u8) !codex.NativeInfo {
    const allocator = connection.allocator;
    const initialization = try codex.initializeRequest(allocator, 1, omux_version);
    defer allocator.free(initialization);
    try connection.send(initialization);
    const response = try connection.reply(1);
    defer allocator.free(response);
    var info = try codex.parseHandshake(allocator, response);
    errdefer allocator.free(info.native_version);
    try requireNativeVersion(info.native_version);
    try connection.send("{\"method\":\"initialized\",\"params\":{}}");
    if (info.support == .native_unsupported) {
        try connection.send("{\"id\":2,\"method\":\"omux/broker/capabilities\",\"params\":{}}");
        const capabilities = try connection.reply(2);
        defer allocator.free(capabilities);
        info.support = try codex.parseCapabilities(allocator, capabilities);
    }
    return info;
}

/// Legacy read-only WebSocket inspection. Primary setup/discovery uses the
/// authenticated owner endpoint; this response never establishes custody.
pub fn inspect(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8) !codex.NativeInfo {
    return inspectWithDeadline(io, allocator, advertised_socket, omux_version, null);
}

pub fn inspectWithDeadline(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !codex.NativeInfo {
    const connection = try openConnection(io, allocator, advertised_socket, deadline);
    defer closeConnection(connection);
    return initializeConnection(connection, omux_version);
}

fn ownerReadOperation(io: std.Io) !native_owner.OperationId {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    return std.fmt.bytesToHex(random, .lower);
}

/// Primary native setup inspection. Availability and compatible metadata do
/// not establish grant activation, attached custody or seamless continuity.
pub fn inspectOwner(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, omux_version: []const u8) !OwnerNativeInfo {
    return inspectOwnerWithDeadline(io, allocator, endpoint, omux_version, null);
}

pub fn inspectOwnerWithDeadline(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !OwnerNativeInfo {
    _ = omux_version;
    var connection = try OwnerConnection.open(io, allocator, endpoint, null, deadline);
    defer connection.deinit();
    return connection.capabilities(try ownerReadOperation(io));
}

/// The inventory must outlive this call. Only the verified native response
/// supplies process identity; the directory suffix is a publication check.
pub fn inspectAutomaticOwnerWithDeadline(io: std.Io, allocator: std.mem.Allocator, candidate: *const inventory.Candidate, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !OwnerNativeInfo {
    _ = omux_version;
    var connection = try OwnerConnection.openAutomatic(io, allocator, candidate, deadline);
    defer connection.deinit();
    const info = try connection.capabilities(try ownerReadOperation(io));
    errdefer info.deinit(allocator);
    try verifyAutomaticPublication(&connection, candidate);
    if (!candidate.matchesOwner(info.owner_id)) return error.NativeOwnerIdentityMismatch;
    return info;
}

pub fn loadedOwnerThreads(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, omux_version: []const u8) !OwnerLoadedThreads {
    return loadedOwnerThreadsWithDeadline(io, allocator, endpoint, omux_version, null);
}

/// Capabilities and thread rows come from the same captured native channel.
/// Reserved generation metadata is not an actor-issued attachment admission.
/// Oversized packet/list refusals never initiate registration or detach.
pub fn loadedOwnerThreadsWithDeadline(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !OwnerLoadedThreads {
    _ = omux_version;
    var connection = try OwnerConnection.open(io, allocator, endpoint, null, deadline);
    defer connection.deinit();
    return readLoadedOwner(&connection);
}

pub fn inspectSourceContextWithDeadline(io: std.Io, allocator: std.mem.Allocator, endpoint: []const u8, expected: peer.Witness, selector: SourceContextSelector, deadline: ?std.Io.Clock.Timestamp) !SourceContextDeclaration {
    try selector.validate();
    var connection = try OwnerConnection.open(io, allocator, endpoint, expected, deadline);
    defer connection.deinit();
    return connection.sourceContext(try ownerReadOperation(io), selector);
}

pub fn inspectAutomaticSourceContextWithDeadline(io: std.Io, allocator: std.mem.Allocator, candidate: *const inventory.Candidate, expected: peer.Witness, selector: SourceContextSelector, deadline: ?std.Io.Clock.Timestamp) !SourceContextDeclaration {
    try selector.validate();
    try expected.validate();
    if (!candidate.matchesOwner(selector.owner_id)) return error.NativeOwnerIdentityMismatch;
    var connection = try OwnerConnection.openAutomatic(io, allocator, candidate, deadline);
    defer connection.deinit();
    if (!peer.sameOriginal(expected, try connection.verifiedWitness())) return error.NativeOwnerPeerMismatch;
    const result = try connection.sourceContext(try ownerReadOperation(io), selector);
    try verifyAutomaticPublication(&connection, candidate);
    if (!peer.sameOriginal(expected, result.witness)) return error.NativeOwnerPeerMismatch;
    return result;
}

/// Qualified read-only inventory from one captured peer and one bounded
/// deadline. Candidate descriptors must remain owned by the caller's inventory.
/// Prospective attachment generations remain metadata, not admitted references.
pub fn loadedAutomaticOwnerThreadsWithDeadline(io: std.Io, allocator: std.mem.Allocator, candidate: *const inventory.Candidate, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !OwnerLoadedThreads {
    _ = omux_version;
    var connection = try OwnerConnection.openAutomatic(io, allocator, candidate, deadline);
    defer connection.deinit();
    const loaded = try readLoadedOwner(&connection);
    errdefer loaded.deinit(allocator);
    if (!candidate.matchesOwner(loaded.owner_id)) return error.NativeOwnerIdentityMismatch;
    try requireQualifiedLoadedResult(allocator, loaded);
    try verifyAutomaticPublication(&connection, candidate);
    return loaded;
}

fn verifyAutomaticPublication(connection: *const OwnerConnection, candidate: *const inventory.Candidate) !void {
    try connection.io.checkCancel();
    if (connection.until.durationFromNow(connection.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
    try candidate.verify(connection.allocator);
    _ = try connection.verifiedWitness();
    if (connection.until.durationFromNow(connection.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
}

fn requireQualifiedLoadedResult(allocator: std.mem.Allocator, loaded: OwnerLoadedThreads) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    const Thread = struct { thread_id: []const u8, thread_instance_generation: []const u8, attachment_generation: []const u8 };
    const rows = try temporary.alloc(Thread, loaded.threads.len);
    for (loaded.threads, rows) |row, *value| value.* = .{
        .thread_id = row.thread_id,
        .thread_instance_generation = try std.fmt.allocPrint(temporary, "{d}", .{row.thread_instance_generation}),
        .attachment_generation = try std.fmt.allocPrint(temporary, "{d}", .{row.attachment_generation}),
    };
    const owner_id = std.fmt.bytesToHex(loaded.owner_id, .lower);
    const nonce = std.fmt.bytesToHex(loaded.native_nonce, .lower);
    const encoded = try std.json.Stringify.valueAlloc(temporary, .{
        .native_socket = loaded.socket_path,
        .native_version = loaded.native_version,
        .support = loaded.support,
        .owner_id = owner_id[0..],
        .process_nonce = nonce[0..],
        .endpoint_generation = try std.fmt.allocPrint(temporary, "{d}", .{loaded.endpoint_generation}),
        .threads = rows,
    }, .{});
    if (encoded.len > maximum_loaded_result_bytes) return error.NativeThreadLimit;
}

fn readLoadedOwner(connection: *OwnerConnection) !OwnerLoadedThreads {
    const io = connection.io;
    const allocator = connection.allocator;
    const info = try connection.capabilities(try ownerReadOperation(io));
    errdefer info.deinit(allocator);
    const snapshot = try connection.threads(try ownerReadOperation(io));
    errdefer snapshot.deinit(allocator);
    if (!std.mem.eql(u8, &info.owner_id, &snapshot.owner_id) or !std.mem.eql(u8, &info.native_nonce, &snapshot.native_nonce) or
        info.endpoint_generation != snapshot.endpoint_generation or !peer.sameOriginal(info.witness, snapshot.witness)) return error.NativeOwnerIdentityMismatch;
    const thread_ids = try allocator.alloc([]u8, snapshot.threads.len);
    errdefer allocator.free(thread_ids);
    for (snapshot.threads, thread_ids) |row, *id| id.* = row.thread_id;
    try requireLoadedResult(allocator, info.native_version, connection.endpoint_path, info.support, thread_ids);
    const socket_path = try allocator.dupe(u8, connection.endpoint_path);
    return .{ .native_version = info.native_version, .socket_path = socket_path, .support = info.support, .owner_id = snapshot.owner_id, .native_nonce = snapshot.native_nonce, .endpoint_generation = snapshot.endpoint_generation, .witness = snapshot.witness, .threads = snapshot.threads, .thread_ids = thread_ids };
}

pub const LoadedThreads = struct {
    native_version: []u8,
    socket_path: []u8,
    support: codex.Support,
    thread_ids: [][]u8,

    pub fn deinit(self: LoadedThreads, allocator: std.mem.Allocator) void {
        allocator.free(self.native_version);
        allocator.free(self.socket_path);
        for (self.thread_ids) |thread_id| allocator.free(thread_id);
        allocator.free(self.thread_ids);
    }
};

/// Legacy read-only WebSocket discovery. Primary discovery uses
/// loadedOwnerThreads; listing metadata never establishes broker attachment.
pub fn loadedThreads(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8) !LoadedThreads {
    return loadedThreadsWithDeadline(io, allocator, advertised_socket, omux_version, null);
}

pub fn loadedThreadsWithDeadline(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, deadline: ?std.Io.Clock.Timestamp) !LoadedThreads {
    const connection = try openConnection(io, allocator, advertised_socket, deadline);
    defer closeConnection(connection);
    const info = try initializeConnection(connection, omux_version);
    errdefer allocator.free(info.native_version);
    var thread_ids: std.ArrayList([]u8) = .empty;
    errdefer {
        for (thread_ids.items) |thread_id| allocator.free(thread_id);
        thread_ids.deinit(allocator);
    }
    var cursor: ?[]u8 = null;
    defer if (cursor) |value| allocator.free(value);
    var page: usize = 0;
    while (page < 8) : (page += 1) {
        const request_id: i64 = @intCast(3 + page);
        const request = try std.json.Stringify.valueAlloc(allocator, .{
            .id = request_id,
            .method = "thread/loaded/list",
            .params = .{ .cursor = cursor, .limit = @as(u32, 64) },
        }, .{});
        defer allocator.free(request);
        try connection.send(request);
        const response = try connection.reply(request_id);
        defer allocator.free(response);
        const parsed = try codex.parseNativeReply(allocator, response);
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidThreadList;
        if (parsed.value.object.get("error") != null) return error.NativeThreadDiscoveryUnsupported;
        const result = parsed.value.object.get("result") orelse return error.InvalidThreadList;
        if (result != .object) return error.InvalidThreadList;
        const data = result.object.get("data") orelse return error.InvalidThreadList;
        if (data != .array or data.array.items.len > 64) return error.InvalidThreadList;
        if (data.array.items.len > 256 -| thread_ids.items.len) return error.NativeThreadLimit;
        for (data.array.items) |entry| {
            if (entry != .string or entry.string.len == 0 or entry.string.len > 256) return error.InvalidThreadList;
            for (entry.string) |byte| if (byte <= 0x20 or byte == 0x7f) return error.InvalidThreadList;
            for (thread_ids.items) |existing| if (std.mem.eql(u8, existing, entry.string)) return error.InvalidThreadList;
            const thread_id = try allocator.dupe(u8, entry.string);
            errdefer allocator.free(thread_id);
            try thread_ids.append(allocator, thread_id);
        }
        try requireLoadedResult(allocator, info.native_version, connection.socket_path, info.support, thread_ids.items);
        const next_cursor = result.object.get("nextCursor");
        if (next_cursor == null or next_cursor.? == .null) {
            const socket_path = try allocator.dupe(u8, connection.socket_path);
            errdefer allocator.free(socket_path);
            return .{ .native_version = info.native_version, .socket_path = socket_path, .support = info.support, .thread_ids = try thread_ids.toOwnedSlice(allocator) };
        }
        const next = next_cursor.?;
        if (next != .string or next.string.len == 0 or next.string.len > 4096 or data.array.items.len == 0) return error.InvalidThreadList;
        if (cursor) |current| if (std.mem.eql(u8, current, next.string)) return error.InvalidThreadList;
        const owned_next = try allocator.dupe(u8, next.string);
        if (cursor) |current| allocator.free(current);
        cursor = owned_next;
    }
    return error.NativeThreadLimit;
}

pub const Attachment = struct {
    native_version: []u8,
    binding_id: []u8,
    support: codex.Support,
    refresh_ownership_acknowledged: bool,
    pub fn deinit(self: Attachment, allocator: std.mem.Allocator) void {
        allocator.free(self.native_version);
        allocator.free(self.binding_id);
    }
};

/// Legacy WebSocket registration fails before I/O. Native custody requires
/// OwnerConnection and the credential-aware v2 endpoint.
pub fn attach(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, thread_id: []const u8, binding_id: []const u8, config: codex.BrokerConfig) !Attachment {
    return attachWithDeadline(io, allocator, advertised_socket, omux_version, thread_id, binding_id, config, null);
}

pub fn attachWithDeadline(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, thread_id: []const u8, binding_id: []const u8, config: codex.BrokerConfig, deadline: ?std.Io.Clock.Timestamp) !Attachment {
    _ = .{ io, allocator, advertised_socket, omux_version, thread_id, binding_id, config, deadline };
    return error.NativeOwnerProtocolRequired;
}

/// Legacy WebSocket detachment fails before I/O. Native custody requires
/// OwnerConnection and an exact v2 unregister acknowledgement.
pub fn detach(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, thread_id: []const u8) !codex.NativeInfo {
    return detachWithDeadline(io, allocator, advertised_socket, omux_version, thread_id, null);
}

pub fn detachWithDeadline(io: std.Io, allocator: std.mem.Allocator, advertised_socket: []const u8, omux_version: []const u8, thread_id: []const u8, deadline: ?std.Io.Clock.Timestamp) !codex.NativeInfo {
    _ = .{ io, allocator, advertised_socket, omux_version, thread_id, deadline };
    return error.NativeOwnerProtocolRequired;
}

test "owner thread reply refuses distinct IDs sharing one native instance generation" {
    const allocator = std.testing.allocator;
    const operation: native_owner.OperationId = @splat('a');
    const owner: [64]u8 = @splat('b');
    const nonce: [64]u8 = @splat('c');
    const WireThread = struct { threadId: []const u8, threadInstanceGeneration: []const u8, attachmentGeneration: []const u8 };
    for ([_]bool{ true, false }) |duplicate| {
        const encoded = try std.json.Stringify.valueAlloc(allocator, .{
            .jsonrpc = "2.0",
            .id = operation[0..],
            .result = .{
                .protocolVersion = owner_protocol_version,
                .ownerId = owner[0..],
                .processNonce = nonce[0..],
                .endpointGeneration = "1",
                .threads = [_]WireThread{
                    .{ .threadId = "fixture-first", .threadInstanceGeneration = "9007199254740993", .attachmentGeneration = "1" },
                    .{ .threadId = "fixture-second", .threadInstanceGeneration = if (duplicate) "9007199254740993" else "9007199254740994", .attachmentGeneration = "1" },
                },
            },
        }, .{});
        defer allocator.free(encoded);
        var parsed = try parseOwnerEnvelope(allocator, encoded, operation);
        defer parsed.deinit();
        const result = parsed.value.object.get("result").?;
        try requireOwnerKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "threads" });
        _ = try ownerHex(result, "ownerId");
        _ = try ownerHex(result, "processNonce");
        if (duplicate) {
            try std.testing.expectError(error.InvalidThreadList, parseOwnerThreadRows(allocator, result.object.get("threads").?));
        } else {
            const rows = try parseOwnerThreadRows(allocator, result.object.get("threads").?);
            defer {
                for (rows) |row| allocator.free(row.thread_id);
                allocator.free(rows);
            }
            try std.testing.expectEqual(@as(usize, 2), rows.len);
            try std.testing.expectEqual(@as(u64, 9007199254740993), rows[0].thread_instance_generation);
            try std.testing.expectEqual(@as(u64, 9007199254740994), rows[1].thread_instance_generation);
        }
    }
}

test "native probe rejects traversal and undeclared socket paths before IO" {
    try std.testing.expectError(error.UnsafePath, inspect(std.testing.io, std.testing.allocator, "/tmp/../wrong/socket", "fixture"));
    try std.testing.expectError(error.InvalidSocketPath, inspect(std.testing.io, std.testing.allocator, "/socket", "fixture"));
    const expired = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.NativeTimeout, inspectWithDeadline(std.testing.io, std.testing.allocator, "/tmp/../unread-socket", "fixture", expired));
}

/// Reuse the existing private RPC server only in declared synthetic tests.
/// Non-test executables have no fixture server type or startup entrypoint.
pub const FixtureForTest = if (builtin.is_test) NativeFixture else struct {};

const NativeFixture = struct {
    listener: c_int,
    mode: enum { stock, hook, attach, loaded, detach, detach_rejected, initialize_ambiguous, initialize_version_oversized, loaded_oversized, attach_server_request, attach_wrong_binding, attach_unowned, detach_ambiguous } = .hook,
    thread: ?std.Thread = null,
    succeeded: std.atomic.Value(bool) = .init(false),
    empty_loaded: bool = false,
    cache_oversized_loaded: bool = false,

    pub fn start(self: *NativeFixture) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }
    pub fn deinit(self: *NativeFixture) void {
        if (self.thread) |thread| thread.join();
        _ = curl.close(self.listener);
    }
    fn run(self: *NativeFixture) void {
        self.serve() catch return;
        self.succeeded.store(true, .release);
    }
    fn receive(fd: c_int, bytes: []u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            var ready: curl.struct_pollfd = .{ .fd = fd, .events = curl.POLLIN, .revents = 0 };
            if (curl.poll(&ready, 1, 2500) <= 0) return error.FixtureTimeout;
            const count = curl.recv(fd, bytes[offset..].ptr, bytes.len - offset, 0);
            if (count <= 0) return error.FixtureDisconnected;
            offset += @intCast(count);
        }
    }
    fn send(fd: c_int, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = curl.send(fd, bytes[offset..].ptr, bytes.len - offset, if (@hasDecl(curl, "MSG_NOSIGNAL")) curl.MSG_NOSIGNAL else 0);
            if (count <= 0) return error.FixtureDisconnected;
            offset += @intCast(count);
        }
    }
    fn text(fd: c_int, payload: []const u8) !void {
        if (payload.len > 65535) return error.FixtureTooLarge;
        if (payload.len < 126) {
            const prefix: [2]u8 = .{ 0x81, @intCast(payload.len) };
            try send(fd, &prefix);
        } else {
            const prefix: [4]u8 = .{ 0x81, 126, @intCast(payload.len >> 8), @truncate(payload.len) };
            try send(fd, &prefix);
        }
        try send(fd, payload);
    }
    fn message(fd: c_int, buffer: []u8) ![]const u8 {
        var prefix: [2]u8 = undefined;
        try receive(fd, &prefix);
        if (prefix[0] != 0x81 or prefix[1] & 0x80 == 0) return error.FixtureInvalidFrame;
        var size: usize = prefix[1] & 0x7f;
        if (size == 126) {
            var length: [2]u8 = undefined;
            try receive(fd, &length);
            size = @as(usize, length[0]) << 8 | length[1];
        } else if (size == 127) return error.FixtureTooLarge;
        if (size > buffer.len) return error.FixtureTooLarge;
        var mask: [4]u8 = undefined;
        try receive(fd, &mask);
        try receive(fd, buffer[0..size]);
        for (buffer[0..size], 0..) |*byte, index| byte.* ^= mask[index % 4];
        return buffer[0..size];
    }
    fn serve(self: *NativeFixture) !void {
        var ready: curl.struct_pollfd = .{ .fd = self.listener, .events = curl.POLLIN, .revents = 0 };
        if (curl.poll(&ready, 1, 2500) <= 0) return error.FixtureTimeout;
        const fd = curl.accept(self.listener, null, null);
        if (fd < 0) return error.FixtureAccept;
        defer _ = curl.close(fd);
        if (@hasDecl(curl, "SO_NOSIGPIPE")) {
            const enabled: c_int = 1;
            _ = curl.setsockopt(fd, curl.SOL_SOCKET, curl.SO_NOSIGPIPE, &enabled, @sizeOf(c_int));
        }
        var request: [8192]u8 = undefined;
        var used: usize = 0;
        while (used < request.len) {
            try receive(fd, request[used .. used + 1]);
            used += 1;
            if (used >= 4 and std.mem.eql(u8, request[used - 4 .. used], "\r\n\r\n")) break;
        }
        const key_prefix = "Sec-WebSocket-Key: ";
        const begin = std.mem.indexOf(u8, request[0..used], key_prefix) orelse return error.FixtureUpgrade;
        const key_start = begin + key_prefix.len;
        const end = std.mem.indexOfPos(u8, request[0..used], key_start, "\r\n") orelse return error.FixtureUpgrade;
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(request[key_start..end]);
        sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        var digest: [20]u8 = undefined;
        sha1.final(&digest);
        var encoded: [28]u8 = undefined;
        const accept = std.base64.standard.Encoder.encode(&encoded, &digest);
        try send(fd, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
        try send(fd, accept);
        try send(fd, "\r\n\r\n");
        var message_buffer: [4096]u8 = undefined;
        const first = try message(fd, &message_buffer);
        if (std.mem.indexOf(u8, first, "\"method\":\"initialize\"") == null) return error.FixtureUnexpectedRequest;
        if (self.mode == .initialize_ambiguous) {
            try text(fd, "{\"id\":1,\"result\":{\"userAgent\":\"fixture-native/1\"},\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
            return;
        }
        if (self.mode == .initialize_version_oversized) {
            const version: [maximum_native_version_bytes + 1]u8 = @splat('v');
            const response = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{ .id = @as(u64, 1), .result = .{ .userAgent = version[0..] } }, .{});
            defer std.heap.page_allocator.free(response);
            try text(fd, response);
            return;
        }
        // An unrelated response and an ordinary notification cannot claim the
        // current request ID or prevent a later valid native response.
        try text(fd, "{\"method\":\"thread/updated\",\"params\":{}}");
        try text(fd, "{\"id\":77,\"result\":{}}");
        try text(fd, "{\"id\":1,\"result\":{\"userAgent\":\"fixture-native/1\"}}");
        const initialized = try message(fd, &message_buffer);
        if (std.mem.indexOf(u8, initialized, "\"method\":\"initialized\"") == null) return error.FixtureUnexpectedRequest;
        const capabilities = try message(fd, &message_buffer);
        if (std.mem.indexOf(u8, capabilities, "\"method\":\"omux/broker/capabilities\"") == null) return error.FixtureUnexpectedRequest;
        if (self.mode == .stock) {
            try text(fd, "{\"id\":2,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
            return;
        }
        try text(fd, "{\"id\":2,\"result\":{\"protocolVersion\":1,\"capabilities\":{\"protocol_version\":1,\"late_thread_binding\":true,\"per_request_auth\":true,\"exclusive_refresh_owner\":true,\"preacceptance_failure\":true,\"account_transport_invalidation\":true,\"native_context_reconstruction\":true}}}");
        if (self.mode == .attach or self.mode == .attach_server_request or self.mode == .attach_wrong_binding or self.mode == .attach_unowned) {
            const registration = try message(fd, &message_buffer);
            if (std.mem.indexOf(u8, registration, "\"method\":\"omux/broker/register\"") == null or std.mem.indexOf(u8, registration, "existing-native-thread") == null or std.mem.indexOf(u8, registration, "capabilityPath") == null) return error.FixtureUnexpectedRequest;
            const response = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{
                .id = @as(u64, 3),
                .result = .{
                    .protocolVersion = @as(u32, 1),
                    .bindingId = if (self.mode == .attach_wrong_binding) "another-binding" else "binding",
                    .refreshOwnershipAcknowledged = self.mode != .attach_unowned,
                    .capabilities = .{ .protocol_version = @as(u32, 1), .late_thread_binding = true, .per_request_auth = true, .exclusive_refresh_owner = true, .preacceptance_failure = true, .account_transport_invalidation = true, .native_context_reconstruction = true },
                },
            }, .{});
            defer std.heap.page_allocator.free(response);
            if (self.mode == .attach_server_request) {
                const malformed = try std.mem.concat(std.heap.page_allocator, u8, &.{ "{\"method\":\"account/read\",", response[1..] });
                defer std.heap.page_allocator.free(malformed);
                try text(fd, malformed);
            } else try text(fd, response);
        } else if (self.mode == .loaded_oversized) {
            // Count and individual raw ID bounds are valid, but the second
            // escaped page makes the real aggregate discovery result too large.
            for (0..2) |page| {
                const listing = try message(fd, &message_buffer);
                if (std.mem.indexOf(u8, listing, "\"method\":\"thread/loaded/list\"") == null) return error.FixtureUnexpectedRequest;
                var ids: [64][256]u8 = @splat(@splat('"'));
                var entries: [64][]const u8 = undefined;
                for (&ids, 0..) |*id, index| {
                    id[0] = @as(u8, '0') + @as(u8, @intCast(page));
                    id[1] = "0123456789abcdef"[index / 16];
                    id[2] = "0123456789abcdef"[index % 16];
                    entries[index] = id;
                }
                const response = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{ .id = @as(u64, @intCast(3 + page)), .result = .{ .data = entries[0..], .nextCursor = if (page == 0) @as(?[]const u8, "second-page") else null } }, .{});
                defer std.heap.page_allocator.free(response);
                try text(fd, response);
            }
        } else if (self.mode == .loaded) {
            const listing = try message(fd, &message_buffer);
            if (std.mem.indexOf(u8, listing, "\"method\":\"thread/loaded/list\"") == null) return error.FixtureUnexpectedRequest;
            if (self.empty_loaded) {
                try text(fd, "{\"id\":3,\"result\":{\"data\":[],\"nextCursor\":null}}");
                return;
            }
            if (self.cache_oversized_loaded) {
                var ids: [2][256]u8 = @splat(@splat('"'));
                ids[0][0] = 'a';
                ids[1][0] = 'b';
                const entries = [_][]const u8{ &ids[0], &ids[1] };
                const response = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{ .id = @as(u64, 3), .result = .{ .data = entries[0..], .nextCursor = @as(?[]const u8, null) } }, .{});
                defer std.heap.page_allocator.free(response);
                try text(fd, response);
                return;
            }
            try text(fd, "{\"id\":3,\"result\":{\"data\":[\"native-thread-one\",\"native-thread-two\"],\"nextCursor\":\"page-two\"}}");
            const continuation = try message(fd, &message_buffer);
            if (std.mem.indexOf(u8, continuation, "\"cursor\":\"page-two\"") == null) return error.FixtureUnexpectedRequest;
            try text(fd, "{\"id\":4,\"result\":{\"data\":[\"native-thread-three\"],\"nextCursor\":null}}");
        } else if (self.mode == .detach or self.mode == .detach_rejected or self.mode == .detach_ambiguous) {
            const removal = try message(fd, &message_buffer);
            if (std.mem.indexOf(u8, removal, "\"method\":\"omux/broker/unregister\"") == null or std.mem.indexOf(u8, removal, "existing-native-thread") == null or std.mem.indexOf(u8, removal, "\"releaseBinding\":false") == null) return error.FixtureUnexpectedRequest;
            if (self.mode == .detach_ambiguous) {
                try text(fd, "{\"id\":3,\"result\":{\"unregistered\":true},\"error\":{\"code\":-32602,\"message\":\"thread is not idle\"}}");
            } else if (self.mode == .detach_rejected) {
                try text(fd, "{\"id\":3,\"error\":{\"code\":-32602,\"message\":\"thread is not idle or contains account-bound context\"}}");
            } else try text(fd, "{\"id\":3,\"result\":{\"unregistered\":true}}");
        }
    }
};

test "native Codex inspection uses actual private Unix WebSocket without auth mutation" {
    const allocator = std.testing.allocator;
    // Native custody now has its own credential-aware protocol epoch. Retain
    // actual WebSocket discovery predicates here; test mutations separately.
    for ([_]@FieldType(NativeFixture, "mode"){ .stock, .hook, .loaded, .initialize_ambiguous, .initialize_version_oversized, .loaded_oversized }) |mode| {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var nonce: [12]u8 = undefined;
        try std.testing.io.randomSecure(&nonce);
        const root_path = try std.fmt.allocPrint(a, "{s}/omux-native-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
        const root_z = try a.dupeSentinel(u8, root_path, 0);
        if (posix.mkdir(root_z.ptr, 0o700) != 0) return error.FixtureDirectory;
        defer _ = posix.rmdir(root_z.ptr);
        const root_fd = try paths.openPrivateRoot(a, root_path, false);
        defer {
            _ = posix.unlinkat(root_fd, "advertised.sock", 0);
            _ = posix.unlinkat(root_fd, "native.sock", 0);
            _ = posix.close(root_fd);
        }
        const socket_path = try std.fmt.allocPrint(a, "{s}/native.sock", .{root_path});
        const fd = curl.socket(curl.AF_UNIX, curl.SOCK_STREAM, 0);
        if (fd < 0) return error.FixtureSocket;
        var fixture: NativeFixture = .{ .listener = fd, .mode = mode };
        defer fixture.deinit();
        var address = std.mem.zeroes(curl.struct_sockaddr_un);
        if (socket_path.len >= address.sun_path.len) return error.FixtureSocketPathTooLong;
        address.sun_family = curl.AF_UNIX;
        @memcpy(address.sun_path[0..socket_path.len], socket_path);
        if (@hasField(curl.struct_sockaddr_un, "sun_len")) address.sun_len = @intCast(@offsetOf(curl.struct_sockaddr_un, "sun_path") + socket_path.len + 1);
        if (curl.bind(fd, @ptrCast(&address), @intCast(@offsetOf(curl.struct_sockaddr_un, "sun_path") + socket_path.len + 1)) != 0) return error.FixtureBind;
        if (posix.fchmodat(root_fd, "native.sock", 0o600, 0) != 0) return error.FixturePermissions;
        const socket_z = try a.dupeSentinel(u8, socket_path, 0);
        if (posix.symlinkat(socket_z.ptr, root_fd, "advertised.sock") != 0) return error.FixtureSymlink;
        const advertised = try std.fmt.allocPrint(a, "{s}/advertised.sock", .{root_path});
        if (curl.listen(fd, 1) != 0) return error.FixtureListen;
        try fixture.start();
        if (mode == .initialize_ambiguous) {
            try std.testing.expectError(error.InvalidHandshake, inspect(std.testing.io, a, advertised, "fixture-omux"));
        } else if (mode == .initialize_version_oversized) {
            try std.testing.expectError(error.InvalidNativeVersion, inspect(std.testing.io, a, advertised, "fixture-omux"));
        } else if (mode == .loaded_oversized) {
            try std.testing.expectError(error.NativeResultTooLarge, loadedThreads(std.testing.io, a, advertised, "fixture-omux"));
        } else if (mode == .loaded) {
            const loaded = try loadedThreads(std.testing.io, a, advertised, "fixture-omux");
            try std.testing.expectEqual(codex.Support.compatible_hook, loaded.support);
            try std.testing.expectEqual(@as(usize, 3), loaded.thread_ids.len);
            try std.testing.expectEqualStrings("native-thread-three", loaded.thread_ids[2]);
            try std.testing.expectEqualStrings(socket_path, loaded.socket_path);
        } else {
            const info = try inspect(std.testing.io, a, advertised, "fixture-omux");
            try std.testing.expectEqual(if (mode == .stock) codex.Support.native_unsupported else codex.Support.compatible_hook, info.support);
            try std.testing.expectEqualStrings("fixture-native/1", info.native_version);
        }
        if (fixture.thread) |thread| {
            thread.join();
            fixture.thread = null;
        }
        try std.testing.expect(fixture.succeeded.load(.acquire));
    }
}
