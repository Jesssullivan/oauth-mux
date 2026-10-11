//! Shared synthetic native producer with genuine Linux socket/packet evidence.
//! No saved-witness constructor, actor ledger seeding or null-peer exemption.
const std = @import("std");
const posix = std.c;
const peer = @import("platform/peer.zig");
const native_owner = @import("native_owner.zig");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const probe = @import("integrations/native_probe.zig");
const paths = @import("paths.zig");
extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) posix.fd_t;
extern "c" fn socketpair(domain: c_int, kind: c_int, protocol: c_int, sockets: *[2]posix.fd_t) c_int;

pub const Method = enum { identify, register, unregister, announce, capabilities, threads, source_context };
pub const Mode = enum { normal, wrong_nonce, wrong_operation, wrong_owner, wrong_generation, numeric_generation, duplicate_keys, wrong_thread, false_success, protocol_v1, ambiguous_envelope, server_request, noncanonical_generation, identify_wrong_thread, oversized_packet, drop_reply, stock_capabilities, capabilities_extra, capabilities_missing, capabilities_nonboolean, native_version_oversized, threads_extra, threads_duplicate, threads_numeric_generation, threads_zero_generation, threads_oversized_packet, threads_identity_mismatch };
pub const Options = struct {
    source_context_mode: enum { available, rotated_context, unavailable, unavailable_nonnull, acquisition_true, acquisition_nonboolean, extra, missing, partial_null, unknown_status, wrong_owner, wrong_nonce, wrong_endpoint, wrong_context, wrong_context_generation, numeric_context_generation, duplicate_context } = .available,
    mode: Mode = .normal,
    owner_id: ?[32]u8 = null,
    process_nonce: ?[32]u8 = null,
    endpoint_generation: u64 = 1,
    thread_instance_generation: u64 = 1,
    announcement_engine: ?*engine_module.Engine = null,
};

/// Ordinary actor installation through the V2 read-only native hook, with no
/// fabricated installed ledger. The caller separately owns the producer.
pub const ActorFixture = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    producer: *Fixture,
    state: [:0]u8,
    home: [:0]u8,
    config: []u8,
    key: [32]u8,
    engine: ?*engine_module.Engine,

    pub fn create(io: std.Io, a: std.mem.Allocator, producer: *Fixture) !*ActorFixture {
        return createConfigured(io, a, producer, null);
    }

    pub fn createWithMeasuredRoot(io: std.Io, a: std.mem.Allocator, producer: *Fixture, root: []const u8) !*ActorFixture {
        return createConfigured(io, a, producer, root);
    }

    fn createConfigured(io: std.Io, a: std.mem.Allocator, producer: *Fixture, measured_root: ?[]const u8) !*ActorFixture {
        const state = try std.fmt.allocPrintSentinel(a, "{s}/state", .{producer.root}, 0);
        errdefer a.free(state);
        if (posix.mkdir(state.ptr, 0o700) != 0) return error.FixtureStateAlreadyExists;
        errdefer std.Io.Dir.cwd().deleteTree(io, state) catch {
            producer.failed.store(true, .release);
        };
        // R-N13: setup edits exactly the home containing this producer's
        // publication; the producer retains ownership of that directory.
        const home = try a.dupeSentinel(u8, producer.home, 0);
        errdefer a.free(home);
        const home_fd = try paths.openPrivateRoot(a, home, false);
        _ = posix.close(home_fd);
        const config = try std.fmt.allocPrint(a, "{s}/config.toml", .{home});
        errdefer a.free(config);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = config, .data = "# synthetic original native configuration\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        errdefer std.Io.Dir.cwd().deleteFile(io, config) catch {
            producer.failed.store(true, .release);
        };
        var key: [32]u8 = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        const engine = if (measured_root) |root| try engine_module.Engine.openWithMeasuredRootForTest(io, a, state, key, root) else try engine_module.Engine.openWithKey(io, a, state, key);
        errdefer engine.deinit();
        const self = try a.create(ActorFixture);
        self.* = .{ .io = io, .allocator = a, .producer = producer, .state = state, .home = home, .config = config, .key = key, .engine = engine };
        producer.setAnnouncementEngine(engine);
        return self;
    }

    pub fn install(self: *ActorFixture) !void {
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const engine = self.engine orelse return error.FixtureEngineUnavailable;
        const health = try engine.dispatch(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.health\",\"params\":null}", .control);
        const health_json = try std.json.parseFromSlice(std.json.Value, a, health, .{});
        const result = control.get(health_json.value, "result") orelse return error.FixtureHealthRefused;
        const revision = control.get(result, "revision") orelse return error.FixtureRevisionMissing;
        var random: [32]u8 = undefined;
        try self.io.randomSecure(&random);
        const operation = std.fmt.bytesToHex(random, .lower);
        const request = try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = 2, .method = "integrations.install", .params = .{
            .adapter = "codex",
            .operation_id = operation[0..],
            .expected_revision = revision,
            .config_path = self.config,
            .native_socket = self.producer.endpoint,
        } }, .{});
        const response = try self.producer.dispatch(engine, a, request, .control);
        const parsed = try std.json.parseFromSlice(std.json.Value, a, response, .{});
        if (control.get(parsed.value, "result") == null) return error.FixtureInstallationRefused;
        if (self.producer.methodCount(.register) != 0 or self.producer.methodCount(.announce) != 0) return error.FixtureDiscoveryCreatedOwner;
    }

    pub fn restart(self: *ActorFixture) !void {
        return self.restartConfigured(null);
    }

    pub fn restartWithMeasuredRoot(self: *ActorFixture, root: []const u8) !void {
        return self.restartConfigured(root);
    }

    fn restartConfigured(self: *ActorFixture, measured_root: ?[]const u8) !void {
        // A worker may retain a raw announcement callback pointer. Join it
        // while its original actor is alive, before freeing that actor.
        self.producer.pause();
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
        const engine = if (measured_root) |root| try engine_module.Engine.openWithMeasuredRootForTest(self.io, self.allocator, self.state, self.key, root) else try engine_module.Engine.openWithKey(self.io, self.allocator, self.state, self.key);
        self.engine = engine;
        if (self.producer.listener >= 0) try self.producer.resumeEndpoint(engine);
    }

    pub fn destroy(self: *ActorFixture) void {
        self.producer.pause();
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
        std.Io.Dir.cwd().deleteTree(self.io, self.state) catch {
            self.producer.failed.store(true, .release);
        };
        // The live publication remains producer-owned. Never delete its home
        // or endpoint as part of actor teardown/restart.
        std.Io.Dir.cwd().deleteFile(self.io, self.config) catch |err| switch (err) {
            error.FileNotFound => {},
            else => self.producer.failed.store(true, .release),
        };
        std.crypto.secureZero(u8, &self.key);
        const a = self.allocator;
        a.free(self.config);
        a.free(self.home);
        a.free(self.state);
        a.destroy(self);
    }
    pub fn deinit(self: *ActorFixture) void {
        self.destroy();
    }
};

pub fn referenceValue(a: std.mem.Allocator, reference: native_owner.NativeRef) !std.json.Value {
    var object: std.json.ObjectMap = .empty;
    const id = std.fmt.bytesToHex(reference.owner_id, .lower);
    try object.put(a, try a.dupe(u8, "owner_id"), .{ .string = try a.dupe(u8, &id) });
    inline for (.{ "adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation" }) |name| {
        try object.put(a, try a.dupe(u8, name), .{ .string = try std.fmt.allocPrint(a, "{d}", .{@field(reference, name)}) });
    }
    return .{ .object = object };
}

const Worker = struct {
    thread: ?std.Thread = null,
    fd: posix.fd_t = -1,
    done: std.atomic.Value(bool) = .init(true),
};

pub const Fixture = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    root: [:0]u8,
    home: [:0]u8,
    publication_directory: [:0]u8,
    endpoint: [:0]u8,
    owner_id: [32]u8,
    native_nonce: [32]u8,
    reference: native_owner.NativeRef,
    options: Options,
    listener: posix.fd_t,
    sender: posix.fd_t,
    receiver: posix.fd_t,
    packet_context: peer.Context,
    thread: ?std.Thread = null,
    workers: [8]Worker = @splat(.{}),
    stopping: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    mode_configuration: std.atomic.Value(u16) = .init(0xff00),
    announcement_engine: std.atomic.Value(usize) = .init(0),
    counts: [7]std.atomic.Value(usize) = @splat(.init(0)),
    mutex: std.Io.Mutex = .init,

    pub fn create(io: std.Io, allocator: std.mem.Allocator) !*Fixture {
        return createWithOptions(io, allocator, .{});
    }

    pub fn createWithOptions(io: std.Io, allocator: std.mem.Allocator, options: Options) !*Fixture {
        var random: [12]u8 = undefined;
        try io.randomSecure(&random);
        const root = try std.fmt.allocPrintSentinel(allocator, "/tmp/omux-owner-{s}", .{std.fmt.bytesToHex(random, .lower)}, 0);
        errdefer allocator.free(root);
        if (posix.mkdir(root.ptr, 0o700) != 0) return error.FixtureDirectoryFailed;
        errdefer _ = posix.rmdir(root.ptr);
        const home = try std.fmt.allocPrintSentinel(allocator, "{s}/home", .{root}, 0);
        errdefer allocator.free(home);
        if (posix.mkdir(home.ptr, 0o700) != 0) return error.FixtureHomeAlreadyExists;
        errdefer _ = posix.rmdir(home.ptr);
        var owner_id: [32]u8 = options.owner_id orelse undefined;
        var nonce: [32]u8 = options.process_nonce orelse undefined;
        if (options.owner_id == null) try io.randomSecure(&owner_id);
        if (options.process_nonce == null) try io.randomSecure(&nonce);
        // R-N13: real owner publication shape, correlated only as a hint;
        // every caller still needs the genuine kernel peer/protocol exchange.
        const publication_directory = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-owner-{s}", .{ home, std.fmt.bytesToHex(owner_id[0..8].*, .lower) }, 0);
        errdefer allocator.free(publication_directory);
        if (posix.mkdir(publication_directory.ptr, 0o700) != 0) return error.FixturePublicationFailed;
        errdefer _ = posix.rmdir(publication_directory.ptr);
        const endpoint = try std.fmt.allocPrintSentinel(allocator, "{s}/owner.sock", .{publication_directory}, 0);
        errdefer allocator.free(endpoint);
        const listener = socket(posix.AF.UNIX, posix.SOCK.SEQPACKET, 0);
        if (listener < 0) return error.FixtureSocketFailed;
        errdefer _ = posix.close(listener);
        try peer.Context.enable(listener);
        var address: posix.sockaddr.un = .{ .path = @splat(0) };
        if (endpoint.len >= address.path.len) return error.FixtureSocketPathTooLong;
        @memcpy(address.path[0..endpoint.len], endpoint);
        if (posix.bind(listener, @ptrCast(&address), @intCast(@offsetOf(posix.sockaddr.un, "path") + endpoint.len + 1)) != 0) return error.FixtureBindFailed;
        errdefer _ = posix.unlink(endpoint.ptr);
        if (posix.fchmodat(posix.AT.FDCWD, endpoint.ptr, 0o600, 0) != 0 or posix.listen(listener, 8) != 0) return error.FixtureListenFailed;
        var sockets: [2]posix.fd_t = undefined;
        if (socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET, 0, &sockets) != 0) return error.FixtureSocketFailed;
        errdefer {
            _ = posix.close(sockets[0]);
            _ = posix.close(sockets[1]);
        }
        try peer.Context.enable(sockets[1]);
        var packet_context = try peer.Context.capture(sockets[1], @intCast(posix.getuid()));
        errdefer packet_context.deinit();
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.* = .{ .io = io, .allocator = allocator, .root = root, .home = home, .publication_directory = publication_directory, .endpoint = endpoint, .owner_id = owner_id, .native_nonce = nonce, .reference = .{ .owner_id = owner_id, .adapter_epoch = 1, .endpoint_generation = options.endpoint_generation, .thread_instance_generation = options.thread_instance_generation, .attachment_generation = 1 }, .options = options, .listener = listener, .sender = sockets[0], .receiver = sockets[1], .packet_context = packet_context };
        try self.reference.validate();
        self.mode_configuration.store(0xff00 | @as(u16, @backingInt(options.mode)), .release);
        if (options.announcement_engine) |engine| self.announcement_engine.store(@intFromPtr(engine), .release);
        self.thread = try std.Thread.spawn(.{}, listenLoop, .{self});
        return self;
    }

    pub fn destroy(self: *Fixture) void {
        self.pause();
        self.packet_context.deinit();
        _ = posix.close(self.sender);
        _ = posix.close(self.receiver);
        if (self.listener >= 0) _ = posix.close(self.listener);
        _ = posix.unlink(self.endpoint.ptr);
        _ = posix.rmdir(self.publication_directory.ptr);
        _ = posix.rmdir(self.home.ptr);
        _ = posix.rmdir(self.root.ptr);
        const a = self.allocator;
        a.free(self.endpoint);
        a.free(self.publication_directory);
        a.free(self.home);
        a.free(self.root);
        a.destroy(self);
    }
    pub fn pause(self: *Fixture) void {
        self.announcement_engine.store(0, .release);
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
        for (&self.workers) |*worker| {
            if (worker.thread) |thread| {
                thread.join();
                worker.thread = null;
            }
        }
    }
    pub fn resumeEndpoint(self: *Fixture, engine: *engine_module.Engine) !void {
        if (self.listener < 0 or self.thread != null) return error.FixtureResumeInvalid;
        self.setAnnouncementEngine(engine);
        self.stopping.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, listenLoop, .{self});
    }
    pub fn deinit(self: *Fixture) void {
        self.destroy();
    }
    pub fn context(self: *const Fixture) *const peer.Context {
        return &self.packet_context;
    }
    pub fn methodCount(self: *const Fixture, method: Method) usize {
        return self.counts[@backingInt(method)].load(.acquire);
    }
    pub fn failure(self: *const Fixture) ?anyerror {
        return if (self.failed.load(.acquire)) error.NativeOwnerFixtureFailed else null;
    }
    pub fn setMode(self: *Fixture, mode: Mode) void {
        self.mode_configuration.store(0xff00 | @as(u16, @backingInt(mode)), .release);
    }
    pub fn setMethodMode(self: *Fixture, method: Method, mode: Mode) void {
        self.mode_configuration.store((@as(u16, @backingInt(method)) << 8) | @as(u16, @backingInt(mode)), .release);
    }
    pub fn setAnnouncementEngine(self: *Fixture, engine: *engine_module.Engine) void {
        self.announcement_engine.store(@intFromPtr(engine), .release);
    }
    pub fn stopEndpoint(self: *Fixture) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.listener >= 0) _ = posix.close(self.listener);
        self.listener = -1;
        _ = posix.unlink(self.endpoint.ptr);
    }

    /// Authenticate the bytes themselves before passing their context to the
    /// actor. Merely capturing a socket once would not prove their writer.
    pub fn dispatch(self: *Fixture, engine: *engine_module.Engine, a: std.mem.Allocator, payload: []const u8, channel: engine_module.Channel) anyerror![]u8 {
        if (payload.len == 0 or payload.len > peer.maximum_packet) return error.FixturePacketTooLarge;
        var buffer: [peer.maximum_packet]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        const length = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (posix.send(self.sender, payload.ptr, payload.len, posix.MSG.NOSIGNAL) != payload.len) return error.FixtureSendFailed;
            const received = try self.packet_context.receivePacket(&buffer);
            if (!std.mem.eql(u8, payload, buffer[0..received])) return error.FixturePacketMismatch;
            break :blk received;
        };
        // Release the transport lock before waiting on the actor: native
        // announce can produce a registration callback on another connection.
        return engine.dispatchWithPeer(a, buffer[0..length], channel, &self.packet_context);
    }

    pub fn register(self: *Fixture, engine: *engine_module.Engine, thread_id: []const u8) !native_owner.NativeRef {
        var random: [32]u8 = undefined;
        try self.io.randomSecure(&random);
        return self.registerOperation(engine, thread_id, std.fmt.bytesToHex(random, .lower));
    }

    pub fn registerOperation(self: *Fixture, engine: *engine_module.Engine, thread_id: []const u8, operation: native_owner.OperationId) !native_owner.NativeRef {
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var capability = try engine.capabilityForTest("codex");
        defer std.crypto.secureZero(u8, &capability);
        const owner_hex = std.fmt.bytesToHex(self.owner_id, .lower);
        const nonce_hex = std.fmt.bytesToHex(self.native_nonce, .lower);
        const request = try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = 1, .method = "adapter.owner.register", .params = .{
            .application = "codex",
            .capability = capability[0..],
            .operation_id = operation[0..],
            .owner_id = owner_hex[0..],
            .process_nonce = nonce_hex[0..],
            .owner_endpoint = self.endpoint,
            .thread_id = thread_id,
            .endpoint_generation = try std.fmt.allocPrint(a, "{d}", .{self.options.endpoint_generation}),
            .thread_instance_generation = try std.fmt.allocPrint(a, "{d}", .{self.options.thread_instance_generation}),
        } }, .{});
        defer std.crypto.secureZero(u8, request);
        const response = try self.dispatch(engine, a, request, .adapter);
        defer std.crypto.secureZero(u8, response);
        const parsed = try std.json.parseFromSlice(std.json.Value, a, response, .{});
        const result = control.get(parsed.value, "result") orelse {
            // Print only a matching static error name. Never serialize a
            // request, response, capability, identity or endpoint diagnostic.
            const registration_error = control.get(parsed.value, "error");
            const name = if (registration_error) |value| control.string(value, "message") catch "" else "";
            var diagnostic: []const u8 = "UnclassifiedNativeRegistrationError";
            for ([_][]const u8{
                "SocketPathTooLong",      "AdapterNotInstalled",   "NativeHookRequired",
                "NativePeerRequired",     "NativeOwnerMismatch",   "NativeRemovalPending",
                "NativeCustodyPending",   "InvalidNativeOwnerAck", "InvalidNativeOwnerThread",
                "InvalidNativeOperation", "InvalidParams",         "Unauthorized",
                "WrongPurpose",           "UnsafePrivatePath",     "UnsafePathPermissions",
                "PathOpenFailed",         "PeerConnectionClosed",  "PeerProcessGone",
                "PeerWriterRequired",     "SnapshotTooLarge",      "RecordLimit",
                "NativeWorkCapacity",     "Timeout",
            }) |known| if (std.mem.eql(u8, name, known)) {
                diagnostic = known;
                break;
            };
            std.debug.print("fixture native owner registration failed: {s}\n", .{diagnostic});
            return error.FixtureRegistrationRefused;
        };
        const wire = control.get(result, "native_ref") orelse return error.FixtureNativeRefMissing;
        var owner: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&owner, try control.string(wire, "owner_id"));
        var reference: native_owner.NativeRef = .{ .owner_id = owner, .adapter_epoch = 0, .endpoint_generation = 0, .thread_instance_generation = 0, .attachment_generation = 0 };
        inline for (.{ "adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation" }) |name| @field(reference, name) = try std.fmt.parseInt(u64, try control.string(wire, name), 10);
        try reference.validate();
        if (!std.mem.eql(u8, &reference.owner_id, &self.owner_id)) return error.FixtureNativeRefMismatch;
        return reference;
    }

    fn ready(fd: posix.fd_t, events: i16) bool {
        var descriptors = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        return posix.poll(&descriptors, 1, 100) > 0 and descriptors[0].revents & (events | posix.POLL.HUP) != 0;
    }
    fn listenLoop(self: *Fixture) void {
        while (!self.stopping.load(.acquire)) {
            if (!ready(self.listener, posix.POLL.IN)) continue;
            const fd = posix.accept(self.listener, null, null);
            if (fd < 0) {
                self.failed.store(true, .release);
                return;
            }
            var admitted = false;
            for (&self.workers, 0..) |*worker, index| {
                if (!worker.done.load(.acquire)) continue;
                if (worker.thread) |old| old.join();
                worker.thread = null;
                worker.fd = fd;
                worker.done.store(false, .release);
                worker.thread = std.Thread.spawn(.{}, serve, .{ self, index, fd }) catch {
                    worker.done.store(true, .release);
                    self.failed.store(true, .release);
                    break;
                };
                admitted = true;
                break;
            }
            if (!admitted) {
                _ = posix.close(fd);
                self.failed.store(true, .release);
            }
        }
    }
    fn serve(self: *Fixture, index: usize, fd: posix.fd_t) void {
        defer self.workers[index].done.store(true, .release);
        defer _ = posix.close(fd);
        serveOwned(self, fd) catch {
            self.failed.store(true, .release);
        };
    }
    fn serveOwned(self: *Fixture, fd: posix.fd_t) anyerror!void {
        try peer.Context.enable(fd);
        var accepted_peer = try peer.Context.capture(fd, @intCast(posix.getuid()));
        defer accepted_peer.deinit();
        var buffer: [peer.maximum_packet]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        while (!self.stopping.load(.acquire)) {
            if (!ready(fd, posix.POLL.IN)) continue;
            const length = accepted_peer.receivePacket(&buffer) catch |err| switch (err) {
                error.PeerConnectionClosed => return,
                error.WouldBlock, error.Interrupted => continue,
                else => return err,
            };
            var arena: std.heap.ArenaAllocator = .init(self.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            const parsed = try std.json.parseFromSlice(std.json.Value, a, buffer[0..length], .{ .duplicate_field_behavior = .@"error" });
            const response = self.answer(a, parsed.value) catch |err| switch (err) {
                error.FixtureResponseDropped => return,
                else => return err,
            };
            if (posix.send(fd, response.ptr, response.len, posix.MSG.NOSIGNAL) != response.len) return error.FixtureSendFailed;
        }
    }

    fn answer(self: *Fixture, a: std.mem.Allocator, request: std.json.Value) anyerror![]u8 {
        if (request != .object or request.object.count() != 4 or !std.mem.eql(u8, try control.string(request, "jsonrpc"), "2.0")) return error.FixtureEnvelopeInvalid;
        const method = try control.string(request, "method");
        const params = control.get(request, "params") orelse return error.FixtureParamsMissing;
        const id = try control.string(request, "id");
        if (std.mem.eql(u8, method, "owner/source/context")) return self.answerSourceContext(a, id, params);
        if (std.mem.eql(u8, method, "owner/capabilities") or std.mem.eql(u8, method, "owner/threads")) return self.answerReadOnly(a, method, id, params);
        const thread_id = try control.string(params, "threadId");
        const identified = std.mem.eql(u8, method, "owner/identify");
        const detached = std.mem.eql(u8, method, "owner/unregister");
        const announced = std.mem.eql(u8, method, "owner/announce");
        const action: Method = if (identified) .identify else if (detached) .unregister else if (announced) .announce else if (std.mem.eql(u8, method, "owner/register")) .register else return error.FixtureMethodUnknown;
        if (id.len != 64) return error.FixtureOperationInvalid;
        var operation_id: native_owner.OperationId = undefined;
        @memcpy(&operation_id, id);
        try native_owner.validateOperation(operation_id);
        const keys: []const []const u8 = switch (action) {
            .identify => &.{ "protocolVersion", "threadId" },
            .register => &.{ "protocolVersion", "ownerId", "processNonce", "adapterEpoch", "endpointGeneration", "threadInstanceGeneration", "attachmentGeneration", "threadId", "operationId", "brokerSocket", "capabilityPath" },
            .unregister => &.{ "protocolVersion", "ownerId", "processNonce", "adapterEpoch", "endpointGeneration", "threadInstanceGeneration", "attachmentGeneration", "threadId", "operationId" },
            .announce => &.{ "protocolVersion", "threadId", "operationId", "brokerSocket", "capabilityPath" },
            .capabilities, .threads, .source_context => unreachable, // Handled by the read-only branch above.
        };
        if (params != .object or params.object.count() != keys.len) return error.FixtureParamsInvalid;
        for (keys) |name| if (!params.object.contains(name)) return error.FixtureParamsInvalid;
        const version = control.get(params, "protocolVersion").?;
        if (version != .integer or version.integer != probe.owner_protocol_version) return error.FixtureProtocolInvalid;
        if (thread_id.len == 0 or thread_id.len > native_owner.maximum_thread_bytes or !std.unicode.utf8ValidateSlice(thread_id)) return error.FixtureThreadInvalid;
        if (!identified and !std.mem.eql(u8, try control.string(params, "operationId"), id)) return error.FixtureOperationInvalid;
        if (action == .register or announced) {
            try paths.validateAbsolute(try control.string(params, "brokerSocket"));
            try paths.validateAbsolute(try control.string(params, "capabilityPath"));
        }
        _ = self.counts[@backingInt(action)].fetchAdd(1, .acq_rel);
        self.mutex.lockUncancelable(self.io);
        var reference = self.reference;
        self.mutex.unlock(self.io);
        if (!identified and !announced) {
            reference = try probe.decodeOwnerReference(params);
            const nonce_hex = std.fmt.bytesToHex(self.native_nonce, .lower);
            if (!std.mem.eql(u8, &reference.owner_id, &self.owner_id) or reference.endpoint_generation != self.options.endpoint_generation or reference.thread_instance_generation != self.options.thread_instance_generation or !std.mem.eql(u8, try control.string(params, "processNonce"), &nonce_hex)) return error.FixtureReferenceMismatch;
        }
        const producer = self.announcement_engine.load(.acquire);
        if (announced and producer != 0) {
            const engine: *engine_module.Engine = @ptrFromInt(producer);
            var operation: native_owner.OperationId = undefined;
            if (id.len != operation.len) return error.FixtureOperationInvalid;
            @memcpy(&operation, id);
            reference = try self.registerOperation(engine, thread_id, operation);
        }
        if (!identified) {
            self.mutex.lockUncancelable(self.io);
            self.reference = reference;
            self.mutex.unlock(self.io);
        }
        var result: std.json.ObjectMap = .empty;
        const configuration = self.mode_configuration.load(.acquire);
        const target = configuration >> 8;
        const mode: Mode = if (target == 255 or target == @backingInt(action)) @fromBackingInt(@intCast(configuration & 0xff)) else .normal;
        if (!identified and mode == .drop_reply) return error.FixtureResponseDropped;
        if (!identified and mode == .oversized_packet) {
            const too_large = try a.alloc(u8, peer.maximum_packet + 1);
            @memset(too_large, 'x');
            return too_large;
        }
        var owner = reference.owner_id;
        var nonce = self.native_nonce;
        if (!identified and mode == .wrong_owner) owner[0] ^= 1;
        if (!identified and mode == .wrong_nonce) nonce[0] ^= 1;
        const owner_hex = std.fmt.bytesToHex(owner, .lower);
        const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
        try result.put(a, "protocolVersion", .{ .integer = if (!identified and mode == .protocol_v1) 1 else 2 });
        try result.put(a, "ownerId", .{ .string = try a.dupe(u8, &owner_hex) });
        try result.put(a, "processNonce", .{ .string = try a.dupe(u8, &nonce_hex) });
        try result.put(a, "endpointGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{reference.endpoint_generation}) });
        try result.put(a, "threadInstanceGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{reference.thread_instance_generation}) });
        try result.put(a, "threadId", .{ .string = if ((!identified and mode == .wrong_thread) or (identified and mode == .identify_wrong_thread)) "fixture-wrong-thread" else thread_id });
        if (!identified) {
            try result.put(a, "adapterEpoch", .{ .string = try std.fmt.allocPrint(a, "{d}", .{reference.adapter_epoch}) });
            try result.put(a, "attachmentGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{reference.attachment_generation + @as(u64, @intFromBool(mode == .wrong_generation))}) });
            const operation = try a.dupe(u8, id);
            if (mode == .wrong_operation and operation.len != 0) operation[0] = if (operation[0] == 'a') 'b' else 'a';
            try result.put(a, "operationId", .{ .string = operation });
            try result.put(a, if (detached) "unregistered" else "registered", .{ .bool = mode != .false_success });
            if (mode == .numeric_generation) try result.put(a, "adapterEpoch", .{ .integer = 1 });
            if (mode == .noncanonical_generation) try result.put(a, "adapterEpoch", .{ .string = "01" });
        }
        var root: std.json.ObjectMap = .empty;
        try root.put(a, "jsonrpc", .{ .string = "2.0" });
        try root.put(a, "id", .{ .string = id });
        try root.put(a, "result", .{ .object = result });
        if (!identified and mode == .ambiguous_envelope) try root.put(a, "error", .{ .object = .empty });
        if (!identified and mode == .server_request) try root.put(a, "method", .{ .string = "fixture/server-request" });
        const encoded = try std.json.Stringify.valueAlloc(a, std.json.Value{ .object = root }, .{});
        if (!identified and mode == .duplicate_keys) return std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"id\":\"{s}\",\"result\":{s},\"result\":{s}}}", .{ id, try std.json.Stringify.valueAlloc(a, std.json.Value{ .object = result }, .{}), try std.json.Stringify.valueAlloc(a, std.json.Value{ .object = result }, .{}) });
        return encoded;
    }

    fn answerSourceContext(self: *Fixture, a: std.mem.Allocator, id: []const u8, params: std.json.Value) ![]u8 {
        if (id.len != 64 or params != .object or params.object.count() != 4) return error.FixtureParamsInvalid;
        var operation: native_owner.OperationId = undefined;
        @memcpy(&operation, id);
        try native_owner.validateOperation(operation);
        for ([_][]const u8{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration" }) |key| if (!params.object.contains(key)) return error.FixtureParamsInvalid;
        const version = params.object.get("protocolVersion").?;
        const owner_hex = std.fmt.bytesToHex(self.owner_id, .lower);
        const nonce_hex = std.fmt.bytesToHex(self.native_nonce, .lower);
        if (version != .integer or version.integer != 2 or !std.mem.eql(u8, try control.string(params, "ownerId"), &owner_hex) or
            !std.mem.eql(u8, try control.string(params, "processNonce"), &nonce_hex) or try probe.parseOwnerGeneration(params.object.get("endpointGeneration").?) != self.options.endpoint_generation) return error.FixtureParamsInvalid;
        _ = self.counts[@backingInt(Method.source_context)].fetchAdd(1, .acq_rel);
        const mode = self.options.source_context_mode;
        var result: std.json.ObjectMap = .empty;
        try result.put(a, "protocolVersion", .{ .integer = 2 });
        try result.put(a, "ownerId", .{ .string = if (mode == .wrong_owner) "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" else try a.dupe(u8, &owner_hex) });
        try result.put(a, "processNonce", .{ .string = if (mode == .wrong_nonce) "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" else try a.dupe(u8, &nonce_hex) });
        try result.put(a, "endpointGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{self.options.endpoint_generation + @as(u64, if (mode == .wrong_endpoint) 1 else 0)}) });
        try result.put(a, "status", .{ .string = if (mode == .unavailable or mode == .unavailable_nonnull) "unavailable" else if (mode == .unknown_status) "ready" else "available" });
        try result.put(a, "sourceContextId", if (mode == .unavailable or mode == .partial_null) .null else .{ .string = if ((mode == .wrong_context or mode == .rotated_context)) "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" else "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
        try result.put(a, "sourceContextGeneration", if (mode == .unavailable) .null else if (mode == .numeric_context_generation) .{ .integer = 1 } else .{ .string = if ((mode == .wrong_context_generation or mode == .rotated_context)) "2" else "1" });
        try result.put(a, "storePresent", if (mode == .unavailable) .null else .{ .bool = false });
        try result.put(a, "credentialAcquisitionAuthorized", if (mode == .acquisition_nonboolean) .{ .integer = 0 } else .{ .bool = mode == .acquisition_true });
        if (mode == .extra) try result.put(a, "authPath", .{ .string = "/synthetic/forbidden" });
        if (mode == .missing) _ = result.swapRemove("storePresent");
        const encoded = try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = id, .result = std.json.Value{ .object = result } }, .{});
        if (mode == .duplicate_context) {
            const needle = "\"sourceContextId\":";
            const at = std.mem.indexOf(u8, encoded, needle) orelse return error.FixtureParamsInvalid;
            return std.fmt.allocPrint(a, "{s}\"sourceContextId\":null,{s}", .{ encoded[0..at], encoded[at..] });
        }
        return encoded;
    }

    fn answerReadOnly(self: *Fixture, a: std.mem.Allocator, method: []const u8, id: []const u8, params: std.json.Value) ![]u8 {
        if (id.len != 64 or params != .object or params.object.count() != 1) return error.FixtureParamsInvalid;
        var operation: native_owner.OperationId = undefined;
        @memcpy(&operation, id);
        try native_owner.validateOperation(operation);
        const version = control.get(params, "protocolVersion") orelse return error.FixtureParamsInvalid;
        if (version != .integer or version.integer != 2) return error.FixtureProtocolInvalid;
        const capabilities = std.mem.eql(u8, method, "owner/capabilities");
        const action: Method = if (capabilities) .capabilities else .threads;
        _ = self.counts[@backingInt(action)].fetchAdd(1, .acq_rel);
        const configuration = self.mode_configuration.load(.acquire);
        const target = configuration >> 8;
        const mode: Mode = if (target == 255 or target == @backingInt(action)) @fromBackingInt(@intCast(configuration & 0xff)) else .normal;
        if (!capabilities and mode == .threads_oversized_packet) {
            const packet = try a.alloc(u8, peer.maximum_packet + 1);
            @memset(packet, 'x');
            return packet;
        }
        var owner = self.owner_id;
        if (!capabilities and mode == .threads_identity_mismatch) owner[0] ^= 1;
        const owner_hex = std.fmt.bytesToHex(owner, .lower);
        const nonce_hex = std.fmt.bytesToHex(self.native_nonce, .lower);
        var result: std.json.ObjectMap = .empty;
        try result.put(a, "protocolVersion", .{ .integer = 2 });
        try result.put(a, "ownerId", .{ .string = try a.dupe(u8, &owner_hex) });
        try result.put(a, "processNonce", .{ .string = try a.dupe(u8, &nonce_hex) });
        try result.put(a, "endpointGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{self.options.endpoint_generation}) });
        if (capabilities) {
            var hook: std.json.ObjectMap = .empty;
            try hook.put(a, "protocol_version", .{ .integer = 1 });
            for ([_][]const u8{ "late_thread_binding", "per_request_auth", "exclusive_refresh_owner", "preacceptance_failure", "account_transport_invalidation", "native_context_reconstruction" }) |name| try hook.put(a, name, .{ .bool = mode != .stock_capabilities });
            if (mode == .capabilities_missing) _ = hook.swapRemove("late_thread_binding");
            if (mode == .capabilities_extra) try hook.put(a, "unexpected", .{ .bool = true });
            if (mode == .capabilities_nonboolean) try hook.put(a, "late_thread_binding", .{ .integer = 1 });
            const native_version: []const u8 = if (mode == .native_version_oversized) blk: {
                const large = try a.alloc(u8, 257);
                @memset(large, 'v');
                break :blk large;
            } else "fixture-owner-v2";
            try result.put(a, "nativeVersion", .{ .string = native_version });
            try result.put(a, "capabilities", .{ .object = hook });
        } else {
            var row: std.json.ObjectMap = .empty;
            try row.put(a, "threadId", .{ .string = "fixture-thread" });
            try row.put(a, "threadInstanceGeneration", .{ .string = try std.fmt.allocPrint(a, "{d}", .{self.options.thread_instance_generation}) });
            try row.put(a, "attachmentGeneration", .{ .string = "1" });
            if (mode == .threads_numeric_generation) try row.put(a, "threadInstanceGeneration", .{ .integer = 1 });
            if (mode == .threads_zero_generation) try row.put(a, "threadInstanceGeneration", .{ .string = "0" });
            // The caller's per-packet arena owns this managed JSON array and
            // its row maps through serialization, then releases them together.
            var rows: std.json.Array = .init(a);
            try rows.append(.{ .object = row });
            if (mode == .threads_duplicate) try rows.append(.{ .object = row });
            try result.put(a, "threads", .{ .array = rows });
            if (mode == .threads_extra) try result.put(a, "unexpected", .{ .bool = true });
        }
        return std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = id, .result = std.json.Value{ .object = result } }, .{});
    }
};
