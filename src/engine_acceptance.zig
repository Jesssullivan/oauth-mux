//! Synthetic actor acceptance proof, with SQLite and encrypted grant custody.
//! These tests never open a personal vault, contact a provider, or run Codex.
//! They prove request-bound routing predicates, not a live seamless-handoff
//! claim. Provider identity and grant bytes are generated inside each test.
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const file_metadata = @import("platform/file_metadata.zig");
const owner_fixture = @import("native_owner_fixture.zig");
const native_owner = @import("native_owner.zig");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const domain = @import("domain.zig");
const storage = @import("storage.zig");
const reliability = @import("reliability.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;

const PrivateDirectory = struct {
    dir: std.Io.Dir,
    path: [:0]u8,

    fn cleanup(self: *PrivateDirectory) void {
        // Refuse cleanup if the original exclusive root was renamed/replaced,
        // or if any path component became an alias. Never sweep other roots.
        const current_fd = paths.openPrivateRoot(allocator, self.path, false) catch @panic("Fixture root custody changed");
        defer _ = std.c.close(current_fd);
        const original = file_metadata.statFd(self.dir.handle) catch @panic("Fixture root identity unavailable");
        const current = file_metadata.statFd(current_fd) catch @panic("Fixture root identity unavailable");
        if (original.dev != current.dev or original.ino != current.ino) @panic("Fixture root identity changed");
        std.Io.Dir.cwd().deleteTree(io, self.path) catch @panic("Fixture root cleanup failed");
        self.dir.close(io);
        allocator.free(self.path);
        self.* = undefined;
    }
};

fn privateDirectory() !PrivateDirectory {
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const root = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-accept-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) }, 0);
    errdefer allocator.free(root);
    if (std.c.mkdir(root.ptr, 0o700) != 0) return error.FixtureDirectoryCreationFailed;
    errdefer _ = std.c.rmdir(root.ptr);
    const fd = try paths.openPrivateRoot(allocator, root, false);
    // Native registration also constructs the real broker socket path. A short
    // state root satisfies its unchanged AF_UNIX bound under long Bazel paths.
    return .{ .dir = .{ .handle = fd }, .path = root };
}

const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    method: []const u8,

    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }

    fn result(self: *const Reply) !std.json.Value {
        if (self.parsed.value != .object) return error.InvalidReply;
        if (self.parsed.value.object.get("result")) |value| return value;
        if (self.parsed.value.object.get("error")) |failure| {
            const name = control.string(failure, "message") catch "InvalidRpcError";
            var canonical = name.len <= 128;
            for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
                canonical = false;
            };
            std.debug.print("actor RPC {s} failed: {s}\n", .{ self.method, if (canonical) name else "NoncanonicalRpcError" });
        }
        return error.UnexpectedRpcFailure;
    }

    fn expectError(self: *const Reply, expected: []const u8) !void {
        try std.testing.expect(self.parsed.value == .object);
        try std.testing.expect(!self.parsed.value.object.contains("result"));
        const failure = self.parsed.value.object.get("error") orelse return error.MissingRpcError;
        try std.testing.expectEqualStrings(expected, try control.string(failure, "message"));
    }

    fn expectFailure(self: *const Reply) !void {
        try std.testing.expect(self.parsed.value == .object);
        try std.testing.expect(self.parsed.value.object.contains("error"));
        try std.testing.expect(!self.parsed.value.object.contains("result"));
    }
};

// One explicit harness per test. Every retained reference was returned by actual
// registration; reopening an actor does not register or reactivate an owner.
var active_owners: ?*OwnerHarness = null;
const OwnerHarness = struct {
    const Owner = struct {
        path: []u8,
        session: []u8,
        producer: *owner_fixture.Fixture,
        reference: native_owner.NativeRef,
        closed: bool = false,
        handles: std.ArrayList([]u8) = .empty,
    };
    rows: std.ArrayList(Owner) = .empty,

    fn activate(self: *OwnerHarness) void {
        std.debug.assert(active_owners == null);
        active_owners = self;
    }
    fn deinit(self: *OwnerHarness) void {
        for (self.rows.items) |*row| {
            row.producer.destroy();
            for (row.handles.items) |handle| allocator.free(handle);
            row.handles.deinit(allocator);
            allocator.free(row.path);
            allocator.free(row.session);
        }
        self.rows.deinit(allocator);
        active_owners = null;
    }
    fn findSession(self: *OwnerHarness, engine: *engine_module.Engine, session: []const u8) ?*Owner {
        for (self.rows.items) |*row| if (std.mem.eql(u8, row.path, engine.state_dir) and std.mem.eql(u8, row.session, session)) return row;
        return null;
    }
    fn prepare(self: *OwnerHarness, engine: *engine_module.Engine, session: []const u8) !void {
        if (self.findSession(engine, session) != null) return;
        for (self.rows.items) |row| if (std.mem.eql(u8, row.path, engine.state_dir) and row.closed) return error.FixtureOwnerReactivationForbidden;
        if (self.rows.items.len == 32) return error.FixtureOwnerLimit;
        const producer = try owner_fixture.Fixture.create(io, allocator);
        errdefer producer.destroy();
        const reference = try producer.register(engine, session);
        const path = try allocator.dupe(u8, engine.state_dir);
        errdefer allocator.free(path);
        const owned_session = try allocator.dupe(u8, session);
        errdefer allocator.free(owned_session);
        try self.rows.append(allocator, .{ .path = path, .session = owned_session, .producer = producer, .reference = reference });
    }
    fn select(self: *OwnerHarness, engine: *engine_module.Engine, params: std.json.Value) !*Owner {
        if (try control.optionalString(params, "session_id")) |session| return self.findSession(engine, session) orelse error.FixtureOwnerNotRegistered;
        const handle = (try control.optionalString(params, "lease_handle")) orelse (try control.optionalString(params, "expected_lease_handle")) orelse return error.FixtureOwnerScopeMissing;
        for (self.rows.items) |*row| if (std.mem.eql(u8, row.path, engine.state_dir)) {
            for (row.handles.items) |retained| if (std.mem.eql(u8, retained, handle)) return row;
        };
        return error.FixtureOwnerHandleUnknown;
    }
    fn remember(self: *OwnerHarness, engine: *engine_module.Engine, session: []const u8, handle: []const u8) !void {
        const row = self.findSession(engine, session) orelse return error.FixtureOwnerNotRegistered;
        const copy = try allocator.dupe(u8, handle);
        errdefer allocator.free(copy);
        try row.handles.append(allocator, copy);
    }
    fn closeEngine(self: *OwnerHarness, engine: *engine_module.Engine) void {
        for (self.rows.items) |*row| if (std.mem.eql(u8, row.path, engine.state_dir)) {
            row.producer.pause();
            row.closed = true;
        };
        engine.deinit();
    }
};

fn rpc(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) anyerror!Reply {
    // Zig's empty tuple serializes as an array; omitted method parameters are
    // JSON null, not an array, under the real control protocol.
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const initial_request = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = 1,
        .method = method,
        .params = normalized,
    }, .{});
    defer {
        std.crypto.secureZero(u8, initial_request);
        allocator.free(initial_request);
    }
    var enriched = try std.json.parseFromSlice(std.json.Value, allocator, initial_request, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(enriched.value);
        enriched.deinit();
    }
    var operation_id: ?[]u8 = null;
    defer if (operation_id) |value| allocator.free(value);
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const target = enriched.value.object.getPtr("params").?;
        if (target.* == .null) target.* = .{ .object = .empty };
        if (!target.object.contains("operation_id")) {
            operation_id = try generatedValue();
            try target.object.put(enriched.arena.allocator(), try enriched.arena.allocator().dupe(u8, "operation_id"), .{ .string = try enriched.arena.allocator().dupe(u8, operation_id.?[10..74]) });
        }
        if (!target.object.contains("expected_revision")) {
            var snapshot = try rpc(engine, .control, "state.snapshot", .{});
            defer snapshot.deinit();
            const revision = control.get(try snapshot.result(), "revision") orelse return error.InvalidReply;
            try target.object.put(enriched.arena.allocator(), try enriched.arena.allocator().dupe(u8, "expected_revision"), revision);
        }
    }
    var native: ?*owner_fixture.Fixture = null;
    if (channel == .adapter) {
        const target = enriched.value.object.getPtr("params").?;
        if (target.* == .object and std.mem.eql(u8, (try control.optionalString(target.*, "application")) orelse "", "codex")) {
            const row = try (active_owners orelse return error.FixtureOwnerHarnessMissing).select(engine, target.*);
            try target.object.put(enriched.arena.allocator(), try enriched.arena.allocator().dupe(u8, "native_ref"), try owner_fixture.referenceValue(enriched.arena.allocator(), row.reference));
            native = row.producer;
        }
    }
    const request = try std.json.Stringify.valueAlloc(allocator, enriched.value, .{});
    defer {
        std.crypto.secureZero(u8, request);
        allocator.free(request);
    }
    const bytes = if (native) |producer| try producer.dispatch(engine, allocator, request, channel) else try engine.dispatch(allocator, request, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{
        .bytes = bytes,
        .method = method,
        .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }),
    };
}

fn success(engine: *engine_module.Engine, channel: engine_module.Channel, method: []const u8, params: anytype) !void {
    var reply = try rpc(engine, channel, method, params);
    defer reply.deinit();
    _ = try reply.result();
}

fn generatedValue() ![]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    const hexadecimal = std.fmt.bytesToHex(random, .lower);
    return std.fmt.allocPrint(allocator, "synthetic-{s}", .{hexadecimal});
}

fn expectPrivateEqual(expected: []const u8, actual: []const u8) !void {
    // Even generated credentials do not belong in failed assertion output.
    try std.testing.expect(std.mem.eql(u8, expected, actual));
}

fn connect(engine: *engine_module.Engine, provider: []const u8) ![]u8 {
    var reply = try rpc(engine, .control, "source.connect", .{ .kind = "explicit", .provider = provider, .label = "synthetic source" });
    defer reply.deinit();
    return allocator.dupe(u8, try control.string(try reply.result(), "source_id"));
}

const Enrolled = struct {
    account_id: []u8,
    grant_id: []u8,

    fn deinit(self: *Enrolled) void {
        allocator.free(self.account_id);
        allocator.free(self.grant_id);
    }
};

fn enroll(engine: *engine_module.Engine, source_id: []const u8, provider: []const u8, subject: []const u8, token: []const u8, provider_account_id: ?[]const u8) !Enrolled {
    return enrollWithUsername(engine, source_id, provider, subject, token, provider_account_id, null);
}

fn enrollWithUsername(engine: *engine_module.Engine, source_id: []const u8, provider: []const u8, subject: []const u8, token: []const u8, provider_account_id: ?[]const u8, username: ?[]const u8) !Enrolled {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = capability[0..],
        .source_id = source_id,
        .provider = provider,
        .subject = subject,
        .label = "synthetic account",
        .access_token = token,
        .provider_account_id = provider_account_id,
        .username = username,
        .audience = if (std.mem.eql(u8, provider, "codex")) "https://chatgpt.com" else "https://github.com",
    });
    defer reply.deinit();
    const result = try reply.result();
    const account_id = try allocator.dupe(u8, try control.string(result, "account_id"));
    errdefer allocator.free(account_id);
    return .{
        .account_id = account_id,
        .grant_id = try allocator.dupe(u8, try control.string(result, "grant_id")),
    };
}

fn generatedUsername() ![]u8 {
    var bytes: [12]u8 = undefined;
    try io.randomSecure(&bytes);
    defer std.crypto.secureZero(u8, &bytes);
    const hexadecimal = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "u-{s}", .{hexadecimal});
}

fn gitGet(engine: *engine_module.Engine, path: []const u8, username: ?[]const u8) !Reply {
    const capability = try engine.capabilityForTest("git");
    return rpc(engine, .adapter, "adapter.gitGet", .{
        .application = "git",
        .capability = capability[0..],
        .request = .{ .protocol = "https", .host = "github.com", .path = path, .username = username },
    });
}

fn gitErase(engine: *engine_module.Engine, path: []const u8, username: []const u8, password: ?[]const u8) !void {
    const capability = try engine.capabilityForTest("git");
    try success(engine, .adapter, "adapter.gitErase", .{
        .application = "git",
        .capability = capability[0..],
        .request = .{ .protocol = "https", .host = "github.com", .path = path, .username = username, .password = password },
    });
}

const Acquisition = struct {
    handle: []u8,
    account_id: []u8,
    route_generation: i64,

    fn deinit(self: *Acquisition) void {
        allocator.free(self.handle);
        allocator.free(self.account_id);
    }
};

const model_a: domain.Resource = .{ .kind = "model", .target = "fixture-model-a", .unit = .tokens };

const HeldImport = struct {
    operation_id: []u8,
    generation: i64,

    fn deinit(self: *HeldImport) void {
        allocator.free(self.operation_id);
    }
};

fn holdImport(engine: *engine_module.Engine, source_id: []const u8, token: []const u8, reenroll: bool) !HeldImport {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importStart", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .provider = "github", .access_token = token, .allow_reenrollment = reenroll });
    defer reply.deinit();
    const result = try reply.result();
    return .{ .operation_id = try allocator.dupe(u8, try control.string(result, "operation_id")), .generation = control.get(result, "generation").?.integer };
}

fn reconcileHeldImport(engine: *engine_module.Engine, source_id: []const u8) !?HeldImport {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importReconcile", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id });
    defer reply.deinit();
    const result = try reply.result();
    if (control.get(result, "operation_id").? == .null) return null;
    return .{ .operation_id = try allocator.dupe(u8, try control.string(result, "operation_id")), .generation = control.get(result, "generation").?.integer };
}

fn completeImport(engine: *engine_module.Engine, source_id: []const u8, held: HeldImport, response: []const u8, expected_error: ?[]const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, .adapter, "fixture.importComplete", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .generation = held.generation, .response = response });
    defer reply.deinit();
    const result = try reply.result();
    try std.testing.expectEqual(expected_error == null, try control.boolean(result, "admitted", false));
    if (expected_error) |name| try std.testing.expectEqualStrings(name, try control.string(result, "reason"));
}

fn importSourceTransition(engine: *engine_module.Engine, source_id: []const u8, transition: []const u8) !void {
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.importSource", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .transition = transition });
}

fn generatedIdentityResponse() ![]u8 {
    var bytes: [8]u8 = undefined;
    try io.randomSecure(&bytes);
    const subject = std.mem.readInt(u64, &bytes, .little) | 1;
    const username = try generatedUsername();
    defer allocator.free(username);
    return std.json.Stringify.valueAlloc(allocator, .{ .id = subject, .login = username, .type = "User" }, .{});
}

fn firstImportedAccount(engine: *engine_module.Engine) ![]u8 {
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const accounts = control.get(try snapshot.result(), "accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    return allocator.dupe(u8, try control.string(accounts[0], "id"));
}

test "async import cannot use pre-forget re-enrollment authority to erase a new tombstone" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(37));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "github");
    defer allocator.free(source_id);
    const token = try generatedValue();
    defer allocator.free(token);
    const response = try generatedIdentityResponse();
    defer allocator.free(response);
    var initial = try holdImport(engine, source_id, token, false);
    defer initial.deinit();
    try completeImport(engine, source_id, initial, response, null);
    const account_id = try firstImportedAccount(engine);
    defer allocator.free(account_id);
    var pending = try holdImport(engine, source_id, token, true);
    defer pending.deinit();
    try success(engine, .control, "account.forget", .{ .account_id = account_id });
    try completeImport(engine, source_id, pending, response, "ImportSuperseded");
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 0), control.get(try snapshot.result(), "accounts").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), control.get(try snapshot.result(), "grants").?.array.items.len);
    owners.closeEngine(engine);
    engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(37));
    var automatic = try holdImport(engine, source_id, token, false);
    defer automatic.deinit();
    try completeImport(engine, source_id, automatic, response, "IdentityNotAdmitted");
    var authorized = try holdImport(engine, source_id, token, true);
    defer authorized.deinit();
    try completeImport(engine, source_id, authorized, response, null);
    const restored = try firstImportedAccount(engine);
    defer allocator.free(restored);
}

test "async source ABA rejects old completion without failing a newer job or deleting detached grants" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    for ([_][]const u8{ "detach", "disconnect" }) |transition| {
        var directory = try privateDirectory();
        defer directory.cleanup();
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(38));
        defer owners.closeEngine(engine);
        const source_id = try connect(engine, "github");
        defer allocator.free(source_id);
        const token = try generatedValue();
        defer allocator.free(token);
        const response = try generatedIdentityResponse();
        defer allocator.free(response);
        var initial = try holdImport(engine, source_id, token, false);
        defer initial.deinit();
        try completeImport(engine, source_id, initial, response, null);
        var old = try holdImport(engine, source_id, token, false);
        defer old.deinit();
        if (std.mem.eql(u8, transition, "disconnect")) try success(engine, .control, "source.disconnect", .{ .source_id = source_id }) else try importSourceTransition(engine, source_id, transition);
        if (std.mem.eql(u8, transition, "detach")) {
            var detached = try rpc(engine, .control, "state.snapshot", .{});
            defer detached.deinit();
            const grants = control.get(try detached.result(), "grants").?.array.items;
            try std.testing.expectEqual(@as(usize, 1), grants.len);
            try std.testing.expectEqualStrings("ready", try control.string(grants[0], "status"));
        }
        try importSourceTransition(engine, source_id, "connect");
        var fresh = try holdImport(engine, source_id, token, false);
        defer fresh.deinit();
        try std.testing.expect(fresh.generation > old.generation);
        try completeImport(engine, source_id, old, response, "ImportSuperseded");
        var snapshot = try rpc(engine, .control, "state.snapshot", .{});
        defer snapshot.deinit();
        const jobs = control.get(try snapshot.result(), "jobs").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), jobs.len);
        try std.testing.expectEqual(fresh.generation, control.get(jobs[0], "operation_generation").?.integer);
        try std.testing.expectEqualStrings("running", try control.string(jobs[0], "status"));
        try completeImport(engine, source_id, fresh, response, null);
    }
}

test "async import refuses terminal or cancelled durable job authority" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    for ([_][]const u8{ "completed", "failed", "pending" }) |status| {
        var directory = try privateDirectory();
        defer directory.cleanup();
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(39));
        defer owners.closeEngine(engine);
        const source_id = try connect(engine, "github");
        defer allocator.free(source_id);
        const token = try generatedValue();
        defer allocator.free(token);
        const response = try generatedIdentityResponse();
        defer allocator.free(response);
        var pending = try holdImport(engine, source_id, token, false);
        defer pending.deinit();
        var issued = try rpc(engine, .control, "operation.cancel", .{ .target_operation_id = pending.operation_id });
        defer issued.deinit();
        try issued.expectError("AlreadyIssued");
        const capability = try engine.capabilityForTest("enrollment");
        try success(engine, .adapter, "fixture.importJob", .{ .application = "enrollment", .capability = capability[0..], .target_operation_id = pending.operation_id, .status = status });
        if (std.mem.eql(u8, status, "pending")) try success(engine, .control, "operation.cancel", .{ .target_operation_id = pending.operation_id });
        try completeImport(engine, source_id, pending, response, "ImportSuperseded");
        var snapshot = try rpc(engine, .control, "state.snapshot", .{});
        defer snapshot.deinit();
        try std.testing.expectEqual(@as(usize, 0), control.get(try snapshot.result(), "accounts").?.array.items.len);
        try std.testing.expectEqual(@as(usize, 0), control.get(try snapshot.result(), "grants").?.array.items.len);
    }
}

test "async import rechecks source provider and custody deadlines at completion" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    for ([_][]const u8{ "source", "provider", "custody" }) |kind| {
        var directory = try privateDirectory();
        defer directory.cleanup();
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(40));
        defer owners.closeEngine(engine);
        const source_id = try connect(engine, "github");
        defer allocator.free(source_id);
        const token = try generatedValue();
        defer allocator.free(token);
        const response = try generatedIdentityResponse();
        defer allocator.free(response);
        var pending = try holdImport(engine, source_id, token, false);
        defer pending.deinit();
        if (std.mem.eql(u8, kind, "source")) {
            try importSourceTransition(engine, source_id, "expire");
        } else {
            const capability = try engine.capabilityForTest("enrollment");
            try success(engine, .adapter, "fixture.importExpire", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .kind = kind });
        }
        try completeImport(engine, source_id, pending, response, if (std.mem.eql(u8, kind, "source")) "SourceUnauthorized" else if (std.mem.eql(u8, kind, "provider")) "ExpiredCredential" else "InvalidCustodyLease");
    }
}

test "actor scheduled maintenance prunes expired custody while a continuous queue backlog remains" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(41));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "github");
    defer allocator.free(source_id);
    const token = try generatedValue();
    defer allocator.free(token);
    const subject = try generatedValue();
    defer allocator.free(subject);
    var account = try enroll(engine, source_id, "github", subject, token, null);
    defer account.deinit();
    const capability = try engine.capabilityForTest("enrollment");
    const first = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "fixture.maintenanceBusy", .params = .{ .application = "enrollment", .capability = capability[0..], .grant_id = account.grant_id, .expire = true } }, .{});
    defer allocator.free(first);
    const busy = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 2, .method = "fixture.maintenanceBusy", .params = .{ .application = "enrollment", .capability = capability[0..], .grant_id = account.grant_id, .expire = false } }, .{});
    defer allocator.free(busy);
    try std.testing.expect(try engine.maintenanceBacklogForTest(allocator, first, busy));
    // Completion of the fixture batch leaves committed redacted metadata. The
    // receipt above additionally required the actual encrypted row to be gone
    // while queued work was still waiting, so an idle-only sweep cannot pass.
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const grants = control.get(try snapshot.result(), "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualStrings("invalid", try control.string(grants[0], "status"));
}

test "native source reappearance refreshes borrowed metadata before held identity admission" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const credential_path = try std.fmt.allocPrint(allocator, "{s}/native-account.json", .{path});
    defer allocator.free(credential_path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(42));
    defer owners.closeEngine(engine);
    const source_label = "reappearing authorized native source";
    var connected = try rpc(engine, .control, "source.connect", .{ .kind = "native_store", .provider = "github", .label = source_label, .source_path = credential_path });
    defer connected.deinit();
    const source_id = try allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
    defer allocator.free(source_id);
    try std.testing.expect((try reconcileHeldImport(engine, source_id)) == null);
    var detached = try rpc(engine, .control, "state.snapshot", .{});
    defer detached.deinit();
    const detached_sources = control.get(try detached.result(), "sources").?.array.items;
    try std.testing.expectEqualStrings("detached", try control.string(detached_sources[0], "status"));
    const token = try generatedValue();
    defer allocator.free(token);
    const document = try std.json.Stringify.valueAlloc(allocator, .{ .access_token = token }, .{});
    defer {
        std.crypto.secureZero(u8, document);
        allocator.free(document);
    }
    try directory.dir.writeFile(io, .{ .sub_path = "native-account.json", .data = document });
    if (std.c.fchmodat(directory.dir.handle, "native-account.json", 0o600, 0) != 0) return error.PermissionChangeFailed;
    var pending = (try reconcileHeldImport(engine, source_id)) orelse return error.MissingImport;
    defer pending.deinit();
    const response = try generatedIdentityResponse();
    defer allocator.free(response);
    try completeImport(engine, source_id, pending, response, null);
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const result = try snapshot.result();
    const sources = control.get(result, "sources").?.array.items;
    const accounts = control.get(result, "accounts").?.array.items;
    const grants = control.get(result, "grants").?.array.items;
    try std.testing.expectEqualStrings("connected", try control.string(sources[0], "status"));
    try std.testing.expectEqualStrings("github", try control.string(sources[0], "provider"));
    try std.testing.expectEqualStrings(source_label, try control.string(sources[0], "label"));
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqualStrings(source_label, try control.string(accounts[0], "label"));
    try std.testing.expectEqualStrings(source_id, try control.string(grants[0], "source_id"));
    try std.testing.expect((try reconcileHeldImport(engine, source_id)) == null);
}

test "completed enrollment job and retained custody survive a later cancellation intent" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(43));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "github");
    defer allocator.free(source_id);
    const token = try generatedValue();
    defer allocator.free(token);
    const response = try generatedIdentityResponse();
    defer allocator.free(response);
    var held = try holdImport(engine, source_id, token, false);
    defer held.deinit();
    try completeImport(engine, source_id, held, response, null);
    var cancellation = try rpc(engine, .control, "operation.cancel", .{ .target_operation_id = held.operation_id });
    defer cancellation.deinit();
    try cancellation.expectError("AlreadyCompleted");
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const result = try snapshot.result();
    const jobs = control.get(result, "jobs").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), jobs.len);
    try std.testing.expectEqualStrings("completed", try control.string(jobs[0], "status"));
    try std.testing.expectEqual(held.generation, control.get(jobs[0], "operation_generation").?.integer);
    const grants = control.get(result, "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualStrings("ready", try control.string(grants[0], "status"));
    // Import generation/custody survives; the retained account is still usable
    // through the actual Git adapter, not merely present in a metadata view.
    const identity = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer identity.deinit();
    var credential = try gitGet(engine, "fixture/cancellation.git", try control.string(identity.value, "login"));
    defer credential.deinit();
    try expectPrivateEqual(token, try control.string(try credential.result(), "password"));
}

test "installed Codex removal uses sealed original endpoints and fences a missing owner ACK" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    const installation = try owner_fixture.Fixture.create(io, allocator);
    defer installation.destroy();
    const actor = try owner_fixture.ActorFixture.create(io, allocator, installation);
    defer {
        for (owners.rows.items) |row| row.producer.pause();
        actor.deinit();
    }
    try actor.install();
    const engine = actor.engine.?;
    const source_id = try connect(engine, "codex");
    defer allocator.free(source_id);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    var account = try enroll(engine, source_id, "codex", subject, token, null);
    defer account.deinit();
    for ([_][]const u8{ "native-thread-one", "endpoint-b-native-thread" }) |thread| {
        var request = try acquire(engine, thread, thread, model_a);
        defer request.deinit();
        try report(engine, request.handle, "accepted");
        try report(engine, request.handle, "completed");
    }
    const second_owner = owners.findSession(engine, "endpoint-b-native-thread").?;
    const retained_ref = second_owner.reference;
    second_owner.producer.setMethodMode(.unregister, .wrong_operation);
    const capability_before = try engine.capabilityForTest("codex");
    const config_before = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(128 * 1024));
    defer allocator.free(config_before);
    const capability_path = try std.fmt.allocPrint(allocator, "{s}/integrations/codex.capability", .{actor.state});
    defer allocator.free(capability_path);
    const capability_file_before = try std.Io.Dir.cwd().readFileAlloc(io, capability_path, allocator, .limited(1024));
    defer {
        std.crypto.secureZero(u8, capability_file_before);
        allocator.free(capability_file_before);
    }
    // Discovery's endpoint cannot replace either sealed registration witness.
    var removal = try rpc(engine, .control, "integrations.remove", .{ .adapter = "codex", .config_path = actor.config, .native_socket = installation.endpoint });
    defer removal.deinit();
    try removal.expectFailure();
    try std.testing.expectEqual(@as(usize, 0), installation.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 1), owners.findSession(engine, "native-thread-one").?.producer.methodCount(.unregister));
    try std.testing.expectEqual(@as(usize, 1), second_owner.producer.methodCount(.unregister));
    const unresolved = engine.native_owners.lookupAttachment(retained_ref).?;
    try std.testing.expectEqual(native_owner.AttachmentPhase.unresolved, unresolved.phase);
    try std.testing.expectEqual(native_owner.UnresolvedFrom.detachment, unresolved.unresolved_from);
    var after = try rpc(engine, .control, "state.snapshot", .{});
    defer after.deinit();
    const bindings = control.get(try after.result(), "bindings").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), bindings.len);
    try std.testing.expectEqualStrings("endpoint-b-native-thread", try control.string(bindings[0], "session_id"));
    const grants = control.get(try after.result(), "grants").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualStrings("ready", try control.string(grants[0], "status"));
    const capability_after = try engine.capabilityForTest("codex");
    try expectPrivateEqual(&capability_before, &capability_after);
    const config_after = try std.Io.Dir.cwd().readFileAlloc(io, actor.config, allocator, .limited(128 * 1024));
    defer allocator.free(config_after);
    try expectPrivateEqual(config_before, config_after);
    const capability_file_after = try std.Io.Dir.cwd().readFileAlloc(io, capability_path, allocator, .limited(1024));
    defer {
        std.crypto.secureZero(u8, capability_file_after);
        allocator.free(capability_file_after);
    }
    try expectPrivateEqual(capability_file_before, capability_file_after);
    var continued = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability_after[0..], .session_id = "endpoint-b-native-thread", .request_id = "after-refused-removal", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer continued.deinit();
    try continued.expectError("NativeRemovalPending");
}

const model_b: domain.Resource = .{ .kind = "model", .target = "fixture-model-b", .unit = .tokens };

fn acquire(engine: *engine_module.Engine, session_id: []const u8, request_id: []const u8, resource: domain.Resource) !Acquisition {
    try (active_owners orelse return error.FixtureOwnerHarnessMissing).prepare(engine, session_id);
    const capability = try engine.capabilityForTest("codex");
    var reply = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = session_id,
        .request_id = request_id,
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .purpose = "request", .resource = resource, .required = 1 },
    });
    defer reply.deinit();
    const result = try reply.result();
    const handle = try allocator.dupe(u8, try control.string(result, "lease_handle"));
    errdefer allocator.free(handle);
    const generation = control.get(result, "route_generation") orelse return error.InvalidReply;
    if (generation != .integer) return error.InvalidReply;
    try active_owners.?.remember(engine, session_id, handle);
    return .{
        .handle = handle,
        .account_id = try allocator.dupe(u8, try control.string(result, "account_id")),
        .route_generation = generation.integer,
    };
}

fn materialization(engine: *engine_module.Engine, handle: []const u8) !Reply {
    const capability = try engine.capabilityForTest("codex");
    return rpc(engine, .adapter, "adapter.materialize", .{ .application = "codex", .capability = capability[0..], .lease_handle = handle });
}

fn report(engine: *engine_module.Engine, handle: []const u8, event: []const u8) !void {
    const capability = try engine.capabilityForTest("codex");
    try success(engine, .adapter, "adapter.report", .{ .application = "codex", .capability = capability[0..], .lease_handle = handle, .event = event });
}

fn reject(engine: *engine_module.Engine, handle: []const u8, response_started: bool) !Reply {
    const capability = try engine.capabilityForTest("codex");
    return rpc(engine, .adapter, "adapter.report", .{
        .application = "codex",
        .capability = capability[0..],
        .lease_handle = handle,
        .event = "rejected",
        .status = 429,
        .pre_acceptance = true,
        .response_started = response_started,
    });
}

fn assertRedacted(engine: *engine_module.Engine, secret_values: []const []const u8) !void {
    for ([_][]const u8{ "state.snapshot", "accounts.list", "sources.list", "usage.summary", "events.watch" }) |method| {
        var snapshot = try rpc(engine, .control, method, .{});
        defer snapshot.deinit();
        _ = try snapshot.result();
        for (secret_values) |secret| try std.testing.expect(std.mem.indexOf(u8, snapshot.bytes, secret) == null);
        for ([_][]const u8{ "access_token", "refresh_token", "provider_account_id", "\"subject\"", "password", "cookie_header" }) |key| {
            try std.testing.expect(std.mem.indexOf(u8, snapshot.bytes, key) == null);
        }
    }
}

fn assertCiphertextFiles(directory: []const u8, secret_values: []const []const u8) !void {
    for ([_][]const u8{ "state.sqlite", "state.sqlite-wal", "state.sqlite-journal" }) |filename| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ directory, filename });
        defer allocator.free(path);
        const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer allocator.free(content);
        for (secret_values) |secret| try std.testing.expect(std.mem.indexOf(u8, content, secret) == null);
    }
}

fn assertCustodyState(directory: []const u8, key: [32]u8, removed: []const Enrolled, ready: []const Enrolled, tombstoned_account: ?[]const u8) !void {
    // The daemon must be closed before this helper. The real SQLite store
    // enforces a single owner thread and does not allow a second writer.
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{directory}, 0);
    defer allocator.free(path);
    const key_id = try storage.Store.readRootId(allocator, path);
    defer allocator.free(key_id);
    var store = try storage.Store.openRoot(io, allocator, path, key_id, key);
    defer store.close();
    for (removed) |grant| try std.testing.expect(try store.readGrantStatus(grant.account_id, grant.grant_id) == null);
    for (ready) |grant| {
        const status = (try store.readGrantStatus(grant.account_id, grant.grant_id)) orelse return error.MissingRetainedGrant;
        try std.testing.expect(status.state == .ready);
    }
    if (tombstoned_account) |account_id| try std.testing.expect(try store.isTombstoned(account_id));
}

fn assertRepairState(engine: *engine_module.Engine, account_id: []const u8, expected_status: []const u8) !void {
    var before = try rpc(engine, .control, "state.snapshot", .{});
    defer before.deinit();
    const before_result = try before.result();
    try std.testing.expect(try control.boolean(before_result, "custody_available", false));
    const before_jobs = control.get(before_result, "jobs") orelse return error.InvalidReply;
    try std.testing.expect(before_jobs == .array);
    var repair = try rpc(engine, .control, "repair.start", .{ .account_id = account_id });
    defer repair.deinit();
    const result = try repair.result();
    try std.testing.expectEqualStrings(expected_status, try control.string(result, "status"));
    const operation = control.get(result, "operation_id") orelse return error.InvalidReply;
    try std.testing.expect(operation == .null);
    var after = try rpc(engine, .control, "state.snapshot", .{});
    defer after.deinit();
    const after_result = try after.result();
    try std.testing.expect(try control.boolean(after_result, "custody_available", false));
    const after_jobs = control.get(after_result, "jobs") orelse return error.InvalidReply;
    try std.testing.expect(after_jobs == .array and after_jobs.array.items.len == before_jobs.array.items.len);
}

test "durable request authority fences accepted and unreported work and acknowledges reports after restart" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(117));
    defer owners.closeEngine(engine);
    const source = try connect(engine, "codex");
    defer allocator.free(source);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    var account = try enroll(engine, source, "codex", subject, token, null);
    defer account.deinit();
    var accepted = try acquire(engine, "preserved-native-thread", "accepted-request", model_a);
    defer accepted.deinit();
    try report(engine, accepted.handle, "accepted");
    try report(engine, accepted.handle, "completed");
    const expiration_capability = try engine.capabilityForTest("codex");
    try success(engine, .adapter, "fixture.expireLease", .{ .application = "codex", .capability = expiration_capability[0..], .lease_handle = accepted.handle });
    try report(engine, accepted.handle, "accepted");
    try report(engine, accepted.handle, "completed");
    var ongoing = try acquire(engine, "preserved-native-thread", "ongoing-accepted-request", model_a);
    defer ongoing.deinit();
    try report(engine, ongoing.handle, "accepted");
    var uncertain = try acquire(engine, "preserved-native-thread", "unreported-request", model_a);
    defer uncertain.deinit();
    const capability = try engine.capabilityForTest("codex");
    for ([_][]const u8{ "accepted-request", "unreported-request" }) |request_id| {
        var refused = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "preserved-native-thread", .request_id = request_id, .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
        defer refused.deinit();
        try refused.expectError("AttemptBudgetExhausted");
    }
    var changed = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "preserved-native-thread", .request_id = "unreported-request", .binding_id = "changed-binding", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer changed.deinit();
    try changed.expectError("RequestMismatch");
    owners.closeEngine(engine);
    engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(117));
    try report(engine, accepted.handle, "accepted");
    try report(engine, accepted.handle, "completed");
    var forget_running = try rpc(engine, .control, "account.forget", .{ .account_id = account.account_id });
    defer forget_running.deinit();
    try forget_running.expectError("InFlight");
    try report(engine, ongoing.handle, "accepted");
    try report(engine, ongoing.handle, "completed");
    var reopened = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "preserved-native-thread", .request_id = "unreported-request", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer reopened.deinit();
    try reopened.expectError("NativeRemovalPending");
    var rejection = try reject(engine, uncertain.handle, false);
    defer rejection.deinit();
    try rejection.expectError("UnsafeReplay");
    try report(engine, uncertain.handle, "abandoned");
    try report(engine, uncertain.handle, "abandoned");
    var old_head = try rpc(engine, .adapter, "adapter.releaseBinding", .{ .application = "codex", .capability = capability[0..], .session_id = "preserved-native-thread", .expected_lease_handle = accepted.handle });
    defer old_head.deinit();
    try old_head.expectError("BindingChanged");
    try success(engine, .adapter, "adapter.releaseBinding", .{ .application = "codex", .capability = capability[0..], .session_id = "preserved-native-thread", .expected_lease_handle = uncertain.handle });
    try success(engine, .control, "account.forget", .{ .account_id = account.account_id });
}

test "durable mutation replay keeps original result across changed correlation revision and restart" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(118));
    defer owners.closeEngine(engine);
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const revision = control.get(try snapshot.result(), "revision").?.integer;
    const intent = .{ .operation_id = "connect-reply-lost", .expected_revision = revision, .kind = "explicit", .provider = "codex", .label = "synthetic source" };
    var original = try rpc(engine, .control, "source.connect", intent);
    defer original.deinit();
    const source_id = try allocator.dupe(u8, try control.string(try original.result(), "source_id"));
    defer allocator.free(source_id);
    try success(engine, .control, "policy.set", .{ .warm_alternatives = false });
    owners.closeEngine(engine);
    engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(118));
    var replay = try rpc(engine, .control, "source.connect", intent);
    defer replay.deinit();
    try std.testing.expectEqualStrings(source_id, try control.string(try replay.result(), "source_id"));
    var status = try rpc(engine, .control, "operation.status", .{ .operation_id = "connect-reply-lost" });
    defer status.deinit();
    try std.testing.expectEqualStrings("completed", try control.string(try status.result(), "status"));
    var conflicting = try rpc(engine, .control, "source.connect", .{ .operation_id = "connect-reply-lost", .expected_revision = revision, .kind = "explicit", .provider = "github" });
    defer conflicting.deinit();
    try conflicting.expectError("OperationIdConflict");
    var after = try rpc(engine, .control, "state.snapshot", .{});
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 1), control.get(try after.result(), "sources").?.array.items.len);
    const current_revision = control.get(try after.result(), "revision").?.integer;
    for ([_][]const u8{ "system.health", "reliability.export", "sources.catalog", "accounts.list", "sources.list" }) |method| {
        var local = try rpc(engine, .control, method, .{});
        defer local.deinit();
        _ = try local.result();
    }
    var final = try rpc(engine, .control, "state.snapshot", .{});
    defer final.deinit();
    try std.testing.expectEqual(current_revision, control.get(try final.result(), "revision").?.integer);
}

test "safe preacceptance alternate is bounded before restart and unresolved ownership never resumes" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(119));
    defer owners.closeEngine(engine);
    const source = try connect(engine, "codex");
    defer allocator.free(source);
    for (0..3) |_| {
        const subject = try generatedValue();
        defer allocator.free(subject);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        var account = try enroll(engine, source, "codex", subject, token, null);
        account.deinit();
    }
    var first = try acquire(engine, "same-native-thread", "bounded-request", model_a);
    defer first.deinit();
    var rejected = try reject(engine, first.handle, false);
    defer rejected.deinit();
    _ = try rejected.result();
    const capability = try engine.capabilityForTest("codex");
    try success(engine, .adapter, "fixture.expireLease", .{ .application = "codex", .capability = capability[0..], .lease_handle = first.handle });
    var exact = try reject(engine, first.handle, false);
    defer exact.deinit();
    _ = try exact.result();
    var mismatch = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "same-native-thread", .request_id = "bounded-request", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_b } });
    defer mismatch.deinit();
    try mismatch.expectError("RequestMismatch");
    var alternate = try acquire(engine, "same-native-thread", "bounded-request", model_a);
    defer alternate.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.account_id, alternate.account_id));
    var alternate_rejected = try reject(engine, alternate.handle, false);
    defer alternate_rejected.deinit();
    _ = try alternate_rejected.result();
    var exhausted = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "same-native-thread", .request_id = "bounded-request", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer exhausted.deinit();
    try exhausted.expectError("AttemptBudgetExhausted");
    const enrollment_capability = try engine.capabilityForTest("enrollment");
    for (0..2) |_| {
        owners.closeEngine(engine);
        engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(119));
        var before = try rpc(engine, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = enrollment_capability[0..] });
        defer before.deinit();
        var held = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "same-native-thread", .request_id = "bounded-request", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
        defer held.deinit();
        try held.expectError("NativeRemovalPending");
        var after = try rpc(engine, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = enrollment_capability[0..] });
        defer after.deinit();
        for ([_][]const u8{ "exact_snapshot_bytes", "reserved_bytes", "credits_bytes", "credit_count", "remaining_bytes" }) |field| {
            const prior = control.get(try before.result(), field).?.integer;
            try std.testing.expectEqual(prior, control.get(try after.result(), field).?.integer);
        }
        var duplicate = try reject(engine, alternate.handle, false);
        defer duplicate.deinit();
        _ = try duplicate.result();
    }
}

test "retained recovery authority refuses missing database before selecting new custody" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(120));
    owners.closeEngine(engine);
    try directory.dir.deleteFile(io, "state.sqlite");
    try std.testing.expectError(error.RecoveryDatabaseMissing, engine_module.Engine.openWithKey(io, allocator, path, @splat(121)));
}

test "expired issued and accepted capabilities retain native lifecycle fences until explicit terminal evidence" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(122));
    defer owners.closeEngine(engine);
    const source = try connect(engine, "codex");
    defer allocator.free(source);
    for (0..2) |_| {
        const subject = try generatedValue();
        defer allocator.free(subject);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        var account = try enroll(engine, source, "codex", subject, token, null);
        account.deinit();
    }
    var issued = try acquire(engine, "native-expiry-thread", "unreported-before-expiry", model_a);
    defer issued.deinit();
    const capability = try engine.capabilityForTest("codex");
    try success(engine, .adapter, "fixture.expireLease", .{ .application = "codex", .capability = capability[0..], .lease_handle = issued.handle });
    var expired_material = try materialization(engine, issued.handle);
    defer expired_material.deinit();
    try expired_material.expectError("LeaseExpired");
    var issued_forget = try rpc(engine, .control, "account.forget", .{ .account_id = issued.account_id });
    defer issued_forget.deinit();
    try issued_forget.expectError("InFlight");
    try success(engine, .control, "account.pause", .{ .account_id = issued.account_id });
    var unsafe_route = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "native-expiry-thread", .request_id = "route-change-before-terminal", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer unsafe_route.deinit();
    try unsafe_route.expectError("InFlight");
    try report(engine, issued.handle, "abandoned");
    var accepted = try acquire(engine, "native-expiry-thread", "accepted-before-expiry", model_a);
    defer accepted.deinit();
    try report(engine, accepted.handle, "accepted");
    try success(engine, .adapter, "fixture.expireLease", .{ .application = "codex", .capability = capability[0..], .lease_handle = accepted.handle });
    var accepted_forget = try rpc(engine, .control, "account.forget", .{ .account_id = accepted.account_id });
    defer accepted_forget.deinit();
    try accepted_forget.expectError("InFlight");
    try report(engine, accepted.handle, "completed");
    try success(engine, .control, "account.forget", .{ .account_id = accepted.account_id });
}

test "disconnect and custody pruning preserve accepted lease metadata and restart completion authority" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    for ([_]bool{ false, true }) |prune_custody| {
        var directory = try privateDirectory();
        defer directory.cleanup();
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        var engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(123));
        defer owners.closeEngine(engine);
        const source = try connect(engine, "codex");
        defer allocator.free(source);
        const subject = try generatedValue();
        defer allocator.free(subject);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        var account = try enroll(engine, source, "codex", subject, token, null);
        defer account.deinit();
        var accepted = try acquire(engine, "native-custody-thread", "accepted-before-custody-end", model_a);
        defer accepted.deinit();
        try report(engine, accepted.handle, "accepted");
        if (prune_custody) {
            const capability = try engine.capabilityForTest("codex");
            try success(engine, .adapter, "fixture.expireGrant", .{ .application = "codex", .capability = capability[0..], .lease_handle = accepted.handle });
        } else try success(engine, .control, "source.disconnect", .{ .source_id = source });
        owners.closeEngine(engine);
        engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(123));
        var pending = try rpc(engine, .control, "account.forget", .{ .account_id = account.account_id });
        defer pending.deinit();
        try pending.expectError("InFlight");
        try report(engine, accepted.handle, "completed");
        try report(engine, accepted.handle, "completed");
        try success(engine, .control, "account.forget", .{ .account_id = account.account_id });
    }
}

test "adapter and enrollment capabilities isolate same-key installations and remain stable across own restart" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var first_directory = try privateDirectory();
    defer first_directory.cleanup();
    var second_directory = try privateDirectory();
    defer second_directory.cleanup();
    const first_path = try first_directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(first_path);
    const second_path = try second_directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(second_path);
    var first = try engine_module.Engine.openWithKey(io, allocator, first_path, @splat(124));
    defer owners.closeEngine(first);
    const second = try engine_module.Engine.openWithKey(io, allocator, second_path, @splat(124));
    defer owners.closeEngine(second);
    var first_native = try first.capabilityForTest("codex");
    defer std.crypto.secureZero(u8, &first_native);
    var second_native = try second.capabilityForTest("codex");
    defer std.crypto.secureZero(u8, &second_native);
    try std.testing.expect(!std.mem.eql(u8, &first_native, &second_native));
    try owners.prepare(first, "native-installation-thread");
    try owners.prepare(second, "native-installation-thread");
    var cross_native = try rpc(second, .adapter, "adapter.metadata", .{ .application = "codex", .capability = first_native[0..], .session_id = "native-installation-thread" });
    defer cross_native.deinit();
    try cross_native.expectError("Unauthorized");
    var first_enrollment = try first.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &first_enrollment);
    var second_enrollment = try second.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &second_enrollment);
    try std.testing.expect(!std.mem.eql(u8, &first_enrollment, &second_enrollment));
    var cross_enrollment = try rpc(second, .adapter, "fixture.enroll", .{ .application = "enrollment", .capability = first_enrollment[0..] });
    defer cross_enrollment.deinit();
    try cross_enrollment.expectError("Unauthorized");
    try success(second, .adapter, "adapter.metadata", .{ .application = "codex", .capability = second_native[0..], .session_id = "native-installation-thread" });
    owners.closeEngine(first);
    first = try engine_module.Engine.openWithKey(io, allocator, first_path, @splat(124));
    var restarted = try first.capabilityForTest("codex");
    defer std.crypto.secureZero(u8, &restarted);
    try std.testing.expect(std.mem.eql(u8, &first_native, &restarted));
    try success(first, .adapter, "adapter.metadata", .{ .application = "codex", .capability = first_native[0..], .session_id = "native-installation-thread" });
}

test "SQLite writer failure never exposes an uncommitted completed operation cache" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(125));
    defer owners.closeEngine(engine);
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const revision = control.get(try snapshot.result(), "revision").?.integer;
    const capability = try engine.capabilityForTest("enrollment");
    try success(engine, .adapter, "fixture.storageReadOnly", .{ .application = "enrollment", .capability = capability[0..] });
    var mutation = try rpc(engine, .control, "policy.set", .{ .operation_id = "write-failure-fixture", .expected_revision = revision, .warm_alternatives = false });
    defer mutation.deinit();
    try mutation.expectFailure();
    var status = try rpc(engine, .control, "operation.status", .{ .operation_id = "write-failure-fixture" });
    defer status.deinit();
    try status.expectError("CustodyUnavailable");
    var health = try rpc(engine, .control, "system.health", .{});
    defer health.deinit();
    try std.testing.expect(!try control.boolean(try health.result(), "custody_available", true));
}

test "actor fixture retries one preacceptance rejection, preserves its session and scopes quota to resource" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: [32]u8 = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
    defer owners.closeEngine(engine);

    const source_id = try connect(engine, "codex");
    defer allocator.free(source_id);
    const first_subject = try generatedValue();
    defer allocator.free(first_subject);
    const second_subject = try generatedValue();
    defer allocator.free(second_subject);
    const first_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, first_token);
        allocator.free(first_token);
    }
    const second_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, second_token);
        allocator.free(second_token);
    }
    const provider_account_id = try generatedValue();
    defer allocator.free(provider_account_id);
    var first_account = try enroll(engine, source_id, "codex", first_subject, first_token, provider_account_id);
    defer first_account.deinit();
    var second_account = try enroll(engine, source_id, "codex", second_subject, second_token, null);
    defer second_account.deinit();

    var first = try acquire(engine, "native-resumed-thread", "native-request", model_a);
    defer first.deinit();
    try std.testing.expectEqualStrings(first_account.account_id, first.account_id);
    var stream_started = try reject(engine, first.handle, true);
    defer stream_started.deinit();
    try stream_started.expectError("UnsafeReplay");
    var first_material = try materialization(engine, first.handle);
    defer first_material.deinit();
    const first_result = try first_material.result();
    try expectPrivateEqual(first_token, try control.string(first_result, "access_token"));
    try expectPrivateEqual(provider_account_id, try control.string(first_result, "provider_account_id"));
    const foreign_capability = try engine.capabilityForTest("git");
    var foreign_material = try rpc(engine, .adapter, "adapter.materialize", .{
        .application = "git",
        .capability = foreign_capability[0..],
        .lease_handle = first.handle,
    });
    defer foreign_material.deinit();
    try foreign_material.expectError("UnknownLease");

    var rejected = try reject(engine, first.handle, false);
    defer rejected.deinit();
    _ = try rejected.result();
    const retry_capability = try engine.capabilityForTest("codex");
    var changed_request = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = retry_capability[0..],
        .session_id = "native-resumed-thread",
        .request_id = "native-request",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_b },
    });
    defer changed_request.deinit();
    try changed_request.expectError("RequestMismatch");
    var alternate = try acquire(engine, "native-resumed-thread", "native-request", model_a);
    defer alternate.deinit();
    try std.testing.expectEqualStrings(second_account.account_id, alternate.account_id);
    try std.testing.expect(!std.mem.eql(u8, first.account_id, alternate.account_id));
    try std.testing.expect(alternate.route_generation > first.route_generation);
    var alternate_material = try materialization(engine, alternate.handle);
    defer alternate_material.deinit();
    try expectPrivateEqual(second_token, try control.string(try alternate_material.result(), "access_token"));

    // A quota response for this exact model must not invalidate authorization
    // or unrelated resource capacity for the first account.
    var other_resource = try acquire(engine, "independent-native-thread", "other-model-request", model_b);
    defer other_resource.deinit();
    try std.testing.expectEqualStrings(first_account.account_id, other_resource.account_id);
    try report(engine, other_resource.handle, "accepted");
    try report(engine, other_resource.handle, "completed");

    try report(engine, alternate.handle, "accepted");
    var unsafe = try reject(engine, alternate.handle, false);
    defer unsafe.deinit();
    try unsafe.expectError("UnsafeReplay");
    const capability = try engine.capabilityForTest("codex");
    var retry = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-resumed-thread",
        .request_id = "native-request",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a },
    });
    defer retry.deinit();
    try retry.expectError("AttemptBudgetExhausted");
    try report(engine, alternate.handle, "completed");

    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const bindings = control.get(try snapshot.result(), "bindings") orelse return error.InvalidReply;
    try std.testing.expect(bindings == .array);
    var found = false;
    for (bindings.array.items) |binding| {
        if (std.mem.eql(u8, try control.string(binding, "session_id"), "native-resumed-thread")) {
            found = true;
            try std.testing.expectEqualStrings(second_account.account_id, try control.string(binding, "account_id"));
        }
    }
    try std.testing.expect(found);
    try assertRedacted(engine, &.{ first_token, second_token, provider_account_id, first_subject, second_subject });
    try assertCiphertextFiles(path, &.{ first_token, second_token, provider_account_id });
}

test "actor enforces channel and application capabilities before materialization" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(39));
    defer owners.closeEngine(engine);
    try owners.prepare(engine, "fixture-thread");
    const capability = try engine.capabilityForTest("codex");
    const different_capability = try engine.capabilityForTest("git");
    var wrong_channel = try rpc(engine, .control, "adapter.materialize", .{ .application = "codex", .capability = capability[0..], .session_id = "fixture-thread", .lease_handle = "unissued" });
    defer wrong_channel.deinit();
    try wrong_channel.expectError("WrongChannel");
    var wrong_application = try rpc(engine, .adapter, "adapter.materialize", .{ .application = "codex", .capability = different_capability[0..], .session_id = "fixture-thread", .lease_handle = "unissued" });
    defer wrong_application.deinit();
    try wrong_application.expectError("Unauthorized");
    var forged = try rpc(engine, .adapter, "adapter.materialize", .{ .application = "codex", .capability = "invalid", .session_id = "fixture-thread", .lease_handle = "unissued" });
    defer forged.deinit();
    try forged.expectError("Unauthorized");
    var public_fixture = try rpc(engine, .control, "fixture.enroll", .{});
    defer public_fixture.deinit();
    try public_fixture.expectFailure();
    var native_as_source = try rpc(engine, .adapter, "fixture.enroll", .{ .application = "codex", .capability = capability[0..], .session_id = "fixture-thread" });
    defer native_as_source.deinit();
    try native_as_source.expectError("WrongPurpose");
    var observation_as_request = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "fixture-thread",
        .request_id = "wrong-purpose",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .purpose = "account_read", .resource = model_a },
    });
    defer observation_as_request.deinit();
    try observation_as_request.expectError("WrongPurpose");
    const acquisition_capability = try engine.capabilityForTest("enrollment");
    var acquisition_as_request = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "enrollment",
        .capability = acquisition_capability[0..],
        .session_id = "fixture-thread",
        .request_id = "acquisition-is-not-materialization",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a },
    });
    defer acquisition_as_request.deinit();
    try acquisition_as_request.expectError("WrongPurpose");
}

test "actor restart preserves encrypted custody and original terminal authority without reactivating admission" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: [32]u8 = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    var engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
    var engine_open = true;
    defer if (engine_open) owners.closeEngine(engine);

    const first_source = try connect(engine, "codex");
    defer allocator.free(first_source);
    const second_source = try connect(engine, "codex");
    defer allocator.free(second_source);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const first_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, first_token);
        allocator.free(first_token);
    }
    const second_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, second_token);
        allocator.free(second_token);
    }
    var first_enrollment = try enroll(engine, first_source, "codex", subject, first_token, null);
    defer first_enrollment.deinit();
    var second_enrollment = try enroll(engine, second_source, "codex", subject, second_token, null);
    defer second_enrollment.deinit();
    try std.testing.expectEqualStrings(first_enrollment.account_id, second_enrollment.account_id);
    var old_lease = try acquire(engine, "native-resumed-thread", "before-daemon-restart", model_a);
    defer old_lease.deinit();
    var material = try materialization(engine, old_lease.handle);
    defer material.deinit();
    try expectPrivateEqual(first_token, try control.string(try material.result(), "access_token"));
    try report(engine, old_lease.handle, "accepted");
    try report(engine, old_lease.handle, "completed");
    try success(engine, .control, "source.disconnect", .{ .source_id = first_source });
    var independent = try acquire(engine, "native-resumed-thread", "independent-source-request", model_a);
    defer independent.deinit();
    try std.testing.expectEqualStrings(first_enrollment.account_id, independent.account_id);
    var independent_material = try materialization(engine, independent.handle);
    defer independent_material.deinit();
    try expectPrivateEqual(second_token, try control.string(try independent_material.result(), "access_token"));
    try report(engine, independent.handle, "accepted");
    owners.closeEngine(engine);
    engine_open = false;
    try assertCiphertextFiles(path, &.{ first_token, second_token });
    try assertCustodyState(path, key, &.{first_enrollment}, &.{second_enrollment}, null);
    var incorrect_key = key;
    incorrect_key[0] ^= 1;
    defer std.crypto.secureZero(u8, &incorrect_key);
    try std.testing.expectError(error.WrongKey, engine_module.Engine.openWithKey(io, allocator, path, incorrect_key));
    engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
    engine_open = true;
    var old_material = try materialization(engine, independent.handle);
    defer old_material.deinit();
    try old_material.expectError("NativeRemovalPending");
    const capability = try engine.capabilityForTest("codex");
    var resumed = try rpc(engine, .adapter, "adapter.acquire", .{ .application = "codex", .capability = capability[0..], .session_id = "native-resumed-thread", .request_id = "after-daemon-restart", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a } });
    defer resumed.deinit();
    try resumed.expectError("NativeRemovalPending");
    // Fresh proof of the sealed original peer can finish its original request;
    // it cannot authorize another request or materialize after reopen.
    try report(engine, independent.handle, "completed");
    try report(engine, independent.handle, "completed");
    try success(engine, .control, "account.forget", .{ .account_id = first_enrollment.account_id });

    const enrollment_capability = try engine.capabilityForTest("enrollment");
    var reenroll = try rpc(engine, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = enrollment_capability[0..],
        .source_id = second_source,
        .provider = "codex",
        .subject = subject,
        .label = "synthetic account",
        .access_token = second_token,
        .audience = "https://chatgpt.com",
    });
    defer reenroll.deinit();
    // An explicit user forget cannot be undone by the next verified source scan.
    try std.testing.expectEqualStrings("tombstoned", try control.string(try reenroll.result(), "status"));
    const newly_authorized_source = try connect(engine, "codex");
    defer allocator.free(newly_authorized_source);
    var new_source_reenroll = try rpc(engine, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = enrollment_capability[0..],
        .source_id = newly_authorized_source,
        .provider = "codex",
        .subject = subject,
        .label = "synthetic account",
        .access_token = second_token,
        .audience = "https://chatgpt.com",
    });
    defer new_source_reenroll.deinit();
    try std.testing.expectEqualStrings("tombstoned", try control.string(try new_source_reenroll.result(), "status"));
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const accounts = control.get(try snapshot.result(), "accounts") orelse return error.InvalidReply;
    try std.testing.expect(accounts == .array and accounts.array.items.len == 0);
    try assertRedacted(engine, &.{ first_token, second_token, subject });

    owners.closeEngine(engine);
    engine_open = false;
    try assertCustodyState(path, key, &.{ first_enrollment, second_enrollment }, &.{}, first_enrollment.account_id);
    engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
    engine_open = true;
    var after_restart = try rpc(engine, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = enrollment_capability[0..],
        .source_id = second_source,
        .provider = "codex",
        .subject = subject,
        .label = "synthetic account",
        .access_token = second_token,
        .audience = "https://chatgpt.com",
    });
    defer after_restart.deinit();
    try std.testing.expectEqualStrings("tombstoned", try control.string(try after_restart.result(), "status"));
}

test "actor drain lets an accepted request finish while blocking new leases and premature forget" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(71));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "codex");
    defer allocator.free(source_id);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    var account = try enroll(engine, source_id, "codex", subject, token, null);
    defer account.deinit();
    try assertRepairState(engine, account.account_id, "ready");
    var lease = try acquire(engine, "native-thread", "accepted-before-drain", model_a);
    defer lease.deinit();
    try report(engine, lease.handle, "accepted");
    try success(engine, .control, "account.drain", .{ .account_id = account.account_id });
    var premature_forget = try rpc(engine, .control, "account.forget", .{ .account_id = account.account_id });
    defer premature_forget.deinit();
    try premature_forget.expectError("InFlight");

    const capability = try engine.capabilityForTest("codex");
    try owners.prepare(engine, "different-native-thread");
    var next = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "different-native-thread",
        .request_id = "after-drain",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a },
    });
    defer next.deinit();
    try next.expectError("NoEligibleAccount");
    try report(engine, lease.handle, "completed");
    try success(engine, .control, "source.disconnect", .{ .source_id = source_id });
    try assertRepairState(engine, account.account_id, "needs_user");
    try success(engine, .control, "account.forget", .{ .account_id = account.account_id });
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const accounts = control.get(try snapshot.result(), "accounts") orelse return error.InvalidReply;
    const leases = control.get(try snapshot.result(), "leases") orelse return error.InvalidReply;
    try std.testing.expect(accounts == .array and accounts.array.items.len == 0);
    try std.testing.expect(leases == .array and leases.array.items.len == 0);
}

test "actor limits one request to one alternate even when another compatible account remains" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(81));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "codex");
    defer allocator.free(source_id);
    for (0..3) |_| {
        const subject = try generatedValue();
        defer allocator.free(subject);
        const token = try generatedValue();
        defer {
            std.crypto.secureZero(u8, token);
            allocator.free(token);
        }
        var account = try enroll(engine, source_id, "codex", subject, token, null);
        defer account.deinit();
    }
    var first = try acquire(engine, "native-thread", "bounded-request", model_a);
    defer first.deinit();
    var first_failure = try reject(engine, first.handle, false);
    defer first_failure.deinit();
    _ = try first_failure.result();
    var alternate = try acquire(engine, "native-thread", "bounded-request", model_a);
    defer alternate.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.account_id, alternate.account_id));
    var second_failure = try reject(engine, alternate.handle, false);
    defer second_failure.deinit();
    _ = try second_failure.result();
    const capability = try engine.capabilityForTest("codex");
    var third_attempt = try rpc(engine, .adapter, "adapter.acquire", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
        .request_id = "bounded-request",
        .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model_a },
    });
    defer third_attempt.deinit();
    try third_attempt.expectError("AttemptBudgetExhausted");
}

test "actor Git credentials honor verified username, context rejection and pause without global account invalidation" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(91));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "github");
    defer allocator.free(source_id);
    const first_subject = try generatedValue();
    defer allocator.free(first_subject);
    const second_subject = try generatedValue();
    defer allocator.free(second_subject);
    const first_username = try generatedUsername();
    defer allocator.free(first_username);
    const second_username = try generatedUsername();
    defer allocator.free(second_username);
    const first_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, first_token);
        allocator.free(first_token);
    }
    const second_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, second_token);
        allocator.free(second_token);
    }
    var first_account = try enrollWithUsername(engine, source_id, "github", first_subject, first_token, null, first_username);
    defer first_account.deinit();
    var second_account = try enrollWithUsername(engine, source_id, "github", second_subject, second_token, null, second_username);
    defer second_account.deinit();

    // The later account must be selected before routing when Git requests its
    // verified username; selecting the first account then comparing is wrong.
    var selected = try gitGet(engine, "fixture/repository-a.git", second_username);
    defer selected.deinit();
    try expectPrivateEqual(second_username, try control.string(try selected.result(), "username"));
    try expectPrivateEqual(second_token, try control.string(try selected.result(), "password"));

    const capability = try engine.capabilityForTest("git");
    var foreign = try rpc(engine, .adapter, "adapter.gitGet", .{
        .application = "git",
        .capability = capability[0..],
        .request = .{ .protocol = "https", .host = "credential.example.invalid", .path = "fixture/repository-a.git" },
    });
    defer foreign.deinit();
    try foreign.expectFailure();
    try std.testing.expect(std.mem.indexOf(u8, foreign.bytes, "password") == null);
    var malformed = try gitGet(engine, "fixture/../repository-a.git", first_username);
    defer malformed.deinit();
    try malformed.expectFailure();
    try std.testing.expect(std.mem.indexOf(u8, malformed.bytes, "password") == null);

    var first_route = try gitGet(engine, "fixture/repository-a.git", first_username);
    defer first_route.deinit();
    try expectPrivateEqual(first_token, try control.string(try first_route.result(), "password"));
    try gitErase(engine, "fixture/repository-a.git", first_username, null);
    var after_missing_password = try gitGet(engine, "fixture/repository-a.git", first_username);
    defer after_missing_password.deinit();
    try expectPrivateEqual(first_token, try control.string(try after_missing_password.result(), "password"));
    try gitErase(engine, "fixture/repository-a.git", first_username, second_token);
    var after_stale_password = try gitGet(engine, "fixture/repository-a.git", first_username);
    defer after_stale_password.deinit();
    try expectPrivateEqual(first_token, try control.string(try after_stale_password.result(), "password"));
    try gitErase(engine, "fixture/repository-a.git", first_username, first_token);
    var rejected_context = try gitGet(engine, "fixture/repository-a.git", first_username);
    defer rejected_context.deinit();
    try rejected_context.expectError("NoEligibleAccount");
    var other_context = try gitGet(engine, "fixture/repository-b.git", first_username);
    defer other_context.deinit();
    try expectPrivateEqual(first_token, try control.string(try other_context.result(), "password"));

    // A normal URL often has no username. Git supplies the helper's returned
    // username in its subsequent erase; that still identifies the same route.
    var anonymous = try gitGet(engine, "fixture/anonymous-context.git", null);
    defer anonymous.deinit();
    try expectPrivateEqual(first_username, try control.string(try anonymous.result(), "username"));
    try gitErase(engine, "fixture/anonymous-context.git", first_username, first_token);
    var anonymous_alternate = try gitGet(engine, "fixture/anonymous-context.git", null);
    defer anonymous_alternate.deinit();
    try expectPrivateEqual(second_username, try control.string(try anonymous_alternate.result(), "username"));
    try expectPrivateEqual(second_token, try control.string(try anonymous_alternate.result(), "password"));

    try success(engine, .control, "account.pause", .{ .account_id = first_account.account_id });
    var paused = try gitGet(engine, "fixture/repository-b.git", first_username);
    defer paused.deinit();
    try paused.expectError("NoEligibleAccount");
    try success(engine, .control, "account.pause", .{ .account_id = second_account.account_id });
    var exhausted = try gitGet(engine, "fixture/repository-b.git", null);
    defer exhausted.deinit();
    try exhausted.expectError("NoEligibleAccount");
    try assertRedacted(engine, &.{ first_subject, second_subject, first_username, second_username, first_token, second_token });
    try assertCiphertextFiles(path, &.{ first_username, second_username, first_token, second_token });
}

test "actor rejects an expired mutation deadline without changing durable revision or state" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(101));
    defer owners.closeEngine(engine);
    var before = try rpc(engine, .control, "state.snapshot", .{});
    defer before.deinit();
    const revision = control.get(try before.result(), "revision") orelse return error.InvalidReply;
    try std.testing.expect(revision == .integer);
    const expired = std.Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, engine.dispatchUntil(
        allocator,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"source.connect\",\"params\":{\"kind\":\"explicit\",\"provider\":\"github\",\"label\":\"expired source\"}}",
        .control,
        expired,
    ));
    var after = try rpc(engine, .control, "state.snapshot", .{});
    defer after.deinit();
    const result = try after.result();
    const current_revision = control.get(result, "revision") orelse return error.InvalidReply;
    const sources = control.get(result, "sources") orelse return error.InvalidReply;
    try std.testing.expect(current_revision == .integer and current_revision.integer == revision.integer);
    try std.testing.expect(sources == .array and sources.array.items.len == 0);
    var metrics = try rpc(engine, .control, "reliability.export", .{});
    defer metrics.deinit();
    const cells = control.get(try metrics.result(), "cells").?.array.items;
    const mutation_cell = cells[@backingInt(reliability.Metric.control_request)].array.items[@backingInt(reliability.Operation.mutation)];
    try std.testing.expectEqual(@as(i64, 1), control.get(mutation_cell, "bad").?.integer);
    try std.testing.expectEqual(@as(i64, 1), control.get(mutation_cell, "causes").?.array.items[@backingInt(reliability.Cause.timeout)].integer);
    const accepted_source = try connect(engine, "github");
    defer allocator.free(accepted_source);
}

test "actor detach cannot retire a binding using an older request handle or while work is in flight" {
    var owners: OwnerHarness = .{};
    owners.activate();
    defer owners.deinit();
    var directory = try privateDirectory();
    defer directory.cleanup();
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const engine = try engine_module.Engine.openWithKey(io, allocator, path, @splat(111));
    defer owners.closeEngine(engine);
    const source_id = try connect(engine, "codex");
    defer allocator.free(source_id);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    var account = try enroll(engine, source_id, "codex", subject, token, null);
    defer account.deinit();
    var completed = try acquire(engine, "native-thread", "earlier-request", model_a);
    defer completed.deinit();
    try report(engine, completed.handle, "accepted");
    try report(engine, completed.handle, "completed");
    var next = try acquire(engine, "native-thread", "newer-request", model_a);
    defer next.deinit();
    try std.testing.expectEqualStrings(completed.account_id, next.account_id);
    const capability = try engine.capabilityForTest("codex");
    var stale_detach = try rpc(engine, .adapter, "adapter.releaseBinding", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
        .expected_lease_handle = completed.handle,
    });
    defer stale_detach.deinit();
    try stale_detach.expectError("BindingChanged");
    var active_detach = try rpc(engine, .adapter, "adapter.releaseBinding", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
        .expected_lease_handle = next.handle,
    });
    defer active_detach.deinit();
    try active_detach.expectError("InFlight");
    var metadata = try rpc(engine, .adapter, "adapter.metadata", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
    });
    defer metadata.deinit();
    try std.testing.expect(try control.boolean(try metadata.result(), "bound", false));
    try std.testing.expect(std.mem.indexOf(u8, metadata.bytes, token) == null);
    try report(engine, next.handle, "accepted");
    try report(engine, next.handle, "completed");
    try success(engine, .adapter, "adapter.releaseBinding", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
        .expected_lease_handle = next.handle,
    });
    var detached = try rpc(engine, .adapter, "adapter.metadata", .{
        .application = "codex",
        .capability = capability[0..],
        .session_id = "native-thread",
    });
    defer detached.deinit();
    try std.testing.expect(!try control.boolean(try detached.result(), "bound", true));
}
