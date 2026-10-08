//! Native command surfaces; applications never have to launch through Omux.
const std = @import("std");
const daemon = @import("daemon.zig");
const paths = @import("paths.zig");
const product = @import("product.zig");
const reference = @import("reference.zig");
const browser_bridge = @import("browser_bridge.zig");
const control_schema = @import("control.zig");
const setup_verification = @import("setup_verification.zig");
const enrollment_wait = @import("enrollment_wait.zig");
const instance = @import("instance.zig");
const git = @import("integrations/git.zig");

pub fn main(init: std.process.Init) !void {
    var threaded: std.Io.Threaded = .init(init.gpa, .{
        .async_limit = .limited(4),
        .concurrent_limit = .limited(24),
        .argv0 = .init(init.minimal.args),
        .environ = init.minimal.environ,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const raw_args = try init.minimal.args.toSlice(allocator);
    if (raw_args.len == 0) return error.MissingExecutableName;
    var args: std.ArrayList([]const u8) = .empty;
    var state_override: ?[]const u8 = null;
    var i: usize = 1;
    while (i < raw_args.len) : (i += 1) {
        if (std.mem.eql(u8, raw_args[i], "--state-dir")) {
            if (state_override != null or i + 1 == raw_args.len) return error.InvalidArguments;
            i += 1;
            state_override = raw_args[i];
        } else try args.append(allocator, raw_args[i]);
    }
    const executable = std.fs.path.basename(raw_args[0]);
    const daemon_default = std.mem.eql(u8, executable, "omuxd");
    const git_default = std.mem.eql(u8, executable, "git-credential-omux");
    const native_default = std.mem.eql(u8, executable, "omux-native-host");
    const command = if (git_default) "git-credential" else if (native_default) "native-host" else if (args.items.len != 0) args.items[0] else if (daemon_default) "daemon" else "help";
    const parameters = if (git_default or native_default) args.items else if (args.items.len != 0) args.items[1..] else &.{};
    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) return help(io, allocator);
    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "version")) return output(io, product.version ++ "\n");
    if (std.mem.eql(u8, command, "reference")) {
        if (parameters.len != 0) return error.InvalidArguments;
        const bundle = try reference.render(allocator);
        try output(io, bundle);
        return output(io, "\n");
    }
    const selection = try instance.Selection.fromEnvironment(init.environ_map);
    const state = state_override orelse try paths.defaultStateForInstance(allocator, init.environ_map, selection);
    const locations = try paths.Locations.fromEnvironmentForInstance(allocator, state, init.environ_map, selection);
    if (std.mem.eql(u8, command, "daemon")) {
        if (parameters.len != 0) return error.InvalidArguments;
        return daemon.run(io, init.gpa, locations);
    }
    if (std.mem.eql(u8, command, "native-host")) {
        if (native_default) try validateNativeArguments(parameters) else if (parameters.len != 0) return error.InvalidArguments;
        return nativeHost(io, init.gpa, locations, if (native_default) parameters else &.{});
    }
    if (std.mem.eql(u8, command, "git-credential")) {
        if (parameters.len != 1) return error.InvalidArguments;
        return gitCredential(io, allocator, locations, parameters[0]);
    }
    if (std.mem.eql(u8, command, "setup") or std.mem.eql(u8, command, "readiness")) {
        if (std.mem.eql(u8, command, "setup") and parameters.len == 1 and std.mem.eql(u8, parameters[0], "verify")) return controlTyped(io, allocator, locations, "setup.refresh", .{ .operation_id = try newOperationId(io, allocator) });
        if (std.mem.eql(u8, command, "setup") and parameters.len == 1 and std.mem.eql(u8, parameters[0], "refresh")) return controlTyped(io, allocator, locations, "setup.refresh", .{});
        if (std.mem.eql(u8, command, "setup") and parameters.len == 1 and std.mem.eql(u8, parameters[0], "evidence")) return controlTyped(io, allocator, locations, "setup.evidence", .{});
        if (parameters.len != 0) return error.InvalidArguments;
        return controlTyped(io, allocator, locations, if (std.mem.eql(u8, command, "setup")) "setup.plan" else "setup.readiness", .{});
    }
    if (std.mem.eql(u8, command, "application-readiness")) {
        // The caller declares its application and demand through stdin. This
        // read-only query neither manufactures context nor starts enrollment.
        if (parameters.len != 1 or !std.mem.eql(u8, parameters[0], "-")) return error.ParametersRequireStdin;
        return controlStdin(io, allocator, locations, "setup.applicationReadiness");
    }
    if (std.mem.eql(u8, command, "enroll")) {
        if (parameters.len == 1 and !std.mem.eql(u8, parameters[0], "--wait")) return enroll(io, allocator, locations, parameters[0], false);
        if (parameters.len == 2 and std.mem.eql(u8, parameters[0], "--wait") and !std.mem.eql(u8, parameters[1], "--wait")) return enroll(io, allocator, locations, parameters[1], true);
        return error.SourceRequired;
    }
    if (std.mem.eql(u8, command, "rpc")) {
        // Parameters may contain grants or browser capsules. They travel only
        // over stdin, never command arguments, environment or diagnostic logs.
        if (parameters.len != 2 or !std.mem.eql(u8, parameters[1], "-")) return error.ParametersRequireStdin;
        return controlStdin(io, allocator, locations, parameters[0]);
    }
    if (std.mem.eql(u8, command, "source")) {
        if (parameters.len >= 1 and std.mem.eql(u8, parameters[0], "connect")) {
            // Source labels and acquisition paths are supplied through the same
            // stdin-only RPC contract as all potentially sensitive parameters.
            if (parameters.len != 2 or !std.mem.eql(u8, parameters[1], "-")) return error.ParametersRequireStdin;
            return controlStdin(io, allocator, locations, "source.connect");
        }
        if (parameters.len != 2) return error.InvalidArguments;
        const method = if (std.mem.eql(u8, parameters[0], "disconnect")) "source.disconnect" else if (std.mem.eql(u8, parameters[0], "reconcile")) "source.reconcile" else return error.InvalidArguments;
        return controlTyped(io, allocator, locations, method, .{ .source_id = parameters[1] });
    }
    if (std.mem.eql(u8, command, "account")) {
        if (parameters.len != 2) return error.InvalidArguments;
        const method = if (std.mem.eql(u8, parameters[0], "pause")) "account.pause" else if (std.mem.eql(u8, parameters[0], "resume")) "account.resume" else if (std.mem.eql(u8, parameters[0], "drain")) "account.drain" else if (std.mem.eql(u8, parameters[0], "forget")) "account.forget" else return error.InvalidArguments;
        return controlTyped(io, allocator, locations, method, .{ .account_id = parameters[1] });
    }
    if (std.mem.eql(u8, command, "--repair") or std.mem.eql(u8, command, "repair")) {
        if (parameters.len != 1) return error.AccountRequired;
        return controlTyped(io, allocator, locations, "repair.start", .{ .account_id = parameters[0] });
    }
    if (std.mem.eql(u8, command, "integration")) {
        if (parameters.len == 1 and std.mem.eql(u8, parameters[0], "status")) return controlTyped(io, allocator, locations, "integrations.status", .{});
        if (parameters.len == 2 and std.mem.eql(u8, parameters[0], "remove")) return controlTyped(io, allocator, locations, "integrations.remove", .{ .adapter = parameters[1] });
        if ((parameters.len == 2 or parameters.len == 3) and std.mem.eql(u8, parameters[0], "install")) return controlTyped(io, allocator, locations, "integrations.install", .{ .adapter = parameters[1], .config_path = if (parameters.len == 3) parameters[2] else @as(?[]const u8, null) });
        if ((parameters.len >= 1 and parameters.len <= 3) and std.mem.eql(u8, parameters[0], "discover")) return controlTyped(io, allocator, locations, "integrations.discover", .{ .adapter = if (parameters.len >= 2) parameters[1] else "codex", .config_path = if (parameters.len == 3) parameters[2] else @as(?[]const u8, null) });
        if ((parameters.len == 2 or parameters.len == 3) and (std.mem.eql(u8, parameters[0], "attach") or std.mem.eql(u8, parameters[0], "detach"))) return controlTyped(io, allocator, locations, if (std.mem.eql(u8, parameters[0], "attach")) "integrations.attach" else "integrations.detach", .{ .adapter = parameters[1], .thread_id = if (parameters.len == 3) parameters[2] else @as(?[]const u8, null) });
        return error.InvalidArguments;
    }
    if (parameters.len != 0) return error.InvalidArguments;
    const method = if (std.mem.eql(u8, command, "status")) "state.snapshot" else if (std.mem.eql(u8, command, "accounts")) "accounts.list" else if (std.mem.eql(u8, command, "sources")) "sources.list" else if (std.mem.eql(u8, command, "usage") or std.mem.eql(u8, command, "capacity")) "usage.summary" else return error.UnknownCommand;
    return control(io, allocator, locations, method, .{ .object = .empty });
}

fn help(io: std.Io, allocator: std.mem.Allocator) !void {
    const text = try reference.commandHelp(allocator);
    defer allocator.free(text);
    try output(io, text);
}

fn output(io: std.Io, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn input(io: std.Io, allocator: std.mem.Allocator, maximum: usize) ![]u8 {
    var buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(maximum));
}

fn request(allocator: std.mem.Allocator, method: []const u8, params: anytype) ![]u8 {
    const normalized = if (comptime emptyAggregate(@TypeOf(params))) @as(?u8, null) else params;
    return std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = @as(u32, 1), .method = method, .params = normalized }, .{});
}

fn emptyAggregate(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => |value| value.field_names.len == 0,
        else => false,
    };
}

fn newOperationId(io: std.Io, allocator: std.mem.Allocator) ![]u8 {
    var random: [32]u8 = undefined;
    io.random(&random);
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.bytesToHex(random, .lower)});
}

fn control(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, method: []const u8, params: std.json.Value) !void {
    const hello_payload = try request(allocator, "system.handshake", .{ .protocol_version = control_schema.protocol_version, .client = "omux-cli" });
    const hello_bytes = try daemon.exchange(io, allocator, locations.control, hello_payload);
    const hello = try std.json.parseFromSlice(std.json.Value, allocator, hello_bytes, .{});
    defer hello.deinit();
    if (hello.value != .object) return error.UnsupportedControlProtocol;
    const hello_result = hello.value.object.get("result") orelse return error.UnsupportedControlProtocol;
    const negotiated = control_schema.get(hello_result, "protocol_version") orelse return error.UnsupportedControlProtocol;
    if (negotiated != .integer or negotiated.integer != control_schema.protocol_version) return error.UnsupportedControlProtocol;
    var supplied = params;
    const operation_authority = control_schema.hasOperationAuthority(method, supplied);
    if (operation_authority) {
        if (supplied != .object) supplied = .{ .object = .empty };
        if (control_schema.get(supplied, "operation_id") == null) {
            // Native custody mutations require a full 256-bit operation ID;
            // the common control identifier accepts the same canonical form.
            const operation_id = try newOperationId(io, allocator);
            try supplied.object.put(allocator, try allocator.dupe(u8, "operation_id"), .{ .string = operation_id });
        }
        _ = try control_schema.operationId(supplied);
        if (control_schema.get(supplied, "expected_revision") == null) {
            const snapshot_request = try request(allocator, "state.snapshot", .{});
            const snapshot_bytes = try daemon.exchange(io, allocator, locations.control, snapshot_request);
            const snapshot = try std.json.parseFromSlice(std.json.Value, allocator, snapshot_bytes, .{});
            defer snapshot.deinit();
            if (snapshot.value != .object) return error.InvalidControlSnapshot;
            const result = snapshot.value.object.get("result") orelse return error.InvalidControlSnapshot;
            const revision = control_schema.get(result, "revision") orelse return error.InvalidControlSnapshot;
            try supplied.object.put(allocator, try allocator.dupe(u8, "expected_revision"), revision);
        }
        _ = try control_schema.expectedRevision(supplied);
    }
    const payload = try request(allocator, method, supplied);
    defer std.crypto.secureZero(u8, payload);
    const reply = daemon.exchange(io, allocator, locations.control, payload) catch |err| {
        if (operation_authority) {
            const unknown = try std.json.Stringify.valueAlloc(allocator, .{ .operation_id = try control_schema.operationId(supplied), .status = "unknown", .message = "Query operation.status with this operation_id before repeating the action." }, .{});
            try output(io, unknown);
            try output(io, "\n");
            try mutationGuidance(io, allocator, supplied);
        }
        return err;
    };
    // Control replies are restricted to redacted metadata by the daemon.
    try output(io, reply);
    try output(io, "\n");
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, reply, .{ .duplicate_field_behavior = .@"error" }) catch |err| {
        if (operation_authority) try mutationGuidance(io, allocator, supplied);
        return err;
    };
    defer parsed.deinit();
    if (operation_authority and !validMutationReply(parsed.value)) {
        try mutationGuidance(io, allocator, supplied);
        return error.InvalidControlReply;
    }
    if (parsed.value == .object and parsed.value.object.contains("error")) {
        if (operation_authority) try mutationGuidance(io, allocator, supplied);
        return error.ControlRequestRejected;
    }
    if (operation_authority and std.mem.eql(u8, method, "setup.refresh")) {
        validateSetupVerificationReply(allocator, reply, try control_schema.operationId(supplied)) catch |err| {
            try mutationGuidance(io, allocator, supplied);
            return err;
        };
    }
    if (std.mem.eql(u8, method, "integrations.remove") and parsed.value == .object) {
        if (parsed.value.object.get("result")) |result| if (result == .object) {
            if (result.object.get("removed")) |removed| if (removed == .bool and !removed.bool) return error.NativeDetachRequired;
        };
    }
}

fn validMutationReply(value: std.json.Value) bool {
    if (value != .object) return false;
    const version = control_schema.get(value, "jsonrpc") orelse return false;
    const id = control_schema.get(value, "id") orelse return false;
    if (version != .string or !std.mem.eql(u8, version.string, "2.0") or id != .integer or id.integer != 1) return false;
    const result = control_schema.get(value, "result");
    const failure = control_schema.get(value, "error");
    if ((result != null) == (failure != null)) return false;
    return if (result) |held| held == .object else failure.? == .object;
}

fn verificationUnsigned(value: std.json.Value) !u64 {
    // Preserve the wire integer before decoding: wide UInt64 values must never
    // pass through a rounded floating-point representation or numeric string.
    if (value != .number_string or value.number_string.len == 0) return error.InvalidControlReply;
    for (value.number_string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidControlReply;
    return std.fmt.parseInt(u64, value.number_string, 10) catch error.InvalidControlReply;
}

fn validateSetupVerificationReply(allocator: std.mem.Allocator, reply: []const u8, operation_id: []const u8) !void {
    const shape = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{ .parse_numbers = false, .duplicate_field_behavior = .@"error" });
    defer shape.deinit();
    const result = control_schema.get(shape.value, "result") orelse return error.InvalidControlReply;
    if (result != .object) return error.InvalidControlReply;
    const identity = control_schema.get(result, "operation_id") orelse return error.InvalidControlReply;
    if (identity != .string or !std.mem.eql(u8, identity.string, operation_id)) return error.InvalidControlReply;
    if (result.object.contains("status")) {
        if (result.object.count() != 4) return error.InvalidControlReply;
        inline for (.{ "schema_version", "operation_id", "generation", "status" }) |field| if (!result.object.contains(field)) return error.InvalidControlReply;
        const status = result.object.get("status").?;
        if (status != .string or !std.mem.eql(u8, status.string, "pending") or
            try verificationUnsigned(result.object.get("schema_version").?) != 1 or
            try verificationUnsigned(result.object.get("generation").?) == 0) return error.InvalidControlReply;
        return;
    }
    if (result.object.count() != 9) return error.InvalidControlReply;
    inline for (.{ "schema_version", "operation_id", "generation", "observed_at", "outcome", "refusal", "phases", "elapsed_ns", "timing_scope" }) |field| if (!result.object.contains(field)) return error.InvalidControlReply;
    if (try verificationUnsigned(result.object.get("schema_version").?) != 1 or
        try verificationUnsigned(result.object.get("observed_at").?) > std.math.maxInt(i64)) return error.InvalidControlReply;
    _ = try verificationUnsigned(result.object.get("generation").?);
    const elapsed = result.object.get("elapsed_ns").?;
    if (elapsed != .null) _ = try verificationUnsigned(elapsed);
    inline for (.{ "outcome", "timing_scope" }) |field| if (result.object.get(field).? != .string) return error.InvalidControlReply;
    const refusal = result.object.get("refusal").?;
    if (refusal != .null and refusal != .string) return error.InvalidControlReply;
    const phases = result.object.get("phases").?;
    if (phases != .array or phases.array.items.len != setup_verification.phase_order.len) return error.InvalidControlReply;
    for (phases.array.items) |phase| {
        if (phase != .object or phase.object.count() != 2) return error.InvalidControlReply;
        inline for (.{ "outcome", "reason" }) |field| {
            const value = phase.object.get(field) orelse return error.InvalidControlReply;
            if (value != .string) return error.InvalidControlReply;
        }
    }
    const encoded = try std.json.Stringify.valueAlloc(allocator, result, .{});
    defer allocator.free(encoded);
    if (encoded.len > setup_verification.maximum_result_bytes) return error.InvalidControlReply;
    const terminal = std.json.parseFromSlice(setup_verification.Result, allocator, encoded, .{ .duplicate_field_behavior = .@"error" }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidControlReply,
    };
    defer terminal.deinit();
    setup_verification.validate(terminal.value) catch return error.InvalidControlReply;
}

fn mutationGuidance(io: std.Io, allocator: std.mem.Allocator, params: std.json.Value) !void {
    const operation_id = try control_schema.operationId(params);
    const text = try std.json.Stringify.valueAlloc(allocator, .{
        .operation_id = operation_id,
        .status = "unresolved",
        .query = .{ .method = "operation.status", .params = .{ .operation_id = operation_id } },
        .message = "Query this operation in the same daemon installation before repeating the action. The CLI does not replay it.",
    }, .{});
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stderr().writerStreaming(io, &buffer);
    try writer.interface.writeAll(text);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn controlStdin(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, method: []const u8) !void {
    const bytes = try input(io, allocator, daemon.max_frame_bytes);
    defer std.crypto.secureZero(u8, bytes);
    const trimmed = std.mem.trim(u8, bytes, " \r\n\t");
    try control_schema.checkDepth(trimmed);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, if (trimmed.len == 0) "{}" else trimmed, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer {
        control_schema.wipeJson(parsed.value);
        parsed.deinit();
    }
    if (parsed.value != .object) return error.InvalidParameters;
    return control(io, allocator, locations, method, parsed.value);
}

fn controlTyped(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, method: []const u8, params: anytype) !void {
    const normalized = if (comptime emptyAggregate(@TypeOf(params))) @as(?u8, null) else params;
    const bytes = try std.json.Stringify.valueAlloc(allocator, normalized, .{});
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    return control(io, allocator, locations, method, parsed.value);
}

fn nativeHost(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, caller: []const []const u8) !void {
    var input_buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &input_buffer);
    var reader = std.Io.File.stdin().readerStreaming(io, &input_buffer);
    var output_buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &output_buffer);
    var writer = std.Io.File.stdout().writerStreaming(io, &output_buffer);
    while (true) {
        var header: [4]u8 = undefined;
        const header_len = try reader.interface.readSliceShort(&header);
        if (header_len == 0) return;
        if (header_len != header.len) return error.IncompleteFrame;
        const len = try browser_bridge.frameLength(header);
        var frame_arena: std.heap.ArenaAllocator = .init(allocator);
        defer frame_arena.deinit();
        const a = frame_arena.allocator();
        const payload = try a.alloc(u8, len);
        defer std.crypto.secureZero(u8, payload);
        try reader.interface.readSliceAll(payload);
        const reply = nativeExchange(io, a, locations, caller, payload) catch |err| try std.json.Stringify.valueAlloc(a, .{ .version = @as(u32, 1), .id = @as(?[]const u8, null), .@"error" = .{ .code = @errorName(err), .message = "Omux browser request was not admitted." } }, .{});
        defer std.crypto.secureZero(u8, reply);
        const framed = try browser_bridge.encodeFrame(a, reply);
        defer std.crypto.secureZero(u8, framed);
        try writer.interface.writeAll(framed);
        try writer.interface.flush();
    }
}

fn nativeExchange(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, caller: []const []const u8, payload: []const u8) ![]u8 {
    var decoded = try browser_bridge.decodeIngress(allocator, payload, false);
    defer decoded.deinit();
    const expected_channel: browser_bridge.Channel = if (locations.instance == .dev) .development else .release;
    if (decoded.validated.provenance.channel != expected_channel) return nativeFailure(allocator, decoded.validated.id, error.BrowserChannelMismatch);
    if (caller.len != 0) {
        const params = decoded.parsed.value.object.get("params").?.object;
        const provenance = params.get("provenance").?.object;
        const browser = provenance.get("browser").?.string;
        const extension_id = provenance.get("extensionId").?.string;
        if (caller.len == 1) {
            const prefix = "chrome-extension://";
            if (!std.mem.eql(u8, browser, "chromium") or !std.mem.eql(u8, extension_id, caller[0][prefix.len .. caller[0].len - 1])) return nativeFailure(allocator, decoded.validated.id, error.NativeHostProvenanceMismatch);
        } else if (!std.mem.eql(u8, browser, "firefox") or !std.mem.eql(u8, extension_id, caller[1])) return nativeFailure(allocator, decoded.validated.id, error.NativeHostProvenanceMismatch);
    }
    _ = try browser_bridge.validateRequest(decoded.parsed.value, false, std.Io.Clock.real.now(io).toSeconds());
    return daemon.exchangeWithTimeout(io, allocator, locations.browser, payload, 8_000) catch |err| nativeFailure(allocator, decoded.validated.id, err);
}

fn nativeFailure(allocator: std.mem.Allocator, id: []const u8, failure: anyerror) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .version = @as(u32, 1), .id = id, .@"error" = .{ .code = @errorName(failure), .message = "Omux browser request was not admitted." } }, .{});
}

/// Browser metadata selects no provider and grants no identity authority.
/// The installed browser host manifest also restricts exact extension IDs.
pub fn validateNativeArguments(arguments: []const []const u8) !void {
    if (arguments.len == 0) return; // Manual stdin bridge diagnostics.
    if (arguments.len == 1) {
        const prefix = "chrome-extension://";
        const origin = arguments[0];
        if (origin.len != prefix.len + 33 or !std.mem.startsWith(u8, origin, prefix) or origin[origin.len - 1] != '/') return error.InvalidNativeHostCaller;
        for (origin[prefix.len .. origin.len - 1]) |byte| if (byte < 'a' or byte > 'p') return error.InvalidNativeHostCaller;
        return;
    }
    if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "browser-sources@omux.xoxd.ai")) {
        try paths.validateAbsolute(arguments[0]);
        if (!std.mem.endsWith(u8, arguments[0], ".json")) return error.InvalidNativeHostCaller;
        return;
    }
    return error.InvalidNativeHostCaller;
}

fn gitCredential(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, name: []const u8) !void {
    const operation = git.operation(name);
    if (operation == .unsupported) return error.UnsupportedCredentialOperation;
    const bytes = try input(io, allocator, git.max_input);
    defer std.crypto.secureZero(u8, bytes);
    const native_request = git.parse(bytes) catch |err| switch (err) {
        error.UnsupportedProtocol => return,
        else => return err,
    };
    if (!std.ascii.eqlIgnoreCase(native_request.host, "github.com") or native_request.path == null) return;
    // Git's `store` is an observation from an externally-owned credential
    // lineage. It cannot grant Omux adoption or renewal ownership.
    if (operation == .store) return;
    const capability = paths.readCapability(allocator, locations.state, "git") catch |err| switch (err) {
        error.AdapterNotInstalled, error.PathOpenFailed => return,
        else => return err,
    };
    defer std.crypto.secureZero(u8, capability);
    const params = .{
        .application = "git",
        .capability = capability,
        .request = .{
            .protocol = native_request.protocol,
            .host = native_request.host,
            .path = native_request.path,
            .username = native_request.username,
        },
    };
    const payload = if (operation == .erase) try request(allocator, "adapter.gitErase", .{
        .application = "git",
        .capability = capability,
        .request = .{
            .protocol = native_request.protocol,
            .host = native_request.host,
            .path = native_request.path,
            .username = native_request.username,
            .password = native_request.password,
        },
    }) else try request(allocator, "adapter.gitGet", params);
    defer std.crypto.secureZero(u8, payload);
    const reply = daemon.exchange(io, allocator, locations.adapter, payload) catch |err| switch (err) {
        error.DaemonUnavailable => return,
        else => return err,
    };
    defer std.crypto.secureZero(u8, reply);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
    defer {
        control_schema.wipeJson(parsed.value);
        parsed.deinit();
    }
    if (parsed.value != .object) return error.InvalidAdapterReply;
    if (parsed.value.object.get("error")) |rejection| {
        if (rejection == .object) if (rejection.object.get("message")) |message| {
            if (message == .string and std.mem.eql(u8, message.string, "NoEligibleAccount")) return;
        };
        return error.AdapterRequestRejected;
    }
    if (operation == .erase) return;
    const result = parsed.value.object.get("result") orelse return error.InvalidAdapterReply;
    if (result == .null) return;
    if (result != .object) return error.InvalidAdapterReply;
    const username = result.object.get("username") orelse return error.InvalidAdapterReply;
    const password = result.object.get("password") orelse return error.InvalidAdapterReply;
    if (username != .string or password != .string) return error.InvalidAdapterReply;
    defer std.crypto.secureZero(u8, @constCast(password.string));
    const expiry = result.object.get("expires_at");
    const expires_at: ?i64 = if (expiry) |value| switch (value) {
        .null => null,
        .integer => value.integer,
        else => return error.InvalidAdapterReply,
    } else null;
    const now = std.Io.Clock.real.now(io).toSeconds();
    const response = try git.response(allocator, native_request, .{ .protocol = native_request.protocol, .host = native_request.host, .path = native_request.path, .username = native_request.username }, .{ .username = username.string, .password = password.string, .expires_at = expires_at }, now);
    defer std.crypto.secureZero(u8, response);
    try output(io, response);
}

const enrollment_wait_budget_ms: i64 = 30_000;
const EnrollmentWaitCause = enum { none, admission_error, observation_error, job_failed, superseded, missing_job, custody_unavailable, stale_observation, invalid_reply, observation_unavailable, deadline_expired, admission_unresolved };
fn enrollmentWaitCause(err: anyerror) EnrollmentWaitCause {
    return switch (err) {
        error.EnrollmentSuperseded => .superseded,
        error.EnrollmentJobMissing => .missing_job,
        error.EnrollmentCustodyUnavailable => .custody_unavailable,
        error.EnrollmentObservationStale => .stale_observation,
        error.InvalidEnrollmentWaitReply => .invalid_reply,
        error.EnrollmentRequestRejected => .observation_error,
        error.Timeout => .deadline_expired,
        else => .observation_unavailable,
    };
}
fn enrollmentWaitOutcome(io: std.Io, allocator: std.mem.Allocator, selected: ?enrollment_wait.Selection, status: enum { completed, failed, unresolved }, cause: EnrollmentWaitCause) !void {
    const bytes = try std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = 1,
        .operation_id = if (selected) |s| s.operation_id else @as(?[]const u8, null),
        .operation_generation = if (selected) |s| s.operation_generation else @as(?u64, null),
        .status = @tagName(status),
        .cause = @tagName(cause),
        .retry_import = false,
    }, .{});
    defer allocator.free(bytes);
    try output(io, bytes);
    try output(io, "\n");
}
fn waitEnrollment(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, selected: enrollment_wait.Selection, until: std.Io.Clock.Timestamp) !void {
    const snapshot_request = try request(allocator, "state.snapshot", .{});
    defer allocator.free(snapshot_request);
    while (true) {
        const reply = daemon.exchangeUntil(io, allocator, locations.control, snapshot_request, until) catch |err| {
            try enrollmentWaitOutcome(io, allocator, selected, .unresolved, enrollmentWaitCause(err));
            return error.EnrollmentWaitUnresolved;
        };
        defer allocator.free(reply);
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, reply, .{
            .parse_numbers = false,
            .duplicate_field_behavior = .@"error",
        }) catch {
            try enrollmentWaitOutcome(io, allocator, selected, .unresolved, .invalid_reply);
            return error.EnrollmentWaitUnresolved;
        };
        defer parsed.deinit();
        const observed = enrollment_wait.observe(selected, parsed.value) catch |err| {
            try enrollmentWaitOutcome(io, allocator, selected, .unresolved, enrollmentWaitCause(err));
            return error.EnrollmentWaitUnresolved;
        };
        if (until.durationFromNow(io).raw.toMilliseconds() <= 0) {
            try enrollmentWaitOutcome(io, allocator, selected, .unresolved, .deadline_expired);
            return error.EnrollmentWaitUnresolved;
        }
        switch (observed) {
            .completed => return enrollmentWaitOutcome(io, allocator, selected, .completed, .none),
            .failed => {
                try enrollmentWaitOutcome(io, allocator, selected, .failed, .job_failed);
                return error.EnrollmentFailed;
            },
            .pending => {},
        }
        const remaining = until.durationFromNow(io).raw.toMilliseconds();
        if (remaining <= 0) {
            try enrollmentWaitOutcome(io, allocator, selected, .unresolved, .deadline_expired);
            return error.EnrollmentWaitUnresolved;
        }
        try io.sleep(.fromMilliseconds(@min(250, remaining)), .awake);
    }
}

fn enroll(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, source_id: []const u8, wait: bool) !void {
    const bytes = try input(io, allocator, daemon.max_frame_bytes);
    defer std.crypto.secureZero(u8, bytes);
    try control_schema.checkDepth(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .duplicate_field_behavior = .@"error" });
    defer {
        control_schema.wipeJson(parsed.value);
        parsed.deinit();
    }
    if (parsed.value != .object) return error.InvalidParameters;
    const provider_name: []const u8 = if (parsed.value.object.get("provider")) |provider| blk: {
        if (provider != .string or (!std.mem.eql(u8, provider.string, "github") and !std.mem.eql(u8, provider.string, "codex"))) return error.UnsupportedProvider;
        break :blk provider.string;
    } else "github";
    var fields = parsed.value.object.iterator();
    while (fields.next()) |entry| {
        const name = entry.key_ptr.*;
        if (!std.mem.eql(u8, name, "provider") and !std.mem.eql(u8, name, "access_token") and !std.mem.eql(u8, name, "provider_account_id") and !std.mem.eql(u8, name, "label") and !std.mem.eql(u8, name, "credential_kind") and !std.mem.eql(u8, name, "allow_reenrollment") and !std.mem.eql(u8, name, "custody_seconds")) return error.InvalidParameters;
    }
    const token = parsed.value.object.get("access_token") orelse return error.AccessCredentialRequired;
    if (token != .string or token.string.len == 0) return error.AccessCredentialRequired;
    const label: ?[]const u8 = if (parsed.value.object.get("label")) |value| switch (value) {
        .string => value.string,
        .null => null,
        else => return error.InvalidParameters,
    } else null;
    const provider_account_id: ?[]const u8 = if (parsed.value.object.get("provider_account_id")) |value| switch (value) {
        .string => value.string,
        .null => null,
        else => return error.InvalidParameters,
    } else null;
    const credential_kind: ?[]const u8 = if (parsed.value.object.get("credential_kind")) |value| blk: {
        if (value != .string or (!std.mem.eql(u8, value.string, "api_key") and !std.mem.eql(u8, value.string, "oauth_access"))) return error.InvalidParameters;
        break :blk value.string;
    } else null;
    const allow_reenrollment = if (parsed.value.object.get("allow_reenrollment")) |value| blk: {
        if (value != .bool) return error.InvalidParameters;
        break :blk value.bool;
    } else false;
    const custody_seconds: ?i64 = if (parsed.value.object.get("custody_seconds")) |value| blk: {
        if (value != .integer or value.integer < 1 or value.integer > 2_592_000) return error.InvalidParameters;
        break :blk value.integer;
    } else null;
    // The optional local wait budget begins after stdin validation. It covers
    // capability loading, the single import exchange and all observations; it
    // does not claim to bound operator time supplying stdin.
    const until: ?std.Io.Clock.Timestamp = if (wait) .fromNow(io, .{
        .clock = .awake,
        .raw = .fromMilliseconds(enrollment_wait_budget_ms),
    }) else null;
    const capability = try paths.readCapability(allocator, locations.state, "enrollment");
    defer std.crypto.secureZero(u8, capability);
    const params = .{ .application = "enrollment", .capability = capability, .source_id = source_id, .provider = provider_name, .access_token = token.string, .provider_account_id = provider_account_id, .credential_kind = credential_kind, .allow_reenrollment = allow_reenrollment, .custody_seconds = custody_seconds, .label = label };
    const payload = if (wait) try request(allocator, "credential.import", .{
        .application = params.application,
        .capability = params.capability,
        .source_id = params.source_id,
        .provider = params.provider,
        .access_token = params.access_token,
        .provider_account_id = params.provider_account_id,
        .credential_kind = params.credential_kind,
        .allow_reenrollment = params.allow_reenrollment,
        .custody_seconds = params.custody_seconds,
        .label = params.label,
        .include_operation_generation = true,
    }) else try request(allocator, "credential.import", params);
    defer std.crypto.secureZero(u8, payload);
    if (until) |original| {
        const reply = daemon.exchangeUntil(io, allocator, locations.adapter, payload, original) catch {
            // No acknowledgement means no generation authority. Never infer
            // the current generation from another snapshot or repeat import.
            try enrollmentWaitOutcome(io, allocator, null, .unresolved, .admission_unresolved);
            return error.EnrollmentWaitUnresolved;
        };
        defer allocator.free(reply);
        const response = std.json.parseFromSlice(std.json.Value, allocator, reply, .{
            .parse_numbers = false,
            .duplicate_field_behavior = .@"error",
        }) catch {
            try enrollmentWaitOutcome(io, allocator, null, .unresolved, .invalid_reply);
            return error.EnrollmentWaitUnresolved;
        };
        defer response.deinit();
        const selected = enrollment_wait.selection(response.value) catch |err| {
            try enrollmentWaitOutcome(io, allocator, null, .unresolved, if (err == error.EnrollmentRequestRejected) .admission_error else .invalid_reply);
            return error.EnrollmentWaitUnresolved;
        };
        return waitEnrollment(io, allocator, locations, selected, original);
    }
    const reply = try daemon.exchange(io, allocator, locations.adapter, payload);
    try output(io, reply);
    try output(io, "\n");
    const response = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
    defer response.deinit();
    if (response.value != .object or response.value.object.contains("error")) return error.EnrollmentRejected;
}

test "control request serialization keeps JSON parameters out of argv" {
    const allocator = std.testing.allocator;
    const payload = try request(allocator, "state.snapshot", .{});
    defer allocator.free(payload);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("2.0", parsed.value.object.get("jsonrpc").?.string);
    try std.testing.expectEqualStrings("state.snapshot", parsed.value.object.get("method").?.string);
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("id").?.integer);
    var admitted = try control_schema.parse(allocator, payload);
    defer admitted.deinit();
    try std.testing.expect(admitted.params == .null);
}

test "native messaging launch metadata accepts only supported browser shapes" {
    try validateNativeArguments(&.{"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"});
    try validateNativeArguments(&.{ "/tmp/ai.xoxd.omux.json", "browser-sources@omux.xoxd.ai" });
    try std.testing.expectError(error.InvalidNativeHostCaller, validateNativeArguments(&.{"https://fixture.invalid"}));
    try std.testing.expectError(error.InvalidNativeHostCaller, validateNativeArguments(&.{ "/tmp/ai.xoxd.omux.json", "other@fixture.invalid" }));
}
