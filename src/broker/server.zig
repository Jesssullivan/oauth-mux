//! MCP-shaped JSON-RPC 2.0 stdio server.
//!
//! Wire framing: line-delimited JSON-RPC 2.0 (one object per line). MCP's
//! stdio transport reserves stdout for valid MCP messages; logs go to
//! stderr. See:
//!   https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
//!   https://www.jsonrpc.org/specification
//!
//! Phase 1 scope: framing, parse, dispatch, write. Method handlers in
//! methods.zig.

const std = @import("std");
const types = @import("types.zig");
const session_mod = @import("session.zig");
const account_pool_mod = @import("account_pool.zig");
const methods = @import("methods.zig");

/// JSON-RPC standard error codes.
pub const ErrorCode = enum(i32) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,

    // -32000 .. -32099 are reserved for the server. We reuse a chunk for
    // broker-semantic errors so adapters can branch on them.
    no_account_selectable = -32010,
    account_not_found = -32011,
    session_not_found = -32012,
    policy_denied = -32013,
    refresh_failed = -32014,
    invalid_shape = -32015,
    not_implemented = -32099,

    pub fn fromBrokerError(err: types.BrokerError) ErrorCode {
        return switch (err) {
            error.NotImplemented => .not_implemented,
            error.NoAccountSelectable => .no_account_selectable,
            error.AccountNotFound => .account_not_found,
            error.SessionNotFound => .session_not_found,
            error.PolicyDenied => .policy_denied,
            error.InvalidParams => .invalid_params,
            error.InvalidShape => .invalid_shape,
            error.ParseError => .parse_error,
            error.RefreshFailed => .refresh_failed,
            error.UnsupportedShape => .invalid_shape,
            error.SecretUnavailable => .internal_error,
            error.OutOfMemory => .internal_error,
        };
    }
};

/// Server context handed to every method handler.
pub const Context = struct {
    allocator: std.mem.Allocator,
    sessions: *session_mod.SessionTable,
    pool: *account_pool_mod.AccountPool,
    /// Optional credential resolver. main.zig wires the Config-aware
    /// implementation; method handlers call it via
    /// credential/materialize. Absent in pure unit tests.
    materializer: ?types.CredentialMaterializer,
    /// stderr writer for diagnostic logs (never on stdout).
    log_writer: std.io.AnyWriter,
};

/// Parsed inbound request.
pub const Request = struct {
    jsonrpc: []const u8,
    id: ?std.json.Value, // notifications have no id
    method: []const u8,
    params: ?std.json.Value,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    sessions: session_mod.SessionTable,
    pool: account_pool_mod.AccountPool,
    materializer: ?types.CredentialMaterializer = null,

    pub fn init(allocator: std.mem.Allocator) Server {
        return .{
            .allocator = allocator,
            .sessions = session_mod.SessionTable.init(allocator),
            .pool = account_pool_mod.AccountPool.init(allocator),
        };
    }

    pub fn setMaterializer(self: *Server, m: types.CredentialMaterializer) void {
        self.materializer = m;
    }

    pub fn deinit(self: *Server) void {
        self.sessions.deinit();
        self.pool.deinit();
    }

    /// Run the server loop on stdin/stdout. Returns when stdin closes or
    /// an unrecoverable error occurs (logged to stderr, exit non-zero).
    pub fn runStdio(self: *Server) !void {
        const stdin = std.io.getStdIn();
        const stdout = std.io.getStdOut();
        const stderr = std.io.getStdErr();

        var buf_reader = std.io.bufferedReader(stdin.reader());
        const reader = buf_reader.reader();

        var buf_writer = std.io.bufferedWriter(stdout.writer());
        const writer = buf_writer.writer();

        var line_buf = std.ArrayListUnmanaged(u8){};
        defer line_buf.deinit(self.allocator);

        while (true) {
            line_buf.clearRetainingCapacity();
            reader.streamUntilDelimiter(line_buf.writer(self.allocator), '\n', null) catch |err| switch (err) {
                error.EndOfStream => return,
                else => return err,
            };
            if (line_buf.items.len == 0) continue;

            // Per-request arena: every method handler allocates against
            // this; we drop it after writing the response so long-lived
            // servers don't accumulate per-call response objects.
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            var ctx: Context = .{
                .allocator = arena.allocator(),
                .sessions = &self.sessions,
                .pool = &self.pool,
                .materializer = self.materializer,
                .log_writer = stderr.writer().any(),
            };

            self.handleLine(&ctx, line_buf.items, writer) catch |err| {
                stderr.writer().print("broker: handleLine error: {s}\n", .{@errorName(err)}) catch {};
            };
            buf_writer.flush() catch {};
        }
    }

    fn handleLine(
        self: *Server,
        ctx: *Context,
        line: []const u8,
        writer: anytype,
    ) !void {
        _ = self;
        var parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, line, .{}) catch {
            try writeError(writer, null, .parse_error, "parse error");
            return;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) {
            try writeError(writer, null, .invalid_request, "request must be an object");
            return;
        }

        const obj = root.object;
        const method_v = obj.get("method") orelse {
            try writeError(writer, obj.get("id"), .invalid_request, "missing method");
            return;
        };
        if (method_v != .string) {
            try writeError(writer, obj.get("id"), .invalid_request, "method must be a string");
            return;
        }

        const req_id = obj.get("id"); // null/missing for notifications
        const params = obj.get("params");

        const result_or_err = methods.dispatch(ctx, method_v.string, params);
        if (req_id == null) return; // notification: no response

        switch (result_or_err) {
            .ok => |result_json| {
                try writeOk(writer, req_id.?, result_json);
            },
            .err => |berr| {
                const code = ErrorCode.fromBrokerError(berr.err);
                try writeError(writer, req_id, code, berr.message);
            },
        }
    }
};

fn writeOk(writer: anytype, id: std.json.Value, result: std.json.Value) !void {
    var sw = std.json.writeStream(writer, .{});
    try sw.beginObject();
    try sw.objectField("jsonrpc");
    try sw.write("2.0");
    try sw.objectField("id");
    try sw.write(id);
    try sw.objectField("result");
    try sw.write(result);
    try sw.endObject();
    try writer.writeByte('\n');
}

fn writeError(writer: anytype, id: ?std.json.Value, code: ErrorCode, msg: []const u8) !void {
    var sw = std.json.writeStream(writer, .{});
    try sw.beginObject();
    try sw.objectField("jsonrpc");
    try sw.write("2.0");
    try sw.objectField("id");
    if (id) |v| try sw.write(v) else try sw.write(null);
    try sw.objectField("error");
    try sw.beginObject();
    try sw.objectField("code");
    try sw.write(@intFromEnum(code));
    try sw.objectField("message");
    try sw.write(msg);
    try sw.endObject();
    try sw.endObject();
    try writer.writeByte('\n');
}

test "ErrorCode round-trip from BrokerError" {
    try std.testing.expectEqual(ErrorCode.no_account_selectable, ErrorCode.fromBrokerError(error.NoAccountSelectable));
    try std.testing.expectEqual(ErrorCode.session_not_found, ErrorCode.fromBrokerError(error.SessionNotFound));
}
