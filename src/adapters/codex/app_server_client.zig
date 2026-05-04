//! JSON-RPC stdio client for `codex app-server --listen stdio://`.
//!
//! Anchor: docs/spec/codex-adapter-contract-2026-05-03.md §2.1 + §3.
//! The Codex adapter spawns the app-server as a child, then talks
//! line-delimited JSON-RPC 2.0 over stdin/stdout. The app-server
//! reserves stdout for protocol messages; logs go to stderr.
//!
//! Phase 1 scope: spawn, initialize round-trip, account/login/start
//! with type=chatgptAuthTokens, observe account/login/completed +
//! account/updated, then close cleanly. Turn driving and
//! chatgptAuthTokens/refresh handling land in tasks #21 / #25.

const std = @import("std");
const broker_types = @import("../../broker/types.zig");

/// A spawned `codex app-server` child plus the framing we wrap around
/// its stdin/stdout. Caller owns the temp `codex_home` directory.
pub const AppServerClient = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    /// Monotonic counter for outbound request ids. Server-initiated
    /// requests carry their own ids; we mirror them on response.
    next_id: u64 = 1,
    /// Read-side line buffer. Allocates against `allocator`.
    line_buf: std.ArrayListUnmanaged(u8) = .{},
    /// Stderr accumulator (stderr is not protocol; we drain to keep
    /// the pipe from blocking the child).
    stderr_buf: std.ArrayListUnmanaged(u8) = .{},

    pub const SpawnOptions = struct {
        /// Path to the codex binary (`codex` by default, overridable
        /// via OMUX_CODEX_APP_SERVER for dev).
        codex_bin: ?[]const u8 = null,
        /// CODEX_HOME directory — typically a per-session tempdir
        /// containing the materialized auth.json and a config.toml
        /// pointing at the wire proxy (Phase 2).
        codex_home: []const u8,
    };

    pub fn spawn(allocator: std.mem.Allocator, opts: SpawnOptions) !AppServerClient {
        const default_bin = "codex";
        const env_bin = std.process.getEnvVarOwned(allocator, "OMUX_CODEX_APP_SERVER") catch null;
        defer if (env_bin) |b| allocator.free(b);
        const bin = opts.codex_bin orelse env_bin orelse default_bin;

        var env_map = try std.process.getEnvMap(allocator);
        errdefer env_map.deinit();
        try env_map.put("CODEX_HOME", opts.codex_home);

        const argv = [_][]const u8{ bin, "app-server", "--listen", "stdio://" };
        var child = std.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        // env_map lives on stack here, so we copy it into a heap-owned
        // map the child holds for its lifetime via setEnv.
        // std.process.Child accepts an env_map pointer; we keep it
        // alive by storing it in the returned struct via a wrapper.
        // Simpler: pass the map directly; std.process.Child borrows.
        child.env_map = &env_map;

        try child.spawn();

        // Once spawned, child no longer needs our env_map view, but we
        // can't deinit it before the child reads it — std.process
        // copies on the spawn syscall path. Safe to drop here.
        env_map.deinit();

        return AppServerClient{
            .allocator = allocator,
            .child = child,
        };
    }

    pub fn deinit(self: *AppServerClient) void {
        self.line_buf.deinit(self.allocator);
        self.stderr_buf.deinit(self.allocator);
        if (self.child.stdin) |s| s.close();
        self.child.stdin = null;
        // Caller is expected to .wait() for the child explicitly via
        // .closeAndWait. deinit just frees buffers.
    }

    /// Close stdin and wait for the child to exit. Returns the term.
    pub fn closeAndWait(self: *AppServerClient) !std.process.Child.Term {
        if (self.child.stdin) |s| {
            s.close();
            self.child.stdin = null;
        }
        return try self.child.wait();
    }

    /// Send a JSON-RPC request line. Returns the id used.
    pub fn sendRequest(
        self: *AppServerClient,
        method: []const u8,
        params_json: []const u8,
    ) !u64 {
        const id = self.next_id;
        self.next_id += 1;
        const stdin = self.child.stdin orelse return error.StdinClosed;

        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try std.fmt.formatInt(id, 10, .lower, .{}, w);
        try w.writeAll(",\"method\":");
        try std.json.stringify(method, .{}, w);
        try w.writeAll(",\"params\":");
        try w.writeAll(params_json);
        try w.writeAll("}\n");
        try stdin.writeAll(buf.items);
        return id;
    }

    /// Send a JSON-RPC response line for a server-initiated request.
    pub fn sendResponse(
        self: *AppServerClient,
        id: std.json.Value,
        result_json: []const u8,
    ) !void {
        const stdin = self.child.stdin orelse return error.StdinClosed;
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try std.json.stringify(id, .{}, w);
        try w.writeAll(",\"result\":");
        try w.writeAll(result_json);
        try w.writeAll("}\n");
        try stdin.writeAll(buf.items);
    }

    /// Read the next JSON-RPC frame from stdout. Returns the parsed
    /// JSON value (caller owns the std.json.Parsed wrapper). Drains
    /// stderr opportunistically into self.stderr_buf so the child's
    /// pipe doesn't fill.
    ///
    /// `timeout_ms` bounds the blocking poll. Returns
    /// error.Timeout if the deadline passes before a complete line.
    pub fn recvFrame(
        self: *AppServerClient,
        timeout_ms: u64,
    ) !std.json.Parsed(std.json.Value) {
        var poller = std.io.poll(self.allocator, enum { stdout, stderr }, .{
            .stdout = self.child.stdout.?,
            .stderr = self.child.stderr.?,
        });
        defer poller.deinit();

        const deadline_ns = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms;

        while (true) {
            // Drain whatever is buffered into our line/stderr buffers.
            try drainFifoInto(self.allocator, &self.line_buf, poller.fifo(.stdout));
            try drainFifoInto(self.allocator, &self.stderr_buf, poller.fifo(.stderr));

            // Look for a complete line in line_buf.
            if (std.mem.indexOfScalar(u8, self.line_buf.items, '\n')) |nl| {
                const line = self.line_buf.items[0..nl];
                if (line.len == 0) {
                    // Skip empty line and keep going.
                    _ = try self.consumeLine(nl + 1);
                    continue;
                }
                const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, line, .{});
                _ = try self.consumeLine(nl + 1);
                return parsed;
            }

            const now = std.time.nanoTimestamp();
            if (now >= deadline_ns) return error.Timeout;
            const remaining_ns = deadline_ns - now;
            const poll_ns: u64 = @intCast(@min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms)));
            const keep_going = try poller.pollTimeout(poll_ns);
            if (!keep_going and self.line_buf.items.len == 0) return error.ChildClosed;
        }
    }

    fn consumeLine(self: *AppServerClient, end: usize) !void {
        const remaining = self.line_buf.items[end..];
        std.mem.copyForwards(u8, self.line_buf.items[0..remaining.len], remaining);
        self.line_buf.shrinkRetainingCapacity(remaining.len);
    }
};

fn drainFifoInto(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    fifo: anytype,
) !void {
    const len = fifo.readableLength();
    if (len == 0) return;
    try out.ensureUnusedCapacity(allocator, len);
    const slice = fifo.readableSlice(0);
    out.appendSliceAssumeCapacity(slice);
    fifo.discard(len);
}

/// Write the params for the `initialize` request. The codex
/// app-server's chatgptAuthTokens login mode requires
/// `capabilities.experimentalApi: true` (per the inplace-broker proof
/// spec §"Local stdio protocol smoke on 2026-05-02").
pub fn writeInitializeParams(writer: anytype) !void {
    try writer.writeAll(
        \\{"capabilities":{"experimentalApi":true},"clientInfo":{"name":"oauth-mux","version":"0.2.0"}}
    );
}

/// Write the params for `account/login/start` with
/// `type:"chatgptAuthTokens"`. The shape mirrors the codex schema at
/// app-server-protocol/schema/json/AccountLoginStartParams.json.
pub fn writeLoginStartParams(
    writer: anytype,
    tokens: broker_types.ChatgptAuthTokens,
) !void {
    try writer.writeAll("{\"loginType\":{\"type\":\"chatgptAuthTokens\",\"tokens\":{");
    try writer.writeAll("\"accessToken\":");
    try std.json.stringify(tokens.access_token, .{}, writer);
    try writer.writeAll(",\"chatgptAccountId\":");
    try std.json.stringify(tokens.account_id, .{}, writer);
    if (tokens.plan_type) |pt| {
        try writer.writeAll(",\"chatgptPlanType\":");
        try std.json.stringify(pt, .{}, writer);
    }
    try writer.writeAll("}}}");
}

/// Decide whether a parsed JSON-RPC frame is a notification with the
/// given method name (no `id` field, `method` matches).
pub fn frameIsNotification(frame: std.json.Value, method: []const u8) bool {
    if (frame != .object) return false;
    if (frame.object.contains("id")) return false;
    const m = frame.object.get("method") orelse return false;
    return m == .string and std.mem.eql(u8, m.string, method);
}

/// Decide whether a parsed JSON-RPC frame is the response to a request
/// with the given id (success or error).
pub fn frameIsResponseTo(frame: std.json.Value, id: u64) bool {
    if (frame != .object) return false;
    const id_v = frame.object.get("id") orelse return false;
    if (id_v != .integer) return false;
    return @as(u64, @intCast(id_v.integer)) == id;
}

test "writeInitializeParams shape" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);
    try writeInitializeParams(buf.writer(std.testing.allocator));

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const caps = parsed.value.object.get("capabilities").?;
    const exp = caps.object.get("experimentalApi").?;
    try std.testing.expect(exp.bool);
}

test "frameIsNotification matches method, rejects requests with id" {
    var parsed_n = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"jsonrpc":"2.0","method":"account/updated","params":{"x":1}}
    , .{});
    defer parsed_n.deinit();
    try std.testing.expect(frameIsNotification(parsed_n.value, "account/updated"));
    try std.testing.expect(!frameIsNotification(parsed_n.value, "other/method"));

    var parsed_r = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"jsonrpc":"2.0","id":42,"method":"account/updated"}
    , .{});
    defer parsed_r.deinit();
    try std.testing.expect(!frameIsNotification(parsed_r.value, "account/updated"));
}

test "frameIsResponseTo matches integer id, rejects mismatched id" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"jsonrpc":"2.0","id":7,"result":{}}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(frameIsResponseTo(parsed.value, 7));
    try std.testing.expect(!frameIsResponseTo(parsed.value, 8));

    var no_id = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"jsonrpc":"2.0","method":"x"}
    , .{});
    defer no_id.deinit();
    try std.testing.expect(!frameIsResponseTo(no_id.value, 7));
}

test "writeLoginStartParams round-trip" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);
    try writeLoginStartParams(buf.writer(std.testing.allocator), .{
        .access_token = "AT-1",
        .account_id = "acc-1",
        .plan_type = "pro",
        .fedramp = false,
    });

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const lt = parsed.value.object.get("loginType").?;
    try std.testing.expectEqualStrings("chatgptAuthTokens", lt.object.get("type").?.string);
    const tokens = lt.object.get("tokens").?;
    try std.testing.expectEqualStrings("AT-1", tokens.object.get("accessToken").?.string);
    try std.testing.expectEqualStrings("acc-1", tokens.object.get("chatgptAccountId").?.string);
    try std.testing.expectEqualStrings("pro", tokens.object.get("chatgptPlanType").?.string);
}
