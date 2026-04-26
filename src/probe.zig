const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const provider_schema = @import("provider_schema.zig");

pub const ProbeError = error{
    UnsupportedMethod,
    UnsupportedTransport,
    NetworkError,
    OutOfMemory,
};

pub const ProbeResult = struct {
    status: u16,
    retry_after_s: ?u32 = null,
    hint: ?[]const u8 = null,

    pub fn deinit(self: ProbeResult, allocator: std.mem.Allocator) void {
        if (self.hint) |hint| allocator.free(hint);
    }
};

pub fn classifyResult(
    allocator: std.mem.Allocator,
    def: provider_schema.ProviderDefinition,
    plan: provider_schema.ProbePlan,
    result: ProbeResult,
) types.HttpClassification {
    if (plan.transport == .command) {
        if (std.mem.eql(u8, def.name, "codex")) {
            if (result.hint) |hint| {
                if (provider_schema.classifyCodexExecJsonl(allocator, hint)) |classification| {
                    return classification;
                }
            }
        }
    }

    const classified = provider_schema.classifyHttp(def, result.status, result.retry_after_s, result.hint);
    if (result.status >= plan.success_status_min and result.status <= plan.success_status_max) {
        return if (classified == .success) .success else classified;
    }
    return classified;
}

pub fn execute(
    allocator: std.mem.Allocator,
    plan: provider_schema.ProbePlan,
    access_token: []const u8,
    env_pairs: []const [2][]const u8,
) ProbeError!ProbeResult {
    return switch (plan.transport) {
        .http => executeHttp(allocator, plan, access_token),
        .command => executeCommand(allocator, plan, env_pairs),
    };
}

fn executeHttp(
    allocator: std.mem.Allocator,
    plan: provider_schema.ProbePlan,
    access_token: []const u8,
) ProbeError!ProbeResult {
    const method = methodFromString(plan.method) orelse return error.UnsupportedMethod;
    const uri = std.Uri.parse(plan.url) catch return error.NetworkError;

    var bearer_value: ?[]u8 = null;
    defer if (bearer_value) |value| allocator.free(value);

    var headers_buf: [4]std.http.Header = undefined;
    var header_count: usize = 0;
    headers_buf[header_count] = .{ .name = "Accept", .value = "application/json" };
    header_count += 1;

    switch (plan.auth) {
        .bearer => {
            bearer_value = std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}) catch return error.OutOfMemory;
            headers_buf[header_count] = .{ .name = "Authorization", .value = bearer_value.? };
            header_count += 1;
        },
        .token_header => {
            const header_name = plan.auth_header orelse return error.UnsupportedTransport;
            headers_buf[header_count] = .{ .name = header_name, .value = access_token };
            header_count += 1;
        },
        .none => {},
    }

    if (plan.body != null) {
        headers_buf[header_count] = .{ .name = "Content-Type", .value = plan.content_type orelse "application/json" };
        header_count += 1;
    }

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var server_header_buf: [16 * 1024]u8 = undefined;
    var req = client.open(method, uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = headers_buf[0..header_count],
    }) catch return error.NetworkError;
    defer req.deinit();

    if (plan.body) |body| {
        req.transfer_encoding = .{ .content_length = body.len };
    }

    req.send() catch return error.NetworkError;
    if (plan.body) |body| {
        req.writeAll(body) catch return error.NetworkError;
    }
    req.finish() catch return error.NetworkError;
    req.wait() catch return error.NetworkError;

    var response_buf: [64 * 1024]u8 = undefined;
    const response_len = req.readAll(&response_buf) catch return error.NetworkError;
    const body_hint = if (plan.hint_body and plan.hint_header == null)
        allocator.dupe(u8, response_buf[0..response_len]) catch return error.OutOfMemory
    else
        null;
    errdefer if (body_hint) |hint| allocator.free(hint);

    return .{
        .status = @intFromEnum(req.response.status),
        .retry_after_s = retryAfterSeconds(req.response),
        .hint = if (plan.hint_header) |header_name|
            try dupeHeaderValue(allocator, req.response, header_name)
        else
            body_hint,
    };
}

fn executeCommand(
    allocator: std.mem.Allocator,
    plan: provider_schema.ProbePlan,
    env_pairs: []const [2][]const u8,
) ProbeError!ProbeResult {
    const argv = plan.command orelse return error.UnsupportedTransport;
    if (argv.len == 0) return error.UnsupportedTransport;

    var env_map = std.process.getEnvMap(allocator) catch return error.OutOfMemory;
    defer env_map.deinit();
    for (env_pairs) |pair| {
        env_map.put(pair[0], pair[1]) catch return error.OutOfMemory;
    }

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = &env_map;

    child.spawn() catch |e| {
        const hint = std.fmt.allocPrint(allocator, "probe command spawn failed: {s}", .{@errorName(e)}) catch return error.OutOfMemory;
        return .{ .status = 500, .hint = hint };
    };

    const output = collectCommandOutput(allocator, &child, plan.timeout_ms) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            const hint = std.fmt.allocPrint(allocator, "probe command wait failed: {s}", .{@errorName(e)}) catch return error.OutOfMemory;
            return .{ .status = 500, .hint = hint };
        },
    };
    defer output.deinit(allocator);

    const joined = joinCommandOutput(allocator, output.stdout, output.stderr) catch return error.OutOfMemory;
    errdefer allocator.free(joined);

    if (output.timed_out) {
        const hint = std.fmt.allocPrint(allocator, "probe command timed out after {d}ms\n{s}", .{ plan.timeout_ms, joined }) catch return error.OutOfMemory;
        allocator.free(joined);
        return .{ .status = 408, .hint = hint };
    }

    const status: u16 = switch (output.term) {
        .Exited => |code| if (code == 0) 200 else 400,
        else => 500,
    };

    return .{ .status = status, .hint = joined };
}

fn joinCommandOutput(allocator: std.mem.Allocator, stdout: []const u8, stderr: []const u8) ![]const u8 {
    if (stderr.len == 0) return try allocator.dupe(u8, stdout);
    if (stdout.len == 0) return try allocator.dupe(u8, stderr);

    var out = try std.ArrayList(u8).initCapacity(allocator, stdout.len + 1 + stderr.len);
    errdefer out.deinit();
    try out.appendSlice(stdout);
    if (stdout[stdout.len - 1] != '\n') try out.append('\n');
    try out.appendSlice(stderr);
    return try out.toOwnedSlice();
}

const CommandOutput = struct {
    stdout: []const u8,
    stderr: []const u8,
    term: std.process.Child.Term,
    timed_out: bool = false,

    fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

fn collectCommandOutput(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    timeout_ms: u32,
) ProbeError!CommandOutput {
    var stdout_buf = std.ArrayListUnmanaged(u8){};
    errdefer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    errdefer stderr_buf.deinit(allocator);

    const timed = try collectOutputWithTimeout(
        allocator,
        child,
        &stdout_buf,
        &stderr_buf,
        1024 * 1024,
        timeout_ms,
    );

    const term = if (timed)
        child.kill() catch return error.NetworkError
    else
        child.wait() catch return error.NetworkError;

    const stdout = stdout_buf.toOwnedSlice(allocator) catch return error.OutOfMemory;
    errdefer allocator.free(stdout);
    const stderr = stderr_buf.toOwnedSlice(allocator) catch return error.OutOfMemory;

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .term = term,
        .timed_out = timed,
    };
}

fn collectOutputWithTimeout(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    stdout: *std.ArrayListUnmanaged(u8),
    stderr: *std.ArrayListUnmanaged(u8),
    max_output_bytes: usize,
    timeout_ms: u32,
) ProbeError!bool {
    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    const timeout_ns = @as(i128, timeout_ms) * @as(i128, std.time.ns_per_ms);
    const deadline_ns = std.time.nanoTimestamp() + timeout_ns;

    while (true) {
        if (poller.fifo(.stdout).readableLength() > max_output_bytes or
            poller.fifo(.stderr).readableLength() > max_output_bytes)
        {
            _ = child.kill() catch {};
            return error.NetworkError;
        }

        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) {
            try appendPollFifo(allocator, stdout, poller.fifo(.stdout));
            try appendPollFifo(allocator, stderr, poller.fifo(.stderr));
            return true;
        }

        const remaining_ns = deadline_ns - now;
        const poll_ns_i = @min(remaining_ns, @as(i128, 50 * std.time.ns_per_ms));
        const keep_polling = poller.pollTimeout(@intCast(poll_ns_i)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.NetworkError,
        };
        if (!keep_polling) {
            try appendPollFifo(allocator, stdout, poller.fifo(.stdout));
            try appendPollFifo(allocator, stderr, poller.fifo(.stderr));
            return false;
        }
    }
}

fn appendPollFifo(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    fifo: *std.io.PollFifo,
) !void {
    var offset: usize = 0;
    const total = fifo.readableLength();
    while (offset < total) {
        const chunk = fifo.readableSlice(offset);
        if (chunk.len == 0) break;
        try list.appendSlice(allocator, chunk);
        offset += chunk.len;
    }
}

fn methodFromString(method: []const u8) ?std.http.Method {
    if (std.mem.eql(u8, method, "GET")) return .GET;
    if (std.mem.eql(u8, method, "POST")) return .POST;
    if (std.mem.eql(u8, method, "HEAD")) return .HEAD;
    return null;
}

fn retryAfterSeconds(response: std.http.Client.Response) ?u32 {
    const value = headerValue(response, "retry-after") orelse return null;
    return std.fmt.parseInt(u32, std.mem.trim(u8, value, " \t"), 10) catch null;
}

fn dupeHeaderValue(
    allocator: std.mem.Allocator,
    response: std.http.Client.Response,
    name: []const u8,
) !?[]const u8 {
    const value = headerValue(response, name) orelse return null;
    return try allocator.dupe(u8, value);
}

fn headerValue(response: std.http.Client.Response, name: []const u8) ?[]const u8 {
    var it = response.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "classifyResult honors probe success range" {
    const plan = provider_schema.ProbePlan{
        .capability = "chat:max",
        .transport = .http,
        .method = "POST",
        .url = "https://example.invalid/v1/probe",
        .auth = .bearer,
        .timeout_ms = 30_000,
        .success_status_min = 202,
        .success_status_max = 204,
    };

    try std.testing.expectEqual(
        types.HttpClassification.success,
        classifyResult(std.testing.allocator, provider_schema.generic_def, plan, .{ .status = 204 }),
    );
}

test "classifyResult falls back to provider failure rules" {
    const plan = provider_schema.ProbePlan{
        .capability = "chat:max",
        .transport = .http,
        .method = "POST",
        .url = "https://example.invalid/v1/probe",
        .auth = .bearer,
        .timeout_ms = 30_000,
        .success_status_min = 200,
        .success_status_max = 299,
    };
    const result = ProbeResult{
        .status = 429,
        .retry_after_s = 7200,
    };

    const classified = classifyResult(std.testing.allocator, provider_schema.generic_def, plan, result);
    switch (classified) {
        .quota_exhausted => |quota| try std.testing.expectEqual(@as(u32, 7200), quota.retry_after_s),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyResult uses hint text" {
    const plan = provider_schema.ProbePlan{
        .capability = "tools/design-context",
        .transport = .http,
        .method = "GET",
        .url = "https://example.invalid/mcp",
        .auth = .bearer,
        .timeout_ms = 30_000,
        .success_status_min = 200,
        .success_status_max = 299,
    };
    const result = ProbeResult{
        .status = 403,
        .hint = "Bearer error=\"insufficient_scope\"",
    };

    const classified = classifyResult(std.testing.allocator, provider_schema.mcp_def, plan, result);
    switch (classified) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyResult can downgrade successful GraphQL status from body hint" {
    const plan = provider_schema.ProbePlan{
        .capability = "identity",
        .transport = .http,
        .method = "POST",
        .url = "https://api.linear.app/graphql",
        .body = "{\"query\":\"query Me { viewer { id name email } }\"}",
        .content_type = "application/json",
        .auth = .bearer,
        .timeout_ms = 30_000,
        .success_status_min = 200,
        .success_status_max = 299,
        .hint_body = true,
    };
    const result = ProbeResult{
        .status = 200,
        .hint = "{\"errors\":[{\"message\":\"Forbidden\"}]}",
    };

    const classified = classifyResult(std.testing.allocator, provider_schema.linear_def, plan, result);
    switch (classified) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.unknown_4xx, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyResult decodes codex command jsonl" {
    const plan = provider_schema.ProbePlan{
        .capability = "codex-mini",
        .transport = .command,
        .method = "GET",
        .url = "",
        .command = &.{ "codex", "exec" },
        .auth = .none,
        .timeout_ms = 30_000,
        .success_status_min = 200,
        .success_status_max = 299,
    };
    const result = ProbeResult{
        .status = 400,
        .hint =
        \\{"type":"error","message":"{\"type\":\"error\",\"status\":400,\"error\":{\"message\":\"model is not supported when using Codex with a ChatGPT account\"}}"}
        ,
    };

    const classified = classifyResult(std.testing.allocator, provider_schema.codex_def, plan, result);
    switch (classified) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.tier_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "execute command probe enforces timeout" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const plan = provider_schema.ProbePlan{
        .capability = "toy",
        .transport = .command,
        .method = "GET",
        .url = "",
        .command = &.{ "sh", "-c", "while true; do :; done" },
        .auth = .none,
        .timeout_ms = 1,
        .success_status_min = 200,
        .success_status_max = 299,
    };

    const result = try execute(std.testing.allocator, plan, "", &.{});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 408), result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.hint.?, "timed out") != null);
}
