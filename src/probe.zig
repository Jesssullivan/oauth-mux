const std = @import("std");
const types = @import("types.zig");
const provider_schema = @import("provider_schema.zig");

pub const ProbeError = error{
    UnsupportedMethod,
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
    def: provider_schema.ProviderDefinition,
    plan: provider_schema.ProbePlan,
    result: ProbeResult,
) types.HttpClassification {
    if (result.status >= plan.success_status_min and result.status <= plan.success_status_max) {
        return .success;
    }
    return provider_schema.classifyHttp(def, result.status, result.retry_after_s, result.hint);
}

pub fn execute(
    allocator: std.mem.Allocator,
    plan: provider_schema.ProbePlan,
    access_token: []const u8,
) ProbeError!ProbeResult {
    const method = methodFromString(plan.method) orelse return error.UnsupportedMethod;
    const uri = std.Uri.parse(plan.url) catch return error.NetworkError;

    var bearer_value: ?[]u8 = null;
    defer if (bearer_value) |value| allocator.free(value);

    var headers_buf: [3]std.http.Header = undefined;
    var header_count: usize = 0;
    headers_buf[header_count] = .{ .name = "Accept", .value = "application/json" };
    header_count += 1;

    if (plan.auth == .bearer) {
        bearer_value = std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}) catch return error.OutOfMemory;
        headers_buf[header_count] = .{ .name = "Authorization", .value = bearer_value.? };
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

    req.send() catch return error.NetworkError;
    req.finish() catch return error.NetworkError;
    req.wait() catch return error.NetworkError;

    var drain_buf: [4096]u8 = undefined;
    _ = req.readAll(&drain_buf) catch return error.NetworkError;

    return .{
        .status = @intFromEnum(req.response.status),
        .retry_after_s = retryAfterSeconds(req.response),
        .hint = if (plan.hint_header) |header_name|
            try dupeHeaderValue(allocator, req.response, header_name)
        else
            null,
    };
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
        .method = "POST",
        .url = "https://example.invalid/v1/probe",
        .auth = .bearer,
        .success_status_min = 202,
        .success_status_max = 204,
    };

    try std.testing.expectEqual(
        types.HttpClassification.success,
        classifyResult(provider_schema.generic_def, plan, .{ .status = 204 }),
    );
}

test "classifyResult falls back to provider failure rules" {
    const plan = provider_schema.ProbePlan{
        .capability = "chat:max",
        .method = "POST",
        .url = "https://example.invalid/v1/probe",
        .auth = .bearer,
        .success_status_min = 200,
        .success_status_max = 299,
    };
    const result = ProbeResult{
        .status = 429,
        .retry_after_s = 7200,
    };

    const classified = classifyResult(provider_schema.generic_def, plan, result);
    switch (classified) {
        .quota_exhausted => |quota| try std.testing.expectEqual(@as(u32, 7200), quota.retry_after_s),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyResult uses hint text" {
    const plan = provider_schema.ProbePlan{
        .capability = "tools/design-context",
        .method = "GET",
        .url = "https://example.invalid/mcp",
        .auth = .bearer,
        .success_status_min = 200,
        .success_status_max = 299,
    };
    const result = ProbeResult{
        .status = 403,
        .hint = "Bearer error=\"insufficient_scope\"",
    };

    const classified = classifyResult(provider_schema.mcp_def, plan, result);
    switch (classified) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}
