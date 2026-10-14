//! Read-only enrollment wait selection. No credential, provider or retry authority.
const std = @import("std");

pub const Selection = struct { operation_id: []const u8, operation_generation: u64, admitted_revision: u64 };
pub const State = enum { pending, completed, failed };

fn get(value: std.json.Value, field: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidEnrollmentWaitReply;
    return value.object.get(field) orelse error.InvalidEnrollmentWaitReply;
}
fn string(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.InvalidEnrollmentWaitReply;
    return value.string;
}
fn unsigned(value: std.json.Value) !u64 {
    return switch (value) {
        .integer => |v| if (v >= 0) @intCast(v) else error.InvalidEnrollmentWaitReply,
        .number_string => |v| blk: {
            if (v.len == 0 or (v.len > 1 and v[0] == '0')) return error.InvalidEnrollmentWaitReply;
            for (v) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidEnrollmentWaitReply;
            break :blk std.fmt.parseInt(u64, v, 10) catch return error.InvalidEnrollmentWaitReply;
        },
        else => error.InvalidEnrollmentWaitReply,
    };
}
pub fn result(reply: std.json.Value) !std.json.Value {
    if (reply != .object or
        !std.mem.eql(u8, try string(try get(reply, "jsonrpc")), "2.0") or
        try unsigned(try get(reply, "id")) != 1) return error.InvalidEnrollmentWaitReply;
    if (reply.object.get("error")) |failure| {
        if (reply.object.contains("result") or failure != .object) return error.InvalidEnrollmentWaitReply;
        _ = try string(try get(failure, "message"));
        const code = try get(failure, "code");
        switch (code) {
            .integer => {},
            .number_string => |v| {
                _ = std.fmt.parseInt(i64, v, 10) catch return error.InvalidEnrollmentWaitReply;
            },
            else => return error.InvalidEnrollmentWaitReply,
        }
        return error.EnrollmentRequestRejected;
    }
    const value = try get(reply, "result");
    if (value != .object) return error.InvalidEnrollmentWaitReply;
    return value;
}
pub fn selection(reply: std.json.Value) !Selection {
    const value = try result(reply);
    if (value.object.count() != 4 or !std.mem.eql(u8, try string(try get(value, "status")), "verifying_identity"))
        return error.InvalidEnrollmentWaitReply;
    const id = try string(try get(value, "operation_id"));
    // Daemon job handles are opaque metadata. Never derive a job from a source.
    if (id.len == 0 or id.len > 4096 or !std.unicode.utf8ValidateSlice(id) or std.mem.indexOfScalar(u8, id, 0) != null)
        return error.InvalidEnrollmentWaitReply;
    const generation = try unsigned(try get(value, "operation_generation"));
    const revision = try unsigned(try get(value, "admitted_revision"));
    if (generation == 0 or revision == 0) return error.InvalidEnrollmentWaitReply;
    return .{ .operation_id = id, .operation_generation = generation, .admitted_revision = revision };
}
pub fn observe(selected: Selection, reply: std.json.Value) !State {
    const snapshot = try result(reply);
    if (try unsigned(try get(snapshot, "protocol_version")) != 2) return error.InvalidEnrollmentWaitReply;
    const custody = try get(snapshot, "custody_available");
    if (custody != .bool) return error.InvalidEnrollmentWaitReply;
    if (!custody.bool) return error.EnrollmentCustodyUnavailable;
    if (try unsigned(try get(snapshot, "revision")) < selected.admitted_revision) return error.EnrollmentObservationStale;
    const jobs = try get(snapshot, "jobs");
    if (jobs != .array or jobs.array.items.len > 1024) return error.InvalidEnrollmentWaitReply;
    var matched: ?State = null;
    for (jobs.array.items) |job| {
        const id = try string(try get(job, "id"));
        if (!std.mem.eql(u8, id, selected.operation_id)) continue;
        if (matched != null) return error.InvalidEnrollmentWaitReply;
        if (!std.mem.eql(u8, try string(try get(job, "kind")), "enrollment")) return error.InvalidEnrollmentWaitReply;
        if (try unsigned(try get(job, "operation_generation")) != selected.operation_generation) return error.EnrollmentSuperseded;
        const status = try string(try get(job, "status"));
        matched = if (std.mem.eql(u8, status, "pending") or std.mem.eql(u8, status, "running")) .pending else if (std.mem.eql(u8, status, "completed")) .completed else if (std.mem.eql(u8, status, "failed")) .failed else return error.InvalidEnrollmentWaitReply;
    }
    return matched orelse error.EnrollmentJobMissing;
}

test "original acknowledgement binds generation and committed admission revision" {
    const bytes = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"operation_id\":\"opaque-job\",\"status\":\"verifying_identity\",\"operation_generation\":7,\"admitted_revision\":12}}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{ .parse_numbers = false, .duplicate_field_behavior = .@"error" });
    defer parsed.deinit();
    const selected = try selection(parsed.value);
    try std.testing.expectEqual(@as(u64, 7), selected.operation_generation);
    try std.testing.expectEqual(@as(u64, 12), selected.admitted_revision);
}
test "snapshot refuses stale missing duplicate superseded and unavailable outcomes" {
    const selected: Selection = .{ .operation_id = "opaque-job", .operation_generation = 7, .admitted_revision = 12 };
    const cases = .{
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":7,\"status\":\"completed\"}]", @as(?anyerror, null), State.completed },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":7,\"status\":\"failed\"}]", @as(?anyerror, null), State.failed },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":7,\"status\":\"running\"}]", @as(?anyerror, null), State.pending },
        .{ "false", "12", "[]", @as(?anyerror, error.EnrollmentCustodyUnavailable), State.pending },
        .{ "true", "11", "[]", @as(?anyerror, error.EnrollmentObservationStale), State.pending },
        .{ "true", "12", "[]", @as(?anyerror, error.EnrollmentJobMissing), State.pending },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":8,\"status\":\"completed\"}]", @as(?anyerror, error.EnrollmentSuperseded), State.pending },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"repair\",\"operation_generation\":7,\"status\":\"completed\"}]", @as(?anyerror, error.InvalidEnrollmentWaitReply), State.pending },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":true,\"status\":\"completed\"}]", @as(?anyerror, error.InvalidEnrollmentWaitReply), State.pending },
        .{ "true", "12", "[{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":7,\"status\":\"completed\"},{\"id\":\"opaque-job\",\"kind\":\"enrollment\",\"operation_generation\":7,\"status\":\"completed\"}]", @as(?anyerror, error.InvalidEnrollmentWaitReply), State.pending },
    };
    inline for (cases) |case| {
        const bytes = try std.fmt.allocPrint(std.testing.allocator, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocol_version\":2,\"revision\":{s},\"custody_available\":{s},\"jobs\":{s}}}}}", .{ case[1], case[0], case[2] });
        defer std.testing.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{ .parse_numbers = false, .duplicate_field_behavior = .@"error" });
        defer parsed.deinit();
        if (case[3]) |expected| try std.testing.expectError(expected, observe(selected, parsed.value)) else try std.testing.expectEqual(case[4], try observe(selected, parsed.value));
    }
}

test "declared error envelope stays rejected without exposing message as outcome" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"SourceUnauthorized\"}}", .{ .parse_numbers = false, .duplicate_field_behavior = .@"error" });
    defer parsed.deinit();
    try std.testing.expectError(error.EnrollmentRequestRejected, selection(parsed.value));
}
