const std = @import("std");
const paths = @import("paths.zig");

pub const schema = "oauth-mux.trace.v1";

pub const Severity = enum {
    debug,
    info,
    warn,
    err,

    fn label(self: Severity) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
        };
    }
};

pub const AttrValue = union(enum) {
    string: []const u8,
    boolean: bool,
    int: i64,
    uint: u64,
    null_value,
};

pub const Attr = struct {
    key: []const u8,
    value: AttrValue,
};

pub fn string(key: []const u8, value: []const u8) Attr {
    return .{ .key = key, .value = .{ .string = value } };
}

pub fn boolean(key: []const u8, value: bool) Attr {
    return .{ .key = key, .value = .{ .boolean = value } };
}

pub fn int(key: []const u8, value: i64) Attr {
    return .{ .key = key, .value = .{ .int = value } };
}

pub fn uint(key: []const u8, value: u64) Attr {
    return .{ .key = key, .value = .{ .uint = value } };
}

pub fn nullValue(key: []const u8) Attr {
    return .{ .key = key, .value = .null_value };
}

pub fn enabled(allocator: std.mem.Allocator) bool {
    const value = std.process.getEnvVarOwned(allocator, "OMUX_TRACE") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => return false,
        error.OutOfMemory => return false,
        else => return false,
    };
    defer allocator.free(value);
    return traceValueEnabled(value);
}

pub fn append(allocator: std.mem.Allocator, name: []const u8, severity: Severity, attrs: []const Attr) void {
    if (!enabled(allocator)) return;
    appendInternal(allocator, name, severity, attrs) catch {};
}

pub fn writeEventForTest(writer: anytype, name: []const u8, severity: Severity, attrs: []const Attr) !void {
    try writeEvent(writer, .{
        .ts_unix_ms = 1_800_000_000_000,
        .trace_id = "00000000000000000000000000000000",
        .span_id = "0000000000000000",
        .parent_span_id = null,
    }, name, severity, attrs);
}

const EventContext = struct {
    ts_unix_ms: i64,
    trace_id: []const u8,
    span_id: []const u8,
    parent_span_id: ?[]const u8,
};

fn appendInternal(allocator: std.mem.Allocator, name: []const u8, severity: Severity, attrs: []const Attr) !void {
    const trace_path = try traceFilePath(allocator);
    defer allocator.free(trace_path);
    try ensureParentDir(trace_path);

    const file = try createOrAppendFile(trace_path);
    defer file.close();
    try file.seekFromEnd(0);

    const ctx = try eventContext(allocator);
    defer ctx.deinit(allocator);

    try writeEvent(file.writer(), ctx.value, name, severity, attrs);
    try file.writeAll("\n");
}

const OwnedEventContext = struct {
    value: EventContext,
    trace_id_owned: ?[]const u8 = null,
    span_id_owned: ?[]const u8 = null,
    parent_span_id_owned: ?[]const u8 = null,

    fn deinit(self: OwnedEventContext, allocator: std.mem.Allocator) void {
        if (self.trace_id_owned) |value| allocator.free(value);
        if (self.span_id_owned) |value| allocator.free(value);
        if (self.parent_span_id_owned) |value| allocator.free(value);
    }
};

fn eventContext(allocator: std.mem.Allocator) !OwnedEventContext {
    const trace_id = try envOrDefault(allocator, "OMUX_TRACE_ID", "00000000000000000000000000000000");
    errdefer if (trace_id.owned) |value| allocator.free(value);
    const span_id = try envOrDefault(allocator, "OMUX_SPAN_ID", "0000000000000000");
    errdefer if (span_id.owned) |value| allocator.free(value);
    const parent_span_id = std.process.getEnvVarOwned(allocator, "OMUX_PARENT_SPAN_ID") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        else => return e,
    };

    return .{
        .value = .{
            .ts_unix_ms = std.time.milliTimestamp(),
            .trace_id = trace_id.value,
            .span_id = span_id.value,
            .parent_span_id = parent_span_id,
        },
        .trace_id_owned = trace_id.owned,
        .span_id_owned = span_id.owned,
        .parent_span_id_owned = parent_span_id,
    };
}

const EnvValue = struct {
    value: []const u8,
    owned: ?[]const u8 = null,
};

fn envOrDefault(allocator: std.mem.Allocator, name: []const u8, default: []const u8) !EnvValue {
    const value = std.process.getEnvVarOwned(allocator, name) catch |e| switch (e) {
        error.EnvironmentVariableNotFound => return .{ .value = default },
        else => return e,
    };
    if (value.len == 0) {
        allocator.free(value);
        return .{ .value = default };
    }
    return .{ .value = value, .owned = value };
}

fn traceFilePath(allocator: std.mem.Allocator) ![]const u8 {
    if (std.process.getEnvVarOwned(allocator, "OMUX_TRACE_FILE")) |value| {
        if (value.len == 0) {
            allocator.free(value);
        } else {
            defer allocator.free(value);
            return try paths.absolutePath(allocator, value);
        }
    } else |e| switch (e) {
        error.EnvironmentVariableNotFound => {},
        else => return e,
    }

    const state_dir = try paths.stateDir(allocator);
    defer allocator.free(state_dir);
    return std.fs.path.join(allocator, &.{ state_dir, "trace.ndjson" });
}

fn ensureParentDir(path_value: []const u8) !void {
    if (std.fs.path.dirname(path_value)) |dir| {
        std.fs.cwd().makePath(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }
}

fn createOrAppendFile(path_value: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path_value)) {
        return std.fs.createFileAbsolute(path_value, .{
            .truncate = false,
            .mode = 0o600,
            .lock = .exclusive,
        });
    }
    return std.fs.cwd().createFile(path_value, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
    });
}

fn writeEvent(writer: anytype, ctx: EventContext, name: []const u8, severity: Severity, attrs: []const Attr) !void {
    try writer.writeAll("{\"schema\":");
    try std.json.stringify(schema, .{}, writer);
    try writer.print(",\"ts_unix_ms\":{d}", .{ctx.ts_unix_ms});
    try writer.writeAll(",\"name\":");
    try std.json.stringify(name, .{}, writer);
    try writer.writeAll(",\"severity\":");
    try std.json.stringify(severity.label(), .{}, writer);
    try writer.writeAll(",\"trace_id\":");
    try std.json.stringify(ctx.trace_id, .{}, writer);
    try writer.writeAll(",\"span_id\":");
    try std.json.stringify(ctx.span_id, .{}, writer);
    try writer.writeAll(",\"parent_span_id\":");
    if (ctx.parent_span_id) |value| try std.json.stringify(value, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"attributes\":{");
    for (attrs, 0..) |attr, idx| {
        if (idx != 0) try writer.writeByte(',');
        try std.json.stringify(attr.key, .{}, writer);
        try writer.writeByte(':');
        try writeAttrValue(writer, attr.value);
    }
    try writer.writeAll("},\"redaction\":{\"tokens\":false,\"raw_account_ids\":false,\"session_ids\":false,\"paths\":false}}");
}

fn writeAttrValue(writer: anytype, value: AttrValue) !void {
    switch (value) {
        .string => |v| try std.json.stringify(v, .{}, writer),
        .boolean => |v| try writer.writeAll(if (v) "true" else "false"),
        .int => |v| try writer.print("{d}", .{v}),
        .uint => |v| try writer.print("{d}", .{v}),
        .null_value => try writer.writeAll("null"),
    }
}

test "trace events use stable redacted OTEL-friendly shape" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeEventForTest(buf.writer(), "route.evaluate", .info, &.{
        string("provider", "codex"),
        string("account_label", "max-1"),
        boolean("selectable", true),
        uint("route_count", 4),
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"schema\":\"oauth-mux.trace.v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"trace_id\":\"00000000000000000000000000000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"span_id\":\"0000000000000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"name\":\"route.evaluate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"tokens\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"paths\":false") != null);
}

test "trace disabled values stay disabled" {
    try std.testing.expect(!traceValueEnabled(""));
    try std.testing.expect(!traceValueEnabled("0"));
    try std.testing.expect(!traceValueEnabled("false"));
    try std.testing.expect(!traceValueEnabled("off"));
    try std.testing.expect(traceValueEnabled("1"));
    try std.testing.expect(traceValueEnabled("otel"));
}

fn traceValueEnabled(value: []const u8) bool {
    if (value.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(value, "0")) return false;
    if (std.ascii.eqlIgnoreCase(value, "false")) return false;
    if (std.ascii.eqlIgnoreCase(value, "off")) return false;
    if (std.ascii.eqlIgnoreCase(value, "no")) return false;
    return true;
}
