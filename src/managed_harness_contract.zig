//! Declaration-only managed harness process contract for v0.2.
//!
//! This module owns the checked JSON Schema projection. It deliberately does
//! not dispatch methods or launch a harness.

const std = @import("std");

const Value = std.json.Value;

pub const surface_version: u32 = 2;
pub const protocol_name = "managed-harness-jsonrpc";
pub const protocol_status = "planned_unshipped";
pub const method_status = "not_implemented";
pub const not_implemented_error_code: i32 = -32099;
pub const unknown_method_error_code: i32 = -32601;
pub const max_upstream_attempts: u8 = 2;

pub const MethodSpec = struct {
    name: []const u8,
    schema_key: []const u8,
    lifecycle_phase: []const u8,
    required_params: []const []const u8,
    required_result_fields: []const []const u8,
};

const no_fields = [_][]const u8{};
const surface_info_result = [_][]const u8{ "surface_version", "status", "methods" };
const preflight_params = [_][]const u8{ "harness", "model_demand" };
const preflight_result = [_][]const u8{ "ready", "harness_handle", "reasons" };
const launch_params = [_][]const u8{ "harness_handle", "model_demand" };
const launch_result = [_][]const u8{ "session_handle", "route_handle", "state" };
const lease_params = [_][]const u8{"session_handle"};
const lease_result = [_][]const u8{ "session_handle", "leases", "observed_at_ms" };
const transition_params = [_][]const u8{ "session_handle", "model_demand", "proxy_attempts" };
const transition_result = [_][]const u8{ "state", "selected_route_handle", "action_required" };
const repair_params = [_][]const u8{ "session_handle", "reason" };
const repair_result = [_][]const u8{ "handoff_handle", "action" };
const teardown_params = [_][]const u8{"session_handle"};
const teardown_result = [_][]const u8{"complete"};

pub const methods = [_]MethodSpec{
    method("surface/info", "surface_info", "discovery", &no_fields, &surface_info_result),
    method("harness/preflight", "harness_preflight", "preflight", &preflight_params, &preflight_result),
    method("session/launch", "session_launch", "launch", &launch_params, &launch_result),
    method("route/lease_snapshot", "route_lease_snapshot", "observe", &lease_params, &lease_result),
    method("session/transition", "session_transition", "transition", &transition_params, &transition_result),
    method("repair/handoff", "repair_handoff", "repair", &repair_params, &repair_result),
    method("session/teardown", "session_teardown", "teardown", &teardown_params, &teardown_result),
};

const forbidden_methods = [_][]const u8{
    "credential/materialize",
    "process/restart",
    "session/respawn",
    "harness/relaunch",
    "auth/login_browser",
    "provider/probe",
};

const forbidden_field_fragments = [_][]const u8{
    "credential",
    "token",
    "authorization",
    "cookie",
    "env",
    "argv",
    "prompt",
    "response_body",
    "raw_account",
};

const envelope_required = [_][]const u8{ "jsonrpc", "id", "method", "params" };
const success_required = [_][]const u8{ "jsonrpc", "id", "result" };
const error_response_required = [_][]const u8{ "jsonrpc", "id", "error" };
const error_required = [_][]const u8{ "code", "message", "data" };
const model_demand_required = [_][]const u8{ "model", "preservation" };
const attempt_required = [_][]const u8{ "ordinal", "account_handle", "route_handle", "model_demand", "outcome", "response_started" };
const method_status_required = [_][]const u8{ "name", "implementation_status" };
const attempt_outcomes = [_][]const u8{ "retained", "switched", "refused", "unproven" };
const transition_states = [_][]const u8{ "ready", "running", "retained", "switched", "refused", "action_required", "teardown_complete" };

fn method(
    name: []const u8,
    schema_key: []const u8,
    lifecycle_phase: []const u8,
    required_params: []const []const u8,
    required_result_fields: []const []const u8,
) MethodSpec {
    return .{
        .name = name,
        .schema_key = schema_key,
        .lifecycle_phase = lifecycle_phase,
        .required_params = required_params,
        .required_result_fields = required_result_fields,
    };
}

pub fn renderSchema(allocator: std.mem.Allocator) ![]u8 {
    try validateStatic();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var root = object(scratch);
    try put(&root, "$schema", string("https://json-schema.org/draft/2020-12/schema"));
    try put(&root, "$id", string("https://omux.dev/schemas/managed-harness-jsonrpc-v2.schema.json"));
    try put(&root, "title", string("omux managed-harness JSON-RPC surface v2"));
    try put(&root, "description", string("Declaration-only compatibility contract. Every listed method is unimplemented until adapter proof lands."));

    var wire_variants = array(scratch);
    for (methods) |entry| {
        try append(&wire_variants, try refSchema(scratch, try schemaRef(scratch, "request", entry.schema_key)));
    }
    try append(&wire_variants, try refSchema(scratch, "#/$defs/success_response"));
    try append(&wire_variants, try refSchema(scratch, "#/$defs/not_implemented_response"));
    try append(&wire_variants, try refSchema(scratch, "#/$defs/unknown_method_response"));
    try put(&root, "oneOf", wire_variants);
    try put(&root, "x-omux-surface", try surfaceMetadata(scratch));

    var definitions = object(scratch);
    try put(&definitions, "safe_extension_value", try safeExtensionValueSchema(scratch));
    try put(&definitions, "opaque_handle", try opaqueHandleSchema(scratch));
    try put(&definitions, "handle_or_null", try handleOrNullSchema(scratch));
    try put(&definitions, "label", try boundedStringSchema(scratch, 1, 256));
    try put(&definitions, "redacted_reason", try boundedStringSchema(scratch, 1, 1024));
    try put(&definitions, "boolean", try typeSchema(scratch, "boolean"));
    try put(&definitions, "nonnegative_integer", try minimumIntegerSchema(scratch, 0));
    try put(&definitions, "string_array", try arrayOf(scratch, try boundedStringSchema(scratch, 0, 1024), null));
    try put(&definitions, "open_object", try openObjectSchema(scratch));
    try put(&definitions, "open_object_array", try arrayOf(scratch, try openObjectSchema(scratch), null));
    try put(&definitions, "transition_state", try enumSchema(scratch, &transition_states));
    try put(&definitions, "model_demand", try modelDemandSchema(scratch));
    try put(&definitions, "proxy_attempt", try proxyAttemptSchema(scratch));
    try put(&definitions, "proxy_attempts", try arrayOf(scratch, try refSchema(scratch, "#/$defs/proxy_attempt"), max_upstream_attempts));
    try put(&definitions, "method_statuses", try methodStatusesSchema(scratch));
    try put(&definitions, "surface_version_const", try constIntegerSchema(scratch, surface_version));
    try put(&definitions, "protocol_status_const", try constStringSchema(scratch, protocol_status));

    var result_refs = array(scratch);
    for (methods) |entry| {
        const request_key = try std.fmt.allocPrint(scratch, "request_{s}", .{entry.schema_key});
        const result_key = try std.fmt.allocPrint(scratch, "result_{s}", .{entry.schema_key});
        try put(&definitions, request_key, try methodRequestSchema(scratch, entry));
        try put(&definitions, result_key, try methodResultSchema(scratch, entry));
        try append(&result_refs, try refSchema(scratch, try schemaRef(scratch, "result", entry.schema_key)));
    }

    try put(&definitions, "success_response", try successResponseSchema(scratch, result_refs));
    try put(&definitions, "not_implemented_error", try errorSchema(scratch, not_implemented_error_code, "method not implemented"));
    try put(&definitions, "unknown_method_error", try errorSchema(scratch, unknown_method_error_code, "method not found"));
    try put(&definitions, "not_implemented_response", try errorResponseSchema(scratch, "#/$defs/not_implemented_error"));
    try put(&definitions, "unknown_method_response", try errorResponseSchema(scratch, "#/$defs/unknown_method_error"));
    try put(&root, "$defs", definitions);

    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();
    try std.json.stringify(root, .{ .whitespace = .indent_2 }, output.writer());
    try output.append('\n');
    return output.toOwnedSlice();
}

fn surfaceMetadata(allocator: std.mem.Allocator) !Value {
    var metadata = object(allocator);
    try put(&metadata, "surface_version", integer(surface_version));
    try put(&metadata, "protocol_name", string(protocol_name));
    try put(&metadata, "status", string(protocol_status));
    try put(&metadata, "exact_model_required", boolean(true));
    try put(&metadata, "max_upstream_attempts", integer(max_upstream_attempts));

    var method_values = array(allocator);
    for (methods) |entry| {
        var method_value = object(allocator);
        try put(&method_value, "name", string(entry.name));
        try put(&method_value, "lifecycle_phase", string(entry.lifecycle_phase));
        try put(&method_value, "implementation_status", string(method_status));
        try put(&method_value, "request_schema", string(try schemaRef(allocator, "request", entry.schema_key)));
        try put(&method_value, "result_schema", string(try schemaRef(allocator, "result", entry.schema_key)));
        try put(&method_value, "required_params", try stringArray(allocator, entry.required_params));
        try put(&method_value, "required_result_fields", try stringArray(allocator, entry.required_result_fields));
        try put(&method_value, "unknown_fields", string("tolerated_except_sensitive_names"));
        try append(&method_values, method_value);
    }
    try put(&metadata, "methods", method_values);
    return metadata;
}

fn methodRequestSchema(allocator: std.mem.Allocator, entry: MethodSpec) !Value {
    var properties = object(allocator);
    try put(&properties, "jsonrpc", try constStringSchema(allocator, "2.0"));
    try put(&properties, "id", try idSchema(allocator));
    try put(&properties, "method", try constStringSchema(allocator, entry.name));
    try put(&properties, "params", try methodFieldsSchema(allocator, entry.required_params, false));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &envelope_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn methodResultSchema(allocator: std.mem.Allocator, entry: MethodSpec) !Value {
    return methodFieldsSchema(allocator, entry.required_result_fields, true);
}

fn methodFieldsSchema(
    allocator: std.mem.Allocator,
    required_fields: []const []const u8,
    is_result: bool,
) !Value {
    var properties = object(allocator);
    for (required_fields) |field| {
        try put(&properties, field, try fieldSchema(allocator, field, is_result));
    }

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, required_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn fieldSchema(allocator: std.mem.Allocator, field: []const u8, is_result: bool) !Value {
    if (std.mem.eql(u8, field, "model_demand")) return refSchema(allocator, "#/$defs/model_demand");
    if (std.mem.eql(u8, field, "proxy_attempts")) return refSchema(allocator, "#/$defs/proxy_attempts");
    if (std.mem.eql(u8, field, "selected_route_handle")) return refSchema(allocator, "#/$defs/handle_or_null");
    if (std.mem.endsWith(u8, field, "_handle")) return refSchema(allocator, "#/$defs/opaque_handle");
    if (std.mem.eql(u8, field, "harness")) return refSchema(allocator, "#/$defs/label");
    if (std.mem.eql(u8, field, "reason")) return refSchema(allocator, "#/$defs/redacted_reason");
    if (!is_result) return error.UnknownManagedHarnessParam;

    if (std.mem.eql(u8, field, "surface_version")) return refSchema(allocator, "#/$defs/surface_version_const");
    if (std.mem.eql(u8, field, "status")) return refSchema(allocator, "#/$defs/protocol_status_const");
    if (std.mem.eql(u8, field, "methods")) return refSchema(allocator, "#/$defs/method_statuses");
    if (std.mem.eql(u8, field, "ready") or std.mem.eql(u8, field, "complete")) return refSchema(allocator, "#/$defs/boolean");
    if (std.mem.eql(u8, field, "reasons")) return refSchema(allocator, "#/$defs/string_array");
    if (std.mem.eql(u8, field, "state")) return refSchema(allocator, "#/$defs/transition_state");
    if (std.mem.eql(u8, field, "leases")) return refSchema(allocator, "#/$defs/open_object_array");
    if (std.mem.eql(u8, field, "observed_at_ms")) return refSchema(allocator, "#/$defs/nonnegative_integer");
    if (std.mem.eql(u8, field, "action_required") or std.mem.eql(u8, field, "action")) return refSchema(allocator, "#/$defs/open_object");
    return error.UnknownManagedHarnessResultField;
}

fn successResponseSchema(allocator: std.mem.Allocator, result_refs: Value) !Value {
    var result = object(allocator);
    try put(&result, "anyOf", result_refs);

    var properties = object(allocator);
    try put(&properties, "jsonrpc", try constStringSchema(allocator, "2.0"));
    try put(&properties, "id", try idSchema(allocator));
    try put(&properties, "result", result);

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &success_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn errorResponseSchema(allocator: std.mem.Allocator, error_ref: []const u8) !Value {
    var properties = object(allocator);
    try put(&properties, "jsonrpc", try constStringSchema(allocator, "2.0"));
    try put(&properties, "id", try idSchema(allocator));
    try put(&properties, "error", try refSchema(allocator, error_ref));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &error_response_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn errorSchema(allocator: std.mem.Allocator, code: i32, message: []const u8) !Value {
    var properties = object(allocator);
    try put(&properties, "code", try constIntegerSchema(allocator, code));
    try put(&properties, "message", try constStringSchema(allocator, message));
    try put(&properties, "data", try openObjectSchema(allocator));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &error_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn modelDemandSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "model", try boundedStringSchema(allocator, 1, 256));
    try put(&properties, "preservation", try constStringSchema(allocator, "exact"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &model_demand_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn proxyAttemptSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "ordinal", try boundedIntegerSchema(allocator, 1, max_upstream_attempts));
    try put(&properties, "account_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "model_demand", try refSchema(allocator, "#/$defs/model_demand"));
    try put(&properties, "outcome", try enumSchema(allocator, &attempt_outcomes));
    try put(&properties, "response_started", try typeSchema(allocator, "boolean"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &attempt_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn methodStatusesSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "name", try enumSchema(allocator, methodNames()));
    try put(&properties, "implementation_status", try constStringSchema(allocator, method_status));
    var item = try objectSchemaBase(allocator);
    try put(&item, "required", try stringArray(allocator, &method_status_required));
    try put(&item, "properties", properties);
    var schema = try arrayOf(allocator, item, methods.len);
    try put(&schema, "minItems", integer(methods.len));
    try put(&schema, "uniqueItems", boolean(true));
    return schema;
}

fn objectSchemaBase(allocator: std.mem.Allocator) !Value {
    var schema = object(allocator);
    try put(&schema, "type", string("object"));
    try put(&schema, "additionalProperties", try refSchema(allocator, "#/$defs/safe_extension_value"));
    try put(&schema, "propertyNames", try propertyNamesSchema(allocator));
    return schema;
}

fn openObjectSchema(allocator: std.mem.Allocator) !Value {
    return objectSchemaBase(allocator);
}

fn propertyNamesSchema(allocator: std.mem.Allocator) !Value {
    var forbidden = object(allocator);
    try put(&forbidden, "pattern", string("(credential|token|authorization|cookie|env|argv|prompt|response_body|raw_account)"));
    var schema = object(allocator);
    try put(&schema, "pattern", string("^[a-z][a-z0-9_-]*$"));
    try put(&schema, "not", forbidden);
    return schema;
}

fn safeExtensionValueSchema(allocator: std.mem.Allocator) !Value {
    var variants = array(allocator);
    try append(&variants, try typeSchema(allocator, "null"));
    try append(&variants, try typeSchema(allocator, "boolean"));
    try append(&variants, try typeSchema(allocator, "number"));
    try append(&variants, try typeSchema(allocator, "string"));

    var array_value = try typeSchema(allocator, "array");
    try put(&array_value, "items", try refSchema(allocator, "#/$defs/safe_extension_value"));
    try append(&variants, array_value);

    var object_value = object(allocator);
    try put(&object_value, "type", string("object"));
    try put(&object_value, "propertyNames", try propertyNamesSchema(allocator));
    try put(&object_value, "additionalProperties", try refSchema(allocator, "#/$defs/safe_extension_value"));
    try append(&variants, object_value);

    var schema = object(allocator);
    try put(&schema, "oneOf", variants);
    return schema;
}

fn opaqueHandleSchema(allocator: std.mem.Allocator) !Value {
    var schema = try boundedStringSchema(allocator, 1, 256);
    try put(&schema, "pattern", string("^[A-Za-z0-9_-]+$"));
    return schema;
}

fn handleOrNullSchema(allocator: std.mem.Allocator) !Value {
    var options = array(allocator);
    try append(&options, try refSchema(allocator, "#/$defs/opaque_handle"));
    try append(&options, try typeSchema(allocator, "null"));
    var schema = object(allocator);
    try put(&schema, "oneOf", options);
    return schema;
}

fn idSchema(allocator: std.mem.Allocator) !Value {
    var options = array(allocator);
    try append(&options, try typeSchema(allocator, "string"));
    try append(&options, try typeSchema(allocator, "integer"));
    var schema = object(allocator);
    try put(&schema, "oneOf", options);
    return schema;
}

fn boundedStringSchema(allocator: std.mem.Allocator, minimum: usize, maximum: usize) !Value {
    var schema = try typeSchema(allocator, "string");
    try put(&schema, "minLength", integer(minimum));
    try put(&schema, "maxLength", integer(maximum));
    return schema;
}

fn boundedIntegerSchema(allocator: std.mem.Allocator, minimum: i64, maximum: i64) !Value {
    var schema = try typeSchema(allocator, "integer");
    try put(&schema, "minimum", integer(minimum));
    try put(&schema, "maximum", integer(maximum));
    return schema;
}

fn minimumIntegerSchema(allocator: std.mem.Allocator, minimum: i64) !Value {
    var schema = try typeSchema(allocator, "integer");
    try put(&schema, "minimum", integer(minimum));
    return schema;
}

fn constStringSchema(allocator: std.mem.Allocator, value: []const u8) !Value {
    var schema = try typeSchema(allocator, "string");
    try put(&schema, "const", string(value));
    return schema;
}

fn constIntegerSchema(allocator: std.mem.Allocator, value: i64) !Value {
    var schema = try typeSchema(allocator, "integer");
    try put(&schema, "const", integer(value));
    return schema;
}

fn enumSchema(allocator: std.mem.Allocator, values: []const []const u8) !Value {
    var schema = try typeSchema(allocator, "string");
    try put(&schema, "enum", try stringArray(allocator, values));
    return schema;
}

fn typeSchema(allocator: std.mem.Allocator, type_name: []const u8) !Value {
    var schema = object(allocator);
    try put(&schema, "type", string(type_name));
    return schema;
}

fn arrayOf(allocator: std.mem.Allocator, item_schema: Value, maximum: ?usize) !Value {
    var schema = try typeSchema(allocator, "array");
    if (maximum) |max_items| try put(&schema, "maxItems", integer(max_items));
    try put(&schema, "items", item_schema);
    return schema;
}

fn refSchema(allocator: std.mem.Allocator, reference: []const u8) !Value {
    var schema = object(allocator);
    try put(&schema, "$ref", string(reference));
    return schema;
}

fn schemaRef(allocator: std.mem.Allocator, prefix: []const u8, key: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "#/$defs/{s}_{s}", .{ prefix, key });
}

fn methodNames() []const []const u8 {
    const names = comptime blk: {
        var values: [methods.len][]const u8 = undefined;
        for (methods, 0..) |entry, index| values[index] = entry.name;
        break :blk values;
    };
    return &names;
}

fn stringArray(allocator: std.mem.Allocator, values: []const []const u8) !Value {
    var result = array(allocator);
    for (values) |value| try append(&result, string(value));
    return result;
}

fn object(allocator: std.mem.Allocator) Value {
    return .{ .object = std.json.ObjectMap.init(allocator) };
}

fn array(allocator: std.mem.Allocator) Value {
    return .{ .array = std.json.Array.init(allocator) };
}

fn string(value: []const u8) Value {
    return .{ .string = value };
}

fn integer(value: anytype) Value {
    return .{ .integer = @intCast(value) };
}

fn boolean(value: bool) Value {
    return .{ .bool = value };
}

fn put(target: *Value, key: []const u8, value: Value) !void {
    switch (target.*) {
        .object => |*map| try map.put(key, value),
        else => unreachable,
    }
}

fn append(target: *Value, value: Value) !void {
    switch (target.*) {
        .array => |*items| try items.append(value),
        else => unreachable,
    }
}

pub fn validateStatic() !void {
    if (methods.len != 7 or max_upstream_attempts != 2) return error.InvalidManagedHarnessContract;
    for (methods, 0..) |entry, index| {
        if (entry.name.len == 0 or entry.schema_key.len == 0) return error.InvalidManagedHarnessMethod;
        for (methods[index + 1 ..]) |other| {
            if (std.mem.eql(u8, entry.name, other.name) or
                std.mem.eql(u8, entry.schema_key, other.schema_key))
            {
                return error.DuplicateManagedHarnessMethod;
            }
        }
        for (forbidden_methods) |forbidden| {
            if (std.mem.eql(u8, entry.name, forbidden)) return error.ForbiddenManagedHarnessMethod;
        }
        try validateFieldNames(entry.required_params);
        try validateFieldNames(entry.required_result_fields);
    }
}

fn validateFieldNames(fields: []const []const u8) !void {
    for (fields, 0..) |field, index| {
        if (field.len == 0) return error.InvalidManagedHarnessField;
        for (forbidden_field_fragments) |forbidden| {
            if (std.mem.indexOf(u8, field, forbidden) != null) return error.ForbiddenManagedHarnessField;
        }
        for (fields[index + 1 ..]) |other| {
            if (std.mem.eql(u8, field, other)) return error.DuplicateManagedHarnessField;
        }
    }
}

test "managed harness surface is declaration-only and stable" {
    try validateStatic();
    try std.testing.expectEqual(@as(u32, 2), surface_version);
    try std.testing.expectEqual(@as(usize, 7), methods.len);
}

test "managed harness schema binds request results and bounded attempts" {
    const allocator = std.testing.allocator;
    const first = try renderSchema(allocator);
    defer allocator.free(first);
    const second = try renderSchema(allocator);
    defer allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    try std.testing.expect(std.mem.indexOf(u8, first, ": null") == null);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, first, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(usize, methods.len + 3), root.get("oneOf").?.array.items.len);

    const metadata = root.get("x-omux-surface").?.object;
    try std.testing.expectEqual(@as(i64, surface_version), metadata.get("surface_version").?.integer);
    try std.testing.expectEqualStrings(protocol_status, metadata.get("status").?.string);
    const declared_methods = metadata.get("methods").?.array.items;
    try std.testing.expectEqual(@as(usize, methods.len), declared_methods.len);
    for (declared_methods) |entry| {
        try std.testing.expectEqualStrings(method_status, entry.object.get("implementation_status").?.string);
        try std.testing.expect(std.mem.startsWith(u8, entry.object.get("request_schema").?.string, "#/$defs/request_"));
        try std.testing.expect(std.mem.startsWith(u8, entry.object.get("result_schema").?.string, "#/$defs/result_"));
    }

    const defs = root.get("$defs").?.object;
    const transition_params_schema = defs.get("request_session_transition").?.object
        .get("properties").?.object.get("params").?.object;
    try std.testing.expectEqual(@as(usize, transition_params.len), transition_params_schema.get("required").?.array.items.len);
    try std.testing.expectEqualStrings(
        "#/$defs/model_demand",
        transition_params_schema.get("properties").?.object.get("model_demand").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/proxy_attempts",
        transition_params_schema.get("properties").?.object.get("proxy_attempts").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, max_upstream_attempts),
        defs.get("proxy_attempts").?.object.get("maxItems").?.integer,
    );
    try std.testing.expectEqual(
        @as(usize, methods.len),
        defs.get("success_response").?.object.get("properties").?.object.get("result").?.object.get("anyOf").?.array.items.len,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/not_implemented_error",
        defs.get("not_implemented_response").?.object.get("properties").?.object.get("error").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/unknown_method_error",
        defs.get("unknown_method_response").?.object.get("properties").?.object.get("error").?.object.get("$ref").?.string,
    );
}

test "managed harness schema excludes sensitive names from extension fields" {
    const allocator = std.testing.allocator;
    const rendered = try renderSchema(allocator);
    defer allocator.free(rendered);

    for (forbidden_methods) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, rendered, forbidden) == null);
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, rendered, .{});
    defer parsed.deinit();
    const defs = parsed.value.object.get("$defs").?.object;
    const request = defs.get("request_session_launch").?.object;
    const params = request.get("properties").?.object.get("params").?.object;
    const names = params.get("propertyNames").?.object;
    try std.testing.expect(names.get("not") != null);
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "credential") != null);
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "token") != null);
    try std.testing.expectEqualStrings(
        "#/$defs/safe_extension_value",
        params.get("additionalProperties").?.object.get("$ref").?.string,
    );
    const safe_variants = defs.get("safe_extension_value").?.object.get("oneOf").?.array.items;
    const nested_object = safe_variants[safe_variants.len - 1].object;
    try std.testing.expectEqualStrings(
        "#/$defs/safe_extension_value",
        nested_object.get("additionalProperties").?.object.get("$ref").?.string,
    );
    try std.testing.expect(nested_object.get("propertyNames") != null);
}
