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
pub const teardown_incomplete_error_code: i32 = -32010;
pub const unknown_method_error_code: i32 = -32601;
pub const max_upstream_attempts: u8 = 2;
pub const max_cross_account_alternates: u8 = 1;
pub const max_same_route_transport_retries: u8 = 1;
pub const capability_bits: u16 = 256;
pub const replay_request_limit_bytes: u64 = 32 * 1024 * 1024;
pub const replay_sidecar_limit_bytes: u64 = 64 * 1024 * 1024;
pub const replay_host_limit_bytes: u64 = 256 * 1024 * 1024;
pub const max_pre_attempt_waits: u8 = 1;
pub const max_pre_attempt_wait_seconds: u8 = 30;
pub const max_json_safe_integer: i64 = 9_007_199_254_740_991;
pub const max_lease_records: u16 = 4096;
pub const max_object_properties: u16 = 128;

pub const MethodSpec = struct {
    name: []const u8,
    schema_key: []const u8,
    lifecycle_phase: []const u8,
    required_params: []const []const u8,
    required_result_fields: []const []const u8,
};

const no_fields = [_][]const u8{};
const surface_info_result = [_][]const u8{ "surface_version", "status", "methods", "policy" };
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
const teardown_result = [_][]const u8{"cleanup"};

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
    "secret",
    "password",
    "api_key",
    "bearer",
    "oauth",
    "account_id",
    "user_id",
    "email",
    "org_id",
    "organization_id",
    "identity",
};

const envelope_required = [_][]const u8{ "jsonrpc", "id", "method", "params" };
const success_required = [_][]const u8{ "jsonrpc", "id", "result" };
const error_response_required = [_][]const u8{ "jsonrpc", "id", "error" };
const error_required = [_][]const u8{ "code", "message", "data" };
const model_demand_required = [_][]const u8{ "model", "preservation" };
const attempt_common_required = [_][]const u8{
    "ordinal",
    "outcome",
    "retry_trigger",
    "route_relation",
    "transport_state",
    "response_started",
    "cross_account_replay",
};
const initial_attempt_required = attempt_common_required ++ [_][]const u8{ "account_handle", "route_handle" };
const same_route_attempt_required = attempt_common_required;
const alternate_attempt_required = attempt_common_required ++ [_][]const u8{ "alternate_account_handle", "alternate_route_handle" };
const method_status_required = [_][]const u8{ "name", "implementation_status" };
const attempt_outcomes = [_][]const u8{ "retained", "switched", "refused", "unproven" };
const transport_states = [_][]const u8{ "not_sent", "response_buffered_before_downstream", "downstream_started", "ambiguous" };
const alternate_retry_triggers = [_][]const u8{ "pre_body_401", "pre_body_403", "pre_body_429" };
const transition_states = [_][]const u8{ "ready", "running", "retained", "switched", "refused", "action_required" };
const lease_states = [_][]const u8{ "active", "stale", "exited" };
const preflight_reason_codes = [_][]const u8{
    "harness_unavailable",
    "managed_config_missing",
    "no_eligible_account",
    "model_parity_unproven",
    "credential_unavailable",
    "identity_conflict",
    "sidecar_unavailable",
    "policy_refused",
};
const repair_reason_codes = [_][]const u8{
    "hard_auth_failure",
    "credential_missing",
    "identity_conflict",
    "refresh_lineage_quarantined",
    "provider_reenroll_required",
};
const teardown_incomplete_reason_codes = [_][]const u8{
    "sidecar_shutdown_failed",
    "capability_disposal_failed",
    "lease_release_failed",
    "replay_reservation_release_failed",
};
const lease_required = [_][]const u8{
    "lease_handle",
    "session_handle",
    "account_handle",
    "route_handle",
    "model_demand",
    "owner_pid",
    "heartbeat_at_ms",
    "expires_at_ms",
    "owner_state",
};
const teardown_cleanup_fields = [_][]const u8{
    "sidecar_terminated",
    "capability_disposed",
    "leases_released",
    "replay_reservations_released",
};
const teardown_incomplete_data_fields = [_][]const u8{ "cleanup", "reason_code" };
const action_required_fields = [_][]const u8{
    "kind",
    "model_demand",
    "http_status",
    "retry_after_seconds",
    "reset_at_ms",
    "waited_ms",
    "evidence",
    "reason",
};
const repair_action_fields = [_][]const u8{ "kind", "provider_owned", "automatic_restore", "reason" };
const policy_fields = [_][]const u8{ "carrier", "replay", "wait", "leases", "redaction" };
const carrier_policy_fields = [_][]const u8{
    "capability_bits",
    "capability_encoding",
    "capability_storage",
    "capability_compare",
    "capability_generation",
    "capability_lifetime",
    "capability_child_binding",
    "capability_log_behavior",
    "inbound_carrier",
    "base_url_carrier",
    "loopback_bind",
    "bad_capability_behavior",
    "inbound_auth_header_behavior",
    "upstream_auth_injection",
    "request_target_form",
    "connect_behavior",
    "absolute_form_behavior",
    "caller_selected_upstream_behavior",
    "upstream_origin",
    "tls_verification",
    "redirect_behavior",
};
const replay_policy_fields = [_][]const u8{
    "max_upstream_attempts",
    "max_cross_account_alternates",
    "max_same_route_transport_retries",
    "alternate_statuses",
    "request_limit_bytes",
    "sidecar_limit_bytes",
    "host_limit_bytes",
    "reservation_storage",
    "reservation_owner",
    "reservation_stale_behavior",
    "reservation_release_behavior",
    "overflow_behavior",
    "chunked_unknown_length_behavior",
    "cancellation_behavior",
    "spool_behavior",
    "ambiguous_transport_behavior",
    "started_response_behavior",
    "provider_5xx_behavior",
};
const wait_policy_fields = [_][]const u8{
    "max_pre_attempt_waits",
    "max_wait_seconds",
    "trusted_reset_required",
    "must_fit_request_deadline",
    "reelect_after_wait",
    "otherwise_status",
    "retry_after_source",
    "loop_behavior",
};
const lease_policy_fields = [_][]const u8{
    "storage",
    "selection",
    "heartbeat_required",
    "expiry_required",
    "stale_owner_behavior",
    "unavailable_state_behavior",
    "exhaustion_trust",
    "availability_freshness",
    "unknown_rank",
};
const redaction_policy_fields = [_][]const u8{
    "wire_material",
    "recursive_sensitive_name_rejection",
    "local_evidence",
    "body_persistence",
    "extension_limits",
};

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
    try append(&wire_variants, try refSchema(scratch, "#/$defs/teardown_incomplete_response"));
    try append(&wire_variants, try refSchema(scratch, "#/$defs/unknown_method_response"));
    try put(&root, "oneOf", wire_variants);
    try put(&root, "x-omux-surface", try surfaceMetadata(scratch));

    var definitions = object(scratch);
    try put(&definitions, "opaque_handle", try opaqueHandleSchema(scratch));
    try put(&definitions, "handle_or_null", try handleOrNullSchema(scratch));
    try put(&definitions, "label", try boundedStringSchema(scratch, 1, 256));
    try put(&definitions, "boolean", try typeSchema(scratch, "boolean"));
    try put(&definitions, "nonnegative_integer", try boundedIntegerSchema(scratch, 0, max_json_safe_integer));
    try put(&definitions, "preflight_reasons", try preflightReasonsSchema(scratch));
    try put(&definitions, "repair_reason_code", try enumSchema(scratch, &repair_reason_codes));
    try put(&definitions, "open_object", try openObjectSchema(scratch));
    try put(&definitions, "transition_state", try enumSchema(scratch, &transition_states));
    try put(&definitions, "model_demand", try modelDemandSchema(scratch));
    try put(&definitions, "broker_policy", try brokerPolicySchema(scratch));
    try put(&definitions, "lease_record", try leaseRecordSchema(scratch));
    try put(&definitions, "lease_records", try arrayOf(scratch, try refSchema(scratch, "#/$defs/lease_record"), max_lease_records));
    try put(&definitions, "transition_action_required", try transitionActionRequiredSchema(scratch));
    try put(&definitions, "transition_action_required_or_null", try refOrNullSchema(scratch, "#/$defs/transition_action_required"));
    try put(&definitions, "repair_action", try repairActionSchema(scratch));
    try put(&definitions, "teardown_cleanup", try teardownCleanupSchema(scratch));
    try put(&definitions, "teardown_incomplete_cleanup", try teardownIncompleteCleanupSchema(scratch));
    try put(&definitions, "teardown_incomplete_data", try teardownIncompleteDataSchema(scratch));
    try put(&definitions, "proxy_attempt_initial", try initialProxyAttemptSchema(scratch));
    try put(&definitions, "proxy_attempt_initial_pre_send_failure", try constrainedInitialProxyAttemptSchema(scratch, "not_sent", "unproven"));
    try put(&definitions, "proxy_attempt_initial_pre_body_failure", try constrainedInitialProxyAttemptSchema(scratch, "response_buffered_before_downstream", "refused"));
    try put(&definitions, "proxy_attempt_same_route_retry", try sameRouteRetryAttemptSchema(scratch));
    try put(&definitions, "proxy_attempt_alternate", try alternateProxyAttemptSchema(scratch));
    try put(&definitions, "proxy_attempt_followup", try followupProxyAttemptSchema(scratch));
    try put(&definitions, "proxy_attempts", try proxyAttemptsSchema(scratch));
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
    try put(&definitions, "teardown_incomplete_error", try teardownIncompleteErrorSchema(scratch));
    try put(&definitions, "unknown_method_error", try errorSchema(scratch, unknown_method_error_code, "method not found"));
    try put(&definitions, "not_implemented_response", try errorResponseSchema(scratch, "#/$defs/not_implemented_error"));
    try put(&definitions, "teardown_incomplete_response", try errorResponseSchema(scratch, "#/$defs/teardown_incomplete_error"));
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
    try put(&metadata, "policy_schema", string("#/$defs/broker_policy"));

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
        try put(&method_value, "unknown_fields", string("typed_scalar_extensions_except_sensitive_names"));
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
    var schema = try methodFieldsSchema(allocator, entry.required_result_fields, true);
    if (std.mem.eql(u8, entry.schema_key, "session_transition")) {
        try put(&schema, "allOf", try transitionActionConsistencySchema(allocator));
    }
    return schema;
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
    if (std.mem.eql(u8, field, "reason")) return refSchema(allocator, "#/$defs/repair_reason_code");
    if (!is_result) return error.UnknownManagedHarnessParam;

    if (std.mem.eql(u8, field, "surface_version")) return refSchema(allocator, "#/$defs/surface_version_const");
    if (std.mem.eql(u8, field, "status")) return refSchema(allocator, "#/$defs/protocol_status_const");
    if (std.mem.eql(u8, field, "methods")) return refSchema(allocator, "#/$defs/method_statuses");
    if (std.mem.eql(u8, field, "policy")) return refSchema(allocator, "#/$defs/broker_policy");
    if (std.mem.eql(u8, field, "ready")) return refSchema(allocator, "#/$defs/boolean");
    if (std.mem.eql(u8, field, "reasons")) return refSchema(allocator, "#/$defs/preflight_reasons");
    if (std.mem.eql(u8, field, "state")) return refSchema(allocator, "#/$defs/transition_state");
    if (std.mem.eql(u8, field, "leases")) return refSchema(allocator, "#/$defs/lease_records");
    if (std.mem.eql(u8, field, "observed_at_ms")) return refSchema(allocator, "#/$defs/nonnegative_integer");
    if (std.mem.eql(u8, field, "action_required")) return refSchema(allocator, "#/$defs/transition_action_required_or_null");
    if (std.mem.eql(u8, field, "action")) return refSchema(allocator, "#/$defs/repair_action");
    if (std.mem.eql(u8, field, "cleanup")) return refSchema(allocator, "#/$defs/teardown_cleanup");
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

fn teardownIncompleteErrorSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "code", try constIntegerSchema(allocator, teardown_incomplete_error_code));
    try put(&properties, "message", try constStringSchema(allocator, "session teardown incomplete"));
    try put(&properties, "data", try refSchema(allocator, "#/$defs/teardown_incomplete_data"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &error_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn preflightReasonsSchema(allocator: std.mem.Allocator) !Value {
    var schema = try arrayOf(allocator, try enumSchema(allocator, &preflight_reason_codes), preflight_reason_codes.len);
    try put(&schema, "uniqueItems", boolean(true));
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

fn brokerPolicySchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "carrier", try carrierPolicySchema(allocator));
    try put(&properties, "replay", try replayPolicySchema(allocator));
    try put(&properties, "wait", try waitPolicySchema(allocator));
    try put(&properties, "leases", try leasePolicySchema(allocator));
    try put(&properties, "redaction", try redactionPolicySchema(allocator));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn carrierPolicySchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "capability_bits", try constIntegerSchema(allocator, capability_bits));
    try put(&properties, "capability_encoding", try constStringSchema(allocator, "base64url_no_padding"));
    try put(&properties, "capability_storage", try constStringSchema(allocator, "memory_only"));
    try put(&properties, "capability_compare", try constStringSchema(allocator, "constant_time"));
    try put(&properties, "capability_generation", try constStringSchema(allocator, "operating_system_csprng"));
    try put(&properties, "capability_lifetime", try constStringSchema(allocator, "session_only"));
    try put(&properties, "capability_child_binding", try constStringSchema(allocator, "managed_child_only"));
    try put(&properties, "capability_log_behavior", try constStringSchema(allocator, "never_emit_dispose_at_teardown"));
    try put(&properties, "inbound_carrier", try constStringSchema(allocator, "ANTHROPIC_AUTH_TOKEN"));
    try put(&properties, "base_url_carrier", try constStringSchema(allocator, "ANTHROPIC_BASE_URL"));
    try put(&properties, "loopback_bind", try constStringSchema(allocator, "127.0.0.1:0"));
    try put(&properties, "bad_capability_behavior", try constStringSchema(allocator, "local_401_zero_upstream"));
    try put(&properties, "inbound_auth_header_behavior", try constStringSchema(allocator, "strip_authorization_and_api_key"));
    try put(&properties, "upstream_auth_injection", try constStringSchema(allocator, "elected_oauth_bearer_only"));
    try put(&properties, "request_target_form", try constStringSchema(allocator, "origin_form_only"));
    try put(&properties, "connect_behavior", try constStringSchema(allocator, "reject"));
    try put(&properties, "absolute_form_behavior", try constStringSchema(allocator, "reject"));
    try put(&properties, "caller_selected_upstream_behavior", try constStringSchema(allocator, "reject"));
    try put(&properties, "upstream_origin", try constStringSchema(allocator, "https://api.anthropic.com"));
    try put(&properties, "tls_verification", try constStringSchema(allocator, "system_roots_required"));
    try put(&properties, "redirect_behavior", try constStringSchema(allocator, "reject_auth_carrying_redirects"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &carrier_policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn replayPolicySchema(allocator: std.mem.Allocator) !Value {
    const alternate_statuses = [_]i64{ 401, 403, 429 };
    var properties = object(allocator);
    try put(&properties, "max_upstream_attempts", try constIntegerSchema(allocator, max_upstream_attempts));
    try put(&properties, "max_cross_account_alternates", try constIntegerSchema(allocator, max_cross_account_alternates));
    try put(&properties, "max_same_route_transport_retries", try constIntegerSchema(allocator, max_same_route_transport_retries));
    try put(&properties, "alternate_statuses", try constIntegerArraySchema(allocator, &alternate_statuses));
    try put(&properties, "request_limit_bytes", try constIntegerSchema(allocator, replay_request_limit_bytes));
    try put(&properties, "sidecar_limit_bytes", try constIntegerSchema(allocator, replay_sidecar_limit_bytes));
    try put(&properties, "host_limit_bytes", try constIntegerSchema(allocator, replay_host_limit_bytes));
    try put(&properties, "reservation_storage", try constStringSchema(allocator, "atomic_cross_process"));
    try put(&properties, "reservation_owner", try constStringSchema(allocator, "pid_heartbeat_expiry"));
    try put(&properties, "reservation_stale_behavior", try constStringSchema(allocator, "ignore_and_reclaim"));
    try put(&properties, "reservation_release_behavior", try constStringSchema(allocator, "hold_until_replay_ineligible_or_cancellation_overflow_teardown"));
    try put(&properties, "overflow_behavior", try constStringSchema(allocator, "stream_once_release_reservation"));
    try put(&properties, "chunked_unknown_length_behavior", try constStringSchema(allocator, "buffer_to_request_limit_then_stream_once_with_backpressure"));
    try put(&properties, "cancellation_behavior", try constStringSchema(allocator, "propagate_no_cross_account_release_reservation"));
    try put(&properties, "spool_behavior", try constStringSchema(allocator, "forbidden"));
    try put(&properties, "ambiguous_transport_behavior", try constStringSchema(allocator, "propagate_original_no_cross_account"));
    try put(&properties, "started_response_behavior", try constStringSchema(allocator, "propagate_original_no_cross_account"));
    try put(&properties, "provider_5xx_behavior", try constStringSchema(allocator, "pass_through_native_retry"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &replay_policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn waitPolicySchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "max_pre_attempt_waits", try constIntegerSchema(allocator, max_pre_attempt_waits));
    try put(&properties, "max_wait_seconds", try constIntegerSchema(allocator, max_pre_attempt_wait_seconds));
    try put(&properties, "trusted_reset_required", try constBooleanSchema(allocator, true));
    try put(&properties, "must_fit_request_deadline", try constBooleanSchema(allocator, true));
    try put(&properties, "reelect_after_wait", try constBooleanSchema(allocator, true));
    try put(&properties, "otherwise_status", try constIntegerSchema(allocator, 429));
    try put(&properties, "retry_after_source", try constStringSchema(allocator, "best_trusted_reset"));
    try put(&properties, "loop_behavior", try constStringSchema(allocator, "forbidden"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &wait_policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn leasePolicySchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "storage", try constStringSchema(allocator, "atomic_redacted_cross_process"));
    try put(&properties, "selection", try constStringSchema(allocator, "sticky_least_loaded_then_least_recent"));
    try put(&properties, "heartbeat_required", try constBooleanSchema(allocator, true));
    try put(&properties, "expiry_required", try constBooleanSchema(allocator, true));
    try put(&properties, "stale_owner_behavior", try constStringSchema(allocator, "ignore_and_reclaim"));
    try put(&properties, "unavailable_state_behavior", try constStringSchema(allocator, "advisory_never_blocks_reactive_routing"));
    try put(&properties, "exhaustion_trust", try constStringSchema(allocator, "through_reset"));
    try put(&properties, "availability_freshness", try constStringSchema(allocator, "deadline_required"));
    try put(&properties, "unknown_rank", try constStringSchema(allocator, "below_known_good_above_dead"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &lease_policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn redactionPolicySchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "wire_material", try constStringSchema(allocator, "opaque_handles_and_redacted_labels_only"));
    try put(&properties, "recursive_sensitive_name_rejection", try constBooleanSchema(allocator, true));
    try put(&properties, "local_evidence", try constStringSchema(allocator, "typed_redacted_only"));
    try put(&properties, "body_persistence", try constStringSchema(allocator, "forbidden"));
    try put(&properties, "extension_limits", try constStringSchema(allocator, "typed_x_flag_x_count_x_ratio_scalars_only"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &redaction_policy_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn leaseRecordSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "lease_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "session_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "account_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "model_demand", try refSchema(allocator, "#/$defs/model_demand"));
    try put(&properties, "owner_pid", try boundedIntegerSchema(allocator, 1, std.math.maxInt(i32)));
    try put(&properties, "heartbeat_at_ms", try boundedIntegerSchema(allocator, 0, max_json_safe_integer));
    try put(&properties, "expires_at_ms", try boundedIntegerSchema(allocator, 0, max_json_safe_integer));
    try put(&properties, "owner_state", try enumSchema(allocator, &lease_states));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &lease_required));
    try put(&schema, "properties", properties);
    return schema;
}

fn transitionActionRequiredSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "kind", try constStringSchema(allocator, "all_exact_model_routes_exhausted"));
    try put(&properties, "model_demand", try refSchema(allocator, "#/$defs/model_demand"));
    try put(&properties, "http_status", try constIntegerSchema(allocator, 429));
    try put(&properties, "retry_after_seconds", try boundedIntegerSchema(allocator, 0, max_json_safe_integer));
    try put(&properties, "reset_at_ms", try boundedIntegerSchema(allocator, 0, max_json_safe_integer));
    try put(&properties, "waited_ms", try boundedIntegerSchema(allocator, 0, @as(i64, max_pre_attempt_wait_seconds) * 1000));
    try put(&properties, "evidence", try constStringSchema(allocator, "trusted_exhaustion_reset"));
    try put(&properties, "reason", try constStringSchema(allocator, "all_exact_model_routes_exhausted"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &action_required_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn repairActionSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "kind", try constStringSchema(allocator, "provider_reenroll"));
    try put(&properties, "provider_owned", try constBooleanSchema(allocator, true));
    try put(&properties, "automatic_restore", try constBooleanSchema(allocator, false));
    try put(&properties, "reason", try refSchema(allocator, "#/$defs/repair_reason_code"));

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &repair_action_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn teardownCleanupSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    inline for (teardown_cleanup_fields) |field| {
        try put(&properties, field, try constBooleanSchema(allocator, true));
    }

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &teardown_cleanup_fields));
    try put(&schema, "properties", properties);
    return schema;
}

fn teardownIncompleteCleanupSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    var all_true_properties = object(allocator);
    inline for (teardown_cleanup_fields) |field| {
        try put(&properties, field, try typeSchema(allocator, "boolean"));
        try put(&all_true_properties, field, try constBooleanSchema(allocator, true));
    }

    var all_true = object(allocator);
    try put(&all_true, "required", try stringArray(allocator, &teardown_cleanup_fields));
    try put(&all_true, "properties", all_true_properties);

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &teardown_cleanup_fields));
    try put(&schema, "properties", properties);
    try put(&schema, "not", all_true);
    return schema;
}

fn teardownIncompleteDataSchema(allocator: std.mem.Allocator) !Value {
    var properties = object(allocator);
    try put(&properties, "cleanup", try refSchema(allocator, "#/$defs/teardown_incomplete_cleanup"));
    try put(&properties, "reason_code", try enumSchema(allocator, &teardown_incomplete_reason_codes));

    var reason_consistency = array(allocator);
    inline for (teardown_incomplete_reason_codes, teardown_cleanup_fields) |reason_code, failed_field| {
        var cleanup_properties = object(allocator);
        try put(&cleanup_properties, failed_field, try constBooleanSchema(allocator, false));
        var cleanup_constraint = object(allocator);
        try put(&cleanup_constraint, "properties", cleanup_properties);

        var variant_properties = object(allocator);
        try put(&variant_properties, "reason_code", try constStringSchema(allocator, reason_code));
        try put(&variant_properties, "cleanup", cleanup_constraint);
        var variant = object(allocator);
        try put(&variant, "properties", variant_properties);
        try append(&reason_consistency, variant);
    }

    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, &teardown_incomplete_data_fields));
    try put(&schema, "properties", properties);
    try put(&schema, "oneOf", reason_consistency);
    return schema;
}

fn transitionActionConsistencySchema(allocator: std.mem.Allocator) !Value {
    var state_properties = object(allocator);
    try put(&state_properties, "state", try constStringSchema(allocator, "action_required"));
    var state_is_action_required = object(allocator);
    try put(&state_is_action_required, "required", try stringArray(allocator, &[_][]const u8{"state"}));
    try put(&state_is_action_required, "properties", state_properties);

    var action_properties = object(allocator);
    try put(&action_properties, "action_required", try refSchema(allocator, "#/$defs/transition_action_required"));
    var action_required = object(allocator);
    try put(&action_required, "properties", action_properties);

    var null_properties = object(allocator);
    try put(&null_properties, "action_required", try typeSchema(allocator, "null"));
    var action_is_null = object(allocator);
    try put(&action_is_null, "properties", null_properties);

    var conditional = object(allocator);
    try put(&conditional, "if", state_is_action_required);
    try put(&conditional, "then", action_required);
    try put(&conditional, "else", action_is_null);

    var conditions = array(allocator);
    try append(&conditions, conditional);

    var switched_state_properties = object(allocator);
    try put(&switched_state_properties, "state", try constStringSchema(allocator, "switched"));
    var state_is_switched = object(allocator);
    try put(&state_is_switched, "required", try stringArray(allocator, &[_][]const u8{"state"}));
    try put(&state_is_switched, "properties", switched_state_properties);

    var selected_route_properties = object(allocator);
    try put(&selected_route_properties, "selected_route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    var selected_route_required = object(allocator);
    try put(&selected_route_required, "properties", selected_route_properties);

    var switched_conditional = object(allocator);
    try put(&switched_conditional, "if", state_is_switched);
    try put(&switched_conditional, "then", selected_route_required);
    try append(&conditions, switched_conditional);
    return conditions;
}

fn proxyAttemptProperties(
    allocator: std.mem.Allocator,
    ordinal_schema: Value,
    outcome_schema: Value,
    trigger_schema: Value,
    relation_schema: Value,
    transport_schema: Value,
    response_started_schema: Value,
    cross_account_schema: Value,
) !Value {
    var properties = object(allocator);
    try put(&properties, "ordinal", ordinal_schema);
    try put(&properties, "model_demand", boolean(false));
    try put(&properties, "outcome", outcome_schema);
    try put(&properties, "retry_trigger", trigger_schema);
    try put(&properties, "route_relation", relation_schema);
    try put(&properties, "transport_state", transport_schema);
    try put(&properties, "response_started", response_started_schema);
    try put(&properties, "cross_account_replay", cross_account_schema);
    return properties;
}

fn proxyAttemptVariantSchema(allocator: std.mem.Allocator, required: []const []const u8, properties: Value) !Value {
    var schema = try objectSchemaBase(allocator);
    try put(&schema, "required", try stringArray(allocator, required));
    try put(&schema, "properties", properties);
    try put(&schema, "allOf", try attemptTransportConsistencySchema(allocator));
    return schema;
}

fn initialProxyAttemptSchema(allocator: std.mem.Allocator) !Value {
    var properties = try proxyAttemptProperties(
        allocator,
        try constIntegerSchema(allocator, 1),
        try enumSchema(allocator, &attempt_outcomes),
        try constStringSchema(allocator, "initial"),
        try constStringSchema(allocator, "initial"),
        try enumSchema(allocator, &transport_states),
        try typeSchema(allocator, "boolean"),
        try constBooleanSchema(allocator, false),
    );
    try put(&properties, "account_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    return proxyAttemptVariantSchema(allocator, &initial_attempt_required, properties);
}

fn constrainedInitialProxyAttemptSchema(
    allocator: std.mem.Allocator,
    transport_state: []const u8,
    outcome: []const u8,
) !Value {
    var properties = try proxyAttemptProperties(
        allocator,
        try constIntegerSchema(allocator, 1),
        try constStringSchema(allocator, outcome),
        try constStringSchema(allocator, "initial"),
        try constStringSchema(allocator, "initial"),
        try constStringSchema(allocator, transport_state),
        try constBooleanSchema(allocator, false),
        try constBooleanSchema(allocator, false),
    );
    try put(&properties, "account_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    return proxyAttemptVariantSchema(allocator, &initial_attempt_required, properties);
}

fn sameRouteRetryAttemptSchema(allocator: std.mem.Allocator) !Value {
    var properties = try proxyAttemptProperties(
        allocator,
        try constIntegerSchema(allocator, 2),
        try enumSchema(allocator, &attempt_outcomes),
        try constStringSchema(allocator, "confirmed_pre_send_transport_failure"),
        try constStringSchema(allocator, "same_route"),
        try enumSchema(allocator, &transport_states),
        try typeSchema(allocator, "boolean"),
        try constBooleanSchema(allocator, false),
    );
    try put(&properties, "account_handle", boolean(false));
    try put(&properties, "route_handle", boolean(false));
    try put(&properties, "alternate_account_handle", boolean(false));
    try put(&properties, "alternate_route_handle", boolean(false));
    return proxyAttemptVariantSchema(allocator, &same_route_attempt_required, properties);
}

fn alternateProxyAttemptSchema(allocator: std.mem.Allocator) !Value {
    var properties = try proxyAttemptProperties(
        allocator,
        try constIntegerSchema(allocator, 2),
        try enumSchema(allocator, &[_][]const u8{ "switched", "refused", "unproven" }),
        try enumSchema(allocator, &alternate_retry_triggers),
        try constStringSchema(allocator, "alternate_account"),
        try enumSchema(allocator, &transport_states),
        try typeSchema(allocator, "boolean"),
        try constBooleanSchema(allocator, true),
    );
    try put(&properties, "account_handle", boolean(false));
    try put(&properties, "route_handle", boolean(false));
    try put(&properties, "alternate_account_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    try put(&properties, "alternate_route_handle", try refSchema(allocator, "#/$defs/opaque_handle"));
    return proxyAttemptVariantSchema(allocator, &alternate_attempt_required, properties);
}

fn attemptTransportConsistencySchema(allocator: std.mem.Allocator) !Value {
    var started_transport_properties = object(allocator);
    try put(&started_transport_properties, "transport_state", try constStringSchema(allocator, "downstream_started"));
    var transport_is_started = object(allocator);
    try put(&transport_is_started, "properties", started_transport_properties);

    var response_true_properties = object(allocator);
    try put(&response_true_properties, "response_started", try constBooleanSchema(allocator, true));
    var response_is_true = object(allocator);
    try put(&response_is_true, "properties", response_true_properties);

    var response_false_properties = object(allocator);
    try put(&response_false_properties, "response_started", try constBooleanSchema(allocator, false));
    var response_is_false = object(allocator);
    try put(&response_is_false, "properties", response_false_properties);

    var transport_condition = object(allocator);
    try put(&transport_condition, "if", transport_is_started);
    try put(&transport_condition, "then", response_is_true);
    try put(&transport_condition, "else", response_is_false);

    var response_condition = object(allocator);
    try put(&response_condition, "if", response_is_true);
    try put(&response_condition, "then", transport_is_started);

    var conditions = array(allocator);
    try append(&conditions, transport_condition);
    try append(&conditions, response_condition);
    return conditions;
}

fn followupProxyAttemptSchema(allocator: std.mem.Allocator) !Value {
    var variants = array(allocator);
    try append(&variants, try refSchema(allocator, "#/$defs/proxy_attempt_same_route_retry"));
    try append(&variants, try refSchema(allocator, "#/$defs/proxy_attempt_alternate"));
    var schema = object(allocator);
    try put(&schema, "oneOf", variants);
    return schema;
}

fn proxyAttemptsSchema(allocator: std.mem.Allocator) !Value {
    var prefix_items = array(allocator);
    try append(&prefix_items, try refSchema(allocator, "#/$defs/proxy_attempt_initial"));
    try append(&prefix_items, try refSchema(allocator, "#/$defs/proxy_attempt_followup"));

    var schema = try typeSchema(allocator, "array");
    try put(&schema, "minItems", integer(1));
    try put(&schema, "maxItems", integer(max_upstream_attempts));
    try put(&schema, "prefixItems", prefix_items);
    try put(&schema, "items", boolean(false));

    var legal_sequences = array(allocator);
    var initial_only = object(allocator);
    try put(&initial_only, "maxItems", integer(1));
    try append(&legal_sequences, initial_only);
    try append(&legal_sequences, try twoAttemptSequenceSchema(
        allocator,
        "#/$defs/proxy_attempt_initial_pre_send_failure",
        "#/$defs/proxy_attempt_same_route_retry",
    ));
    try append(&legal_sequences, try twoAttemptSequenceSchema(
        allocator,
        "#/$defs/proxy_attempt_initial_pre_body_failure",
        "#/$defs/proxy_attempt_alternate",
    ));
    try put(&schema, "oneOf", legal_sequences);
    return schema;
}

fn twoAttemptSequenceSchema(
    allocator: std.mem.Allocator,
    initial_ref: []const u8,
    followup_ref: []const u8,
) !Value {
    var prefix_items = array(allocator);
    try append(&prefix_items, try refSchema(allocator, initial_ref));
    try append(&prefix_items, try refSchema(allocator, followup_ref));

    var schema = try typeSchema(allocator, "array");
    try put(&schema, "minItems", integer(2));
    try put(&schema, "maxItems", integer(2));
    try put(&schema, "prefixItems", prefix_items);
    try put(&schema, "items", boolean(false));
    return schema;
}

fn methodStatusesSchema(allocator: std.mem.Allocator) !Value {
    var entries = array(allocator);
    for (methods) |entry| {
        var properties = object(allocator);
        try put(&properties, "name", try constStringSchema(allocator, entry.name));
        try put(&properties, "implementation_status", try constStringSchema(allocator, method_status));
        var item = try objectSchemaBase(allocator);
        try put(&item, "required", try stringArray(allocator, &method_status_required));
        try put(&item, "properties", properties);
        try append(&entries, item);
    }

    var schema = try typeSchema(allocator, "array");
    try put(&schema, "minItems", integer(methods.len));
    try put(&schema, "maxItems", integer(methods.len));
    try put(&schema, "prefixItems", entries);
    try put(&schema, "items", boolean(false));
    return schema;
}

fn objectSchemaBase(allocator: std.mem.Allocator) !Value {
    var schema = object(allocator);
    try put(&schema, "type", string("object"));
    try put(&schema, "maxProperties", integer(max_object_properties));
    try put(&schema, "additionalProperties", boolean(false));
    try put(&schema, "patternProperties", try extensionPatternPropertiesSchema(allocator));
    try put(&schema, "propertyNames", try propertyNamesSchema(allocator));
    return schema;
}

fn openObjectSchema(allocator: std.mem.Allocator) !Value {
    return objectSchemaBase(allocator);
}

fn propertyNamesSchema(allocator: std.mem.Allocator) !Value {
    var forbidden = object(allocator);
    try put(&forbidden, "pattern", string("(credential|token|authorization|cookie|env|argv|prompt|response[_-]*body|raw[_-]*account|secret|password|api[_-]*key|bearer|oauth|account[_-]*id|user[_-]*id|email|org[_-]*id|organization[_-]*id|identity)"));
    var schema = object(allocator);
    try put(&schema, "pattern", string("^[a-z][a-z0-9_-]*$"));
    try put(&schema, "maxLength", integer(128));
    try put(&schema, "not", forbidden);
    return schema;
}

fn extensionPatternPropertiesSchema(allocator: std.mem.Allocator) !Value {
    var patterns = object(allocator);
    try put(&patterns, "^x_flag_[a-z0-9_]{1,64}$", try typeSchema(allocator, "boolean"));
    try put(&patterns, "^x_count_[a-z0-9_]{1,64}$", try boundedIntegerSchema(allocator, 0, max_json_safe_integer));
    try put(&patterns, "^x_ratio_[a-z0-9_]{1,64}$", try boundedNumberSchema(allocator, 0, 1));
    return patterns;
}

fn opaqueHandleSchema(allocator: std.mem.Allocator) !Value {
    var schema = try boundedStringSchema(allocator, 1, 256);
    try put(&schema, "pattern", string("^[A-Za-z0-9_-]+$"));
    return schema;
}

fn handleOrNullSchema(allocator: std.mem.Allocator) !Value {
    return refOrNullSchema(allocator, "#/$defs/opaque_handle");
}

fn refOrNullSchema(allocator: std.mem.Allocator, reference: []const u8) !Value {
    var options = array(allocator);
    try append(&options, try refSchema(allocator, reference));
    try append(&options, try typeSchema(allocator, "null"));
    var schema = object(allocator);
    try put(&schema, "oneOf", options);
    return schema;
}

fn idSchema(allocator: std.mem.Allocator) !Value {
    var options = array(allocator);
    var opaque_string = try boundedStringSchema(allocator, 1, 128);
    try put(&opaque_string, "pattern", string("^[A-Za-z0-9_-]+$"));
    try append(&options, opaque_string);
    try append(&options, try boundedIntegerSchema(allocator, -max_json_safe_integer, max_json_safe_integer));
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

fn boundedNumberSchema(allocator: std.mem.Allocator, minimum: i64, maximum: i64) !Value {
    var schema = try typeSchema(allocator, "number");
    try put(&schema, "minimum", integer(minimum));
    try put(&schema, "maximum", integer(maximum));
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

fn constBooleanSchema(allocator: std.mem.Allocator, value: bool) !Value {
    var schema = try typeSchema(allocator, "boolean");
    try put(&schema, "const", boolean(value));
    return schema;
}

fn constIntegerArraySchema(allocator: std.mem.Allocator, values: []const i64) !Value {
    var prefix_items = array(allocator);
    for (values) |value| try append(&prefix_items, try constIntegerSchema(allocator, value));

    var schema = try typeSchema(allocator, "array");
    try put(&schema, "minItems", integer(values.len));
    try put(&schema, "maxItems", integer(values.len));
    try put(&schema, "prefixItems", prefix_items);
    try put(&schema, "items", boolean(false));
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
    if (methods.len != 7 or
        teardown_incomplete_error_code != -32010 or
        max_upstream_attempts != 2 or
        max_cross_account_alternates != 1 or
        max_same_route_transport_retries != 1 or
        capability_bits != 256 or
        replay_request_limit_bytes != 32 * 1024 * 1024 or
        replay_sidecar_limit_bytes != 64 * 1024 * 1024 or
        replay_host_limit_bytes != 256 * 1024 * 1024 or
        max_pre_attempt_waits != 1 or
        max_pre_attempt_wait_seconds != 30 or
        max_json_safe_integer != 9_007_199_254_740_991 or
        max_lease_records < 1000)
    {
        return error.InvalidManagedHarnessContract;
    }
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
    try std.testing.expectEqual(@as(usize, methods.len + 4), root.get("oneOf").?.array.items.len);

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
    try std.testing.expectEqual(@as(i64, 1), defs.get("proxy_attempts").?.object.get("minItems").?.integer);
    try std.testing.expectEqual(@as(usize, 2), defs.get("proxy_attempts").?.object.get("prefixItems").?.array.items.len);
    try std.testing.expectEqual(false, defs.get("proxy_attempts").?.object.get("items").?.bool);
    try std.testing.expectEqual(@as(usize, 3), defs.get("proxy_attempts").?.object.get("oneOf").?.array.items.len);
    try std.testing.expectEqual(
        @as(usize, 2),
        defs.get("proxy_attempt_followup").?.object.get("oneOf").?.array.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, methods.len),
        defs.get("success_response").?.object.get("properties").?.object.get("result").?.object.get("anyOf").?.array.items.len,
    );
    const status_schema = defs.get("method_statuses").?.object;
    try std.testing.expectEqual(@as(usize, methods.len), status_schema.get("prefixItems").?.array.items.len);
    try std.testing.expectEqual(false, status_schema.get("items").?.bool);
    for (methods, 0..) |entry, index| {
        const item = status_schema.get("prefixItems").?.array.items[index].object;
        try std.testing.expectEqualStrings(
            entry.name,
            item.get("properties").?.object.get("name").?.object.get("const").?.string,
        );
    }
    try std.testing.expectEqualStrings(
        "#/$defs/not_implemented_error",
        defs.get("not_implemented_response").?.object.get("properties").?.object.get("error").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/teardown_incomplete_error",
        defs.get("teardown_incomplete_response").?.object.get("properties").?.object.get("error").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/unknown_method_error",
        defs.get("unknown_method_response").?.object.get("properties").?.object.get("error").?.object.get("$ref").?.string,
    );
}

test "managed harness schema freezes carrier replay wait lease and redaction policy" {
    const allocator = std.testing.allocator;
    const rendered = try renderSchema(allocator);
    defer allocator.free(rendered);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, rendered, .{});
    defer parsed.deinit();
    const defs = parsed.value.object.get("$defs").?.object;
    const policy = defs.get("broker_policy").?.object.get("properties").?.object;

    const carrier = policy.get("carrier").?.object.get("properties").?.object;
    try std.testing.expectEqual(@as(i64, capability_bits), carrier.get("capability_bits").?.object.get("const").?.integer);
    try std.testing.expectEqualStrings("base64url_no_padding", carrier.get("capability_encoding").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("memory_only", carrier.get("capability_storage").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("constant_time", carrier.get("capability_compare").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("ANTHROPIC_AUTH_TOKEN", carrier.get("inbound_carrier").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("127.0.0.1:0", carrier.get("loopback_bind").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("local_401_zero_upstream", carrier.get("bad_capability_behavior").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("operating_system_csprng", carrier.get("capability_generation").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("strip_authorization_and_api_key", carrier.get("inbound_auth_header_behavior").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("elected_oauth_bearer_only", carrier.get("upstream_auth_injection").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("reject", carrier.get("connect_behavior").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("https://api.anthropic.com", carrier.get("upstream_origin").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("system_roots_required", carrier.get("tls_verification").?.object.get("const").?.string);

    const replay = policy.get("replay").?.object.get("properties").?.object;
    try std.testing.expectEqual(@as(i64, max_upstream_attempts), replay.get("max_upstream_attempts").?.object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, max_cross_account_alternates), replay.get("max_cross_account_alternates").?.object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, replay_request_limit_bytes), replay.get("request_limit_bytes").?.object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, replay_sidecar_limit_bytes), replay.get("sidecar_limit_bytes").?.object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, replay_host_limit_bytes), replay.get("host_limit_bytes").?.object.get("const").?.integer);
    try std.testing.expectEqualStrings("atomic_cross_process", replay.get("reservation_storage").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("pid_heartbeat_expiry", replay.get("reservation_owner").?.object.get("const").?.string);
    try std.testing.expectEqualStrings(
        "hold_until_replay_ineligible_or_cancellation_overflow_teardown",
        replay.get("reservation_release_behavior").?.object.get("const").?.string,
    );
    try std.testing.expectEqualStrings("propagate_no_cross_account_release_reservation", replay.get("cancellation_behavior").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("pass_through_native_retry", replay.get("provider_5xx_behavior").?.object.get("const").?.string);
    const statuses = replay.get("alternate_statuses").?.object.get("prefixItems").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), statuses.len);
    try std.testing.expectEqual(@as(i64, 401), statuses[0].object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, 403), statuses[1].object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, 429), statuses[2].object.get("const").?.integer);

    const wait = policy.get("wait").?.object.get("properties").?.object;
    try std.testing.expectEqual(@as(i64, max_pre_attempt_waits), wait.get("max_pre_attempt_waits").?.object.get("const").?.integer);
    try std.testing.expectEqual(@as(i64, max_pre_attempt_wait_seconds), wait.get("max_wait_seconds").?.object.get("const").?.integer);
    try std.testing.expectEqual(true, wait.get("trusted_reset_required").?.object.get("const").?.bool);
    try std.testing.expectEqual(@as(i64, 429), wait.get("otherwise_status").?.object.get("const").?.integer);

    const leases = policy.get("leases").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("atomic_redacted_cross_process", leases.get("storage").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("ignore_and_reclaim", leases.get("stale_owner_behavior").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("below_known_good_above_dead", leases.get("unknown_rank").?.object.get("const").?.string);

    const redaction = policy.get("redaction").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("opaque_handles_and_redacted_labels_only", redaction.get("wire_material").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("forbidden", redaction.get("body_persistence").?.object.get("const").?.string);
}

test "managed harness schema types leases actions and the only legal followup attempts" {
    const allocator = std.testing.allocator;
    const rendered = try renderSchema(allocator);
    defer allocator.free(rendered);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, rendered, .{});
    defer parsed.deinit();
    const defs = parsed.value.object.get("$defs").?.object;

    const surface_info = defs.get("result_surface_info").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/broker_policy", surface_info.get("policy").?.object.get("$ref").?.string);
    const lease_result_schema = defs.get("result_route_lease_snapshot").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/lease_records", lease_result_schema.get("leases").?.object.get("$ref").?.string);
    const transition_result_schema = defs.get("result_session_transition").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings(
        "#/$defs/transition_action_required_or_null",
        transition_result_schema.get("action_required").?.object.get("$ref").?.string,
    );
    const transition_result_object = defs.get("result_session_transition").?.object;
    try std.testing.expectEqual(@as(usize, 2), transition_result_object.get("allOf").?.array.items.len);
    const action_condition = transition_result_object.get("allOf").?.array.items[0].object;
    try std.testing.expectEqualStrings(
        "action_required",
        action_condition.get("if").?.object.get("properties").?.object.get("state").?.object.get("const").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/transition_action_required",
        action_condition.get("then").?.object.get("properties").?.object.get("action_required").?.object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "null",
        action_condition.get("else").?.object.get("properties").?.object.get("action_required").?.object.get("type").?.string,
    );
    const switched_condition = transition_result_object.get("allOf").?.array.items[1].object;
    try std.testing.expectEqualStrings(
        "#/$defs/opaque_handle",
        switched_condition.get("then").?.object.get("properties").?.object.get("selected_route_handle").?.object.get("$ref").?.string,
    );
    const repair_result_schema = defs.get("result_repair_handoff").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/repair_action", repair_result_schema.get("action").?.object.get("$ref").?.string);
    const teardown_result_schema = defs.get("result_session_teardown").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/teardown_cleanup", teardown_result_schema.get("cleanup").?.object.get("$ref").?.string);
    const teardown_error_data = defs.get("teardown_incomplete_error").?.object.get("properties").?.object
        .get("data").?.object;
    try std.testing.expectEqualStrings("#/$defs/teardown_incomplete_data", teardown_error_data.get("$ref").?.string);
    const teardown_reason_variants = defs.get("teardown_incomplete_data").?.object.get("oneOf").?.array.items;
    try std.testing.expectEqual(@as(usize, teardown_incomplete_reason_codes.len), teardown_reason_variants.len);
    inline for (teardown_incomplete_reason_codes, teardown_cleanup_fields, 0..) |reason_code, failed_field, index| {
        const variant_properties = teardown_reason_variants[index].object.get("properties").?.object;
        try std.testing.expectEqualStrings(
            reason_code,
            variant_properties.get("reason_code").?.object.get("const").?.string,
        );
        try std.testing.expectEqual(
            false,
            variant_properties.get("cleanup").?.object.get("properties").?.object
                .get(failed_field).?.object.get("const").?.bool,
        );
    }

    const lease_record = defs.get("lease_record").?.object;
    try std.testing.expectEqual(@as(usize, lease_required.len), lease_record.get("required").?.array.items.len);
    try std.testing.expect(lease_record.get("properties").?.object.get("owner_pid") != null);
    try std.testing.expect(lease_record.get("properties").?.object.get("heartbeat_at_ms") != null);
    try std.testing.expect(lease_record.get("properties").?.object.get("expires_at_ms") != null);

    const same_route = defs.get("proxy_attempt_same_route_retry").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings(
        "confirmed_pre_send_transport_failure",
        same_route.get("retry_trigger").?.object.get("const").?.string,
    );
    try std.testing.expectEqual(false, same_route.get("cross_account_replay").?.object.get("const").?.bool);
    try std.testing.expectEqual(false, same_route.get("account_handle").?.bool);
    try std.testing.expectEqual(false, same_route.get("route_handle").?.bool);
    try std.testing.expectEqual(false, same_route.get("model_demand").?.bool);
    const alternate = defs.get("proxy_attempt_alternate").?.object.get("properties").?.object;
    try std.testing.expectEqual(@as(usize, alternate_retry_triggers.len), alternate.get("retry_trigger").?.object.get("enum").?.array.items.len);
    try std.testing.expectEqualStrings("alternate_account", alternate.get("route_relation").?.object.get("const").?.string);
    try std.testing.expectEqualStrings("boolean", alternate.get("response_started").?.object.get("type").?.string);
    try std.testing.expectEqual(true, alternate.get("cross_account_replay").?.object.get("const").?.bool);
    try std.testing.expectEqual(false, alternate.get("model_demand").?.bool);
    try std.testing.expect(alternate.get("alternate_account_handle") != null);
    try std.testing.expect(alternate.get("alternate_route_handle") != null);
    const legal_sequences = defs.get("proxy_attempts").?.object.get("oneOf").?.array.items;
    try std.testing.expectEqualStrings(
        "#/$defs/proxy_attempt_initial_pre_send_failure",
        legal_sequences[1].object.get("prefixItems").?.array.items[0].object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/proxy_attempt_same_route_retry",
        legal_sequences[1].object.get("prefixItems").?.array.items[1].object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/proxy_attempt_initial_pre_body_failure",
        legal_sequences[2].object.get("prefixItems").?.array.items[0].object.get("$ref").?.string,
    );
    try std.testing.expectEqualStrings(
        "#/$defs/proxy_attempt_alternate",
        legal_sequences[2].object.get("prefixItems").?.array.items[1].object.get("$ref").?.string,
    );
}

test "managed harness schema excludes sensitive names and bounds typed extensions" {
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
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "secret") != null);
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "account[_-]*id") != null);
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "email") != null);
    try std.testing.expect(std.mem.indexOf(u8, names.get("not").?.object.get("pattern").?.string, "api[_-]*key") != null);
    try std.testing.expectEqual(@as(i64, 128), names.get("maxLength").?.integer);
    try std.testing.expectEqual(false, params.get("additionalProperties").?.bool);
    const extensions = params.get("patternProperties").?.object;
    try std.testing.expectEqualStrings("boolean", extensions.get("^x_flag_[a-z0-9_]{1,64}$").?.object.get("type").?.string);
    try std.testing.expectEqualStrings("integer", extensions.get("^x_count_[a-z0-9_]{1,64}$").?.object.get("type").?.string);
    try std.testing.expectEqualStrings("number", extensions.get("^x_ratio_[a-z0-9_]{1,64}$").?.object.get("type").?.string);
    const request_id = request.get("properties").?.object.get("id").?.object.get("oneOf").?.array.items[0].object;
    try std.testing.expectEqualStrings("^[A-Za-z0-9_-]+$", request_id.get("pattern").?.string);
    const preflight_reasons = defs.get("preflight_reasons").?.object;
    try std.testing.expectEqual(true, preflight_reasons.get("uniqueItems").?.bool);
    try std.testing.expectEqual(@as(i64, preflight_reason_codes.len), preflight_reasons.get("maxItems").?.integer);
}
