//! Trusted native access-copy codec. No source permission is created here.
//! The caller retains original peer, image, consent, source and deadline fences.
const std = @import("std");
const consent = @import("native_source_consent.zig");
const discovery = @import("discovery.zig");
const metadata = @import("platform/file_metadata.zig");
const c = std.c;

// Existing source.connect acquires this separate meaning only when an opaque
// selected_native_context is present. Ordinary daemon-default and explicit
// source paths continue through their existing branch.
pub const ControlSelection = struct {
    owner_id: consent.Handle,
    nonce: consent.Handle,
    endpoint_generation: u64,
    context: consent.Context,
    custody_seconds: u32,
    consent_seconds: u32,
    allow_reenrollment: bool,
};

pub fn controlSelection(params: std.json.Value) !ControlSelection {
    if (params != .object) return error.InvalidParams;
    for (params.object.keys()) |name| {
        var admitted = false;
        inline for (.{ "kind", "provider", "operation_id", "expected_revision", "label", "selected_native_context",
            "native_access_copy", "custody_seconds", "consent_seconds", "allow_reenrollment" }) |allowed| {
            if (std.mem.eql(u8, name, allowed)) admitted = true;
        }
        if (!admitted) return error.InvalidParams;
    }
    try sameString(params, "kind", "native_store");
    try sameString(params, "provider", "codex");
    const permission = params.object.get("native_access_copy") orelse return error.NativeSourceConsentRequired;
    if (permission != .bool or !permission.bool) return error.NativeSourceConsentRequired;
    const selected = params.object.get("selected_native_context") orelse return error.InvalidParams;
    try requireKeys(selected, &.{ "owner_id", "process_nonce", "endpoint_generation", "source_context_id", "source_context_generation" });
    var allow_reenrollment = false;
    if (params.object.get("allow_reenrollment")) |value| {
        if (value != .bool) return error.InvalidParams;
        allow_reenrollment = value.bool;
    }
    return .{ .owner_id = try decodeHandle(try string(selected, "owner_id")),
        .nonce = try decodeHandle(try string(selected, "process_nonce")),
        .endpoint_generation = try canonicalGeneration(try string(selected, "endpoint_generation")),
        .context = .{ .id = try decodeHandle(try string(selected, "source_context_id")),
            .generation = try canonicalGeneration(try string(selected, "source_context_generation")) },
        .custody_seconds = try controlSeconds(params, "custody_seconds"),
        .consent_seconds = try controlSeconds(params, "consent_seconds"),
        .allow_reenrollment = allow_reenrollment };
}
fn controlSeconds(value: std.json.Value, name: []const u8) !u32 {
    const seconds = value.object.get(name) orelse return error.InvalidParams;
    if (seconds != .integer or seconds.integer < 1 or seconds.integer > 3600) return error.InvalidParams;
    return @intCast(seconds.integer);
}
fn canonicalGeneration(value: []const u8) !u64 {
    if (value.len == 0 or value.len > 20 or value[0] == '0') return error.InvalidParams;
    for (value) |byte| if (byte < '0' or byte > '9') return error.InvalidParams;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidParams;
}
pub const maximum_payload = 16 * 1024;
pub const payload_format = "omux-codex-access-v1";
pub const Request = struct {
    admission: consent.Admission,
    origin: consent.Handle,
    operation: [64]u8,
    custody_seconds: u32,
    consent_expires_at: i64,
    pub fn validate(self: Request) !void {
        try self.admission.owner.validate();
        try self.admission.context.validate();
        if (std.mem.allEqual(u8, &self.origin, 0) or self.custody_seconds == 0 or self.custody_seconds > 3600 or self.consent_expires_at <= 0 or
            self.admission.source_generation == 0 or self.admission.consent_generation == 0 or
            std.mem.allEqual(u8, &self.admission.source_id, 0) or std.mem.allEqual(u8, &self.admission.consent_id, 0)) return error.InvalidNativeSourceAuthority;
        for (self.operation) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidNativeSourceAuthority;
        if (std.mem.allEqual(u8, &self.operation, '0')) return error.InvalidNativeSourceAuthority;
    }
};
// Ordered strings are shared with the maintained native protocol. Numeric JSON
// values cannot masquerade as canonical generation strings.
pub const Fields = struct {
    protocolVersion: u32 = 2,
    ownerId: []const u8,
    processNonce: []const u8,
    endpointGeneration: []const u8,
    sourceOriginId: []const u8,
    sourceContextId: []const u8,
    sourceContextGeneration: []const u8,
    operationId: []const u8,
    consentId: []const u8,
    consentGeneration: []const u8,
    consentExpiresAt: []const u8,
    sourceId: []const u8,
    sourceGeneration: []const u8,
    forgetEpoch: []const u8,
    custodySeconds: []const u8,
    pub fn ordered(self: Fields) [15][]const u8 {
        return .{ "2", self.ownerId, self.processNonce, self.endpointGeneration, self.sourceOriginId,
            self.sourceContextId, self.sourceContextGeneration, self.operationId, self.consentId,
            self.consentGeneration, self.consentExpiresAt, self.sourceId, self.sourceGeneration, self.forgetEpoch, self.custodySeconds };
    }
};
fn handle(a: std.mem.Allocator, value: [32]u8) ![]const u8 {
    const hex = std.fmt.bytesToHex(value, .lower);
    return a.dupe(u8, &hex);
}
// Scratch field allocations belong to the caller's bounded request arena.
pub fn fields(a: std.mem.Allocator, request: Request) !Fields {
    try request.validate();
    return .{ .ownerId = try handle(a, request.admission.owner.id), .processNonce = try handle(a, request.admission.owner.nonce),
        .endpointGeneration = try std.fmt.allocPrint(a, "{d}", .{request.admission.owner.endpoint_generation}),
        .sourceOriginId = try handle(a, request.origin), .sourceContextId = try handle(a, request.admission.context.id),
        .sourceContextGeneration = try std.fmt.allocPrint(a, "{d}", .{request.admission.context.generation}),
        .operationId = try a.dupe(u8, &request.operation), .consentId = try handle(a, request.admission.consent_id),
        .consentGeneration = try std.fmt.allocPrint(a, "{d}", .{request.admission.consent_generation}),
        .consentExpiresAt = try std.fmt.allocPrint(a, "{d}", .{request.consent_expires_at}),
        .sourceId = try handle(a, request.admission.source_id), .sourceGeneration = try std.fmt.allocPrint(a, "{d}", .{request.admission.source_generation}),
        .forgetEpoch = try std.fmt.allocPrint(a, "{d}", .{request.admission.forget_epoch}),
        .custodySeconds = try std.fmt.allocPrint(a, "{d}", .{request.custody_seconds}) };
}
fn canonical(a: std.mem.Allocator, domain: []const u8, ordered: []const []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(a);
    try result.appendSlice(a, domain);
    try result.append(a, '\n');
    for (ordered) |field| {
        if (std.mem.indexOfScalar(u8, field, '\n') != null) return error.InvalidNativeSourceAuthority;
        try result.appendSlice(a, field);
        try result.append(a, '\n');
    }
    return result.toOwnedSlice(a);
}
fn macHex(a: std.mem.Allocator, key: [32]u8, domain: []const u8, ordered: []const []const u8) ![64]u8 {
    const bytes = try canonical(a, domain, ordered);
    defer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&digest, bytes, &key);
    defer std.crypto.secureZero(u8, &digest);
    return std.fmt.bytesToHex(digest, .lower);
}
pub fn requestProof(a: std.mem.Allocator, request: Request, key: [32]u8) ![64]u8 {
    const ordered = (try fields(a, request)).ordered();
    return macHex(a, key, "omux-native-source-acquire-v1", &ordered);
}
pub fn capabilityKey(text: [64]u8) ![32]u8 {
    var key: [32]u8 = undefined;
    for (text) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidNativeCapability;
    _ = std.fmt.hexToBytes(&key, &text) catch return error.InvalidNativeCapability;
    return key;
}
pub fn encodeRequest(a: std.mem.Allocator, request: Request, key: [32]u8) ![]u8 {
    const value = try fields(a, request);
    const proof = try requestProof(a, request, key);
    var params: std.json.ObjectMap = .empty;
    inline for (std.meta.fields(Fields)) |field| {
        try params.put(a, field.name, if (comptime std.mem.eql(u8, field.name, "protocolVersion"))
            .{ .integer = 2 } else .{ .string = @field(value, field.name) });
    }
    try params.put(a, "proof", .{ .string = try a.dupe(u8, &proof) });
    return std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = request.operation[0..],
        .method = "owner/source/acquire", .params = std.json.Value{ .object = params } }, .{});
}
fn requireKeys(value: std.json.Value, names: []const []const u8) !void {
    if (value != .object or value.object.count() != names.len) return error.InvalidNativeSourcePayload;
    for (names) |name| if (!value.object.contains(name)) return error.InvalidNativeSourcePayload;
}
fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    const found = value.object.get(name) orelse return error.InvalidNativeSourcePayload;
    if (found != .string) return error.InvalidNativeSourcePayload;
    return found.string;
}
fn sameString(value: std.json.Value, name: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try string(value, name), expected)) return error.NativeSourceBindingChanged;
}
fn decodeHandle(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidNativeSourcePayload;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidNativeSourcePayload;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidNativeSourcePayload;
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidNativeSourcePayload;
    return result;
}
pub fn verifyOrigin(a: std.mem.Allocator, result: std.json.Value, owner: consent.Owner, context: consent.Context, key: [32]u8) !consent.Handle {
    try owner.validate();
    try context.validate();
    try requireKeys(result, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "sourceContextId",
        "sourceContextGeneration", "sourceOriginId", "status", "credentialAcquisitionAuthorized", "originProof" });
    const version = result.object.get("protocolVersion").?;
    const acquisition = result.object.get("credentialAcquisitionAuthorized").?;
    if (version != .integer or version.integer != 2 or acquisition != .bool or acquisition.bool) return error.InvalidNativeSourcePayload;
    const id = try handle(a, owner.id);
    const nonce = try handle(a, owner.nonce);
    const endpoint = try std.fmt.allocPrint(a, "{d}", .{owner.endpoint_generation});
    const context_id = try handle(a, context.id);
    const generation = try std.fmt.allocPrint(a, "{d}", .{context.generation});
    try sameString(result, "ownerId", id);
    try sameString(result, "processNonce", nonce);
    try sameString(result, "endpointGeneration", endpoint);
    const status = try string(result, "status");
    if (std.mem.eql(u8, status, "unavailable")) {
        for ([_][]const u8{ "sourceContextId", "sourceContextGeneration", "sourceOriginId", "originProof" }) |name| {
            if (result.object.get(name).? != .null) return error.InvalidNativeSourcePayload;
        }
        return error.NativeSourceUnavailable;
    }
    try sameString(result, "sourceContextId", context_id);
    try sameString(result, "sourceContextGeneration", generation);
    try sameString(result, "status", "available");
    const origin_text = try string(result, "sourceOriginId");
    const origin = try decodeHandle(origin_text);
    const ordered = [_][]const u8{ "2", id, nonce, endpoint, context_id, generation, origin_text, "available", "false" };
    const expected_proof = try macHex(a, key, "omux-native-source-origin-v1", &ordered);
    const proof = try string(result, "originProof");
    if (proof.len != 64 or !std.crypto.timing_safe.eql([64]u8, expected_proof, proof[0..64].*)) return error.NativeSourceProofInvalid;
    return origin;
}
pub fn verifyReply(a: std.mem.Allocator, value: std.json.Value, request: Request, key: [32]u8, payload: []const u8) !void {
    try request.validate();
    if (payload.len == 0 or payload.len > maximum_payload) return error.InvalidNativeSourcePayload;
    try requireKeys(value, &.{ "protocolVersion", "ownerId", "processNonce", "endpointGeneration", "sourceOriginId", "sourceContextId",
        "sourceContextGeneration", "operationId", "consentId", "consentGeneration", "consentExpiresAt", "sourceId", "sourceGeneration", "forgetEpoch", "custodySeconds",
        "payloadFormat", "payloadBytes", "renewalOwner", "credentialAcquisitionAuthorized", "payloadSha256", "replyProof" });
    const version = value.object.get("protocolVersion").?;
    if (version != .integer or version.integer != 2) return error.InvalidNativeSourcePayload;
    const expected = try fields(a, request);
    inline for (std.meta.fields(Fields)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "protocolVersion")) try sameString(value, field.name, @field(expected, field.name));
    }
    try sameString(value, "payloadFormat", payload_format);
    const payload_bytes = try std.fmt.allocPrint(a, "{d}", .{payload.len});
    try sameString(value, "payloadBytes", payload_bytes);
    try sameString(value, "renewalOwner", "external");
    const acquired = value.object.get("credentialAcquisitionAuthorized").?;
    if (acquired != .bool or !acquired.bool) return error.InvalidNativeSourcePayload;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    defer std.crypto.secureZero(u8, &digest);
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    try sameString(value, "payloadSha256", &digest_hex);
    const ordered = expected.ordered();
    var reply_fields: [20][]const u8 = undefined;
    @memcpy(reply_fields[0..15], &ordered);
    reply_fields[15..].* = .{ payload_format, payload_bytes, "external", "true", &digest_hex };
    const expected_proof = try macHex(a, key, "omux-native-source-acquire-reply-v1", &reply_fields);
    const proof = try string(value, "replyProof");
    if (proof.len != 64 or !std.crypto.timing_safe.eql([64]u8, expected_proof, proof[0..64].*)) return error.NativeSourceProofInvalid;
}
// Test fixture construction only; never a production credential producer.
pub fn fixtureReply(a: std.mem.Allocator, request: Request, key: [32]u8, payload: []const u8) !std.json.Value {
    if (!@import("builtin").is_test) return error.TestOnly;
    const expected = try fields(a, request);
    var result: std.json.ObjectMap = .empty;
    inline for (std.meta.fields(Fields)) |field| {
        try result.put(a, field.name, if (comptime std.mem.eql(u8, field.name, "protocolVersion"))
            .{ .integer = 2 } else .{ .string = @field(expected, field.name) });
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const size = try std.fmt.allocPrint(a, "{d}", .{payload.len});
    var ordered: [20][]const u8 = undefined;
    const request_fields = expected.ordered();
    @memcpy(ordered[0..15], &request_fields);
    ordered[15..].* = .{ payload_format, size, "external", "true", &digest_hex };
    const proof = try macHex(a, key, "omux-native-source-acquire-reply-v1", &ordered);
    try result.put(a, "payloadFormat", .{ .string = payload_format });
    try result.put(a, "payloadBytes", .{ .string = size });
    try result.put(a, "renewalOwner", .{ .string = "external" });
    try result.put(a, "credentialAcquisitionAuthorized", .{ .bool = true });
    try result.put(a, "payloadSha256", .{ .string = try a.dupe(u8, &digest_hex) });
    try result.put(a, "replyProof", .{ .string = try a.dupe(u8, &proof) });
    return .{ .object = result };
}
// This function consumes fd even if cancellation, EOF, or expiry refuses it.
// The opt-in authenticated peer transport has already checked full seals.
pub fn readDescriptor(io: std.Io, a: std.mem.Allocator, fd: c.fd_t, until: std.Io.Clock.Timestamp) ![]u8 {
    defer _ = c.close(fd);
    try deadline(io, until);
    const status = try metadata.statFd(fd);
    if (status.size <= 0 or status.size > maximum_payload) return error.InvalidNativeSourcePayload;
    const bytes = try a.alloc(u8, @intCast(status.size));
    errdefer { std.crypto.secureZero(u8, bytes); a.free(bytes); }
    var offset: usize = 0;
    var interruptions: usize = 0;
    while (offset < bytes.len) {
        try deadline(io, until);
        const count = c.pread(fd, bytes[offset..].ptr, bytes.len - offset, @intCast(offset));
        if (count < 0) {
            if (c.errno(count) == .INTR and interruptions < 16) { interruptions += 1; continue; }
            return error.NativeSourceDescriptorRead;
        }
        if (count == 0) return error.NativeSourceDescriptorRead;
        offset += @intCast(count);
    }
    try deadline(io, until);
    return bytes;
}
pub fn deadline(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    try io.checkCancel();
    if (until.clock != .awake or until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.NativeSourceDeadline;
}
pub fn parsePayload(a: std.mem.Allocator, source_id: []const u8, payload: []const u8, now: i64, custody_seconds: u32) !discovery.OwnedCandidate {
    if (payload.len == 0 or payload.len > maximum_payload or custody_seconds == 0 or custody_seconds > 3600) return error.InvalidNativeSourcePayload;
    var scratch: [128 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
    var parsed = try std.json.parseFromSlice(std.json.Value, fixed.allocator(), payload, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer parsed.deinit();
    try requireKeys(parsed.value, &.{ "tokens", "expires_at" });
    const tokens = parsed.value.object.get("tokens").?;
    try requireKeys(tokens, &.{ "access_token" });
    _ = try string(tokens, "access_token");
    const expiry = parsed.value.object.get("expires_at").?;
    if (expiry != .null and expiry != .integer) return error.InvalidNativeSourcePayload;
    var result = try discovery.parseDocument(a, .codex, source_id, payload, now);
    errdefer result.deinit();
    result.custody_expires_at = @min(result.custody_expires_at, try std.math.add(i64, now, custody_seconds));
    return result;
}
