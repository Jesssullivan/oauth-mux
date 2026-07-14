const std = @import("std");

pub const entropy_len = 32;
pub const carrier_len = std.base64.url_safe_no_pad.Encoder.calcSize(entropy_len);

comptime {
    if (carrier_len != 43) @compileError("256-bit base64url carrier length changed");
}

pub const AccessError = error{Revoked};

const State = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    encoded: [carrier_len]u8,
    revoked: bool = false,
};

/// Opaque ownership prevents value copies of the secret-bearing state. Pointer
/// aliases refer to the same synchronized capability and observe revocation.
pub const SessionCapability = opaque {
    /// Generates 256 bits with std's OS-seeded CSPRNG. The entropy input is
    /// zeroed before returning; only the canonical unpadded base64url carrier
    /// remains in the allocated state.
    pub fn generate(allocator: std.mem.Allocator) !*SessionCapability {
        var entropy: [entropy_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        std.crypto.random.bytes(&entropy);
        return fromEntropy(allocator, &entropy);
    }

    /// Copies the carrier into caller-owned memory. Borrowed views are not
    /// exposed because concurrent revocation securely clears the owned bytes.
    pub fn copyCarrier(
        self: *SessionCapability,
        destination: *[carrier_len]u8,
    ) AccessError!void {
        std.crypto.secureZero(u8, destination);
        const state = statePtr(self);
        state.mutex.lock();
        defer state.mutex.unlock();
        if (state.revoked) return error.Revoked;
        @memcpy(destination, &state.encoded);
    }

    /// Validates a canonical carrier without value-dependent comparison time.
    /// Length and revoked-state rejection are public framing decisions.
    pub fn validate(self: *SessionCapability, candidate: []const u8) bool {
        if (candidate.len != carrier_len) return false;
        const state = statePtr(self);
        state.mutex.lock();
        defer state.mutex.unlock();
        if (state.revoked) return false;
        return std.crypto.timing_safe.compare(
            u8,
            &state.encoded,
            candidate,
            .big,
        ) == .eq;
    }

    /// Idempotently denies future access and securely clears owned material.
    /// It is safe to race with copyCarrier, validate, and isRevoked.
    pub fn revoke(self: *SessionCapability) void {
        const state = statePtr(self);
        state.mutex.lock();
        defer state.mutex.unlock();
        std.crypto.secureZero(u8, &state.encoded);
        state.revoked = true;
    }

    pub fn isRevoked(self: *SessionCapability) bool {
        const state = statePtr(self);
        state.mutex.lock();
        defer state.mutex.unlock();
        return state.revoked;
    }

    /// Requires listener/request threads to be joined first. Revocation itself
    /// is synchronized; freeing storage while another thread enters a method is
    /// intentionally outside this object's ownership contract.
    pub fn deinit(self: *SessionCapability) void {
        const state = statePtr(self);
        self.revoke();
        const allocator = state.allocator;
        allocator.destroy(state);
    }
};

fn statePtr(capability: *SessionCapability) *State {
    return @ptrCast(@alignCast(capability));
}

fn fromEntropy(
    allocator: std.mem.Allocator,
    entropy: *const [entropy_len]u8,
) !*SessionCapability {
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .allocator = allocator,
        .encoded = undefined,
    };
    errdefer std.crypto.secureZero(u8, &state.encoded);
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(
        &state.encoded,
        entropy,
    );
    std.debug.assert(encoded.len == carrier_len);
    return @ptrCast(state);
}

fn copyCarrier(capability: *SessionCapability) ![carrier_len]u8 {
    var carrier: [carrier_len]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &carrier);
    try capability.copyCarrier(&carrier);
    return carrier;
}

test "generated capability is a canonical 256-bit base64url carrier" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();

    var encoded = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &encoded);
    try std.testing.expectEqual(carrier_len, encoded.len);
    try std.testing.expect(capability.validate(&encoded));

    const decoder = std.base64.url_safe_no_pad.Decoder;
    try std.testing.expectEqual(entropy_len, try decoder.calcSizeForSlice(&encoded));
    var decoded: [entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    try decoder.decode(&decoded, &encoded);

    var canonical: [carrier_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &canonical);
    const reencoded = std.base64.url_safe_no_pad.Encoder.encode(&canonical, &decoded);
    try std.testing.expectEqualStrings(&encoded, reencoded);
}

test "capability rejects every wrong carrier length" {
    var entropy = [_]u8{0x3c} ** entropy_len;
    defer std.crypto.secureZero(u8, &entropy);
    const capability = try fromEntropy(std.testing.allocator, &entropy);
    defer capability.deinit();

    var candidate: [carrier_len + 1]u8 = undefined;
    @memset(&candidate, 'A');
    for (0..candidate.len + 1) |len| {
        if (len == carrier_len) continue;
        try std.testing.expect(!capability.validate(candidate[0..len]));
    }
}

test "capability rejects malformed base64url encoding" {
    var entropy = [_]u8{0x5a} ** entropy_len;
    defer std.crypto.secureZero(u8, &entropy);
    const capability = try fromEntropy(std.testing.allocator, &entropy);
    defer capability.deinit();

    var expected = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &expected);
    var candidate = expected;
    defer std.crypto.secureZero(u8, &candidate);
    const invalid_bytes = [_]u8{ '=', '+', '/', ' ', '\n' };
    for (invalid_bytes) |invalid| {
        for (0..carrier_len) |index| {
            candidate = expected;
            candidate[index] = invalid;
            try std.testing.expect(!capability.validate(&candidate));
        }
    }
}

test "capability rejects every single-byte wrong value" {
    var entropy = [_]u8{0xa7} ** entropy_len;
    defer std.crypto.secureZero(u8, &entropy);
    const capability = try fromEntropy(std.testing.allocator, &entropy);
    defer capability.deinit();

    var expected = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &expected);
    var candidate = expected;
    defer std.crypto.secureZero(u8, &candidate);
    for (0..carrier_len) |index| {
        candidate = expected;
        candidate[index] = if (candidate[index] == 'A') 'B' else 'A';
        try std.testing.expect(!capability.validate(&candidate));
    }

    var other_entropy = [_]u8{0x4d} ** entropy_len;
    defer std.crypto.secureZero(u8, &other_entropy);
    const other = try fromEntropy(std.testing.allocator, &other_entropy);
    defer other.deinit();
    var other_carrier = try copyCarrier(other);
    defer std.crypto.secureZero(u8, &other_carrier);
    try std.testing.expect(!capability.validate(&other_carrier));
}

test "pointer aliases observe synchronized revocation and zeroing" {
    var entropy = [_]u8{0x91} ** entropy_len;
    defer std.crypto.secureZero(u8, &entropy);
    const capability = try fromEntropy(std.testing.allocator, &entropy);
    defer capability.deinit();
    const alias = capability;

    var saved = try copyCarrier(alias);
    defer std.crypto.secureZero(u8, &saved);
    try std.testing.expect(capability.validate(&saved));

    capability.revoke();
    try std.testing.expect(alias.isRevoked());
    var denied: [carrier_len]u8 = undefined;
    try std.testing.expectError(error.Revoked, alias.copyCarrier(&denied));
    for (denied) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expect(!alias.validate(&saved));
    for (statePtr(alias).encoded) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    alias.revoke();
    try std.testing.expect(alias.isRevoked());
}

test "validation and revocation are synchronized" {
    var entropy = [_]u8{0x2e} ** entropy_len;
    defer std.crypto.secureZero(u8, &entropy);
    const capability = try fromEntropy(std.testing.allocator, &entropy);
    defer capability.deinit();
    var expected = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &expected);

    const Validator = struct {
        capability: *SessionCapability,
        expected: *const [carrier_len]u8,
        stop: *std.atomic.Value(bool),
        iterations: *std.atomic.Value(usize),

        fn run(self: *@This()) void {
            while (true) {
                _ = self.capability.validate(self.expected);
                _ = self.capability.isRevoked();
                _ = self.iterations.fetchAdd(1, .release);
                if (self.stop.load(.acquire)) return;
            }
        }
    };
    var stop = std.atomic.Value(bool).init(false);
    var iterations = std.atomic.Value(usize).init(0);
    var validator = Validator{
        .capability = capability,
        .expected = &expected,
        .stop = &stop,
        .iterations = &iterations,
    };
    const thread = try std.Thread.spawn(.{}, Validator.run, .{&validator});
    while (iterations.load(.acquire) == 0) std.Thread.yield() catch {};
    capability.revoke();
    stop.store(true, .release);
    thread.join();

    try std.testing.expect(iterations.load(.acquire) > 0);
    try std.testing.expect(capability.isRevoked());
    try std.testing.expect(!capability.validate(&expected));
}
