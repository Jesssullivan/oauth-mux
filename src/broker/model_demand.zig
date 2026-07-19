//! Parse-free exact-model demand for the shared broker decision core.
//!
//! Adapters admit request metadata before constructing this type. The core
//! copies only the already-observed exact model bytes into a bounded value: it
//! has no provider vocabulary, request-body access, parsing, interning, or
//! allocation.

const std = @import("std");

pub const max_model_len: usize = 256;
pub const ModelError = error{InvalidExactModel};

/// Stable exact-model identity from an admitted request observation. Model
/// bytes are case-sensitive and byte-preserving; this type validates only the
/// surface-v2 1..256 byte bound and never parses or normalizes provider names.
pub const ExactModel = struct {
    buf: [max_model_len]u8 = [_]u8{0} ** max_model_len,
    len: u16 = 0,

    pub fn init(value: []const u8) ModelError!ExactModel {
        if (value.len == 0 or value.len > max_model_len) {
            return error.InvalidExactModel;
        }
        var model = ExactModel{};
        @memcpy(model.buf[0..value.len], value);
        model.len = @intCast(value.len);
        return model;
    }

    pub fn isValid(self: ExactModel) bool {
        return self.len > 0 and self.len <= max_model_len;
    }

    pub fn bytes(self: *const ExactModel) []const u8 {
        if (!self.isValid()) return &.{};
        return self.buf[0..self.len];
    }

    pub fn eql(self: ExactModel, other: ExactModel) bool {
        return self.isValid() and
            other.isValid() and
            std.mem.eql(u8, self.bytes(), other.bytes());
    }
};

/// One admitted request's exact-model requirement. Model classes and fallback
/// substitutions are intentionally not representable.
pub const ModelDemand = struct {
    exact_model: ExactModel,

    pub fn init(exact_model: []const u8) ModelError!ModelDemand {
        return .{ .exact_model = try ExactModel.init(exact_model) };
    }

    pub fn isValid(self: ModelDemand) bool {
        return self.exact_model.isValid();
    }

    pub fn accepts(self: ModelDemand, candidate: ExactModel) bool {
        return self.isValid() and self.exact_model.eql(candidate);
    }
};

test {
    std.testing.refAllDeclsRecursive(@This());
}

test "ModelDemand owns stable byte-exact model state" {
    const fields = @typeInfo(ModelDemand).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expect(fields[0].type == ExactModel);

    var source = [_]u8{ 'M', 'o', 'd', 'e', 'l', '-', 'E', 'x', 'a', 'c', 't' };
    const demand = try ModelDemand.init(&source);
    source[0] = 'x';

    try std.testing.expectEqualStrings("Model-Exact", demand.exact_model.bytes());
    try std.testing.expect(demand.accepts(try ExactModel.init("Model-Exact")));
    try std.testing.expect(!demand.accepts(try ExactModel.init("model-exact")));
    try std.testing.expect(!demand.accepts(try ExactModel.init("Model")));
}

test "exact model enforces the surface-v2 byte bounds" {
    try std.testing.expectError(error.InvalidExactModel, ModelDemand.init(""));

    var max: [max_model_len]u8 = [_]u8{'m'} ** max_model_len;
    const demand = try ModelDemand.init(&max);
    try std.testing.expectEqual(@as(usize, max_model_len), demand.exact_model.bytes().len);

    var overlong: [max_model_len + 1]u8 = [_]u8{'m'} ** (max_model_len + 1);
    try std.testing.expectError(error.InvalidExactModel, ModelDemand.init(&overlong));

    const invalid = ModelDemand{ .exact_model = .{} };
    try std.testing.expect(!invalid.isValid());
    try std.testing.expect(!invalid.accepts(try ExactModel.init("model")));
}

fn acceptsAfterAsciiNormalization(demand: ModelDemand, candidate: ExactModel) bool {
    return demand.isValid() and
        candidate.isValid() and
        std.ascii.eqlIgnoreCase(demand.exact_model.bytes(), candidate.bytes());
}

test "negative control: model normalization violates exact-model demand" {
    const demand = try ModelDemand.init("claude-opus-4");
    const normalized_candidate = try ExactModel.init("CLAUDE-OPUS-4");

    try std.testing.expect(!demand.accepts(normalized_candidate));
    try std.testing.expect(acceptsAfterAsciiNormalization(demand, normalized_candidate));
}
