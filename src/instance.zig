//! Immutable launch-time instance selection. This never changes application HOME
//! or native session locations. Invalid explicit selections fail closed.
const std = @import("std");

pub const Selection = enum {
    default,
    dev,

    pub fn parse(value: ?[]const u8) !Selection {
        const supplied = value orelse return .default;
        if (std.mem.eql(u8, supplied, "default")) return .default;
        if (std.mem.eql(u8, supplied, "dev")) return .dev;
        return error.InvalidInstance;
    }

    pub fn fromEnvironment(env: *const std.process.Environ.Map) !Selection {
        return parse(env.get("OMUX_INSTANCE"));
    }

    /// Preserve existing release custody identity; development cannot share it.
    pub fn vaultRoot(self: Selection) [:0]const u8 {
        return switch (self) {
            .default => "installation-v1",
            .dev => "installation-dev-v1",
        };
    }
};
