//! EnrollModuleTests: test root for src/enroll/* modules
//!
//! This module imports all enroll-related modules and ensures their tests compile and run.

const std = @import("std");

const reauth = @import("reauth.zig");
const device_code = @import("device_code.zig");
const browser_launch = @import("browser_launch.zig");
const claude_login = @import("claude_login.zig");

// Pull all test declarations into scope.
comptime {
    _ = reauth;
    _ = device_code;
    _ = browser_launch;
    _ = claude_login;
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
