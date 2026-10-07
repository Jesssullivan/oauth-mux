const std = @import("std");

test "secure entropy succeeds on the supported libc target" {
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &first);
    defer std.crypto.secureZero(u8, &second);
    try std.testing.io.randomSecure(&first);
    try std.testing.io.randomSecure(&second);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}
