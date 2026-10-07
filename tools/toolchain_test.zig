const std = @import("std");
test "Zig release and std.Io boundary" {
    try std.testing.expectEqualStrings("0.17.0", @import("builtin").zig_version_string);
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{ .async_limit = .limited(2) });
    defer threaded.deinit();
    const io = threaded.io();
    _ = io;
}
