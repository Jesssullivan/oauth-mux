//! Build-time documentation renderer; uses the maintained runtime catalog.
//! This executable grants no provider, installation, or application authority.
const std = @import("std");
const reference = @import("reference.zig");

pub fn main(init: std.process.Init) !void {
    var threaded: std.Io.Threaded = .init(init.gpa, .{
        .async_limit = .limited(4),
        .concurrent_limit = .limited(24),
        .argv0 = .init(init.minimal.args),
        .environ = init.minimal.environ,
    });
    defer threaded.deinit();
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2 or !std.mem.eql(u8, args[1], "reference")) return error.InvalidArguments;
    const bundle = try reference.renderArguments(allocator, args[2..]);
    var buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var writer = std.Io.File.stdout().writerStreaming(threaded.io(), &buffer);
    try writer.interface.writeAll(bundle);
    try writer.interface.writeAll("\n");
    try writer.interface.flush();
}
