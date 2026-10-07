//! Dedicated Bazel delivery-test executable; excluded from shipped artifacts.
//! Exercises the real transport/trust policy against one ephemeral local server.
const std = @import("std");
const transport = @import("transport.zig");
pub const allow_transport_fixtures = true;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = .limited(1), .concurrent_limit = .limited(2), .argv0 = .init(init.minimal.args), .environ = init.minimal.environ });
    defer threaded.deinit();
    const io = threaded.io();
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    const prefix = "https://localhost:";
    const suffix = "/identity";
    const url = args[1];
    if (!std.mem.startsWith(u8, url, prefix) or !std.mem.endsWith(u8, url, suffix) or url.len <= prefix.len + suffix.len) return error.UndeclaredEndpoint;
    const port = try std.fmt.parseInt(u16, url[prefix.len .. url.len - suffix.len], 10);
    if (port == 0) return error.UndeclaredEndpoint;
    const client = try transport.Client.init(allocator);
    defer client.deinit();
    _ = try client.fetchJson(.{ .endpoint = .fixture_tls_identity, .fixture_port = port, .account_id = "tls-fixture", .grant_id = "tls-fixture", .timeout_ms = 3000 });
    for (0..400) |_| {
        if (client.poll()) |value| {
            var completion = value;
            defer completion.deinit(allocator);
            const response = switch (completion.result) {
                .response => |data| data,
                .failure => |reason| return switch (reason) {
                    .canceled => error.TlsProbeCanceled,
                    .deadline => error.TlsProbeDeadline,
                    .response_too_large => error.TlsProbeResponseTooLarge,
                    .transport => error.TlsProbeTransportFailure,
                    .tls => error.TlsProbeTrustFailure,
                    .allocation => error.TlsProbeAllocationFailure,
                    .invalid_json => error.TlsProbeInvalidJson,
                },
            };
            if (response.status != 200) return error.FixtureRejected;
            var buffer: [4096]u8 = undefined;
            var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
            try writer.interface.writeAll(response.body);
            try writer.interface.flush();
            return;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.FixtureTimeout;
}
