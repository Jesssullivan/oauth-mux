//! Test-only ephemeral RSA signer. Private key exists only beneath TEST_TMPDIR,
//! never argv/stdout/logs/evidence. Production import cannot use this factory.
const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("oauth_oidc_crypto.zig");
const c = @import("c");
pub const Signer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    tool: []u8,
    directory: [:0]u8,
    descriptor: c_int = -1,
    created: [3]bool = @splat(false),
    pub const names = [_][:0]const u8{ "key.pem", "input.txt", "signature.bin" };

    pub fn init(a: std.mem.Allocator, io: std.Io, tool: []const u8, until: std.Io.Clock.Timestamp) !Signer {
        if (!builtin.is_test) return error.TestOnlySigner;
        if (tool.len == 0 or tool.len > 4096 or std.mem.indexOfScalar(u8, tool, 0) != null or
            std.mem.indexOfScalar(u8, tool, '/') == null) return error.InvalidFixtureTool;
        const temp = std.c.getenv("TEST_TMPDIR") orelse return error.MissingDeclaredTestTmpdir;
        const root = std.mem.span(temp);
        if (root.len == 0 or root.len > 3000 or root[0] != '/') return error.InvalidFixtureTmpdir;
        // Keys never go beneath the evidence collector's directory.
        if (std.c.getenv("TEST_UNDECLARED_OUTPUTS_DIR")) |outputs| {
            const evidence = std.mem.span(outputs);
            if (evidence.len != 0 and (std.mem.eql(u8, root, evidence) or
                (std.mem.startsWith(u8, root, evidence) and root.len > evidence.len and root[evidence.len] == '/')))
                return error.InvalidFixtureTmpdir;
        }
        const directory = try std.fmt.allocPrintSentinel(a, "{s}/omux-oidc-key-XXXXXX", .{root}, 0);
        if (c.mkdtemp(directory.ptr) == null) { a.free(directory); return error.FixtureDirectoryFailed; }
        const owned_tool = a.dupe(u8, tool) catch |err| { _ = c.rmdir(directory.ptr); a.free(directory); return err; };
        var self: Signer = .{ .allocator = a, .io = io, .until = until, .tool = owned_tool, .directory = directory };
        errdefer self.cleanupOwned() catch @panic("synthetic signer initialization cleanup failed");
        self.descriptor = c.open(directory.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_NOFOLLOW | c.O_CLOEXEC);
        if (self.descriptor < 0) return error.FixtureDirectoryFailed;
        var info: c.struct_stat = undefined;
        if (c.fstat(self.descriptor, &info) != 0 or info.st_uid != c.getuid() or
            info.st_mode & 0o777 != 0o700) return error.FixtureDirectoryFailed;
        for (names, 0..) |name, index| {
            const fd = c.openat(self.descriptor, name.ptr, c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_NOFOLLOW | c.O_CLOEXEC, @as(c_uint, 0o600));
            if (fd < 0) return error.FixtureFileFailed;
            self.created[index] = true;
            if (c.close(fd) != 0) return error.FixtureCloseFailed;
        }
        const key_path = try self.path("key.pem");
        defer a.free(key_path);
        const output = try self.run(&.{ self.tool, "genpkey", "-quiet", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048", "-pkeyopt", "rsa_keygen_pubexp:65537", "-out", key_path }, 1);
        defer wipeFree(a, output);
        if (output.len != 0 or c.fchmodat(self.descriptor, "key.pem", 0o400, 0) != 0) return error.FixtureKeyFailed;
        try self.check();
        return self;
    }
    pub fn deinit(self: *Signer) !void {
        const result = self.cleanupOwned();
        self.* = undefined;
        try result;
    }
    fn cleanupOwned(self: *Signer) !void {
        var failed = false;
        for (names, self.created) |name, created| if (created) {
            if (c.unlinkat(self.descriptor, name.ptr, 0) != 0) failed = true;
        };
        if (self.descriptor >= 0 and c.close(self.descriptor) != 0) failed = true;
        self.descriptor = -1;
        if (c.rmdir(self.directory.ptr) != 0) failed = true;
        wipeFree(self.allocator, self.tool);
        wipeFree(self.allocator, self.directory);
        if (failed) return error.FixtureCleanupFailed;
    }
    fn path(self: *const Signer, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.directory, name });
    }
    fn check(self: *const Signer) !void {
        if (!builtin.is_test or self.until.clock != .awake or
            self.until.durationFromNow(self.io).raw.toNanoseconds() <= 0) return error.FixtureDeadline;
    }
    fn run(self: *const Signer, argv: []const []const u8, stdout_limit: usize) ![]u8 {
        try self.check();
        var env = std.process.Environ.Map.init(self.allocator);
        defer env.deinit();
        try env.put("OPENSSL_CONF", "/dev/null");
        // Fixed wrapper owns executable selection; no PATH/provider/config lookup.
        const result = try std.process.run(self.allocator, self.io, .{ .argv = argv,
            .environ_map = &env, .stdout_limit = .limited(stdout_limit), .stderr_limit = .limited(4096),
            .timeout = .{ .deadline = self.until } });
        defer wipeFree(self.allocator, result.stderr);
        errdefer wipeFree(self.allocator, result.stdout);
        if (result.term != .exited or result.term.exited != 0) return error.FixtureToolFailed;
        try self.check();
        return result.stdout;
    }
    pub fn jwks(self: *const Signer) ![]u8 {
        const key_path = try self.path("key.pem");
        defer self.allocator.free(key_path);
        const public = try self.run(&.{ self.tool, "rsa", "-in", key_path, "-modulus", "-noout" }, 1024);
        defer wipeFree(self.allocator, public);
        const row = std.mem.trim(u8, public, "\r\n");
        if (!std.mem.startsWith(u8, row, "Modulus=") or row.len != 8 + 512) return error.FixtureKeyFailed;
        var modulus: [256]u8 = undefined;
        _ = try std.fmt.hexToBytes(&modulus, row[8..]);
        var encoded: [342]u8 = undefined;
        const n = std.base64.url_safe_no_pad.Encoder.encode(&encoded, &modulus);
        return std.fmt.allocPrint(self.allocator, "{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"synthetic-ephemeral\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"{s}\",\"e\":\"AQAB\"}}]}}", .{n});
    }
    /// Caller owns and wipes result. claims must be synthetic test-only data.
    pub fn sign(self: *const Signer, claims: []const u8) ![]u8 {
        try self.check();
        if (claims.len == 0 or claims.len > 4096) return error.FixtureInputBound;
        const header = "{\"alg\":\"RS256\",\"kid\":\"synthetic-ephemeral\",\"typ\":\"JWT\"}";
        var encoded_header: [128]u8 = undefined;
        var encoded_claims: [5500]u8 = undefined;
        const h = std.base64.url_safe_no_pad.Encoder.encode(&encoded_header, header);
        const p = std.base64.url_safe_no_pad.Encoder.encode(&encoded_claims, claims);
        const input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ h, p });
        defer wipeFree(self.allocator, input);
        const fd = c.openat(self.descriptor, "input.txt", c.O_WRONLY | c.O_TRUNC | c.O_NOFOLLOW | c.O_CLOEXEC);
        if (fd < 0) return error.FixtureFileFailed;
        var written: usize = 0;
        while (written < input.len) {
            const n = c.write(fd, input[written..].ptr, input.len - written);
            if (n <= 0) { _ = c.close(fd); return error.FixtureFileFailed; }
            written += @intCast(n);
        }
        if (c.close(fd) != 0) return error.FixtureCloseFailed;
        const key_path = try self.path("key.pem");
        defer self.allocator.free(key_path);
        const input_path = try self.path("input.txt");
        defer self.allocator.free(input_path);
        const signature_path = try self.path("signature.bin");
        defer self.allocator.free(signature_path);
        const output = try self.run(&.{ self.tool, "dgst", "-sha256", "-sign", key_path,
            "-sigopt", "rsa_padding_mode:pkcs1", "-out", signature_path, input_path }, 1);
        defer wipeFree(self.allocator, output);
        if (output.len != 0) return error.FixtureToolFailed;
        const sig_fd = c.openat(self.descriptor, "signature.bin", c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
        if (sig_fd < 0) return error.FixtureFileFailed;
        var signature: [257]u8 = undefined;
        const length = c.read(sig_fd, &signature, signature.len);
        const closed = c.close(sig_fd);
        if (length != 256 or closed != 0) return error.FixtureSignatureFailed;
        var encoded_sig: [342]u8 = undefined;
        const sig = std.base64.url_safe_no_pad.Encoder.encode(&encoded_sig, signature[0..256]);
        try self.check();
        return std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ input, sig });
    }
};
fn wipeFree(a: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    a.free(bytes);
}

test "ephemeral declared OpenSSL signature passes actual RS256 then signed wrong nonce refuses" {
    const a = std.testing.allocator;
    const declared = std.c.getenv("OMUX_OIDC_OPENSSL") orelse return error.MissingDeclaredSignerTool;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(30) });
    var signer = try Signer.init(a, io, std.mem.span(declared), until);
    defer signer.deinit() catch @panic("synthetic signer cleanup failed");
    const keys = try signer.jwks();
    defer wipeFree(a, keys);
    const claims = "{\"iss\":\"https://auth.openai.com\",\"aud\":\"oaiapp_synthetic\",\"sub\":\"synthetic-subject\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"iat\":990,\"exp\":1100}";
    const jwt = try signer.sign(claims);
    defer wipeFree(a, jwt);
    var nonce: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &nonce, .{});
    var checked = try crypto.verifyIdToken(a, jwt, keys, "oaiapp_synthetic", nonce, 1000);
    defer checked.deinit();
    try std.testing.expectEqualStrings("synthetic-subject", checked.subject);
    try std.testing.expectError(error.OidcNonceMismatch, crypto.verifyIdToken(a, jwt, keys, "oaiapp_synthetic", @splat(1), 1000));
    try std.testing.expectError(error.OidcAudienceMismatch, crypto.verifyIdToken(a, jwt, keys, "oaiapp_other", nonce, 1000));
    try std.testing.expectError(error.OidcTokenTime, crypto.verifyIdToken(a, jwt, keys, "oaiapp_synthetic", nonce, 1100));
    const signature_start = std.mem.lastIndexOfScalar(u8, jwt, '.').? + 1;
    const original = jwt[signature_start];
    jwt[signature_start] = if (original == 'A') 'B' else 'A';
    try std.testing.expectError(error.InvalidOidcSignature, crypto.verifyIdToken(a, jwt, keys, "oaiapp_synthetic", nonce, 1000));
    jwt[signature_start] = original;
    const wrong_issuer = try signer.sign("{\"iss\":\"https://untrusted.invalid\",\"aud\":\"oaiapp_synthetic\",\"sub\":\"synthetic-subject\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"iat\":990,\"exp\":1100}");
    defer wipeFree(a, wrong_issuer);
    try std.testing.expectError(error.OidcIssuerMismatch, crypto.verifyIdToken(a, wrong_issuer, keys, "oaiapp_synthetic", nonce, 1000));
}
