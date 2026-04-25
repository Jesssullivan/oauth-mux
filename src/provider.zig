const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

pub const ParseError = error{
    InvalidFormat,
    MissingField,
    OutOfMemory,
};

pub const TokenFields = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: types.TokenType = .bearer,
    expires_at: ?i64 = null,
};

pub fn parseToken(kind: types.ProviderKind, raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    return switch (kind) {
        .claude => parseClaude(raw, allocator),
        .codex => parseCodex(raw, allocator),
        .gemini => parseGemini(raw, allocator),
        .github => parseGitHub(raw, allocator),
        .vercel => parseVercel(raw, allocator),
        .mcp => parseMcp(raw, allocator),
    };
}

pub fn buildCredentialFile(kind: types.ProviderKind, token: TokenFields, allocator: std.mem.Allocator) ![]const u8 {
    return switch (kind) {
        .claude => buildClaudeCredential(token, allocator),
        .codex => buildCodexAuth(token, allocator),
        .gemini => buildGeminiCreds(token, allocator),
        else => buildGenericJson(token, allocator),
    };
}

pub fn credentialFileName(kind: types.ProviderKind) []const u8 {
    return switch (kind) {
        .claude => ".credentials.json",
        .codex => "auth.json",
        .gemini => "oauth_creds.json",
        else => "credentials.json",
    };
}

pub fn detectProvider(argv: []const []const u8) ?types.ProviderKind {
    if (argv.len == 0) return null;
    const cmd = std.fs.path.basename(argv[0]);
    if (std.mem.eql(u8, cmd, "claude")) return .claude;
    if (std.mem.eql(u8, cmd, "codex")) return .codex;
    if (std.mem.eql(u8, cmd, "gemini")) return .gemini;
    if (std.mem.eql(u8, cmd, "vercel")) return .vercel;
    if (std.mem.eql(u8, cmd, "gh")) return .github;
    return null;
}

// ── Claude Code ──
// Format: {"accessToken":"...","refreshToken":"...","expiresAt":"2025-..."}

fn parseClaude(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    // Try wrapped format first: {"claudeAiOauth":{"accessToken":"...",...}}
    if (std.json.parseFromSlice(ClaudeWrapped, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    })) |parsed| {
        defer parsed.deinit();
        if (parsed.value.claudeAiOauth) |creds| {
            return .{
                .access_token = allocator.dupe(u8, creds.accessToken) catch return error.OutOfMemory,
                .refresh_token = if (creds.refreshToken) |rt|
                    (allocator.dupe(u8, rt) catch return error.OutOfMemory)
                else
                    null,
                .expires_at = creds.expiresAt,
            };
        }
    } else |_| {}

    // Try flat format: {"accessToken":"...",...}
    const parsed = std.json.parseFromSlice(ClaudeCredentials, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidFormat;
    defer parsed.deinit();

    return .{
        .access_token = allocator.dupe(u8, parsed.value.accessToken) catch return error.OutOfMemory,
        .refresh_token = if (parsed.value.refreshToken) |rt|
            (allocator.dupe(u8, rt) catch return error.OutOfMemory)
        else
            null,
        .expires_at = parsed.value.expiresAt,
    };
}

const ClaudeWrapped = struct {
    claudeAiOauth: ?ClaudeCredentials = null,
};

const ClaudeCredentials = struct {
    accessToken: []const u8,
    refreshToken: ?[]const u8 = null,
    expiresAt: ?i64 = null,
};

fn buildClaudeCredential(token: TokenFields, allocator: std.mem.Allocator) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();
    try writer.writeAll("{\"accessToken\":\"");
    try writer.writeAll(token.access_token);
    try writer.writeAll("\"");
    if (token.refresh_token) |rt| {
        try writer.writeAll(",\"refreshToken\":\"");
        try writer.writeAll(rt);
        try writer.writeAll("\"");
    }
    if (token.expires_at) |exp| {
        try writer.print(",\"expiresAt\":{d}", .{exp});
    }
    try writer.writeAll("}");
    return buf.toOwnedSlice();
}

// ── Codex CLI ──
// Format: {"auth_mode":"chatgpt","tokens":{"access_token":"...","refresh_token":"...","expires_in":3600}}

fn parseCodex(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    const parsed = std.json.parseFromSlice(CodexAuth, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidFormat;
    defer parsed.deinit();

    // API key mode
    if (parsed.value.OPENAI_API_KEY) |key| {
        return .{
            .access_token = allocator.dupe(u8, key) catch return error.OutOfMemory,
            .token_type = .api_key,
        };
    }

    // OAuth mode
    if (parsed.value.tokens) |tokens| {
        return .{
            .access_token = allocator.dupe(u8, tokens.access_token) catch return error.OutOfMemory,
            .refresh_token = if (tokens.refresh_token) |rt|
                (allocator.dupe(u8, rt) catch return error.OutOfMemory)
            else
                null,
        };
    }

    return error.MissingField;
}

const CodexAuth = struct {
    auth_mode: ?[]const u8 = null,
    OPENAI_API_KEY: ?[]const u8 = null,
    tokens: ?CodexTokens = null,
};

const CodexTokens = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_in: ?i64 = null,
};

fn buildCodexAuth(token: TokenFields, allocator: std.mem.Allocator) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();
    if (token.token_type == .api_key) {
        try writer.writeAll("{\"auth_mode\":\"api\",\"OPENAI_API_KEY\":\"");
        try writer.writeAll(token.access_token);
        try writer.writeAll("\"}");
    } else {
        try writer.writeAll("{\"auth_mode\":\"chatgpt\",\"tokens\":{\"access_token\":\"");
        try writer.writeAll(token.access_token);
        try writer.writeAll("\"");
        if (token.refresh_token) |rt| {
            try writer.writeAll(",\"refresh_token\":\"");
            try writer.writeAll(rt);
            try writer.writeAll("\"");
        }
        try writer.writeAll("}}");
    }
    return buf.toOwnedSlice();
}

// ── Gemini CLI ──
// Format: {"access_token":"...","refresh_token":"...","token_uri":"...","expiry":"2025-..."}

fn parseGemini(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    const parsed = std.json.parseFromSlice(GeminiCreds, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidFormat;
    defer parsed.deinit();

    return .{
        .access_token = allocator.dupe(u8, parsed.value.access_token) catch return error.OutOfMemory,
        .refresh_token = if (parsed.value.refresh_token) |rt|
            (allocator.dupe(u8, rt) catch return error.OutOfMemory)
        else
            null,
    };
}

const GeminiCreds = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_uri: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
};

fn buildGeminiCreds(token: TokenFields, allocator: std.mem.Allocator) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();
    try writer.writeAll("{\"access_token\":\"");
    try writer.writeAll(token.access_token);
    try writer.writeAll("\"");
    if (token.refresh_token) |rt| {
        try writer.writeAll(",\"refresh_token\":\"");
        try writer.writeAll(rt);
        try writer.writeAll("\"");
    }
    try writer.writeAll("}");
    return buf.toOwnedSlice();
}

// ── GitHub CLI ──
// Format: {"oauth_token":"gho_..."}
fn parseGitHub(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    return parseGenericBearer(raw, allocator);
}

// ── Vercel CLI ──
// Format: {"token":"...","refreshToken":"...","expiresAt":12345}
fn parseVercel(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    const parsed = std.json.parseFromSlice(struct {
        token: ?[]const u8 = null,
        refreshToken: ?[]const u8 = null,
        expiresAt: ?i64 = null,
    }, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidFormat;
    defer parsed.deinit();

    const tok = parsed.value.token orelse return error.MissingField;
    return .{
        .access_token = allocator.dupe(u8, tok) catch return error.OutOfMemory,
        .refresh_token = if (parsed.value.refreshToken) |rt|
            (allocator.dupe(u8, rt) catch return error.OutOfMemory)
        else
            null,
        .expires_at = parsed.value.expiresAt,
    };
}

// ── MCP ──
fn parseMcp(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    return parseGenericBearer(raw, allocator);
}

fn parseGenericBearer(raw: []const u8, allocator: std.mem.Allocator) ParseError!TokenFields {
    // Try JSON first
    if (std.json.parseFromSlice(struct {
        access_token: ?[]const u8 = null,
        oauth_token: ?[]const u8 = null,
        token: ?[]const u8 = null,
    }, allocator, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    })) |parsed| {
        defer parsed.deinit();
        const tok = parsed.value.access_token orelse
            parsed.value.oauth_token orelse
            parsed.value.token orelse
            return error.MissingField;
        return .{
            .access_token = allocator.dupe(u8, tok) catch return error.OutOfMemory,
        };
    } else |_| {}

    // Treat as raw token string
    const trimmed = std.mem.trim(u8, raw, " \t\n\r");
    if (trimmed.len == 0) return error.MissingField;
    return .{
        .access_token = allocator.dupe(u8, trimmed) catch return error.OutOfMemory,
        .token_type = .api_key,
    };
}

fn buildGenericJson(token: TokenFields, allocator: std.mem.Allocator) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();
    try writer.writeAll("{\"access_token\":\"");
    try writer.writeAll(token.access_token);
    try writer.writeAll("\"}");
    return buf.toOwnedSlice();
}

// ── Tests ──

test "parseClaude valid" {
    const json =
        \\{"accessToken":"sk-ant-123","refreshToken":"rt-456","expiresAt":1700000000}
    ;
    const result = try parseClaude(json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("sk-ant-123", result.access_token);
    try std.testing.expectEqualStrings("rt-456", result.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 1700000000), result.expires_at);
}

test "parseCodex oauth mode" {
    const json =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"oat-789","refresh_token":"ort-012"}}
    ;
    const result = try parseCodex(json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("oat-789", result.access_token);
    try std.testing.expectEqualStrings("ort-012", result.refresh_token.?);
}

test "parseCodex api key mode" {
    const json =
        \\{"auth_mode":"api","OPENAI_API_KEY":"sk-proj-abc"}
    ;
    const result = try parseCodex(json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    try std.testing.expectEqualStrings("sk-proj-abc", result.access_token);
    try std.testing.expectEqual(types.TokenType.api_key, result.token_type);
}

test "parseGemini valid" {
    const json =
        \\{"access_token":"ya29.xyz","refresh_token":"1//abc","token_uri":"https://oauth2.googleapis.com/token"}
    ;
    const result = try parseGemini(json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("ya29.xyz", result.access_token);
    try std.testing.expectEqualStrings("1//abc", result.refresh_token.?);
}

test "detectProvider" {
    try std.testing.expectEqual(@as(?types.ProviderKind, .claude), detectProvider(&.{"claude"}));
    try std.testing.expectEqual(@as(?types.ProviderKind, .codex), detectProvider(&.{"codex"}));
    try std.testing.expectEqual(@as(?types.ProviderKind, .github), detectProvider(&.{"gh"}));
    try std.testing.expectEqual(@as(?types.ProviderKind, null), detectProvider(&.{"unknown"}));
    try std.testing.expectEqual(@as(?types.ProviderKind, null), detectProvider(&.{}));
}

test "buildClaudeCredential" {
    const cred = try buildClaudeCredential(.{
        .access_token = "tok",
        .refresh_token = "ref",
        .expires_at = 999,
    }, std.testing.allocator);
    defer std.testing.allocator.free(cred);
    try std.testing.expectEqualStrings(
        "{\"accessToken\":\"tok\",\"refreshToken\":\"ref\",\"expiresAt\":999}",
        cred,
    );
}
