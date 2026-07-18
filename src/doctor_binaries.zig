//! doctor "binaries" section (TIN-2723): version/SHA truth for the resident
//! keepalive service and the PATH-resolved oauth-mux, plus stale-binary and
//! PATH-shadow detection. Split from the service-residency proof in TIN-1830.
//!
//! Design notes:
//!  * Discovery never establishes execution trust. PATH and plist candidates
//!    are statted and hashed without running them.
//!  * A selected binary inherits the running binary's known version only when
//!    its SHA-256 is identical. Different or unreadable bytes remain version
//!    unknown; no selected binary is executed.
//!  * Invalid or unreadable resident containment is an explicit unhealthy,
//!    stale state. The doctor remains available without treating uncertainty
//!    as healthy.

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");

pub const keepalive_label = "dev.xoxd.omux.keepalive";
pub const keepalive_plist_rel = "Library/LaunchAgents/dev.xoxd.omux.keepalive.plist";
const resident_plist_max_bytes = 256 * 1024;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

pub const BinaryFacts = struct {
    path: []const u8,
    exists: bool,
    sha256: ?[]const u8,
    version: ?[]const u8,
    /// how `version` was resolved: "self" | "sha_match_self" | "unknown"
    version_source: []const u8,
    /// classifyOauthMuxBinarySource: repo_local | user_local | homebrew | nix_store | npm | path_or_installed
    source: []const u8,
};

pub const ResidentContainment = enum {
    unsupported,
    identity_unavailable,
    absent,
    plist_unreadable,
    plist_invalid,
    legacy_uncontained,
    binary_unreadable,
    healthy,

    pub fn label(self: ResidentContainment) []const u8 {
        return switch (self) {
            .unsupported => "unsupported",
            .identity_unavailable => "identity_unavailable",
            .absent => "absent",
            .plist_unreadable => "plist_unreadable",
            .plist_invalid => "plist_invalid",
            .legacy_uncontained => "legacy_uncontained",
            .binary_unreadable => "binary_unreadable",
            .healthy => "healthy",
        };
    }

    pub fn unhealthy(self: ResidentContainment) bool {
        return switch (self) {
            .identity_unavailable, .plist_unreadable, .plist_invalid, .legacy_uncontained, .binary_unreadable => true,
            .unsupported, .absent, .healthy => false,
        };
    }
};

pub const ResidentInfo = struct {
    /// launchd is darwin-only; false on other platforms (section still renders).
    supported: bool,
    label: []const u8,
    plist_path: []const u8,
    plist_present: bool,
    program_path: ?[]const u8,
    binary: ?BinaryFacts,
    containment: ResidentContainment,
};

const ResidentIdentity = struct {
    user: []const u8,
    home: []const u8,
};

const ResidentPlistRead = union(enum) {
    absent,
    unreadable,
    contents: []const u8,
};

pub const ShadowVerdict = struct {
    /// > 1 distinct SHA across the oauth-mux binaries on PATH.
    shadowed: bool,
    distinct_sha_count: usize,
};

pub const StaleInputs = struct {
    resident_containment: ResidentContainment,
    resident_sha: ?[]const u8,
    /// PATH-winner ("installed") reference.
    installed_sha: ?[]const u8,
    /// The currently running doctor binary.
    self_sha: ?[]const u8,
};

pub const StaleVerdict = struct {
    stale: bool,
    containment_unhealthy: bool = false,
    sha_mismatch: bool,
    version_older: bool,
    reason: []const u8,
};

pub const BinariesReport = struct {
    self: BinaryFacts,
    path_env_present: bool,
    path_entries: []const BinaryFacts,
    path_winner: ?BinaryFacts,
    shadow: ShadowVerdict,
    resident: ?ResidentInfo,
    stale: StaleVerdict,
};

pub const GatherOptions = struct {};

// ---------------------------------------------------------------------------
// Pure core: PATH scan
// ---------------------------------------------------------------------------

pub const ExecCheck = *const fn (ctx: *anyopaque, path: []const u8) bool;

pub const PathScan = struct {
    /// Full paths to executable oauth-mux binaries, in PATH order, deduped.
    paths: []const []const u8,

    pub fn winner(self: PathScan) ?[]const u8 {
        return if (self.paths.len > 0) self.paths[0] else null;
    }
};

/// Pure over `path_env`: splits on `delimiter`, joins each non-empty dir with
/// `binary_name`, and keeps the ones the injected `check` marks executable.
/// The first survivor wins (PATH precedence). Exact-duplicate paths collapse.
/// No side effects beyond allocation; callers pass an arena.
pub fn scanPath(
    allocator: std.mem.Allocator,
    path_env: []const u8,
    delimiter: u8,
    binary_name: []const u8,
    ctx: *anyopaque,
    check: ExecCheck,
) !PathScan {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();

    var it = std.mem.splitScalar(u8, path_env, delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, binary_name });
        if (!check(ctx, candidate)) continue;
        var dup = false;
        for (list.items) |seen| {
            if (std.mem.eql(u8, seen, candidate)) {
                dup = true;
                break;
            }
        }
        if (!dup) try list.append(candidate);
    }

    return .{ .paths = try list.toOwnedSlice() };
}

/// Count of distinct non-null SHAs — the PATH-shadow signal.
pub fn distinctShaCount(shas: []const ?[]const u8) usize {
    var count: usize = 0;
    var i: usize = 0;
    outer: while (i < shas.len) : (i += 1) {
        const s = shas[i] orelse continue;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (shas[j]) |prev| {
                if (std.mem.eql(u8, prev, s)) continue :outer;
            }
        }
        count += 1;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Pure core: version compare + staleness
// ---------------------------------------------------------------------------

pub const Ordering = enum { lt, eq, gt, unknown };

/// Offline, numeric semver compare over the first three dotted components.
/// Tolerant of a leading 'v' and of trailing build suffixes (`0.1.14-5-gabc`
/// compares as `0.1.14`). Any non-numeric component → `.unknown`.
pub fn compareSemver(a_in: []const u8, b_in: []const u8) Ordering {
    const a = std.mem.trimLeft(u8, a_in, "v");
    const b = std.mem.trimLeft(u8, b_in, "v");
    var ai = std.mem.splitScalar(u8, a, '.');
    var bi = std.mem.splitScalar(u8, b, '.');
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const av = parseLeadingUint(ai.next() orelse "0") orelse return .unknown;
        const bv = parseLeadingUint(bi.next() orelse "0") orelse return .unknown;
        if (av < bv) return .lt;
        if (av > bv) return .gt;
    }
    return .eq;
}

fn parseLeadingUint(s: []const u8) ?u64 {
    var end: usize = 0;
    while (end < s.len and s[end] >= '0' and s[end] <= '9') : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(u64, s[0..end], 10) catch null;
}

/// Offline staleness verdict for the resident keepalive binary. Invalid or
/// unreadable containment is stale by construction. A healthy resident must
/// have complete, identical SHA identity across the resident binary, PATH
/// winner, and currently running binary; uncertainty fails closed.
pub fn evaluateStaleness(in: StaleInputs) StaleVerdict {
    if (in.resident_containment.unhealthy()) {
        return .{
            .stale = true,
            .containment_unhealthy = true,
            .sha_mismatch = false,
            .version_older = false,
            .reason = in.resident_containment.label(),
        };
    }

    if (in.resident_containment == .unsupported or
        in.resident_containment == .absent)
    {
        return .{
            .stale = false,
            .containment_unhealthy = false,
            .sha_mismatch = false,
            .version_older = false,
            .reason = if (in.resident_containment == .unsupported)
                "unsupported"
            else
                "no_resident",
        };
    }

    const resident_sha = in.resident_sha orelse return .{
        .stale = true,
        .containment_unhealthy = false,
        .sha_mismatch = false,
        .version_older = false,
        .reason = "resident_identity_provenance_incomplete",
    };
    const installed_sha = in.installed_sha orelse return .{
        .stale = true,
        .containment_unhealthy = false,
        .sha_mismatch = false,
        .version_older = false,
        .reason = "resident_identity_provenance_incomplete",
    };
    const self_sha = in.self_sha orelse return .{
        .stale = true,
        .containment_unhealthy = false,
        .sha_mismatch = false,
        .version_older = false,
        .reason = "resident_identity_provenance_incomplete",
    };

    const differs_from_installed = !std.mem.eql(u8, resident_sha, installed_sha);
    const differs_from_current = !std.mem.eql(u8, resident_sha, self_sha);
    const sha_mismatch = differs_from_installed or differs_from_current;
    const reason: []const u8 = if (differs_from_installed and differs_from_current)
        "resident_sha_differs_from_installed_and_current"
    else if (differs_from_installed)
        "resident_sha_differs_from_installed"
    else if (differs_from_current)
        "resident_sha_differs_from_current"
    else
        "in_sync";

    return .{
        .stale = sha_mismatch,
        .containment_unhealthy = false,
        .sha_mismatch = sha_mismatch,
        .version_older = false,
        .reason = reason,
    };
}

// ---------------------------------------------------------------------------
// Pure core: LaunchAgent plist parse
// ---------------------------------------------------------------------------

const keepalive_program_tail = [_][]const u8{
    "keepalive",
    "--iterations",
    "100000",
    "--interval-ms",
    "60000",
    "--json",
};

const LaunchAgentKey = enum {
    label,
    program_arguments,
    run_at_load,
    keep_alive,
    throttle_interval,
    process_type,
    standard_out_path,
    standard_error_path,
    environment_variables,
};

const launch_agent_key_count = 9;
const launch_agent_required_key_count = 8;
const launch_agent_path = "/usr/bin:/bin:/usr/sbin:/sbin";

const ParsedXmlText = struct {
    value: []const u8,
    had_entity: bool,
};

const PlistCursor = struct {
    contents: []const u8,
    index: usize = 0,

    fn skipWhitespace(self: *PlistCursor) void {
        while (self.index < self.contents.len and isXmlWhitespace(self.contents[self.index])) {
            self.index += 1;
        }
    }

    fn startsWith(self: PlistCursor, literal: []const u8) bool {
        return std.mem.startsWith(u8, self.contents[self.index..], literal);
    }

    fn consume(self: *PlistCursor, literal: []const u8) bool {
        if (!self.startsWith(literal)) return false;
        self.index += literal.len;
        return true;
    }

    fn skipThrough(self: *PlistCursor, terminator: []const u8) bool {
        const relative = std.mem.indexOf(u8, self.contents[self.index..], terminator) orelse return false;
        self.index += relative + terminator.len;
        return true;
    }

    fn skipDocumentPrefix(self: *PlistCursor) bool {
        self.skipWhitespace();
        if (self.startsWith("<?")) {
            if (!self.consume("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")) return false;
        }

        while (true) {
            self.skipWhitespace();
            if (self.consume("<!--")) {
                if (!self.skipThrough("-->")) return false;
                continue;
            }
            if (self.startsWith("<!DOCTYPE")) {
                const end = std.mem.indexOfScalar(u8, self.contents[self.index..], '>') orelse return false;
                const declaration = self.contents[self.index .. self.index + end];
                // Custom entity declarations would require a full DTD parser.
                // The installed template uses only the standard external DTD.
                if (std.mem.indexOfScalar(u8, declaration, '[') != null) return false;
                self.index += end + 1;
                continue;
            }
            return true;
        }
    }

    fn parseTextElement(
        self: *PlistCursor,
        allocator: std.mem.Allocator,
        open: []const u8,
        close: []const u8,
    ) !?ParsedXmlText {
        if (!self.consume(open)) return null;
        const relative_end = std.mem.indexOf(u8, self.contents[self.index..], close) orelse return null;
        const raw = self.contents[self.index .. self.index + relative_end];
        if (std.mem.indexOfScalar(u8, raw, '<') != null) return null;
        self.index += relative_end + close.len;
        const decoded = (try decodeXmlText(allocator, raw)) orelse return null;
        return .{
            .value = decoded,
            .had_entity = std.mem.indexOfScalar(u8, raw, '&') != null,
        };
    }
};

const ParsedProgramArguments = union(enum) {
    contained: struct {
        home: []const u8,
        user: []const u8,
        binary: []const u8,
    },
    legacy_uncontained: []const u8,
};

const ParsedLaunchAgent = union(enum) {
    contained: []const u8,
    legacy_uncontained: []const u8,
};

/// Resolve the resident oauth-mux executable only when the complete effective
/// top-level LaunchAgent dictionary matches the contained service contract.
/// The legacy v0.1 shape is deliberately not returned as contained.
pub fn parseLaunchAgentProgramPath(
    allocator: std.mem.Allocator,
    contents: []const u8,
    expected_home: []const u8,
    expected_user: []const u8,
) !?[]const u8 {
    const parsed = (try parseLaunchAgent(
        allocator,
        contents,
        expected_home,
        expected_user,
    )) orelse return null;
    return switch (parsed) {
        .contained => |binary| binary,
        .legacy_uncontained => null,
    };
}

/// Classify only the exact contained contract or the exact shipped v0.1
/// direct-exec contract. Missing, duplicate, unknown, or malformed fields are
/// invalid rather than compatible.
fn parseLaunchAgent(
    allocator: std.mem.Allocator,
    contents: []const u8,
    expected_home: []const u8,
    expected_user: []const u8,
) !?ParsedLaunchAgent {
    var cursor = PlistCursor{ .contents = contents };
    if (!cursor.skipDocumentPrefix()) return null;
    if (!cursor.consume("<plist version=\"1.0\">")) return null;
    cursor.skipWhitespace();
    if (!cursor.consume("<dict>")) return null;

    var seen = [_]bool{false} ** launch_agent_key_count;
    var parsed_program: ?ParsedProgramArguments = null;
    var standard_out_path: ?[]const u8 = null;
    var standard_error_path: ?[]const u8 = null;

    while (true) {
        cursor.skipWhitespace();
        if (cursor.consume("</dict>")) break;

        const parsed_key = (try cursor.parseTextElement(allocator, "<key>", "</key>")) orelse return null;
        const key = launchAgentKey(parsed_key.value) orelse return null;
        const key_index = @intFromEnum(key);
        if (seen[key_index]) return null;
        seen[key_index] = true;
        // Keys in the installed canonical document are literal ASCII. Decoding
        // before this check makes entity aliases collide with their real key.
        if (parsed_key.had_entity) return null;

        cursor.skipWhitespace();
        switch (key) {
            .label => {
                const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return null;
                if (!std.mem.eql(u8, value.value, keepalive_label)) return null;
            },
            .program_arguments => {
                parsed_program = (try parseProgramArguments(allocator, &cursor)) orelse return null;
            },
            .run_at_load, .keep_alive => {
                if (!cursor.consume("<true/>")) return null;
            },
            .throttle_interval => {
                const value = (try cursor.parseTextElement(allocator, "<integer>", "</integer>")) orelse return null;
                if (!std.mem.eql(u8, value.value, "300")) return null;
            },
            .process_type => {
                const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return null;
                if (!std.mem.eql(u8, value.value, "Background")) return null;
            },
            .standard_out_path => {
                const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return null;
                standard_out_path = value.value;
            },
            .standard_error_path => {
                const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return null;
                standard_error_path = value.value;
            },
            .environment_variables => {
                if (!(try parseLegacyEnvironmentVariables(allocator, &cursor))) return null;
            },
        }
    }

    for (seen[0..launch_agent_required_key_count]) |present| {
        if (!present) return null;
    }
    cursor.skipWhitespace();
    if (!cursor.consume("</plist>")) return null;
    cursor.skipWhitespace();
    if (cursor.index != contents.len) return null;

    const program = parsed_program orelse return null;
    const expected_out = try std.fmt.allocPrint(
        allocator,
        "{s}/Library/Logs/oauth-mux/keepalive.out.log",
        .{expected_home},
    );
    const expected_error = try std.fmt.allocPrint(
        allocator,
        "{s}/Library/Logs/oauth-mux/keepalive.err.log",
        .{expected_home},
    );
    if (!std.mem.eql(u8, standard_out_path orelse return null, expected_out)) return null;
    if (!std.mem.eql(u8, standard_error_path orelse return null, expected_error)) return null;

    const has_legacy_environment = seen[@intFromEnum(LaunchAgentKey.environment_variables)];
    return switch (program) {
        .contained => |contained| {
            if (has_legacy_environment) return null;
            if (!std.mem.eql(u8, contained.home, expected_home)) return null;
            if (!std.mem.eql(u8, contained.user, expected_user)) return null;
            return ParsedLaunchAgent{ .contained = contained.binary };
        },
        .legacy_uncontained => |binary| {
            if (!has_legacy_environment) return null;
            return ParsedLaunchAgent{ .legacy_uncontained = binary };
        },
    };
}

fn isXmlWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

fn launchAgentKey(value: []const u8) ?LaunchAgentKey {
    if (std.mem.eql(u8, value, "Label")) return .label;
    if (std.mem.eql(u8, value, "ProgramArguments")) return .program_arguments;
    if (std.mem.eql(u8, value, "RunAtLoad")) return .run_at_load;
    if (std.mem.eql(u8, value, "KeepAlive")) return .keep_alive;
    if (std.mem.eql(u8, value, "ThrottleInterval")) return .throttle_interval;
    if (std.mem.eql(u8, value, "ProcessType")) return .process_type;
    if (std.mem.eql(u8, value, "StandardOutPath")) return .standard_out_path;
    if (std.mem.eql(u8, value, "StandardErrorPath")) return .standard_error_path;
    if (std.mem.eql(u8, value, "EnvironmentVariables")) return .environment_variables;
    return null;
}

fn parseProgramArguments(
    allocator: std.mem.Allocator,
    cursor: *PlistCursor,
) !?ParsedProgramArguments {
    if (!cursor.consume("<array>")) return null;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();
    while (true) {
        cursor.skipWhitespace();
        if (cursor.consume("</array>")) break;
        if (args.items.len >= 13) return null;
        const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return null;
        if (value.value.len == 0) return null;
        try args.append(value.value);
    }

    if (args.items.len == 13) {
        if (!std.mem.eql(u8, args.items[0], "/usr/bin/env")) return null;
        if (!std.mem.eql(u8, args.items[1], "-i")) return null;
        if (!std.mem.startsWith(u8, args.items[2], "HOME=")) return null;
        const home = args.items[2]["HOME=".len..];
        if (home.len == 0 or home[0] != '/' or !isSafeLaunchAgentValue(home)) return null;
        if (!std.mem.startsWith(u8, args.items[3], "USER=")) return null;
        const user = args.items[3]["USER=".len..];
        if (!isSafeLaunchAgentUser(user)) return null;
        if (!std.mem.eql(u8, args.items[4], "PATH=" ++ launch_agent_path)) return null;
        if (!std.mem.eql(u8, args.items[5], "NO_COLOR=1")) return null;
        if (!isSafeLaunchAgentPath(args.items[6])) return null;
        if (!hasKeepaliveProgramTail(args.items, 7)) return null;
        return ParsedProgramArguments{ .contained = .{
            .home = home,
            .user = user,
            .binary = args.items[6],
        } };
    }

    if (args.items.len == 7) {
        if (!isSafeLaunchAgentPath(args.items[0])) return null;
        if (!hasKeepaliveProgramTail(args.items, 1)) return null;
        return ParsedProgramArguments{ .legacy_uncontained = args.items[0] };
    }
    return null;
}

fn parseLegacyEnvironmentVariables(
    allocator: std.mem.Allocator,
    cursor: *PlistCursor,
) !bool {
    if (!cursor.consume("<dict>")) return false;
    var no_color_seen = false;
    var path_seen = false;

    while (true) {
        cursor.skipWhitespace();
        if (cursor.consume("</dict>")) break;

        const key = (try cursor.parseTextElement(allocator, "<key>", "</key>")) orelse return false;
        if (key.had_entity) return false;
        cursor.skipWhitespace();
        const value = (try cursor.parseTextElement(allocator, "<string>", "</string>")) orelse return false;
        if (std.mem.eql(u8, key.value, "NO_COLOR")) {
            if (no_color_seen or !std.mem.eql(u8, value.value, "1")) return false;
            no_color_seen = true;
        } else if (std.mem.eql(u8, key.value, "PATH")) {
            if (path_seen or !std.mem.eql(u8, value.value, launch_agent_path)) return false;
            path_seen = true;
        } else {
            return false;
        }
    }
    return no_color_seen and path_seen;
}

fn decodeXmlText(allocator: std.mem.Allocator, raw: []const u8) !?[]const u8 {
    if (!isValidRawXmlText(raw)) return null;
    var decoded = std.ArrayList(u8).init(allocator);
    errdefer decoded.deinit();

    var index: usize = 0;
    while (index < raw.len) {
        const amp_relative = std.mem.indexOfScalar(u8, raw[index..], '&') orelse {
            try decoded.appendSlice(raw[index..]);
            break;
        };
        const amp = index + amp_relative;
        try decoded.appendSlice(raw[index..amp]);
        const semicolon_relative = std.mem.indexOfScalar(u8, raw[amp + 1 ..], ';') orelse return null;
        const semicolon = amp + 1 + semicolon_relative;
        const entity = raw[amp + 1 .. semicolon];
        if (std.mem.eql(u8, entity, "amp")) {
            try decoded.append('&');
        } else if (std.mem.eql(u8, entity, "lt")) {
            try decoded.append('<');
        } else if (std.mem.eql(u8, entity, "gt")) {
            try decoded.append('>');
        } else if (std.mem.eql(u8, entity, "quot")) {
            try decoded.append('"');
        } else if (std.mem.eql(u8, entity, "apos")) {
            try decoded.append('\'');
        } else {
            const digits, const base: u8 = if (std.mem.startsWith(u8, entity, "#x"))
                .{ entity[2..], 16 }
            else if (std.mem.startsWith(u8, entity, "#"))
                .{ entity[1..], 10 }
            else
                return null;
            if (digits.len == 0) return null;
            for (digits) |digit| {
                const valid = if (base == 10)
                    digit >= '0' and digit <= '9'
                else
                    (digit >= '0' and digit <= '9') or
                        (digit >= 'a' and digit <= 'f') or
                        (digit >= 'A' and digit <= 'F');
                if (!valid) return null;
            }
            const codepoint = std.fmt.parseInt(u21, digits, base) catch return null;
            if (!isValidXmlCodepoint(codepoint)) return null;
            var encoded: [4]u8 = undefined;
            const encoded_len = std.unicode.utf8Encode(codepoint, &encoded) catch return null;
            try decoded.appendSlice(encoded[0..encoded_len]);
        }
        index = semicolon + 1;
    }
    return try decoded.toOwnedSlice();
}

fn isValidRawXmlText(raw: []const u8) bool {
    const view = std.unicode.Utf8View.init(raw) catch return false;
    var iterator = view.iterator();
    while (iterator.nextCodepoint()) |codepoint| {
        if (!isValidXmlCodepoint(codepoint)) return false;
    }
    return true;
}

fn isValidXmlCodepoint(codepoint: u21) bool {
    return codepoint == 0x9 or
        codepoint == 0xA or
        codepoint == 0xD or
        (codepoint >= 0x20 and codepoint <= 0xD7FF) or
        (codepoint >= 0xE000 and codepoint <= 0xFFFD) or
        (codepoint >= 0x10000 and codepoint <= 0x10FFFF);
}

fn isSafeLaunchAgentValue(value: []const u8) bool {
    if (value.len == 0 or
        std.mem.indexOf(u8, value, "@OMUX_") != null or
        std.mem.indexOf(u8, value, "--") != null or
        containsControlCodepoint(value))
    {
        return false;
    }
    for (value) |byte| {
        switch (byte) {
            '&', '<', '>', '|', '\\', '\r', '\n' => return false,
            else => {},
        }
    }
    return true;
}

fn containsControlCodepoint(value: []const u8) bool {
    const view = std.unicode.Utf8View.init(value) catch return true;
    var iterator = view.iterator();
    while (iterator.nextCodepoint()) |codepoint| {
        if (codepoint <= 0x1f or (codepoint >= 0x7f and codepoint <= 0x9f)) {
            return true;
        }
    }
    return false;
}

fn isSafeLaunchAgentUser(user: []const u8) bool {
    if (!isSafeLaunchAgentValue(user) or user[0] == '-') return false;
    for (user) |byte| {
        const alphanumeric =
            (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9');
        if (!alphanumeric and byte != '.' and byte != '_' and byte != '-') return false;
    }
    return true;
}

fn isSafeLaunchAgentPath(path: []const u8) bool {
    return isSafeLaunchAgentValue(path) and path[0] == '/' and
        std.mem.indexOfScalar(u8, path, '=') == null;
}

fn hasKeepaliveProgramTail(args: []const []const u8, offset: usize) bool {
    if (args.len != offset + keepalive_program_tail.len) return false;
    for (keepalive_program_tail, 0..) |expected, i| {
        if (!std.mem.eql(u8, args[offset + i], expected)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Effectful gather
// ---------------------------------------------------------------------------

/// Build the full binaries report. Every step is catch-guarded; on total
/// failure the caller renders "unavailable" and the doctor stays ok.
pub fn gather(arena: std.mem.Allocator, self_version: []const u8, opts: GatherOptions) !BinariesReport {
    _ = opts;

    // Self.
    const self_path = std.fs.selfExePathAlloc(arena) catch try arena.dupe(u8, "unknown");
    const self_known = !std.mem.eql(u8, self_path, "unknown");
    const self_sha: ?[]const u8 = if (self_known) (runtime.hashFileSha256Hex(arena, self_path) catch null) else null;
    const self_facts = BinaryFacts{
        .path = self_path,
        .exists = self_known,
        .sha256 = self_sha,
        .version = try arena.dupe(u8, self_version),
        .version_source = "self",
        .source = runtime.classifyOauthMuxBinarySource(self_path),
    };

    // PATH scan.
    const path_env = std.process.getEnvVarOwned(arena, "PATH") catch null;
    const path_present = path_env != null and path_env.?.len > 0;
    var entries = std.ArrayList(BinaryFacts).init(arena);
    if (path_env) |pe| {
        var scan_ctx: u8 = 0;
        const scan = scanPath(arena, pe, pathDelimiter(), "oauth-mux", &scan_ctx, realExecCheck) catch PathScan{ .paths = &.{} };
        for (scan.paths) |p| {
            try entries.append(factsFor(arena, p, self_sha, self_version));
        }
    }
    const entries_slice = try entries.toOwnedSlice();
    const winner: ?BinaryFacts = if (entries_slice.len > 0) entries_slice[0] else null;

    // PATH shadow.
    var shas = std.ArrayList(?[]const u8).init(arena);
    for (entries_slice) |f| try shas.append(f.sha256);
    const distinct = distinctShaCount(shas.items);

    // Resident service.
    const resident = gatherResident(arena, self_sha, self_version) catch null;

    // Staleness.
    const resident_binary: ?BinaryFacts = if (resident) |res| res.binary else null;
    const stale = evaluateStaleness(.{
        .resident_containment = if (resident) |res| res.containment else .identity_unavailable,
        .resident_sha = if (resident_binary) |b| b.sha256 else null,
        .installed_sha = if (winner) |w| w.sha256 else null,
        .self_sha = self_sha,
    });

    return .{
        .self = self_facts,
        .path_env_present = path_present,
        .path_entries = entries_slice,
        .path_winner = winner,
        .shadow = .{ .shadowed = distinct > 1, .distinct_sha_count = distinct },
        .resident = resident,
        .stale = stale,
    };
}

fn gatherResident(
    arena: std.mem.Allocator,
    self_sha: ?[]const u8,
    self_version: []const u8,
) !?ResidentInfo {
    if (builtin.os.tag != .macos) {
        return ResidentInfo{
            .supported = false,
            .label = keepalive_label,
            .plist_path = "",
            .plist_present = false,
            .program_path = null,
            .binary = null,
            .containment = .unsupported,
        };
    }

    return try gatherResidentForIdentity(
        arena,
        resolveDarwinResidentIdentity(arena),
        self_sha,
        self_version,
    );
}

fn gatherResidentForIdentity(
    arena: std.mem.Allocator,
    identity: ?ResidentIdentity,
    self_sha: ?[]const u8,
    self_version: []const u8,
) !ResidentInfo {
    const resolved = identity orelse return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = "",
        .plist_present = false,
        .program_path = null,
        .binary = null,
        .containment = .identity_unavailable,
    };

    const plist_path = try std.fs.path.join(arena, &.{ resolved.home, keepalive_plist_rel });
    const contents = switch (readResidentPlist(arena, plist_path)) {
        .contents => |value| value,
        .absent => return ResidentInfo{
            .supported = true,
            .label = keepalive_label,
            .plist_path = plist_path,
            .plist_present = false,
            .program_path = null,
            .binary = null,
            .containment = .absent,
        },
        .unreadable => return ResidentInfo{
            .supported = true,
            .label = keepalive_label,
            .plist_path = plist_path,
            .plist_present = true,
            .program_path = null,
            .binary = null,
            .containment = .plist_unreadable,
        },
    };

    const normalized = normalizeDarwinPlist(arena, contents) orelse return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = null,
        .binary = null,
        .containment = .plist_invalid,
    };
    const raw_parsed = (try parseLaunchAgent(
        arena,
        contents,
        resolved.home,
        resolved.user,
    )) orelse return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = null,
        .binary = null,
        .containment = .plist_invalid,
    };
    const normalized_parsed = (try parseLaunchAgent(
        arena,
        normalized,
        resolved.home,
        resolved.user,
    )) orelse return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = null,
        .binary = null,
        .containment = .plist_invalid,
    };
    if (!sameParsedLaunchAgent(raw_parsed, normalized_parsed)) return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = null,
        .binary = null,
        .containment = .plist_invalid,
    };

    const program = switch (raw_parsed) {
        .contained => |path| path,
        .legacy_uncontained => return ResidentInfo{
            .supported = true,
            .label = keepalive_label,
            .plist_path = plist_path,
            .plist_present = true,
            .program_path = null,
            .binary = null,
            .containment = .legacy_uncontained,
        },
    };
    const binary = factsForResident(arena, program, self_sha, self_version);
    const containment: ResidentContainment = if (!binary.exists or binary.sha256 == null)
        .binary_unreadable
    else
        .healthy;

    return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = if (containment == .healthy) program else null,
        .binary = if (containment == .healthy) binary else null,
        .containment = containment,
    };
}

fn readResidentPlist(arena: std.mem.Allocator, path: []const u8) ResidentPlistRead {
    if (builtin.os.tag != .macos) return .unreadable;

    // O_NONBLOCK prevents a FIFO reached directly or through a symlink from
    // blocking open. Final-target classification, size, and bytes all come
    // from this one descriptor, so a regular-file symlink is accepted without
    // introducing a stat/read path race.
    const fd = std.posix.open(path, .{
        .ACCMODE = .RDONLY,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0) catch |open_err| {
        return if (open_err == error.FileNotFound) .absent else .unreadable;
    };
    var file = std.fs.File{ .handle = fd };
    defer file.close();

    const stat = file.stat() catch return .unreadable;
    if (stat.kind != .file or stat.size > resident_plist_max_bytes) return .unreadable;

    const contents = file.readToEndAlloc(arena, resident_plist_max_bytes) catch return .unreadable;
    return .{ .contents = contents };
}

fn sameParsedLaunchAgent(left: ParsedLaunchAgent, right: ParsedLaunchAgent) bool {
    return switch (left) {
        .contained => |left_path| switch (right) {
            .contained => |right_path| std.mem.eql(u8, left_path, right_path),
            .legacy_uncontained => false,
        },
        .legacy_uncontained => |left_path| switch (right) {
            .contained => false,
            .legacy_uncontained => |right_path| std.mem.eql(u8, left_path, right_path),
        },
    };
}

const fixed_helper_timeout_ms: u64 = 2000;
const fixed_helper_poll_slice_ms: i32 = 10;
const fixed_helper_reap_reserve_max_ns: i128 = 100 * std.time.ns_per_ms;

const FixedHelperCommand = enum {
    plutil_normalize,
    id_uid,
    id_account,
    test_spin,
    test_inherited_stdout,
    test_output_overflow,
};

const FixedHelperFailure = enum {
    unsupported,
    invalid_command,
    spawn_failed,
    io_setup_failed,
    io_failed,
    output_too_large,
    timeout,
    kill_failed,
    reap_failed,
    reap_timeout,
    stdin_incomplete,
    exited_nonzero,
    signaled,
    allocation_failed,
};

const FixedHelperOutput = struct {
    stdout: []const u8,
    stderr: []const u8,
};

const FixedHelperResult = union(enum) {
    success: FixedHelperOutput,
    failure: FixedHelperFailure,
};

const FixedHelperLimits = struct {
    timeout_ms: u64,
    max_output_bytes: usize,
};

const FixedHelperDeadlines = struct {
    terminate_ns: i128,
    final_ns: i128,
};

const RawWaitResult = union(enum) {
    running,
    exited: u32,
    interrupted,
    no_child,
    failed,
};

const RawIoResult = union(enum) {
    bytes: usize,
    eof,
    would_block,
    interrupted,
    failed,
};

const RawPollResult = enum {
    ready,
    elapsed,
    interrupted,
    failed,
};

const RawFcntlResult = union(enum) {
    value: usize,
    interrupted,
    failed,
};

const FixedHelperOps = struct {
    context: ?*anyopaque = null,
    now_fn: *const fn (?*anyopaque) i128,
    read_fn: *const fn (?*anyopaque, std.posix.fd_t, []u8) RawIoResult,
    poll_fn: *const fn (?*anyopaque, []std.posix.pollfd, i32) RawPollResult,
    wait_fn: *const fn (?*anyopaque, std.posix.pid_t) RawWaitResult,
    kill_fn: *const fn (?*anyopaque, std.posix.pid_t) bool,

    fn now(self: *const FixedHelperOps) i128 {
        return self.now_fn(self.context);
    }

    fn read(
        self: *const FixedHelperOps,
        fd: std.posix.fd_t,
        buffer: []u8,
    ) RawIoResult {
        return self.read_fn(self.context, fd, buffer);
    }

    fn poll(
        self: *const FixedHelperOps,
        fds: []std.posix.pollfd,
        timeout_ms: i32,
    ) RawPollResult {
        return self.poll_fn(self.context, fds, timeout_ms);
    }

    fn waitNoHang(
        self: *const FixedHelperOps,
        pid: std.posix.pid_t,
    ) RawWaitResult {
        return self.wait_fn(self.context, pid);
    }

    fn killExact(
        self: *const FixedHelperOps,
        pid: std.posix.pid_t,
    ) bool {
        std.debug.assert(pid > 0);
        return self.kill_fn(self.context, pid);
    }
};

fn fixedHelperArgv(command: FixedHelperCommand) ?[]const []const u8 {
    return switch (command) {
        .plutil_normalize => &.{
            "/usr/bin/plutil",
            "-convert",
            "xml1",
            "-o",
            "-",
            "--",
            "-",
        },
        .id_uid => &.{ "/usr/bin/id", "-u" },
        .id_account => &.{ "/usr/bin/id", "-P" },
        // These fixed commands are compiled only into Zig test binaries. The
        // production helper has no path, argv, environment, or config seam
        // through which a caller can select an executable.
        .test_spin => if (builtin.is_test)
            &.{ "/bin/sh", "-c", "while :; do :; done" }
        else
            null,
        .test_inherited_stdout => if (builtin.is_test)
            &.{ "/bin/sh", "-c", "(/bin/sleep 1) & printf ok" }
        else
            null,
        .test_output_overflow => if (builtin.is_test)
            &.{
                "/bin/sh",
                "-c",
                "i=0; while [ \"$i\" -lt 1000 ]; do printf 0123456789; i=$((i + 1)); done",
            }
        else
            null,
    };
}

fn fixedHelperDeadlines(start_ns: i128, timeout_ms: u64) FixedHelperDeadlines {
    const timeout_ns = @max(
        @as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms,
        @as(i128, std.time.ns_per_ms),
    );
    const final_ns = start_ns + timeout_ns;
    const reap_reserve_ns = @max(
        @as(i128, std.time.ns_per_ms),
        @min(timeout_ns / 4, fixed_helper_reap_reserve_max_ns),
    );
    return .{
        .terminate_ns = final_ns - reap_reserve_ns,
        .final_ns = final_ns,
    };
}

/// Convert the remaining portion of one immutable deadline into a short poll
/// slice. A raw EINTR returns to the outer loop, which calls this again with
/// the same deadline and a newer monotonic timestamp.
fn fixedHelperPollTimeoutMs(deadline_ns: i128, now_ns: i128) ?i32 {
    if (now_ns >= deadline_ns) return null;
    const remaining_ns = deadline_ns - now_ns;
    const rounded_ms = @divTrunc(remaining_ns, std.time.ns_per_ms);
    return @intCast(@min(
        rounded_ms,
        @as(i128, fixed_helper_poll_slice_ms),
    ));
}

fn rawFcntl(fd: std.posix.fd_t, command: i32, arg: usize) RawFcntlResult {
    const rc = std.posix.system.fcntl(fd, command, arg);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => .{ .value = @intCast(rc) },
        .INTR => .interrupted,
        else => .failed,
    };
}

fn setNonBlocking(
    ops: *const FixedHelperOps,
    fd: std.posix.fd_t,
    deadline_ns: i128,
) ?FixedHelperFailure {
    var current: usize = undefined;
    while (true) {
        if (ops.now() >= deadline_ns) return .timeout;
        switch (rawFcntl(fd, std.posix.F.GETFL, 0)) {
            .value => |flags| {
                current = flags;
                break;
            },
            .interrupted => continue,
            .failed => return .io_setup_failed,
        }
    }

    const nonblocking: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    while (true) {
        if (ops.now() >= deadline_ns) return .timeout;
        switch (rawFcntl(
            fd,
            std.posix.F.SETFL,
            current | @as(usize, nonblocking),
        )) {
            .value => return null,
            .interrupted => continue,
            .failed => return .io_setup_failed,
        }
    }
}

fn rawRead(fd: std.posix.fd_t, buffer: []u8) RawIoResult {
    const rc = std.posix.system.read(fd, buffer.ptr, buffer.len);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => if (rc == 0)
            .eof
        else
            .{ .bytes = @intCast(rc) },
        .AGAIN => .would_block,
        .INTR => .interrupted,
        else => .failed,
    };
}

fn rawWrite(fd: std.posix.fd_t, bytes: []const u8) RawIoResult {
    if (bytes.len == 0) return .eof;
    const rc = std.posix.system.write(fd, bytes.ptr, bytes.len);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => if (rc == 0)
            .failed
        else
            .{ .bytes = @intCast(rc) },
        .AGAIN => .would_block,
        .INTR => .interrupted,
        else => .failed,
    };
}

fn rawPoll(fds: []std.posix.pollfd, timeout_ms: i32) RawPollResult {
    const rc = std.posix.system.poll(
        fds.ptr,
        @intCast(fds.len),
        timeout_ms,
    );
    return switch (std.posix.errno(rc)) {
        .SUCCESS => if (rc == 0) .elapsed else .ready,
        .INTR => .interrupted,
        else => .failed,
    };
}

fn rawWaitNoHang(pid: std.posix.pid_t) RawWaitResult {
    var status: if (builtin.link_libc) c_int else u32 = 0;
    const rc = std.posix.system.waitpid(
        pid,
        &status,
        @intCast(std.posix.W.NOHANG),
    );
    return switch (std.posix.errno(rc)) {
        .SUCCESS => if (rc == 0)
            .running
        else if (@as(std.posix.pid_t, @intCast(rc)) == pid)
            .{ .exited = @bitCast(status) }
        else
            .failed,
        .INTR => .interrupted,
        .CHILD => .no_child,
        else => .failed,
    };
}

fn closeChildStdin(child: *std.process.Child) void {
    if (child.stdin) |file| file.close();
    child.stdin = null;
}

fn closeChildPipes(child: *std.process.Child) void {
    closeChildStdin(child);
    if (child.stdout) |file| file.close();
    child.stdout = null;
    if (child.stderr) |file| file.close();
    child.stderr = null;
    if (comptime builtin.os.tag != .windows) {
        if (child.err_pipe) |fd| std.posix.close(fd);
        child.err_pipe = null;
    }
}

fn appendFixedHelperChunk(
    ops: *const FixedHelperOps,
    fd: std.posix.fd_t,
    output: *std.ArrayListUnmanaged(u8),
    max_output_bytes: usize,
    interrupt_is_failure: bool,
) ?FixedHelperFailure {
    var buffer: [4096]u8 = undefined;
    return switch (ops.read(fd, &buffer)) {
        .bytes => |count| blk: {
            if (count > max_output_bytes -| output.items.len) {
                break :blk .output_too_large;
            }
            std.debug.assert(output.capacity >= output.items.len + count);
            output.appendSliceAssumeCapacity(buffer[0..count]);
            break :blk null;
        },
        .eof, .would_block => null,
        .interrupted => if (interrupt_is_failure) .io_failed else null,
        .failed => .io_failed,
    };
}

const FixedHelperMonotonicClock = struct {
    timer: std.time.Timer,
};

fn systemFixedHelperNow(context: ?*anyopaque) i128 {
    const clock: *FixedHelperMonotonicClock =
        @ptrCast(@alignCast(context.?));
    return @intCast(clock.timer.read());
}

fn systemFixedHelperRead(
    _: ?*anyopaque,
    fd: std.posix.fd_t,
    buffer: []u8,
) RawIoResult {
    return rawRead(fd, buffer);
}

fn systemFixedHelperPoll(
    _: ?*anyopaque,
    fds: []std.posix.pollfd,
    timeout_ms: i32,
) RawPollResult {
    return rawPoll(fds, timeout_ms);
}

fn systemFixedHelperWait(
    _: ?*anyopaque,
    pid: std.posix.pid_t,
) RawWaitResult {
    return rawWaitNoHang(pid);
}

fn systemKillExactChild(_: ?*anyopaque, pid: std.posix.pid_t) bool {
    std.debug.assert(pid > 0);
    std.posix.kill(pid, std.posix.SIG.KILL) catch |err| switch (err) {
        error.ProcessNotFound => return true,
        else => return false,
    };
    return true;
}

fn systemFixedHelperOps(clock: *FixedHelperMonotonicClock) FixedHelperOps {
    return .{
        .context = clock,
        .now_fn = systemFixedHelperNow,
        .read_fn = systemFixedHelperRead,
        .poll_fn = systemFixedHelperPoll,
        .wait_fn = systemFixedHelperWait,
        .kill_fn = systemKillExactChild,
    };
}

fn terminateAndReapFixedHelper(
    ops: *const FixedHelperOps,
    pid: std.posix.pid_t,
    final_deadline_ns: i128,
    initial_failure: FixedHelperFailure,
) FixedHelperFailure {
    std.debug.assert(pid > 0);
    var failure = initial_failure;
    if (!ops.killExact(pid)) failure = .kill_failed;

    while (true) {
        switch (ops.waitNoHang(pid)) {
            .exited, .no_child => return failure,
            .running, .interrupted => {},
            .failed => failure = .reap_failed,
        }

        const now_ns = ops.now();
        if (now_ns >= final_deadline_ns) {
            // Every reap-timeout exit performs one final post-kill waitpid.
            // This remains nonblocking and does not extend the original
            // monotonic deadline.
            return switch (ops.waitNoHang(pid)) {
                .exited, .no_child => failure,
                .failed => .reap_failed,
                .running, .interrupted => .reap_timeout,
            };
        }

        var no_fds = [_]std.posix.pollfd{};
        const poll_ms = fixedHelperPollTimeoutMs(
            final_deadline_ns,
            now_ns,
        ) orelse continue;
        switch (ops.poll(&no_fds, poll_ms)) {
            .ready, .elapsed, .interrupted => {},
            .failed => if (failure != .kill_failed) {
                failure = .reap_failed;
            },
        }
    }
}

fn finishFixedHelper(
    status: u32,
    prior_failure: ?FixedHelperFailure,
    stdin_complete: bool,
    stdout: *std.ArrayListUnmanaged(u8),
    stderr: *std.ArrayListUnmanaged(u8),
) FixedHelperResult {
    if (prior_failure) |failure| return .{ .failure = failure };
    if (!stdin_complete) return .{ .failure = .stdin_incomplete };
    if (!std.posix.W.IFEXITED(status)) return .{ .failure = .signaled };
    if (std.posix.W.EXITSTATUS(status) != 0) return .{ .failure = .exited_nonzero };

    return .{ .success = .{
        .stdout = stdout.items,
        .stderr = stderr.items,
    } };
}

/// Run one allowlisted system helper with a single end-to-end monotonic
/// deadline. Parent pipe ends are nonblocking. Only the positive direct-child
/// PID is signaled; waitpid(WNOHANG) is retried within the original budget, and
/// the helper never waits for descendant-inherited stdout/stderr to close.
fn runBoundedFixedHelper(
    arena: std.mem.Allocator,
    command: FixedHelperCommand,
    child_env: ?*const std.process.EnvMap,
    stdin_bytes: ?[]const u8,
    limits: FixedHelperLimits,
) FixedHelperResult {
    var clock = FixedHelperMonotonicClock{
        .timer = std.time.Timer.start() catch
            return .{ .failure = .unsupported },
    };
    const ops = systemFixedHelperOps(&clock);
    return runBoundedFixedHelperWithOps(
        arena,
        command,
        child_env,
        stdin_bytes,
        limits,
        &ops,
    );
}

fn runBoundedFixedHelperWithOps(
    arena: std.mem.Allocator,
    command: FixedHelperCommand,
    child_env: ?*const std.process.EnvMap,
    stdin_bytes: ?[]const u8,
    limits: FixedHelperLimits,
    ops: *const FixedHelperOps,
) FixedHelperResult {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return .{ .failure = .unsupported };
    }

    const argv = fixedHelperArgv(command) orelse
        return .{ .failure = .invalid_command };
    const deadlines = fixedHelperDeadlines(ops.now(), limits.timeout_ms);

    // Preallocate exactly the per-stream cap. ArrayList's geometric growth
    // would otherwise make the stated output memory bound imprecise.
    var stdout = std.ArrayListUnmanaged(u8){};
    stdout.ensureTotalCapacityPrecise(arena, limits.max_output_bytes) catch
        return .{ .failure = .allocation_failed };
    var stderr = std.ArrayListUnmanaged(u8){};
    stderr.ensureTotalCapacityPrecise(arena, limits.max_output_bytes) catch
        return .{ .failure = .allocation_failed };

    var child = std.process.Child.init(argv, arena);
    child.stdin_behavior = if (stdin_bytes != null) .Pipe else .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = child_env;
    child.spawn() catch return .{ .failure = .spawn_failed };
    defer closeChildPipes(&child);

    // We classify deferred exec failure from the direct child's status. The
    // std.Child err pipe is intentionally not read with its blocking helper.
    if (child.err_pipe) |fd| {
        std.posix.close(fd);
        child.err_pipe = null;
    }

    var failure: ?FixedHelperFailure = null;
    var stdin_offset: usize = 0;
    var stdin_complete = stdin_bytes == null;

    const stdout_fd = child.stdout.?.handle;
    const stderr_fd = child.stderr.?.handle;
    if (setNonBlocking(ops, stdout_fd, deadlines.terminate_ns)) |setup_failure|
        failure = setup_failure;
    if (failure == null) {
        if (setNonBlocking(ops, stderr_fd, deadlines.terminate_ns)) |setup_failure|
            failure = setup_failure;
    }
    if (child.stdin) |stdin_file| {
        if (failure == null) {
            if (setNonBlocking(
                ops,
                stdin_file.handle,
                deadlines.terminate_ns,
            )) |setup_failure|
                failure = setup_failure;
        }
    }

    while (true) {
        const now_ns = ops.now();
        if (failure) |terminal_failure| {
            closeChildStdin(&child);
            return .{ .failure = terminateAndReapFixedHelper(
                ops,
                child.id,
                deadlines.final_ns,
                terminal_failure,
            ) };
        }
        if (failure == null and now_ns >= deadlines.terminate_ns) {
            closeChildStdin(&child);
            return .{ .failure = terminateAndReapFixedHelper(
                ops,
                child.id,
                deadlines.final_ns,
                .timeout,
            ) };
        }

        if (failure == null) {
            if (child.stdin) |stdin_file| {
                const input = stdin_bytes.?;
                if (stdin_offset == input.len) {
                    closeChildStdin(&child);
                    stdin_complete = true;
                } else {
                    switch (rawWrite(stdin_file.handle, input[stdin_offset..])) {
                        .bytes => |count| stdin_offset += count,
                        .would_block, .interrupted => {},
                        .eof, .failed => failure = .io_failed,
                    }
                }
            }

            if (appendFixedHelperChunk(
                ops,
                stdout_fd,
                &stdout,
                limits.max_output_bytes,
                false,
            )) |read_failure| failure = read_failure;
            if (appendFixedHelperChunk(
                ops,
                stderr_fd,
                &stderr,
                limits.max_output_bytes,
                false,
            )) |read_failure| failure = read_failure;
        }

        if (failure) |terminal_failure| {
            closeChildStdin(&child);
            return .{ .failure = terminateAndReapFixedHelper(
                ops,
                child.id,
                deadlines.final_ns,
                terminal_failure,
            ) };
        }

        const wait_result = ops.waitNoHang(child.id);
        switch (wait_result) {
            .exited => |status| {
                // Drain only bytes already available after the direct child is
                // reaped. Do not wait for an inherited descriptor to close.
                var drain_count: usize = 0;
                while (drain_count < 64) : (drain_count += 1) {
                    const before = stdout.items.len + stderr.items.len;
                    if (appendFixedHelperChunk(
                        ops,
                        stdout_fd,
                        &stdout,
                        limits.max_output_bytes,
                        true,
                    )) |read_failure| failure = read_failure;
                    if (appendFixedHelperChunk(
                        ops,
                        stderr_fd,
                        &stderr,
                        limits.max_output_bytes,
                        true,
                    )) |read_failure| failure = read_failure;
                    if (stdout.items.len + stderr.items.len == before) break;
                }
                return finishFixedHelper(
                    status,
                    failure,
                    stdin_complete or stdin_offset == (stdin_bytes orelse "").len,
                    &stdout,
                    &stderr,
                );
            },
            .interrupted => continue,
            .no_child => return .{ .failure = .reap_failed },
            .failed => failure = .reap_failed,
            .running => {},
        }

        if (failure) |terminal_failure| {
            closeChildStdin(&child);
            return .{ .failure = terminateAndReapFixedHelper(
                ops,
                child.id,
                deadlines.final_ns,
                terminal_failure,
            ) };
        }

        var fds = [_]std.posix.pollfd{
            .{
                .fd = if (child.stdin) |file| file.handle else -1,
                .events = std.posix.POLL.OUT,
                .revents = 0,
            },
            .{
                .fd = stdout_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            },
            .{
                .fd = stderr_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            },
        };
        const poll_ms = fixedHelperPollTimeoutMs(
            deadlines.terminate_ns,
            ops.now(),
        ) orelse continue;
        switch (ops.poll(&fds, poll_ms)) {
            .ready, .elapsed, .interrupted => {},
            .failed => if (failure == null) {
                failure = .io_failed;
            },
        }
    }
}

fn normalizeDarwinPlist(
    arena: std.mem.Allocator,
    contents: []const u8,
) ?[]const u8 {
    if (builtin.os.tag != .macos) return null;

    var child_env = std.process.EnvMap.init(arena);
    defer child_env.deinit();
    child_env.put("LC_ALL", "C") catch return null;

    const result = runBoundedFixedHelper(
        arena,
        .plutil_normalize,
        &child_env,
        contents,
        .{
            .timeout_ms = fixed_helper_timeout_ms,
            .max_output_bytes = 1024 * 1024,
        },
    );
    return switch (result) {
        .success => |output| if (output.stdout.len == 0) null else output.stdout,
        .failure => null,
    };
}

fn resolveDarwinResidentIdentity(arena: std.mem.Allocator) ?ResidentIdentity {
    var child_env = std.process.EnvMap.init(arena);
    defer child_env.deinit();
    child_env.put("LC_ALL", "C") catch return null;

    const uid_output = switch (runDarwinId(arena, &child_env, .id_uid)) {
        .success => |output| output.stdout,
        .failure => return null,
    };
    const uid_text = std.mem.trimRight(u8, uid_output, "\r\n");
    if (uid_text.len == 0 or
        std.mem.indexOfScalar(u8, uid_text, '\r') != null or
        std.mem.indexOfScalar(u8, uid_text, '\n') != null)
    {
        return null;
    }
    const uid = std.fmt.parseInt(u64, uid_text, 10) catch return null;
    const account_output = switch (runDarwinId(arena, &child_env, .id_account)) {
        .success => |output| output.stdout,
        .failure => return null,
    };
    return parseDarwinAccountRecord(arena, account_output, uid);
}

fn runDarwinId(
    arena: std.mem.Allocator,
    child_env: *const std.process.EnvMap,
    command: FixedHelperCommand,
) FixedHelperResult {
    std.debug.assert(command == .id_uid or command == .id_account);
    return runBoundedFixedHelper(
        arena,
        command,
        child_env,
        null,
        .{
            .timeout_ms = fixed_helper_timeout_ms,
            .max_output_bytes = 16 * 1024,
        },
    );
}

fn parseDarwinAccountRecord(
    allocator: std.mem.Allocator,
    output: []const u8,
    expected_uid: u64,
) ?ResidentIdentity {
    const record = std.mem.trimRight(u8, output, "\r\n");
    if (record.len == 0 or
        std.mem.indexOfScalar(u8, record, '\r') != null or
        std.mem.indexOfScalar(u8, record, '\n') != null)
    {
        return null;
    }

    var fields: [10][]const u8 = undefined;
    var field_it = std.mem.splitScalar(u8, record, ':');
    for (&fields) |*field| {
        field.* = field_it.next() orelse return null;
    }
    if (field_it.next() != null) return null;

    const uid = std.fmt.parseInt(u64, fields[2], 10) catch return null;
    if (uid != expected_uid) return null;
    const user = fields[0];
    const home = fields[8];
    if (!isSafeLaunchAgentUser(user) or
        !isSafeLaunchAgentValue(home) or
        home[0] != '/')
    {
        return null;
    }

    return .{
        .user = allocator.dupe(u8, user) catch return null,
        .home = allocator.dupe(u8, home) catch return null,
    };
}

fn factsForResident(
    arena: std.mem.Allocator,
    path: []const u8,
    self_sha: ?[]const u8,
    self_version: []const u8,
) BinaryFacts {
    return factsFor(arena, path, self_sha, self_version);
}

fn factsFor(
    arena: std.mem.Allocator,
    path: []const u8,
    self_sha: ?[]const u8,
    self_version: []const u8,
) BinaryFacts {
    const exists = isRegularExecutable(path);
    const sha: ?[]const u8 = if (exists) (runtime.hashFileSha256Hex(arena, path) catch null) else null;

    var version: ?[]const u8 = null;
    var version_source: []const u8 = "unknown";
    if (exists and self_sha != null and sha != null and
        std.mem.eql(u8, self_sha.?, sha.?))
    {
        version = arena.dupe(u8, self_version) catch null;
        if (version != null) version_source = "sha_match_self";
    }

    return .{
        .path = arena.dupe(u8, path) catch path,
        .exists = exists,
        .sha256 = sha,
        .version = version,
        .version_source = version_source,
        .source = runtime.classifyOauthMuxBinarySource(path),
    };
}

fn realExecCheck(_: *anyopaque, path: []const u8) bool {
    return isRegularExecutable(path);
}

/// Stat + execute-bit check only (never runs the file).
fn isRegularExecutable(path: []const u8) bool {
    const st = std.fs.cwd().statFile(path) catch return false;
    if (st.kind != .file) return false;
    if (builtin.os.tag == .windows) return true;
    std.posix.access(path, std.posix.X_OK) catch return false;
    return true;
}

fn pathDelimiter() u8 {
    return if (builtin.os.tag == .windows) ';' else ':';
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn writeJson(report: ?BinariesReport, writer: anytype) !void {
    try writer.writeAll("\"binaries\":");
    const r = report orelse {
        try writer.writeAll("{\"available\":false}");
        return;
    };

    try writer.writeAll("{\"available\":true,\"path_env_present\":");
    try writer.writeAll(if (r.path_env_present) "true" else "false");

    try writer.writeAll(",\"self\":");
    try writeFactsJson(writer, r.self);

    try writer.writeAll(",\"path_winner\":");
    if (r.path_winner) |w| try writeFactsJson(writer, w) else try writer.writeAll("null");

    try writer.writeAll(",\"path_entries\":[");
    for (r.path_entries, 0..) |f, i| {
        if (i > 0) try writer.writeByte(',');
        try writeFactsJson(writer, f);
    }
    try writer.writeAll("]");

    try writer.print(",\"path_shadow\":{{\"shadowed\":{s},\"distinct_sha_count\":{d}}}", .{
        if (r.shadow.shadowed) "true" else "false",
        r.shadow.distinct_sha_count,
    });

    try writer.writeAll(",\"resident\":");
    if (r.resident) |res| {
        const expose_resident_facts = res.containment == .healthy;
        try writer.writeAll("{\"supported\":");
        try writer.writeAll(if (res.supported) "true" else "false");
        try writer.writeAll(",\"label\":");
        try std.json.stringify(res.label, .{}, writer);
        try writer.writeAll(",\"plist_path\":");
        try std.json.stringify(res.plist_path, .{}, writer);
        try writer.writeAll(",\"plist_present\":");
        try writer.writeAll(if (res.plist_present) "true" else "false");
        try writer.writeAll(",\"containment_state\":");
        try std.json.stringify(res.containment.label(), .{}, writer);
        try writer.writeAll(",\"containment_healthy\":");
        try writer.writeAll(if (res.containment == .healthy) "true" else "false");
        try writer.writeAll(",\"program_path\":");
        if (expose_resident_facts and res.program_path != null)
            try std.json.stringify(res.program_path.?, .{}, writer)
        else
            try writer.writeAll("null");
        try writer.writeAll(",\"binary\":");
        if (expose_resident_facts and res.binary != null)
            try writeFactsJson(writer, res.binary.?)
        else
            try writer.writeAll("null");
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }

    try writer.print(",\"stale\":{{\"stale\":{s},\"containment_unhealthy\":{s},\"sha_mismatch\":{s},\"version_older\":{s},\"reason\":", .{
        if (r.stale.stale) "true" else "false",
        if (r.stale.containment_unhealthy) "true" else "false",
        if (r.stale.sha_mismatch) "true" else "false",
        if (r.stale.version_older) "true" else "false",
    });
    try std.json.stringify(r.stale.reason, .{}, writer);
    try writer.writeAll("}}");
}

fn writeFactsJson(writer: anytype, f: BinaryFacts) !void {
    try writer.writeAll("{\"path\":");
    try std.json.stringify(f.path, .{}, writer);
    try writer.writeAll(",\"exists\":");
    try writer.writeAll(if (f.exists) "true" else "false");
    try writer.writeAll(",\"sha256\":");
    if (f.sha256) |s| try std.json.stringify(s, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"version\":");
    if (f.version) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"version_source\":");
    try std.json.stringify(f.version_source, .{}, writer);
    try writer.writeAll(",\"source\":");
    try std.json.stringify(f.source, .{}, writer);
    try writer.writeByte('}');
}

pub fn writeText(report: ?BinariesReport, writer: anytype) !void {
    try writer.writeAll("\n  binaries:\n");
    const r = report orelse {
        try writer.writeAll("    unavailable (could not gather binary facts)\n");
        return;
    };

    try writer.writeAll("    self:        ");
    try writeFactsLine(writer, r.self);

    if (r.path_winner) |w| {
        try writer.writeAll("    path winner: ");
        try writeFactsLine(writer, w);
    } else {
        try writer.print("    path winner: none on PATH{s}\n", .{
            if (r.path_env_present) "" else " (PATH unset)",
        });
    }

    try writer.print("    path entries: {d}\n", .{r.path_entries.len});
    for (r.path_entries, 0..) |f, idx| {
        try writer.print("      {d}. ", .{idx + 1});
        try writeFactsLine(writer, f);
    }

    if (r.resident) |res| {
        if (!res.supported) {
            try writer.writeAll("    resident service: not supported on this platform (launchd is darwin-only)\n");
        } else {
            try writer.print("    resident service: {s}\n", .{res.label});
            try writer.print("      plist:   {s} ({s})\n", .{
                if (res.plist_path.len == 0) "(OS account identity unavailable)" else res.plist_path,
                if (res.plist_present) "present" else "absent",
            });
            try writer.print("      containment: {s}\n", .{res.containment.label()});
            if (res.containment.unhealthy()) {
                try writer.writeAll("      program: (withheld because resident containment is unhealthy)\n");
            } else if (res.containment == .healthy and res.binary != null) {
                try writer.writeAll("      program: ");
                try writeFactsLine(writer, res.binary.?);
            } else if (res.plist_present) {
                try writer.writeAll("      program: (could not parse program path from plist)\n");
            } else {
                try writer.writeAll("      program: (no resident service)\n");
            }
        }
    }

    if (r.stale.containment_unhealthy and
        r.resident != null and
        r.resident.?.containment == .legacy_uncontained)
    {
        try writer.writeAll("    WARN: resident keepalive LaunchAgent is legacy and uncontained; reinstall the service to upgrade containment\n");
    } else if (r.stale.containment_unhealthy) {
        try writer.print("    WARN: resident keepalive containment is unhealthy ({s}); inspect and reinstall the service\n", .{r.stale.reason});
    } else if (r.stale.stale) {
        try writer.print("    WARN: resident keepalive binary is stale ({s}); reload the service after installing a new binary\n", .{r.stale.reason});
    }
    if (r.shadow.shadowed) {
        try writer.print("    WARN: PATH shadow — {d} distinct oauth-mux binaries on PATH; winner: {s}\n", .{
            r.shadow.distinct_sha_count,
            if (r.path_winner) |w| w.path else "unknown",
        });
    }
}

fn writeFactsLine(writer: anytype, f: BinaryFacts) !void {
    try writer.print("{s} (", .{f.path});
    if (f.version) |v| {
        try writer.print("{s}", .{v});
    } else {
        try writer.writeAll("version=unknown");
    }
    try writer.writeAll(", sha ");
    if (f.sha256) |s| {
        try writer.print("{s}", .{s[0..@min(@as(usize, 12), s.len)]});
    } else {
        try writer.writeAll("unreadable");
    }
    try writer.print(", {s})\n", .{f.source});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const FakeChecker = struct {
    execs: []const []const u8,

    fn check(ctx: *anyopaque, path: []const u8) bool {
        const self: *FakeChecker = @ptrCast(@alignCast(ctx));
        for (self.execs) |e| {
            if (std.mem.eql(u8, e, path)) return true;
        }
        return false;
    }
};

fn isExpectedLiveSchedulerTimeout(failure: FixedHelperFailure) bool {
    return failure == .timeout or failure == .reap_timeout;
}

test "scanPath lists executable oauth-mux dirs, winner first, dedups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fake = FakeChecker{ .execs = &.{ "/a/oauth-mux", "/b/oauth-mux" } };
    // /a and /b hold executables, /x does not, /a is listed twice.
    const scan = try scanPath(a, "/a:/x:/b:/a", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 2), scan.paths.len);
    try std.testing.expectEqualStrings("/a/oauth-mux", scan.paths[0]);
    try std.testing.expectEqualStrings("/b/oauth-mux", scan.paths[1]);
    try std.testing.expectEqualStrings("/a/oauth-mux", scan.winner().?);
}

test "scanPath empty PATH yields no entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fake = FakeChecker{ .execs = &.{"/a/oauth-mux"} };
    const scan = try scanPath(arena.allocator(), "", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 0), scan.paths.len);
    try std.testing.expect(scan.winner() == null);
}

test "scanPath skips dirs without an executable oauth-mux" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fake = FakeChecker{ .execs = &.{} }; // nothing is executable
    const scan = try scanPath(arena.allocator(), "/a:/b:/c", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 0), scan.paths.len);
}

test "distinctShaCount counts distinct non-null shas" {
    const a: ?[]const u8 = "aaa";
    const b: ?[]const u8 = "bbb";
    const n: ?[]const u8 = null;
    try std.testing.expectEqual(@as(usize, 0), distinctShaCount(&.{}));
    try std.testing.expectEqual(@as(usize, 1), distinctShaCount(&.{ a, a }));
    try std.testing.expectEqual(@as(usize, 2), distinctShaCount(&.{ a, b, a }));
    try std.testing.expectEqual(@as(usize, 1), distinctShaCount(&.{ a, n, a }));
}

const InjectedFixedHelperState = struct {
    logical_start_ns: i128,
    logical_step_ns: i128,
    now_calls: usize = 0,
    first_now_ns: ?i128 = null,
    last_now_ns: i128 = 0,
    read_eintr_remaining: usize = 2,
    read_eintr_injected: usize = 0,
    poll_eintr_before_kill_remaining: usize = 2,
    poll_eintr_after_kill_remaining: usize = 2,
    poll_eintr_injected: usize = 0,
    wait_eintr_before_kill_remaining: usize = 2,
    wait_eintr_after_kill_remaining: usize = 2,
    wait_eintr_injected: usize = 0,
    kill_calls: usize = 0,
    post_kill_wait_calls: usize = 0,
    reaped_after_kill: bool = false,

    fn fromContext(context: ?*anyopaque) *InjectedFixedHelperState {
        return @ptrCast(@alignCast(context.?));
    }

    fn now(context: ?*anyopaque) i128 {
        const self = fromContext(context);
        const current = self.logical_start_ns +
            @as(i128, @intCast(self.now_calls)) * self.logical_step_ns;
        self.now_calls += 1;
        if (self.first_now_ns == null) self.first_now_ns = current;
        self.last_now_ns = current;
        return current;
    }

    fn read(
        context: ?*anyopaque,
        fd: std.posix.fd_t,
        buffer: []u8,
    ) RawIoResult {
        const self = fromContext(context);
        if (self.read_eintr_remaining > 0) {
            self.read_eintr_remaining -= 1;
            self.read_eintr_injected += 1;
            return .interrupted;
        }
        return rawRead(fd, buffer);
    }

    fn poll(
        context: ?*anyopaque,
        fds: []std.posix.pollfd,
        timeout_ms: i32,
    ) RawPollResult {
        const self = fromContext(context);
        const remaining = if (self.kill_calls == 0)
            &self.poll_eintr_before_kill_remaining
        else
            &self.poll_eintr_after_kill_remaining;
        if (remaining.* > 0) {
            remaining.* -= 1;
            self.poll_eintr_injected += 1;
            return .interrupted;
        }
        return rawPoll(fds, timeout_ms);
    }

    fn waitNoHang(
        context: ?*anyopaque,
        pid: std.posix.pid_t,
    ) RawWaitResult {
        const self = fromContext(context);
        const after_kill = self.kill_calls > 0;
        if (after_kill) self.post_kill_wait_calls += 1;
        const remaining = if (after_kill)
            &self.wait_eintr_after_kill_remaining
        else
            &self.wait_eintr_before_kill_remaining;
        if (remaining.* > 0) {
            remaining.* -= 1;
            self.wait_eintr_injected += 1;
            return .interrupted;
        }

        const result = rawWaitNoHang(pid);
        if (after_kill) {
            switch (result) {
                .exited, .no_child => self.reaped_after_kill = true,
                else => {},
            }
        }
        return result;
    }

    fn killExact(context: ?*anyopaque, pid: std.posix.pid_t) bool {
        const self = fromContext(context);
        self.kill_calls += 1;
        return systemKillExactChild(null, pid);
    }

    fn ops(self: *InjectedFixedHelperState) FixedHelperOps {
        return .{
            .context = self,
            .now_fn = now,
            .read_fn = read,
            .poll_fn = poll,
            .wait_fn = waitNoHang,
            .kill_fn = killExact,
        };
    }
};

const BlockedHeadReapAudit = struct {
    kill_calls: usize = 0,
    post_kill_wait_calls: usize = 0,
};

fn modelBlockedHead559228eFinalDeadline(audit: *BlockedHeadReapAudit) void {
    // 559228e signaled the child and returned immediately from both final
    // deadline branches. This negative control intentionally preserves that
    // ordering so the new contract test can prove it is insufficient.
    audit.kill_calls += 1;
}

fn satisfiesPostKillReapContract(audit: BlockedHeadReapAudit) bool {
    return audit.kill_calls == 1 and audit.post_kill_wait_calls > 0;
}

test "negative control 559228e kill-and-return violates reap contract" {
    var audit = BlockedHeadReapAudit{};
    modelBlockedHead559228eFinalDeadline(&audit);
    try std.testing.expect(!satisfiesPostKillReapContract(audit));
}

test "production fixed helper clock is Timer-backed, never wall-clock-backed" {
    const source = @embedFile("doctor_binaries.zig");
    const start = std.mem.indexOf(
        u8,
        source,
        "fn systemFixedHelperNow",
    ) orelse return error.TestUnexpectedResult;
    const finish = std.mem.indexOfPos(
        u8,
        source,
        start,
        "fn systemFixedHelperRead",
    ) orelse return error.TestUnexpectedResult;
    const production_clock_body = source[start..finish];

    try std.testing.expect(std.mem.indexOf(
        u8,
        production_clock_body,
        "clock.timer.read()",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        production_clock_body,
        "nanoTimestamp",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        production_clock_body,
        ".REALTIME",
    ) == null);

    var clock = FixedHelperMonotonicClock{
        .timer = std.time.Timer.start() catch return error.SkipZigTest,
    };
    const ops = systemFixedHelperOps(&clock);
    const first = ops.now();
    const second = ops.now();
    try std.testing.expect(second >= first);
}

test "bounded fixed helper times out and reaps its direct child" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var elapsed_timer = try std.time.Timer.start();
    const result = runBoundedFixedHelper(
        arena_state.allocator(),
        .test_spin,
        null,
        null,
        .{ .timeout_ms = 120, .max_output_bytes = 1024 },
    );
    const elapsed_ns = elapsed_timer.read();

    switch (result) {
        .failure => |failure| try std.testing.expect(isExpectedLiveSchedulerTimeout(failure)),
        .success => return error.TestUnexpectedResult,
    }
    try std.testing.expect(elapsed_ns < std.time.ns_per_s);
}

test "bounded fixed helper consumes injected EINTR and reaps within original deadline" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var injected = InjectedFixedHelperState{
        .logical_start_ns = 10 * std.time.ns_per_s,
        .logical_step_ns = 10 * std.time.ns_per_ms,
    };
    const ops = injected.ops();
    const result = runBoundedFixedHelperWithOps(
        arena_state.allocator(),
        .test_spin,
        null,
        null,
        .{ .timeout_ms = 500, .max_output_bytes = 1024 },
        &ops,
    );

    switch (result) {
        .failure => |failure| try std.testing.expect(isExpectedLiveSchedulerTimeout(failure)),
        .success => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 2), injected.read_eintr_injected);
    try std.testing.expectEqual(@as(usize, 4), injected.poll_eintr_injected);
    try std.testing.expectEqual(@as(usize, 4), injected.wait_eintr_injected);
    try std.testing.expectEqual(@as(usize, 1), injected.kill_calls);
    try std.testing.expect(injected.post_kill_wait_calls >= 3);
    try std.testing.expect(injected.reaped_after_kill);

    const original_final_ns = injected.first_now_ns.? +
        500 * std.time.ns_per_ms;
    try std.testing.expect(
        injected.last_now_ns <= original_final_ns + injected.logical_step_ns,
    );
    try std.testing.expect(
        injected.now_calls <= 500 / 10 + 2,
    );
}

test "bounded fixed helper does not wait for descendant-inherited stdout" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var elapsed_timer = try std.time.Timer.start();
    const result = runBoundedFixedHelper(
        arena_state.allocator(),
        .test_inherited_stdout,
        null,
        null,
        .{ .timeout_ms = 500, .max_output_bytes = 1024 },
    );
    const elapsed_ns = elapsed_timer.read();

    switch (result) {
        .success => |output| try std.testing.expectEqualStrings("ok", output.stdout),
        .failure => return error.TestUnexpectedResult,
    }
    try std.testing.expect(elapsed_ns < 500 * std.time.ns_per_ms);
}

test "bounded fixed helper rejects output beyond its memory cap" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const result = runBoundedFixedHelper(
        arena_state.allocator(),
        .test_output_overflow,
        null,
        null,
        .{ .timeout_ms = 500, .max_output_bytes = 64 },
    );

    switch (result) {
        .failure => |failure| try std.testing.expectEqual(FixedHelperFailure.output_too_large, failure),
        .success => return error.TestUnexpectedResult,
    }
}

test "bounded fixed helper EINTR retries consume one deadline budget" {
    const start_ns: i128 = 10 * std.time.ns_per_s;
    const deadlines = fixedHelperDeadlines(start_ns, 100);

    // Treat each observation as occurring after a raw poll/wait returned
    // EINTR. The immutable deadline makes each later budget strictly smaller.
    const first = fixedHelperPollTimeoutMs(
        deadlines.terminate_ns,
        start_ns + 5 * std.time.ns_per_ms,
    ).?;
    const later = fixedHelperPollTimeoutMs(
        deadlines.terminate_ns,
        start_ns + 70 * std.time.ns_per_ms,
    ).?;
    try std.testing.expect(later < first);
    try std.testing.expect(fixedHelperPollTimeoutMs(
        deadlines.terminate_ns,
        deadlines.terminate_ns,
    ) == null);
}

test "resident metadata gathering never executes a plist-selected binary" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try tmp.dir.realpathAlloc(a, ".");
    const hostile_path = try std.fs.path.join(a, &.{ root, "hostile-oauth-mux" });
    const side_effect_path = try std.fs.path.join(a, &.{ root, "executed" });
    const script = try std.fmt.allocPrint(
        a,
        "#!/bin/sh\n: > '{s}'\nprintf '{{\"version\":\"hostile\"}}\\n'\n",
        .{side_effect_path},
    );
    var hostile = try tmp.dir.createFile("hostile-oauth-mux", .{});
    defer hostile.close();
    try hostile.writeAll(script);
    try hostile.chmod(0o755);

    const facts = factsForResident(
        a,
        hostile_path,
        null,
        "0.0.0-test",
    );
    try std.testing.expect(facts.exists);
    try std.testing.expect(facts.sha256 != null);
    try std.testing.expect(facts.version == null);
    try std.testing.expectEqualStrings("unknown", facts.version_source);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("executed", .{}));
}

test "PATH metadata gathering never executes a selected executable" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try tmp.dir.realpathAlloc(a, ".");
    const path = try std.fs.path.join(a, &.{ root, "oauth-mux" });
    const side_effect_path = try std.fs.path.join(a, &.{ root, "executed" });
    const script = try std.fmt.allocPrint(
        a,
        "#!/bin/sh\n: > '{s}'\nprintf '{{\"version\":\"999.0.0\"}}\\n'\n",
        .{side_effect_path},
    );
    var selected = try tmp.dir.createFile("oauth-mux", .{ .mode = 0o755 });
    defer selected.close();
    try selected.writeAll(script);

    const facts = factsFor(a, path, null, "0.0.0-test");
    try std.testing.expect(facts.exists);
    try std.testing.expect(facts.sha256 != null);
    try std.testing.expect(facts.version == null);
    try std.testing.expectEqualStrings("unknown", facts.version_source);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("executed", .{}));
}

test "SHA-equivalent selected binary inherits only the current version" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try tmp.dir.realpathAlloc(a, ".");
    const path = try std.fs.path.join(a, &.{ root, "oauth-mux" });
    const side_effect_path = try std.fs.path.join(a, &.{ root, "executed" });
    const script = try std.fmt.allocPrint(
        a,
        "#!/bin/sh\n: > '{s}'\nprintf '{{\"version\":\"hostile\"}}\\n'\n",
        .{side_effect_path},
    );
    var selected = try tmp.dir.createFile("oauth-mux", .{ .mode = 0o755 });
    defer selected.close();
    try selected.writeAll(script);

    const selected_sha = try runtime.hashFileSha256Hex(a, path);
    const facts = factsFor(a, path, selected_sha, "0.1.15-current");
    try std.testing.expectEqualStrings("0.1.15-current", facts.version.?);
    try std.testing.expectEqualStrings("sha_match_self", facts.version_source);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("executed", .{}));
}

test "Darwin account records provide resident identity without environment input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const identity = parseDarwinAccountRecord(
        a,
        "alice:********:501:20::0:0:Alice Example:/Users/alice:/bin/sh\n",
        501,
    ).?;
    try std.testing.expectEqualStrings("alice", identity.user);
    try std.testing.expectEqualStrings("/Users/alice", identity.home);

    const malformed = [_][]const u8{
        "",
        "alice:********:501:20::0:0:Alice Example:/Users/alice\n",
        "alice:********:501:20::0:0:Alice Example:relative:/bin/sh\n",
        "alice:********:501:20::0:0:Alice Example:/Users/alice:/bin/sh\nextra",
        "ali\tce:********:501:20::0:0:Alice Example:/Users/alice:/bin/sh\n",
        "alice:********:501:20::0:0:Alice Example:/Users/ali\x7fce:/bin/sh\n",
        "alice:********:501:20::0:0:Alice Example:/Users/ali\xc2\x80ce:/bin/sh\n",
    };
    for (malformed) |record| {
        try std.testing.expect(parseDarwinAccountRecord(a, record, 501) == null);
    }
    try std.testing.expect(parseDarwinAccountRecord(
        a,
        "alice:********:502:20::0:0:Alice Example:/Users/alice:/bin/sh\n",
        501,
    ) == null);
}

test "resident gathering degrades cleanly when OS identity is unavailable" {
    const info = try gatherResidentForIdentity(
        std.testing.allocator,
        null,
        null,
        "0.0.0-test",
    );
    try std.testing.expectEqual(ResidentContainment.identity_unavailable, info.containment);
    try std.testing.expectEqualStrings("", info.plist_path);
    try std.testing.expect(info.program_path == null);
    try std.testing.expect(info.binary == null);
}

fn makeTestFifo(arena: std.mem.Allocator, path: []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = arena,
        .argv = &.{ "/usr/bin/mkfifo", path },
        .max_output_bytes = 16 * 1024,
    });
    const clean_exit = switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    try std.testing.expect(clean_exit);
}

test "resident plist reader rejects direct and symlinked FIFOs without blocking" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    const plist_path = try std.fs.path.join(a, &.{ home, keepalive_plist_rel });
    try makeTestFifo(a, plist_path);
    switch (readResidentPlist(a, plist_path)) {
        .unreadable => {},
        else => return error.TestExpectedEqual,
    }

    try tmp.dir.deleteFile(keepalive_plist_rel);
    const fifo_target = try std.fs.path.join(a, &.{ home, "plist-fifo" });
    try makeTestFifo(a, fifo_target);
    try tmp.dir.symLink(fifo_target, keepalive_plist_rel, .{});
    switch (readResidentPlist(a, plist_path)) {
        .unreadable => {},
        else => return error.TestExpectedEqual,
    }
}

test "resident plist reader accepts a symlink resolving to a regular file" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const expected = "regular plist fixture";
    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    {
        const target = try tmp.dir.createFile("regular.plist", .{});
        defer target.close();
        try target.writeAll(expected);
    }
    const target_path = try std.fs.path.join(a, &.{ home, "regular.plist" });
    try tmp.dir.symLink(target_path, keepalive_plist_rel, .{});
    const plist_path = try std.fs.path.join(a, &.{ home, keepalive_plist_rel });
    switch (readResidentPlist(a, plist_path)) {
        .contents => |contents| try std.testing.expectEqualStrings(expected, contents),
        else => return error.TestExpectedEqual,
    }
}

test "resident plist reader rejects an oversized regular file" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    {
        const plist = try tmp.dir.createFile(keepalive_plist_rel, .{});
        defer plist.close();
        try plist.setEndPos(resident_plist_max_bytes + 1);
    }
    const plist_path = try std.fs.path.join(a, &.{ home, keepalive_plist_rel });
    switch (readResidentPlist(a, plist_path)) {
        .unreadable => {},
        else => return error.TestExpectedEqual,
    }
}

test "compareSemver ordering table" {
    try std.testing.expectEqual(Ordering.eq, compareSemver("0.1.14", "0.1.14"));
    try std.testing.expectEqual(Ordering.lt, compareSemver("0.1.13", "0.1.14"));
    try std.testing.expectEqual(Ordering.gt, compareSemver("0.1.14", "0.1.13"));
    // numeric, not lexical: 14 > 4
    try std.testing.expectEqual(Ordering.gt, compareSemver("0.1.14", "0.1.4"));
    try std.testing.expectEqual(Ordering.eq, compareSemver("v0.1.14", "0.1.14"));
    try std.testing.expectEqual(Ordering.eq, compareSemver("1.2", "1.2.0"));
    try std.testing.expectEqual(Ordering.lt, compareSemver("0.9.0", "1.0.0"));
    // trailing build suffix ignored
    try std.testing.expectEqual(Ordering.eq, compareSemver("0.1.14-5-gabc", "0.1.14"));
    // non-numeric → unknown
    try std.testing.expectEqual(Ordering.unknown, compareSemver("abc", "0.1.0"));
}

test "evaluateStaleness table" {
    // Absent resident is distinct from unhealthy containment.
    var v = evaluateStaleness(.{
        .resident_containment = .absent,
        .resident_sha = null,
        .installed_sha = "aaa",
        .self_sha = "aaa",
    });
    try std.testing.expect(!v.stale);
    try std.testing.expect(!v.containment_unhealthy);
    try std.testing.expectEqualStrings("no_resident", v.reason);

    // In sync.
    v = evaluateStaleness(.{
        .resident_containment = .healthy,
        .resident_sha = "aaa",
        .installed_sha = "aaa",
        .self_sha = "aaa",
    });
    try std.testing.expect(!v.stale);
    try std.testing.expectEqualStrings("in_sync", v.reason);

    // Resident differs from PATH, while matching the current process.
    v = evaluateStaleness(.{
        .resident_containment = .healthy,
        .resident_sha = "aaa",
        .installed_sha = "bbb",
        .self_sha = "aaa",
    });
    try std.testing.expect(v.stale and v.sha_mismatch and !v.version_older);
    try std.testing.expectEqualStrings("resident_sha_differs_from_installed", v.reason);

    // Resident differs from the current process, while matching PATH.
    v = evaluateStaleness(.{
        .resident_containment = .healthy,
        .resident_sha = "aaa",
        .installed_sha = "aaa",
        .self_sha = "bbb",
    });
    try std.testing.expect(v.stale and v.sha_mismatch and !v.version_older);
    try std.testing.expectEqualStrings("resident_sha_differs_from_current", v.reason);

    // Resident differs from both references.
    v = evaluateStaleness(.{
        .resident_containment = .healthy,
        .resident_sha = "aaa",
        .installed_sha = "bbb",
        .self_sha = "ccc",
    });
    try std.testing.expect(v.stale and v.sha_mismatch and !v.version_older);
    try std.testing.expectEqualStrings("resident_sha_differs_from_installed_and_current", v.reason);

    // Any missing SHA makes a healthy resident unverifiable.
    const incomplete = [_]StaleInputs{
        .{ .resident_containment = .healthy, .resident_sha = null, .installed_sha = "aaa", .self_sha = "aaa" },
        .{ .resident_containment = .healthy, .resident_sha = "aaa", .installed_sha = null, .self_sha = "aaa" },
        .{ .resident_containment = .healthy, .resident_sha = "aaa", .installed_sha = "aaa", .self_sha = null },
    };
    for (incomplete) |inputs| {
        v = evaluateStaleness(inputs);
        try std.testing.expect(v.stale);
        try std.testing.expect(!v.sha_mismatch);
        try std.testing.expectEqualStrings("resident_identity_provenance_incomplete", v.reason);
    }

    for ([_]ResidentContainment{
        .identity_unavailable,
        .plist_unreadable,
        .plist_invalid,
        .legacy_uncontained,
        .binary_unreadable,
    }) |unhealthy| {
        v = evaluateStaleness(.{
            .resident_containment = unhealthy,
            .resident_sha = null,
            .installed_sha = "aaa",
            .self_sha = "aaa",
        });
        try std.testing.expect(v.stale);
        try std.testing.expect(v.containment_unhealthy);
        try std.testing.expectEqualStrings(unhealthy.label(), v.reason);
    }
}

const launch_agent_document_open = "<plist version=\"1.0\"><dict>";
const launch_agent_label =
    "<key>Label</key><string>dev.xoxd.omux.keepalive</string>";
const launch_agent_program_arguments =
    "<key>ProgramArguments</key><array>" ++
    "<string>/usr/bin/env</string>" ++
    "<string>-i</string>" ++
    "<string>HOME=/Users/x</string>" ++
    "<string>USER=x</string>" ++
    "<string>PATH=/usr/bin:/bin:/usr/sbin:/sbin</string>" ++
    "<string>NO_COLOR=1</string>" ++
    "<string>/Users/x/.local/bin/oauth-mux</string>" ++
    "<string>keepalive</string>" ++
    "<string>--iterations</string>" ++
    "<string>100000</string>" ++
    "<string>--interval-ms</string>" ++
    "<string>60000</string>" ++
    "<string>--json</string>" ++
    "</array>";
const launch_agent_required_fields =
    "<key>RunAtLoad</key><true/>" ++
    "<key>KeepAlive</key><true/>" ++
    "<key>ThrottleInterval</key><integer>300</integer>" ++
    "<key>ProcessType</key><string>Background</string>" ++
    "<key>StandardOutPath</key><string>/Users/x/Library/Logs/oauth-mux/keepalive.out.log</string>" ++
    "<key>StandardErrorPath</key><string>/Users/x/Library/Logs/oauth-mux/keepalive.err.log</string>";
const launch_agent_document_close = "</dict></plist>";
const canonical_launch_agent =
    launch_agent_document_open ++
    launch_agent_label ++
    launch_agent_program_arguments ++
    launch_agent_required_fields ++
    launch_agent_document_close;
const legacy_v01_launch_agent =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    \\  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    \\<plist version="1.0">
    \\<dict>
    \\  <key>Label</key>
    \\  <string>dev.xoxd.omux.keepalive</string>
    \\  <key>ProgramArguments</key>
    \\  <array>
    \\    <string>/Users/x/.local/bin/oauth-mux</string>
    \\    <string>keepalive</string>
    \\    <string>--iterations</string>
    \\    <string>100000</string>
    \\    <string>--interval-ms</string>
    \\    <string>60000</string>
    \\    <string>--json</string>
    \\  </array>
    \\  <key>RunAtLoad</key>
    \\  <true/>
    \\  <key>KeepAlive</key>
    \\  <true/>
    \\  <key>ThrottleInterval</key>
    \\  <integer>300</integer>
    \\  <key>ProcessType</key>
    \\  <string>Background</string>
    \\  <key>EnvironmentVariables</key>
    \\  <dict>
    \\    <key>NO_COLOR</key>
    \\    <string>1</string>
    \\    <key>PATH</key>
    \\    <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    \\  </dict>
    \\  <key>StandardOutPath</key>
    \\  <string>/Users/x/Library/Logs/oauth-mux/keepalive.out.log</string>
    \\  <key>StandardErrorPath</key>
    \\  <string>/Users/x/Library/Logs/oauth-mux/keepalive.err.log</string>
    \\</dict>
    \\</plist>
;

fn launchAgentWithBinary(
    allocator: std.mem.Allocator,
    encoded_binary: []const u8,
) ![]const u8 {
    const literal_binary = "/Users/x/.local/bin/oauth-mux";
    const offset = std.mem.indexOf(u8, canonical_launch_agent, literal_binary).?;
    return std.mem.concat(allocator, u8, &.{
        canonical_launch_agent[0..offset],
        encoded_binary,
        canonical_launch_agent[offset + literal_binary.len ..],
    });
}

test "parseLaunchAgentProgramPath validates complete contained LaunchAgent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const plist =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        \\  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<!-- canonical contained LaunchAgent -->
        \\<plist version="1.0"><dict>
        \\  <key>ProgramArguments</key>
        \\  <array>
        \\    <string>/usr/bin/env</string>
        \\    <string>-i</string>
        \\    <string>HOME=/Users/x</string>
        \\    <string>USER=x</string>
        \\    <string>PATH=/usr/bin:/bin:/usr/sbin:/sbin</string>
        \\    <string>NO_COLOR=1</string>
        \\    <string>/Users/x/.local/bin/oauth-mux</string>
        \\    <string>keepalive</string>
        \\    <string>--iterations</string>
        \\    <string>100000</string>
        \\    <string>--interval-ms</string>
        \\    <string>60000</string>
        \\    <string>--json</string>
        \\  </array>
        \\  <key>Label</key>
        \\  <string>dev.xoxd.omux.keepalive</string>
        \\  <key>RunAtLoad</key><true/>
        \\  <key>KeepAlive</key><true/>
        \\  <key>ThrottleInterval</key><integer>300</integer>
        \\  <key>ProcessType</key><string>Background</string>
        \\  <key>StandardOutPath</key>
        \\  <string>/Users/x/Library/Logs/oauth-mux/keepalive.out.log</string>
        \\  <key>StandardErrorPath</key>
        \\  <string>/Users/x/Library/Logs/oauth-mux/keepalive.err.log</string>
        \\</dict>
        \\</plist>
    ;
    const p = try parseLaunchAgentProgramPath(arena.allocator(), plist, "/Users/x", "x");
    try std.testing.expectEqualStrings("/Users/x/.local/bin/oauth-mux", p.?);

    const compact = try parseLaunchAgentProgramPath(
        arena.allocator(),
        canonical_launch_agent,
        "/Users/x",
        "x",
    );
    try std.testing.expectEqualStrings("/Users/x/.local/bin/oauth-mux", compact.?);
}

test "LaunchAgent parser rejects an incompatible XML encoding declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const plist =
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" ++ canonical_launch_agent;
    try std.testing.expect(
        (try parseLaunchAgentProgramPath(
            arena.allocator(),
            plist,
            "/Users/x",
            "x",
        )) == null,
    );
}

test "LaunchAgent parser classifies the shipped v0.1 shape as legacy uncontained" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = (try parseLaunchAgent(
        a,
        legacy_v01_launch_agent,
        "/Users/x",
        "x",
    )).?;
    switch (parsed) {
        .legacy_uncontained => |binary| {
            try std.testing.expectEqualStrings("/Users/x/.local/bin/oauth-mux", binary);
        },
        .contained => return error.TestUnexpectedResult,
    }
    try std.testing.expect(
        (try parseLaunchAgentProgramPath(
            a,
            legacy_v01_launch_agent,
            "/Users/x",
            "x",
        )) == null,
    );

    const unsafe_legacy = try std.mem.replaceOwned(
        u8,
        a,
        legacy_v01_launch_agent,
        "/Users/x/.local/bin/oauth-mux",
        "/Users/x/.local/bin/oauth\x7fmux",
    );
    try std.testing.expect(
        (try parseLaunchAgent(a, unsafe_legacy, "/Users/x", "x")) == null,
    );
    const altered_environment = try std.mem.replaceOwned(
        u8,
        a,
        legacy_v01_launch_agent,
        "<key>NO_COLOR</key>\n    <string>1</string>",
        "<key>NO_COLOR</key>\n    <string>0</string>",
    );
    try std.testing.expect(
        (try parseLaunchAgent(a, altered_environment, "/Users/x", "x")) == null,
    );
}

test "parseLaunchAgentProgramPath enforces strict XML numeric references" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const decimal_slash = try launchAgentWithBinary(
        a,
        "&#47;Users/x/.local/bin/oauth-mux",
    );
    const parsed = try parseLaunchAgentProgramPath(a, decimal_slash, "/Users/x", "x");
    try std.testing.expectEqualStrings("/Users/x/.local/bin/oauth-mux", parsed.?);

    const malformed_references = [_][]const u8{
        "&#+47;Users/x/.local/bin/oauth-mux",
        "&#x2_F;Users/x/.local/bin/oauth-mux",
        "&#;Users/x/.local/bin/oauth-mux",
        "&#x;Users/x/.local/bin/oauth-mux",
        "&#0;Users/x/.local/bin/oauth-mux",
        "&#xD800;Users/x/.local/bin/oauth-mux",
        "&#xFFFE;Users/x/.local/bin/oauth-mux",
        "&#x110000;Users/x/.local/bin/oauth-mux",
        "/Users/x/.local/bin/\x01oauth-mux",
    };
    for (malformed_references) |encoded_binary| {
        const plist = try launchAgentWithBinary(a, encoded_binary);
        try std.testing.expect(
            (try parseLaunchAgentProgramPath(a, plist, "/Users/x", "x")) == null,
        );
    }
}

test "LaunchAgent executable paths reject every control codepoint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var codepoint: u21 = 0;
    while (codepoint <= 0x1f) : (codepoint += 1) {
        var encoded: [4]u8 = undefined;
        const encoded_len = try std.unicode.utf8Encode(codepoint, &encoded);
        const path = try std.mem.concat(a, u8, &.{
            "/Users/x/.local/bin/oauth",
            encoded[0..encoded_len],
            "mux",
        });
        try std.testing.expect(!isSafeLaunchAgentPath(path));
    }
    codepoint = 0x7f;
    while (codepoint <= 0x9f) : (codepoint += 1) {
        var encoded: [4]u8 = undefined;
        const encoded_len = try std.unicode.utf8Encode(codepoint, &encoded);
        const path = try std.mem.concat(a, u8, &.{
            "/Users/x/.local/bin/oauth",
            encoded[0..encoded_len],
            "mux",
        });
        try std.testing.expect(!isSafeLaunchAgentPath(path));
    }

    try std.testing.expect(isSafeLaunchAgentPath("/Users/x/.local/bin/oauth-mux"));
    try std.testing.expect(isSafeLaunchAgentPath("/Users/Jos\xc3\xa9/bin/oauth-mux"));
}

test "LaunchAgent parser rejects raw TAB DEL and C1 executable paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unsafe_paths = [_][]const u8{
        "/Users/x/.local/bin/oauth\tmux",
        "/Users/x/.local/bin/oauth\x7fmux",
        "/Users/x/.local/bin/oauth\xc2\x80mux",
        "/Users/x/.local/bin/oauth\xc2\x9fmux",
    };
    for (unsafe_paths) |unsafe_path| {
        const plist = try launchAgentWithBinary(a, unsafe_path);
        try std.testing.expect(
            (try parseLaunchAgentProgramPath(a, plist, "/Users/x", "x")) == null,
        );
    }
}

test "parseLaunchAgentProgramPath rejects semantic top-level overrides" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const override_argv =
        "<key>ProgramArguments</key><array><string>/bin/false</string></array>";
    const semantic_overrides = [_][]const u8{
        // Program overrides ProgramArguments execution semantics.
        launch_agent_document_open ++
            launch_agent_label ++
            "<key>Program</key><string>/bin/false</string>" ++
            launch_agent_program_arguments ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        // EnvironmentVariables would bypass the env -i allowlist boundary.
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "<key>EnvironmentVariables</key><dict><key>FOO</key><string>bar</string></dict>" ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        // Literal duplicates are rejected regardless of indentation or value.
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "\n    " ++ override_argv ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "\n\t<key>ProgramArguments</key>\n\t<array><string>/bin/false</string></array>" ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        // Entity aliases decode to ProgramArguments before duplicate detection.
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "<key>Program&#65;rguments</key><array><string>/bin/false</string></array>" ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        // Duplicate non-argv values cannot override the canonical dictionary.
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            launch_agent_required_fields ++
            "<key>StandardOutPath</key><string>/tmp/override</string>" ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            "<key>Label</key><string>override</string>" ++
            launch_agent_program_arguments ++
            launch_agent_required_fields ++
            launch_agent_document_close,
    };
    for (semantic_overrides) |plist| {
        try std.testing.expect((try parseLaunchAgentProgramPath(a, plist, "/Users/x", "x")) == null);
    }
}

test "parseLaunchAgentProgramPath rejects incomplete and noncanonical dictionaries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expect(
        (try parseLaunchAgentProgramPath(a, canonical_launch_agent, "/tmp/override", "x")) == null,
    );
    try std.testing.expect(
        (try parseLaunchAgentProgramPath(a, canonical_launch_agent, "/Users/x", "override")) == null,
    );

    const legacy_program_arguments =
        "<key>ProgramArguments</key><array>" ++
        "<string>/Users/x/.local/bin/oauth-mux</string>" ++
        "<string>keepalive</string>" ++
        "<string>--iterations</string><string>100000</string>" ++
        "<string>--interval-ms</string><string>60000</string><string>--json</string>" ++
        "</array>";
    const wrong_interval_arguments =
        "<key>ProgramArguments</key><array>" ++
        "<string>/usr/bin/env</string><string>-i</string>" ++
        "<string>HOME=/Users/x</string><string>USER=x</string>" ++
        "<string>PATH=/usr/bin:/bin:/usr/sbin:/sbin</string><string>NO_COLOR=1</string>" ++
        "<string>/Users/x/.local/bin/oauth-mux</string>" ++
        "<string>keepalive</string><string>--iterations</string><string>100000</string>" ++
        "<string>--interval-ms</string><string>1</string><string>--json</string>" ++
        "</array>";
    const malformed = [_][]const u8{
        "",
        "<plist>no program args here</plist>",
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            legacy_program_arguments ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            wrong_interval_arguments ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            "<key>Program&#65;rguments</key>" ++
            launch_agent_program_arguments["<key>ProgramArguments</key>".len..] ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        launch_agent_document_open ++
            "<key>Label</key><string>override</string>" ++
            launch_agent_program_arguments ++
            launch_agent_required_fields ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "<key>RunAtLoad</key><false/>" ++
            "<key>KeepAlive</key><true/>" ++
            "<key>ThrottleInterval</key><integer>300</integer>" ++
            "<key>ProcessType</key><string>Background</string>" ++
            "<key>StandardOutPath</key><string>/Users/x/Library/Logs/oauth-mux/keepalive.out.log</string>" ++
            "<key>StandardErrorPath</key><string>/Users/x/Library/Logs/oauth-mux/keepalive.err.log</string>" ++
            launch_agent_document_close,
        launch_agent_document_open ++
            launch_agent_label ++
            launch_agent_program_arguments ++
            "<key>RunAtLoad</key><true/>" ++
            "<key>KeepAlive</key><true/>" ++
            "<key>ThrottleInterval</key><integer>300</integer>" ++
            "<key>ProcessType</key><string>Background</string>" ++
            "<key>StandardOutPath</key><string>/tmp/override</string>" ++
            "<key>StandardErrorPath</key><string>/Users/x/Library/Logs/oauth-mux/keepalive.err.log</string>" ++
            launch_agent_document_close,
    };
    for (malformed) |plist| {
        try std.testing.expect((try parseLaunchAgentProgramPath(a, plist, "/Users/x", "x")) == null);
    }
}

test "binary-unreadable resident gathering retains no plist-selected facts" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    const plist = try std.mem.replaceOwned(
        u8,
        a,
        canonical_launch_agent,
        "/Users/x",
        home,
    );
    var plist_file = try tmp.dir.createFile(keepalive_plist_rel, .{});
    defer plist_file.close();
    try plist_file.writeAll(plist);

    const info = try gatherResidentForIdentity(
        a,
        .{ .user = "x", .home = home },
        null,
        "0.0.0-test",
    );
    try std.testing.expectEqual(ResidentContainment.binary_unreadable, info.containment);
    try std.testing.expect(info.program_path == null);
    try std.testing.expect(info.binary == null);
}

test "resident gathering fails closed when plutil rejects the XML encoding" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    try tmp.dir.makePath(".local/bin");
    {
        const binary_file = try tmp.dir.createFile(".local/bin/oauth-mux", .{ .mode = 0o755 });
        defer binary_file.close();
        try binary_file.writeAll("synthetic executable bytes\n");
    }

    const contained = try std.mem.replaceOwned(
        u8,
        a,
        canonical_launch_agent,
        "/Users/x",
        home,
    );
    const malformed = try std.mem.concat(a, u8, &.{
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
        contained,
    });
    try std.testing.expect(normalizeDarwinPlist(a, malformed) == null);
    {
        const plist_file = try tmp.dir.createFile(keepalive_plist_rel, .{});
        defer plist_file.close();
        try plist_file.writeAll(malformed);
    }

    const info = try gatherResidentForIdentity(
        a,
        .{ .user = "x", .home = home },
        null,
        "0.0.0-test",
    );
    try std.testing.expectEqual(ResidentContainment.plist_invalid, info.containment);
    try std.testing.expect(info.program_path == null);
    try std.testing.expect(info.binary == null);

    const selected_path = try std.fs.path.join(a, &.{ home, ".local/bin/oauth-mux" });
    var report = sampleReport();
    report.resident = info;
    report.stale = evaluateStaleness(.{
        .resident_containment = info.containment,
        .resident_sha = null,
        .installed_sha = null,
        .self_sha = null,
    });
    var json = std.ArrayList(u8).init(a);
    try writeJson(report, json.writer());
    try std.testing.expect(std.mem.indexOf(u8, json.items, "\"program_path\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.items, "\"binary\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.items, selected_path) == null);

    var text = std.ArrayList(u8).init(a);
    try writeText(report, text.writer());
    try std.testing.expect(std.mem.indexOf(u8, text.items, selected_path) == null);
}

test "resident gathering reports v0.1 compatibility without resident facts" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const home = try tmp.dir.realpathAlloc(a, ".");
    try tmp.dir.makePath("Library/LaunchAgents");
    const plist = try std.mem.replaceOwned(
        u8,
        a,
        legacy_v01_launch_agent,
        "/Users/x",
        home,
    );
    {
        const plist_file = try tmp.dir.createFile(keepalive_plist_rel, .{});
        defer plist_file.close();
        try plist_file.writeAll(plist);
    }

    const info = try gatherResidentForIdentity(
        a,
        .{ .user = "x", .home = home },
        null,
        "0.0.0-test",
    );
    try std.testing.expectEqual(ResidentContainment.legacy_uncontained, info.containment);
    try std.testing.expect(info.program_path == null);
    try std.testing.expect(info.binary == null);

    const selected_path = try std.fs.path.join(a, &.{ home, ".local/bin/oauth-mux" });
    var report = sampleReport();
    report.resident = info;
    report.stale = evaluateStaleness(.{
        .resident_containment = info.containment,
        .resident_sha = null,
        .installed_sha = null,
        .self_sha = null,
    });
    var json = std.ArrayList(u8).init(a);
    try writeJson(report, json.writer());
    try std.testing.expect(std.mem.indexOf(u8, json.items, "\"containment_state\":\"legacy_uncontained\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.items, "\"program_path\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.items, "\"binary\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.items, selected_path) == null);

    var text = std.ArrayList(u8).init(a);
    try writeText(report, text.writer());
    try std.testing.expect(std.mem.indexOf(u8, text.items, "containment: legacy_uncontained") != null);
    try std.testing.expect(std.mem.indexOf(u8, text.items, "reinstall the service to upgrade containment") != null);
    try std.testing.expect(std.mem.indexOf(u8, text.items, selected_path) == null);
}

fn sampleReport() BinariesReport {
    const facts = BinaryFacts{
        .path = "/x/oauth-mux",
        .exists = true,
        .sha256 = null,
        .version = null,
        .version_source = "unknown",
        .source = "path_or_installed",
    };
    return .{
        .self = facts,
        .path_env_present = false,
        .path_entries = &.{},
        .path_winner = null,
        .shadow = .{ .shadowed = false, .distinct_sha_count = 0 },
        .resident = ResidentInfo{
            .supported = false,
            .label = keepalive_label,
            .plist_path = "",
            .plist_present = false,
            .program_path = null,
            .binary = null,
            .containment = .unsupported,
        },
        .stale = .{
            .stale = false,
            .containment_unhealthy = false,
            .sha_mismatch = false,
            .version_older = false,
            .reason = "unsupported",
        },
    };
}

test "writeJson renders a null-safe, well-formed binaries object" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(sampleReport(), buf.writer());
    const out = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, out, "\"binaries\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"path_winner\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"sha256\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"shadowed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"containment_state\":\"unsupported\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"reason\":\"unsupported\"") != null);

    // Wrap and parse to confirm it is valid JSON.
    var full = std.ArrayList(u8).init(std.testing.allocator);
    defer full.deinit();
    try full.append('{');
    try full.appendSlice(out);
    try full.append('}');
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, full.items, .{});
    parsed.deinit();
}

test "writeJson unavailable when report is null" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(null, buf.writer());
    try std.testing.expectEqualStrings("\"binaries\":{\"available\":false}", buf.items);
}

test "writeText renders and is null-safe" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeText(null, buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "binaries:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "unavailable") != null);

    buf.clearRetainingCapacity();
    try writeText(sampleReport(), buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "self:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "not supported") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "none on PATH") != null);
}

test "renderers withhold plist-selected path and facts for every unhealthy state" {
    var json = std.ArrayList(u8).init(std.testing.allocator);
    defer json.deinit();
    var text = std.ArrayList(u8).init(std.testing.allocator);
    defer text.deinit();

    const selected_path = "/private/plist-selected/oauth-mux";
    const selected_version = "resident-version-must-not-render";
    const selected_sha = "resident-sha-must-not-render";
    for ([_]ResidentContainment{
        .identity_unavailable,
        .plist_unreadable,
        .plist_invalid,
        .legacy_uncontained,
        .binary_unreadable,
    }) |unhealthy| {
        var report = sampleReport();
        report.resident = ResidentInfo{
            .supported = true,
            .label = keepalive_label,
            .plist_path = "/redacted/LaunchAgent.plist",
            .plist_present = true,
            .program_path = selected_path,
            .binary = BinaryFacts{
                .path = selected_path,
                .exists = false,
                .sha256 = selected_sha,
                .version = selected_version,
                .version_source = "unknown",
                .source = "path_or_installed",
            },
            .containment = unhealthy,
        };
        report.stale = evaluateStaleness(.{
            .resident_containment = unhealthy,
            .resident_sha = null,
            .installed_sha = null,
            .self_sha = null,
        });

        json.clearRetainingCapacity();
        try writeJson(report, json.writer());
        try std.testing.expect(std.mem.indexOf(u8, json.items, "\"containment_healthy\":false") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, "\"program_path\":null") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, "\"binary\":null") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, "\"stale\":true") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, "\"containment_unhealthy\":true") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, selected_path) == null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, selected_version) == null);
        try std.testing.expect(std.mem.indexOf(u8, json.items, selected_sha) == null);

        text.clearRetainingCapacity();
        try writeText(report, text.writer());
        try std.testing.expect(std.mem.indexOf(u8, text.items, "program: (withheld because resident containment is unhealthy)") != null);
        if (unhealthy == .legacy_uncontained) {
            try std.testing.expect(std.mem.indexOf(u8, text.items, "WARN: resident keepalive LaunchAgent is legacy and uncontained") != null);
        } else {
            try std.testing.expect(std.mem.indexOf(u8, text.items, "WARN: resident keepalive containment is unhealthy") != null);
        }
        try std.testing.expect(std.mem.indexOf(u8, text.items, selected_path) == null);
        try std.testing.expect(std.mem.indexOf(u8, text.items, selected_version) == null);
        try std.testing.expect(std.mem.indexOf(u8, text.items, selected_sha) == null);
    }
}
