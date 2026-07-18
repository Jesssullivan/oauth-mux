//! `oauth-mux version --check [--online]` (TIN-2463): an opt-in, offline-DEFAULT
//! binary staleness check — the user-invocable complement to the doctor binary
//! version-truth that merged in #455.
//!
//! Design notes:
//!  * OFFLINE by construction. `version --check` makes ZERO network calls. The
//!    PATH scan, SHA-256 truth, and PATH-shadow detection are reused from
//!    `doctor_binaries`. Discovered binaries are never executed.
//!  * The ONLY path that may open a socket is `realOnlineFetch`, and it is
//!    reachable exclusively when the operator passes `--online` (gated by
//!    `onlineConsultAllowed`). It is never implicit, never cached-auto, and is
//!    unreachable from the daemon/keepalive loop.
//!  * Local binary identity is SHA-only: identical bytes match; differing or
//!    unreadable provenance fails closed. Version ordering is reserved for the
//!    explicit online release consult.
//!  * Exit non-zero (`stale_exit_code`) when local identity cannot be verified,
//!    local bytes differ, or an explicit online consult proves the running
//!    version stale.

const std = @import("std");
const cli = @import("cli.zig");
const doctor_binaries = @import("doctor_binaries.zig");

/// Sibling file an install lane MAY drop next to the installed binary to record
/// the version/SHA it installed. Reading it is this module's job; writing it in
/// the install lanes is a separate follow-on. Shape (fields optional, unknown
/// fields ignored): {"version": "0.1.15", "binary_sha256": "<hex>"}.
pub const sidecar_filename = "oauth-mux.version.json";

/// Default GitHub repo consulted by `--online` (override with OMUX_RELEASE_REPO).
pub const default_repo_slug = "Jesssullivan/oauth-mux";

/// The only non-zero exit code — emitted when the binary check fails closed.
pub const stale_exit_code: u8 = 1;

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

pub const Verdict = enum {
    /// Identical bytes as the running binary — in sync.
    match,
    /// Running binary is OLDER than a trusted version-only reference.
    stale,
    /// Running binary is NEWER than the reference (the reference is behind).
    ahead,
    /// Local reference bytes differ from the running binary.
    diverged,
    /// Cannot compare (reference absent, or fields missing/unparseable).
    unknown_provenance,

    pub fn isStale(self: Verdict) bool {
        return self == .stale;
    }

    pub fn identityVerified(self: Verdict) bool {
        return self == .match;
    }

    pub fn label(self: Verdict) []const u8 {
        return switch (self) {
            .match => "match",
            .stale => "stale",
            .ahead => "ahead",
            .diverged => "diverged",
            .unknown_provenance => "unknown-provenance",
        };
    }

    pub fn phrase(self: Verdict) []const u8 {
        return switch (self) {
            .match => "match (running binary is in sync)",
            .stale => "STALE (running binary is older)",
            .ahead => "ahead (running binary is newer)",
            .diverged => "diverged (different binary bytes)",
            .unknown_provenance => "unknown-provenance (cannot compare)",
        };
    }
};

// ---------------------------------------------------------------------------
// Pure compare core
// ---------------------------------------------------------------------------

pub const CompareInputs = struct {
    self_sha: ?[]const u8,
    ref_sha: ?[]const u8,
};

/// SHA-only compare of the running binary against a local reference
/// (PATH-installed binary or install sidecar). Pure.
pub fn compareAgainst(in: CompareInputs) Verdict {
    const self_sha = in.self_sha orelse return .unknown_provenance;
    const ref_sha = in.ref_sha orelse return .unknown_provenance;
    return if (std.mem.eql(u8, self_sha, ref_sha)) .match else .diverged;
}

/// Version-only compare, used for the `--online` latest-release consult where no
/// SHA is available. Pure.
pub fn compareVersionOnly(self_version: ?[]const u8, ref_version: ?[]const u8) Verdict {
    const sv = self_version orelse return .unknown_provenance;
    const rv = ref_version orelse return .unknown_provenance;
    return switch (doctor_binaries.compareSemver(sv, rv)) {
        .lt => .stale,
        .gt => .ahead,
        .eq => .match,
        .unknown => .unknown_provenance,
    };
}

// ---------------------------------------------------------------------------
// Sidecar
// ---------------------------------------------------------------------------

pub const Sidecar = struct {
    version: ?[]const u8 = null,
    binary_sha256: ?[]const u8 = null,
};

/// Tolerant sidecar parse: any malformed input → null (never an error).
pub fn parseSidecar(allocator: std.mem.Allocator, data: []const u8) ?Sidecar {
    const Shape = struct {
        version: ?[]const u8 = null,
        binary_sha256: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Shape, allocator, data, .{ .ignore_unknown_fields = true }) catch return null;
    defer parsed.deinit();

    var out = Sidecar{};
    if (parsed.value.version) |v| {
        if (v.len != 0) out.version = allocator.dupe(u8, v) catch return null;
    }
    if (parsed.value.binary_sha256) |s| {
        if (s.len != 0) out.binary_sha256 = allocator.dupe(u8, s) catch return null;
    }
    if (out.version == null and out.binary_sha256 == null) return null;
    return out;
}

const SidecarLookup = struct {
    sidecar: ?Sidecar = null,
    /// Where we read it from, or the primary expected location when absent.
    expected_path: ?[]const u8 = null,
    found: bool = false,
};

fn appendSidecarCandidate(arena: std.mem.Allocator, list: *std.ArrayList([]const u8), bin_path: []const u8) void {
    if (std.mem.eql(u8, bin_path, "unknown")) return;
    const dir = std.fs.path.dirname(bin_path) orelse return;
    const candidate = std.fs.path.join(arena, &.{ dir, sidecar_filename }) catch return;
    for (list.items) |seen| {
        if (std.mem.eql(u8, seen, candidate)) return;
    }
    list.append(candidate) catch return;
}

/// Look for an install sidecar next to the PATH-installed binary first, then
/// next to the running binary. Absent/unreadable → graceful null (never error).
fn readSidecar(arena: std.mem.Allocator, report: doctor_binaries.BinariesReport) SidecarLookup {
    var candidates = std.ArrayList([]const u8).init(arena);
    if (report.path_winner) |w| appendSidecarCandidate(arena, &candidates, w.path);
    appendSidecarCandidate(arena, &candidates, report.self.path);

    var result = SidecarLookup{};
    for (candidates.items, 0..) |path, idx| {
        if (idx == 0) result.expected_path = path;
        const data = std.fs.cwd().readFileAlloc(arena, path, 64 * 1024) catch continue;
        if (parseSidecar(arena, data)) |sc| {
            result.sidecar = sc;
            result.expected_path = path;
            result.found = true;
            return result;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Report assembly (pure over its inputs)
// ---------------------------------------------------------------------------

pub const CheckReport = struct {
    self: doctor_binaries.BinaryFacts,
    self_build_id: []const u8,

    path_winner: ?doctor_binaries.BinaryFacts,
    path_verdict: Verdict,

    sidecar: ?Sidecar,
    sidecar_path: ?[]const u8,
    sidecar_verdict: Verdict,
    resident_verdict: doctor_binaries.StaleVerdict,

    shadow: doctor_binaries.ShadowVerdict,
    path_entries: []const doctor_binaries.BinaryFacts,
    path_env_present: bool,

    online_attempted: bool,
    online_latest: ?[]const u8,
    online_verdict: Verdict,

    pub fn stale(self: CheckReport) bool {
        // PATH is the active executable authority. Missing, unreadable, or
        // different bytes fail closed.
        if (!self.path_verdict.identityVerified()) return true;
        // The sidecar is optional, but once present its SHA must agree.
        if (self.sidecar != null and !self.sidecar_verdict.identityVerified()) return true;
        if (self.resident_verdict.stale) return true;
        // Online only contributes when the operator actually consulted it.
        if (self.online_attempted and self.online_verdict.isStale()) return true;
        return false;
    }

    pub fn exitCode(self: CheckReport) u8 {
        return if (self.stale()) stale_exit_code else 0;
    }
};

/// Interpret a `doctor_binaries` report plus an optional sidecar/online tag into
/// per-source verdicts. Pure — the effectful gather/read/fetch happen in `run`.
pub fn assemble(
    report: doctor_binaries.BinariesReport,
    self_build_id: []const u8,
    sidecar: ?Sidecar,
    sidecar_path: ?[]const u8,
    online_attempted: bool,
    online_latest: ?[]const u8,
) CheckReport {
    const self_sha = report.self.sha256;

    const path_verdict: Verdict = if (report.path_winner) |w| compareAgainst(.{
        .self_sha = self_sha,
        .ref_sha = w.sha256,
    }) else .unknown_provenance;

    const sidecar_verdict: Verdict = if (sidecar) |s| compareAgainst(.{
        .self_sha = self_sha,
        .ref_sha = s.binary_sha256,
    }) else .unknown_provenance;

    const online_verdict: Verdict = if (online_attempted)
        compareVersionOnly(report.self.version, online_latest)
    else
        .unknown_provenance;

    return .{
        .self = report.self,
        .self_build_id = self_build_id,
        .path_winner = report.path_winner,
        .path_verdict = path_verdict,
        .sidecar = sidecar,
        .sidecar_path = sidecar_path,
        .sidecar_verdict = sidecar_verdict,
        .resident_verdict = report.stale,
        .shadow = report.shadow,
        .path_entries = report.path_entries,
        .path_env_present = report.path_env_present,
        .online_attempted = online_attempted,
        .online_latest = online_latest,
        .online_verdict = online_verdict,
    };
}

// ---------------------------------------------------------------------------
// Network posture
// ---------------------------------------------------------------------------

pub const RunOptions = struct {
    json: bool = false,
    online: bool = false,
};

/// The single gate that permits a network consult. Returns true ONLY when the
/// operator passed `--online`. `run` calls the network fetch exclusively when
/// this returns true, so the offline default makes zero network calls by
/// construction.
pub fn onlineConsultAllowed(opts: RunOptions) bool {
    return opts.online;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn writeSha12(writer: anytype, sha: ?[]const u8) !void {
    if (sha) |s| {
        try writer.writeAll(s[0..@min(@as(usize, 12), s.len)]);
    } else {
        try writer.writeAll("unreadable");
    }
}

pub fn writeText(report: CheckReport, writer: anytype) !void {
    try writer.writeAll("oauth-mux version --check\n\n");

    try writer.print("  running: {s}\n", .{report.self.path});
    try writer.print("           version {s}  build {s}\n", .{
        report.self.version orelse "unknown",
        report.self_build_id,
    });
    try writer.writeAll("           sha ");
    try writeSha12(writer, report.self.sha256);
    try writer.print("  ({s})\n\n", .{report.self.source});

    // Source (a): PATH-installed binary.
    try writer.print("  vs PATH-installed:  {s}\n", .{report.path_verdict.phrase()});
    if (report.path_winner) |w| {
        try writer.print("           {s}\n", .{w.path});
        try writer.print("           version {s}  sha ", .{w.version orelse "unknown"});
        try writeSha12(writer, w.sha256);
        try writer.print("  ({s})\n", .{w.source});
    } else {
        try writer.print("           (no oauth-mux on PATH{s})\n", .{
            if (report.path_env_present) "" else "; PATH unset",
        });
    }

    // Source (b): install sidecar.
    try writer.print("  vs install sidecar: {s}\n", .{report.sidecar_verdict.phrase()});
    if (report.sidecar) |s| {
        try writer.print("           {s}\n", .{report.sidecar_path orelse "(unknown path)"});
        try writer.print("           version {s}  sha ", .{s.version orelse "unknown"});
        try writeSha12(writer, s.binary_sha256);
        try writer.writeByte('\n');
    } else if (report.sidecar_path) |p| {
        try writer.print("           none at {s} (install provenance unrecorded)\n", .{p});
    } else {
        try writer.writeAll("           none found (install provenance unrecorded)\n");
    }

    try writer.print("  vs resident service: {s} ({s})\n", .{
        if (report.resident_verdict.stale) "FAILED" else "ok",
        report.resident_verdict.reason,
    });

    // PATH shadow (only when there is more than one distinct binary on PATH).
    if (report.shadow.shadowed) {
        try writer.print("\n  PATH shadow: {d} distinct oauth-mux on PATH (winner: {s})\n", .{
            report.shadow.distinct_sha_count,
            if (report.path_winner) |w| w.path else "unknown",
        });
        for (report.path_entries, 0..) |f, idx| {
            try writer.print("    {d}. {s} ({s}, sha ", .{
                idx + 1,
                f.path,
                f.version orelse "version=unknown",
            });
            try writeSha12(writer, f.sha256);
            try writer.print(", {s})\n", .{f.source});
        }
    }

    // Online (only under --online).
    if (report.online_attempted) {
        try writer.writeAll("\n  latest release: ");
        if (report.online_latest) |tag| {
            try writer.print("{s}  ->  {s}\n", .{ tag, report.online_verdict.phrase() });
        } else {
            try writer.writeAll("(unavailable)\n");
        }
    }

    try writer.print("\n  verdict: {s}\n", .{
        if (report.stale())
            "FAILED — local binary identity is unverified/diverged or the running version is stale"
        else
            "ok — local binary identity is verified",
    });
}

fn writeFactsJson(writer: anytype, f: doctor_binaries.BinaryFacts) !void {
    try writer.writeAll("{\"path\":");
    try std.json.stringify(f.path, .{}, writer);
    try writer.writeAll(",\"exists\":");
    try writer.writeAll(if (f.exists) "true" else "false");
    try writer.writeAll(",\"sha256\":");
    if (f.sha256) |s| try std.json.stringify(s, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"version\":");
    if (f.version) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"source\":");
    try std.json.stringify(f.source, .{}, writer);
    try writer.writeByte('}');
}

pub fn writeJson(report: CheckReport, writer: anytype) !void {
    try writer.writeAll("{\"check\":true,\"running\":");
    try writer.writeAll("{\"path\":");
    try std.json.stringify(report.self.path, .{}, writer);
    try writer.writeAll(",\"version\":");
    if (report.self.version) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"build_id\":");
    try std.json.stringify(report.self_build_id, .{}, writer);
    try writer.writeAll(",\"sha256\":");
    if (report.self.sha256) |s| try std.json.stringify(s, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"source\":");
    try std.json.stringify(report.self.source, .{}, writer);
    try writer.writeByte('}');

    try writer.writeAll(",\"resident_identity\":{\"stale\":");
    try writer.writeAll(if (report.resident_verdict.stale) "true" else "false");
    try writer.writeAll(",\"sha_mismatch\":");
    try writer.writeAll(if (report.resident_verdict.sha_mismatch) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(report.resident_verdict.reason, .{}, writer);
    try writer.writeByte('}');

    // PATH-installed.
    try writer.writeAll(",\"path_installed\":{\"present\":");
    try writer.writeAll(if (report.path_winner != null) "true" else "false");
    try writer.writeAll(",\"verdict\":");
    try std.json.stringify(report.path_verdict.label(), .{}, writer);
    if (report.path_winner) |w| {
        try writer.writeAll(",\"facts\":");
        try writeFactsJson(writer, w);
    } else {
        try writer.writeAll(",\"facts\":null");
    }
    try writer.writeByte('}');

    // Sidecar.
    try writer.writeAll(",\"sidecar\":{\"present\":");
    try writer.writeAll(if (report.sidecar != null) "true" else "false");
    try writer.writeAll(",\"path\":");
    if (report.sidecar_path) |p| try std.json.stringify(p, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"verdict\":");
    try std.json.stringify(report.sidecar_verdict.label(), .{}, writer);
    try writer.writeAll(",\"version\":");
    if (report.sidecar) |s| {
        if (s.version) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
    } else try writer.writeAll("null");
    try writer.writeAll(",\"binary_sha256\":");
    if (report.sidecar) |s| {
        if (s.binary_sha256) |x| try std.json.stringify(x, .{}, writer) else try writer.writeAll("null");
    } else try writer.writeAll("null");
    try writer.writeByte('}');

    // Shadow.
    try writer.print(",\"path_shadow\":{{\"shadowed\":{s},\"distinct_sha_count\":{d}}}", .{
        if (report.shadow.shadowed) "true" else "false",
        report.shadow.distinct_sha_count,
    });

    // PATH entries.
    try writer.writeAll(",\"path_entries\":[");
    for (report.path_entries, 0..) |f, i| {
        if (i > 0) try writer.writeByte(',');
        try writeFactsJson(writer, f);
    }
    try writer.writeByte(']');

    // Online.
    try writer.writeAll(",\"online\":{\"attempted\":");
    try writer.writeAll(if (report.online_attempted) "true" else "false");
    try writer.writeAll(",\"latest\":");
    if (report.online_latest) |tag| try std.json.stringify(tag, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"verdict\":");
    try std.json.stringify(report.online_verdict.label(), .{}, writer);
    try writer.writeByte('}');

    // Top-level verdict + exit code.
    try writer.print(",\"stale\":{s},\"exit_code\":{d}}}\n", .{
        if (report.stale()) "true" else "false",
        report.exitCode(),
    });
}

// ---------------------------------------------------------------------------
// Effectful entry point
// ---------------------------------------------------------------------------

/// `oauth-mux version --check [--online]`. Returns the process exit code
/// (non-zero when local identity cannot be verified or an explicit online
/// consult proves staleness). All effects (PATH gather, sidecar read, optional
/// online consult) are confined here; the offline default makes zero network
/// calls and executes no selected binary.
pub fn run(gpa: std.mem.Allocator, writer: anytype, opts: RunOptions) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Reuse the doctor's metadata-only PATH scan + SHA + shadow detection.
    const report = doctor_binaries.gather(arena, cli.version, .{}) catch {
        if (opts.json) {
            try writer.writeAll("{\"check\":true,\"error\":\"binary_facts_unavailable\",\"stale\":true,\"exit_code\":1}\n");
        } else {
            try writer.writeAll("oauth-mux version --check\n\n  FAILED: could not gather binary facts\n");
        }
        return stale_exit_code;
    };

    const sc = readSidecar(arena, report);

    // Network is reachable ONLY under the explicit flag.
    const online_attempted = onlineConsultAllowed(opts);
    const online_latest: ?[]const u8 = if (online_attempted) realOnlineFetch(arena) else null;

    const check = assemble(report, cli.build_id, sc.sidecar, sc.expected_path, online_attempted, online_latest);

    if (opts.json) {
        try writeJson(check, writer);
    } else {
        try writeText(check, writer);
    }
    return check.exitCode();
}

/// GET the GitHub Releases latest tag. Tolerant of every failure (offline, DNS,
/// TLS, non-200, unparsable) → null. Reachable ONLY via `run` under `--online`;
/// untested against live infrastructure by design.
fn realOnlineFetch(arena: std.mem.Allocator) ?[]const u8 {
    const repo_owned = std.process.getEnvVarOwned(arena, "OMUX_RELEASE_REPO") catch null;
    const slug = if (repo_owned) |r| (if (r.len != 0) r else default_repo_slug) else default_repo_slug;

    const url = std.fmt.allocPrint(arena, "https://api.github.com/repos/{s}/releases/latest", .{slug}) catch return null;
    const uri = std.Uri.parse(url) catch return null;

    var client = std.http.Client{ .allocator = arena };
    defer client.deinit();

    const headers = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "User-Agent", .value = "oauth-mux-version-check" },
    };

    var server_header_buf: [16 * 1024]u8 = undefined;
    var req = client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = &headers,
    }) catch return null;
    defer req.deinit();

    req.send() catch return null;
    req.finish() catch return null;
    req.wait() catch return null;
    if (req.response.status != .ok) return null;

    var response_buf: [256 * 1024]u8 = undefined;
    const n = req.readAll(&response_buf) catch return null;
    return parseLatestTag(arena, response_buf[0..n]);
}

fn parseLatestTag(allocator: std.mem.Allocator, data: []const u8) ?[]const u8 {
    const Shape = struct { tag_name: ?[]const u8 = null };
    const parsed = std.json.parseFromSlice(Shape, allocator, data, .{ .ignore_unknown_fields = true }) catch return null;
    defer parsed.deinit();
    const tag = parsed.value.tag_name orelse return null;
    if (tag.len == 0) return null;
    return allocator.dupe(u8, tag) catch null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "compareAgainst: identical SHA is a match" {
    try std.testing.expectEqual(Verdict.match, compareAgainst(.{
        .self_sha = "aaa",
        .ref_sha = "aaa",
    }));
}

test "compareAgainst: differing local bytes diverge" {
    try std.testing.expectEqual(Verdict.diverged, compareAgainst(.{
        .self_sha = "aaa",
        .ref_sha = "bbb",
    }));
}

test "compareAgainst: missing SHA is unknown-provenance" {
    try std.testing.expectEqual(Verdict.unknown_provenance, compareAgainst(.{
        .self_sha = "aaa",
        .ref_sha = null,
    }));
    try std.testing.expectEqual(Verdict.unknown_provenance, compareAgainst(.{
        .self_sha = null,
        .ref_sha = "bbb",
    }));
}

test "compareVersionOnly ordering table" {
    try std.testing.expectEqual(Verdict.match, compareVersionOnly("0.1.15", "0.1.15"));
    try std.testing.expectEqual(Verdict.stale, compareVersionOnly("0.1.13", "0.1.15"));
    try std.testing.expectEqual(Verdict.ahead, compareVersionOnly("0.1.16", "0.1.15"));
    try std.testing.expectEqual(Verdict.match, compareVersionOnly("0.1.15", "v0.1.15"));
    try std.testing.expectEqual(Verdict.unknown_provenance, compareVersionOnly(null, "0.1.15"));
    try std.testing.expectEqual(Verdict.unknown_provenance, compareVersionOnly("0.1.15", null));
    try std.testing.expectEqual(Verdict.unknown_provenance, compareVersionOnly("abc", "0.1.15"));
}

test "onlineConsultAllowed: false without the flag, true with it" {
    // Network posture: the ONLY gate that permits a socket. Absent flag → no
    // network call is ever reachable.
    try std.testing.expect(!onlineConsultAllowed(.{}));
    try std.testing.expect(!onlineConsultAllowed(.{ .json = true }));
    try std.testing.expect(onlineConsultAllowed(.{ .online = true }));
}

test "parseSidecar: valid, partial, and malformed" {
    const a = std.testing.allocator;

    const full = parseSidecar(a, "{\"version\":\"0.1.15\",\"binary_sha256\":\"deadbeef\"}").?;
    defer {
        if (full.version) |v| a.free(v);
        if (full.binary_sha256) |s| a.free(s);
    }
    try std.testing.expectEqualStrings("0.1.15", full.version.?);
    try std.testing.expectEqualStrings("deadbeef", full.binary_sha256.?);

    // version-only sidecar is still usable.
    const ver_only = parseSidecar(a, "{\"version\":\"0.1.14\"}").?;
    defer if (ver_only.version) |v| a.free(v);
    try std.testing.expectEqualStrings("0.1.14", ver_only.version.?);
    try std.testing.expect(ver_only.binary_sha256 == null);

    // empty object → nothing to compare → null.
    try std.testing.expect(parseSidecar(a, "{}") == null);
    // unknown fields ignored, no usable fields → null.
    try std.testing.expect(parseSidecar(a, "{\"other\":1}") == null);
    // garbage → null, never an error.
    try std.testing.expect(parseSidecar(a, "not json") == null);
    try std.testing.expect(parseSidecar(a, "") == null);
}

fn factsFixture(path: []const u8, sha: ?[]const u8, version: ?[]const u8) doctor_binaries.BinaryFacts {
    return .{
        .path = path,
        .exists = true,
        .sha256 = sha,
        .version = version,
        .version_source = "fixture",
        .source = "path_or_installed",
    };
}

fn reportFixture(self_sha: ?[]const u8, self_version: ?[]const u8, winner: ?doctor_binaries.BinaryFacts) doctor_binaries.BinariesReport {
    return .{
        .self = factsFixture("/self/oauth-mux", self_sha, self_version),
        .path_env_present = true,
        .path_entries = &.{},
        .path_winner = winner,
        .shadow = .{ .shadowed = false, .distinct_sha_count = if (winner != null) 1 else 0 },
        .resident = null,
        .stale = .{ .stale = false, .sha_mismatch = false, .version_older = false, .reason = "n/a" },
    };
}

test "assemble + exitCode contract: stale PATH winner exits non-zero" {
    // Different local bytes fail closed without executing either binary.
    const winner = factsFixture("/usr/local/bin/oauth-mux", "bbb", "0.1.15");
    const check = assemble(reportFixture("aaa", "0.1.13", winner), "0.1.13", null, null, false, null);
    try std.testing.expectEqual(Verdict.diverged, check.path_verdict);
    try std.testing.expect(check.stale());
    try std.testing.expectEqual(stale_exit_code, check.exitCode());
}

test "assemble + exitCode contract: differing PATH winner fails even when its version is older" {
    const winner = factsFixture("/nix/store/x/bin/oauth-mux", "bbb", "0.1.13");
    const check = assemble(reportFixture("aaa", "0.1.15", winner), "0.1.15", null, null, false, null);
    try std.testing.expectEqual(Verdict.diverged, check.path_verdict);
    try std.testing.expect(check.stale());
    try std.testing.expectEqual(stale_exit_code, check.exitCode());
}

test "assemble + exitCode contract: match PATH winner exits zero" {
    const winner = factsFixture("/usr/local/bin/oauth-mux", "aaa", "0.1.15");
    const check = assemble(reportFixture("aaa", "0.1.15", winner), "0.1.15", null, null, false, null);
    try std.testing.expectEqual(Verdict.match, check.path_verdict);
    try std.testing.expect(!check.stale());
    try std.testing.expectEqual(@as(u8, 0), check.exitCode());
}

test "assemble: no PATH winner is unknown-provenance and fails closed" {
    const check = assemble(reportFixture("aaa", "0.1.15", null), "0.1.15", null, null, false, null);
    try std.testing.expectEqual(Verdict.unknown_provenance, check.path_verdict);
    try std.testing.expectEqual(Verdict.unknown_provenance, check.sidecar_verdict);
    try std.testing.expect(check.stale());
    try std.testing.expectEqual(stale_exit_code, check.exitCode());
}

test "assemble: divergent sidecar exits non-zero" {
    const sc = Sidecar{ .version = "0.1.15", .binary_sha256 = "ccc" };
    const winner = factsFixture("/usr/local/bin/oauth-mux", "aaa", "0.1.13");
    const check = assemble(reportFixture("aaa", "0.1.13", winner), "0.1.13", sc, "/usr/local/bin/oauth-mux.version.json", false, null);
    try std.testing.expectEqual(Verdict.diverged, check.sidecar_verdict);
    try std.testing.expect(check.stale());
    try std.testing.expectEqual(stale_exit_code, check.exitCode());
}

test "assemble: resident provenance failure exits non-zero" {
    const winner = factsFixture("/usr/local/bin/oauth-mux", "aaa", "0.1.15");
    var report = reportFixture("aaa", "0.1.15", winner);
    report.stale = .{
        .stale = true,
        .sha_mismatch = false,
        .version_older = false,
        .reason = "resident_identity_provenance_incomplete",
    };
    const check = assemble(report, "0.1.15", null, null, false, null);
    try std.testing.expectEqual(Verdict.match, check.path_verdict);
    try std.testing.expect(check.stale());
    try std.testing.expectEqual(stale_exit_code, check.exitCode());
}

test "assemble: online is inert unless attempted, then can flip staleness" {
    const winner_013 = factsFixture("/usr/local/bin/oauth-mux", "aaa", "0.1.13");
    const winner_015 = factsFixture("/usr/local/bin/oauth-mux", "aaa", "0.1.15");
    // Not attempted: even a newer latest tag cannot affect the verdict.
    var check = assemble(reportFixture("aaa", "0.1.13", winner_013), "0.1.13", null, null, false, "0.1.99");
    try std.testing.expect(!check.stale());
    try std.testing.expectEqual(Verdict.unknown_provenance, check.online_verdict);

    // Attempted + behind latest release → stale.
    check = assemble(reportFixture("aaa", "0.1.13", winner_013), "0.1.13", null, null, true, "0.1.99");
    try std.testing.expectEqual(Verdict.stale, check.online_verdict);
    try std.testing.expect(check.stale());

    // Attempted + on latest release → not stale.
    check = assemble(reportFixture("aaa", "0.1.15", winner_015), "0.1.15", null, null, true, "v0.1.15");
    try std.testing.expectEqual(Verdict.match, check.online_verdict);
    try std.testing.expect(!check.stale());
}

test "writeJson renders well-formed, parseable JSON" {
    const winner = factsFixture("/nix/store/x/bin/oauth-mux", "aaa", "0.1.15");
    const check = assemble(reportFixture("aaa", "0.1.15", winner), "0.1.15", null, "/nix/store/x/bin/oauth-mux.version.json", false, null);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(check, buf.writer());

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"check\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"resident_identity\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"verdict\":\"match\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stale\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"exit_code\":0") != null);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buf.items, .{});
    parsed.deinit();
}

test "writeText renders the running/PATH/sidecar sections and a verdict" {
    const winner = factsFixture("/nix/store/x/bin/oauth-mux", "aaa", "0.1.15");
    const check = assemble(reportFixture("aaa", "0.1.15", winner), "0.1.15", null, null, false, null);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeText(check, buf.writer());

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "running:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "vs PATH-installed:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "vs install sidecar:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "vs resident service:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "verdict:") != null);
    // No --online → no online section.
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "latest release:") == null);
}
