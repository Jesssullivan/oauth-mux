//! Claude (Claude Code) OAuth reauth CASSETTE — greenfield, the deterministic
//! offline-proof core for the Claude reauth adapter (PR#354) and the keepalive
//! warm scheduler (PR#355). TIN-1823 / A.7 (cassettes/recorder+replayer).
//!
//! Why this exists: re-authing accounts and warming tokens means hitting a real
//! OAuth token endpoint. To unit-test the adapter/scheduler WITHOUT a live
//! account or network — and without ever materializing a real secret — we replay
//! a recorded token-endpoint exchange. The hazard a token cassette must avoid is
//! obvious: a refresh token is account-takeover-grade, and the repo's own
//! `src/fixture_redaction.zig` scanner (run in the main test suite) walks
//! `test/fixtures/` and REJECTS any file containing `sk-`, `access_token`,
//! `refresh_token`, `id_token`, etc.
//!
//! Design: NEUTRALIZE-ON-DISK, RECONSTRUCT-IN-MEMORY.
//!   * On disk (`test/fixtures/cassettes/claude/*.jsonl`) a cassette line carries
//!     only NON-secret shape: the op, the HTTP status, the token LENGTH-CLASSES,
//!     and the (non-secret) expiry/scope/token_type. It contains none of the
//!     forbidden markers, so it passes the fixture scanner.
//!   * At replay time the `Replayer` RECONSTRUCTS the real-shaped token-endpoint
//!     JSON body in memory (`{"access_token":"sk-ant-oat01-…", …}`) so the real
//!     adapter parser + prefix checks are exercised. That body is never written
//!     to disk. The `sk-ant-…` prefix constants live in THIS source file, which
//!     the fixture scanner does not walk.
//!
//! The `Recorder` (for an optional, opt-in live capture) redacts AT CAPTURE TIME,
//! FAIL-CLOSED: it extracts only the length-class + non-secret fields and drops
//! the line unless the response matches the known token shape, so a renamed
//! upstream field can never leak a raw value. The recommended default is to
//! HAND-AUTHOR the neutral fixtures (no real secret ever exists) — see the repo
//! runbook; the recorder is the regression escape hatch.
//!
//! Self-contained: `std` only, NO `@import` of existing `src`. The HTTP and
//! refresh seams below are STRUCTURAL copies of `claude_reauth.HttpPostFn`
//! (PR#354) and `warm_scheduler.RefreshFn` (PR#355); the replayer/shim are
//! assignable wherever those seams are expected (checked at compile time on the
//! integration branch). Pure, allocation-explicit, `std.testing.allocator`-clean.

const std = @import("std");

// ── Local structural mirrors of the PR#354 / PR#355 seams (no @import of src) ──

/// Mirror of `claude_reauth.HttpError`.
pub const HttpError = error{ OutOfMemory, HttpFailed };

/// Mirror of `claude_reauth.HttpPostFn`: POST `body` to `url`, return the
/// freshly-allocated response body bytes (the caller frees). Non-2xx is signalled
/// as `error.HttpFailed` (the body-only seam carries no status to the adapter).
pub const HttpPostFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    url: []const u8,
    body: []const u8,
    content_type: []const u8,
) HttpError![]u8;

/// Mirror of `warm_scheduler.RefreshError`.
pub const RefreshError = error{ OutOfMemory, RefreshFailed };

/// Mirror of `warm_scheduler.RefreshResult`.
pub const RefreshResult = struct {
    new_last_refresh_ms: i64,
    new_expires_at_ms: i64,
};

/// Mirror of `warm_scheduler.RefreshFn`.
pub const RefreshFn = *const fn (ctx: *anyopaque, account_key: []const u8) RefreshError!RefreshResult;

// ── Real-shape constants (source-only; NEVER written to a fixture file) ─────────

pub const token_endpoint = "https://console.anthropic.com/v1/oauth/token";
pub const form_content_type = "application/x-www-form-urlencoded";
pub const access_token_prefix = "sk-ant-oat01-";
pub const refresh_token_prefix = "sk-ant-ort01-";

/// Known token markers. A neutral cassette line must contain NONE of these — the
/// recorder checks the FINAL emitted line against this set (defense in depth) so
/// that even a passthrough field (scope/token_type) carrying a marker fails closed
/// rather than writing something the fixture scanner would reject. `sk-ant-`
/// subsumes both token prefixes; `eyJ` is the base64url JWT header.
const token_markers = [_][]const u8{ "sk-ant-", "eyJ" };

fn containsTokenMarker(s: []const u8) bool {
    for (token_markers) |m| {
        if (std.mem.indexOf(u8, s, m) != null) return true;
    }
    return false;
}

/// True iff `body` contains the form param `key=value` at a real param boundary:
/// `key` starts at the body start or just after `&`, is followed by `=`, and the
/// value runs exactly to the next `&` (or end). Prevents a `key=value` substring
/// hiding inside another param's value from matching.
fn hasFormParam(body: []const u8, key: []const u8, value: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, body, i, key)) |pos| {
        i = pos + 1;
        if (pos != 0 and body[pos - 1] != '&') continue; // not a param boundary
        const after_key = pos + key.len;
        if (after_key >= body.len or body[after_key] != '=') continue;
        const vstart = after_key + 1;
        const vend = std.mem.indexOfScalarPos(u8, body, vstart, '&') orelse body.len;
        if (std.mem.eql(u8, body[vstart..vend], value)) return true;
    }
    return false;
}

/// The single, constant redaction filler. A fixed char keeps cassettes
/// byte-deterministic across re-records and is class-preserving / value-
/// destroying (it carries length, never the secret).
pub const filler_char: u8 = 'A';

// ── Cassette model ─────────────────────────────────────────────────────────

pub const Op = enum {
    exchange, // grant_type=authorization_code
    refresh, // grant_type=refresh_token

    fn fromStr(s: []const u8) ?Op {
        if (std.mem.eql(u8, s, "exchange")) return .exchange;
        if (std.mem.eql(u8, s, "refresh")) return .refresh;
        return null;
    }

    /// Discriminator carried in the request FORM body (the token endpoint URL is
    /// constant for both ops, so we key off the grant_type — the analogue of the
    /// codex cassettes' (method,path) key).
    fn fromRequestBody(body: []const u8) ?Op {
        // Anchored on a real form-param boundary so a `grant_type=…` substring
        // buried in another param's value (e.g. a redirect_uri) can't misroute.
        if (hasFormParam(body, "grant_type", "authorization_code")) return .exchange;
        if (hasFormParam(body, "grant_type", "refresh_token")) return .refresh;
        return null;
    }
};

/// One recorded exchange — NON-secret shape only.
pub const Entry = struct {
    op: Op,
    status: u16,
    /// Length-class of the access/refresh token values (so length assertions stay
    /// exercised); the values themselves are never stored.
    at_len: usize,
    rt_len: usize,
    /// Relative expiry (seconds). Non-secret. Replay computes the absolute instant
    /// from an injected clock, keeping determinism.
    ttl_s: i64,
    scope: []const u8, // non-secret; arena-owned
    ttype: []const u8, // token_type, non-secret; arena-owned
};

pub const ParseError = error{ OutOfMemory, MalformedCassette };

/// A parsed cassette: a slice of entries backed by an internal arena. Call
/// `deinit` to free everything.
pub const Cassette = struct {
    entries: []Entry,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Cassette) void {
        self.arena.deinit();
    }

    /// Parse newline-delimited JSON (one `Entry` per non-empty line). Pure: no
    /// I/O, no globals. Unknown fields are ignored (tolerant to additive drift).
    pub fn parse(gpa: std.mem.Allocator, jsonl: []const u8) ParseError!Cassette {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        var list = std.ArrayList(Entry).init(a);

        // On-disk neutral schema (no forbidden markers).
        const RawEntry = struct {
            v: u32 = 1,
            op: []const u8 = "",
            status: u16 = 0,
            at_len: usize = 0,
            rt_len: usize = 0,
            ttl_s: i64 = 0,
            scope: []const u8 = "",
            ttype: []const u8 = "Bearer",
        };

        var it = std.mem.splitScalar(u8, jsonl, '\n');
        while (it.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;

            const parsed = std.json.parseFromSlice(RawEntry, gpa, line, .{
                .ignore_unknown_fields = true,
            }) catch return error.MalformedCassette;
            defer parsed.deinit();
            const r = parsed.value;

            const op = Op.fromStr(r.op) orelse return error.MalformedCassette;
            if (r.status == 0) return error.MalformedCassette;

            try list.append(.{
                .op = op,
                .status = r.status,
                .at_len = r.at_len,
                .rt_len = r.rt_len,
                .ttl_s = r.ttl_s,
                .scope = try a.dupe(u8, r.scope),
                .ttype = try a.dupe(u8, r.ttype),
            });
        }

        return .{ .entries = try list.toOwnedSlice(), .arena = arena };
    }
};

// ── Reconstruction (neutral Entry -> real-shaped token-endpoint body, in memory) ─

/// Build a token value: real prefix + filler padded to `total_len` (clamped so it
/// is never shorter than the prefix). Source-only; never persisted.
fn buildTokenValue(a: std.mem.Allocator, prefix: []const u8, total_len: usize) ![]u8 {
    const pad: usize = if (total_len > prefix.len) total_len - prefix.len else 0;
    var buf = try a.alloc(u8, prefix.len + pad);
    @memcpy(buf[0..prefix.len], prefix);
    @memset(buf[prefix.len..], filler_char);
    return buf;
}

/// Reconstruct the REAL-shaped token-endpoint success body for a 2xx entry. The
/// returned bytes carry `sk-ant-…` prefixes + `access_token`/`refresh_token`
/// keys so the real adapter parser is exercised — but they exist only in memory.
pub fn reconstructSuccessBody(a: std.mem.Allocator, entry: Entry) ![]u8 {
    const access = try buildTokenValue(a, access_token_prefix, entry.at_len);
    defer a.free(access);
    const refresh = try buildTokenValue(a, refresh_token_prefix, entry.rt_len);
    defer a.free(refresh);

    return std.fmt.allocPrint(
        a,
        "{{\"access_token\":\"{s}\",\"refresh_token\":\"{s}\"," ++
            "\"expires_in\":{d},\"scope\":\"{s}\",\"token_type\":\"{s}\"}}",
        .{ access, refresh, entry.ttl_s, entry.scope, entry.ttype },
    );
}

// ── Replayer: serves as an HttpPostFn ──────────────────────────────────────

pub const Miss = struct {
    op: Op,
    reason: enum { no_line_for_op, failure_status },
};

/// Replays a cassette as the adapter's injected HTTP seam. One saturating cursor
/// per op (a single line replays every tick; a multi-line sequence plays in order
/// then sticks on the last). Matching keys off the request body's grant_type, so
/// it is robust to the constant endpoint URL.
pub const Replayer = struct {
    cassette: *const Cassette,
    exchange_cursor: usize = 0,
    refresh_cursor: usize = 0,
    last_miss: ?Miss = null,

    fn nextEntry(self: *Replayer, op: Op) ?*const Entry {
        var seen: usize = 0;
        var idx: usize = 0;
        // Walk entries for this op; pick the one at the op-local cursor, saturating.
        const cursor = switch (op) {
            .exchange => self.exchange_cursor,
            .refresh => self.refresh_cursor,
        };
        var last_for_op: ?*const Entry = null;
        while (idx < self.cassette.entries.len) : (idx += 1) {
            const e = &self.cassette.entries[idx];
            if (e.op != op) continue;
            last_for_op = e;
            if (seen == cursor) {
                // advance (saturate at the last matching entry)
                switch (op) {
                    .exchange => self.exchange_cursor += 1,
                    .refresh => self.refresh_cursor += 1,
                }
                return e;
            }
            seen += 1;
        }
        // Cursor past the end: saturate on the last matching entry, if any.
        return last_for_op;
    }

    /// Matches `HttpPostFn`. Returns a freshly-allocated reconstructed body for a
    /// 2xx entry, or `error.HttpFailed` for a failure-status entry or an op miss
    /// (a value-free diagnostic is recorded in `last_miss`).
    pub fn post(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        url: []const u8,
        body: []const u8,
        content_type: []const u8,
    ) HttpError![]u8 {
        const self: *Replayer = @ptrCast(@alignCast(ctx));
        _ = url;
        _ = content_type;

        const op = Op.fromRequestBody(body) orelse {
            // Unknown grant: treat as a refresh miss for diagnostics (fail-closed).
            self.last_miss = .{ .op = .refresh, .reason = .no_line_for_op };
            return error.HttpFailed;
        };

        const entry = self.nextEntry(op) orelse {
            self.last_miss = .{ .op = op, .reason = .no_line_for_op };
            return error.HttpFailed;
        };

        if (entry.status >= 400) {
            self.last_miss = .{ .op = op, .reason = .failure_status };
            return error.HttpFailed;
        }

        return reconstructSuccessBody(allocator, entry.*) catch return error.OutOfMemory;
    }
};

// ── Recorder: wraps a real HttpPostFn, neutralizes at capture, fail-closed ─────

/// Pure, fail-closed neutralizer: given a REAL token-endpoint success body, emit
/// one neutral JSONL line carrying only length-class + non-secret fields. Returns
/// `error.MalformedCassette` (drop the line) unless the body matches the known
/// token shape with the expected `sk-ant-…` prefixes — so a renamed/unknown field
/// can never carry a raw value through. The real token VALUES are never copied.
pub fn neutralizeSuccessBody(a: std.mem.Allocator, op: Op, real_body: []const u8) ParseError![]u8 {
    const Shape = struct {
        access_token: []const u8 = "",
        refresh_token: []const u8 = "",
        expires_in: i64 = 0,
        scope: []const u8 = "",
        token_type: []const u8 = "Bearer",
    };
    const parsed = std.json.parseFromSlice(Shape, a, real_body, .{
        .ignore_unknown_fields = true,
    }) catch return error.MalformedCassette;
    defer parsed.deinit();
    const s = parsed.value;

    // Fail-closed: only record if the secret fields match the known prefixes.
    if (!std.mem.startsWith(u8, s.access_token, access_token_prefix)) return error.MalformedCassette;
    if (!std.mem.startsWith(u8, s.refresh_token, refresh_token_prefix)) return error.MalformedCassette;

    const op_str = switch (op) {
        .exchange => "exchange",
        .refresh => "refresh",
    };
    const line = try std.fmt.allocPrint(
        a,
        "{{\"v\":1,\"op\":\"{s}\",\"status\":200,\"at_len\":{d},\"rt_len\":{d}," ++
            "\"ttl_s\":{d},\"scope\":\"{s}\",\"ttype\":\"{s}\"}}",
        .{ op_str, s.access_token.len, s.refresh_token.len, s.expires_in, s.scope, s.token_type },
    );
    // Defense in depth: scope/token_type are echoed from the real response. Refuse
    // to emit any neutral line that itself carries a token marker, so the recorder
    // can never write something the fixture scanner would reject (fail-closed).
    if (containsTokenMarker(line)) {
        a.free(line);
        return error.MalformedCassette;
    }
    return line;
}

/// Wraps a real HTTP seam: forwards the request unchanged, appends a neutral
/// recorded line to `sink` (JSONL), and returns the inner body untouched so
/// recording is transparent to the adapter. On a fail-closed redaction drop the
/// request still succeeds — only the cassette line is skipped (never raw-written).
pub const Recorder = struct {
    inner: HttpPostFn,
    inner_ctx: *anyopaque,
    sink: *std.ArrayList(u8),

    pub fn post(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        url: []const u8,
        body: []const u8,
        content_type: []const u8,
    ) HttpError![]u8 {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        const resp = try self.inner(allocator, self.inner_ctx, url, body, content_type);
        // Record best-effort; a redaction failure drops the line, never the call.
        if (Op.fromRequestBody(body)) |op| {
            if (neutralizeSuccessBody(allocator, op, resp)) |line| {
                defer allocator.free(line);
                self.sink.appendSlice(line) catch {};
                self.sink.append('\n') catch {};
            } else |_| {}
        }
        return resp;
    }
};

// ── Scheduler binding: replayer -> warm_scheduler.RefreshFn shim ───────────────

/// Binds a `Replayer` as the keepalive scheduler's refresh seam. A `tick` that
/// finds an account due calls this; it replays the `refresh` cassette, parses the
/// (non-secret) relative expiry, and returns the absolute instants the scheduler
/// records. A failure cassette maps to `error.RefreshFailed` — driving the
/// scheduler's backoff/dead path (never-halt) while siblings stay warm.
pub const SchedulerBinding = struct {
    replayer: *Replayer,
    allocator: std.mem.Allocator,
    now_ms: i64,

    /// Matches `warm_scheduler.RefreshFn`.
    pub fn refresh(ctx: *anyopaque, account_key: []const u8) RefreshError!RefreshResult {
        const self: *SchedulerBinding = @ptrCast(@alignCast(ctx));
        _ = account_key;

        // A minimal refresh-grant body so the replayer matches op=refresh.
        const req = "grant_type=refresh_token";
        const resp = Replayer.post(
            self.allocator,
            @ptrCast(self.replayer),
            token_endpoint,
            req,
            form_content_type,
        ) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.HttpFailed => return error.RefreshFailed,
        };
        defer self.allocator.free(resp);

        const Shape = struct { expires_in: i64 = 0 };
        const parsed = std.json.parseFromSlice(Shape, self.allocator, resp, .{
            .ignore_unknown_fields = true,
        }) catch return error.RefreshFailed;
        defer parsed.deinit();

        const ttl_ms = parsed.value.expires_in *| std.time.ms_per_s;
        return .{
            .new_last_refresh_ms = self.now_ms,
            .new_expires_at_ms = self.now_ms +| ttl_ms,
        };
    }
};
