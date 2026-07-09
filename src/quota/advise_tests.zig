//! Property-based tests for the pure valet advisor core (`advise.zig`).
//! Deterministic-PRNG fuzz loops, `std` only, no I/O, no allocation in the core.
//!
//!     zig test src/quota/advise_tests.zig
//!
//! Mirrors `bucket_tests.zig`: `refAllDeclsRecursive`, fuzz `Gen`, a structural
//! purity seam test (A6, the P7 technique), and negative controls that prove the
//! properties BITE. Implements the design's §Required Properties surface for the
//! advisor (TIN-2719 M0 PR1):
//!
//!   A1 determinism        — same rows+now → bit-identical Advice; any input
//!                            permutation → the same suggestion (design §8).
//!   A2 honesty monotonicity— max output provenance ≤ max input confidence; empty
//!                            rows → ALL classes unobserved, suggestion null
//!                            (design §7: confidence is visible; §Pure Core).
//!   A3 all-waiting         — no eligible account → suggestion null and
//!                            wait_until = the earliest reset among waiting
//!                            candidates.
//!   A4 extremes            — i64 min/max now/resets_at never panic (saturating).
//!   A5 exclusion respected — an excluded account is never suggested even if best
//!                            (design §Required Property 3: duplicate collapse).
//!   A6 module-purity seam  — no clock/refresh/net seam; data-in / data-out.

const std = @import("std");
const advise = @import("advise.zig");
const bucket = @import("bucket.zig");

test {
    std.testing.refAllDeclsRecursive(advise);
}

// ── shared fixtures ───────────────────────────────────────────────────────────

const providers = [_][]const u8{ "claude", "codex" };
const accounts = [_][]const u8{ "acct-a", "acct-b", "acct-c", "acct-d" };
const classes = [_][]const u8{ "opus", "fable", "sonnet", "haiku" };
const states = [_][]const u8{ "live", "degraded", "dead" };
const avails = [_]?[]const u8{ null, "available", "rate_limited", "quota_exhausted", "cooldown" };

// The provider-schema-declared class set (passed in; never hardcoded in advise.zig).
const declared = [_]advise.DeclaredClass{
    .{ .provider = "claude", .class = "opus" },
    .{ .provider = "claude", .class = "fable" },
    .{ .provider = "claude", .class = "sonnet" },
    .{ .provider = "claude", .class = "haiku" },
    .{ .provider = "codex", .class = "opus" },
};

const Gen = struct {
    r: std.Random,
    extreme: bool = false,

    fn pick(self: Gen, comptime T: type, arr: []const T) T {
        return arr[self.r.intRangeAtMost(usize, 0, arr.len - 1)];
    }
    fn ts(self: Gen) ?i64 {
        if (self.r.boolean()) return null;
        if (self.extreme) return switch (self.r.intRangeAtMost(u8, 0, 3)) {
            0 => std.math.minInt(i64),
            1 => std.math.maxInt(i64),
            2 => 0,
            else => self.r.int(i64),
        };
        return self.r.intRangeAtMost(i64, -1_000_000, 1_000_000);
    }
    fn row(self: Gen) advise.Row {
        return .{
            .provider = self.pick([]const u8, &providers),
            .account = self.pick([]const u8, &accounts),
            .class = self.pick([]const u8, &classes),
            .state = self.pick([]const u8, &states),
            .availability = self.pick(?[]const u8, &avails),
            .since = self.ts(),
            .retry_after_s = if (self.r.boolean()) null else self.r.int(u32),
            .limited_at = self.ts(),
            .window_resets_at = self.ts(),
            .usage_pct = if (self.r.boolean()) null else self.r.int(u8),
            .exhausted_at = self.ts(),
            .cooldown_until = self.ts(),
        };
    }
};

fn shuffle(r: std.Random, rows: []advise.Row) void {
    var i: usize = rows.len;
    while (i > 1) {
        i -= 1;
        const j = r.intRangeAtMost(usize, 0, i);
        const tmp = rows[i];
        rows[i] = rows[j];
        rows[j] = tmp;
    }
}

fn summaryEql(a: advise.ClassSummary, b: advise.ClassSummary) bool {
    return std.mem.eql(u8, a.provider, b.provider) and
        std.mem.eql(u8, a.class, b.class) and
        std.meta.eql(a.status, b.status) and
        a.usage_pct == b.usage_pct and
        a.resets_at == b.resets_at and
        a.provenance == b.provenance;
}

fn suggestionEql(a: ?advise.Suggestion, b: ?advise.Suggestion) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    const x = a.?;
    const y = b.?;
    return std.mem.eql(u8, x.provider, y.provider) and
        std.mem.eql(u8, x.account, y.account) and
        std.mem.eql(u8, x.class, y.class) and
        std.mem.eql(u8, x.reason, y.reason) and
        x.provenance == y.provenance;
}

fn adviceEql(a: advise.Advice, b: advise.Advice) bool {
    if (a.classes.len != b.classes.len) return false;
    for (a.classes, b.classes) |x, y| if (!summaryEql(x, y)) return false;
    return suggestionEql(a.suggestion, b.suggestion) and a.wait_until == b.wait_until;
}

// ── A1: determinism + permutation-invariant suggestion ────────────────────────

test "A1 same input → bit-identical Advice; any permutation → same suggestion" {
    var prng = std.Random.DefaultPrng.init(0xAD715E01);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 600) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 12);
        var rows: [12]advise.Row = undefined;
        for (0..n) |i| rows[i] = g.row();
        const now = g.ts() orelse 0;
        const demand = advise.Demand{
            .provider = if (g.r.boolean()) null else g.pick([]const u8, &providers),
            .class = if (g.r.boolean()) null else g.pick([]const u8, &classes),
        };

        var buf_a: [16]advise.ClassSummary = undefined;
        const ref = advise.advise(rows[0..n], &declared, demand, &.{}, now, &buf_a);

        // Same input, fresh buffer → bit-identical.
        var buf_a2: [16]advise.ClassSummary = undefined;
        const ref2 = advise.advise(rows[0..n], &declared, demand, &.{}, now, &buf_a2);
        try std.testing.expect(adviceEql(ref, ref2));

        // Any permutation of the input rows → the same suggestion + summaries.
        var perm: usize = 0;
        while (perm < 5) : (perm += 1) {
            var copy: [12]advise.Row = undefined;
            @memcpy(copy[0..n], rows[0..n]);
            shuffle(g.r, copy[0..n]);
            var buf_b: [16]advise.ClassSummary = undefined;
            const got = advise.advise(copy[0..n], &declared, demand, &.{}, now, &buf_b);
            try std.testing.expect(adviceEql(ref, got));
        }
    }
}

// ── A2: honesty monotonicity + empty-rows → all unobserved ────────────────────

test "A2 output provenance never exceeds input confidence; never fabricated" {
    var prng = std.Random.DefaultPrng.init(0x40E57C0F);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 600) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 12);
        var rows: [12]advise.Row = undefined;
        var max_in: u8 = 0; // unobserved
        for (0..n) |i| {
            rows[i] = g.row();
            max_in = @max(max_in, @intFromEnum(advise.rowProvenance(rows[i])));
        }
        const now = g.ts() orelse 0;

        var buf: [16]advise.ClassSummary = undefined;
        const adv = advise.advise(rows[0..n], &declared, .{}, &.{}, now, &buf);

        for (adv.classes) |cs| {
            // A persisted row is never a provider-stated header → never `.proven`.
            try std.testing.expect(cs.provenance != .proven);
            try std.testing.expect(@intFromEnum(cs.provenance) <= max_in);
        }
        if (adv.suggestion) |s| {
            try std.testing.expect(s.provenance != .proven);
            try std.testing.expect(@intFromEnum(s.provenance) <= max_in);
        }
    }
}

test "A2 empty rows → all declared classes unobserved, suggestion null" {
    var buf: [16]advise.ClassSummary = undefined;
    const adv = advise.advise(&.{}, &declared, .{ .provider = "claude", .class = "opus" }, &.{}, 1000, &buf);
    try std.testing.expectEqual(declared.len, adv.classes.len);
    for (adv.classes) |cs| {
        try std.testing.expectEqual(advise.Provenance.unobserved, cs.provenance);
    }
    try std.testing.expect(adv.suggestion == null);
    try std.testing.expect(adv.wait_until == null);
}

// ── A3: all-waiting → suggestion null, wait_until = min reset ──────────────────

test "A3 all candidates waiting → suggestion null, wait_until = earliest reset" {
    // Three live, demand-matching accounts, all quota_exhausted with FUTURE resets.
    const resets_s = [_]i64{ 5000, 2000, 8000 }; // seconds; min = 2000
    var rows: [3]advise.Row = undefined;
    for (0..3) |i| rows[i] = .{
        .provider = "claude",
        .account = accounts[i],
        .class = "opus",
        .state = "live",
        .availability = "quota_exhausted",
        .exhausted_at = 100,
        .window_resets_at = resets_s[i],
    };
    const now_ms: i64 = 1000 * 1000; // 1000s in ms; before every reset (2000s = 2_000_000 ms)
    var buf: [16]advise.ClassSummary = undefined;
    const adv = advise.advise(&rows, &declared, .{ .provider = "claude", .class = "opus" }, &.{}, now_ms, &buf);

    try std.testing.expect(adv.suggestion == null);
    try std.testing.expectEqual(@as(?i64, 2000 * 1000), adv.wait_until); // min reset, in ms
}

// ── A4: extremes never panic (saturating) ─────────────────────────────────────

test "A4 i64 min/max now/resets never panic" {
    var prng = std.Random.DefaultPrng.init(0xE47E3E11);
    const g = Gen{ .r = prng.random(), .extreme = true };
    const nows = [_]i64{ std.math.minInt(i64), std.math.maxInt(i64), 0 };
    var trial: usize = 0;
    while (trial < 1000) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 10);
        var rows: [10]advise.Row = undefined;
        for (0..n) |i| rows[i] = g.row();
        for (nows) |now| {
            var buf: [16]advise.ClassSummary = undefined;
            const adv = advise.advise(rows[0..n], &declared, .{}, &.{}, now, &buf);
            // Touch every field so the optimizer cannot elide the computation.
            std.mem.doNotOptimizeAway(adv.wait_until);
            for (adv.classes) |cs| std.mem.doNotOptimizeAway(cs.resets_at);
        }
    }
}

// ── A5: exclusion list respected ──────────────────────────────────────────────

test "A5 excluded account is never suggested even when it would rank best" {
    // Two eligible accounts for the demand; "acct-a" sorts first (best on the
    // lexicographic tiebreak). Excluding it must hand the suggestion to "acct-b".
    const rows = [_]advise.Row{
        .{ .provider = "claude", .account = "acct-a", .class = "opus", .state = "live", .availability = "available" },
        .{ .provider = "claude", .account = "acct-b", .class = "opus", .state = "live", .availability = "available" },
    };
    const demand = advise.Demand{ .provider = "claude", .class = "opus" };

    var buf1: [16]advise.ClassSummary = undefined;
    const open = advise.advise(&rows, &declared, demand, &.{}, 0, &buf1);
    try std.testing.expect(open.suggestion != null);
    try std.testing.expectEqualStrings("acct-a", open.suggestion.?.account);

    const excluded = [_][]const u8{"acct-a"};
    var buf2: [16]advise.ClassSummary = undefined;
    const gated = advise.advise(&rows, &declared, demand, &excluded, 0, &buf2);
    try std.testing.expect(gated.suggestion != null);
    try std.testing.expectEqualStrings("acct-b", gated.suggestion.?.account);

    // Excluding BOTH → no suggestion at all (never a "dead" outcome).
    const both = [_][]const u8{ "acct-a", "acct-b" };
    var buf3: [16]advise.ClassSummary = undefined;
    const none = advise.advise(&rows, &declared, demand, &both, 0, &buf3);
    try std.testing.expect(none.suggestion == null);
}

test "A5 a dead/degraded credential is never suggested (credential gate)" {
    const rows = [_]advise.Row{
        .{ .provider = "claude", .account = "acct-a", .class = "opus", .state = "dead", .availability = "available" },
        .{ .provider = "claude", .account = "acct-b", .class = "opus", .state = "degraded", .availability = "available" },
    };
    var buf: [16]advise.ClassSummary = undefined;
    const adv = advise.advise(&rows, &declared, .{ .provider = "claude", .class = "opus" }, &.{}, 0, &buf);
    // Both quota-available but neither credential-alive → no honest suggestion.
    try std.testing.expect(adv.suggestion == null);
}

// ── A6: module-purity seam (the P7 technique) ─────────────────────────────────

test "A6 module exposes no clock/refresh/net seam; data-in / data-out" {
    comptime {
        try std.testing.expect(!@hasDecl(advise, "RefreshFn"));
        try std.testing.expect(!@hasDecl(advise, "ClockFn"));
        try std.testing.expect(!@hasDecl(advise, "RefreshError"));
        try std.testing.expect(!@hasDecl(advise, "Client")); // no std.http.Client seam

        // The advisor is data-in / data-out: it returns a plain `Advice` value, not
        // an error union, and reads no clock (every instant is a passed-in i64).
        const A = @typeInfo(@TypeOf(advise.advise)).@"fn";
        try std.testing.expect(A.return_type.? == advise.Advice);

        // The boundary adapter yields a plain QuotaBucket — no seam, no error union.
        const B = @typeInfo(@TypeOf(advise.bucketFromHealthRow)).@"fn";
        try std.testing.expect(B.return_type.? == bucket.QuotaBucket);
        try std.testing.expectEqual(@as(usize, 1), B.params.len);
    }
}

// ── NEGATIVE CONTROL: the determinism property BITES ──────────────────────────
//
// A deliberately-broken picker that takes the FIRST eligible row in input order
// with no lexicographic tiebreak. We prove it is order-sensitive (so A1's
// permutation invariance is meaningful) while the real advisor is not.

fn firstEligible(rows: []const advise.Row, demand: advise.Demand, now: i64) ?advise.Row {
    for (rows) |row| {
        if (demand.provider) |p| if (!std.mem.eql(u8, row.provider, p)) continue;
        if (demand.class) |c| if (!std.mem.eql(u8, row.class, c)) continue;
        if (!std.mem.eql(u8, row.state, "live")) continue;
        const b = advise.bucketFromHealthRow(row);
        if (bucket.effectiveStatus(b, now) == .available) return row;
    }
    return null;
}

test "negative control: order-blind picker is order-sensitive; advisor is not" {
    const a = advise.Row{ .provider = "claude", .account = "acct-a", .class = "opus", .state = "live", .availability = "available" };
    const b = advise.Row{ .provider = "claude", .account = "acct-b", .class = "opus", .state = "live", .availability = "available" };
    const demand = advise.Demand{ .provider = "claude", .class = "opus" };

    const fwd = [_]advise.Row{ a, b };
    const rev = [_]advise.Row{ b, a };

    // Broken picker: first-in-order → different accounts under permutation.
    try std.testing.expectEqualStrings("acct-a", firstEligible(&fwd, demand, 0).?.account);
    try std.testing.expectEqualStrings("acct-b", firstEligible(&rev, demand, 0).?.account);

    // Real advisor: lexicographic tiebreak → "acct-a" regardless of input order.
    var buf1: [16]advise.ClassSummary = undefined;
    var buf2: [16]advise.ClassSummary = undefined;
    const adv_fwd = advise.advise(&fwd, &declared, demand, &.{}, 0, &buf1);
    const adv_rev = advise.advise(&rev, &declared, demand, &.{}, 0, &buf2);
    try std.testing.expectEqualStrings("acct-a", adv_fwd.suggestion.?.account);
    try std.testing.expectEqualStrings("acct-a", adv_rev.suggestion.?.account);
}
