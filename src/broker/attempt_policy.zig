//! Provider-neutral upstream attempt-budget reducer for the v0.2 broker.
//!
//! This is the first bounded TIN-1790 sub-slice: one TOTAL pure reduction that
//! makes the v0.2 attempt budget mechanically unambiguous for every managed
//! adapter (Claude, Codex, OpenCode). It carries no credentials, account or
//! route handles, models, clocks, allocators, writers, locks, or network seams;
//! it observes only the shape of an upstream attempt outcome and decides whether
//! a single bounded follow-up is authorized.
//!
//! Budget constraints enforced here (pinned to the declaration-only contract by
//! the comptime drift controls below):
//! - at most two upstream attempts per request;
//! - the second attempt is EITHER one confirmed-not-sent same-route retry OR one
//!   cross-account alternate, never both;
//! - only a replayable, pre-body 401/403/429 from the initial authenticated
//!   upstream attempt can authorize the alternate;
//! - provider 5xx passes through so the harness owns its native retry;
//! - partial send, sent/ambiguous transport, cancellation, a downstream-started
//!   response, and every replay-budget overflow never retry across accounts;
//! - terminal states are absorbing.
//!
//! Local capability 401 responses are rejected before an authenticated upstream
//! attempt exists and therefore never enter this reducer. This reducer is
//! standalone and provider-neutral; it does not replace the Claude wire retry
//! machine.

const std = @import("std");

/// Imported ONLY for the comptime drift controls at the bottom of this file,
/// which pin the 2/1/1 attempt budget and the exact alternate-trigger set to
/// the declaration-only managed-harness contract.
const contract = @import("../managed_harness_contract.zig");

/// Why a request body cannot be held in memory for replay. Any block
/// irrevocably demotes replay to stream-once; a stream-once request can never
/// authorize a cross-account alternate or a same-route retry.
pub const ReplayBlock = enum {
    known_length_oversize,
    unknown_length_limit_crossing,
    sidecar_budget_unavailable,
    host_budget_unavailable,
    reservation_unavailable,
};

/// The replay state of the initial attempt. `eligible_reserved` holds a memory
/// reservation and permits exactly one bounded follow-up; `stream_once` holds
/// no reservation and permits none.
pub const Replay = union(enum) {
    eligible_reserved,
    stream_once: ReplayBlock,
};

/// The only upstream statuses that can consume the single cross-account
/// alternate slot. Exactly pre-body 401, 403, and 429.
pub const AlternateTrigger = enum {
    pre_body_401,
    pre_body_403,
    pre_body_429,

    /// The HTTP status this trigger corresponds to.
    pub fn httpStatus(self: AlternateTrigger) u16 {
        return switch (self) {
            .pre_body_401 => 401,
            .pre_body_403 => 403,
            .pre_body_429 => 429,
        };
    }
};

/// The reduction state of one request's attempt budget. `initial` carries its
/// replay state; `alternate` carries the trigger that authorized it. The two
/// in-flight follow-up states each hold the reservation retained by the
/// authorizing transition. `terminal` is absorbing and holds no reservation.
pub const State = union(enum) {
    initial: Replay,
    same_route_retry_in_flight,
    alternate_in_flight: AlternateTrigger,
    terminal,
};

/// Transport delivery classification of a completed send. Only
/// `confirmed_not_sent` proves no request byte reached the wire.
pub const SendState = enum {
    confirmed_not_sent,
    partially_sent,
    sent,
    ambiguous,
};

/// Whether an upstream response was fully buffered before any byte reached the
/// harness, or the harness stream had already started. A started response can
/// never be replaced by an alternate.
pub const Delivery = enum {
    buffered_before_downstream,
    downstream_started,
};

/// The observed result of one upstream attempt.
pub const Outcome = union(enum) {
    /// An upstream HTTP status arrived with a known delivery classification.
    upstream_status: struct {
        status: u16,
        delivery: Delivery,
    },
    /// The attempt failed at the transport layer with the given send state.
    transport_failure: SendState,
    /// The request was canceled.
    canceled,
};

/// What the reducer authorizes next for this request.
pub const Decision = union(enum) {
    retry_same_route,
    retry_alternate: AlternateTrigger,
    finish_original,
};

/// What must happen to any held replay reservation as a result of the
/// transition. `retain` keeps it for the authorized follow-up; `release` frees
/// a reservation that was held; `none` means no reservation was held.
pub const ReservationDisposition = enum {
    retain,
    release,
    none,
};

/// The full result of one reduction step.
pub const Transition = struct {
    next: State,
    decision: Decision,
    reservation: ReservationDisposition,
};

/// TOTAL provider-neutral attempt-budget reduction. Defined for every
/// (State, Outcome) pair with no panic on valid input; `terminal` and the two
/// in-flight follow-up states are absorbing.
pub fn reduce(state: State, outcome: Outcome) Transition {
    return switch (state) {
        .initial => |replay| reduceInitial(replay, outcome),
        // Every outcome from an in-flight follow-up is terminal: a later
        // 401/403/429 cannot alternate and a later confirmed-not-sent failure
        // cannot same-route retry. The reservation retained to authorize this
        // follow-up is now released.
        .same_route_retry_in_flight, .alternate_in_flight => .{
            .next = .terminal,
            .decision = .finish_original,
            .reservation = .release,
        },
        // Absorbing terminal no-op; no reservation is held.
        .terminal => .{
            .next = .terminal,
            .decision = .finish_original,
            .reservation = .none,
        },
    };
}

fn reduceInitial(replay: Replay, outcome: Outcome) Transition {
    return switch (outcome) {
        .upstream_status => |s| reduceInitialStatus(replay, s.status, s.delivery),
        .transport_failure => |send_state| switch (send_state) {
            // The sole same-route retry: only when no request byte was sent and
            // the body is still replay-eligible.
            .confirmed_not_sent => switch (replay) {
                .eligible_reserved => .{
                    .next = .same_route_retry_in_flight,
                    .decision = .retry_same_route,
                    .reservation = .retain,
                },
                .stream_once => finishOriginal(replay),
            },
            // Partial, sent, or ambiguous transport returns the original
            // failure without replay.
            .partially_sent, .sent, .ambiguous => finishOriginal(replay),
        },
        // Cancellation propagates and releases any held reservation.
        .canceled => finishOriginal(replay),
    };
}

fn reduceInitialStatus(replay: Replay, status: u16, delivery: Delivery) Transition {
    // A downstream-started response can never be replaced; a pre-body
    // 401/403/429 is the only path to the alternate, and only while replayable.
    if (delivery == .buffered_before_downstream) {
        if (alternateTriggerForStatus(status)) |trigger| {
            switch (replay) {
                .eligible_reserved => return .{
                    .next = .{ .alternate_in_flight = trigger },
                    .decision = .{ .retry_alternate = trigger },
                    .reservation = .retain,
                },
                // Stream-once 401/403/429: finish the original response.
                .stream_once => {},
            }
        }
    }
    // Provider 5xx, downstream-started responses, non-trigger statuses, and
    // stream-once trigger statuses all finish the original.
    return finishOriginal(replay);
}

fn alternateTriggerForStatus(status: u16) ?AlternateTrigger {
    return switch (status) {
        401 => .pre_body_401,
        403 => .pre_body_403,
        429 => .pre_body_429,
        else => null,
    };
}

/// Finish the original response and release any reservation the initial attempt
/// was holding. Stream-once initial attempts hold none.
fn finishOriginal(replay: Replay) Transition {
    return .{
        .next = .terminal,
        .decision = .finish_original,
        .reservation = switch (replay) {
            .eligible_reserved => .release,
            .stream_once => .none,
        },
    };
}

// ---------------------------------------------------------------------------
// Comptime drift controls (test 10). These pin the reducer to the immutable
// 2/1/1 budget and the exact alternate-trigger set. They fail the build, not a
// test, if the contract or this reducer drifts.
// ---------------------------------------------------------------------------
comptime {
    // The 2/1/1 attempt budget mirrors the declaration-only contract.
    if (contract.max_upstream_attempts != 2)
        @compileError("attempt budget drift: max_upstream_attempts must be 2");
    if (contract.max_cross_account_alternates != 1)
        @compileError("attempt budget drift: max_cross_account_alternates must be 1");
    if (contract.max_same_route_transport_retries != 1)
        @compileError("attempt budget drift: max_same_route_transport_retries must be 1");

    // The alternate trigger set is exactly {401, 403, 429}, in that order.
    const trigger_fields = @typeInfo(AlternateTrigger).@"enum".fields;
    if (trigger_fields.len != 1 + @as(usize, contract.max_upstream_attempts))
        @compileError("alternate trigger set must hold exactly three statuses");
    const expected_statuses = [_]u16{ 401, 403, 429 };
    if (trigger_fields.len != expected_statuses.len)
        @compileError("alternate trigger set size drift");
    for (std.enums.values(AlternateTrigger), expected_statuses) |trigger, want| {
        if (trigger.httpStatus() != want)
            @compileError("alternate trigger status drift");
    }
}

// ---------------------------------------------------------------------------
// Tests. Deterministic, in-file, exhaustive where the contract is finite.
// ---------------------------------------------------------------------------
const testing = std.testing;

/// Every ReplayBlock value, used to enumerate stream-once demotions.
const all_replay_blocks = std.enums.values(ReplayBlock);
/// Every SendState value.
const all_send_states = std.enums.values(SendState);
/// Every Delivery value.
const all_deliveries = std.enums.values(Delivery);
/// Every AlternateTrigger value.
const all_triggers = std.enums.values(AlternateTrigger);

/// Enumerate every distinct State value, including each replay-block demotion
/// and each alternate trigger, so state-space tests are genuinely exhaustive.
fn allStates(buf: []State) []State {
    var n: usize = 0;
    buf[n] = .{ .initial = .eligible_reserved };
    n += 1;
    for (all_replay_blocks) |block| {
        buf[n] = .{ .initial = .{ .stream_once = block } };
        n += 1;
    }
    buf[n] = .same_route_retry_in_flight;
    n += 1;
    for (all_triggers) |trigger| {
        buf[n] = .{ .alternate_in_flight = trigger };
        n += 1;
    }
    buf[n] = .terminal;
    n += 1;
    return buf[0..n];
}

fn stateIsInitialReserved(state: State) bool {
    return switch (state) {
        .initial => |replay| replay == .eligible_reserved,
        else => false,
    };
}

fn attemptCountForDecision(decision: Decision) u8 {
    return switch (decision) {
        .retry_same_route, .retry_alternate => 1,
        .finish_original => 0,
    };
}

test "1: alternate authorized iff initial, reserved, buffered, status exactly 401/403/429" {
    var status: u16 = 0;
    while (true) : (status += 1) {
        inline for (.{ Delivery.buffered_before_downstream, Delivery.downstream_started }) |delivery| {
            const outcome = Outcome{ .upstream_status = .{ .status = status, .delivery = delivery } };
            const t = reduce(.{ .initial = .eligible_reserved }, outcome);

            const authorized = switch (t.decision) {
                .retry_alternate => true,
                else => false,
            };
            const should_authorize = delivery == .buffered_before_downstream and
                (status == 401 or status == 403 or status == 429);
            try testing.expectEqual(should_authorize, authorized);

            if (authorized) {
                const trigger = t.decision.retry_alternate;
                try testing.expectEqual(status, trigger.httpStatus());
                try testing.expectEqual(State{ .alternate_in_flight = trigger }, t.next);
                try testing.expectEqual(ReservationDisposition.retain, t.reservation);
            } else {
                try testing.expectEqual(Decision.finish_original, t.decision);
                try testing.expectEqual(State.terminal, t.next);
            }
        }
        if (status == std.math.maxInt(u16)) break;
    }
}

test "2: every 5xx across every state and delivery passes through to the harness" {
    var buf: [16]State = undefined;
    const states = allStates(&buf);
    var status: u16 = 500;
    while (status <= 599) : (status += 1) {
        for (states) |state| {
            for (all_deliveries) |delivery| {
                const outcome = Outcome{ .upstream_status = .{ .status = status, .delivery = delivery } };
                const t = reduce(state, outcome);
                // 5xx never retries in any form; the harness owns native retry.
                try testing.expectEqual(Decision.finish_original, t.decision);
                try testing.expectEqual(State.terminal, t.next);
            }
        }
    }
}

test "3: cross-product of send state, replay block, state, and delivery holds all invariants" {
    var buf: [16]State = undefined;
    const states = allStates(&buf);

    // Genuine exhaustive enumeration: every State x every Outcome shape drawn
    // from every SendState, every ReplayBlock (via the state set), every
    // representative status, and every Delivery.
    const status_probes = [_]u16{ 0, 200, 401, 403, 404, 418, 429, 500, 503, std.math.maxInt(u16) };

    for (states) |state| {
        // upstream_status x status x delivery
        for (status_probes) |status| {
            for (all_deliveries) |delivery| {
                const t = reduce(state, .{ .upstream_status = .{ .status = status, .delivery = delivery } });
                try assertInvariants(state, t);
            }
        }
        // transport_failure x every send state
        for (all_send_states) |send_state| {
            const t = reduce(state, .{ .transport_failure = send_state });
            try assertInvariants(state, t);
        }
        // cancellation
        const tc = reduce(state, .canceled);
        try assertInvariants(state, tc);
    }
}

/// Structural invariants every transition must satisfy regardless of input.
fn assertInvariants(state: State, t: Transition) !void {
    switch (t.decision) {
        .retry_same_route => {
            // A same-route retry is authorized only from an initial reserved
            // state, retains the reservation, and moves to the in-flight state.
            try testing.expect(stateIsInitialReserved(state));
            try testing.expectEqual(ReservationDisposition.retain, t.reservation);
            try testing.expectEqual(State.same_route_retry_in_flight, t.next);
        },
        .retry_alternate => |trigger| {
            try testing.expect(stateIsInitialReserved(state));
            try testing.expectEqual(ReservationDisposition.retain, t.reservation);
            try testing.expectEqual(State{ .alternate_in_flight = trigger }, t.next);
        },
        .finish_original => {
            // Finishing is always terminal and never retains a reservation.
            try testing.expectEqual(State.terminal, t.next);
            try testing.expect(t.reservation != .retain);
        },
    }

    // Reservation accounting: only a retry retains; a finish from a
    // reservation-holding state releases; otherwise none.
    if (t.reservation == .retain) {
        try testing.expect(t.decision != .finish_original);
    }
    if (t.reservation == .release) {
        try testing.expect(t.decision == .finish_original);
        try testing.expect(stateHeldReservation(state));
    }
    if (t.reservation == .none) {
        try testing.expect(!stateHeldReservation(state));
    }
}

/// Whether the given input state was holding a replay reservation.
fn stateHeldReservation(state: State) bool {
    return switch (state) {
        .initial => |replay| replay == .eligible_reserved,
        .same_route_retry_in_flight, .alternate_in_flight => true,
        .terminal => false,
    };
}

test "4: only confirmed-not-sent transport failure authorizes a same-route retry" {
    for (all_send_states) |send_state| {
        const t = reduce(.{ .initial = .eligible_reserved }, .{ .transport_failure = send_state });
        const is_retry = switch (t.decision) {
            .retry_same_route => true,
            else => false,
        };
        try testing.expectEqual(send_state == .confirmed_not_sent, is_retry);
    }
    // Even confirmed-not-sent cannot retry when the body is stream-once.
    for (all_replay_blocks) |block| {
        const t = reduce(.{ .initial = .{ .stream_once = block } }, .{ .transport_failure = .confirmed_not_sent });
        try testing.expectEqual(Decision.finish_original, t.decision);
    }
}

test "5: started, partial, sent, ambiguous, cancellation, and every oversize/budget reason never retry" {
    // Downstream-started responses (every status) never retry.
    inline for (.{ @as(u16, 401), 403, 429, 200, 500 }) |status| {
        const t = reduce(.{ .initial = .eligible_reserved }, .{
            .upstream_status = .{ .status = status, .delivery = .downstream_started },
        });
        try testing.expectEqual(Decision.finish_original, t.decision);
    }
    // Partial, sent, ambiguous transport, and cancellation never retry.
    inline for (.{ SendState.partially_sent, SendState.sent, SendState.ambiguous }) |send_state| {
        const t = reduce(.{ .initial = .eligible_reserved }, .{ .transport_failure = send_state });
        try testing.expectEqual(Decision.finish_original, t.decision);
    }
    const tc = reduce(.{ .initial = .eligible_reserved }, .canceled);
    try testing.expectEqual(Decision.finish_original, tc.decision);

    // Every replay-block reason demotes to stream-once and blocks both retry
    // forms, even against an otherwise-authorizing outcome.
    for (all_replay_blocks) |block| {
        const state = State{ .initial = .{ .stream_once = block } };
        const t_alt = reduce(state, .{ .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream } });
        try testing.expectEqual(Decision.finish_original, t_alt.decision);
        const t_same = reduce(state, .{ .transport_failure = .confirmed_not_sent });
        try testing.expectEqual(Decision.finish_original, t_same.decision);
    }
}

test "6: negative sequence — same-route retry followed by 429 cannot alternate" {
    const first = reduce(.{ .initial = .eligible_reserved }, .{ .transport_failure = .confirmed_not_sent });
    try testing.expectEqual(Decision.retry_same_route, first.decision);
    try testing.expectEqual(State.same_route_retry_in_flight, first.next);

    // A pre-body 429 on the same-route retry must NOT authorize an alternate.
    const second = reduce(first.next, .{ .upstream_status = .{ .status = 429, .delivery = .buffered_before_downstream } });
    try testing.expectEqual(Decision.finish_original, second.decision);
    try testing.expectEqual(State.terminal, second.next);
    try testing.expectEqual(ReservationDisposition.release, second.reservation);
}

test "7: negative sequence — alternate followed by confirmed-not-sent cannot retry" {
    const first = reduce(.{ .initial = .eligible_reserved }, .{
        .upstream_status = .{ .status = 401, .delivery = .buffered_before_downstream },
    });
    try testing.expectEqual(Decision{ .retry_alternate = .pre_body_401 }, first.decision);
    try testing.expectEqual(State{ .alternate_in_flight = .pre_body_401 }, first.next);

    // A confirmed-not-sent failure on the alternate must NOT same-route retry.
    const second = reduce(first.next, .{ .transport_failure = .confirmed_not_sent });
    try testing.expectEqual(Decision.finish_original, second.decision);
    try testing.expectEqual(State.terminal, second.next);
    try testing.expectEqual(ReservationDisposition.release, second.reservation);
}

test "8: every retry retains a reservation; every terminal path releases it or has none" {
    var buf: [16]State = undefined;
    const states = allStates(&buf);
    const status_probes = [_]u16{ 0, 401, 403, 429, 500, std.math.maxInt(u16) };

    for (states) |state| {
        for (status_probes) |status| {
            for (all_deliveries) |delivery| {
                try assertReservationLaw(state, reduce(state, .{ .upstream_status = .{ .status = status, .delivery = delivery } }));
            }
        }
        for (all_send_states) |send_state| {
            try assertReservationLaw(state, reduce(state, .{ .transport_failure = send_state }));
        }
        try assertReservationLaw(state, reduce(state, .canceled));
    }
}

fn assertReservationLaw(state: State, t: Transition) !void {
    switch (t.decision) {
        .retry_same_route, .retry_alternate => try testing.expectEqual(ReservationDisposition.retain, t.reservation),
        .finish_original => {
            // A finish never retains; it releases exactly when the input state
            // held a reservation, otherwise none.
            try testing.expect(t.reservation != .retain);
            const expected: ReservationDisposition = if (stateHeldReservation(state)) .release else .none;
            try testing.expectEqual(expected, t.reservation);
        },
    }
}

test "9: no transition sequence exceeds two attempts or consumes both retry forms" {
    // Attempt 1 is the initial in-flight attempt. Walk every first outcome from
    // the initial reserved state, then every second outcome from wherever it
    // lands, and prove total attempts <= 2 and never both retry forms.
    const status_probes = [_]u16{ 0, 200, 401, 403, 404, 429, 500, std.math.maxInt(u16) };

    for (firstOutcomes(&status_probes)) |first_outcome| {
        const first = reduce(.{ .initial = .eligible_reserved }, first_outcome);
        var attempts: u8 = 1 + attemptCountForDecision(first.decision);
        var used_same_route = first.decision == .retry_same_route;
        var used_alternate = switch (first.decision) {
            .retry_alternate => true,
            else => false,
        };

        // Second step from the resulting state (in-flight or terminal).
        for (firstOutcomes(&status_probes)) |second_outcome| {
            const second = reduce(first.next, second_outcome);
            const total = attempts + attemptCountForDecision(second.decision);
            try testing.expect(total <= 2);
            // A follow-up state never authorizes any further retry.
            if (first.decision != .finish_original) {
                try testing.expectEqual(Decision.finish_original, second.decision);
            }
        }
        _ = &attempts;
        // Never both forms in the single authorized follow-up.
        try testing.expect(!(used_same_route and used_alternate));
        _ = &used_same_route;
        _ = &used_alternate;
    }
}

/// Build a fixed set of representative outcomes covering every union arm.
fn firstOutcomes(status_probes: []const u16) []const Outcome {
    // A static upper bound: statuses x deliveries + send states + cancel.
    const S = struct {
        var buf: [64]Outcome = undefined;
    };
    var n: usize = 0;
    for (status_probes) |status| {
        for (all_deliveries) |delivery| {
            S.buf[n] = .{ .upstream_status = .{ .status = status, .delivery = delivery } };
            n += 1;
        }
    }
    for (all_send_states) |send_state| {
        S.buf[n] = .{ .transport_failure = send_state };
        n += 1;
    }
    S.buf[n] = .canceled;
    n += 1;
    return S.buf[0..n];
}

test "totality: reduce is defined for every state and outcome shape without panic" {
    var buf: [16]State = undefined;
    const states = allStates(&buf);
    for (states) |state| {
        var status: u16 = 0;
        while (true) : (status += 1) {
            for (all_deliveries) |delivery| {
                _ = reduce(state, .{ .upstream_status = .{ .status = status, .delivery = delivery } });
            }
            if (status == std.math.maxInt(u16)) break;
        }
        for (all_send_states) |send_state| {
            _ = reduce(state, .{ .transport_failure = send_state });
        }
        _ = reduce(state, .canceled);
    }
}
