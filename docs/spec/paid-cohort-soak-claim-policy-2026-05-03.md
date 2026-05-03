# Paid Cohort Soak Claim Policy
Date: 2026-05-03

Tracking: Linear `TIN-895`, parent `TIN-892`; related to `TIN-893`, `TIN-894`,
`TIN-896`, `TIN-738`, `TIN-925`; GitHub `#67`, `#68`, `#131`, `#149`.

## Purpose

Paid provider evidence should raise public claims only when the exact provider,
account shape, capability, and mediation level have redacted artifacts. The
soak lane is not a production daemon launch and is not a universal provider
claim. It is the gate between dogfood observations and website/README wording.

Current Codex truth as of this spec:

- `max-1#codex-max` is selected after spend-gated exhausted-route
  revalidation.
- `max-4#codex-max` is a selectable spare fallback.
- `max-2#codex-max` and `max-3#codex-max` are provider quota-exhausted.
- Dashboard credit, Spark, or mini availability is not generalized to
  `codex-max`; route evidence remains capability-scoped.

## Soak Cadence

Run the soak as an explicit foreground lane for seven calendar days. Do not
schedule live provider spend by default.

Recommended daily no-spend snapshot for each paid cohort profile:

```bash
just paid-cohort-soak-snapshot
```

This writes redacted artifacts under `dist/soak/<timestamp>/<profile>/` using
the active operator config and state. Override with `OMUX_SOAK_PROFILE`,
`OMUX_SOAK_CAPABILITY`, `OMUX_SOAK_PROVIDER`, `OMUX_SOAK_OUT`,
`OMUX_SOAK_LOOP_ITERATIONS`, or `OMUX_SOAK_LOOP_INTERVAL_MS` when collecting a
different cohort lane.

Equivalent manual commands:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="dist/soak/$stamp/codex-max"
mkdir -p "$out"

./zig-out/bin/oauth-mux accounts list --provider codex --json >"$out/accounts.json"
./zig-out/bin/oauth-mux providers list --json >"$out/providers.json"
./zig-out/bin/oauth-mux route explain --profile codex-max --capability codex-max --json >"$out/route-explain.json"
./zig-out/bin/oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json >"$out/broker-session-plan.json"
./zig-out/bin/oauth-mux stay-afloat next --profile codex-max --capability codex-max --json >"$out/stay-afloat-next.json"
./zig-out/bin/oauth-mux stay-afloat --once --profile codex-max --capability codex-max --json >"$out/stay-afloat-once.json"
```

Recommended bounded foreground wrapper snapshot:

```bash
./zig-out/bin/oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 \
  --profile codex-max --capability codex-max --json >"$out/stay-afloat-loop.json"
```

Spend-gated revalidation or live QA is optional and operator-triggered only:

```bash
./zig-out/bin/oauth-mux codex revalidate-exhausted \
  --profile codex-max --capability codex-max --confirm-spend --json \
  >"$out/revalidate-exhausted.json"

OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROVIDER=codex \
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3,max-4 \
OMUX_LIVE_QA_CAPABILITIES=codex-mini,codex-max \
  just live-qa
```

Do not run spend-gated commands from unattended loops. If a route has no spare
fallback, record the `resilience_actions` and decide manually whether to
revalidate, enroll another account, or wait for reset.

The daily no-spend snapshot may also include confirmation-gate artifacts such
as `revalidate-exhausted.confirmation.json` or
`broker-run.confirmation.json`. Those files are expected to report
`confirmation_required:true`; they prove the operator gate is still closed and
are not evidence that provider calls ran.

## Artifact Rules

Artifacts may be local under `dist/soak/<timestamp>/...` or hosted workflow
artifacts. They must be redacted and must not contain:

- access tokens, refresh tokens, id tokens, raw JWTs, or Authorization headers;
- ChatGPT account IDs or provider account IDs;
- credential paths when a command intentionally redacts them;
- prompt text, assistant output, or raw app-server protocol transcripts;
- `.env` files or upstream provider credential stores.

Minimum complete Codex soak snapshot:

- `accounts.json`;
- `providers.json`;
- `route-explain.json`;
- `broker-session-plan.json`;
- `stay-afloat-next.json`;
- `stay-afloat-once.json`;
- `stay-afloat-loop.json` when wrapper behavior is part of the claim;
- `revalidate-exhausted.confirmation.json` and
  `broker-run.confirmation.json` when the snapshot needs to prove spend gates
  are closed;
- `revalidate-exhausted.json` only when the operator intentionally spent a
  route revalidation call.

## Pass Conditions

The paid cohort soak passes for a named capability only when:

- at least one route is selectable for the requested capability;
- unavailable routes have typed liveness such as `quota_exhausted`,
  `rate_limited`, `tier_insufficient`, `scope_insufficient`, `runtime_not_ready`,
  or auth-dead states instead of ambiguous failure;
- an unavailable account does not poison a separate available account for the
  same provider;
- `stay-afloat --once` remains planning-only unless `--execute` is explicitly
  used;
- browser/device login and provider-spend commands are never run silently;
- every public claim maps to the exact profile, capability, provider, and
  mediation level proven by artifacts.

For Codex `codex-max`, `spare_fallback_ready:true` is stronger than merely
`afloat:true`. If `single_route_at_risk:true`, the product may still claim a
selected route for next launch, but public copy must say the route has no spare
fallback until revalidation, enrollment, or reset.

## Claim States

Use these labels consistently in docs, website copy, and tracker comments:

- `needs_operator_proof`: modeled behavior or local code support exists, but no
  current redacted live/operator evidence is attached.
- `capability_live_proven`: one provider/account/capability lane has redacted
  live evidence. This does not promote the whole provider family.
- `paid_cohort_route_proven`: a named paid cohort route shape has enrollment,
  runtime readiness, typed liveness, and route-selection evidence.
- `foreground_stay_afloat_proven`: explicit user-run foreground stay-afloat
  snapshots show the selected route, fallback state, and typed actions over the
  soak window.
- `broker_owned_session_proven`: a mediated broker-owned session surface has
  redacted proof for the named provider and capability.
- `route_state_fallback_proven`: controlled or provider-recorded route state
  selects a distinct fallback route for the next mediated action.
- `provider_originated_fallback_proven`: a live provider quota/rate-limit event
  was observed during a broker-owned session, route health was persisted, and a
  later broker-owned session continued on the selected fallback route.
- `paid_cohort_proven`: the named cohort shape passed enrollment, liveness,
  route selection, and foreground stay-afloat gates without unresolved claim
  blockers.

## Public Copy Rules

Allowed now for Codex, with the current artifacts:

- "oauth-mux can select among account-scoped Codex routes using typed route
  health."
- "Broker-owned Codex sessions have live one-turn and bounded multi-turn proof."
- "Next-session continuation is the honest fallback boundary after quota or
  rate-limit evidence unless a same-thread hook is proven."
- "The current Codex Max cohort has `max-1` selected and `max-4` as spare
  fallback, while `max-2` and `max-3` are quota-exhausted for `codex-max`."

Not allowed without new evidence:

- "Universal OAuth muxing is proven."
- "The production background daemon keeps every provider afloat."
- "oauth-mux seamlessly hot-swaps unmanaged already-running Codex TUI sessions."
- "Codex same-thread quota recovery is proven."
- "Per-request muxing is supported."
- "Figma is proven" without qualifying OAuth, PAT, plan-token, and MCP
  resource-token proof separately.
- "Claude is proven" beyond the exact command/auth, subscription, and quota
  shapes with artifacts.
- "A provider-owned Codex usage-limit screen proves native account handoff."

## Promotion Checklist

Before README or `omux.xoxd.ai` copy expands:

1. Attach seven days of redacted foreground snapshots or explain why a shorter
   bounded dogfood window is the accepted gate for this release.
2. Attach any spend-gated live QA artifacts referenced by the claim.
3. Confirm provider dashboards and provider execution agree, or document the
   execution result as authoritative when they disagree.
4. Confirm `providers list --json` and `accounts list --json` proof statuses
   match the proposed copy.
5. Confirm no claim depends on an unmanaged current-process hot-swap.
6. Update Linear `TIN-895` and site-copy `TIN-925` / GitHub `#149` before
   publishing broader website copy.
