# Paid Multi-Account Proof Cohort
Date: 2026-05-01

Issue context: Linear `TIN-892`, with children `TIN-893`, `TIN-894`,
`TIN-895`, and `TIN-896`; parent `TIN-736`; related to stay-afloat `TIN-738`.
GitHub `Jesssullivan/oauth-mux#68` and `#67`.

## Baseline

The current product can prove Codex fallback with three configured accounts and
can prove several non-Codex identity capabilities. That is not the same as
being ready to tell users that oauth-mux handles their real multi-account
subscription reality.

The next proof lane should intentionally buy or allocate a one-month cohort of
common paid account shapes, then run the same boring user story across each
provider:

1. enroll account without stealing upstream credential ownership;
2. list accounts and proof requirements without leaking secrets;
3. prove runtime readiness;
4. prove liveness with typed outcomes;
5. select a fallback route;
6. keep work afloat through the foreground stay-afloat contract;
7. record artifacts and update claims only for the exact shape proven.

This lane is about evidence, not broad claims. A paid account only earns a
public claim after the probe, route, repair, and stay-afloat surfaces agree.
The current route-state, handoff, reauth, resume, cassette, and account-label
vocabulary is centralized in `docs/qa-handoff-matrix.md`; keep new cohort
claims aligned with that matrix instead of duplicating a second state taxonomy
here.

## Current Source Facts

These are time-sensitive and should be rechecked before purchasing.

- OpenAI's current Codex pricing page says Codex is included in ChatGPT Free,
  Go, Plus, Pro, Business, Edu, and Enterprise. It lists Plus at $20/month and
  Pro from $100/month, with Pro offering higher Codex usage than Plus.
- OpenAI's Codex CLI docs say first run prompts the user to authenticate with a
  ChatGPT account or API key, and that the CLI runs on macOS, Windows, and
  Linux.
- Anthropic's pricing page lists Claude Pro at $20 monthly, Max from $100
  monthly, Team standard and premium seats, and Enterprise. It also says Pro
  includes Claude Code; the Claude Code costs page says Pro and Max subscribers
  see plan usage bars rather than API session dollar cost as billing truth.
- Anthropic's enterprise pricing page says Claude Code can be used with a
  Claude subscription or billed through an Anthropic Console account.
- Figma's pricing page lists Professional Full, Dev, and Collab seats and says
  Dev Mode and MCP support are plan/seat features.
- Figma's REST auth docs separate OAuth apps, plan access tokens, and personal
  access tokens. Plan access tokens are available for Organization and
  Enterprise plans and are not tied to a user.
- Figma's REST rate-limit docs say limits depend on seat type, endpoint tier,
  and the plan/location of the requested resource. They also say OAuth limits
  are per user, per plan, per app; plan-token limits are per token and plan;
  PAT limits are per user and plan.

Primary sources:

- https://developers.openai.com/codex/pricing
- https://developers.openai.com/codex/cli
- https://claude.com/pricing
- https://code.claude.com/docs/en/costs
- https://claude.com/pricing/enterprise
- https://www.figma.com/pricing/
- https://developers.figma.com/docs/rest-api/authentication/
- https://developers.figma.com/docs/rest-api/rate-limits/
- https://developers.figma.com/docs/rest-api/plan-access-tokens/

## Cohort Shape

### Codex: `TIN-893`

Use the current four Max-capable account-scoped routes as the high-usage
cohort. Keep one lower-tier OAuth account as a separate proof target for tier
and usage contrast.

Historical dogfood truth as of 2026-05-03:

- `max-1#codex-max` revalidated from provider evidence and is selectable.
- `max-4#codex-max` is selectable fallback.
- `max-2#codex-max` and `max-3#codex-max` still return provider quota
  exhaustion.
- No logout or reauth was required when capacity changed; spend-gated
  `codex revalidate-exhausted` refreshed route health from provider evidence.
- Separate from route-health revalidation, a provider-owned live Codex session
  that hit `You've hit your usage limit` on 2026-05-03 did not perform a
  native account handoff. Manual logout/login restored future mediated launch
  readiness; it did not prove in-session fallback.
- Dashboard credit/Spark availability must not be generalized to
  `codex-max`; route health remains capability-scoped.

Current dogfood truth after the 2026-05-09 engineered managed handoff:

- Installed `oauth-mux codex resume <session-id>` has live proof for managed
  Codex quota handoff: a selected route returned provider-originated
  `usage_limit_reached`, oauth-mux recorded durable quota evidence, retried the
  buffered request on a distinct fallback route before Codex saw the 429, and
  the fallback route returned `status:200`.
- The strongest preserved proof bundle is
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Current no-spend route truth for `codex-max` is intentionally not described
  as afloat: `max-1`, `max-2`, and `max-4` are quota-exhausted; `max-3` is
  runtime-ready but recorded `auth_permanently_failed`; there are currently no
  selectable fallback routes until labeled reauth, reset repair, revalidation,
  or another credited account restores capacity.
- Same-thread continuity across account boundaries, mid-turn streaming
  recovery, unmanaged bare-`codex` daemon handoff, reset-window repair, and
  broader auth/quota/tier negative permutations remain separate proof lanes.

Suggested labels:

| Label | Intended shape | Proof value |
| --- | --- | --- |
| `codex-max-1` | Max-capable account | Quota/reset-window repair and priority-order regression. |
| `codex-max-2` | Max-capable account | Low-weekly primary route used for engineered handoff proof; later reset repair. |
| `codex-max-3` | Max-capable account | High-capacity fallback route used for engineered handoff proof; labeled reauth regression when stale. |
| `codex-max-4` | Max-capable account | Quota/reset-window repair and all-fallbacks-unavailable regression. |
| `codex-plus-1` | New lower-tier ChatGPT OAuth account | Tier/usage contrast against Max; proves lower-tier accounts do not poison Max route health. |

Do not model the lower-tier account as a broken Max account. Expected outcomes
may include `tier_insufficient`, `quota_exhausted`, or `rate_limited` for some
capabilities and `available` for others.
Do not record raw email identity, account id, credential paths, or session ids
in this spec or public tracker comments; route labels and capacity-role labels
are the public vocabulary.

Required proof:

```bash
oauth-mux accounts list --provider codex --json
oauth-mux enroll plan codex --account codex-plus-1 --json
oauth-mux enroll codex --account codex-plus-1 --confirm-enroll --json
# user-mediated handoff from enroll output
oauth-mux doctor runtime --provider codex --account codex-plus-1 --capability codex-mini --json
oauth-mux stay-afloat refresh --profile codex-mini --capability codex-mini --json
oauth-mux route explain --profile codex-mini --capability codex-mini --json
oauth-mux stay-afloat --once --profile codex-mini --capability codex-mini --json
```

Spendful proof remains behind explicit confirmation:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROVIDER=codex \
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3,max-4,codex-plus-1 \
OMUX_LIVE_QA_CAPABILITIES=codex-mini,codex-max \
  just live-qa
```

### Claude Code: `TIN-894`

Use three account or billing shapes only if they produce different product
evidence. A good one-month target is:

| Label | Intended shape | Proof value |
| --- | --- | --- |
| `claude-pro-1` | Pro subscription | Common individual user with Claude Code included. |
| `claude-max-1` | Max 5x or 20x | Higher usage route and priority behavior. |
| `claude-team-or-api-1` | Team seat or Console/API-billed Claude Code | Admin/billing boundary distinct from personal subscription. |

If Team minimums or account policy make the third shape too expensive or noisy,
use API-billed Console auth for the third proof and record that Team remains
unproven.

Required proof:

```bash
oauth-mux accounts list --provider claude --json
oauth-mux enroll plan claude --account claude-pro-1 --json
oauth-mux enroll claude --account claude-pro-1 --confirm-enroll --json
# user-mediated: env CLAUDE_CONFIG_DIR=<account-dir> claude auth login
oauth-mux doctor runtime --provider claude --account claude-pro-1 --capability auth-status --json
oauth-mux probe --provider claude --account claude-pro-1 --capability auth-status --json
oauth-mux stay-afloat --once --profile claude --capability auth-status --json
```

The first Claude cohort gate is account-store isolation and `auth-status`.
Usage/quota proof should come after fixtures cover logged-out, missing CLI,
keychain/store boundary, quota/usage limited, and provider degraded states.

### Figma: `TIN-896`

Figma needs token and resource diversity more than three identical users.

Suggested one-month target:

| Label | Intended shape | Proof value |
| --- | --- | --- |
| `figma-full-1` | Professional Full seat with PAT and OAuth | Common designer/admin route; proves OAuth `identity` and PAT `identity-pat` separately. |
| `figma-dev-1` | Professional Dev seat | Common engineering/Dev Mode/MCP route. |
| `figma-plan-1` | Organization or Enterprise plan access token | User-independent automation and file metadata proof. |

If an Organization/Enterprise plan is not worth the month of spend, keep
`figma-plan-1` as explicitly unproven and do not promote
`file-metadata-plan`.

Required proof:

```bash
oauth-mux accounts list --provider figma --json
oauth-mux enroll plan figma --account figma-full-1 --mode oauth --json
oauth-mux enroll figma --account figma-full-1 --mode oauth --secret-env OMUX_FIGMA_FULL_OAUTH --confirm-enroll --json
oauth-mux probe --provider figma --account figma-full-1 --capability identity --json

oauth-mux enroll plan figma --account figma-dev-1 --mode pat --json
oauth-mux enroll figma --account figma-dev-1 --mode pat --secret-env OMUX_FIGMA_DEV_PAT --confirm-enroll --json
oauth-mux probe --provider figma-pat --account figma-dev-1 --capability identity-pat --json

oauth-mux enroll plan figma --account figma-plan-1 --mode plan --json
oauth-mux enroll figma --account figma-plan-1 --mode plan --secret-env OMUX_FIGMA_PLAN_TOKEN --confirm-enroll --json
OMUX_FIGMA_PLAN_FILE_KEY=<file-key> \
  oauth-mux probe --provider figma-plan --account figma-plan-1 --capability file-metadata-plan --json
```

The Figma proof must intentionally keep these states distinct:

- OAuth bearer identity;
- PAT identity;
- plan-token file metadata;
- Figma remote MCP bearer-resource token;
- insufficient scope;
- file/resource not permitted;
- rate limit with retry/upgrade hints.

## Stay-Afloat Soak Gate: `TIN-895`

The paid cohort should not promote the background daemon by accident. The
portable product contract remains foreground and wrapper-friendly:
`docs/spec/paid-cohort-soak-claim-policy-2026-05-03.md` is the detailed
operator policy for cadence, artifact names, claim states, and promotion
blockers.

```bash
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux route select --profile <profile> --capability <capability> --json
oauth-mux repair-plan --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat refresh --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile <profile> --capability <capability> --json
```

Seven-day soak criteria:

- no silent provider-spend probes;
- no silent browser/device login;
- no mutation outside oauth-mux-owned config/store scaffolding;
- no platform-specific dependency such as `systemctl`;
- route-state refresh stays explicit and redacted;
- at least one planned unavailable account does not poison a separate
  available account for the same provider;
- every unavailable state has a typed action or handoff.

Evidence should be recorded as:

- hosted workflow artifact ID or local `dist/live-qa/<timestamp>`;
- redacted command transcript;
- `accounts list --json`;
- `providers list --json`;
- `route explain --json`;
- `stay-afloat --once --json`;
- provider-specific live probe output.

## Claim Policy

Allowed after this lane:

- `capability_live_proven`: a specific provider/account capability has redacted
  live proof.
- `paid_cohort_proven`: the named cohort shape passed enrollment, routing, and
  stay-afloat gates.
- `foreground_stay_afloat_proven`: explicit user-run stay-afloat kept a route
  selectable or returned the right handoff.

Not allowed yet:

- "Universal OAuth muxing is proven."
- "Production background daemon keeps every provider afloat."
- "Figma is proven" unless OAuth, PAT, plan-token, and MCP resource-token
  claims are separately qualified.
- "Claude is proven" beyond the specific subscription/auth-status/quota shapes
  that have artifacts.

## Immediate Work

1. Land the proof-requirements JSON surface so agents can discover the missing
   values without reading this spec.
2. Enroll the lower-tier Codex account and run no-spend inventory/runtime
   checks before live probes.
3. Decide the Claude third shape: Team seat, Enterprise/self-serve path, or
   API-billed Console auth.
4. Decide whether Figma Organization/Enterprise spend is worth plan-token
   proof this month.
5. Run the seven-day foreground stay-afloat soak after all paid accounts are
   enrolled and one live proof pass has succeeded.
