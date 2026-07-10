# Claude quota-observation evidence (TIN-2722, the TIN-2400 P1 gate)

This directory is the committed, redacted evidence the model-quota-granularity
design of record (`docs/spec/model-quota-granularity-2026-07-03.md` §5) requires
before **any** model-quota claim. Captured live on the neo dogfood fleet
2026-07-09 (operator present, `OMUX_E2_OPERATOR_ACK=yes`) via
`scripts/capture-claude-quota-headers.sh`; runbook
`docs/runbooks/claude-quota-header-capture-2026-07-10.md`.

Accounts appear only as `sha256_12hex` directory names (all 5 enrolled Claude
accounts: xoxd, sulliwood, columbari, coye, lmux — `personal`/canonical
excluded). Header names and numeric/timestamp values are verbatim; request-ids,
`anthropic-organization-id`, and `cf-ray` are hashed (correlation preserved:
same org → same hash across files); authorization is never present.

## Spend ledger

Direct `POST https://api.anthropic.com/v1/messages`, `anthropic-version:
2023-06-01`, `anthropic-beta: oauth-2025-04-20`, OAuth subscription access token
(the `oat01` access-token class, ~5.6h fresh) read per-account from the suffixed
keychain service. Total spend: **5 × haiku 200 ≈ 130 output tokens** (26 each); every
other request was a 4xx and spent nothing. See `SPEND-LEDGER.txt`.

## The findings

### 1. The real rate-limit header family — corrects the repo placeholders

On a **200** response the server returns twelve `anthropic-ratelimit-unified-*`
headers. This is the ground truth that replaces the repo's placeholder
`x-ratelimit-*` (`provider_schema.zig` `claude_def.rate_limits`, ~:805-808) AND
the family name previously *assumed* in the design note (`anthropic-ratelimit-*`
without `-unified-`). Observed on every haiku 200:

| Header | Example value | Meaning |
|---|---|---|
| `anthropic-ratelimit-unified-status` | `allowed` | overall gate |
| `anthropic-ratelimit-unified-5h-status` | `allowed` | 5-hour rolling window |
| `anthropic-ratelimit-unified-5h-reset` | `1783652400` | absolute epoch (seconds) reset |
| `anthropic-ratelimit-unified-5h-utilization` | `0.0` | fraction of the 5h window used |
| `anthropic-ratelimit-unified-7d-status` | `allowed` | **7-day (weekly) window** |
| `anthropic-ratelimit-unified-7d-reset` | `1783958400` | absolute epoch (seconds) reset |
| `anthropic-ratelimit-unified-7d-utilization` | `0.0` | fraction of the 7d window used |
| `anthropic-ratelimit-unified-representative-claim` | `five_hour` | which window is binding |
| `anthropic-ratelimit-unified-fallback-percentage` | `0.5` | — |
| `anthropic-ratelimit-unified-reset` | `1783652400` | representative reset |
| `anthropic-ratelimit-unified-overage-disabled-reason` | `out_of_credits` | why overage is off |
| `anthropic-ratelimit-unified-overage-status` | `rejected` | overage gate |

Consequences for the design of record:

- The signal is **account-unified, NOT per-model.** There is no `#opus`/`#fable`
  dimension in the header names; the 5h + 7d windows are account-wide. This
  confirms the DOR §1 "category error" point structurally: quota windows are
  per-account, and model *routing* readiness is "which account has 5h/7d
  headroom," never a per-model credential or per-model header bucket.
- The window model is **richer than assumed**: two independent windows (5h
  rolling + 7d), each with `status`, absolute `reset` (epoch seconds), and a
  `utilization` fraction (real headroom, `0.0`–`1.0`) — a *proven* headroom
  signal, not the `usage_pct`-only guess. `deriveResetsAt` should prefer the
  provider-absolute `*-reset` (clock-skew-safe), exactly as the DOR specifies.

### 2. The headers ride 200s, not errors — and the 429 body is opaque

A **429** `rate_limit_error` carries **no** `anthropic-ratelimit-*` headers, no
`retry-after`; only `x-should-retry: true` and an opaque body
`{"error":{"message":"Error","type":"rate_limit_error"}}`. A **404** cleanly
distinguishes model-not-found (`not_found_error`, body names the model) from the
429 quota path — so the classifier can tell "class unavailable" from "quota
gated" by status alone. The DOR's assumption that quota could be read passively
off error responses is **false for the 429 path**; the usable signal is on the
200.

### 3. CRITICAL caveat — the fable/opus 429 is a probe-path artifact, NOT harness quota

Uniformly across all 5 accounts: **haiku → 200** (utilization `0.0`, i.e. window
headroom), **fable + opus → 429**. This does **not** mean the accounts cannot
serve Fable/Opus: this very capture session was a live Claude Code **Fable**
session running on one of these same accounts. The direct raw-API OAuth path is
gated differently from the Claude Code client path — the most likely correlate
is `overage-status: rejected` / `overage-disabled-reason: out_of_credits` on
accounts sitting at `0.0` window utilization (fable/opus appear to require
overage/credits on this path that haiku does not).

Load-bearing conclusion for the ladder: **a synthetic direct probe is not the
operator's own harness traffic and cannot observe fable/opus quota state.** The
real fable/opus signal must come from the Claude Code client's own traffic (needs
the managed wire that does not exist) or the browser usage panel (TIN-2720). E2
proves the header schema exists and is capturable; it does **not** license a
fable/opus model-quota claim from this channel.

## What this evidence licenses (and does not)

- **Licenses:** correcting `claude_def` header names to the
  `anthropic-ratelimit-unified-*` family; declaring the two-window (5h/7d)
  shape with absolute-reset + utilization; a classifier that reads these off
  **200** responses at `confidence=proven`; a 404-vs-429 status distinction.
- **Does NOT license:** any per-model quota claim from direct probing; any
  fable/opus availability inference from this channel; treating the 429 as
  window exhaustion (it co-occurs with `0.0` utilization). Advisor rendering for
  fable/opus stays `unobserved` until the harness-traffic or browser channel
  lands. **Credential keepalive ≠ model-quota keepalive** is unchanged.

## Follow-ups teed up

- `provider_schema.zig`: replace `x-ratelimit-*` with the unified family; declare
  opus/fable/sonnet/haiku CapabilityDefinitions (aliases = the real model ids
  used here: `claude-fable-5`, `claude-opus-4-8`, `claude-haiku-4-5-20251001`);
  parse `*-5h-*`/`*-7d-*` on 200s. Fixture-literal `classifyHttp` tests.
- The unified headers have no model dimension → the bucket key's `#capability`
  axis is fed by the **request** model, not the response headers; the harness
  traffic or browser channel (TIN-2720) remains the only per-model source.
