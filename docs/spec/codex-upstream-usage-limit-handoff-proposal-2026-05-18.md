# Codex Upstream Usage-Limit Handoff Hook Proposal
Date: 2026-05-18
Status: upstream-facing proposal draft for #164 / TIN-939.

This document is a draft issue/proposal body for upstream Codex. It records why
oauth-mux can prove managed Codex quota handoff at the local proxy boundary, but
cannot honestly claim same-thread provider continuity or mid-turn streaming
recovery without an explicit Codex/provider handoff contract.

Source check: OpenAI Codex `main` at
`9531e932ef33b3834e5dc23fe71ae7ac84e6e213`, reviewed 2026-05-18.

## Current Upstream Shape

The current Codex sources distinguish usage limits from ordinary retryable
transport errors:

- `codex-api` maps HTTP `429` bodies with
  `error.type:"usage_limit_reached"` to `UsageLimitReachedError`, preserving
  plan, reset time, rate-limit headers, and promo message when present:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/codex-api/src/api_bridge.rs#L80-L99>.
- `CodexErr::is_retryable` treats `UsageLimitReached`, `UsageNotIncluded`,
  `QuotaExceeded`, and `RetryLimit` as non-retryable:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/protocol/src/error.rs#L169-L205>.
- The protocol-facing error class collapses usage-limit, quota, and
  usage-not-included failures into `usageLimitExceeded`:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/protocol/src/error.rs#L215-L241>.
- App-server `chatgptAuthTokens` mode is explicitly in-memory external auth;
  token refresh is host-owned:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/src/protocol/common.rs#L20-L33>.
- The only external auth refresh server request is
  `account/chatgptAuthTokens/refresh`:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/src/protocol/common.rs#L1346-L1349>.
- Its serialized reason is currently `unauthorized`, backed by the test shape:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/src/protocol/common.rs#L2145-L2164>.
- The generated app-server schema also defines
  `ChatgptAuthTokensRefreshReason` as unauthorized-only:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/schema/json/ServerRequest.json#L116-L132>.
- Rate-limit read/update surfaces exist and include limit id, reset windows,
  plan type, credits, and reached-type fields:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/schema/json/v2/GetAccountRateLimitsResponse.json#L42-L130>.
- Error notifications carry `willRetry`, but they do not carry an external
  account-switch request or an alternate credential slot:
  <https://github.com/openai/codex/blob/9531e932ef33b3834e5dc23fe71ae7ac84e6e213/codex-rs/app-server-protocol/schema/json/v2/ErrorNotification.json#L177-L198>.

oauth-mux currently handles managed Codex quota handoff by interposing a local
wire proxy before Codex receives the provider `429`. That is enough for the
managed `oauth-mux codex` proof bundles, but it is not an upstream-sanctioned
same-thread provider continuity contract.

## Problem Statement

External host apps can currently satisfy Codex's unauthorized-token recovery
flow by returning fresh `chatgptAuthTokens` for the same auth continuity class.
There is no equivalent app-server request for a usage-limit, subscription-quota,
or workspace-credit limit that asks the host whether a different external
account can continue the turn.

That leaves external brokers with two imperfect choices:

1. Intercept the provider wire before Codex handles the usage-limit response,
   which proves local managed behavior but depends on proxy topology.
2. Let Codex surface `usageLimitExceeded`, then continue in a later session or
   thread, which is honest but not same-turn or same-thread recovery.

oauth-mux should not market either choice as upstream-endorsed same-thread
quota handoff. A first-class Codex hook would make the boundary explicit.

## Requested Hook

Add one explicit usage-limit handoff surface for external-auth mode. The hook
should be secret-free and should not require Codex to understand oauth-mux route
policy.

Candidate server request:

```jsonc
{
  "method": "account/chatgptAuthTokens/usageLimitHandoff",
  "id": 42,
  "params": {
    "previousAccountId": "acct_or_workspace_hint",
    "limitId": "codex",
    "limitName": "Codex",
    "reason": "usage_limit_reached",
    "rateLimitReachedType": "workspace_member_usage_limit_reached",
    "planType": "pro",
    "resetsAt": 1778362800,
    "retryable": true,
    "turnId": "turn_hint_if_available",
    "threadId": "thread_hint_if_available"
  }
}
```

Candidate response:

```jsonc
{
  "type": "chatgptAuthTokens",
  "accessToken": "redacted-to-codex-protocol-only",
  "chatgptAccountId": "fallback_account_or_workspace_id",
  "chatgptPlanType": "pro",
  "continuation": {
    "mode": "retry_same_turn_without_prior_turn_state",
    "dropHeaders": ["x-codex-turn-state"]
  }
}
```

If Codex cannot safely retry the same turn, the response should allow Codex to
say so explicitly:

```jsonc
{
  "type": "unsupported",
  "recommendedAction": "start_new_thread",
  "reason": "same_thread_continuity_not_supported"
}
```

## Compatibility Options

One of these would satisfy oauth-mux's need:

1. **Usage-limit notification only.** Codex emits a structured
   `usageLimitReached` notification with limit id, reset time, plan, account
   hint, and retryability. Brokers use it for next-turn or next-session
   planning, but Codex does not retry in place.
2. **External account switch request.** Codex asks the external auth host for a
   replacement `chatgptAuthTokens` tuple when a usage-limit response is
   retryable. Codex owns the decision to retry the same request, start a new
   thread, or refuse.
3. **Rate-limit read semantics.** Codex exposes enough structured rate-limit
   state before a turn starts for external hosts to avoid selecting an exhausted
   account proactively. This reduces failure frequency but does not replace a
   failure-time hook.
4. **Thread continuation guidance.** Codex returns a machine-readable
   continuation recommendation when same-thread or same-turn recovery is not
   supported, so brokers can report the exact boundary instead of inferring it
   from a generic usage-limit error.

## oauth-mux Claim Boundary

Until upstream Codex exposes one of the compatible hooks above, oauth-mux claims
only what it has proven:

- Managed `oauth-mux codex` can classify provider-originated
  `usage_limit_reached`, record durable route-health evidence, and retry the
  buffered request on an eligible fallback account before Codex receives the
  `429`.
- Same-thread continuity across account boundaries is not proven.
- Mid-turn streaming recovery after partial response delivery is not proven.
- Unmanaged bare-Codex daemon hot-swap is not proven.
- Non-Codex harness stay-afloat behavior remains adapter-specific and unproven
  until each adapter has its own source-backed contract.

## Draft Upstream Issue Body

Title:

```text
Expose an external-auth usage-limit handoff hook for app-server hosts
```

Body:

```markdown
Codex app-server external auth currently has an unauthorized-token recovery
hook, `account/chatgptAuthTokens/refresh`, whose reason enum is
`unauthorized`. Usage-limit and quota responses are classified separately as
`usageLimitExceeded` / `UsageLimitReached` and are non-retryable at the Codex
error boundary.

That distinction is correct for a single account, but external-auth hosts that
own multiple user-authorized ChatGPT workspaces/accounts need a structured,
secret-free way to handle subscription usage limits:

- Codex should tell the host which account/workspace hint hit a limit.
- Codex should include limit id/name, reset time, plan type, and reached type
  when available.
- Codex should let the host either provide a replacement
  `chatgptAuthTokens` tuple or decline with a machine-readable recommended
  action.
- Codex should own whether same-turn retry, new-thread continuation, or a user
  visible failure is safe for the current thread/turn state.

This would avoid external hosts inferring continuation semantics from a generic
`usageLimitExceeded` error and would make the difference between token refresh,
usage-limit handoff, and unsupported same-thread continuation explicit.
```

