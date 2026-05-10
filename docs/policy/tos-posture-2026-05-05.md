# OpenAI/Codex Terms Posture
Date: 2026-05-05
Status: operator posture; not legal advice; not a product claim.

Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md`.
Codex adapter contract: `docs/spec/codex-adapter-contract-2026-05-03.md`.

This document exists to keep the Codex adapter honest before any public
promotion. It describes the policy boundary the repo must respect while
building account muxing. It does not decide whether any operator's use is
permitted; the operator must read current provider terms and make that
decision.

## Current Official Sources Checked

Checked on 2026-05-05:

- OpenAI Terms & Policies index:
  https://openai.com/policies/
- OpenAI Terms of Use, effective 2026-01-01:
  https://openai.com/policies/terms-of-use/
- OpenAI Account Sharing Policy, updated 2026-04-23:
  https://help.openai.com/en/articles/10471989-openai-account-sharing-policy
- Using Codex with your ChatGPT plan, updated 2026-05-04:
  https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan
- Codex CLI docs:
  https://developers.openai.com/codex/cli

Facts from those sources that matter for this repo:

- OpenAI's terms say users may not share account credentials or make an
  account available to someone else, and may not interfere with or
  disrupt OpenAI services, including circumventing rate limits,
  restrictions, protective measures, or safety mitigations.
- OpenAI's account-sharing policy says an account is meant for the
  individual who created it; account sharing is not allowed; usage
  limits may apply based on activity and subscription level.
- Codex is included with specified ChatGPT plans, and Codex usage limits
  depend on plan and task shape.
- Codex with a ChatGPT account is governed by ChatGPT Terms of Use and
  Privacy Policy, or the applicable business/enterprise agreement.
- Codex CLI is an OpenAI local terminal agent that prompts the user to
  authenticate with a ChatGPT account or API key.

## Repo Posture

oauth-mux must not market, document, or implement Codex account muxing as
"unlimited Codex", rate-limit bypass, anti-detection, resale, or shared
credential pooling. Those framings are wrong for the product and risky
against the official terms above.

The only acceptable repo framing is narrower:

- The operator enrolls accounts they are authorized to use.
- Account material stays local to the operator-controlled machine.
- The tool exposes which route is selected through redacted evidence.
- Provider quota, tier, auth, and policy failures remain typed states.
- Provider-originated restrictions are observed and classified; they are
  not hidden as success.
- Public docs must say that account muxing is policy-sensitive and that
  operators must evaluate provider terms for their own use.

## Hard Product Guardrails

The Codex adapter and public-facing docs MUST NOT:

- Encourage credential sharing across humans.
- Offer any API-key-reseller, hosted proxy, team credential pool, or
  third-party access service.
- Claim unlimited usage or avoidance of OpenAI limits.
- Forge browser-only headers, defeat Cloudflare or other protective
  systems, or implement anti-detection behavior.
- Silently spend provider calls without explicit operator confirmation
  on live/spend paths.
- Print tokens, account IDs, raw JWTs, credential paths, raw protocol, or
  prompt/assistant transcript text in normal evidence output.
- Promote `prepared_fallback`, restart, supervised relaunch, or synthetic
  smokes as the product success metric.

The Codex adapter SHOULD:

- Provide an explicit account-pin mode that disables rotation for
  operators who want single-account behavior.
- Keep live provider probes and captures behind explicit confirmation.
- Preserve redacted event artifacts for live acceptance and operator
  review.
- Keep terms-sensitive wording out of marketing and first-run copy until
  Level 3 acceptance is real and the posture has been re-reviewed.
- Re-check official terms before any public release, package promotion,
  or hosted service discussion.

## Technical Boundary

The current product bar is still technical, not legal:

> `oauth-mux codex` runs a real Codex session. The selected account hits
> provider-originated quota exhaustion. Another credited, operator-enrolled
> account continues in place without restart or prompt.

That managed Codex bar is now live-proven for installed
`oauth-mux codex resume` artifacts, including an engineered 2026-05-09 run
where a route returned successful turns before provider-originated
`usage_limit_reached`, oauth-mux retried the same buffered request on a
credited route, and the fallback returned 200. Synthetic smokes, route
readiness, `prepared_fallback`, restart diagnostics, unmanaged bare-`codex`
daemon handoff, and non-Codex harnesses remain separate partial or unproven
claims.

## Operator Decision Points

Before using Codex account muxing outside local development, an operator
must decide:

1. Whether every enrolled account is theirs or otherwise authorized for
   their individual use.
2. Whether rotating among authorized accounts is consistent with their
   reading of OpenAI's current terms, account-sharing policy, and plan
   limits.
3. Whether their organization has business, enterprise, workspace, or
   compliance terms that differ from individual ChatGPT Terms of Use.
4. Whether they want account rotation at all; if not, they should pin a
   single account and treat oauth-mux as route-state and evidence tooling.

## Review Triggers

Update this document before:

- Public README or website copy is restored.
- npm/Homebrew/package promotion.
- Any first-run banner mentions account muxing.
- A second harness adapter is promoted.
- OpenAI changes Terms of Use, account-sharing policy, Codex plan limits,
  Codex auth, or Codex local usage docs.

If future provider terms explicitly disallow this workflow, the repo
posture must change. The implementation may remain useful as diagnostic
or single-account tooling, but public account-rotation claims must be
removed.
