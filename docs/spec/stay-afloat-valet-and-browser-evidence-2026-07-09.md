# Stay-Afloat Valet and Browser Evidence Lane

> **SUPERSEDED 2026-07-11; DO NOT EXECUTE.** This file is historical input,
> not active design authority. Binding invariants moved to
> `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` and
> `docs/security/omux-v0.2-threat-model-2026-07-11.md`. It is pending deletion
> under the v0.2 deletion ledger; Git is the archive. Preserve cited immutable
> evidence and shipped release history.
Date: 2026-07-09
Status: DESIGN NOTE. Traceable, not yet implemented.
Trackers: Linear TIN-2057, TIN-2400, TIN-2071, TIN-2077, TIN-2719,
TIN-2720.

This note reframes the next oauth-mux push around the user's actual path of
least resistance for Claude Code and similar singleton-auth harnesses.

It does not replace the broker product anchor in
`docs/spec/broker-mcp-contract-2026-05-03.md`. The final product is still:

> The user runs `oauth-mux <harness>`. The active account exhausts quota. Another
> credited account is substituted in place. The harness process is not restarted.
> The user is not prompted.

This note defines the smaller, high-leverage MVP that can sit between shipped
credential keepalive and the full broker adapter: a singleton-aware
stay-afloat valet that recommends and safely executes account switches before
running work halts.

## User Workflow Being Replaced

Today, a developer with multiple Claude accounts normally already has those
accounts signed into Chrome through Google/OAuth sessions. When a long-running
Claude Code workflow approaches a 5-hour cycle, weekly cap, usage-credit cap,
Fable cap, Opus cap, or team-plan boundary, the developer must:

1. Notice the active account is close to a limit.
2. Remember which accounts have the required model or plan parity.
3. Open browser usage/settings surfaces for several signed-in accounts.
4. Determine which account still has suitable quota for the current work.
5. Switch the upstream auth singleton, usually through `/login` or a browser
   OAuth handoff, before the active agents halt.
6. Hope existing subagents and sessions pick up the new singleton without losing
   work.

That workflow is not impossible, but it is attention-intensive. oauth-mux should
replace that babysitting with a small number of trusted decisions:

```text
oauth-mux stay-afloat status
oauth-mux stay-afloat recommend --models fable,opus --horizon 2h
oauth-mux stay-afloat switch <account> --confirm
```

Names above are illustrative. The product shape is the important part:
inventory, evidence, recommendation, guarded handoff.

## Three Account-Juggling Strategies

The work has diverged into several useful strategies. They should remain
separate in code, docs, tests, and claims.

### 1. Sandbox Per Harness

Run each account in an isolated harness home/config directory:

- Codex: per-account `CODEX_HOME` and route-local session authority.
- Claude: per-account `CLAUDE_CONFIG_DIR` with derived keychain services.

This enables:

- multiple live accounts concurrently;
- credential keepalive per account;
- spread of work across independently authenticated harness instances;
- strong evidence that one account's login or refresh does not clobber another.

This is the right substrate for parallel work and for proving isolation. It does
not automatically solve the common user problem where existing Claude Code
sessions are governed by a single upstream auth singleton.

### 2. Singleton Valet

Many real harnesses still expose one effective live auth singleton. In that
world, the practical MVP is a valet:

- observe or ask what models the current work requires;
- inspect account credential readiness, identity, entitlement, quota evidence,
  and current singleton identity;
- recommend the best account to make active before the limit is reached;
- execute or print a guarded switch plan through the provider-owned login flow;
- record evidence that active sessions continued or failed.

This is the closest replacement for the developer's current manual Chrome +
usage-panel + `/login` routine. It is smaller than a full adapter, and it may
deliver most of the near-term user value.

### 3. Full Broker Adapter

The broker adapter remains the ideal architecture. It owns the mediation point
inside `oauth-mux <harness>` and can swap accounts on provider-originated quota,
rate, tier, or auth failures without user-visible restart.

This is proven for parts of the Codex path. It is not proven for Claude Code.
Until a Claude adapter owns the relevant session and auth boundary, claims must
not imply seamless Claude same-session broker handoff.

## Browser/Cookie-Picker Evidence Lane

The current manual path is browser-mediated. That means the evidence lane should
be browser-mediated too.

Agents should use the gstack browser/cookie tools to capture the headed,
realistic flow that users already perform:

- `setup-browser-cookies`: opens an interactive cookie picker for installed
  Chromium browsers. The operator selects domains to import. The tool shows
  domain names and counts, never cookie values.
- `browse`: drives pages, snapshots, screenshots, downloads, and persisted
  browser state after cookies are imported.
- Headed mode or CDP mode may be used when the operator needs to interact with
  provider login, usage, or account-switcher UI.

This lane is for evidence and operator-assist only:

- Do not commit cookies, tokens, raw account ids, raw emails, screenshots with
  visible PII, or provider page dumps.
- Do not treat browser observations as a production API contract.
- Do not forge browser-only headers, bypass provider controls, or spend provider
  calls without an explicit proof budget.
- Do commit redacted transcripts, selector notes, hashes, counts, and derived
  cassette summaries when they prove a user-visible flow.

The browser lane should produce evidence such as:

- "These five accounts are signed in and distinguishable by redacted identity
  hash."
- "The provider usage UI exposes model/plan/quota text sufficient for a human or
  agent to classify Fable/Opus/Sonnet readiness."
- "Switching the upstream singleton from account A to account B while a
  long-running harness is active leaves the non-switching sessions alive."
- "A shared browser session bleeds account identity; an isolated profile or
  incognito-first launch prevents it."

## Pure Core

Keep the decision engine pure. All browser, CLI, keychain, daemon, and harness
effects should feed typed events into a reducer. The recommendation path should
be ordinary deterministic data transformation.

### Inputs

```text
AccountIdentity
CredentialState
EntitlementState
ModelQuotaBucket
CurrentSingletonState
ActiveWorkDemand
SwitchCost
EvidenceProvenance
Policy
Now
```

### Event Types

```text
CredentialObserved(provider, account, identity, expires_at, source)
CredentialRefreshed(provider, account, identity, expires_at)
EntitlementObserved(provider, account, plan, model_classes, source)
QuotaObserved(provider, account, model_class, state, resets_at, source)
SingletonObserved(provider, identity, source)
WorkDemandDeclared(model_classes, horizon, source)
AccountSelected(provider, account, model_class, at)
SwitchAttempted(provider, from_identity, to_identity, method)
SwitchSucceeded(provider, to_identity, evidence)
SwitchFailed(provider, reason, evidence)
```

### Queries

```text
credentialReady(account, now) -> bool
modelReady(account, model_class, now) -> Availability
supportsDemand(account, demand, now) -> bool
switchRisk(account, singleton, policy) -> Risk
score(account, demand, singleton, now, policy) -> Score
recommend(accounts, demand, singleton, now, policy) -> Recommendation
switchPlan(recommendation, policy) -> Plan
```

### Ranking

Rank feasible accounts lexicographically:

1. exact model-class parity for the active work;
2. credential ready and refreshable;
3. distinct OAuth identity, no duplicate-family hazard;
4. quota evidence confidence;
5. longest expected usable horizon;
6. lowest switch cost and lowest bleed risk;
7. least-recently selected for the requested model class.

This is O(n*m) over accounts and model classes. For a human operator fleet, n and
m are small. The complexity risk is not Big-O. The risk is false evidence,
unclear authority, and mutating the wrong singleton.

## Required Properties

Property tests and live evidence should defend these invariants:

1. **Credential keepalive is account-scoped.** A credential refresh never creates
   or removes model quota capacity.
2. **Model quota is capability-scoped.** A Fable cap does not mark an account
   dead for every model class.
3. **Duplicate identities collapse.** Two labels with the same OAuth identity
   cannot both be admitted as independent capacity.
4. **No blind singleton write.** A switch plan that would change the provider
   singleton requires explicit operator confirmation and pre/post identity
   evidence.
5. **Sandbox and singleton modes do not mix silently.** A sandboxed account can be
   recommended for new work without implying that existing singleton-governed
   sessions will switch.
6. **Browser evidence is redacted by construction.** Cookie values, token values,
   raw emails, and raw account ids never enter committed artifacts.
7. **Confidence is visible.** A recommendation from browser-observed usage text is
   not the same as a provider API quota header. Both can be useful, but the source
   must be carried into JSON and evidence.
8. **Recommendation is deterministic.** The same event log, policy, and `now`
   produce the same recommendation.
9. **Refusal is a product behavior.** If model parity cannot be proven, the valet
   should refuse or ask for confirmation rather than silently switch to a weaker
   account.

## MVP Slice

The next useful product increment is not another broad daemon layer. It is:

1. `stay-afloat status`: show current singleton identity, enrolled accounts,
   credential readiness, model/entitlement evidence, and confidence.
2. `stay-afloat recommend`: compute the best account for a declared model demand
   and horizon.
3. `stay-afloat switch-plan`: produce the guarded login/switch command and
   evidence checklist.
4. Browser evidence capture: drive the current Chrome path with cookie picker and
   headed browser tools, then commit redacted proof of the manual flow and its
   hazards.
5. One live under-load proof: switch the singleton before a quota wall while
   active sessions are running, then record whether they continue, reload, or
   fail.

## Next-Week Decomposition

### W0: Hygiene and Truth Surfaces

- Land this design note and AGENTS pointer.
- Cross-link TIN-2057, TIN-2400, TIN-2071, and TIN-2077.
- Cross-link TIN-2719 (singleton valet MVP) and TIN-2720 (browser/cookie-picker
  evidence lane) to the Agent Control Plane cookie/browser lease tickets.

### W1: Browser Evidence Harness

- Use `setup-browser-cookies` to import only operator-selected provider domains.
- Use `browse` snapshots/screenshots with redaction discipline.
- Capture the manual account-juggling flow as a redacted cassette:
  account picker, usage page, active singleton identity, model entitlement text,
  and switch confirmation.

### W2: Model-Parity Observation

- Add a typed observation schema for model entitlement and quota confidence.
- Feed browser-derived observations into the same event-log shape as future API
  or wire observations.
- Prove at least two accounts with different model readiness or confidence.

### W3: Pure Recommendation Core

- Implement the account scoring and switch-plan reducer as a pure module.
- Property-test the invariants above, especially duplicate identity collapse,
  deterministic ranking, and no credential/model clock conflation.

### W4: Guarded Singleton Switch Proof

- Build the operator-invoked switch plan.
- Run a live proof with active Claude Code sessions under load.
- Commit redacted evidence showing the before singleton, recommended account,
  switch method, after singleton, and session outcome.

### W5: Decide Product Claim

- If W4 succeeds, the claim is "singleton valet can reduce babysitting and switch
  before the wall."
- If W4 fails, keep the value as "recommendation and preflight" and route effort
  back to sandbox-per-harness and full broker adapter lanes.

## Explicit Non-Goals

- No hosted account pool.
- No automatic browser scraping as a production dependency.
- No evasion of provider quota or plan boundaries.
- No claim that credential keepalive is model-quota keepalive.
- No claim that Claude has seamless same-session broker handoff until TIN-2077
  has committed live evidence.
- No silent mutation of the user's canonical singleton.
