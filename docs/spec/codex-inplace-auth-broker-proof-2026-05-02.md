# Codex In-Place Auth Broker Proof
Date: 2026-05-02

Issue context: Linear `TIN-913`, parent `TIN-738`, related to `TIN-911`;
GitHub `#125`, parent stay-afloat issue `#67`, related restart issue `#123`.

## State

The previous stay-afloat contract was correct for the product surface we had
actually proven: `oauth-mux` can keep route evidence warm, queue handoffs, and
launch the next Codex process with a selected account. It cannot blindly edit a
standalone already-running Codex process after that process has loaded managed
auth state.

That does not mean current-process handoff is impossible. A source pass against
installed Codex `0.128.0` and upstream `openai/codex` commit
`35aaa5d9fcb606fb6f27dd5747ecab3f4ba0c07e` shows a stronger route:
Codex app-server has an external ChatGPT auth-token mode and a
server-initiated token refresh request. In that mode, the client can supply a
fresh access token when Codex receives `401 Unauthorized`, and Codex retries
the same turn with the refreshed token.

The new working hypothesis is:

`oauth-mux` can become a Codex app-server external-auth broker. For Codex
sessions launched under that brokered app-server topology, oauth-mux may be
able to switch from one selected Codex account to another inside the live
app-server process without restarting the app-server or losing the active
thread.

This is not yet proven in oauth-mux. It is now specific enough to deserve a
tracked proof track.

## Source Evidence

Observed surfaces:

- `codex app-server generate-ts --out /tmp/codex-app-schema/ts` generated an
  `account/login/start` request variant with `type:"chatgptAuthTokens"`.
- The same generated schema includes the server-initiated
  `account/chatgptAuthTokens/refresh` request and response fields:
  `accessToken`, `chatgptAccountId`, and `chatgptPlanType`.
- `codex-rs/login/src/auth/manager.rs` documents `AuthManager` as a cached
  auth snapshot. External changes to `auth.json` are ignored until `reload()`.
- The managed-auth recovery path uses `reload_if_account_id_matches`, which
  intentionally refuses a cross-account file swap when the account id differs.
- `codex-rs/app-server/src/message_processor.rs` installs
  `ExternalAuthRefreshBridge`, which sends
  `account/chatgptAuthTokens/refresh` to the connected app-server client.
- `codex-rs/app-server/src/codex_message_processor.rs` accepts
  `account/login/start` with `chatgptAuthTokens`, saves that auth as ephemeral
  app-server state, and calls `auth_manager.reload()`.
- `codex-rs/app-server/tests/suite/v2/account.rs` has a test where a turn
  starts with `org-initial`, receives a 401, the client returns tokens for
  `org-refreshed`, and the retried request uses the refreshed token.
- The same test suite rejects a mismatched account only when a forced workspace
  id is configured. That is the right guardrail for work/personal boundaries.
- `codex-rs/tui` does not currently appear to answer
  `ChatgptAuthTokensRefresh` itself; the in-process app-server client rejects
  that request. A brokered topology therefore needs oauth-mux to own or
  sidecar the app-server auth-refresh client, not merely rewrite files behind a
  standalone TUI.
- Local stdio protocol smoke on 2026-05-02 showed
  `account/login/start` with `type:"chatgptAuthTokens"` is gated behind
  `initialize.params.capabilities.experimentalApi:true`. Without that
  capability app-server rejects the request; with it, a fake JWT-shaped token
  is accepted locally and app-server emits `account/login/completed` plus
  `account/updated` with `authMode:"chatgptAuthTokens"`. This proves local
  protocol shape only, not live provider auth or quota recovery.

## Boundary Correction

There are now five distinct stay-afloat claim surfaces:

1. `prepared_fallback`: already shipped. The next mediated launch can select a
   healthy account.
2. `observed_child_process`: implemented as wrapper-owned diagnostic
   capture. oauth-mux owns a child process, can classify typed failure evidence,
   records route health, and stops. Restart is not an acceptable stay-afloat
   success level.
3. `broker_owned_app_server`: implemented for Codex app-server proof paths where
   oauth-mux owns the app-server mediation point. This is the current claim
   level for broker-session planning, local smokes, live broker-run, and
   next-session continuation.
4. `current_process_auth_broker`: reserved for a proven provider/native hook
   that updates an already-running process outside the broker-owned boundary.
   Do not use it for unmanaged Codex TUI hot-swap.
5. `per_request_muxing`: not implemented. Every model/provider request passes
   through oauth-mux or an oauth-mux-aware adapter.

Codex app-server external auth belongs to `broker_owned_app_server` when
oauth-mux starts or sidecars the app-server. A regular Codex TUI or `codex
exec` process launched without that mediation point remains level 1 or level 2
only.

## Product Semantics

The broker must distinguish auth recovery from quota recovery.

The external auth refresh reason currently generated by Codex is
`unauthorized`. That covers revoked, expired, or otherwise invalid access-token
paths. It does not prove that Codex will ask for a brokered account switch on
subscription quota exhaustion, weekly limits, monthly limits, or rate limits.

For quota and usage-limit states, the first product shape should be:

- keep route evidence and Codex app-server rate-limit snapshots warm;
- switch the app-server account before the next turn when the current account
  is known unavailable and policy allows account switching;
- only claim same-turn seamless recovery when a real app-server event path
  proves it.

The immediate dogfood question is therefore split:

- revoked/expired token during a request: likely brokerable in the same
  app-server process;
- quota exhaustion during a request: likely next-turn broker switch first,
  unless app-server exposes a usable quota-triggered mediation hook.

## Broker Topologies

### A. Broker-owned stdio app-server proof

This is the safest first proof.

`oauth-mux` starts `codex app-server --listen stdio://` as a child process and
speaks JSON-RPC JSONL over stdin/stdout. It:

1. sends `initialize`;
2. selects an initial Codex route;
3. obtains an access token and account metadata for that route;
4. sends `account/login/start` with `type:"chatgptAuthTokens"`;
5. starts or resumes a test thread;
6. handles `account/chatgptAuthTokens/refresh` by selecting a route and
   returning new token metadata;
7. records redacted route-switch evidence.

This avoids WebSocket implementation risk and proves the app-server auth
contract in-process. It does not provide a full human TUI yet.

### B. Remote app-server with oauth-mux sidecar

This is the likely user-facing Codex beta topology.

`oauth-mux` starts `codex app-server --listen ws://127.0.0.1:<port>` with a
capability token. A user launches Codex TUI with:

```bash
codex --remote ws://127.0.0.1:<port> --remote-auth-token-env OMUX_CODEX_REMOTE_TOKEN
```

An oauth-mux sidecar connection remains attached to the same app-server and
answers external-auth refresh requests. The broker should connect after the TUI
if app-server's active external-auth bridge is last-writer-wins; that behavior
needs proof before productizing this topology.

This topology may allow a normal Codex TUI to keep its active app-server thread
while oauth-mux supplies account changes. It requires WebSocket client support
or an acceptable local proxy path.

### C. Upstream TUI integration

The cleanest long-term route is native Codex support: the TUI or extension
delegates auth refresh/account choice to an external broker. oauth-mux should
track this as an upstream or plugin-facing opportunity, but not block the first
proof on it.

## Token Source Contract

The broker needs a provider-neutral token-source layer, but Codex should start
with explicit rules:

- Prefer account-scoped `CODEX_HOME` stores already enrolled by oauth-mux.
- Before reading an account store, run a low-impact upstream-managed refresh
  path when admitted, such as `CODEX_HOME=<account> codex login status`, so
  Codex keeps ownership of managed refresh semantics.
- Parse access token, account id, and plan type from the account store only
  inside the broker process; never emit token values.
- If direct OAuth refresh is later admitted, use current Codex semantics and a
  separate writeback gate. Do not reuse stale endpoint assumptions without a
  source/version check.
- If a route cannot produce a valid access token and `chatgptAccountId`, return
  a typed broker failure and let the app-server turn fail normally.

For account switching, `previousAccountId` is a routing hint, not an automatic
permission to cross a boundary. Config must decide whether a broker may switch:

- same account only;
- same profile only;
- same trust domain only;
- any account in a named mux profile.

The default should be same profile, no work/personal crossing unless the user
explicitly put both accounts in that profile.

## JSON Shape

A future broker status should be explicit:

```json
{
  "mode": "codex_broker_owned_session_live_run",
  "claim": {
    "level": "broker_owned_app_server",
    "broker_owned_session": true,
    "current_process_auth_broker": false,
    "prepared_fallback": true,
    "supervised_restart": false,
    "current_process_hotswap": false,
    "unmanaged_tui_hotswap": false,
    "per_request_muxing": false
  },
  "app_server": {
    "transport": "stdio",
    "codex_version": "0.128.0",
    "external_auth_active": true,
    "requires_experimental_api": true
  },
  "refresh_request": {
    "reason": "unauthorized",
    "previous_account_id_present": true
  },
  "selected": {
    "provider": "codex",
    "account": "max-3",
    "capability": "codex-max"
  },
  "outcome": "tokens_supplied"
}
```

For quota-driven account changes, use a different action name, such as
`account_switch_before_next_turn`, until a same-turn quota handoff is proven.

## Implementation Order

1. Track this separately from `TIN-911` / GitHub `#123`. The wrapper path is
   diagnostic failure observation only; it is not fallback for unmanaged
   harnesses.
2. Add a source-truth fixture for Codex app-server protocol generation:
   `account/login/start` with `chatgptAuthTokens`,
   `account/chatgptAuthTokens/refresh`, and `account/rateLimits/read`.
3. Add JWT claim parsing for Codex ChatGPT access tokens without logging token
   bodies.
4. Add a token-source planner that can report whether an account can supply
   `accessToken`, `chatgptAccountId`, and `chatgptPlanType` for broker use.
   First slice: `oauth-mux codex broker-plan --profile codex-max --capability
   codex-max --json` reports this locally and redacts token, account-id,
   credential-path, and provider-call evidence. It is auth-material-only and
   does not read route liveness or claim prepared fallback; use
   `oauth-mux codex broker-session-plan` for route-aware session selection.
5. Add a broker command behind an explicit beta name:

   ```bash
   oauth-mux codex broker-smoke \
     --profile codex-max \
     --capability codex-max \
     --confirm-broker \
     --json
   ```

6. Prove topology A against a disposable app-server process. The first
   implementation is `broker-smoke`: it starts `codex app-server --listen
   stdio://`, initializes app-server with `capabilities.experimentalApi:true`,
   sends `account/login/start.chatgptAuthTokens` from a selected route, and
   reports only redacted protocol milestones.
7. Prove the local refresh-response primitive with
   `oauth-mux codex broker-refresh-smoke --profile codex-max --capability
   codex-max --confirm-broker --json`: after app-server login, observe
   `account/chatgptAuthTokens/refresh`, respond with the next ready route's
   external-auth tuple when a fallback account exists, and report only redacted
   protocol milestones.
8. Add a controlled 401 proof:
   `oauth-mux codex broker-401-smoke --profile codex-max --capability
   codex-max --confirm-broker --json` starts a disposable app-server, points
   Responses and ChatGPT backend traffic at a local mock, returns 401 to the
   first turn Responses request, answers `account/chatgptAuthTokens/refresh`
   with the next ready route, and verifies the retried Responses request uses
   the fallback token. This is a local mediated-session proof, not unmanaged
   TUI hot-swap.
9. Add a no-overclaim quota proof: show that rate-limit snapshots can trigger
   next-turn account selection, but do not claim same-turn quota recovery until
   Codex exposes or proves that hook. `oauth-mux codex broker-quota-smoke
   --profile codex-max --capability codex-max --confirm-broker --json` now
   proves the first no-spend version: local usage-limit 429 does not produce
   the 401 refresh hook, fallback app-server login is accepted, and a new
   brokered thread uses fallback Authorization.
10. Add a no-spend session planning surface:
   `oauth-mux codex broker-session-plan --profile codex-max --capability
   codex-max --json` joins recorded route liveness with broker auth readiness
   and reports selected, fallback, quota-blocked, and auth-unready routes for
   the future broker-owned session UX. Its `resilience` object explicitly marks
   whether the selected broker session has a spare fallback route or is a
   single-route-at-risk state. For Codex routes, broker-session, `route
   explain`, and `stay-afloat` surfaces expose the same operator todo list:
   revalidate exhausted routes, enroll another account, or wait for quota reset.
   JSON clients read `resilience_actions`; text output prints the matching
   `next:` hint.
11. Add a no-spend broker-owned session smoke:
   `oauth-mux codex broker-session-smoke --profile codex-max --capability
   codex-max --confirm-broker --json` uses the session plan's selected and
   fallback routes, starts a local app-server session against mocked backend
   endpoints, simulates quota exhaustion on turn one, and verifies a new
   brokered thread uses fallback Authorization.
12. Add the first spend-gated live broker-owned session proof:
   `oauth-mux codex broker-run --profile codex-max --capability codex-max
   --prompt ... --confirm-spend --json` starts the selected route against the
   live Codex provider for one turn and emits redacted protocol evidence.
   A bounded beta loop form accepts line-delimited prompts via `--stdin` and
   keeps one broker-owned app-server session open across those turns.
13. Add explicit next-session continuation:
   `oauth-mux codex broker-run ... --continue-on-failure` records a live
   quota/rate-limit failure, reruns broker-session planning, starts a fresh
   broker-owned app-server session on the selected fallback route, and replays
   the failed prompt plus remaining queued prompts. This is the honest
   next-session stay-afloat path; it is not same-thread recovery. The output
   includes the post-failure resilience state so operators can see when the
   fallback route is now the last selectable route and which actions are left.
14. Add a controlled fallback observation drill:
   `oauth-mux codex broker-fallback-drill --profile codex-max --capability
   codex-max --from-account max-3 --confirm-drill --json` records the named
   route as quota-exhausted in local route health and verifies the next
   broker-owned route selection picks a distinct fallback. This is no-spend
   route-state evidence, not provider-originated quota evidence.
15. Only after topology A is green, attempt topology B with a remote TUI and
   sidecar broker.
16. Update website and README claim language only after live dogfood passes.

## Acceptance Criteria

- The broker never prints access tokens, refresh tokens, id tokens, raw JWTs, or
  credential file paths in normal output.
- The broker can explain why it did or did not switch accounts.
- A 401-triggered app-server refresh request can be handled by oauth-mux with a
  selected account from the configured profile.
- The controlled 401 smoke proves the retried local Responses request used the
  fallback route token without printing token, account-id, or raw protocol
  values.
- The controlled quota smoke proves new-thread fallback after local
  usage-limit classification. It also records the negative evidence:
  same-turn and same-thread quota recovery are not proven.
- The broker session plan is no-spend and planning-only. It can report a
  broker-owned session start route plus immediate selectable fallbacks, but it
  does not start Codex, spend provider calls, or claim unmanaged TUI hot-swap.
- The broker session smoke is no-spend and local. It can prove a multi-turn
  broker-owned app-server handoff using session-plan route selection, but it
  still does not prove same-thread quota recovery or unmanaged TUI hot-swap.
- The broker live run is spend-gated. Its `--prompt` form proves one live turn;
  its bounded `--stdin` beta can exercise multiple turns in one broker-owned
  app-server session. It reports counts without printing transcript content.
  Live quota/rate-limit failures from the app-server protocol are recorded as
  route-health evidence so the output can report the next selected route.
- `broker-run --continue-on-failure` can start a fresh broker-owned session on
  that selected fallback and replay the failed prompt plus remaining queued
  prompts. It still does not prove same-thread recovery or unmanaged TUI
  hot-swap.
- Native provider-owned Codex usage-limit behavior has negative evidence:
  on 2026-05-03, an already-running Codex session returned `You've hit your
  usage limit` and did not emit a provider-native handoff that oauth-mux could
  answer. Manual logout/login restored future route readiness, but it did not
  prove in-place fallback. Keep this distinct from broker-owned next-session
  continuation.
- The upstream Codex OSS shape matches that boundary. In `openai/codex`,
  `UsageLimitReached` is a distinct, non-retryable core error mapped to
  `CodexErrorInfo::UsageLimitExceeded`; the app-server
  `account/chatgptAuthTokens/refresh` path is tested for 401 unauthorized
  refresh, not quota handoff. Relevant source surfaces:
  <https://github.com/openai/codex/blob/main/codex-rs/protocol/src/error.rs>,
  <https://github.com/openai/codex/blob/main/codex-rs/core/src/session/turn.rs>,
  and
  <https://github.com/openai/codex/blob/main/codex-rs/app-server/tests/suite/v2/account.rs>.
- `stay-afloat observe --classify-codex-usage-limit` is the matching
  wrapper-owned instrumentation path. It classifies the usage-limit screen from
  captured child output, records route health, and stops. It still does not
  prove fallback, same-thread recovery, or unmanaged TUI hot-swap.
- Exhausted route revalidation is spend-gated. It exists for external billing,
  plan, or credit changes: bypass only recorded exhausted route-health blocks,
  re-probe the provider, and persist the fresh capability evidence. It removes
  the manual health-reset step, but it does not imply dashboard credits make a
  route available for every Codex capability.
- The broker fallback drill is no-spend but mutates local route health. It can
  observe next-route fallback after a controlled quota-exhausted mark, while
  explicitly not claiming provider-originated quota exhaustion.
- Cross-account switching is blocked when forced workspace or profile policy
  forbids it.
- Quota/rate-limit behavior is separately classified as next-turn account
  switching unless same-turn proof exists.
- Existing `prepared_fallback` claims remain unchanged for unmanaged Codex
  launches; `supervised_restart` remains false because restart is not an
  acceptable product handoff.

## Immediate Dogfood Procedure

For the current unmanaged Codex session, do not claim this proof yet. Instead:

1. keep the foreground stay-afloat loop running to preserve route truth;
2. enroll the credited fallback account;
3. prove `route explain` and `stay-afloat next` select the expected account;
4. run `codex broker-401-smoke --confirm-broker --json` to prove topology A
   locally without provider spend;
5. start a broker-owned app-server proof session for any broader manual
   app-server behavior that the smoke does not cover;
6. trigger or simulate quota exhaustion and observe whether oauth-mux supplies
   another account without restarting the app-server;
7. separately test quota exhaustion and record whether the switch is same-turn
   or next-turn only.

If topology A works, the product answer changes from "Codex hot-swap is not
possible" to "Codex app-server broker hot-swap is possible for proven auth
refresh paths when the session is launched under oauth-mux mediation."
