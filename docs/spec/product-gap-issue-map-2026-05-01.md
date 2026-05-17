# Product Gap Issue Map
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#66`, `#67`, `#68`; Linear
`TIN-858`, `TIN-736`, `TIN-738`, `TIN-859`, `TIN-860`, `TIN-861`, `TIN-862`,
`TIN-863`, `TIN-866`, `TIN-867`, `TIN-876`, `TIN-877`, `TIN-878`, and
`TIN-879`, plus paid cohort lane `TIN-892` with children `TIN-893`,
`TIN-894`, `TIN-895`, and `TIN-896`, plus production daemon contract
`TIN-897`, supervised-loop implementation `TIN-898`, and Codex app-server
auth-broker proof `TIN-913` / GitHub `#125`.

## Baseline

`oauth-mux` v0.1.7 is published and dogfooded for the Codex route-selection
path. The release has public GitHub assets, npm `latest`, `curl | sh`,
deb/rpm assets, and a public Jess-owned Homebrew tap. The remaining adoption
risks are no longer general release mechanics. They are specific product
boundaries that need separate tracking.

Supersession note, 2026-05-08: the Codex proof ladder now includes
broker-owned session planning, no-spend local broker smokes, spend-gated
broker-run live turns, bounded broker-run session loops, exhausted-route
revalidation, controlled fallback drills, managed resume, and dogfood-9 live
auth-continuity plus failed-quota evidence. On 2026-05-08, installed
`oauth-mux codex resume <id>` runs observed provider-originated
`usage_limit_reached` on `codex:default`, recorded quota evidence, dropped
`x-codex-turn-state`, retried the same `responses` request on `codex:max-2`,
and received `status:200` in the same managed process. That proves the
managed load/resume quota handoff path. The then-remaining stricter grail was
an engineered in-session exhaustion event where an initially available account
burns through quota during the managed session and hands off without restart,
logout, login, manual resume, prompt, or provider-forced thread loss.
Closure criteria for that stricter proof live in
`docs/spec/codex-live-acceptance-checklist-2026-05-08.md`; the 2026-05-09
supersession below records that proof.

Supersession note, 2026-05-09: the engineered managed-session quota handoff
artifact now exists. The installed `oauth-mux codex resume <id>` run preserved
in `docs/evidence/codex-engineered-quota-handoff-20260509/` shows successful
`codex:max-2` traffic before provider-originated `usage_limit_reached`, a
same-request retry to `codex:max-3`, and fallback `status:200`. Keep
same-thread continuity semantics, mid-turn streaming recovery, unmanaged
bare-`codex` daemon handoff, non-Codex harnesses, and the remaining auth/quota
permutations as open proof lanes.

Supersession note, 2026-05-17: `v0.1.7` package parity is live. GitHub Release,
npm, curl installer, Homebrew public tap, and deb/rpm package QA resolve to
`0.1.7`. This updates distribution truth only; it does not add new live
provider handoff claims beyond the preserved Codex evidence above.

## Public Issue Map

| Facet | Public GitHub issue | Linear tracking | Current posture |
| --- | --- | --- | --- |
| Homebrew distribution | `#66` | `TIN-858`, related to `TIN-737` | Public Jess-owned tap exists and clean local install QA passes for `0.1.7`; Tinyland tap remains private/staged. Live website copy was rechecked on 2026-05-03 and used the public `jesssullivan/omux` tap, but site copy should be refreshed against the 2026-05-17 package-parity truth. |
| Stay-afloat daemon | `#67` | `TIN-738`, `TIN-859`, `TIN-860`, `TIN-866`, `TIN-867`, `TIN-897`, `TIN-898`, `TIN-940` | Foreground/agent-safe stay-afloat is shipped; production background daemon is not. Socket daemon is explicitly non-product plumbing. The active claim matrix lives in `docs/daemon-boundary.md`; managed Codex launch/resume and broker-owned app-server sessions are scoped proof surfaces. Supervised child capture is diagnostic only, not a product claim level. |
| Provider expansion | `#68` | `TIN-736`, `TIN-861`, `TIN-862`, `TIN-863`, `TIN-876`, `TIN-877`, `TIN-878`, `TIN-879` | Managed Codex route selection, broker-owned sessions, and installed `oauth-mux codex resume` quota handoff are live-proven for scoped commands, including the 2026-05-09 engineered handoff. Same-thread semantics, unmanaged daemon handoff, and non-Codex proof remain capability-level or still need operator proof. |
| Paid multi-account proof | `#67`, `#68` | `TIN-892`, `TIN-893`, `TIN-894`, `TIN-895`, `TIN-896` | Codex has a four-route paid cohort. Dogfood-9 proved managed auth-continuity and failed-quota truth. The 2026-05-08 installed-runtime artifacts proved managed load/resume quota handoff from `codex:default` to `codex:max-2`; the 2026-05-09 engineered artifact proved managed-session quota handoff from `codex:max-2` to `codex:max-3` after successful primary traffic. Claude, Figma, same-thread semantics, unmanaged daemon handoff, and long-window soak evidence remain separate gates. |

## Homebrew Boundary

Current truth:

- `brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git`
  plus `brew install jesssullivan/omux/oauth-mux` installs v0.1.7 from the
  public tap.
- The public tap is `Jesssullivan/homebrew-omux`, default branch `main`.
- `tinyland-inc/homebrew-tools` still exists and remains private/staged
  Tinyland infrastructure.
- This is not Homebrew core. It is a public Homebrew tap.
- Formula updates must continue to come from public GitHub Release
  `oauth-mux.rb` and `SHA256SUMS`, not local `dist/out` output.
- A historical live check of `https://omux.xoxd.ai/` on 2026-05-01 still
  found `brew install tinyland-inc/tools/oauth-mux`. A 2026-05-03 recheck of
  the live site shows the public `jesssullivan/omux` tap, the current
  four-route Codex Max state, and an explicit provider-originated fallback
  proof lane. Keep any remaining `#66` / `TIN-858` work scoped to release-copy
  or artifact cleanup, not the live website tap string.

The decision record is
`docs/spec/homebrew-public-lane-decision-2026-05-01.md`. The live website now
uses the public tap wording that matches this repo truth.

## Stay-Afloat Daemon Boundary

Current truth:

- `stay-afloat --once`, bounded `stay-afloat --loop`, `--execute`, handoffs,
  redacted events, route selection, locks, and writeback admission are shipped.
- `TIN-859` landed in PR `#71` and PR `#72`: the portable foreground
  supervisor contract is documented, and the socket status/stop lifecycle has
  no-mutation E2E coverage.
- `TIN-860` landed in PR `#73`: user-mediated handoffs now have list, ack,
  clear, and named refresh commands.
- `TIN-865` covers a stay-afloat hardening slice: command-probe runtime
  failures must surface as runtime repair state without poisoning persisted
  credential liveness.
- `TIN-866` covers the scheduler policy gate before background daemon wrappers:
  route-level tick JSON must expose deterministic `next_tick_after` and
  `schedule_reason` values, and the summary must report the earliest wake-up
  reason.
- `TIN-867` is complete: the socket daemon boundary is decided and documented
  as non-product plumbing for this release line.
- The default daemon policy refuses provider-spend probes, silent interactive
  auth, and silent mutation.
- Codex fallback is proven across several scopes: historical 2026-05-01
  route-state evidence moved from exhausted `max-1#codex-max` to available
  `max-2#codex-max`; 2026-05-05 spend-gated revalidation restored all four
  `codex-max` routes as selectable; dogfood-9 proved managed auth-continuity
  fallback from selected `max-1` to successful live traffic on `max-4`, then
  observed live quota exhaustion on `max-4` without a successful handoff; the
  2026-05-08 installed-runtime artifacts proved managed load/resume quota
  handoff from `codex:default` to `codex:max-2`; the 2026-05-09 engineered
  artifact proved managed-session quota handoff from `codex:max-2` to
  `codex:max-3` after successful primary traffic.
- The 2026-05-01 sandbox recheck remains useful historical evidence: inside
  the Codex sandbox, all configured Codex account stores reported
  `unwritable_store`; outside that sandbox, the stores were runtime-ready and
  route selection worked. This is a sandbox/runtime-boundary product concern,
  not OAuth death or quota failure.
- Automatic reauth, background repair, same-thread quota recovery, unmanaged
  TUI hot-swap, and broader negative permutations remain unproven.

Remaining daemon split:

- Align the experimental socket daemon with the foreground tick contract before
  calling it a beta background daemon.
- `TIN-867` resolved the current release-line decision: keep the socket daemon
  out of the product stay-afloat surface. `daemon status --json` exposes
  `contract:"experimental_socket_stub"` and `hosts_stay_afloat:false` so
  wrappers do not treat the socket stub as production stay-afloat. Future
  background-daemon work must promote the foreground tick engine deliberately.
- Runtime repair actions now expose a non-executing `diagnostic_command` such
  as `oauth-mux doctor runtime --provider codex --account max-1 --capability
  codex-max --json`, so agents can ask for the precise local proof command
  without treating diagnostics as automatic repair.
- Add optional package wrapper examples only after public install lanes and
  stop/status behavior are stable.
- Keep production background scheduling separate from first-run and release
  gates.

The `TIN-859` contract artifact is
`docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`. It defines the
foreground tick contract as the portable core, keeps the current socket daemon
experimental, and treats Homebrew/systemd/launchd/Windows service integration
as optional wrappers rather than product semantics.

The `TIN-891` permission-broker artifact is
`docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md`. It defines
how agents, shells, CI jobs, and optional service wrappers should handle
`action.diagnostic_command` in the right process boundary without turning
runtime diagnostics into OAuth liveness or automatic repair evidence.

The `TIN-897` background-daemon artifact is
`docs/spec/background-stay-afloat-daemon-contract-2026-05-02.md`. It defines
the stay-afloat claim ladder: prepared fallback for the next mediated action,
diagnostic child-boundary observation, broker-owned app-server sessions,
reserved current-process auth brokering, and true per-request muxing. The
current product is aiming first at prepared fallback plus daemon-warmed route
state, while the only Codex success metric for true stay-afloat remains an
already-running `codex` process handing off to another credited account without
logout, manual resume, restart, or lost thread. Do not claim hot-swap of an
already-running Codex, Claude, or Figma harness unless that harness has a proven
live reload, auth broker, proxy, or in-agent mediation path.
`TIN-898` adds `daemon run --stay-afloat` / `daemon loop` as an opt-in
beta host for the same foreground tick engine. Status can report
`stay_afloat_loop.hosted:true`, but production support remains false until
soak and wrapper proof complete.
The 2026-05-03 live usage-limit observation strengthens that caution: an
already-running provider-owned Codex session hit a usage limit and no seamless
daemon handoff occurred. Manual logout/login restored future mediated launch
readiness, but did not prove active-session rescue.

The `TIN-934` / GitHub `#160` managed-entrypoint slice addresses the practical
startup gap: native Codex sessions that need route-local resume should be
started with `oauth-mux codex managed`, not with an unmanaged `codex` process
that oauth-mux tries to rescue later. Its claim level is `managed_codex_process`
and its resume namespace is the selected route-local `CODEX_HOME`; it does not
claim cross-route import, same-thread quota recovery, or unmanaged TUI hot-swap.
Explicit `--resume <id>` now adds a route-local diagnostic: oauth-mux checks
the selected store's session index, rollout filenames, and Codex state-store
bytes before launch, refuses missing ids before child exec, and keeps ids and
paths out of normal output. This improves wrong-route visibility without
turning managed launch into seamless active-session handoff.

The `TIN-913` / GitHub `#125` Codex app-server auth-broker artifact is
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md`. It records the
source-backed opportunity discovered after the supervised-restart contract:
Codex app-server can accept external ChatGPT auth tokens and request refreshed
tokens from a client after `401 Unauthorized`. oauth-mux now labels those
mediated app-server surfaces as `broker_owned_app_server`; reserve
`current_process_auth_broker` for a future provider/native hook outside that
broker-owned boundary. The broker proof does not prove quota-exhaustion
same-turn handoff and does not change claims for unmanaged Codex TUI/CLI
processes.

The account-enrollment artifact is
`docs/spec/account-enrollment-agent-contract-2026-05-01.md`. It defines the
provider-neutral visibility, admission, and mutation layers for N+1 Codex,
Claude, Figma, and future MCP-facing enrollment. The first implementation slice
is the non-mutating `oauth-mux accounts list --json` inventory surface. The
second slice is `oauth-mux enroll plan <provider> --json`, which explains the
provider-specific setup path and labels each step before any mutation. The
third slice is Codex `oauth-mux enroll codex --account <name> --confirm-enroll
--json`; the fourth slice is Claude `oauth-mux enroll claude --account <name>
--confirm-enroll --json`; the fifth slice is Figma `oauth-mux enroll figma
--account <name> --mode <oauth|pat|plan> --confirm-enroll --json`. These mutate
oauth-mux config/store scaffolding but return upstream login, secret, or proof
setup as user-mediated handoffs.

Core product docs must remain service-manager agnostic. `systemctl`,
`launchctl`, Homebrew services, cron, and Windows Services can become wrapper
examples only after the portable contract is stable.

## Provider Expansion Boundary

Current truth:

- Codex is the only live-proven multi-account subscription harness.
- Built-ins/schema surfaces exist for Claude, GitHub, Linear, Vercel, Figma,
  FlakeHub/Determinate, Gemini, Anthropic API key, and MCP HTTP resource
  servers.
- Public claims should keep `schema_modeled`, `needs_operator_proof`, and
  `live_proven` separate. Capability proof can be narrower than provider proof:
  `local_live_proven` means a local redacted operator proof exists, while
  `public_live_proven` means a no-secret public metadata route was verified.

Next split:

- `TIN-861`: prove Claude Code through command-owned auth/session behavior.
  The first no-spend local proof is captured in
  `docs/spec/provider-proof-claude-command-auth-2026-05-01.md`: `auth-status`
  can now run through `claude auth status --json` without first reading or
  mutating Claude's credential store. Its capability proof status is
  `local_live_proven`. Synthetic fixture coverage now keeps logged-out auth
  evidence separate from `runtime.missing_binary`.
- `TIN-862`: prove GitHub and Linear low-impact identity probes. This is now
  underway with classifier hardening and a proof spec in
  `docs/spec/provider-proof-github-linear-2026-05-01.md`; local GitHub live QA
  has passed, Linear personal API-key live QA has passed, and Linear OAuth
  bearer proof remains pending. GitHub `identity` and Linear
  `identity-api-key` are `local_live_proven`; Linear OAuth `identity` remains
  `needs_operator_proof`.
- `TIN-863`: prove MCP HTTP authorization and protected-resource metadata.
  The first metadata hardening slice is captured in
  `docs/spec/provider-proof-mcp-http-authorization-2026-05-01.md`: MCP
  `resource-metadata` no longer treats any HTTP 200 body as live unless the
  RFC 9728/MCP metadata fields are structurally valid. Its capability proof
  status is `public_live_proven`. The next slice now has a typed target for
  resource-token routing errors: explicit resource/audience mismatch evidence
  is `degraded.audience_mismatch`, not a revoked account.
- `TIN-876`: prove Vercel identity. A low-impact local proof now shows
  `vercel:work#identity` returning HTTP 200 and `live.available`; the
  capability proof status is `local_live_proven`. Broader provider status stays
  conservative until Vercel token, team, scope, and project/resource failure
  shapes have redacted fixture coverage.
- `TIN-877`: prove Figma OAuth, PAT, and plan-token shapes separately.
  `identity`, `identity-pat`, and `file-metadata-plan` must not collapse into a
  single generic "Figma works" claim. A 2026-05-01 OAuth bearer attempt
  returned HTTP 403 and correctly classified as `degraded.scope_insufficient`;
  that is classifier evidence, not live proof. A later SOPS-backed PAT proof
  returned HTTP 200 and `live.available` for `identity-pat`, so only that
  capability is `local_live_proven`; OAuth bearer identity, plan/file metadata,
  and MCP resource-token proof remain open.
- `TIN-878`: prove FlakeHub/Determinate as command-first status. A low-impact
  local proof now shows `flakehub:work#status` through `determinate-nixd
  status` returning HTTP-shaped status 200 and `live.available`; the capability
  proof status is `local_live_proven`. Broader provider status stays
  conservative until logged-out, missing-binary, timeout, cache/apply, and
  private-flake permission states have fixture coverage.
- `TIN-879`: decide and prove the Gemini CLI provider shape before any proof
  promotion; do not assume generic Google OAuth token behavior is enough for
  the harness.
- `TIN-892`: run a paid multi-account proof cohort for common subscription and
  token shapes. Children: `TIN-893` Codex Max plus lower-tier OAuth contrast,
  `TIN-894` Claude Code Pro/Max/team-or-API shapes, `TIN-896` Figma PAT/OAuth/
  plan-token seat and resource limits, and `TIN-895` the seven-day
  foreground stay-afloat soak and public claim policy.

Older broad wave tickets `TIN-818` and `TIN-816` are canceled as superseded by
these precise provider-proof children.

## Immediate Execution Order

1. Keep `TIN-940` open until active docs and site-copy evidence agree with the
   May 3 dogfood truth: foreground prepared fallback, scoped broker-owned
   sessions, managed Codex launch/resume, and no unmanaged active-session
   handoff claim.
2. Recast `TIN-937` as diagnostic child-output capture only. Restart/relaunch
   is not an acceptable stay-afloat path; PTY work is useful only if it helps
   classify the real provider-owned failure and preserve evidence for the live
   handoff effort.
3. Continue `TIN-936` for Codex session-store portability and explicit import
   policy; `codex managed --resume <id>` now diagnoses route-local ownership
   but does not copy or import sessions.
4. Continue `TIN-938` only if the managed local entrypoint is insufficient and
   a remote app-server sidecar can preserve oauth-mux mediation.
5. Draft `TIN-939` upstream usage-limit handoff proposal after the local
   session-store and wrapper semantics are clean.
6. Continue `TIN-861` and `TIN-863` on their remaining hard shapes: Claude
   quota/repair semantics and MCP resource-bound bearer-token proof.
7. Continue `TIN-892` paid proof as billing choices are confirmed. Use
   `docs/spec/paid-multi-account-proof-cohort-2026-05-01.md` as the cohort
   matrix and keep provider-level promotion conservative.
8. Work provider proof in narrow slices: `TIN-876` Vercel, `TIN-877` Figma,
   `TIN-878` FlakeHub/Determinate, and `TIN-879` Gemini.
9. Work `TIN-897` as the daemon promotion contract: define daemon snapshot
   status, supervised tick loop, wrapper recipes, and mediation adapters before
   making seamless handoff claims.
10. Keep `TIN-913` / GitHub `#125` as the Codex app-server auth-broker proof
   record; broker-owned app-server paths are viable, but still separate from
   unmanaged current-process auth brokering.
   `oauth-mux codex broker-plan` proves local credential tuple readiness only;
   it does not read route liveness or claim prepared fallback. Use
   `oauth-mux codex broker-session-plan` for route-aware selection.
   `oauth-mux codex broker-smoke --confirm-broker` proves broker-owned
   app-server stdio external-auth login. `oauth-mux codex broker-401-smoke
   --confirm-broker` proves the local mediated 401 retry path with a fallback
   route. `oauth-mux codex broker-quota-smoke --confirm-broker` proves the
   local no-spend quota boundary: new brokered thread fallback works after
   fallback login, while same-turn and same-thread quota recovery remain
   unclaimed. `oauth-mux codex broker-session-plan` is the next UX slice: it
   combines route liveness with broker readiness to plan a broker-owned Codex
   session without spending provider calls. `oauth-mux codex
   broker-session-smoke --confirm-broker` exercises that plan as a local
   multi-turn broker-owned app-server session against mocked backend endpoints.
   `oauth-mux codex broker-run --prompt ... --confirm-spend` is the matching
   live one-turn broker-owned session proof and remains spend-gated. Its
   bounded `--stdin` beta keeps one broker-owned app-server session open across
   line-delimited live turns while still suppressing transcript content. Live
   quota/rate-limit failures are persisted as route-health evidence and the
   output reports the next selected route plus broker-session resilience
   actions when no spare route remains. With `--continue-on-failure`, the
   command starts a fresh broker-owned session on that selected fallback and
   replays the failed prompt plus remaining queued prompts. This is the honest
   next-session stay-afloat path; it does not imply same-thread recovery.
   `oauth-mux codex revalidate-exhausted --confirm-spend` is the spend-gated
   hygiene path after billing or credit changes: it re-probes only routes
   already blocked by recorded quota/rate evidence and persists the new provider
   result, instead of requiring a manual health reset.
   `oauth-mux codex broker-fallback-drill --from-account ...
   --confirm-drill` is the controlled operator drill for fallback observation:
   it marks a route quota-exhausted in local route health and verifies the next
   broker-owned selection moves to a distinct fallback, without claiming that
   the quota signal came from the provider.
10. Return to daemon background implementation only after wrapper/install
   decisions and provider proof produce enough real operator evidence. The
   current socket daemon decision is complete under `TIN-867`; future
   production daemon work must promote the foreground tick engine deliberately.

## Guardrails

- Do not describe the public tap as Homebrew core.
- Do not make daemon execution a first-run or release gate.
- Do not describe the current daemon or beta loop as hardened seamless
  stay-afloat for active provider-owned sessions.
- Do not claim hot-swap inside an already-running harness without a proven
  live reload, auth broker, proxy, or in-agent mediation path that preserves the
  active session.
- Treat `docs/spec/observed-child-diagnostic-contract-2026-05-02.md` /
  `TIN-911` / GitHub `#123` as diagnostic failure-observation history. Do not
  infer product fallback from a fresh daemon snapshot or child restart.
- Do not run live probes by default.
- Do not mutate upstream CLI-owned credential stores.
- Do not promote a provider to `live_proven` without redacted fixtures and an
  explicit proof run. Promote individual capabilities first when the evidence
  only covers one route shape.
