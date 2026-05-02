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

`oauth-mux` v0.1.6 is published and dogfooded for the Codex three-account
route. The release has public GitHub assets, npm `latest`, `curl | sh`,
deb/rpm assets, and a public Jess-owned Homebrew tap. The remaining adoption
risks are no longer general release mechanics. They are specific product
boundaries that need separate tracking.

## Public Issue Map

| Facet | Public GitHub issue | Linear tracking | Current posture |
| --- | --- | --- | --- |
| Homebrew distribution | `#66` | `TIN-858`, related to `TIN-737` | Public Jess-owned tap exists and clean local install QA passes; Tinyland tap remains private/staged. Live website copy still needs to stop advertising the private tap. |
| Stay-afloat daemon | `#67` | `TIN-738`, `TIN-859`, `TIN-860`, `TIN-866`, `TIN-867`, `TIN-897`, `TIN-898` | Foreground/agent-safe stay-afloat is shipped; production background daemon is not. Socket daemon is explicitly non-product plumbing for this release line. `TIN-897` defines the mediation boundary for seamless handoff claims; `TIN-898` adds the first opt-in beta supervised loop without changing default policy or production claims. |
| Provider expansion | `#68` | `TIN-736`, `TIN-861`, `TIN-862`, `TIN-863`, `TIN-876`, `TIN-877`, `TIN-878`, `TIN-879` | Codex is live-proven; non-Codex proof is capability-level or still needs operator proof. |
| Paid multi-account proof | `#67`, `#68` | `TIN-892`, `TIN-893`, `TIN-894`, `TIN-895`, `TIN-896` | A one-month paid cohort is now tracked for Codex lower-tier contrast, Claude subscription/billing shapes, Figma token/seat/plan shapes, and a foreground stay-afloat soak gate. |

## Homebrew Boundary

Current truth:

- `brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git`
  plus `brew install jesssullivan/omux/oauth-mux` installs v0.1.6 from the
  public tap.
- The public tap is `Jesssullivan/homebrew-omux`, default branch `main`.
- `tinyland-inc/homebrew-tools` still exists and remains private/staged
  Tinyland infrastructure.
- This is not Homebrew core. It is a public Homebrew tap.
- Formula updates must continue to come from public GitHub Release
  `oauth-mux.rb` and `SHA256SUMS`, not local `dist/out` output.
- A live check of `https://omux.xoxd.ai/` on 2026-05-01 still found
  `brew install tinyland-inc/tools/oauth-mux`; `#66` / `TIN-858` stay open
  until website and release copy use the public `jesssullivan/omux` tap.

The decision record is
`docs/spec/homebrew-public-lane-decision-2026-05-01.md`. The website can now
use public tap wording once it matches this repo truth.

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
- Codex fallback is proven from quota-exhausted `max-1#codex-max` to available
  `max-2#codex-max`; automatic reauth and background repair are not proven.
- A 2026-05-01 recheck split the runtime truth cleanly: inside the current
  Codex sandbox, all three configured Codex account stores report
  `unwritable_store`; outside that sandbox, all three stores are runtime-ready
  and `stay-afloat --once --profile codex-max --capability codex-max --json`
  selects `codex:max-2#codex-max` with `max-3` still selectable. This is a
  sandbox/runtime-boundary product concern, not OAuth death or quota failure.

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
four levels of seamless muxing: prepared fallback for the next mediated
action, supervised restart/relaunch, current-process auth brokering, and true
per-request muxing. The current product is aiming first at prepared fallback
plus daemon-warmed route state. It must not claim hot-swap of an
already-running Codex, Claude, or Figma harness unless that harness has a
proven reload, broker, restart, proxy, or in-agent mediation path.
`TIN-898` adds `daemon run --stay-afloat` / `daemon supervise` as an opt-in
beta host for the same foreground tick engine. Status can report
`stay_afloat_loop.hosted:true`, but production support remains false until
soak and wrapper proof complete.

The `TIN-913` / GitHub `#125` Codex app-server auth-broker artifact is
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md`. It records the
source-backed opportunity discovered after the supervised-restart contract:
Codex app-server can accept external ChatGPT auth tokens and request refreshed
tokens from a client after `401 Unauthorized`. That may become the first
`current_process_auth_broker` proof for sessions launched under oauth-mux
mediation. It does not prove quota-exhaustion same-turn handoff and does not
change claims for unmanaged Codex TUI/CLI processes.

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

1. Keep provider-neutral account inventory and enrollment planning aligned with
   the account-enrollment contract, so agents can inspect N configured accounts
   and explain setup before route, repair, handoff, or live-proof decisions.
2. Use the Codex, Claude, and Figma confirmed enrollment paths as the
   consent/mutation reference before adding MCP mutation tools.
3. Update website/release copy to use the public `jesssullivan/omux` Homebrew
   tap and close `#66` / `TIN-858` after those surfaces are aligned.
4. Finish `TIN-862` by adding Linear OAuth bearer proof. GitHub identity and
   Linear API-key identity are locally proven; Linear OAuth `identity` remains
   `needs_operator_proof`.
5. Continue `TIN-861` and `TIN-863` on their remaining hard shapes: Claude
   quota/repair semantics and MCP resource-bound bearer-token proof.
6. Start `TIN-892` paid proof once billing choices are confirmed. Use
   `docs/spec/paid-multi-account-proof-cohort-2026-05-01.md` as the cohort
   matrix and keep provider-level promotion conservative.
7. Work provider proof in narrow slices: `TIN-876` Vercel, `TIN-877` Figma,
   `TIN-878` FlakeHub/Determinate, and `TIN-879` Gemini.
8. Work `TIN-897` as the daemon promotion contract: define daemon snapshot
   status, supervised tick loop, wrapper recipes, and mediation adapters before
   making seamless handoff claims.
9. Work `TIN-913` / GitHub `#125` as the Codex app-server auth-broker proof
   track before assuming restart is the only viable Codex current-process path.
   `oauth-mux codex broker-plan` proves local credential tuple readiness, and
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
   line-delimited live turns while still suppressing transcript content.
10. Return to daemon background implementation only after wrapper/install
   decisions and provider proof produce enough real operator evidence. The
   current socket daemon decision is complete under `TIN-867`; future
   production daemon work must promote the foreground tick engine deliberately.

## Guardrails

- Do not describe the public tap as Homebrew core.
- Do not make daemon execution a first-run or release gate.
- Do not claim hot-swap inside an already-running harness without a proven
  reload, auth broker, supervised restart, proxy, or in-agent mediation path.
- Track wrapper-owned supervised restart separately under
  `docs/spec/supervised-harness-restart-contract-2026-05-02.md` / `TIN-911` /
  GitHub `#123`; do not infer it from a fresh daemon snapshot.
- Do not run live probes by default.
- Do not mutate upstream CLI-owned credential stores.
- Do not promote a provider to `live_proven` without redacted fixtures and an
  explicit proof run. Promote individual capabilities first when the evidence
  only covers one route shape.
