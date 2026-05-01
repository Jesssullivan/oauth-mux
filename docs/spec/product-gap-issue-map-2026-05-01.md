# Product Gap Issue Map
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#66`, `#67`, `#68`; Linear
`TIN-858`, `TIN-736`, `TIN-738`, `TIN-859`, `TIN-860`, `TIN-861`, `TIN-862`,
`TIN-863`, and `TIN-866`.

## Baseline

`oauth-mux` v0.1.6 is published and dogfooded for the Codex three-account
route. The release has public GitHub assets, npm `latest`, `curl | sh`,
deb/rpm assets, and a public Jess-owned Homebrew tap. The remaining adoption
risks are no longer general release mechanics. They are specific product
boundaries that need separate tracking.

## Public Issue Map

| Facet | Public GitHub issue | Linear tracking | Current posture |
| --- | --- | --- | --- |
| Homebrew distribution | `#66` | `TIN-858`, related to `TIN-737` | Public Jess-owned tap exists and clean local install QA passes; Tinyland tap remains private/staged. |
| Stay-afloat daemon | `#67` | `TIN-738`, `TIN-859`, `TIN-860`, `TIN-866` | Foreground/agent-safe stay-afloat is shipped; production background daemon is not. |
| Provider expansion | `#68` | `TIN-736`, `TIN-861`, `TIN-862`, `TIN-863` | Codex is live-proven; most other providers are schema-modeled or admitted but not live-proven. |

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
- The default daemon policy refuses provider-spend probes, silent interactive
  auth, and silent mutation.
- Codex fallback is proven from quota-exhausted `max-1#codex-max` to available
  `max-2#codex-max`; automatic reauth and background repair are not proven.

Remaining daemon split:

- Align the experimental socket daemon with the foreground tick contract before
  calling it a beta background daemon.
- Add optional package wrapper examples only after public install lanes and
  stop/status behavior are stable.
- Keep production background scheduling separate from first-run and release
  gates.

The `TIN-859` contract artifact is
`docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`. It defines the
foreground tick contract as the portable core, keeps the current socket daemon
experimental, and treats Homebrew/systemd/launchd/Windows service integration
as optional wrappers rather than product semantics.

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

Later slices should cover Vercel/Figma token variants and Gemini plus
FlakeHub/Determinate command-first status once the first three provider-proof
patterns are settled.

## Immediate Execution Order

1. Update website/release copy to use the public `jesssullivan/omux` Homebrew
   tap and close `#66` / `TIN-858` after those surfaces are aligned.
2. Finish `TIN-862` as the first non-Codex provider proof by running redacted
   GitHub and Linear identity artifacts after the classifier/documentation
   patch lands.
3. Use `TIN-861` and `TIN-863` to prove the two harder shapes: CLI-owned
   subscription state and MCP resource-bound OAuth.
4. Return to daemon background scheduling only after wrapper/install decisions
   and provider proof produce enough real operator evidence. The immediate
   daemon-side exceptions are `TIN-865`, because false liveness evidence would
   make every later scheduler less trustworthy, and `TIN-866`, because wrappers
   need deterministic wake-up hints before any service-manager recipes are
   honest.

## Guardrails

- Do not describe the public tap as Homebrew core.
- Do not make daemon execution a first-run or release gate.
- Do not run live probes by default.
- Do not mutate upstream CLI-owned credential stores.
- Do not promote a provider to `live_proven` without redacted fixtures and an
  explicit proof run. Promote individual capabilities first when the evidence
  only covers one route shape.
