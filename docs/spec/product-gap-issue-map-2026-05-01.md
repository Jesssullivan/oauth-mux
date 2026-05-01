# Product Gap Issue Map
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#66`, `#67`, `#68`; Linear
`TIN-858`, `TIN-736`, `TIN-738`, `TIN-859`, `TIN-860`, `TIN-861`, `TIN-862`,
and `TIN-863`.

## Baseline

`oauth-mux` v0.1.6 is published and dogfooded for the Codex three-account
route. The release has public GitHub assets, npm `latest`, `curl | sh`,
deb/rpm assets, and a private/staged Homebrew tap path. The remaining adoption
risks are no longer general release mechanics. They are three specific product
boundaries that need separate tracking.

## Public Issue Map

| Facet | Public GitHub issue | Linear tracking | Current posture |
| --- | --- | --- | --- |
| Homebrew distribution | `#66` | `TIN-858`, related to `TIN-737` | Private/staged Tinyland tap works; public Homebrew lane undecided. |
| Stay-afloat daemon | `#67` | `TIN-738`, `TIN-859`, `TIN-860` | Foreground/agent-safe stay-afloat is shipped; production background daemon is not. |
| Provider expansion | `#68` | `TIN-736`, `TIN-861`, `TIN-862`, `TIN-863` | Codex is live-proven; most other providers are schema-modeled or admitted but not live-proven. |

## Homebrew Boundary

Current truth:

- `brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git`
  plus `brew install tinyland/tools/oauth-mux` installs v0.1.6.
- The tap is still private/staged infrastructure, not Homebrew core and not a
  public tap promise.
- Formula updates must continue to come from public GitHub Release
  `oauth-mux.rb` and `SHA256SUMS`, not local `dist/out` output.

Decision options:

1. Make `tinyland-inc/homebrew-tools` public.
2. Create a public Jess-owned tap, such as `Jesssullivan/homebrew-omux`.
3. Keep Homebrew staged/private and advertise npm, GitHub Release, curl, and
   deb/rpm as the public install surfaces.

The website must use staged/private wording until this is decided.

## Stay-Afloat Daemon Boundary

Current truth:

- `stay-afloat --once`, bounded `stay-afloat --loop`, `--execute`, handoffs,
  redacted events, route selection, locks, and writeback admission are shipped.
- `TIN-859` landed in PR `#71` and PR `#72`: the portable foreground
  supervisor contract is documented, and the socket status/stop lifecycle has
  no-mutation E2E coverage.
- `TIN-860` landed in PR `#73`: user-mediated handoffs now have list, ack,
  clear, and named refresh commands.
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
  `live_proven` separate.

Next split:

- `TIN-861`: prove Claude Code through command-owned auth/session behavior.
- `TIN-862`: prove GitHub and Linear low-impact identity probes. This is now
  underway with classifier hardening and a proof spec in
  `docs/spec/provider-proof-github-linear-2026-05-01.md`; local GitHub live QA
  has passed, while Linear live proof and durable tracking evidence are still
  pending.
- `TIN-863`: prove MCP HTTP authorization and protected-resource metadata.

Later slices should cover Vercel/Figma token variants and Gemini plus
FlakeHub/Determinate command-first status once the first three provider-proof
patterns are settled.

## Immediate Execution Order

1. Resolve `#66` / `TIN-858` enough for website wording: public tap, Jess tap,
   or staged-only.
2. Finish `TIN-862` as the first non-Codex provider proof by running redacted
   GitHub and Linear identity artifacts after the classifier/documentation
   patch lands.
3. Use `TIN-861` and `TIN-863` to prove the two harder shapes: CLI-owned
   subscription state and MCP resource-bound OAuth.
4. Return to daemon background scheduling only after wrapper/install decisions
   and provider proof produce enough real operator evidence.

## Guardrails

- Do not advertise Homebrew as public until the tap visibility/ownership is
  settled.
- Do not make daemon execution a first-run or release gate.
- Do not run live probes by default.
- Do not mutate upstream CLI-owned credential stores.
- Do not promote a provider to `live_proven` without redacted fixtures and an
  explicit proof run.
