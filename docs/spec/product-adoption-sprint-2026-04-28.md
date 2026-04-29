# Product Adoption Sprint

Date: 2026-04-28

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Baseline

`oauth-mux` has crossed the line from architecture experiment to usable public
tool for the first concrete use case:

- `v0.1.2` is published on npm and is the first usable public npm release.
- GitHub Release, npm package layout, Homebrew formula audit, deb/rpm metadata,
  curl installer smoke, and rollback docs have all been exercised through the
  release proof or registry dry-run paths.
- The Codex three-account path is live-proven through secret-scoped hosted QA.
  All three current accounts classify as `live.available` across `codex-mini`
  and `codex-max`.
- Installed CLI commands now cover the core Codex flow:
  `oauth-mux codex onboard`, `oauth-mux codex canary`, and
  `oauth-mux codex probe-all`.
- Probe JSON exposes typed liveness, `ok`, `error`, and `exit_code`, so agents
  can distinguish dead auth, route degradation, quota exhaustion, rate limits,
  cooldowns, and usable accounts.

The next product gap is not the mux algebra. The gap is adoption: first-run
clarity, website narrative, provider-author contribution paths, community
feedback, and a staged launch loop that does not overclaim provider coverage.

## Sprint Objective

Move from "a public binary exists" to "a developer can discover, install, trust,
try, and extend the tool in one sitting."

Success means:

1. the website and README explain the problem in one screen;
2. the first-run Codex path works from installed packages, not repo-local `just`;
3. users and agents can run a redacted diagnostic bundle without reading token
   files;
4. provider authors can add or evaluate a harness from a checklist and fixtures;
5. public launch material drives specific feedback instead of vague attention;
6. every claim about provider support is separated into `live-proven`,
   `schema-modeled`, or `planned`.

## Product Positioning

Primary claim:

> `oauth-mux` is a small compiled mux for OAuth-backed AI harness accounts. It
> keeps account, route, quota, rate-limit, and auth-failure states distinct so
> tools and agents can fall back without guessing or leaking credentials.

What to say now:

- real three-account Codex muxing works;
- subscription quota exhaustion is a typed availability state, not generic
  failure;
- the tool is zero external Zig dependencies and ships as static binaries;
- secrets stay behind selected backends: env refs, files, keychain,
  `secret-tool`, SOPS/age, commands, or stdin;
- agents get redacted discovery and typed JSON, not token material.

What not to say yet:

- do not claim every provider is live-proven;
- do not imply `oauth-mux` bypasses provider limits or subscription terms;
- do not claim automatic background refresh is production-ready;
- do not claim generic OAuth tokens can always substitute for provider-owned CLI
  session stores.

## Website Plan

The website should be an operator-facing devtool page, not a marketing splash.
The first viewport should show the tool name, the actual CLI problem, and a
copyable install/diagnostic path.

Required sections:

1. Hero with real command output.
   - headline: `oauth-mux`
   - subhead: "Typed OAuth fallback for AI harness accounts."
   - primary snippet:

     ```bash
     npm install -g oauth-mux
     oauth-mux codex onboard
     oauth-mux codex probe-all --capability codex-max --json
     ```

   - show a compact redacted JSON excerpt with `live.available`,
     `live.quota_exhausted`, and `dead.auth_permanently_failed`.

2. Problem statement.
   - Developers increasingly carry multiple personal, work, team, subscription,
     and on-prem AI identities.
   - Current CLIs often expose one active account path.
   - Losing focus to manual login/logout, profile copying, and ambiguous 401/429
     failures is the product pain.

3. How fallback works.
   - `CredentialLiveness = live | degraded | dead`.
   - `Availability = available | rate_limited | quota_exhausted | cooldown`.
   - explain route-scoped keys such as `codex:max-1#codex-max`.

4. Install surface.
   - npm now.
   - GitHub Release tarballs now.
   - Homebrew/deb/rpm/curl lanes are release-staged and dry-runed; mark public
     publication state precisely.

5. First-run flows.
   - Codex three-account happy path.
   - generic provider author path.
   - agent discovery path:

     ```bash
     oauth-mux discover --json
     oauth-mux health --json
     oauth-mux probe --profile <profile> --capability <capability> --json
     ```

6. Security and privacy.
   - no `.env` token dumping;
   - no committed credential stores;
   - no raw token output in discovery/health;
   - explicit live probes only when they may spend calls.

7. Provider status matrix.
   - `live-proven`: Codex.
   - `schema-modeled`: Claude, GitHub, Linear, Vercel, Figma, FlakeHub, MCP HTTP
     resource servers.
   - `seeking proof`: each provider that needs real QA or official endpoint
     confirmation.

8. Contribute a provider.
   - link the provider-authoring checklist;
   - ask for redacted cassettes, official docs links, and one positive/negative
     probe case.

9. Launch/contact.
   - GitHub issues for bugs;
   - GitHub discussions or issue templates for provider requests;
   - security contact once public security policy exists.

Useful website artifacts:

- short terminal GIF or asciinema showing account fallback;
- one static architecture diagram of route-scoped liveness;
- one redacted live-QA artifact excerpt;
- a "copy this into an agent" snippet that tells an AI assistant how to inspect
  the mux safely.

## v0.1.3 Onboarding Scope

The next implementation release should optimize first-run trust and support.

Candidate CLI additions:

- `oauth-mux doctor --json`
  - validates binary version, config path, state path, provider definitions,
    secret backend reachability, upstream CLI availability, and redaction
    posture;
  - never reads or prints raw token values;
  - exits with typed categories usable by agents.

- `oauth-mux setup codex`
  - alias or friendlier wrapper for `oauth-mux codex onboard`;
  - prints exactly what will be created before login;
  - supports `--accounts`, `--store-root`, `--device`, `--status-only`, and
    `--live`.

- `oauth-mux report --redacted`
  - writes a support bundle containing version, OS/arch, config shape,
    provider/account labels, health summaries, recent probe evidence, and
    command availability;
  - omits credential paths by default unless `--include-paths` is supplied;
  - suitable for GitHub issue attachment.

- `oauth-mux providers list --json`
  - reports provider status as `built_in`, `schema_modeled`, `live_proven`, or
    `needs_operator_proof`.

Acceptance:

- `just check` passes.
- no-secret E2E covers `doctor` and redacted report output.
- docs and website first-run examples use installed commands only.
- hosted live QA reruns for the Codex matrix before publication.
- full registry dry-run reruns for the bumped version before CI-only publish.

## Launch Plan

Launch in three passes.

### Pass 0: Readiness

Complete before broad posting:

- public repository/README has the exact install commands;
- website first page is live;
- GitHub issue templates exist for bug, provider request, and security-sensitive
  report guidance;
- `doctor` or an equivalent redacted diagnostic flow exists;
- `v0.1.3` is published or staged with dry-run evidence;
- package install smoke is run from a fresh project;
- provider support language is precise.

### Pass 1: Soft Launch

Target users who can give concrete feedback:

- GitHub release notes and pinned issue/discussion;
- npm package README;
- Tinyland blog post or project note;
- MCP and agent-tooling communities where provider-author feedback is welcome;
- maintainers/users of existing multi-profile scripts and profile switchers;
- people already discussing multi-account Codex/Claude/Roo/OpenCode friction in
  public issues.

Launch post angle:

> I built a tiny Zig CLI for typed OAuth fallback across AI harness accounts.
> The first live-proven path is three Codex subscriptions. The part I most want
> feedback on is the provider schema and liveness algebra: does it model your
> harness's auth/rate/quota failure modes cleanly?

### Pass 2: Public Noise

Use broader channels only after the first soft-launch feedback round:

- Hacker News `Show HN`;
- Product Hunt if the website has a polished user-facing demo;
- relevant Reddit/Discord/Slack communities where devtool launch posts are
  accepted;
- blog post aimed at AI agent operators and devtool maintainers;
- short demo video showing `quota_exhausted` fallback and redacted agent
  discovery.

Avoid cross-posting the same day everywhere. Post, answer questions, patch docs,
then post the improved artifact to the next channel.

## Outreach Targets

Use respectful, issue-specific outreach. Do not send generic launch spam.

High-signal categories:

- maintainers of community multi-account tools for Codex, Claude Code, Gemini
  CLI, Roo Code, OpenCode, and similar harnesses;
- people filing or commenting on provider issues about multiple OAuth accounts,
  account switching, subscription quota ambiguity, or MCP auth;
- AI tooling writers who have recently covered agent CLI/auth confusion;
- MCP server authors with HTTP OAuth surfaces;
- OAuth/OIDC practitioners working on protected resource metadata, dynamic
  client registration, token exchange, DPoP, and agentic identity;
- package/channel maintainers for Homebrew, distro packages, and Nix flakes once
  those lanes are promoted.

Suggested ask:

> I am not asking you to endorse it. I would value a technical read on whether
> this liveness/fallback model captures the failure modes you see in your tool.
> If it does not, I would rather fix the schema now than grow a pile of
> provider-specific hacks.

Specific communities/surfaces to prepare for:

- GitHub issues/discussions in the relevant harness repositories;
- OpenAI developer/Codex community surfaces for Codex-specific feedback;
- Anthropic Claude Code public issues/discussions for profile/account switching
  feedback;
- MCP specification and implementation communities for OAuth resource-server
  modeling;
- Vercel AI SDK and agent-framework communities for provider-integration
  feedback;
- Figma MCP users for OAuth vs PAT account-boundary discussion;
- Zig community only after the devtool story is clear, because the value is the
  product, not just the implementation language.

## Content Plan

Write three concise pieces:

1. Launch note: "Typed fallback for AI CLI accounts."
   - problem, demo, install, current status, feedback ask.

2. Technical note: "Why 401, 403, and 429 are not the same failure."
   - explain auth, operability, availability, route-scoped health.

3. Provider-author note: "Adding an OAuth-backed harness to oauth-mux."
   - provider schema, cassettes, failure rules, live QA boundary.

Each post should link to:

- website;
- GitHub repo;
- npm package;
- provider authoring checklist;
- daemon boundary;
- live QA docs;
- rollback docs.

## Linear Split Proposal

Close `TIN-491` only after the planning doc is merged and the split tickets
exist. Follow-up work should be tracked independently:

1. `v0.1.3 onboarding and doctor UX`.
2. `Website and launch narrative`.
3. `Adoption outreach and feedback loop`.
4. `Provider expansion beyond Codex`.
5. `Homebrew/system package publication lane`.
6. `Daemon RFC and promotion criteria`.

## Sources To Keep Current

- Hacker News `Show HN`: https://news.ycombinator.com/showhn.html
- Product Hunt launch guide: https://www.producthunt.com/launch
- MCP authorization spec: https://modelcontextprotocol.io/specification/draft/basic/authorization
- OAuth working group: https://datatracker.ietf.org/wg/oauth/about/
- OAuth 2.1 draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15
- OAuth security BCP, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- Protected resource metadata, RFC 9728: https://www.rfc-editor.org/rfc/rfc9728
