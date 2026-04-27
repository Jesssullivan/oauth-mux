# oauth-mux Onboarding and Discovery

This document defines the user and agent onboarding path for `oauth-mux`.
The goal is that a user can make expected OAuth accounts muxable with one or
two intentional commands, and an AI agent can discover the safe command surface
without reading token files.

## User Stories

1. Multi-subscription Codex user.
   The user has several ChatGPT/Codex subscription accounts and wants Codex
   routes to fall through when one route is rate-limited, quota-exhausted, or
   auth-broken.

2. Agent harness operator.
   The operator wants Claude, Codex, GitHub, Linear, Figma, Vercel, FlakeHub,
   and MCP accounts represented as named accounts without storing raw OAuth
   tokens in `.env`.

3. AI agent.
   The agent needs to discover configured providers, profiles, health, and safe
   commands without opening credential stores or printing tokens.

4. Provider author.
   The author wants to add support for a new OAuth-backed harness through a
   JSON provider definition and fixtures before writing Zig.

5. Release operator.
   The operator wants local proof, self-hosted cache-first proof, registry
   dry-runs, and rollback instructions before any public package publication.

## First-Run Flow

Generic starter:

```bash
oauth-mux init
oauth-mux config validate
oauth-mux discover
```

Codex Max three-account starter:

```bash
oauth-mux init --codex-max
just codex-max-onboard
```

`just codex-max-onboard` creates the expected isolated `CODEX_HOME` directories,
runs `codex login` for accounts that are not logged in, prints login status, and
then prints `oauth-mux discover`. It does not run live route probes unless the
operator explicitly sets:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls just codex-max-onboard
```

For device-code login instead of browser login:

```bash
OMUX_CODEX_LOGIN_MODE=device just codex-max-onboard
```

For status-only inspection:

```bash
OMUX_CODEX_LOGIN_MODE=status-only just codex-max-onboard
```

## Agent Discovery Contract

Agents should start with:

```bash
oauth-mux discover --json
oauth-mux status --json
oauth-mux health --json
```

Agents may run:

```bash
oauth-mux probe --profile <profile> --capability <capability> --json
oauth-mux env --profile <profile> --capability <capability> --shell <shell>
oauth-mux exec --profile <profile> --capability <capability> -- <command>
```

Agents must not:

- read files referenced by `secret.path`;
- print token-shaped values;
- copy OAuth stores between accounts;
- run live probes unless the user explicitly authorized spend.

`discover --json` is intentionally redacted. It reports config path, state path,
providers, account names, secret backend names, tags, profiles, and safe command
templates. It does not include token material.

## Provider Onboarding Checklist

1. Add or select a provider definition.
2. Add named accounts and secret backends.
3. Add profiles that encode provider/account/capability fallback order.
4. Run `oauth-mux config validate`.
5. Run `oauth-mux discover --json`.
6. Run no-spend checks first: `status`, `health`, and credential parse probes.
7. Run live probes only through `scripts/live-provider-qa.sh` or the manual
   Live Provider QA workflow.

## Operator Definition of Done

- Config validates.
- `discover --json` is usable by agents.
- `status --json` shows expected providers and accounts.
- `health --json` is redacted.
- First live QA run is captured under `dist/live-qa/`.
- Rollback path is documented before registry publication.
