# Codex Max Operator Plan

Updated: 2026-04-26

This note narrows the next `oauth-mux` arc to three Codex Max accounts.

## Current Evidence

Official OpenAI help currently describes Codex as available with ChatGPT Plus,
Pro, Business, and Enterprise/Edu plans, with Codex CLI and IDE sign-in through
ChatGPT. The help surface still mentions the GPT-5.1-Codex family, but the
installed Codex CLI 0.125.0 catalog on this workstation exposes
`gpt-5.3-codex` and `gpt-5.3-codex-spark`. Treat `codex-max` and
`codex-mini` as oauth-mux route labels, not fixed OpenAI model IDs.

Local structure-only inspection of this workstation's Codex cache confirms the
credential shape expected by `oauth-mux`:

```text
auth_mode
tokens.id_token
tokens.access_token
tokens.refresh_token
tokens.account_id
last_refresh
```

No token values were printed or copied.

Live non-secret Codex evidence captured on 2026-04-25:

```text
codex login status -> Logged in using ChatGPT
codex debug models -> gpt-5.3-codex, gpt-5.3-codex-spark
codex exec -m gpt-5.3-codex-spark -> turn.completed with usage
codex exec -m gpt-5.1-codex-max -> status 400 unsupported model for ChatGPT account
```

Redacted JSONL cassettes for these two `codex exec --json` outcomes live under:

```text
test/fixtures/cassettes/codex/
```

Sources:

- <https://help.openai.com/en/articles/11369540-codex-in-chatgpt>
- <https://help.openai.com/en/articles/11381614>

## Account Layout

Use one `CODEX_HOME` per account. The example config uses:

```text
~/.local/share/oauth-mux/codex/max-1/auth.json
~/.local/share/oauth-mux/codex/max-2/auth.json
~/.local/share/oauth-mux/codex/max-3/auth.json
```

The config file lives at:

```text
examples/codex-max.config.json
```

It can also be generated as the active user config:

```bash
oauth-mux init --codex-max
```

Each account is represented twice:

- `config_dir`: the directory exported to Codex as `CODEX_HOME`
- `secret.path`: the `auth.json` read by `oauth-mux` for validation and future
  refresh/probe work

This duplication is intentional for now. It keeps the runtime explicit and
avoids guessing that every config-dir-backed provider stores credentials at the
same relative path.

## Store Bootstrap

The three Codex Max stores are intentionally not created or populated by
`oauth-mux`; each store must be logged in through Codex so refresh/session state
belongs to that isolated `CODEX_HOME`.

On this workstation, inspection on 2026-04-26 found the default
`~/.codex/auth.json` but not the three example stores under
`~/.local/share/oauth-mux/codex/`.

Create the isolation directories:

```bash
mkdir -p \
  ~/.local/share/oauth-mux/codex/max-1 \
  ~/.local/share/oauth-mux/codex/max-2 \
  ~/.local/share/oauth-mux/codex/max-3
```

Then login each subscription account separately:

```bash
CODEX_HOME=$HOME/.local/share/oauth-mux/codex/max-1 codex login
CODEX_HOME=$HOME/.local/share/oauth-mux/codex/max-2 codex login
CODEX_HOME=$HOME/.local/share/oauth-mux/codex/max-3 codex login
```

Do not copy `~/.codex/auth.json` into these stores unless the goal is
deliberately to duplicate the same account. For the three-plan mux, each login
should produce its own `auth.json` in its own store.

## Route Profiles

Two profile lanes are defined with stable route labels:

```text
codex-max  -> codex:max-1#codex-max, max-2, max-3
codex-mini -> codex:max-1#codex-mini, max-2, max-3
```

Route health is stored independently from account health. A quota-exhausted
`codex:max-1#codex-max` route should not make `codex:max-1` unusable for
`codex-mini`.

## Operator Commands

Validate the example schema:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux config validate
```

Equivalent repo helper:

```bash
just codex-max-validate
```

Check selection, credential parse/expiry state, and the built-in max route
command probe:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux probe --profile codex-max --capability codex-max
```

Force a specific account:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux probe --provider codex --account max-2 --capability codex-max --json
```

Safer first-pass matrix probe, using the cheaper `codex-mini` route and a
temporary health store:

```bash
just codex-max-probe-all
```

Probe one account and route:

```bash
just codex-max-probe max-2 codex-max
```

The JSON output includes redacted last-probe evidence:

```json
{
  "last_probe": {
    "source": "credential_validation",
    "observed_at": 1770000000,
    "retry_after_s": null,
    "hint_class": "none",
    "decision": "use_this"
  }
}
```

Run Codex through the mux:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux exec --profile codex-max -- codex
```

## Probe Status

The built-in Codex provider now has command-transport probes for the semantic
route labels:

```text
codex-max  -> codex exec --json --ephemeral --ignore-rules -m gpt-5.3-codex
codex-mini -> codex exec --json --ephemeral --ignore-rules -m gpt-5.3-codex-spark
```

These probes run with the selected account's `CODEX_HOME`, parse Codex JSONL,
and classify `turn.completed` as success. Codex JSONL errors are fed through
provider failure rules, so unsupported model or plan-tier messages become
`degraded.tier_insufficient` instead of a generic circuit-breaker penalty.
The built-in Codex probes use a 120 second timeout; custom probes default to 30
seconds unless `timeout_ms` is set explicitly.

The command probes intentionally burn a tiny Codex call. Use them for explicit
operator `probe` runs and capability-aware fallback decisions, not as a tight
background polling loop.

Do not add a direct Codex HTTP probe endpoint until all of the following are
verified:

- endpoint and method
- required request body, if any
- whether subscription-backed Codex accepts the token directly
- which status/header/body fields distinguish rate limit, quota exhaustion,
  inactive subscription, and revoked auth
- whether probing consumes meaningful user quota
