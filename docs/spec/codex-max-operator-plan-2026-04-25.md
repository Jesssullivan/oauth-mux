# Codex Max Operator Plan

Updated: 2026-04-25

This note narrows the next `oauth-mux` arc to three Codex Max accounts.

## Current Evidence

Official OpenAI help currently describes Codex as available with ChatGPT Plus,
Pro, Business, and Enterprise/Edu plans, with Codex CLI and IDE sign-in through
ChatGPT. The same help surface says the current Codex CLI / IDE model family is
GPT-5.1-Codex, with Max as default and Mini as optional.

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

## Route Profiles

Two profile lanes are defined:

```text
codex-max  -> codex:max-1#gpt-5.1-codex-max, max-2, max-3
codex-mini -> codex:max-1#gpt-5.1-codex-mini, max-2, max-3
```

Route health is stored independently from account health. A quota-exhausted
`codex:max-1#gpt-5.1-codex-max` route should not make `codex:max-1` unusable
for `gpt-5.1-codex-mini`.

## Operator Commands

Validate the example schema:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux config validate
```

Check selection and credential parse/expiry state for the max route:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux probe --profile codex-max --capability gpt-5.1-codex-max
```

Force a specific account:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux probe --provider codex --account max-2 --capability gpt-5.1-codex-max --json
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

The Codex capabilities are named in the built-in provider definition, but no
live route probe is pinned yet. The `probe` command therefore validates account
selection and credential parsing today, then reports that no configured
capability probe exists.

Do not add a Codex probe endpoint until all of the following are verified:

- endpoint and method
- required request body, if any
- whether subscription-backed Codex accepts the token directly
- which status/header/body fields distinguish rate limit, quota exhaustion,
  inactive subscription, and revoked auth
- whether probing consumes meaningful user quota
