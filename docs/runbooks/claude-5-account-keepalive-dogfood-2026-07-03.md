# 5-Claude credential keepalive dogfood (2026-07-03)

Status: operator-gated lab runbook.

This runbook proves only Claude credential keepalive/writeback across isolated
Claude Code config dirs. It does not prove Claude quota keepalive, model-specific
Fable/Opus routing, Claude adapter parity, or service residency.

## Preconditions

- Use the dogfood binary explicitly:

  ```bash
  /Users/jess/.local/bin/oauth-mux --version
  /Users/jess/.local/bin/oauth-mux config validate
  ```

- Current target build: `oauth-mux 0.1.13` from this dogfood branch after the
  keepalive wait hardening and isolated-login helper changes.
- `personal` stays out of the dogfood pool because it uses the canonical
  unsuffixed Claude keychain service.
- `xoxd` and `sulliwood` are already isolated, live, and opted in.
- `columbari`, `coye`, and `lmux` are scaffolded but require operator login.

## Operator login gate

Run each command one at a time. Use a fresh Private/incognito browser context
for each login, and sign into the intended account only. Do not export
`CLAUDE_CONFIG_DIR` globally.

```bash
env CLAUDE_CONFIG_DIR='/Users/jess/.local/share/oauth-mux/claude/columbari' claude auth login
env CLAUDE_CONFIG_DIR='/Users/jess/.local/share/oauth-mux/claude/coye' claude auth login
env CLAUDE_CONFIG_DIR='/Users/jess/.local/share/oauth-mux/claude/lmux' claude auth login
```

If an agent is executing the login command directly, wrap the command with the
repo helper so Claude's browser launch uses a fresh Chrome user-data-dir instead
of the operator's default browser profile:

```bash
profile=$(mktemp -d "${TMPDIR:-/tmp}/omux-claude-<account>.XXXXXX")
env PATH="$PWD/scripts/claude-open-shim:$PATH" \
  BROWSER="$PWD/scripts/claude-isolated-browser.sh" \
  OMUX_CLAUDE_BROWSER_PROFILE="$profile" \
  CLAUDE_CONFIG_DIR='/Users/jess/.local/share/oauth-mux/claude/<account>' \
  claude auth login
```

After the login succeeds and the isolated browser window is closed, remove the
temporary profile:

```bash
rm -rf "$profile"
```

After all three complete, tell the agent: `done`.

## Agent verification gate

After the operator says `done`, run:

```bash
/Users/jess/.local/bin/oauth-mux accounts list --provider claude --json
```

Proceed only if all five isolated dogfood accounts are live and distinct by
redacted identity hash. Keep `personal` excluded even if it is live.

Required checks:

- `xoxd`, `sulliwood`, `columbari`, `coye`, and `lmux` each have a live
  `auth-status` route.
- Their `<CLAUDE_CONFIG_DIR>/.claude.json` `oauthAccount.accountUuid` hashes are
  distinct.
- No two participating config dirs share one OAuth identity.
- No raw tokens, raw account UUIDs, or raw emails are printed or committed.

If the distinct-identity gate passes, back up config and flip
`allow_proactive_refresh: true` only on `columbari`, `coye`, and `lmux`.
`xoxd` and `sulliwood` are already opted in.

## Foreground evidence

Run foreground evidence before testing service residency:

```bash
/Users/jess/.local/bin/oauth-mux keepalive --once --json
/Users/jess/.local/bin/oauth-mux keepalive --iterations 5 --interval-ms 60000 --json
```

Capture a new evidence directory:

```text
docs/evidence/keepalive-warm-loop-<UTC>/
```

Include:

- UTC start/finish timestamps.
- Redacted `accounts list --provider claude --json` before and after.
- `keepalive --once --json` stdout and stderr.
- Bounded soak stdout and stderr.
- Config backup path.
- A README that states exactly what passed and what was not claimed.

Before any commit or PR, run a credential-material scan over the evidence dir.

## Service proof

Only after clean foreground evidence:

```bash
just keepalive-service-install
just keepalive-service-status
just keepalive-service-verify
```

Service proof belongs to TIN-1830 and needs start -> warm -> restart evidence.
Do not cite foreground credential evidence as service residency proof.

## Allowed language

- "5-Claude credential keepalive dogfood"
- "Claude OAuth refresh/writeback dogfood"
- "distinct isolated Claude config dirs refreshed without credential collision"

## Forbidden language

- "Claude quota keepalive"
- "Claude model keepalive"
- "Fable/Opus quota routing"
- "Claude adapter parity"
- "service residency proven"
