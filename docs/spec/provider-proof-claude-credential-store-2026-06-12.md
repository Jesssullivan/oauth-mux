# Provider Proof: Claude Code credential store under CLAUDE_CONFIG_DIR (macOS)

Status: VERIFIED (TIN-2060). Updated: 2026-06-12. Live empirical proof on
macOS with two real accounts under isolated `CLAUDE_CONFIG_DIR`s.

## Question

Everything Claude in the golden metric (TIN-2057) is gated on: **where does
Claude Code persist credentials when `CLAUDE_CONFIG_DIR` points at a non-default
dir on macOS** — the keychain or `<CLAUDE_CONFIG_DIR>/.credentials.json`? And is
the storage key per-config-dir (per-account separation possible) or global (two
accounts clobber one slot)?

## Verified answer (the result)

**macOS Claude Code stores OAuth credentials in the login keychain, in a
per-config-dir keychain service. The service name is:**

```
Claude Code-credentials-<first 8 hex of sha256(absolute CLAUDE_CONFIG_DIR)>
```

The default config dir (`~/.claude`) uses the unsuffixed service
`Claude Code-credentials`. No `.credentials.json` is written in the config dir.
Per-account separation is **structural** — there is no clobber risk.

### Evidence (two accounts, predicted-then-confirmed)

| Account | CLAUDE_CONFIG_DIR | keychain service | `.credentials.json`? | identity (`oauthAccount.accountUuid` sha256_12) |
| --- | --- | --- | --- | --- |
| (canonical) | `~/.claude` | `Claude Code-credentials` | no | — |
| xoxd | `~/.local/share/oauth-mux/claude/xoxd` | `Claude Code-credentials-26ae8e92` | no | `70bc972b598c` |
| sulliwood | `~/.local/share/oauth-mux/claude/sulliwood` | `Claude Code-credentials-cec7498b` | no | `4b6405c6e227` |

`sha256("/Users/<u>/.local/share/oauth-mux/claude/xoxd")` → `26ae8e92…`;
`sha256(".../sulliwood")` → `cec7498b…`. The sulliwood service name was
**predicted from the formula before the login and confirmed exactly** after.
Both identities are distinct (no duplicate-account trap between these two).

The per-account `<CLAUDE_CONFIG_DIR>/.claude.json` carries
`oauthAccount.accountUuid` (the stable identity source for #360's labeler);
credentials are NOT in `.claude.json`.

## Decisions for the Claude lane

1. **Claude refresh writeback on macOS requires keychain WRITE.**
   **Implemented (TIN-2070)**: `secret.zig` `writeKeychain` shells
   `/usr/bin/security add-generic-password -U` (the plan reason is now
   `keychain_writeback_available` on macOS; other platforms refuse with
   `keychain_write_unproven_on_platform`). Reads target the suffixed service
   via config-load derivation. The keychain items additionally key on
   `acct=<local username>` (verified live: both enrolled accounts carry
   `acct="jess"`) — `-U` updates in place only when (service, account) both
   match, so config derivation also defaults the account to `$USER`.
2. **Service-name derivation is a shared helper.**
   **Implemented (TIN-2070)**: `provider_schema.claudeKeychainService` —
   `sha256(config_dir)[:8]` lowercase hex over the tilde-expanded absolute
   dir (the exact string the launcher exports as `CLAUDE_CONFIG_DIR`), with
   the two vectors above as golden-vector unit tests. Config load
   (`applyClaudeKeychainDefaults`) derives service/account for claude
   keychain accounts that omit them; explicit config always wins.
3. **Linux**: unverified here (no secret-tool/keychain run on Linux in this
   proof). The Claude lane on Linux likely uses `<CLAUDE_CONFIG_DIR>/.credentials.json`
   (file backend) or `secret-tool` — must be proven before a Linux Claude
   keepalive claim. Tracked as follow-up. TIN-2070's derivation is therefore
   comptime-gated to macOS; other platforms keep failing fast at validation.

### Known caveats in the implementation (TIN-2070 review)

- **`$USER` is a proxy** for the passwd-database username Claude Code keys the
  item on. It diverges under `sudo` and is unset in launchd contexts — set
  `secret.account` explicitly in config for those; explicit always wins.
- **`config_dir` pointing at the default `~/.claude` is an unverified edge**:
  the proof did not establish whether the CLI uses the unsuffixed base when
  `CLAUDE_CONFIG_DIR` is exported but equals the default dir, or hashes
  whatever the env var holds. The derivation suffixes whenever `config_dir`
  is present; if an account deliberately targets the canonical dir, pin
  `secret.service` explicitly until this edge is proven.
- **Accounts without `config_dir` derive nothing**: the launcher tmpdir-modes
  them (`CLAUDE_CONFIG_DIR=<tmpdir>`), so no stable keychain identity exists;
  such accounts keep requiring an explicit service. Note the deeper issue:
  per this proof, macOS Claude Code ignores injected `.credentials.json`
  entirely, so tmpdir mode cannot deliver credentials to the CLI on macOS at
  all — that is the Claude adapter contract amendment (#354 lane), not a
  TIN-2070 concern.

## Operational finding: manual-paste OAuth has a per-account session-bleed defect

Claude's CLI login uses the manual code-paste flow (`code=true`,
`redirect_uri=https://platform.claude.com/oauth/code/callback`): the callback
page renders an `Authentication Code` (`<code>#<state>`) to paste back into the
CLI prompt.

**Defect proven live**: the FIRST account (browser with no claude.com session)
resolves the code page normally. The SECOND account's OAuth, run in the SAME
browser carrying the first account's live claude.com session, **does not
surface a fresh code** — the existing session short-circuits consent and the
callback never renders a copyable code; the CLI prompt times out / aborts.

**Workaround proven necessary**: per-account browser isolation. A signed-out
context (Safari Private Window) forced a fresh sign-in and resolved the code
page for the second account on the first try.

**Design consequence**: this empirically establishes #344's
`browser_launch.zig` *incognito-first, ephemeral-profile* launch as
**load-bearing, not optional**. The mediated Claude reauth flow (per the
TIN-2064 designation, behind the contract amendment) MUST launch an isolated
browser context per account, or code delivery breaks for every account after
the first. Connects to the earlier cross-account identity/phone bleed
observation in the same browser-session class.

## Acceptance (TIN-2060)

Met: verified credential-store matrix + named decision (keychain-write-required,
suffix derivation), with golden vectors and the session-bleed design
consequence. Follow-up implementation tickets: keychain write + suffixed
read (secret.zig), Linux proof, and the incognito-first requirement folded into
the Claude reauth flow work (#344/#354 wiring).
