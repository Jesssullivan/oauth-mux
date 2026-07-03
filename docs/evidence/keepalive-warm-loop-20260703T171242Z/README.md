# Keepalive warm-loop evidence — 5-Claude credential dogfood prep

- Date (UTC): 2026-07-03T17:12:42Z -> 2026-07-03T17:19:54Z
- Binary: `/Users/jess/.local/bin/oauth-mux`, `oauth-mux 0.1.13`
- Binary sha256 after reinstalling the dogfood branch with the wait hardening:
  `73bfbde28ec18a2c4036e7927a57d44304e2fafda2a67f5e596becf315fc5102`
- Config backup before opt-in:
  `/Users/jess/.config/oauth-mux/config.json.backup-20260703T171215Z`

## Setup

The operator completed user-mediated `claude auth login` for three newly
scaffolded isolated Claude config dirs:

- `columbari`
- `coye`
- `lmux`

The agent then verified `auth-status ok:true` for the five isolated dogfood
accounts (`xoxd`, `sulliwood`, `columbari`, `coye`, `lmux`) and checked their
redacted `oauthAccount.accountUuid` hashes were distinct:

```text
xoxd       70bc972b598c
sulliwood  4b6405c6e227
columbari  7671eeeaa688
coye       5a4695d5ec37
lmux       68f062968f9e
```

`personal` was left out of the dogfood pool because it uses the canonical
unsuffixed Claude keychain service and has no account UUID in `.claude.json`.

After the distinct-identity gate passed, `allow_proactive_refresh:true` was set
on `columbari`, `coye`, and `lmux`. `xoxd` and `sulliwood` were already opted in.
The config still validates.

## Commands and results

Initial foreground once tick:

```bash
/Users/jess/.local/bin/oauth-mux keepalive --once --json
```

Result:

```json
{"accounts":8,"ticks":1,"refreshed":0,"failed":2,"died":0,"drained":false}
```

Bounded soak attempt with the installed binary initially panicked:

```bash
/Users/jess/.local/bin/oauth-mux keepalive --iterations 5 --interval-ms 60000 --json
```

Failure captured in `keepalive-soak-5x60s.stderr.log`:

```text
thread ... panic: integer overflow
... in _main.KeepaliveWait.wait
```

The operator session then reinstalled the dogfood branch with the
`KeepaliveWait.wait` hardening refactor from this branch, ran local debug tests
(`nix develop --command zig build test`), and reran the soak.

Final clean retry:

```bash
/Users/jess/.local/bin/oauth-mux keepalive --iterations 5 --interval-ms 60000 --json
```

Result:

```json
{"accounts":8,"ticks":5,"refreshed":0,"failed":10,"died":0,"drained":false}
```

Exit code: `0`

## What this shows

1. Five isolated Claude config dirs are logged in, identity-distinct, and opted
   in for proactive refresh.
2. The keepalive pool admits the five Claude accounts without duplicate-identity
   exclusion or canonical-keychain refusal.
3. The bounded foreground keepalive loop survives the five-account Claude pool
   with no Claude refresh failures.
4. The TIN-2113 Codex shared-identity guard still fires for `codex:default` and
   `codex:max-1`.
5. `codex:max-3` and `codex:max-4` remain unopted for proactive refresh and
   account for the repeated `failed` counter in the soak.
6. `gemini:default` and `vercel:default` still fail secret read (`NotFound`) and
   are unrelated to the Claude dogfood lane.
7. The installed dogfood binary used for the first soak could panic in the
   keepalive multi-iteration wait path; this evidence includes both the panic
   artifact and the clean retry after reinstalling the branch binary.

## What this does not claim

- No live Claude credential rotation happened in this run (`refreshed:0`):
  the fresh Claude credentials were not due under the warm scheduler's
  first-refresh staggering policy.
- Not a Claude quota/model keepalive proof.
- Not Fable/Opus route-bucket proof.
- Not Claude adapter parity.
- Not service residency proof; launchd/systemd service units were not installed
  or started during this run.
- Not proof that current `origin/main` had the same wait arithmetic crash; TIN-2409
  records the stale installed-binary/version-skew correction.
- The wait hardening refactor has local debug-test coverage in this session, but
  still needs the repo's remote validation lane before being treated as
  merge-ready.
