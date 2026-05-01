# Provider Proof: Claude Command Auth
Date: 2026-05-01

Issue context: Linear `TIN-861`, parent `TIN-736`; GitHub
`Jesssullivan/oauth-mux#68`.

## Baseline

Claude Code is a CLI-owned subscription/session provider. Its safest first
probe is not direct OAuth refresh and not a model call. The admitted probe is
the upstream command:

```bash
claude auth status --json
```

`oauth-mux` models that as the built-in `claude` provider capability
`auth-status` with `transport = command`, `auth = none`, and
`budget = free_command`. The selected account still supplies
`CLAUDE_CONFIG_DIR`, but the probe itself must not require `oauth-mux` to parse
or rewrite Claude's credential store before the upstream CLI has reported its
own status.

## Bug Found During Dogfood

The first Claude proof attempt failed before invoking `claude auth status`.
`oauth-mux probe --profile claude --capability auth-status --json` tried to read
`~/.claude/.credentials.json`, then marked the account dead when that file was
not readable from the current process.

That was the wrong boundary. For `auth = none` command probes, credential-file
readability is runtime repair evidence, not a prerequisite for asking the
provider CLI whether the selected config directory has an active session.

## Pipeline Decision

`runProbe` now marks the pipeline as probe-only while candidate selection runs.
If the selected capability resolves to a probe plan whose auth mode is `none`,
the pipeline skips `readSecret` and `validateToken`, executes the command probe,
records the typed liveness result, and selects or skips the account based on
the probe's mux decision.

This does not weaken HTTP or bearer-token probes. Non-`none` probe plans still
require a parsed token before `probe.execute` runs.

## Local Proof

No-spend Claude proof with isolated oauth-mux state:

```bash
tmp="$(mktemp -d)"
OMUX_STATE_DIR="$tmp" \
OMUX_CONFIG=$PWD/examples/claude.config.json \
  ./zig-out/bin/oauth-mux probe --profile claude --capability auth-status --json
```

Observed local result on 2026-05-01:

- selected route: `claude:work#auth-status`
- probe executed: `true`
- probe status: `200`
- decision: `use_this`
- liveness: `live.available`
- runtime readiness: ready

This proves the command-owned auth-status lane can report a live Claude session
without reading or mutating Claude's credential file. It does not prove Claude
quota, tier, or model-call availability, and it does not make direct OAuth
repair admissible. The capability can be reported as `local_live_proven`, while
the provider remains `needs_operator_proof` for broader Claude account and quota
semantics.

## Fixture Coverage

Synthetic tests now cover the two non-spend states needed before broader Claude
claims:

- `claude auth status --json` output with `{"loggedIn":false}` is classified as
  `dead.token_revoked`, which means user-mediated login is required.
- A missing command-adapter binary is `runtime.missing_binary`, not OAuth
  liveness and not provider degradation.

These fixtures keep local runtime absence separate from Claude account state.
They do not replace real operator proof for logged-out, keychain, or quota
conditions.

## Remaining Work

- Attach the fixture and live proof evidence to `TIN-861` and GitHub `#68`.
- Add real logged-out/keychain/session operator fixtures when available.
- Keep Claude as command-first until provider-owned docs expose direct repair
  semantics that are safe for subscription session stores.
- Do not schedule Claude model-call probes by default. Any future route probe
  that spends provider quota must require explicit operator confirmation.
