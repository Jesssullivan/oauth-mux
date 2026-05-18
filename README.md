# oauth-mux

`oauth-mux` is OAuth/account multiplexing for professional AI harnesses and
autonomous agents.

Developers and agents now operate across personal, work, team, subscription,
API-key, and service identities. Most CLIs still expose a brittle single-account
path: one local auth store, one active subscription, one opaque 401/429 failure
surface. `oauth-mux` puts a broker in front of that path so a harness session can
stay usable when auth, quota, tier, or local runtime state changes.

The product bar is intentionally narrow and hard:

> The user runs `oauth-mux <harness>` such as `oauth-mux codex`. The harness
> behaves like the real one. The active subscription account exhausts quota.
> Another credited account is substituted in place. The harness process is not
> restarted. The user is not prompted.

Restart, supervised relaunch, route warming, and `prepared_fallback` are
diagnostic infrastructure. They are not product success.

## Current Truth

Public install lanes currently resolve to `0.1.7`: GitHub Release assets, npm
root and platform packages, the public Homebrew tap, the curl installer, and
published deb/rpm assets. The current source tree also tightens install parity
after a 2026-05-18 finding that the public Homebrew `codex` shim routed native
admin commands such as `codex --version` through oauth-mux route election.

What works today:

- Managed Codex launch and resume through `oauth-mux codex` and
  `oauth-mux codex resume`.
- Current source/user-local dogfood and next package artifacts include a
  `codex` shim, so a future bare `codex` command is managed only when PATH
  resolves that shim. Admin commands such as `codex login` and
  `codex --version` must pass through to native Codex. Direct native Codex
  binaries and already-running native sessions are not globally protected.
- Native Codex chooser/session authority bridge, including canonical
  `state_5.sqlite*` when present.
- Root-partitioned Codex config passthrough for user settings such as
  `[features]`, legacy `experimental_*`, MCP servers, approval/sandbox policy,
  profiles, model defaults, and non-managed provider definitions.
- Lazy account refresh at credential materialization or explicit repair time;
  managed launch reports `pre_spawn_network_refresh:false`.
- Managed Codex launch/resume auto-revalidates expired Codex quota/rate windows
  under the Codex stay-afloat policy before route election. Interactive login
  remains user-mediated.
- Live managed Codex quota handoff for installed `oauth-mux codex resume`, with
  the strongest preserved proof in
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Redacted JSON diagnostics and opt-in trace JSONL for agents and operators.

Still research or open:

- Same-thread provider semantic continuity across account boundaries.
- Mid-turn streaming recovery.
- Unmanaged bare-`codex` daemon hot-swap.
- Non-Codex provider stay-afloat proof.
- Long-window soak and negative permutation cassette coverage.

## Lifecycle

```mermaid
flowchart LR
    install["Install"] --> init["init"]
    init --> enroll["Enroll accounts"]
    enroll --> diagnose["Local diagnostics"]
    diagnose --> route["Route selection"]
    route --> launch["Managed harness launch"]
    launch --> signal["Provider signal observed"]
    signal --> decision["Broker decision"]
    decision --> materialize["Fallback materialization"]
    materialize --> status["Redacted status artifact"]
    status --> repair["Repair / revalidate loop"]
    repair --> diagnose
```

```mermaid
sequenceDiagram
    participant User
    participant Mux as oauth-mux
    participant Codex
    participant Proxy
    participant Provider

    User->>Mux: oauth-mux codex resume
    Mux->>Mux: select route
    Mux->>Mux: build auth/config overlay
    Mux->>Mux: bridge canonical session authority
    Mux->>Codex: spawn managed Codex
    Codex->>Proxy: responses request
    Proxy->>Provider: selected account request
    Provider-->>Proxy: 200 / 401 / 429 usage_limit_reached / tier or rate error
    Proxy->>Mux: classify signal
    Mux-->>Proxy: retry fallback when eligible
    Proxy-->>Codex: successful response or typed terminal result
    Mux->>Mux: write redacted evidence
```

Route-state labels are stable public vocabulary:
`available`, `quota_exhausted`, `rate_limited`, `tier_insufficient`,
`auth_permanently_failed`, `credential_unavailable`, `revalidation_needed`, and
`not_afloat`.

See `docs/lifecycle.md` for the deeper lifecycle, agent control-plane, and claim
ladder diagrams.

## Install

Public install lanes currently resolve to `0.1.7`:

```bash
npm install -g oauth-mux
# or
brew install jesssullivan/omux/oauth-mux
```

Unreleased source dogfood should keep provenance explicit:

```bash
just install-local-dogfood
which -a oauth-mux
which -a codex
oauth-mux version
oauth-mux version --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
```

If `which -a oauth-mux` resolves Homebrew before the user-local dogfood binary,
adjust PATH or invoke `./zig-out/bin/oauth-mux` directly for source-tree proof.

`version --json` prints the active executable path classification and SHA-256
under `runtime_identity`. Use it when public packages and local dogfood have
nearby version strings and you need machine-readable proof of the exact binary
that will run.

`codex preflight` prints the active `oauth-mux` path, all visible `oauth-mux`
and `codex` PATH candidates, whether active `codex` is the managed oauth-mux
shim, the first native Codex binary, and the `OMUX_CODEX_BIN` escape hatch. Use
that before debugging stale package or managed-versus-unmanaged Codex behavior.
Its JSON separates `agent_safe_next_actions` from
`spend_confirmed_next_actions`; text output uses matching no-spend diagnostics
and spend-confirmed repair sections. The same JSON includes `repair_summary`,
a compact blocked-route rollup for agents that need to distinguish expired
quota-window revalidation, auth handoff, runtime repair, and wait-only states
without scraping per-route diagnostics.

On macOS, remove the old Mach-O before copying the dogfood binary. Overwriting in
place can leave stale taskgated/code-signing state on the old vnode and produce
an immediate `SIGKILL` / status `137`.

`just install-local-dogfood` uses that remove-then-copy lane, verifies the
installed binary hash against `./zig-out/bin/oauth-mux`, and installs a managed
`codex` shim in the same user-local bin directory. The shim resolves the native
upstream Codex executable, passes native admin commands through, and enters
`oauth-mux codex` for managed session commands. It refuses to replace a
non-oauth-mux `codex` already in that directory unless
`OMUX_DOGFOOD_REPLACE_CODEX=1` is set. Public packages may carry a managed
`codex` shim, but installed behavior must still be proven with `version --json`,
`which -a codex`, and `codex preflight` when you need to distinguish a package
binary from a worktree dogfood binary.

## Usage

Human first run:

```bash
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux route explain --profile codex-max --capability codex-max
oauth-mux codex resume
```

If a route needs upstream auth, run the labeled handoff reported by
`route explain`, for example:

```bash
oauth-mux codex login-device max-3
```

Agent-safe inspection:

```bash
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
oauth-mux codex status-latest --json
```

When shell, install, auth, and route-health state disagree, enable the redacted
trace sink:

```bash
OMUX_TRACE=1 \
OMUX_TRACE_FILE=/tmp/oauth-mux-trace.ndjson \
oauth-mux codex preflight --profile codex-max --capability codex-max --json
```

See `docs/tracing.md` for the trace schema and redaction contract.

Those inspection commands do not spend provider calls. In the `0.1.7` release,
managed Codex launch/resume and admitted stay-afloat execution may spend
provider calls only to revalidate expired Codex quota/rate windows before route
election. Live probes, broad revalidation, and non-Codex provider-spend paths
remain explicit.

## UX / DX / AX Contract

UX:

- The managed harness should feel native.
- There is no hidden daemon dependency for the current Codex path.
- Handoffs are labeled and user-mediated when upstream login is required.

DX:

```bash
just build
just test
just check-local
```

Use `just release-proof <version>` before any registry mutation. Direct
`zig build` is fine for iteration, but `just` is the operator entrypoint.

AX:

- JSON surfaces are redacted and account-label based.
- Trace events are opt-in and must not print token bytes, raw provider account
  ids, raw Codex session ids, or local auth/config file paths.
- Agents do not need token files or raw provider stores to choose a next action.
- Provider-spend behavior is policy-labeled; no-spend inspection surfaces stay
  separate from managed Codex auto-revalidation and live probes.
- Diagnostic output should include exact next-action commands.

## Proof

Keep the claim ladder tied to evidence:

- `docs/qa-handoff-matrix.md`: route states, handoff patterns, and current Codex
  truth.
- `docs/productionization-ledger.md`: UX/DX/AX stance, feature ledger,
  adapter strategy, daemon beta boundary, release posture, and tracker map.
- `docs/release-install-lanes.md`: public package lanes versus local dogfood
  lanes.
- `docs/lifecycle.md`: application lifecycle, managed Codex flow, agent-safe
  control plane, and claim levels.
- `docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md`: agent/MCP
  contract for user-mediated reauth prompts, consent, and redaction.
- `docs/tracing.md`: opt-in trace schema, sink selection, and redaction rules.
- `docs/evidence/codex-engineered-quota-handoff-20260509/`: current headline
  managed Codex quota-handoff proof.

The product anchor is `docs/spec/broker-mcp-contract-2026-05-03.md`. The Codex
adapter contract is `docs/spec/codex-adapter-contract-2026-05-03.md`.
