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

Source and local dogfood are `0.1.7` candidate. Public npm, GitHub Release, and
Homebrew install lanes still publish `0.1.6`.

What works today:

- Managed Codex launch and resume through `oauth-mux codex` and
  `oauth-mux codex resume`.
- Native Codex chooser/session authority bridge, including canonical
  `state_5.sqlite*` when present.
- Root-partitioned Codex config passthrough for user settings such as
  `[features]`, legacy `experimental_*`, MCP servers, approval/sandbox policy,
  profiles, model defaults, and non-managed provider definitions.
- Lazy account refresh at credential materialization or explicit repair time;
  managed launch reports `pre_spawn_network_refresh:false`.
- Live managed Codex quota handoff for installed `oauth-mux codex resume`, with
  the strongest preserved proof in
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Redacted JSON diagnostics for agents and operators.

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

Public install lanes currently resolve to `0.1.6`:

```bash
npm install -g oauth-mux
# or
brew install jesssullivan/omux/oauth-mux
```

Local `0.1.7` candidate dogfood should keep provenance explicit:

```bash
just build
mkdir -p ~/.local/bin
rm -f ~/.local/bin/oauth-mux
cp ./zig-out/bin/oauth-mux ~/.local/bin/oauth-mux
shasum -a 256 ./zig-out/bin/oauth-mux ~/.local/bin/oauth-mux
which -a oauth-mux
oauth-mux version
```

On macOS, remove the old Mach-O before copying the dogfood binary. Overwriting in
place can leave stale taskgated/code-signing state on the old vnode and produce
an immediate `SIGKILL` / status `137`.

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
oauth-mux codex status-latest --json
```

Those commands do not spend provider calls. Live probes, revalidation, and
provider-spend paths stay behind explicit confirmation.

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
- Agents do not need token files or raw provider stores to choose a next action.
- oauth-mux does not silently perform provider-spend actions.
- Diagnostic output should include exact next-action commands.

## Proof

Keep the claim ladder tied to evidence:

- `docs/qa-handoff-matrix.md`: route states, handoff patterns, and current Codex
  truth.
- `docs/release-install-lanes.md`: public package lanes versus local dogfood
  lanes.
- `docs/lifecycle.md`: application lifecycle, managed Codex flow, agent-safe
  control plane, and claim levels.
- `docs/evidence/codex-engineered-quota-handoff-20260509/`: current headline
  managed Codex quota-handoff proof.

The product anchor is `docs/spec/broker-mcp-contract-2026-05-03.md`. The Codex
adapter contract is `docs/spec/codex-adapter-contract-2026-05-03.md`.
