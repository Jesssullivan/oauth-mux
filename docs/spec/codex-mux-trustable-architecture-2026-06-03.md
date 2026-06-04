# Codex Mux Trustable Architecture Gate

Status: planning gate, 2026-06-03.

## Product Bar

`oauth-mux codex` is successful only when it keeps the managed Codex harness
usable across account auth, quota, tier, and local runtime changes without
corrupting native Codex state or requiring the user to relaunch the harness.

The gate is not satisfied by login success, green route preflight, synthetic
unit tests, or a provider answer that leaves the child process hung.

## Current Reality

Main contains the durable canonical bridge lineage through #365. That lineage is
better than the older disposable `$TMPDIR` bridge, but it still treats canonical
Codex session authority as part of the muxed session path.

The stronger TIN-1851 branch at `/private/tmp/omux-tin1851` implements the
home-is-store candidate architecture:

- selected account home is used directly as `CODEX_HOME`;
- no auth copy is buffered through an overlay;
- no canonical `CODEX_SQLITE_HOME` bridge is set by default;
- canonical `~/.codex` is not a muxed session write target;
- same-account and duplicate-upstream-identity session locks serialize refresh
  token rotation.

That branch is unmerged. Linear marking TIN-1851 Done must not be interpreted as
mainline production readiness until the branch, or an equivalent design, lands
and passes live e2e.

Open GitHub #366 remains a release blocker for dogfooding because the live mux
e2e can receive a successful provider answer and still hang during child
shutdown/finalization. Provider success is not session lifecycle success.

## Dogfood Gate

Managed oauth-mux Codex dogfooding can resume only after a live e2e artifact
proves all of:

1. `oauth-mux codex` completes a real Codex transaction.
2. `oauth-mux codex resume` completes against a previously created muxed
   session.
3. Two distinct managed account sessions can run concurrently without refresh
   token reuse or sqlite authority poisoning.
4. The child process reaches a terminal frame and exits cleanly.
5. No new canonical `~/.codex/state_5.sqlite` rows point at disposable or
   scrubbed oauth-mux homes.
6. Canonical sqlite lock holders are gone after the harness exits.
7. Status output identifies the session authority model honestly.

Until then, native Codex is the safe default for day-to-day engineering work and
muxed Codex remains a gated test path.

## Worktree Hygiene

Keep these worktrees until their changes are explicitly reconciled:

- `/private/tmp/omux-tin1851`: home-is-store muxing architecture candidate.
- `.claude/worktrees/wf_40577f82-730-4`: UX/default profile and in-session
  fallback refresh work.

Park stale greenfield reauth, identity, keepalive, web UI, and Claude adapter
PRs until the Codex state model is safe. They may be valuable, but they do not
fix the state-authority failure.

## Remote Proof

Low-power developer machines should not carry full proof burden. Use
`just remote-check`, `just remote-test`, `just remote-build`, `just remote-e2e`,
and `just remote-release-proof` to dispatch the existing Just/Nix validation
bodies onto the GloriousFlywheel runner substrate.

Bazel is not the next step for this repo unless a real oauth-mux target graph or
consumer need exists. Remote-first validation rides the Just/Nix contract first.
