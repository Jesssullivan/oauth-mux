# Codex Mux Trustable Architecture Gate

Status: planning gate, updated 2026-06-04.

## Product Bar

`oauth-mux codex` is successful only when it keeps the managed Codex harness
usable across account auth, quota, tier, and local runtime changes without
corrupting native Codex state or requiring the user to relaunch the harness.

The gate is not satisfied by login success, green route preflight, synthetic
unit tests, or a provider answer that leaves the child process hung.

## Current Reality

Main contains the TIN-1851 home-is-store architecture through #367, plus the
managed Codex feature-config fix in #370. The older durable canonical bridge
lineage through #365 is superseded for managed Codex sessions; it is useful
history, not the current dogfood model.

The landed home-is-store architecture:

- selected account home is used directly as `CODEX_HOME`;
- no auth copy is buffered through an overlay;
- no canonical `CODEX_SQLITE_HOME` bridge is set by default;
- canonical `~/.codex` is not a muxed session write target;
- same-account and duplicate-upstream-identity session locks serialize refresh
  token rotation.

#367 passed CI and was installed locally on `neo`; #370 then fixed the generated
managed Codex feature config and the installed-binary live e2e completed a real
brokered Codex session without canonical sqlite poisoning. GitHub #366 remains a
regression sentinel for "provider answered but child shutdown hung"; it should
block release only if reproduced against the #367/#370 lineage.

## Dogfood Gate

Managed oauth-mux Codex dogfooding can remain enabled only when live e2e
artifacts continue to prove all of:

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

Native Codex remains the safe fallback for day-to-day engineering work. Muxed
Codex is a dogfood path only when the installed binary matches the proven
lineage and the account pool has enough live route depth for fallback.

## Worktree Hygiene

Keep or remove worktrees based on current branch state, not old planning notes:

- `/private/tmp/omux-tin1851`: may be removable after confirming it contains no
  unmerged local changes beyond #367.
- `.claude/worktrees/wf_40577f82-730-4`: inspect before removal; it was used for
  UX/default profile and in-session fallback refresh work.

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
