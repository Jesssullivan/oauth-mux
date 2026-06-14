# Release And Install Lanes

Updated: 2026-05-18

This is the DRY map for installer, package, CI, and dogfood lanes.
Detailed historical evidence stays in `docs/install-beta-matrix.md` and
`docs/release-runbook.md`.

## Lane Contract

| Lane | User command | Source of artifact | Proof gate | Claim |
| --- | --- | --- | --- | --- |
| Worktree dogfood | `./zig-out/bin/oauth-mux ...` | current checkout | `just remote-build`, `just remote-check`, plus hash/version proof for the local copied artifact | unreleased behavior only |
| User-local dogfood | `oauth-mux ...` and managed `codex ...` with PATH resolving to `~/.local/bin` | copied worktree binary plus shared POSIX shim | hash match with `./zig-out/bin/oauth-mux`, version check, shim pass-through smoke, preflight check | installed-command dogfood for current checkout |
| Nix package | `nix build .#` | flake package plus shared POSIX shim | `./result/bin/oauth-mux version`, `nix flake check` binary+shim smoke | package derivation proof |
| GitHub Release | downloaded tarball | `dist/out/v*/artifacts` from release workflow | checksum verify, tarball binary+shim smoke | public raw binary lane |
| npm (RETIRED 2026-06-12) | — | lane retired; stale `0.1.9` package abandoned in place | none | excluded from the Bazel SSOT derived lanes (TIN-2046/2050) |
| Homebrew | `brew install jesssullivan/omux/oauth-mux` | public tap formula from release checksums | `just homebrew-qa <version>`, formula test proves no `codex` install, parsed version check | public macOS/Linux tap lane |
| curl installer | `curl .../install.sh \| sh` | GitHub Release `install.sh` + tarballs | local file URL binary+shim smoke and public installer smoke | shell installer lane |
| deb/rpm | system package install | GitHub Release `.deb` / `.rpm` | hosted container install QA for `/usr/bin/oauth-mux`; set `OMUX_EXPECT_CODEX_SHIM=1` for releases that should include `/usr/bin/codex` | distro package lane |
| Home Manager | `programs.oauth-mux.enable = true` | flake Home Manager module | `just home-manager-smoke` package-variant smoke | Nix user-profile lane with opt-in Codex shim |

## Codex Shim Contract

Every install lane that puts `codex` on PATH must preserve this behavior:

- `codex --help`, `codex -h`, `codex help`, `codex --version`,
  `codex -V`, `codex version`, `codex login`, `codex logout`, `codex auth`,
  `codex mcp`, `codex completion`, and `codex completions` exec the native
  upstream Codex CLI without route election.
- Managed session commands such as `codex resume` and `codex run` enter
  `oauth-mux codex` only when PATH resolves the oauth-mux shim.
- The shim discovers native Codex via `OMUX_CODEX_BIN` first, then PATH,
  skipping other files marked `OMUX_CODEX_SHIM`.
- POSIX shim-bearing lanes use the single shared source `dist/codex-shim.sh`:
  user-local dogfood, GitHub Release tarballs, curl installer, opt-in Nix /
  Home Manager packages, and generated deb/rpm packages.
- Homebrew is intentionally binary-only for PATH ownership: the formula installs
  `oauth-mux` but must not install or link `codex`. A managed Codex shim for
  Homebrew users must be an explicit opt-in lane, not the default formula.
- npm uses `dist/npm/bin/codex.js`, which must match the same admin
  pass-through contract even though it is a JS wrapper.
- Windows raw tarballs currently ship only `oauth-mux.exe`. The 2026-05-18
  decision is that managed `codex` command parity on Windows is covered by the
  npm JS wrapper, not by a standalone raw-tarball `.cmd` or PowerShell shim,
  until a native Windows operator need is proven.

## Home Manager

The flake exposes `homeManagerModules.default`. The Home Manager lane is safer
than the default Nix package lane by default:

- `programs.oauth-mux.enable = true` installs only the binary-only
  `packages.<system>.oauth-mux` package.
- `programs.oauth-mux.codexShim.enable = true` explicitly opts into
  `packages.<system>.withCodexShim`, which puts the managed `codex` shim on
  PATH.

See `docs/home-manager.md` for the module snippet and local smoke command.

The 2026-05-18 investigation found that public Homebrew `0.1.7` installed a
`codex` shim that always entered `oauth-mux codex`, so `codex --version` and
`codex login` could hit route election and fail with `NoAccountSelectable`.
That was package-lane drift, not a route-health issue. The current source tree
fixes the release templates and adds package smokes so Homebrew proves native
Codex command resolution is unchanged by `brew install jesssullivan/omux/oauth-mux`.

## CI/CD Surfaces

| Surface | Workflow or command | Mutates registries? | Purpose |
| --- | --- | --- | --- |
| PR/push CI | `.github/workflows/ci.yml` | no | unit tests, example validation, local E2E, cross-compile, Nix build/check, optional GloriousFlywheel cache-first proof |
| Release staging | `just remote-release-proof <ref> <version>` / `.github/workflows/release-proof.yml` | no | build the release tree, smoke installers/packages, generate handoff on the remote runner |
| GitHub Release | `.github/workflows/release.yml` on `v*` tag | GitHub release assets only | upload staged tarballs, npm tarballs, formula, checksums, installer, handoff |
| Registry dry run | `.github/workflows/registry-dry-run.yml` | no | contact configured registries/taps with explicit non-publishing confirmation |
| npm publish | `.github/workflows/npm-publish.yml` | yes, npm only | publish CI-generated npm tarballs after release proof |
| npm deprecate | `.github/workflows/npm-deprecate.yml` | yes when `plan_only=false` | repair bad npm package versions through an explicit production environment |
| System package QA | `.github/workflows/system-package-install-qa.yml` | no | install published `.deb` and `.rpm` assets in clean containers; `expect_codex_shim` gates new shim-bearing releases |
| Live provider QA | `.github/workflows/live-provider-qa.yml` | provider calls only with confirmation | produce redacted live/cassette evidence; never a default CI gate |

## Operator Rules

- Use `scripts/project-version.sh` as the version source. Do not hand-edit
  package versions independently.
- `just remote-release-proof <ref> <version>` is the release tree proof. It must pass
  before any registry mutation.
- `nix flake check` is a local package debugging smoke, not release proof.
  Remote release proof must prove the package runs, reports the source version,
  and validates no-secret examples.
- npm publication is CI-only through `.github/workflows/npm-publish.yml`.
  Workstation `npm publish` is unsupported.
- Release and registry scripts must use an isolated npm cache so root-owned or
  stale workstation `~/.npm` state cannot affect release proof.
- Registry dry-runs are non-publishing gates. Use
  `OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run`.
- Homebrew and system package checks are package-lane QA. They do not prove
  unreleased worktree behavior unless the package was rebuilt from that tree.
- Homebrew package QA must check the installed binary and Homebrew's parsed
  `versions.stable`; a working binary with bad formula metadata is not release
  parity.
- Homebrew package QA must prove the formula does not install `codex`, does not
  link an `OMUX_CODEX_SHIM` into the Homebrew prefix, and leaves `command -v
  codex` unchanged from before install.
- Shim-bearing package QA must check the managed `codex` shim's admin
  pass-through behavior with a native Codex stub. A binary version check alone
  is not sufficient.
- For live Codex acceptance, use an installed binary on PATH and preserve the
  status artifact `runtime_identity`, including `binary_source` and
  `binary_sha256`. Repo-local wrapper runs are not acceptance evidence.

## Local Dogfood Provenance

Before dogfooding unreleased behavior:

```bash
just install-local-dogfood
which -a oauth-mux
which -a codex
oauth-mux version
oauth-mux version --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
```

Expected when testing unreleased managed-shim behavior:

- `./zig-out/bin/oauth-mux` and `~/.local/bin/oauth-mux` hashes match.
- `oauth-mux version --json` reports the active executable's
  `runtime_identity.binary_source` and `runtime_identity.binary_sha256`, so
  agents can compare dogfood/package binaries without a separate hash command.
- `which -a oauth-mux` resolves `~/.local/bin/oauth-mux` before Homebrew when
  testing unreleased behavior.
- `which -a codex` resolves `~/.local/bin/codex` before the native upstream
  Codex CLI only when testing the explicit managed-shim lane.
- `oauth-mux codex preflight --json` is handled by oauth-mux, not by the native
  Codex CLI usage parser.
- Homebrew may report the same source version while still being a different
  binary hash; treat it as the package lane.

If Homebrew appears before `~/.local/bin` in PATH, use the worktree binary or
adjust PATH before recording unreleased dogfood evidence. The active public
Homebrew is a package binary, not worktree proof. It must not shadow native
Codex by default; use `which -a codex` before and after Homebrew QA to verify
the `codex` executable owner did not change.

On macOS, do not overwrite an existing Mach-O in place for this lane. A direct
`cp` over `~/.local/bin/oauth-mux` can leave stale taskgated/code-signing state
on the old vnode; the symptom is immediate `SIGKILL` / shell status `137` with
a DiagnosticReports entry saying `Taskgated Invalid Signature`. The local
installer copies to a temporary file in the install directory, then renames the
new file into place so the installed file has a fresh vnode and the hash still
matches the worktree binary. Re-signing the installed copy is a separate repair
fallback, but it changes the hash and no longer proves byte identity with
`./zig-out/bin/oauth-mux`.

The local installer installs only `~/.local/bin/oauth-mux` by default and leaves
the native `codex` command unshadowed. Before replacing the binary, it refuses
when active managed `oauth-mux codex` sessions are visible and prints a redacted
parent/child PID and listener-port report. Use
`OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1` only after explicitly accepting that
already-running sessions keep their current process image.

Use `OMUX_DOGFOOD_INSTALL_CODEX_SHIM=1` or `just install-local-dogfood-shim`
only when managed-shim dogfood is the point of the test. The local installer
refuses to replace an existing non-oauth-mux `~/.local/bin/codex` unless
`OMUX_DOGFOOD_REPLACE_CODEX=1` is set. Use `just uninstall-local-dogfood` to
remove the local dogfood binary and any oauth-mux-marked `codex` shim without
touching a native Codex executable.

## UX, DX, AX Gates

UX gates:

- clean install command works;
- `oauth-mux version`, `doctor`, `accounts list`, and `route explain` produce
  actionable output;
- Codex managed status artifacts stay redacted and summarize with
  `oauth-mux codex status-latest --json`.

DX gates:

- `just check` is the default validation chain for PR and dogfood readiness; it
  dispatches the GloriousFlywheel remote lane;
- `just build`, `just test`, and `just e2e` are targeted remote proof lanes;
- `just remote-build`, `just remote-test`, `just remote-check`, and
  `just remote-e2e` remain explicit aliases for the same dispatch path;
- `just release-proof <version> [ref]` or
  `just remote-release-proof <ref> <version>` is required before any registry
  mutation;
- local `just check-local`, `just release-proof-local <version>`, `nix build .#`,
  and `nix flake check` are debugging tools only and do not replace remote
  proof.

AX gates:

- JSON surfaces are stable and redacted;
- no command requires agents to read token files to decide next action;
- user-mediated actions are labeled commands, such as
  `oauth-mux codex login-device max-3`;
- no live provider-spend action runs without explicit confirmation.
