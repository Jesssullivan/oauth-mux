# Release And Install Lanes

Updated: 2026-05-10

This is the DRY map for installer, package, CI, and local dogfood lanes.
Detailed historical evidence stays in `docs/install-beta-matrix.md` and
`docs/release-runbook.md`.

## Lane Contract

| Lane | User command | Source of artifact | Proof gate | Claim |
| --- | --- | --- | --- | --- |
| Worktree dogfood | `./zig-out/bin/oauth-mux ...` | current checkout | `zig build`, `just check-local` | unreleased behavior only |
| User-local dogfood | `oauth-mux ...` with PATH resolving to `~/.local/bin` | copied worktree binary | hash match with `./zig-out/bin/oauth-mux`, version check | installed-command dogfood for current checkout |
| Nix package | `nix build .#` | flake package | `./result/bin/oauth-mux version` | package derivation proof |
| GitHub Release | downloaded tarball | `dist/out/v*/artifacts` from release workflow | checksum verify and tarball smoke | public raw binary lane |
| npm | `npm install -g oauth-mux` / `npx oauth-mux` | CI-generated npm tarballs | npm install smoke and `npm view` | public JS package lane |
| Homebrew | `brew install jesssullivan/omux/oauth-mux` | public tap formula from release checksums | `just homebrew-qa <version>` | public macOS/Linux tap lane |
| curl installer | `curl .../install.sh \| sh` | GitHub Release `install.sh` + tarballs | local file URL smoke and public installer smoke | shell installer lane |
| deb/rpm | system package install | GitHub Release `.deb` / `.rpm` | hosted container install QA | distro package lane |

## CI/CD Surfaces

| Surface | Workflow or command | Mutates registries? | Purpose |
| --- | --- | --- | --- |
| PR/push CI | `.github/workflows/ci.yml` | no | unit tests, example validation, local E2E, cross-compile, Nix build/check, optional GloriousFlywheel cache-first proof |
| Release staging | `just release-proof <version>` / `.github/workflows/release-proof.yml` | no | build the release tree, smoke installers/packages, generate handoff |
| GitHub Release | `.github/workflows/release.yml` on `v*` tag | GitHub release assets only | upload staged tarballs, npm tarballs, formula, checksums, installer, handoff |
| Registry dry run | `.github/workflows/registry-dry-run.yml` | no | contact configured registries/taps with explicit non-publishing confirmation |
| npm publish | `.github/workflows/npm-publish.yml` | yes, npm only | publish CI-generated npm tarballs after release proof |
| npm deprecate | `.github/workflows/npm-deprecate.yml` | yes when `plan_only=false` | repair bad npm package versions through an explicit production environment |
| System package QA | `.github/workflows/system-package-install-qa.yml` | no | install published `.deb` and `.rpm` assets in clean containers |
| Live provider QA | `.github/workflows/live-provider-qa.yml` | provider calls only with confirmation | produce redacted live/cassette evidence; never a default CI gate |

## Operator Rules

- Use `scripts/project-version.sh` as the version source. Do not hand-edit
  package versions independently.
- `just release-proof <version>` is the local release tree proof. It must pass
  before any registry mutation.
- npm publication is CI-only through `.github/workflows/npm-publish.yml`.
  Workstation `npm publish` is unsupported.
- Registry dry-runs are non-publishing gates. Use
  `OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run`.
- Homebrew and system package checks are package-lane QA. They do not prove
  unreleased worktree behavior unless the package was rebuilt from that tree.
- For live Codex acceptance, use an installed binary on PATH and preserve
  `runtime_identity` in the status artifact. Repo-local wrapper runs are not
  acceptance evidence.

## Local Dogfood Provenance

Before dogfooding unreleased behavior:

```bash
just build
cp ./zig-out/bin/oauth-mux ~/.local/bin/oauth-mux
codesign --force --sign - ~/.local/bin/oauth-mux  # macOS ad-hoc local install
shasum -a 256 ./zig-out/bin/oauth-mux ~/.local/bin/oauth-mux
which -a oauth-mux
oauth-mux version
```

Expected:

- `./zig-out/bin/oauth-mux` and `~/.local/bin/oauth-mux` hashes match.
- `which -a oauth-mux` resolves `~/.local/bin/oauth-mux` before Homebrew when
  testing unreleased behavior.
- Homebrew may report the same source version while still being a different
  binary hash; treat it as the package lane.

On macOS, a copied ad-hoc binary can fail immediately with no output if the
signature/provenance state is inconsistent. Re-signing the copied binary with
`codesign --force --sign -` is the local dogfood repair.

## UX, DX, AX Gates

UX gates:

- clean install command works;
- `oauth-mux version`, `doctor`, `accounts list`, and `route explain` produce
  actionable output;
- Codex managed status artifacts stay redacted and summarize with
  `oauth-mux codex status-latest --json`.

DX gates:

- `just check-local` is the single no-network local validation chain;
- `just release-proof <version>` is the local release validation chain;
- `nix build .#` proves the flake package for the current checkout.

AX gates:

- JSON surfaces are stable and redacted;
- no command requires agents to read token files to decide next action;
- user-mediated actions are labeled commands, such as
  `oauth-mux codex login-device max-3`;
- no live provider-spend action runs without explicit confirmation.
