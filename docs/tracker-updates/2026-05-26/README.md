# Tracker Update Drafts - 2026-05-26

Status: local coordination draft. Do not post to GitHub or Linear without
explicit operator approval.

## Verified Install State

- Public release: `v0.1.11`
  <https://github.com/Jesssullivan/oauth-mux/releases/tag/v0.1.11>
- Source version: `scripts/project-version.sh` reports `0.1.11`.
- User-local dogfood binary is PATH-first:
  `/Users/jess/.local/bin/oauth-mux`, version `0.1.11`, build id `v0.1.11`.
- Homebrew binary is installed:
  `/opt/homebrew/bin/oauth-mux`, version `0.1.11`.
- Homebrew tap checksum drift was fixed in
  <https://github.com/Jesssullivan/homebrew-omux/pull/8>.
- `brew fetch --force jesssullivan/omux/oauth-mux` passes.
- npm remains stale: `npm view oauth-mux version` reports `0.1.9`; npm
  `oauth-mux@0.1.11` is not published.
- Release checksum note: `SHA256SUMS` / `SHA256SUMS.full` cover binary and
  package artifacts, but `SHA256SUMS.full` does not list `publish-files.txt` or
  `release-handoff.md`. Decide whether "full" should mean every release asset
  before the next release.

## Current GitHub Queue

Open PRs in `Jesssullivan/oauth-mux`: none.

Open issues:

- `#67` - broker daemon and adapter contract umbrella.
- `#68` - provider proof beyond Codex.
- `#163` - Codex remote app-server sidecar.
- `#176` - real Codex wire cassettes.
- `#212` - quota reset and engineered in-session exhaustion plan.

Recently landed:

- `#289` - Codex 0.132 SQLite resume authority fix; closed `#288`.
- `#290` - capture review `--require-proxy-meta` gate.
- `#291` - `0.1.11` release.
- `#292` - post-release capture cookie redaction hardening; does not close
  `#176`.

## Current Linear Queue

Core open or active:

- `TIN-1591` In Progress - process/fd hygiene. Contained, not resolved.
- `TIN-738` In Progress - broker daemon and adapter contract umbrella.
- `TIN-937` In Progress - usage-limit diagnostics without restart.
- `TIN-938` Todo - remote app-server sidecar; keep diagnostic loopback only.
- `TIN-1079` Backlog - engineered quota reset/exhaustion plan; maps to `#212`.
- `TIN-736` In Progress - provider proof beyond Codex; maps to `#68`.
- `TIN-893` In Progress - paid Codex cohort.
- `TIN-895` In Progress - paid cohort soak/public claim policy.

Closed but relevant:

- `TIN-1624` Done - Codex 0.132 resume authority; maps to `#288` / PR `#289`.
- `TIN-979` Done - original harness session authority split.
- `TIN-936` Done - session-store portability policy.
- `TIN-950` Done - real Codex wire cassettes in Linear, but GitHub `#176`
  remains open. Treat this as tracker mismatch until real quota/error cassette
  acceptance lands or Linear is clarified.

## Branch And Worktree Hygiene

`oauth-mux`:

- `main` is clean and in sync with `origin/main`.
- Stale worktree registration for `/private/tmp/oauth-mux-tin1517` was removed
  with `git worktree prune --verbose`; only the active oauth-mux worktree
  remains registered.
- Local branch residue remains from squashed/merged work. Classify before
  deleting because squash merges do not show ancestry containment reliably.
- Cleanup candidates after operator approval:
  `codex/homebrew-explicit-version-metadata` (PR `#281` merged),
  `codex/homebrew-formula-order-and-dogfood-truth` (PR `#282` merged),
  `codex/live-version-provenance` (PR `#280` merged),
  `codex/codex-sqlite-resume-authority` (PR `#289` merged).
- Keep/classify before deletion:
  `jess/tin-1517-harden-codex-managed-route-election` has closed PR `#272`
  rather than merged ancestry, and `archive/broker-mcp-codex-adapter-20260518`
  is explicitly archival.

`lab`:

- `main` is clean and in sync with `origin/main`.
- Home Manager Fish PATH precedence is merged in
  <https://github.com/tinyland-inc/lab/pull/505>.
- Open PR `#504` is unrelated YubiKey policy work.
- Cleanup candidates after operator approval:
  `codex/oauth-mux-fish-path-precedence` (PR `#505` merged) and
  `jess/tin-1252-pzm-materialized-session-vars` (PR `#475` merged).
- Keep: `jess/yubikey-touchless-gpg-policy` while PR `#504` remains open.

`homebrew-omux`:

- Remote `origin/main` includes the `0.1.11` checksum fix.
- Local checkout is on `codex/oauth-mux-0.1.11-checksums`.
- Local `main` is divergent from `origin/main` because older tap work is still
  preserved locally. Do not reset it without first preserving or explicitly
  retiring the local-only commit.
- Cleanup candidates after operator approval:
  `codex/oauth-mux-0.1.11-checksums` (PR `#8` merged) and
  `codex/oauth-mux-0.1.9-tap-v2` (PR `#3` merged).
- Keep/classify before deletion:
  `codex/oauth-mux-0.1.9-tap` has closed PR `#2` and diverged local state;
  `codex/add-oauth-mux-formula` has no matching PR from the audit.

## Backlog Priority

1. Resolve/contain `TIN-1591` with an exact cleanup policy and repeated
   snapshots before using dogfood runs for broad reliability claims.
2. Continue `#176` with real cassette evidence under `--require-proxy-meta`.
   The successful Codex 0.132 capture observed `/backend-api/codex/responses`
   as a WebSocket `101`, but quota/error shapes are still missing.
3. Move `#212` / `TIN-1079` out of backlog only when fallback capacity and
   operator-approved provider spend are ready for engineered exhaustion.
4. Keep `#163` / `TIN-938` to a diagnostic loopback sidecar smoke until cassette
   evidence is stronger.
5. Keep `#68` / `TIN-736` secondary to the Codex reference adapter; admit the
   next provider only through fixture-backed proof.
6. Tighten release hygiene before `0.1.12`: decide whether `SHA256SUMS.full`
   should include every uploaded release asset, including handoff metadata.
