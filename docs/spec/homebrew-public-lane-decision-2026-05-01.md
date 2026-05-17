# Homebrew Public Lane Decision
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#66`; Linear `TIN-858`.

## Decision

Use a Jess-owned public tap for public Homebrew adoption. Keep
`tinyland-inc/homebrew-tools` as the private/staged Tinyland tap.

Recommended public repository:

```text
Jesssullivan/homebrew-omux
```

Recommended install command after the public tap exists:

```bash
brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git
brew install jesssullivan/omux/oauth-mux
```

As of the implementation update below, that repository exists and clean local
install QA passes. Public docs may use the public tap wording, while still
avoiding any claim that this is Homebrew core.

## Current Truth

- `tinyland-inc/homebrew-tools` exists and is private.
- `tinyland/tools/oauth-mux` installs v0.1.6 from that private tap.
- The private tap has passed local Homebrew QA: tap, audit, install/reinstall,
  test, `oauth-mux version`, and `oauth-mux doctor --json`.
- `Jesssullivan/homebrew-omux` now exists as the public tap, with default
  branch `main`.
- The public `jesssullivan/omux` tap installs `oauth-mux 0.1.7` and
  `brew info --json=v2` reports stable version `0.1.7`.
- The release workflow already emits `oauth-mux.rb` and `SHA256SUMS` from the
  public GitHub Release tree.

## Implementation Update

On 2026-05-01, `Jesssullivan/homebrew-omux` was created as a public repository
and populated from the public `oauth-mux` v0.1.6 release asset
`oauth-mux.rb`.

Strict local dogfood then removed the existing local `oauth-mux` install and
public tap, tapped `jesssullivan/omux` from
`https://github.com/Jesssullivan/homebrew-omux.git`, installed
`jesssullivan/omux/oauth-mux`, ran `brew audit`, ran `brew test`, checked
`oauth-mux version`, and ran `oauth-mux doctor --json`.

Hosted registry dry-run `25199131583` also checked out
`Jesssullivan/homebrew-omux` and passed the Homebrew lane against the public
tap.

Result:

```text
Homebrew install QA passed for oauth-mux 0.1.6 via jesssullivan/omux/oauth-mux
```

On 2026-05-17, public tap PR `Jesssullivan/homebrew-omux#1` updated the formula
from the published `oauth-mux` v0.1.7 GitHub Release formula asset and merged at
`43c32ce`. Clean local QA removed the previous install/tap, tapped the public
repo, ran strict audit, checked Homebrew's parsed stable version, installed,
ran `brew test`, checked `oauth-mux version`, and ran `oauth-mux doctor --json`.

Result:

```text
Homebrew install QA passed for oauth-mux 0.1.7 via jesssullivan/omux/oauth-mux
```

## Rationale

The core repository is a Jess Sullivan FOSS project, with Tinyland acting as
the development and release-infrastructure partner. A Jess-owned Homebrew tap
matches that ownership shape better than making the internal Tinyland tools tap
public.

Keeping the Tinyland tap private also reduces accidental public exposure of
future internal formulas, private staging workflows, or org-specific package
policy. The public tap can stay intentionally small: one formula, one release
source, one rollback path.

## Publication Contract

The public tap formula must be derived from public release artifacts, not from a
developer workstation:

1. Cut the `oauth-mux` release through the existing CI release workflow.
2. Use the generated public release assets:
   - `oauth-mux.rb`
   - `SHA256SUMS`
   - platform tarballs
3. Copy or automate the generated formula into the public tap.
4. Run Homebrew QA against the public tap URL.
5. Only then update public adoption docs from staged/private wording to public
   Homebrew wording.

The existing `scripts/homebrew-install-qa.sh` already supports this by
overriding:

```bash
OMUX_HOMEBREW_TAP_NAME=jesssullivan/omux
OMUX_HOMEBREW_TAP_GIT_URL=https://github.com/Jesssullivan/homebrew-omux.git
```

## Rollback

Rollback should be a tap commit, not a local formula edit:

1. Revert the public tap commit that introduced the bad formula.
2. Confirm `brew update` sees the reverted formula.
3. Run `scripts/homebrew-install-qa.sh <last-good-version>` against the public
   tap.
4. If a GitHub Release asset is bad, mark the release as bad in release notes
   and cut a patch release rather than mutating published checksums in place.

## Website Wording

Before public tap creation, historical wording was:

```text
Homebrew: staged/private tap; npm, GitHub Release, curl, deb, and rpm are the
public install lanes today.
```

After public tap creation and QA:

```text
brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git
brew install jesssullivan/omux/oauth-mux
```

Do not describe this as Homebrew core. It is a public tap.

## Completion Gate

Close `#66` / `TIN-858` only after:

1. `Jesssullivan/homebrew-omux` exists and is public.
2. The formula is populated from a public `oauth-mux` release asset.
3. Clean-machine or clean-local QA passes against the public tap.
4. `docs/adoption.md`, `docs/install-beta-matrix.md`, the website, and release
   notes use the public tap wording.

Items 1-4 have repo-doc clean-local v0.1.7 proof as of 2026-05-17. The website
still needs a separate source refresh if its copy names a specific older
version.
