# Repository Ownership And URL Decision

Date: 2026-04-28

## Decision

The canonical public source repository for `oauth-mux` is:

```text
https://github.com/Jesssullivan/oauth-mux
```

Ownership model:

- `Jesssullivan/oauth-mux` is the upstream source repo, issue tracker, release
  home, provider schema, and contributor surface.
- Tinyland remains the development organization and release-infrastructure
  partner: GloriousFlywheel proof, Homebrew tap, package publication, website
  build support, and launch amplification.
- Public language should describe the project as a Jess Sullivan FOSS devtool
  built with Tinyland release infrastructure.

This matches the actual stewardship model: the project is authored and
maintained by Jess Sullivan, while Tinyland provides the operator/release
substrate that proved the package graph.

## Website URL

Use this as the canonical product URL:

```text
https://omux.xoxd.ai
```

Rationale:

- short enough for CLI output and launch posts;
- belongs to the author-facing `xoxd.ai` namespace rather than making the
  project look like a Tinyland-owned product;
- leaves Tinyland free to host or promote a separate org page.

Recommended redirects or secondary surfaces:

- `https://oauth-mux.xoxd.ai` redirects to `https://omux.xoxd.ai`;
- `https://omux.tinyland.dev` can be a Tinyland project page or redirect to the
  canonical site;
- `omux.lmux.ai` is deferred until `lmux.ai` has a clear product-family role.

## Publication Boundary

Before making the source repo public:

1. run a history-aware leak scan;
2. remove live account credential bundle secrets from the public repo;
3. keep release links and generated package metadata pointed at
   `Jesssullivan/oauth-mux`;
4. keep Tinyland-only proof references documented as optional infrastructure,
   not an end-user dependency.

Current hardening evidence:

- `gitleaks detect --source . --redact --verbose` scanned 91 commits and found
  no leaks.
- DNS currently resolves nameservers for `xoxd.ai`, `tinyland.dev`, and
  `lmux.ai`; no candidate `omux` host had an address record at decision time.

## Follow-Up Work

- Build the website under `omux.xoxd.ai`.
- Use Tinyland web/release infrastructure for polish and publication support.
- Recreate public-repo-safe live QA secrets only in a scoped environment if
  hosted live provider QA needs to run from the public source repository.
- Re-enable npm provenance from the public source repo after the next release
  dry-run proves the new owner and source URL.
