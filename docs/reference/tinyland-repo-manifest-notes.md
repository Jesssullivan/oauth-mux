# tinyland.repo.json — divergence and enrollment notes

The tinyland repo-manifest schema
(`site.scaffold/docs/schemas/tinyland-repo-manifest.schema.json`) is
`additionalProperties: false` at the top level and inside `enrollment`, so the
prose that used to live in the manifest's `known_divergences` and
`enrollment.notes` keys was relocated here on 2026-07-02 (TIN-2105, PR #426).
The manifest stays schema-valid; this doc carries the content.

## Known divergences

- **ci_templates_not_consumed** — Workflows predate `ci-templates@v2.0.0`;
  migration workstream tracked under the omux Foundations release-packaging
  project.
- **repo_local_flywheel_wrapper** — `scripts/gloriousflywheel-bazel.sh` is a
  repo-local dispatcher; house direction is sourcing the canonical wrapper
  from `nix develop` / profile-tools.

## Enrollment notes

TIN-2105 bounded Zig REAPI candidate: targets `//:zig_build`
`//:zig_build_test` tagged `gloriousflywheel-rbe-candidate`
(target-class=oauth-mux-zig-build-test). Candidate until a forced
executor-backed proof promotes the class.

## Linear context

- Issue: TIN-2105
- Initiative: "omux Foundations: Race-Safe, Embeddable, Resumable
  Multi-Harness OAuth Broker" (the schema's `repo.linear.initiative` field
  requires an `^[A-Z]+-[0-9]+$` identifier, so the prose name lives here).
