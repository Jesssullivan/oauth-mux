# Adoption Path

`oauth-mux` should be usable by people who are not running the Tinyland lab
stack. Lab SOPS, GloriousFlywheel, and Codex Max canaries are proving grounds;
they must not become requirements for ordinary users.

## Install Surfaces

Target install surfaces:

- npm: `npm install -g oauth-mux`
- Homebrew: `brew install tinyland-inc/tools/oauth-mux`
- curl installer: `curl -fsSL ... | sh`
- deb/rpm packages for Linux hosts
- raw release tarballs for air-gapped or policy-managed systems

Each release artifact should be derived from the same CI release tree. npm is
published only from CI tarballs with provenance; workstation `npm publish` is
not supported.

## First User Experience

The happy path should stay small:

```bash
oauth-mux init
oauth-mux config validate
oauth-mux discover --json
```

For Codex subscription users working from a source checkout today:

```bash
oauth-mux init --codex-max
oauth-mux codex onboard
oauth-mux codex canary
```

Those commands are installed CLI surface, not source-checkout-only helpers.
Users can override the default three-account shape with
`--accounts work,personal,team` and can point account stores somewhere explicit
with `--store-root <path>`.

Live probes remain explicit because they can spend subscription calls:

```bash
oauth-mux codex canary --live
```

## Provider Author Experience

A new provider should usually start as data, not Zig:

1. Write a JSON provider definition with credential parsing, injection, probes,
   and failure rules.
2. Add redacted fixtures for the provider's success, rate-limit, quota,
   degraded, and auth-dead responses.
3. Run `oauth-mux config validate` and the no-secret E2E harness.
4. Run live QA only with explicit account-scoped consent.

Compiled Zig changes should be reserved for new transports, parser primitives,
or core liveness algebra changes.

## Non-Tinyland Deployments

External users may use any secret backend that fits their environment:

- env references
- files under XDG or platform config dirs
- keychain or `secret-tool`
- command backends
- SOPS/age
- stdin for short-lived automation

No adoption flow should require the lab repo, Tinyland SOPS keys,
GloriousFlywheel, or Codex Max accounts.
