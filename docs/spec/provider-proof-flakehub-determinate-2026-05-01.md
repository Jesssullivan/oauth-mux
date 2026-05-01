# Provider Proof: FlakeHub / Determinate Status
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#68`; Linear `TIN-736`,
`TIN-878`.

## Boundary

FlakeHub / Determinate is command-owned in oauth-mux. The first proven
capability is `status`, implemented as a no-token command probe through
`determinate-nixd status`. oauth-mux does not own or rewrite Determinate Nixd's
credential store.

The official Determinate Nix docs describe `determinate-nixd login` as the
FlakeHub login path and `determinate-nixd status` as the command that shows the
current FlakeHub login status:

- Determinate Nix:
  <https://docs.determinate.systems/determinate-nix/>

The official authentication docs describe FlakeHub/Determinate authentication
through generated tokens and Determinate Nixd registration:

- FlakeHub authentication:
  <https://docs.determinate.systems/flakehub/concepts/authentication/>

The separate `fh` CLI also has its own `fh status` command, but this proof does
not depend on `fh` being present. The current built-in provider uses
`determinate-nixd status` because that binary is the installed command owner on
the dogfood host.

## Local Live Proof

Low-impact local proof used the existing `examples/flakehub.config.json`
profile with a temporary oauth-mux state directory. The command probe uses
`auth = none`, so oauth-mux did not read or write a FlakeHub token.

```bash
OMUX_STATE_DIR=$(mktemp -d) \
OMUX_CONFIG=$PWD/examples/flakehub.config.json \
./zig-out/bin/oauth-mux probe --profile flakehub --capability status --json
```

Redacted result:

```json
{
  "provider": "flakehub",
  "account": "work",
  "capability": "status",
  "ok": true,
  "probe_executed": true,
  "probe_status": 200,
  "decision": "use_this",
  "runtime": {
    "readiness": {
      "state": "ready"
    },
    "required_binaries": ["determinate-nixd"]
  },
  "liveness": {
    "summary": "available",
    "state": "live",
    "availability": "available"
  },
  "last_probe": {
    "source": "capability_probe",
    "hint_class": "none",
    "decision": "use_this"
  }
}
```

The FlakeHub `status` capability can now report `local_live_proven`. Provider
level status should remain conservative until logged-out, missing-binary,
timeout, and cache/apply permission states have redacted or synthetic fixture
coverage.

## Next

- Add synthetic command fixtures for logged-out status and missing
  `determinate-nixd`.
- Decide whether `fh status` should be an alternate command capability or only
  documented as an adjacent CLI.
- Keep `fh apply` / cache access / private flake resolution outside the proven
  status capability until those behaviors have their own proof and admission
  policy.
