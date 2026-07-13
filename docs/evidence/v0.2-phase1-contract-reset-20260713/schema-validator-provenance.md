# Managed-harness schema validator provenance

Claim class: source/toolchain declaration only. Final remote proof is pending.

The managed-harness instance gate uses `check-jsonschema` only in the Nix
development and validation shell. It is not linked into the Zig binary, copied
into release artifacts, or required at runtime.

| Field | Value |
| --- | --- |
| Package | `check-jsonschema 0.37.1` |
| Source | existing locked `nixpkgs` input |
| nixpkgs revision | `0726a0ecb6d4e08f6adced58726b95db924cef57` |
| Homepage | `https://github.com/python-jsonschema/check-jsonschema` |
| License | Apache-2.0; free and redistributable in nixpkgs metadata |
| Purpose | Draft 2020-12 positive/negative contract-instance validation |

Verification commands:

```sh
nix develop --command check-jsonschema --version
nix eval --json --impure --expr \
  '(builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.aarch64-darwin.check-jsonschema.meta'
```

`build.zig.zon` is unchanged by this addition. The product remains pure Zig
with no external runtime dependency. The checked Python helper uses only the
standard library to enforce cross-element handle relationships that Draft
2020-12 cannot express by value.
