# Home Manager Lane

Updated: 2026-05-18

oauth-mux exposes a Home Manager module from the flake:

```nix
inputs.oauth-mux.url = "github:Jesssullivan/oauth-mux";
```

Then import the module in your Home Manager configuration:

```nix
{
  imports = [
    inputs.oauth-mux.homeManagerModules.default
  ];

  programs.oauth-mux.enable = true;
}
```

By default this installs only the `oauth-mux` binary. It does not install a
`codex` command, so it does not unexpectedly shadow an upstream Codex CLI that
is already on PATH.

To intentionally install the managed Codex shim:

```nix
{
  imports = [
    inputs.oauth-mux.homeManagerModules.default
  ];

  programs.oauth-mux = {
    enable = true;
    codexShim.enable = true;
  };
}
```

With `codexShim.enable = true`, the Home Manager profile installs the same
managed `codex` shim as the Nix package. Native admin commands such as
`codex --version`, `codex login`, `codex logout`, `codex auth`, and `codex mcp`
pass through to the native upstream Codex CLI. Managed session commands such as
`codex resume` enter `oauth-mux codex` only when PATH resolves this shim.

The module chooses between two flake packages:

- `packages.<system>.oauth-mux`: binary-only package, no `codex` shim.
- `packages.<system>.withCodexShim`: `oauth-mux` plus the managed `codex` shim.

Smoke the lane from the repo with:

```bash
just home-manager-smoke
```

That smoke builds both package variants and verifies that the shimmed package
passes native `codex --version` through to a native Codex stub.
