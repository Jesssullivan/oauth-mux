# oauth-mux — OAuth fallback muxing for AI harness subscriptions

zig := "nix develop --command zig"

default:
    @just --list

# ── Build ──

build:
    {{zig}} build

build-release:
    {{zig}} build -Doptimize=ReleaseSafe

build-small:
    {{zig}} build -Doptimize=ReleaseSmall

# ── Test ──

test:
    {{zig}} build test

# ── Run ──

run *ARGS:
    {{zig}} build run -- {{ARGS}}

version: build
    ./zig-out/bin/oauth-mux version

status: build
    ./zig-out/bin/oauth-mux status --json

health: build
    ./zig-out/bin/oauth-mux health

probe *ARGS: build
    ./zig-out/bin/oauth-mux probe {{ARGS}}

# ── Codex Max operator helpers ──

codex_max_config := "examples/codex-max.config.json"
codex_max_state := "/tmp/oauth-mux-codex-max-health"

codex-max-bootstrap-dirs: build
    ./zig-out/bin/oauth-mux codex bootstrap-dirs

codex-max-validate: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux config validate

codex-max-login ACCOUNT: build
    ./zig-out/bin/oauth-mux codex login {{ACCOUNT}}

codex-max-login-device ACCOUNT: build
    ./zig-out/bin/oauth-mux codex login-device {{ACCOUNT}}

codex-max-login-status ACCOUNT: build
    ./zig-out/bin/oauth-mux codex login-status {{ACCOUNT}}

codex-max-login-status-all: build
    ./zig-out/bin/oauth-mux codex login-status-all

codex-max-onboard: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex onboard

codex-max-canary: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} OMUX_STATE_DIR={{codex_max_state}} ./zig-out/bin/oauth-mux codex canary

codex-max-probe ACCOUNT CAPABILITY="codex-mini": build
    OMUX_CONFIG=$PWD/{{codex_max_config}} OMUX_STATE_DIR={{codex_max_state}} ./zig-out/bin/oauth-mux probe --provider codex --account {{ACCOUNT}} --capability {{CAPABILITY}} --json

codex-max-probe-all CAPABILITY="codex-mini": build
    OMUX_CONFIG=$PWD/{{codex_max_config}} OMUX_STATE_DIR={{codex_max_state}} ./zig-out/bin/oauth-mux codex probe-all --capability {{CAPABILITY}} --json

# ── Cross-compilation ──

release: release-all

release-all:
    {{zig}} build release
    @echo "all release builds complete"

release-local VERSION="0.1.0":
    nix develop --command ./scripts/release-local.sh {{VERSION}}

release-smoke VERSION="0.1.0":
    nix develop --command ./scripts/release-smoke.sh {{VERSION}}

release-handoff VERSION="0.1.0":
    nix develop --command ./scripts/release-handoff.sh {{VERSION}}

registry-dry-run VERSION="0.1.0":
    nix develop --command ./scripts/registry-dry-run.sh {{VERSION}}

npm-deprecate-plan VERSION="0.1.1":
    OMUX_NPM_DEPRECATE_PLAN_ONLY=1 nix develop --command ./scripts/npm-ci-deprecate.sh {{VERSION}}

release-proof VERSION="0.1.0":
    nix develop --command just release-proof-local {{VERSION}}

release-proof-local VERSION="0.1.0":
    ./scripts/release-local.sh {{VERSION}}
    ./scripts/release-smoke.sh {{VERSION}}
    ./scripts/release-handoff.sh {{VERSION}}

release-linux-amd64:
    {{zig}} build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe

release-linux-arm64:
    {{zig}} build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe

release-macos-amd64:
    {{zig}} build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe

release-macos-arm64:
    {{zig}} build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe

release-windows-amd64:
    {{zig}} build -Dtarget=x86_64-windows -Doptimize=ReleaseSafe

release-windows-arm64:
    {{zig}} build -Dtarget=aarch64-windows -Doptimize=ReleaseSafe

# ── Nix ──

nix-build:
    nix build .#

nix-check:
    nix flake check

# ── Validation ──

check:
    nix develop --command just check-local

check-local:
    sh -c 'zig build test && zig build && for cfg in examples/*.config.json; do OMUX_CONFIG="$PWD/$cfg" ./zig-out/bin/oauth-mux config validate; done && ./scripts/e2e-local.sh'
    @echo "all checks passed"

e2e:
    nix develop --command just e2e-local

e2e-local:
    zig build
    ./scripts/e2e-local.sh

live-qa:
    nix develop --command ./scripts/live-provider-qa.sh

# ── Config ──

init: build
    ./zig-out/bin/oauth-mux init

config-path: build
    ./zig-out/bin/oauth-mux config path

config-validate: build
    ./zig-out/bin/oauth-mux config validate

# ── Daemon ──

daemon-start: build
    ./zig-out/bin/oauth-mux daemon start

daemon-stop: build
    ./zig-out/bin/oauth-mux daemon stop

daemon-status: build
    ./zig-out/bin/oauth-mux daemon status

# ── Shell integration ──

completions-fish: build
    ./zig-out/bin/oauth-mux completions fish

completions-zsh: build
    ./zig-out/bin/oauth-mux completions zsh

completions-bash: build
    ./zig-out/bin/oauth-mux completions bash

# ── Utilities ──

clean:
    rm -rf zig-out .zig-cache

size: build-release
    @ls -lh zig-out/bin/oauth-mux

# ── E2E smoke test ──

smoke: build
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== version ==="
    ./zig-out/bin/oauth-mux version
    echo "=== config path ==="
    ./zig-out/bin/oauth-mux config path
    echo "=== status ==="
    ./zig-out/bin/oauth-mux status --json 2>/dev/null || echo "(no config)"
    echo "=== health ==="
    ./zig-out/bin/oauth-mux health 2>/dev/null || echo "(no health data)"
    echo "=== daemon status ==="
    ./zig-out/bin/oauth-mux daemon status 2>/dev/null
    echo "=== smoke passed ==="
