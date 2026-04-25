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

# ── Cross-compilation ──

release-all: release-linux-amd64 release-linux-arm64 release-macos-amd64 release-macos-arm64
    @echo "all release builds complete"

release-linux-amd64:
    {{zig}} build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe

release-linux-arm64:
    {{zig}} build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe

release-macos-amd64:
    {{zig}} build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe

release-macos-arm64:
    {{zig}} build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe

# ── Nix ──

nix-build:
    nix build .#

nix-check:
    nix flake check

# ── Validation ──

check: test build
    @echo "all checks passed"

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
