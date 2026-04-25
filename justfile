# oauth-mux — OAuth fallback muxing for AI harness subscriptions

default:
    @just --list

# ── Build ──

build:
    zig build

build-release:
    zig build -Doptimize=ReleaseSafe

build-small:
    zig build -Doptimize=ReleaseSmall

# ── Test ──

test:
    zig build test

test-verbose:
    zig build test 2>&1

# ── Run ──

run *ARGS:
    zig build run -- {{ARGS}}

version:
    zig build run -- version

status:
    zig build run -- status --json

# ── Cross-compilation release ──

release:
    zig build release

release-linux-amd64:
    zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe

release-linux-arm64:
    zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe

release-macos-amd64:
    zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe

release-macos-arm64:
    zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe

# ── Nix ──

nix-build:
    nix build .#

nix-check:
    nix flake check

nix-shell:
    nix develop

# ── Validation ──

check: test
    @echo "all checks passed"

# ── Clean ──

clean:
    rm -rf zig-out .zig-cache

# ── Config ──

init:
    zig build run -- init

config-path:
    zig build run -- config path

config-validate:
    zig build run -- config validate

# ── Binary size ──

size: build-release
    @ls -lh zig-out/bin/oauth-mux 2>/dev/null || echo "build first"
