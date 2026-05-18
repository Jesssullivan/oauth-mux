# oauth-mux — OAuth fallback muxing for AI harness subscriptions

zig := "nix develop --command zig"
release_version := `./scripts/project-version.sh`

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

install-local-dogfood:
    nix develop --command ./scripts/install-local-dogfood.sh

install-local-dogfood-shim:
    OMUX_DOGFOOD_INSTALL_CODEX_SHIM=1 nix develop --command ./scripts/install-local-dogfood.sh

uninstall-local-dogfood:
    ./scripts/uninstall-local-dogfood.sh

status: build
    ./zig-out/bin/oauth-mux status --json

doctor: build
    ./zig-out/bin/oauth-mux doctor

report: build
    ./zig-out/bin/oauth-mux report --redacted

providers: build
    ./zig-out/bin/oauth-mux providers list

health: build
    ./zig-out/bin/oauth-mux health

probe *ARGS: build
    ./zig-out/bin/oauth-mux probe {{ARGS}}

# ── Codex Max operator helpers ──

codex_max_config := "examples/codex-max.config.json"

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

codex-max-setup: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux setup codex

codex-max-canary: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex canary

paid-cohort-soak-snapshot: build
    ./scripts/paid-cohort-soak-snapshot.sh

codex-max-soak-snapshot: paid-cohort-soak-snapshot

codex-max-live-qa: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex live-qa

codex-max-live-qa-confirmed: build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex live-qa --confirm-spend

codex-max-repair-plan CAPABILITY="codex-max": build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux repair-plan --profile {{CAPABILITY}} --capability {{CAPABILITY}} --json

codex-max-config-candidate OUTPUT="/tmp/oauth-mux-codex-max.config.json": build
    ./zig-out/bin/oauth-mux codex config-candidate --output {{OUTPUT}}

codex-max-config-merge CANDIDATE="/tmp/oauth-mux-codex-max.config.json": build
    ./zig-out/bin/oauth-mux codex config-merge --candidate {{CANDIDATE}}

codex-max-probe ACCOUNT CAPABILITY="codex-mini": build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux probe --provider codex --account {{ACCOUNT}} --capability {{CAPABILITY}} --json

codex-max-probe-all CAPABILITY="codex-mini": build
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex probe-all --capability {{CAPABILITY}} --json

# ── Cross-compilation ──

release: release-all

release-all:
    {{zig}} build release
    @echo "all release builds complete"

release-local VERSION=release_version:
    nix develop --command ./scripts/release-local.sh {{VERSION}}

release-smoke VERSION=release_version:
    nix develop --command ./scripts/release-smoke.sh {{VERSION}}

release-handoff VERSION=release_version:
    nix develop --command ./scripts/release-handoff.sh {{VERSION}}

registry-dry-run VERSION=release_version:
    nix develop --command ./scripts/registry-dry-run.sh {{VERSION}}

system-package-qa VERSION=release_version:
    ./scripts/system-package-install-qa.sh {{VERSION}}

homebrew-qa VERSION=release_version:
    ./scripts/homebrew-install-qa.sh {{VERSION}}

npm-deprecate-plan VERSION="0.1.1":
    OMUX_NPM_DEPRECATE_PLAN_ONLY=1 nix develop --command ./scripts/npm-ci-deprecate.sh {{VERSION}}

release-proof VERSION=release_version:
    nix develop --command just release-proof-local {{VERSION}}

release-proof-local VERSION=release_version:
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
    ./scripts/check-local.sh
    @echo "all checks passed"

e2e:
    nix develop --command just e2e-local

e2e-local:
    zig build
    ./scripts/e2e-local.sh

first-run-e2e:
    nix develop --command just first-run-e2e-local

first-run-e2e-local:
    zig build
    ./scripts/first-run-e2e.sh

live-qa:
    nix develop --command ./scripts/live-provider-qa.sh

# ── Broker MCP smoke (provider-neutral regression catch-net) ──

smoke-broker:
    nix develop --command just smoke-broker-local

smoke-broker-local:
    zig build
    ./scripts/smoke-broker.sh

# ── Codex adapter synthetic smoke (no provider traffic) ──

smoke-codex-cli-ux:
    nix develop --command just smoke-codex-cli-ux-local

smoke-codex-cli-ux-local:
    zig build
    ./scripts/smoke-codex-cli-ux.sh

smoke-codex-acceptance:
    nix develop --command just smoke-codex-acceptance-local

smoke-codex-acceptance-local:
    zig build
    ./scripts/smoke-codex-acceptance.sh

# ── Codex adapter concurrent-session smoke (no provider traffic) ──

smoke-codex-concurrent-sessions:
    nix develop --command just smoke-codex-concurrent-sessions-local

smoke-codex-concurrent-sessions-local:
    zig build
    ./scripts/smoke-codex-concurrent-sessions.sh

# ── Codex adapter same-account refresh smoke (no provider traffic) ──

smoke-codex-child-refresh:
    nix develop --command just smoke-codex-child-refresh-local

smoke-codex-child-refresh-local:
    zig build
    ./scripts/smoke-codex-child-refresh.sh

# ── Codex adapter negative-path smokes (no provider traffic) ──

smoke-codex-tier-insufficient:
    nix develop --command just smoke-codex-tier-insufficient-local

smoke-codex-tier-insufficient-local:
    zig build
    ./scripts/smoke-codex-tier-insufficient.sh

smoke-codex-all-exhausted:
    nix develop --command just smoke-codex-all-exhausted-local

smoke-codex-all-exhausted-local:
    zig build
    ./scripts/smoke-codex-all-exhausted.sh

smoke-codex-401-propagation:
    nix develop --command just smoke-codex-401-propagation-local

smoke-codex-401-propagation-local:
    zig build
    ./scripts/smoke-codex-401-propagation.sh

smoke-codex-provider-degraded:
    nix develop --command just smoke-codex-provider-degraded-local

smoke-codex-provider-degraded-local:
    zig build
    ./scripts/smoke-codex-provider-degraded.sh

# ── Codex cassette replay smoke (no provider traffic) ──

smoke-codex-cassette-replay:
    nix develop --command just smoke-codex-cassette-replay-local

smoke-codex-cassette-replay-local:
    ./scripts/smoke-codex-cassette-replay.sh

smoke-codex-cassette-all-exhausted:
    nix develop --command just smoke-codex-cassette-all-exhausted-local

smoke-codex-cassette-all-exhausted-local:
    zig build
    ./scripts/smoke-codex-cassette-all-exhausted.sh

smoke-codex-capture-review:
    nix develop --command just smoke-codex-capture-review-local

smoke-codex-capture-review-local:
    ./scripts/smoke-codex-capture-review.sh

smoke-codex-status-summary:
    ./scripts/smoke-codex-status-summary.sh

smoke-github-tracker-comment:
    ./scripts/smoke-github-tracker-comment.sh

github-tracker-comment ISSUE BODY_FILE:
    ./scripts/github-tracker-comment.sh {{ISSUE}} {{BODY_FILE}}

# ── Config ──

init: build
    ./zig-out/bin/oauth-mux init

config-path: build
    ./zig-out/bin/oauth-mux config path

config-validate: build
    ./zig-out/bin/oauth-mux config validate

# ── Daemon ──

daemon-run: build
    ./zig-out/bin/oauth-mux daemon run

daemon-start: build
    ./zig-out/bin/oauth-mux daemon start

daemon-stop: build
    ./zig-out/bin/oauth-mux daemon stop

daemon-status: build
    ./zig-out/bin/oauth-mux daemon status --json

daemon-events: build
    ./zig-out/bin/oauth-mux daemon events --json

daemon-tick PROFILE="codex-max" CAPABILITY="codex-max": build
    ./zig-out/bin/oauth-mux daemon tick --once --profile {{PROFILE}} --capability {{CAPABILITY}} --json

daemon-loop PROFILE="codex-max" CAPABILITY="codex-max" ITERATIONS="2" INTERVAL_MS="0": build
    ./zig-out/bin/oauth-mux daemon tick --loop --iterations {{ITERATIONS}} --interval-ms {{INTERVAL_MS}} --profile {{PROFILE}} --capability {{CAPABILITY}} --json

daemon-loop-host PROFILE="codex-max" CAPABILITY="codex-max" INTERVAL_MS="60000": build
    ./zig-out/bin/oauth-mux daemon loop --profile {{PROFILE}} --capability {{CAPABILITY}} --interval-ms {{INTERVAL_MS}}

daemon-loop-smoke PROFILE="codex-max" CAPABILITY="codex-max" ITERATIONS="3" INTERVAL_MS="500": build
    ./zig-out/bin/oauth-mux daemon loop --profile {{PROFILE}} --capability {{CAPABILITY}} --iterations {{ITERATIONS}} --interval-ms {{INTERVAL_MS}}

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
