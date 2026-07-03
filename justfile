# oauth-mux — OAuth fallback muxing for AI harness subscriptions

zig := "nix develop --command zig"
release_version := `./scripts/project-version.sh`

default:
    @just --list

# ── Build ──

build REF="":
    ./scripts/remote-validate.sh build {{REF}}

build-local:
    {{zig}} build

build-release REF="":
    ./scripts/remote-validate.sh build-release {{REF}}

build-release-local:
    {{zig}} build -Doptimize=ReleaseSafe

build-small REF="":
    ./scripts/remote-validate.sh build-small {{REF}}

build-small-local:
    {{zig}} build -Doptimize=ReleaseSmall

# ── Test ──

test REF="":
    ./scripts/remote-validate.sh test {{REF}}

test-local:
    {{zig}} build test

# ── Run ──

run *ARGS:
    {{zig}} build run -- {{ARGS}}

version: build-local
    ./zig-out/bin/oauth-mux version

install-local-dogfood:
    nix develop --command ./scripts/install-local-dogfood.sh

install-local-dogfood-shim:
    OMUX_DOGFOOD_INSTALL_CODEX_SHIM=1 nix develop --command ./scripts/install-local-dogfood.sh

uninstall-local-dogfood:
    ./scripts/uninstall-local-dogfood.sh

# ── Keepalive service units (TIN-1830, operator-explicit) ──

keepalive-service-install:
    ./scripts/keepalive-service.sh install

keepalive-service-uninstall:
    ./scripts/keepalive-service.sh uninstall

keepalive-service-status:
    ./scripts/keepalive-service.sh status

keepalive-service-verify:
    ./scripts/keepalive-service.sh verify

status: build-local
    ./zig-out/bin/oauth-mux status --json

doctor: build-local
    ./zig-out/bin/oauth-mux doctor

report: build-local
    ./zig-out/bin/oauth-mux report --redacted

providers: build-local
    ./zig-out/bin/oauth-mux providers list

health: build-local
    ./zig-out/bin/oauth-mux health

probe *ARGS: build-local
    ./zig-out/bin/oauth-mux probe {{ARGS}}

# ── Codex Max operator helpers ──

codex_max_config := "examples/codex-max.config.json"

codex-max-bootstrap-dirs: build-local
    ./zig-out/bin/oauth-mux codex bootstrap-dirs

codex-max-validate: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux config validate

codex-max-login ACCOUNT: build-local
    ./zig-out/bin/oauth-mux codex login {{ACCOUNT}}

codex-max-login-device ACCOUNT: build-local
    ./zig-out/bin/oauth-mux codex login-device {{ACCOUNT}}

codex-max-login-status ACCOUNT: build-local
    ./zig-out/bin/oauth-mux codex login-status {{ACCOUNT}}

codex-max-login-status-all: build-local
    ./zig-out/bin/oauth-mux codex login-status-all

codex-max-onboard: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex onboard

codex-max-setup: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux setup codex

codex-max-canary: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex canary

paid-cohort-soak-snapshot: build-local
    ./scripts/paid-cohort-soak-snapshot.sh

codex-max-soak-snapshot: paid-cohort-soak-snapshot

dogfood-process-snapshot OUT="dist/dogfood/process":
    python3 ./scripts/dogfood-process-snapshot.py --out {{OUT}}

dogfood-process-snapshot-json:
    python3 ./scripts/dogfood-process-snapshot.py --json

codex-max-process-snapshot OUT="dist/dogfood/process":
    python3 ./scripts/dogfood-process-snapshot.py --out {{OUT}} --tag codex-max

codex-max-live-qa: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex live-qa

codex-max-live-qa-confirmed: build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex live-qa --confirm-spend

codex-max-repair-plan CAPABILITY="codex-max": build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux repair-plan --profile {{CAPABILITY}} --capability {{CAPABILITY}} --json

codex-max-config-candidate OUTPUT="/tmp/oauth-mux-codex-max.config.json": build-local
    ./zig-out/bin/oauth-mux codex config-candidate --output {{OUTPUT}}

codex-max-config-merge CANDIDATE="/tmp/oauth-mux-codex-max.config.json": build-local
    ./zig-out/bin/oauth-mux codex config-merge --candidate {{CANDIDATE}}

codex-max-probe ACCOUNT CAPABILITY="codex-mini": build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux probe --provider codex --account {{ACCOUNT}} --capability {{CAPABILITY}} --json

codex-max-probe-all CAPABILITY="codex-mini": build-local
    OMUX_CONFIG=$PWD/{{codex_max_config}} ./zig-out/bin/oauth-mux codex probe-all --capability {{CAPABILITY}} --json

# ── Cross-compilation ──

release VERSION=release_version REF="":
    OMUX_REMOTE_RELEASE_VERSION={{VERSION}} ./scripts/remote-validate.sh release-proof {{REF}}

release-all-local:
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

release-proof VERSION=release_version REF="":
    OMUX_REMOTE_RELEASE_VERSION={{VERSION}} ./scripts/remote-validate.sh release-proof {{REF}}

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

home-manager-smoke:
    ./scripts/smoke-home-manager-lane.sh

# ── Validation ──

check REF="":
    ./scripts/remote-validate.sh check {{REF}}

check-local:
    ./scripts/check-local.sh
    @echo "all checks passed"

e2e REF="":
    ./scripts/remote-validate.sh e2e {{REF}}

e2e-local:
    zig build
    ./scripts/e2e-local.sh

first-run-e2e REF="":
    ./scripts/remote-validate.sh first-run-e2e {{REF}}

first-run-e2e-local:
    zig build
    ./scripts/first-run-e2e.sh

live-qa:
    nix develop --command ./scripts/live-provider-qa.sh

# ── Remote validation (GloriousFlywheel runner dispatch) ──

remote-validate TARGET="check" REF="":
    ./scripts/remote-validate.sh {{TARGET}} {{REF}}

remote-check REF="":
    ./scripts/remote-validate.sh check {{REF}}

remote-test REF="":
    ./scripts/remote-validate.sh test {{REF}}

remote-build REF="":
    ./scripts/remote-validate.sh build {{REF}}

remote-build-release REF="":
    ./scripts/remote-validate.sh build-release {{REF}}

remote-build-small REF="":
    ./scripts/remote-validate.sh build-small {{REF}}

remote-e2e REF="":
    ./scripts/remote-validate.sh e2e {{REF}}

remote-first-run-e2e REF="":
    ./scripts/remote-validate.sh first-run-e2e {{REF}}

remote-release-proof REF="" VERSION=release_version:
    OMUX_REMOTE_RELEASE_VERSION={{VERSION}} ./scripts/remote-validate.sh release-proof {{REF}}

# ── Bazel / REAPI candidate (TIN-2105, not proof authority yet) ──

flywheel-zig-info *ARGS:
    ./scripts/gloriousflywheel-bazel.sh info {{ARGS}}

flywheel-zig-build *ARGS:
    ./scripts/gloriousflywheel-bazel.sh build //:zig_build {{ARGS}}

flywheel-zig-test *ARGS:
    ./scripts/gloriousflywheel-bazel.sh test //:zig_build_test {{ARGS}}

flywheel-zig-proof-dispatch *ARGS:
    ./scripts/dispatch-zig-reapi-proof.sh {{ARGS}}

flywheel-zig-proof-verify RUN_ID *ARGS:
    ./scripts/verify-zig-reapi-proof.sh --run-id {{RUN_ID}} {{ARGS}}

# ── Delivery gates (TIN-2105 W1-2: config hygiene, endpoint + secrets) ──

# Checked-in Bazel config must never pin remote cache/executor endpoints;
# endpoint authority is env-only (BAZEL_REMOTE_CACHE, BAZEL_REMOTE_EXECUTOR,
# GF_BAZEL_SUBSTRATE_MODE, GF_BAZEL_REMOTE_UPLOAD). Guard list lives in the
# script, explicit and commented.
endpoint-free-check:
    ./scripts/endpoint-free-check.sh

# gitleaks over the working tree with the repo .gitleaks.toml (house shape).
# Fails closed with a clear message when gitleaks and nix are both missing.
secrets-scan-dir:
    ./scripts/secrets-scan-dir.sh

# ── Broker MCP smoke (provider-neutral regression catch-net) ──

smoke-broker:
    nix develop --command just smoke-broker-local

smoke-broker-local:
    zig build
    ./scripts/smoke-broker.sh

smoke-broker-claude:
    nix develop --command just smoke-broker-claude-local

smoke-broker-claude-local:
    zig build
    ./scripts/smoke-broker-claude.sh

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

init: build-local
    ./zig-out/bin/oauth-mux init

config-path: build-local
    ./zig-out/bin/oauth-mux config path

config-validate: build-local
    ./zig-out/bin/oauth-mux config validate

# ── Daemon ──

daemon-run: build-local
    ./zig-out/bin/oauth-mux daemon run

daemon-start: build-local
    ./zig-out/bin/oauth-mux daemon start

daemon-stop: build-local
    ./zig-out/bin/oauth-mux daemon stop

daemon-status: build-local
    ./zig-out/bin/oauth-mux daemon status --json

daemon-events: build-local
    ./zig-out/bin/oauth-mux daemon events --json

daemon-tick PROFILE="codex-max" CAPABILITY="codex-max": build-local
    ./zig-out/bin/oauth-mux daemon tick --once --profile {{PROFILE}} --capability {{CAPABILITY}} --json

daemon-loop PROFILE="codex-max" CAPABILITY="codex-max" ITERATIONS="2" INTERVAL_MS="0": build-local
    ./zig-out/bin/oauth-mux daemon tick --loop --iterations {{ITERATIONS}} --interval-ms {{INTERVAL_MS}} --profile {{PROFILE}} --capability {{CAPABILITY}} --json

daemon-loop-host PROFILE="codex-max" CAPABILITY="codex-max" INTERVAL_MS="60000": build-local
    ./zig-out/bin/oauth-mux daemon loop --profile {{PROFILE}} --capability {{CAPABILITY}} --interval-ms {{INTERVAL_MS}}

daemon-loop-smoke PROFILE="codex-max" CAPABILITY="codex-max" ITERATIONS="3" INTERVAL_MS="500": build-local
    ./zig-out/bin/oauth-mux daemon loop --profile {{PROFILE}} --capability {{CAPABILITY}} --iterations {{ITERATIONS}} --interval-ms {{INTERVAL_MS}}

# ── Shell integration ──

completions-fish: build-local
    ./zig-out/bin/oauth-mux completions fish

completions-zsh: build-local
    ./zig-out/bin/oauth-mux completions zsh

completions-bash: build-local
    ./zig-out/bin/oauth-mux completions bash

# ── Utilities ──

clean:
    rm -rf zig-out .zig-cache

size: build-release-local
    @ls -lh zig-out/bin/oauth-mux

# ── E2E smoke test ──

smoke: build-local
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
