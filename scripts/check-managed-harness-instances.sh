#!/usr/bin/env sh
# Validate checked v2 contract instances against Draft 2020-12 and semantic
# relationships that JSON Schema cannot compare across array elements.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCHEMA="$ROOT/schemas/managed-harness-jsonrpc-v2.schema.json"
FIXTURES="$ROOT/test/fixtures/managed-harness-v2"
VALIDATOR="$ROOT/scripts/validate-managed-harness-instance.py"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/omux-managed-harness.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

if ! command -v check-jsonschema >/dev/null 2>&1; then
  printf '%s\n' 'check-managed-harness-instances: check-jsonschema is required from the Nix dev shell' >&2
  exit 2
fi

for fixture in "$FIXTURES"/valid/*.json "$FIXTURES"/invalid-semantic/*.json; do
  if ! check-jsonschema --schemafile "$SCHEMA" "$fixture" >/dev/null; then
    printf 'check-managed-harness-instances: schema rejected expected-valid fixture %s\n' "${fixture#"$ROOT"/}" >&2
    exit 1
  fi
done

for fixture in "$FIXTURES"/invalid-schema/*.json; do
  if check-jsonschema --schemafile "$SCHEMA" "$fixture" >/dev/null 2>&1; then
    printf 'check-managed-harness-instances: schema accepted invalid fixture %s\n' "${fixture#"$ROOT"/}" >&2
    exit 1
  fi
done

python3 - "$FIXTURES/valid/surface-info.json" "$TMP_DIR" <<'PY'
import copy
import json
import pathlib
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
destination = pathlib.Path(sys.argv[2])

policy_drift = copy.deepcopy(source)
policy_drift["result"]["policy"]["carrier"]["capability_bits"] = 128
(destination / "policy-value-drift.json").write_text(json.dumps(policy_drift), encoding="utf-8")

method_duplication = copy.deepcopy(source)
method_duplication["result"]["methods"][1]["name"] = "surface/info"
(destination / "method-duplication.json").write_text(json.dumps(method_duplication), encoding="utf-8")
PY

for fixture in "$TMP_DIR"/*.json; do
  if check-jsonschema --schemafile "$SCHEMA" "$fixture" >/dev/null 2>&1; then
    printf 'check-managed-harness-instances: schema accepted generated negative %s\n' "$(basename "$fixture")" >&2
    exit 1
  fi
done

for fixture in "$FIXTURES"/valid/*.json; do
  python3 "$VALIDATOR" "$fixture"
done

for fixture in "$FIXTURES"/invalid-semantic/*.json; do
  if python3 "$VALIDATOR" "$fixture" >/dev/null 2>&1; then
    printf 'check-managed-harness-instances: semantic validator accepted invalid fixture %s\n' "${fixture#"$ROOT"/}" >&2
    exit 1
  fi
done

printf '%s\n' 'managed-harness v2 schema and semantic fixtures: ok'
