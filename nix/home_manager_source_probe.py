"""Local read-only exact HM pair metadata; byte proof remains pending."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import sqlite3
import time
from home_manager_inputs import paired_lock
from home_manager_io import read_regular


def probe(lock, locate, database):
    locked = paired_lock(lock)
    deadline = time.monotonic() + 10
    candidates = {}
    for name in ("home-manager", "nixpkgs"):
        digest = base64.b64decode(locked[name]["narHash"].removeprefix("sha256-"), validate=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("paired-metadata-deadline")
        candidates[name] = locate(database, "sha256:" + digest.hex(), seconds=remaining)
    return {"scope": "local-operator-bootstrap-metadata", "passed": all(candidates.values()),
            "source_candidates": candidates, "byte_verification": "pending-declared-nar-action"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--probe-library", required=True,
                        help="Bazel-declared tools/nix_source_probe.py location")
    args = parser.parse_args()
    try:
        data = read_regular(args.lock)
        spec = importlib.util.spec_from_file_location("declared_nix_source_probe", args.probe_library)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = probe(json.loads(data), module.locate, module.DATABASE)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["passed"] else 2
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        print(json.dumps({"scope": "local-operator-bootstrap-metadata", "passed": False,
                          "source_candidates": {}, "gate": "read-only-paired-metadata-unavailable"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
