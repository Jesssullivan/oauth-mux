"""Stage declared inputs and emit bounded retained-byte selection facts.

Run only in the declared Bazel/Nix lane. This producer invokes no build, service,
registration, daemon or browser. The stage's declared patchelf action remains
part of portable assembly; selection does not attest running executable bytes.
"""
import argparse
import json
from pathlib import Path
import re
import sys

from dev_generation import GenerationError, MAX_RECEIPT, parse, select_generation
from dev_stage import StageError, artifact, digest, stage_generation

MAX_OUTPUT = 8192
SCOPE = "development-retained-generation-selection"


class SelectedStageError(ValueError):
    pass


def input_hashes(core, daemon, extension):
    return {name: digest(artifact(path)) for name, path in (
        ("core", core), ("daemon", daemon), ("extension", extension))}


def encode(facts):
    output = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(output) > MAX_OUTPUT:
        raise SelectedStageError("selection-output-bound")
    return output


def produce(root, core, daemon, extension, metadata_path, *, replace_owned=False,
            runtime_files=None, patchelf=None, ca_bundle=None):
    # Independent hashes come from the declared input files, not stage output
    # metadata. A second observation detects inputs drifting during assembly.
    expected = input_hashes(core, daemon, extension)
    metadata_bytes = artifact(metadata_path)
    if len(metadata_bytes) > MAX_RECEIPT:
        raise SelectedStageError("metadata-byte-bound")
    metadata = parse(metadata_bytes)
    if type(metadata) is not dict:
        raise SelectedStageError("metadata-shape")
    outcome = stage_generation(root, core, daemon, extension, metadata, replace_owned,
                               runtime_files=runtime_files, patchelf=patchelf, ca_bundle=ca_bundle)
    if input_hashes(core, daemon, extension) != expected:
        raise SelectedStageError("declared-inputs-changed")
    selected = select_generation(root, outcome.generation, outcome.receipt_sha256,
                                 expected_artifacts=expected, require_portable=True)
    version = selected.extension_version
    if not re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}", version) or any(
            int(component) > 65535 for component in version.split(".")):
        raise SelectedStageError("extension-version-shape")
    facts = {"schemaVersion": 1, "scope": SCOPE, "generation": selected.generation,
             "receiptSha256": selected.receipt_sha256, "artifacts": dict(selected.artifact_sha256),
             "extension": {"id": selected.extension_id, "version": version},
             "channel": "development", "instance": "dev", "distribution": selected.distribution,
             "selectedBytesVerified": True, "daemonRestarted": False, "chromiumReloaded": False,
             "providerAccess": False, "liveExecutableAttributed": False, "atomicExecutionWitness": False}
    encode(facts)
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "core", "daemon", "extension", "metadata"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--replace-owned", action="store_true")
    parser.add_argument("--runtime-file", type=Path, action="append", default=[])
    parser.add_argument("--runtime-files", default="")
    parser.add_argument("--patchelf", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    args = parser.parse_args()
    try:
        if len(args.runtime_files) > 1024 * 1024:
            raise SelectedStageError("runtime-path-list-bound")
        runtime_files = list(args.runtime_file)
        runtime_files.extend(Path(value) for value in args.runtime_files.split())
        if len(runtime_files) > 4096:
            raise SelectedStageError("runtime-path-count-bound")
        facts = produce(args.root, args.core, args.daemon, args.extension, args.metadata,
                        replace_owned=args.replace_owned, runtime_files=runtime_files,
                        patchelf=args.patchelf, ca_bundle=args.ca_bundle)
        sys.stdout.buffer.write(encode(facts))
    except (StageError, GenerationError, SelectedStageError, OSError, ValueError, TypeError, KeyError, RecursionError):
        # Never forward native diagnostics, paths, source contents or arbitrary
        # metadata fields. Retained private files remain available for review.
        print(json.dumps({"scope": SCOPE, "result": "refused"}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
