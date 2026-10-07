"""Declared exact-source HM evaluation; no fetch, realization or activation."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from evaluation_runner import EvaluationFailure, command, evaluate, hash_command
from home_manager_inputs import paired_sources
from home_manager_io import read_json


def nix_literal(value):
    return json.dumps(value).replace("${", r"\${")


def validated_artifact(artifact):
    if not isinstance(artifact, dict):
        raise ValueError("artifact-input-incomplete")
    patterns = {"directory": r"/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+",
                "narHash": r"sha256-[A-Za-z0-9+/]{43}=", "sourceRevision": r"[0-9a-f]{40}",
                "channel": r"(?:development|release)"}
    for key, pattern in patterns.items():
        value = artifact.get(key)
        if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(pattern, value):
            raise ValueError("artifact-input-invalid")
    if any(component in (".", "..") for component in artifact["directory"].split("/")):
        raise ValueError("artifact-path-invalid")
    return artifact


def evaluation_command(nix, expression, sources, system, artifact):
    if system not in ("x86_64-linux", "aarch64-linux"):
        raise ValueError("home-manager-platform-unqualified")
    validated_artifact(artifact)
    # Nix literals use JSON escaping, never shell interpolation. The consumer
    # performs manifest/channel/revision/path validation and NAR-bound import.
    literal = nix_literal
    code = ("let r = import " + literal(str(Path(expression).resolve())) + " {"
            + " pkgs = import " + literal(sources["nixpkgs"]["source"])
            + " { system = " + literal(system) + "; config = {}; overlays = []; };"
            + " homeManagerSource = " + literal(sources["home-manager"]["source"]) + ";"
            + " artifactDirectory = " + literal(artifact["directory"]) + ";"
            + " artifactNarHash = " + literal(artifact["narHash"]) + ";"
            + " artifactSourceRevision = " + literal(artifact["sourceRevision"]) + ";"
            + " channel = " + literal(artifact["channel"]) + "; }; in {"
            + ' genuineModule = r.scope == "genuine-module-evaluation-only";'
            + ' activationUnproved = r.activation == "unproved";'
            + ' bytesUnverified = r.generatedBytes == "unrealized-unverified";'
            + ' witnessScope = r.serviceWitness.scope == "definition-only-not-activation";'
            + ' manifestBound = r.serviceWitness.artifactManifestSha256 == r.artifactManifestSha256;'
            + ' recordGenerated = builtins.stringLength (toString r.recordSource) > 0; }')
    argv = command(nix, expression, sources["nixpkgs"]["source"], system)
    argv[-1] = code
    return argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("nix", "expression", "lock", "home-manager-input", "nixpkgs-input", "artifact-input"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    phase = "paired-input"
    try:
        read = read_json
        metadata = {"home-manager": read(args.home_manager_input), "nixpkgs": read(args.nixpkgs_input)}
        sources = paired_sources(read(args.lock), metadata)
        artifact = validated_artifact(read(args.artifact_input))
        system = metadata["nixpkgs"].get("system")
        if metadata["home-manager"].get("system") != system:
            raise ValueError("paired-source-system-mismatch")
        with tempfile.TemporaryDirectory(prefix="omux-hm-evaluation-", dir=os.environ.get("TEST_TMPDIR")) as home:
            for name in ("home-manager", "nixpkgs"):
                phase = name + "-nar"
                evaluate(hash_command(args.nix, sources[name]["source"]), home, sources[name]["narHash"])
            phase = "genuine-home-manager-module"
            predicates = evaluate(evaluation_command(args.nix, args.expression, sources, system, artifact), home)
        print(json.dumps({"passed": True, "scope": "genuine-module-evaluation-only",
                          "sourceNars": "verified", "activation": "unproved", "predicates": predicates}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        result = {"passed": False, "phase": phase, "activation": "unproved",
                  "category": error.category if isinstance(error, EvaluationFailure) else "declared-input-unavailable"}
        if isinstance(error, EvaluationFailure):
            result["diagnostic"] = error.diagnostic
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
