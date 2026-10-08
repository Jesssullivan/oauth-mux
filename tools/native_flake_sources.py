"""Declared byte verification of the three locked native-flake source roles.

Repository setup reads inert filesystem metadata. Only the declared Bazel
action opens regular-file labels and proves their canonical NAR hashes.
Source proof does not authorize execution or establish a complete build seed.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from nar_descriptor import MAX_ENTRIES, MAX_METADATA_BYTES, describe, hash_descriptor, validate_descriptor
from nix_source_probe import native_source_hashes
from verify_declared_nars import metadata_alias_roots, open_declared

ROLES = ("nixpkgs", "flake-utils", "systems")
MAX_LOCK_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SECONDS = 600
SOURCE = re.compile(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-(?:[A-Za-z0-9._+-]{1,180}-)?source")


def locked_sources(content):
    if len(content) > MAX_LOCK_BYTES:
        raise ValueError("native-source-lock-bound")
    lock = json.loads(content)
    if type(lock.get("version")) is not int or lock["version"] != 7:
        raise ValueError("native-source-lock-version")
    hashes = native_source_hashes(lock)
    inputs = lock["nodes"][lock["root"]]["inputs"]
    utils = inputs["flake-utils"]
    nodes = {"nixpkgs": inputs["nixpkgs"], "flake-utils": utils,
             "systems": lock["nodes"][utils]["inputs"]["systems"]}
    result = {}
    for role in ROLES:
        node = nodes[role]
        revision = lock["nodes"][node]["locked"]["rev"]
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("native-source-revision")
        result[role] = {"node": node, "revision": revision, "narHash": hashes[role]}
    return result


def validate_selection(sources):
    if not isinstance(sources, dict) or set(sources) != set(ROLES):
        raise ValueError("native-source-role-set")
    if any(not isinstance(value, str) or not SOURCE.fullmatch(value) for value in sources.values()):
        raise ValueError("native-source-store-root")
    if len(set(sources.values())) != len(ROLES):
        raise ValueError("native-source-distinct-roots")
    return sources


def generate(lock_bytes, sources, repository):
    locked = locked_sources(lock_bytes)
    validate_selection(sources)
    items, regular_inputs = [], []
    entries, payload_bytes = 0, 0
    for role in ROLES:
        root = sources[role]
        if not stat.S_ISDIR(os.lstat(root).st_mode):
            raise ValueError("native-source-root-not-directory")
        descriptor = describe(root)
        mapping = {}
        for node in descriptor["nodes"]:
            if node["type"] == "regular":
                label = "regular/" + str(len(regular_inputs)).zfill(8)
                mapping[node["path"]] = label
                regular_inputs.append({"label": label, "source": str(Path(root) / node["path"])})
                payload_bytes += node["size"]
        entries += len(descriptor["nodes"])
        if entries > MAX_ENTRIES or payload_bytes > MAX_SOURCE_BYTES:
            raise ValueError("native-source-aggregate-bound")
        items.append({"role": role, **locked[role], "descriptor": descriptor,
                      "regularInputs": mapping})
    bundle = {"schemaVersion": 1, "kind": "locked-native-flake-source-descriptors",
              "lockSha256": hashlib.sha256(lock_bytes).hexdigest(), "sources": items}
    encoded = json.dumps(bundle, sort_keys=True).encode()
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError("native-source-descriptor-bound")
    (Path(repository) / "source-descriptors.json").write_bytes(encoded + b"\n")
    return {"regularInputs": regular_inputs, "sourceRoles": list(ROLES),
            "descriptorBytes": len(encoded) + 1, "contentRehashed": False}


def verify(lock_bytes, descriptor_bytes, label_root, physical_roots, *, deadline=None):
    now = time.monotonic()
    if deadline is None:
        deadline = now + MAX_SECONDS
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline) or not 0 < deadline - now <= MAX_SECONDS):
        raise ValueError("native-source-deadline")
    locked = locked_sources(lock_bytes)
    if len(descriptor_bytes) > MAX_METADATA_BYTES:
        raise ValueError("native-source-descriptor-bound")
    bundle = json.loads(descriptor_bytes)
    if (not isinstance(bundle, dict)
            or set(bundle) != {"schemaVersion", "kind", "lockSha256", "sources"}
            or type(bundle["schemaVersion"]) is not int or bundle["schemaVersion"] != 1
            or bundle["kind"] != "locked-native-flake-source-descriptors"
            or bundle["lockSha256"] != hashlib.sha256(lock_bytes).hexdigest()
            or not isinstance(bundle["sources"], list) or len(bundle["sources"]) != len(ROLES)):
        raise ValueError("native-source-descriptor-lock")
    items, labels, sources = {}, set(), {}
    entries, payload_bytes = 0, 0
    # Validate the complete role and declared-label sets before opening bytes.
    for item in bundle["sources"]:
        if not isinstance(item, dict) or set(item) != {
                "role", "node", "revision", "narHash", "descriptor", "regularInputs"}:
            raise ValueError("native-source-descriptor-fields")
        role = item["role"]
        if not isinstance(role, str) or role not in locked or role in items:
            raise ValueError("native-source-role-set")
        if {key: item[key] for key in ("node", "revision", "narHash")} != locked[role]:
            raise ValueError("native-source-lock-role")
        nodes, _ = validate_descriptor(item["descriptor"])
        if nodes[""]["type"] != "directory":
            raise ValueError("native-source-root-not-directory")
        sources[role] = item["descriptor"]["root"]
        mapping = item["regularInputs"]
        regular = {path for path, node in nodes.items() if node["type"] == "regular"}
        if not isinstance(mapping, dict) or set(mapping) != regular:
            raise ValueError("native-source-regular-label-set")
        for label in mapping.values():
            if not isinstance(label, str) or not re.fullmatch(r"regular/[0-9]{8}", label) or label in labels:
                raise ValueError("native-source-declared-label")
            labels.add(label)
        entries += len(nodes)
        payload_bytes += sum(nodes[path]["size"] for path in regular)
        if entries > MAX_ENTRIES or payload_bytes > MAX_SOURCE_BYTES:
            raise ValueError("native-source-aggregate-bound")
        items[role] = (item, nodes)
    validate_selection(sources)
    results, total = [], 0
    for role in ROLES:
        if time.monotonic() >= deadline:
            raise ValueError("native-source-deadline")
        item, nodes = items[role]
        root = item["descriptor"]["root"]
        mapping = item["regularInputs"]
        def opener(selected_root, path):
            if selected_root != root or path not in mapping:
                raise ValueError("native-source-undeclared-file")
            label = mapping[path]
            return open_declared(Path(label_root) / label,
                                 [Path(physical) / label for physical in physical_roots],
                                 str(Path(root) / path), nodes[path])
        result = hash_descriptor(item["descriptor"], opener=opener, deadline=deadline)
        if result["narHash"] != locked[role]["narHash"]:
            raise ValueError("native-source-nar-mismatch")
        total += result["narSize"]
        if total > MAX_SOURCE_BYTES:
            raise ValueError("native-source-aggregate-bound")
        results.append({"role": role, **locked[role], "source": root, "narSize": result["narSize"]})
    if time.monotonic() >= deadline:
        raise ValueError("native-source-deadline")
    return {"schemaVersion": 1, "passed": True, "scope": "locked-native-flake-source-bytes",
            "lockSha256": bundle["lockSha256"],
            "descriptorSha256": hashlib.sha256(descriptor_bytes).hexdigest(),
            "sources": results, "verifiedRegularInputs": len(labels), "verifiedNarBytes": total,
            "sourceNarVerified": True, "contentRehashed": True, "linkTargetsFollowed": False,
            "executionAuthority": False, "buildSeedVerified": False, "nativeRuntimeQualified": False}


def read_bounded(path, maximum):
    with Path(path).open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("native-source-input-bound")
    return content


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    generator = sub.add_parser("describe")
    generator.add_argument("--selection", required=True)
    generator.add_argument("--lock", required=True)
    generator.add_argument("--repository", required=True)
    proof = sub.add_parser("verify")
    proof.add_argument("--lock", required=True)
    proof.add_argument("--descriptors", required=True)
    args = parser.parse_args()
    original_deadline = time.monotonic() + MAX_SECONDS
    try:
        lock = read_bounded(args.lock, MAX_LOCK_BYTES)
        if args.operation == "describe":
            sources = json.loads(read_bounded(args.selection, MAX_LOCK_BYTES))
            result = generate(lock, sources, args.repository)
        else:
            selected = Path(args.descriptors).absolute()
            descriptors = read_bounded(selected, MAX_METADATA_BYTES)
            result = verify(lock, descriptors, selected.parent,
                            metadata_alias_roots(selected), deadline=original_deadline)
            output = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
            if output:
                (Path(output) / "locked-native-flake-source-proof.json").write_text(
                    json.dumps(result, sort_keys=True) + "\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        print(json.dumps({"schemaVersion": 1, "passed": False,
                          "gate": "declared-native-flake-source-unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
