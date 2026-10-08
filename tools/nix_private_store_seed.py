"""Finite Bash/Nix runtime seed metadata; repository setup performs no Nix IO."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import nar_descriptor as nar
from nix_interpreter_closure import STORE, reachable, registrations

KIND = "omux-nix-private-store-seed-v1"
MAX_FILES = 200000
MAX_BYTES = 4 * 1024**3
MAX_METADATA = 64 * 1024**2
ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"


def require(value):
    if value is not True:
        raise ValueError("private-store seed contract")


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def expected_hash(value):
    require(isinstance(value, str) and value.startswith("sha256:"))
    value = value[7:]
    if re.fullmatch("[a-f0-9]{64}", value):
        return value
    require(len(value) == 52 and all(character in ALPHABET for character in value))
    number = 0
    for character in value:
        number = number * 32 + ALPHABET.index(character)
    require(number < 1 << 256)
    return number.to_bytes(32, "little").hex()


def metadata(path, bound):
    with nar.open_regular(str(Path(path).absolute()), "") as stream:
        payload = stream.read(bound + 1)
    require(len(payload) <= bound)
    return payload



def resolve_member(value, logical):
    """Resolve seeded NAR nodes only; a link never consults the host."""
    require(isinstance(logical, str) and logical.startswith("/nix/store/"))
    pending = logical.split("/")[1:]
    current = []
    hops = 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            require(len(current) > 2)
            current.pop()
            continue
        candidate = current + [component]
        if len(candidate) < 3:
            require(candidate in (["nix"], ["nix", "store"]))
            current = candidate
            continue
        root = "/" + "/".join(candidate[:3])
        require(root in value["descriptors"])
        nodes = {row["path"]: row for row in value["descriptors"][root]["nodes"]}
        member = "/".join(candidate[3:])
        require(member in nodes)
        row = nodes[member]
        if row["type"] == "symlink":
            hops += 1
            require(hops <= 64)
            target = row["target"]
            require("\x00" not in target)
            if target.startswith("/"):
                current = []
            pending = target.split("/") + pending
            continue
        current = candidate
        if pending:
            require(row["type"] == "directory")
        else:
            require(row["type"] == "regular" and row["executable"] is True)
            return "/" + "/".join(current)
    raise ValueError("private-store executable member")


def describe_seed(native_raw, paths_raw, registration_raw, *, describe=nar.describe):
    native = json.loads(native_raw, object_pairs_hook=unique)
    require(native["system"] == "x86_64-linux")
    paths = paths_raw.decode("ascii").splitlines()
    records = registrations(registration_raw.decode("ascii"), paths)
    packages = native["packages"]
    tools = {name: packages["nix" if name == "nix_store" else name]["out"] + suffix
             for name, suffix in (("bash", "/bin/bash"), ("nix", "/bin/nix"),
                                  ("nix_store", "/bin/nix-store"))}
    roots = [tools["bash"].rsplit("/bin/", 1)[0], tools["nix"].rsplit("/bin/", 1)[0]]
    require(all(re.fullmatch(STORE, root) is not None for root in roots))
    selected = reachable(records, roots)
    descriptors = {}
    files = []
    total = 0
    for root in selected:
        descriptor = describe(root)
        require(descriptor["root"] == root)
        nar.validate_descriptor(descriptor)
        # Root objects themselves may be regular store writeText objects.
        for node in descriptor["nodes"]:
            if node["type"] == "regular":
                actual = root + ("/" + node["path"] if node["path"] else "")
                alias = "private-store-inputs/" + str(len(files))
                files.append({"source": actual, "alias": alias})
                total += node["size"]
        descriptors[root] = descriptor
    require(0 < len(files) <= MAX_FILES and total <= MAX_BYTES)
    require(all(resolve_member({"descriptors": descriptors}, tool) in {row["source"] for row in files}
                for tool in tools.values()))
    selected_registration = "".join("\n".join(records[root]["record"]) + "\n" for root in selected)
    result = {"schemaVersion": 1, "kind": KIND, "system": "x86_64-linux",
              "tools": tools, "roots": selected, "registration": selected_registration,
              "descriptors": descriptors, "files": files, "regular_bytes": total,
              "metadata_sha256": {"native": sha(native_raw), "paths": sha(paths_raw),
                                  "registration": sha(registration_raw)}}
    require(len(encoded(result)) <= MAX_METADATA)
    return result


def validate(value):
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "kind", "system", "tools",
        "roots", "registration", "descriptors", "files", "regular_bytes", "metadata_sha256"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["kind"] == KIND and value["system"] == "x86_64-linux")
    roots = value["roots"]
    records = registrations(value["registration"], roots)
    require(roots == sorted(roots) and set(value["descriptors"]) == set(roots))
    tools = value["tools"]
    require(set(tools) == {"bash", "nix", "nix_store"})
    require(all(isinstance(tool, str) and re.fullmatch(STORE + r"/bin/(bash|nix|nix-store)", tool)
                for tool in tools.values()))
    require(tools["bash"].endswith("/bin/bash") and tools["nix"].endswith("/bin/nix")
            and tools["nix_store"] == tools["nix"] + "-store")
    require(reachable(records, [tools["bash"].rsplit("/bin/", 1)[0],
                               tools["nix"].rsplit("/bin/", 1)[0]]) == roots)
    expected = []
    total = 0
    for root in roots:
        descriptor = value["descriptors"][root]
        require(descriptor["root"] == root)
        nar.validate_descriptor(descriptor)
        require(type(descriptor["schemaVersion"]) is int and descriptor["schemaVersion"] == 1)
        require(descriptor["nodes"] == sorted(descriptor["nodes"], key=lambda row: os.fsencode(row["path"])))
        for node in descriptor["nodes"]:
            if node["type"] == "regular":
                expected.append({"source": root + ("/" + node["path"] if node["path"] else ""),
                                 "alias": "private-store-inputs/" + str(len(expected))})
                total += node["size"]
        expected_hash(records[root]["record"][1])
    require(value["files"] == expected and 0 < len(expected) <= MAX_FILES and total <= MAX_BYTES)
    require(type(value["regular_bytes"]) is int and value["regular_bytes"] == total)
    require(all(resolve_member(value, tool) in {row["source"] for row in expected}
                for tool in tools.values()))
    pins = value["metadata_sha256"]
    require(set(pins) == {"native", "paths", "registration"}
            and all(isinstance(pin, str) and re.fullmatch("[a-f0-9]{64}", pin) for pin in pins.values()))
    return records


def main():
    # Repository-only fixed arguments; no executable, store, daemon, or DB access.
    require(len(sys.argv) == 4)
    native = metadata(sys.argv[1], 2 * 1024**2)
    paths = metadata(sys.argv[2], 1024**2)
    registration = metadata(sys.argv[3], 4 * 1024**2)
    result = describe_seed(native, paths, registration)
    validate(result)
    sys.stdout.buffer.write(encoded(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        print("private-store seed metadata refused", file=sys.stderr)
        raise SystemExit(1) from None
