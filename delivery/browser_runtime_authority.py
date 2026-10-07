"""Join declared public proof inputs for the provider-free Chromium test lane.

This helper never runs candidate tools or follows closure symlinks. A producer
checks operator-supplied input digests, validates existing proof JSON, and emits
only public receipt fields. The consumer rechecks exact bindings before using
candidate runtime inputs. This document authorizes only the scoped test lane.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

INVENTORY_SHA256 = "1c1d555f3124479d30972c05ce025f6d0f008dffb25698e085524421e16ac931"
ROOTS_SHA256 = "0414b0102496d85ec10818d45dc127c605a51a18ae2f7df53db6e5d1e9a72d27"
LOCK_SHA256 = "8bf597bc60b2cf908a5e1772256e178e9593d0474434f4407ee1247bed38197a"
SELECTION_SHA256 = "6ab7f828fcf92df8394869029462541ce0a495bcd14ff7dc9c25c4c469abc2c7"
FLAKE_SHA256 = "ae04bb4a08b0627ca0c778e1cb8163d8493b60f9caaf65d6b400659afd6f7039"
REVISION = "1c3fe55ad329cbcb28471bb30f05c9827f724c76"
SOURCE_NAR_HASH = "sha256-bxrdOn8SCOv8tN4JbTF/TXq7kjo9ag4M+C8yzzIRYbE="
BLUEZ_ROOT = "/nix/store/zb0vr338s1sq0c7a3ca5i4zx89kjzd4n-bluez-5.86"
EXCLUSION_POLICY = "cached-site-bluez-5.86"
MAX_INPUT = 8 * 1024 * 1024
MAX_AUTHORITY = 16 * 1024 * 1024
STORE = re.compile(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]{1,211}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MASKS = ["/etc/bluetooth", "/etc/environment"]
SYSTEMD_ALIASES = {
    "closure/574yk616w63vrqixip1b9f6ndd816xd9-systemd-minimal-260.1/lib/environment.d/99-environment.conf",
    "closure/9rpism89x6lyjcwzzkp6kana25rs03nn-systemd-260.1/lib/environment.d/99-environment.conf",
}
RUNTIME_ROOT_REASONS = frozenset({
    "runtime_closure_unavailable", "runtime_closure_missing", "runtime_closure_unreadable",
    "runtime_closure_special", "runtime_closure_alias_unqualified",
    "runtime_closure_alias_target_invalid", "runtime_closure_alias_nar_mismatch",
})


class RuntimeRootError(ValueError):
    """Finite diagnostic only; never retain a path or raw filesystem error."""
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in RUNTIME_ROOT_REASONS else "runtime_closure_unavailable"
        super().__init__(self.reason)


def validate_runtime_roots(paths, inventory_rows, *, lstat=None, readlink=None):
    """Check qualified inventory roots without following links or reading files.

    The caller must first validate_authority and supply its exact decoded rows.
    One direct root link is admitted only across a declared reference edge to a
    registered directory/file, with its literal text matching the inventory NAR.
    Injected metadata readers support tests without accessing the actual store.
    """
    lstat = os.lstat if lstat is None else lstat
    readlink = os.readlink if readlink is None else readlink
    def admitted(condition, reason):
        if not condition:
            raise RuntimeRootError(reason)
    admitted(type(paths) is list and 1 <= len(paths) <= 4096
             and all(type(path) is str and STORE.fullmatch(path) for path in paths),
             "runtime_closure_unavailable")
    roots = set(paths)
    admitted(len(roots) == len(paths) and type(inventory_rows) is dict and set(inventory_rows) == roots,
             "runtime_closure_unavailable")
    for path in paths:
        row = inventory_rows[path]
        admitted(type(row) is dict and row.get("path") == path and type(row.get("references")) is list
                 and all(type(reference) is str and reference in roots for reference in row["references"]),
                 "runtime_closure_unavailable")
    def metadata(path):
        try:
            return lstat(path)
        except FileNotFoundError:
            raise RuntimeRootError("runtime_closure_missing") from None
        except OSError:
            raise RuntimeRootError("runtime_closure_unreadable") from None
    for path in paths:
        information = metadata(path)
        if not stat.S_ISLNK(information.st_mode):
            admitted(stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode),
                     "runtime_closure_special")
            continue
        try:
            target = readlink(path)
        except FileNotFoundError:
            raise RuntimeRootError("runtime_closure_missing") from None
        except OSError:
            raise RuntimeRootError("runtime_closure_unreadable") from None
        row = inventory_rows[path]
        admitted(type(target) is str and len(os.fsencode(target)) <= 256
                 and target in roots and target in row["references"], "runtime_closure_alias_unqualified")
        # A root-symlink NAR contains only its literal link text. Serialize that
        # bounded structure and compare both hash and size to the pinned prior
        # inventory. No candidate tool or target content participates.
        encoded = bytearray()
        for value in (b"nix-archive-1", b"(", b"type", b"symlink", b"target", os.fsencode(target), b")"):
            encoded.extend(len(value).to_bytes(8, "little"))
            encoded.extend(value)
            encoded.extend(b"\0" * (-len(value) % 8))
        actual = hashlib.sha256(encoded).digest()
        expected = row.get("narHash")
        admitted(type(row.get("narSize")) is int and row["narSize"] == len(encoded)
                 and type(expected) is str and expected in {
                     "sha256:" + actual.hex(), "sha256-" + base64.b64encode(actual).decode("ascii")},
                 "runtime_closure_alias_nar_mismatch")
        target_information = metadata(target)
        admitted(stat.S_ISDIR(target_information.st_mode) or stat.S_ISREG(target_information.st_mode),
                 "runtime_closure_alias_target_invalid")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-field")
        result[key] = value
    return result


def parse(content):
    return json.loads(content, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite-json")))


def checked_bytes(path, expected, maximum=MAX_INPUT):
    require(isinstance(expected, str) and SHA256.fullmatch(expected), "input-sha256-shape")
    with Path(path).open("rb") as stream:
        content = stream.read(maximum + 1)
    require(len(content) <= maximum and digest(content) == expected, "input-sha256-or-bound")
    return content


def receipt_from_input(content):
    """Accept exact JSON or one bounded success JSON line in a declared test log."""
    require(len(content) <= MAX_INPUT, "receipt-byte-bound")
    try:
        value = parse(content)
        if type(value) is dict:
            return value
    except (ValueError, UnicodeError):
        pass
    candidates = []
    for line in content.splitlines():
        if not line.startswith(b"{") or len(line) > 65536:
            continue
        try:
            value = parse(line)
            if type(value) is dict and value.get("schemaVersion") == 1:
                candidates.append(value)
        except (ValueError, UnicodeError):
            pass
    require(len(candidates) == 1, "ambiguous-receipt-log")
    return candidates[0]


def validate_inventory(content):
    require(len(content) <= MAX_INPUT and digest(content) == INVENTORY_SHA256, "inventory-binding")
    value = parse(content)
    require(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
            and value.get("system") == "x86_64-linux" and value.get("mode") == "local-sqlite-readonly-snapshot"
            and value.get("contentRehashed") is False and value.get("realized") is False
            and value.get("published") is False, "inventory-claim-boundary")
    rows = value["paths"]
    require(type(rows) is list and 1 <= len(rows) <= 4096, "inventory-path-bound")
    paths, total = set(), 0
    for row in rows:
        require(type(row) is dict and STORE.fullmatch(row["path"]) and row["path"] not in paths
                and type(row["narSize"]) is int and row["narSize"] > 0
                and type(row["references"]) is list, "inventory-row")
        paths.add(row["path"])
        total += row["narSize"]
    require(total <= 16 * 1024**3 and all(ref in paths for row in rows for ref in row["references"]),
            "inventory-closure-bound")
    require(type(value["roots"]) is list and set(value["roots"]).issubset(paths), "inventory-root-set")
    require(set(value["packages"]) == {"node", "python", "pnpm", "bash", "coreutils", "chromium"}
            and all(package["out"] in paths for package in value["packages"].values()), "inventory-packages")
    return value, sorted(paths), total


def validate_mapping(receipt):
    expected = {"schemaVersion", "passed", "mode", "provenance", "sourceInputSha256", "nixpkgsRevision",
                "nixpkgsSourceNarHash", "sourceContentRehashed", "selectedOutputsMatched", "evaluationStore",
                "evaluationStoreByteLimit", "wholeFlakeEvaluated", "realized", "browserExecuted"}
    require(type(receipt) is dict and set(receipt) == expected and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["passed"] is True and receipt["mode"] == "shared-selection-offline-evaluation",
            "mapping-receipt-schema")
    require(receipt["provenance"] == {"rootsSha256": ROOTS_SHA256, "lockSha256": LOCK_SHA256,
                                      "selectionSha256": SELECTION_SHA256, "flakeSha256": FLAKE_SHA256}
            and receipt["nixpkgsRevision"] == REVISION and receipt["sourceContentRehashed"] is True
            and receipt["selectedOutputsMatched"] is True and receipt["wholeFlakeEvaluated"] is False
            and receipt["realized"] is False and receipt["browserExecuted"] is False
            and receipt["evaluationStore"] == "private-local-temporary"
            and type(receipt["evaluationStoreByteLimit"]) is int and receipt["evaluationStoreByteLimit"] == 1024**3
            and SHA256.fullmatch(receipt["sourceInputSha256"]), "mapping-receipt-binding")
    require(receipt["nixpkgsSourceNarHash"] == SOURCE_NAR_HASH, "mapping-source-hash")


def validate_nar(receipt, paths, total):
    expected = {"schemaVersion", "passed", "inventorySha256", "descriptorSha256", "verifiedPaths",
                "verifiedRegularInputs", "verifiedNarBytes", "contentRehashed", "linkTargetsFollowed",
                "executionAuthority", "flakeMappingVerified", "realized"}
    require(type(receipt) is dict and set(receipt) == expected and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["passed"] is True and receipt["inventorySha256"] == INVENTORY_SHA256
            and SHA256.fullmatch(receipt["descriptorSha256"]) and type(receipt["verifiedPaths"]) is int
            and receipt["verifiedPaths"] == len(paths) and type(receipt["verifiedNarBytes"]) is int
            and receipt["verifiedNarBytes"] == total and type(receipt["verifiedRegularInputs"]) is int
            and receipt["verifiedRegularInputs"] > 0 and receipt["contentRehashed"] is True
            and receipt["linkTargetsFollowed"] is False and receipt["executionAuthority"] is False
            and receipt["flakeMappingVerified"] is False and receipt["realized"] is False,
            "nar-receipt-binding")


def validate_exclusions(entries, paths):
    require(type(entries) is list and len(entries) == 5 and BLUEZ_ROOT in paths, "runtime-exclusion-bound")
    seen = set()
    for item in entries:
        if type(item) is dict and item.get("alias") in SYSTEMD_ALIASES:
            alias = item["alias"]
            require(set(item) == {"alias", "reason"} and alias not in seen
                    and "/nix/store/" + alias.split("/")[1] in paths
                    and item["reason"] == "operator runtime environment configuration; not an action input",
                    "runtime-systemd-exclusion-binding")
            seen.add(alias)
            continue
        require(type(item) is dict and set(item) == {"alias", "policy", "reason", "target_class", "target_followed"},
                "runtime-exclusion-fields")
        alias = item["alias"]
        expected_aliases = {"closure/" + BLUEZ_ROOT.split("/")[-1] + "/etc/bluetooth/" + name + ".conf"
                            for name in ("input", "main", "network")}
        require(alias in expected_aliases and alias not in seen and item["policy"] == EXCLUSION_POLICY
                and item["reason"] == "inert host configuration link; excluded from execution inputs"
                and item["target_class"] == "host-configuration" and item["target_followed"] is False,
                "runtime-exclusion-binding")
        seen.add(alias)
    require(SYSTEMD_ALIASES.issubset(seen), "runtime-systemd-exclusion-set")


def exclusion_manifest(content, paths):
    value = parse(content)
    require(type(value) is dict and set(value) == {"schemaVersion", "policy", "exclusions", "executionAuthority"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["policy"] == EXCLUSION_POLICY
            and value["executionAuthority"] is False, "runtime-exclusion-manifest")
    validate_exclusions(value["exclusions"], paths)
    return value["exclusions"]


def join(inventory_content, mapping_content, nar_content, exclusions_content, mapping_sha, nar_sha, exclusions_sha):
    require(digest(mapping_content) == mapping_sha and digest(nar_content) == nar_sha
            and digest(exclusions_content) == exclusions_sha, "proof-input-binding")
    inventory, paths, total = validate_inventory(inventory_content)
    mapping, nar = receipt_from_input(mapping_content), receipt_from_input(nar_content)
    validate_mapping(mapping)
    validate_nar(nar, paths, total)
    exclusions = exclusion_manifest(exclusions_content, paths)
    return {"schemaVersion": 1, "scope": "installed-chromium-synthetic-source-transport",
            "inventorySha256": INVENTORY_SHA256, "inventoryBase64": base64.b64encode(inventory_content).decode("ascii"),
            "storePaths": paths, "packages": inventory["packages"],
            "proofs": {"mapping": {"inputSha256": mapping_sha, "receiptSha256": digest(canonical(mapping)), "receipt": mapping},
                       "nar": {"inputSha256": nar_sha, "receiptSha256": digest(canonical(nar)), "receipt": nar}},
            "exclusionsInputSha256": exclusions_sha,
            "exclusionsBase64": base64.b64encode(exclusions_content).decode("ascii"), "excludedNonInputs": exclusions,
            "requiredUnavailablePaths": MASKS, "providerAccess": False, "productionExport": False,
            "manualPopupConsentProven": False, "browserExecuted": False}


def validate_authority(content):
    require(len(content) <= MAX_AUTHORITY, "runtime-authority-bound")
    value = parse(content)
    fields = {"schemaVersion", "scope", "inventorySha256", "inventoryBase64", "storePaths", "packages", "proofs",
              "exclusionsInputSha256", "exclusionsBase64", "excludedNonInputs", "requiredUnavailablePaths", "providerAccess",
              "productionExport", "manualPopupConsentProven", "browserExecuted"}
    require(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == "installed-chromium-synthetic-source-transport"
            and value["inventorySha256"] == INVENTORY_SHA256 and value["requiredUnavailablePaths"] == MASKS
            and all(value[field] is False for field in ("providerAccess", "productionExport", "manualPopupConsentProven", "browserExecuted")),
            "runtime-authority-scope")
    inventory, paths, total = validate_inventory(base64.b64decode(value["inventoryBase64"], validate=True))
    require(value["storePaths"] == paths and value["packages"] == inventory["packages"]
            and set(value["proofs"]) == {"mapping", "nar"}, "runtime-authority-roots")
    for name, proof in value["proofs"].items():
        require(type(proof) is dict and set(proof) == {"inputSha256", "receiptSha256", "receipt"}
                and SHA256.fullmatch(proof["inputSha256"])
                and proof["receiptSha256"] == digest(canonical(proof["receipt"])), "runtime-proof-digest")
    validate_mapping(value["proofs"]["mapping"]["receipt"])
    validate_nar(value["proofs"]["nar"]["receipt"], paths, total)
    require(SHA256.fullmatch(value["exclusionsInputSha256"]), "runtime-exclusion-digest")
    exclusions_content = base64.b64decode(value["exclusionsBase64"], validate=True)
    require(len(exclusions_content) <= MAX_INPUT and digest(exclusions_content) == value["exclusionsInputSha256"],
            "runtime-exclusion-byte-binding")
    require(value["excludedNonInputs"] == exclusion_manifest(exclusions_content, paths), "runtime-exclusion-binding")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "mapping", "nar", "exclusions"):
        parser.add_argument("--" + name, required=True)
    for name in ("mapping", "nar"):
        parser.add_argument("--" + name + "-sha256", required=True)
    exclusions_binding = parser.add_mutually_exclusive_group(required=True)
    exclusions_binding.add_argument("--exclusions-sha256")
    exclusions_binding.add_argument("--declared-exclusions", action="store_true",
                                    help="Exclusions are a declared Bazel action input; retain its byte digest and exact semantics.")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.declared_exclusions:
        # This mode is only for an explicitly declared action input. It never
        # relaxes the exact five-alias policy enforced by join/consumer checks.
        with Path(args.exclusions).open("rb") as stream:
            exclusions_content = stream.read(MAX_INPUT + 1)
        require(len(exclusions_content) <= MAX_INPUT, "declared-exclusions-byte-bound")
        exclusions_sha = digest(exclusions_content)
    else:
        exclusions_content = checked_bytes(args.exclusions, args.exclusions_sha256)
        exclusions_sha = args.exclusions_sha256
    value = join(checked_bytes(args.inventory, INVENTORY_SHA256),
                 checked_bytes(args.mapping, args.mapping_sha256), checked_bytes(args.nar, args.nar_sha256),
                 exclusions_content, args.mapping_sha256, args.nar_sha256, exclusions_sha)
    encoded = canonical(value) + b"\n"
    validate_authority(encoded)
    Path(args.out).write_bytes(encoded)


if __name__ == "__main__":
    main()
