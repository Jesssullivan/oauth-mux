"""Enumerate pinned SDK dependency descriptors; never fetch or prove closure."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

from codex_sdk_profile import hash_regular, trusted_parent, validate_source
from fetch_codex_archives import ARCHIVES
from restore_pristine_inputs import unique_object

CRATE_FACT = "@@rules_rs+//rs:extensions.bzl%crate"
PUBLIC_HOSTS = {"bcr.bazel.build", "static.crates.io", "static.rust-lang.org", "github.com",
                "files.pythonhosted.org", "mirror.bazel.build", "storage.googleapis.com"}
# R-N13: these four archive URL/integrity pairs come from already verified BCR
# source.json bytes. They authorize no other path, mirror, version or host.
EXACT_BCR_ARCHIVES = {
    "https://www.alsa-project.org/files/pub/lib/alsa-lib-1.2.9.tar.bz2":
        "sha256-3JxkP9xMz9BXLMaFhY3UHgivtYPzBGCzF+QYgnX2FbI=",
    "https://mirrors.kernel.org/gnu/gawk/gawk-5.3.2.tar.xz":
        "sha256-+MNIZQnecFGSE4sA7ywAu73Q6Eww1cB9I/xzqdxMycw=",
    "https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.27.tar.gz":
        "sha256-JgtUnBVLB8PNwWuczJPARjPDn0+2pKO40fpbipw/X+g=",
    "https://mirrors.kernel.org/gnu/sed/sed-4.9.tar.xz":
        "sha256-biJrcy4c1zlGStaGK9Ghq6QteYKSLaelNRljHSSXUYE=",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def public_url(value, expected_sha256=None):
    if value in EXACT_BCR_ARCHIVES:
        return expected_sha256 == sha(None, EXACT_BCR_ARCHIVES[value])
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and parsed.hostname in PUBLIC_HOSTS
            and parsed.username is None and parsed.password is None
            and parsed.port in (None, 443) and not parsed.fragment and not parsed.query)


def opaque_identity(value):
    return "unsupported-identity-sha256:" + hashlib.sha256(value.encode()).hexdigest()


def sha(value, integrity=None):
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    if isinstance(integrity, str) and integrity.startswith("sha256-"):
        decoded = base64.b64decode(integrity[7:], validate=True)
        require(len(decoded) == 32, "invalid integrity digest")
        return decoded.hex()
    return None


def derive(module_lock, cargo_lock):
    artifacts, unsupported, snapshots = {}, [], []
    def add(kind, identity, urls, expected):
        require(len(artifacts) + len(unsupported) < 30000, "dependency descriptor count exceeds bound")
        if not expected or not urls or not all(isinstance(url, str) and public_url(url, expected) for url in urls):
            safe_identity = (opaque_identity(identity)
                             if "://" in identity and not public_url(identity, expected) else identity)
            unsupported.append({"type": kind, "identity": safe_identity,
                                "reason": "missing-digest-or-unsupported-public-url"})
            return
        key = (kind, identity)
        row = {"type": kind, "identity": identity, "urls": urls, "sha256": expected}
        require(key not in artifacts or artifacts[key] == row, "conflicting dependency descriptor")
        artifacts[key] = row
    require(module_lock.get("lockFileVersion") == 26, "unsupported module lock version")
    registry = module_lock.get("registryFileHashes")
    require(isinstance(registry, dict) and len(registry) <= 10000, "invalid registry descriptor map")
    for url, expected in sorted(registry.items()):
        add("bazel-registry-file", url, [url], sha(expected))
        if urlsplit(url).path.endswith("/source.json"):
            unsupported.append({"type": "bazel-module-archive", "identity": url if public_url(url) else opaque_identity(url),
                                "reason": "archive URL/digest requires separately verified source.json; not embedded in this lock"})
    facts = module_lock.get("facts", {}).get(CRATE_FACT)
    require(isinstance(facts, dict) and len(facts) <= 15000, "rules_rs crate snapshot missing or oversized")
    packages = cargo_lock.get("package")
    require(isinstance(packages, list) and len(packages) <= 15000, "Cargo package inventory missing or oversized")
    public_keys = {package["name"] + "_" + package["version"] for package in packages
                   if isinstance(package, dict) and package.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
                   and isinstance(package.get("name"), str) and isinstance(package.get("version"), str)}
    for key, encoded in sorted(facts.items()):
        require(isinstance(encoded, str) and len(encoded) <= 1024 * 1024, "snapshot value exceeds bound")
        snapshot = json.loads(encoded, object_pairs_hook=unique_object)
        require(isinstance(snapshot, dict), "snapshot must be an object")
        identity = key if key in public_keys and re.fullmatch(r"[A-Za-z0-9_-]+_[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+_-]+)?", key) else opaque_identity(key)
        snapshots.append({"identity": identity, "snapshot_sha256": hashlib.sha256(encoded.encode()).hexdigest()})
        if key.startswith("git+"):
            unsupported.append({"type": "rules-rs-git-snapshot", "identity": identity,
                                "reason": "Git commit/snapshot does not establish a digest-bound downloadable archive"})
    for package in packages:
        name, version, source = package.get("name"), package.get("version"), package.get("source")
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]+", name)
                and isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9.+_-]+", version), "unsafe Cargo identity")
        identity = name + "@" + version
        if source is None:
            continue  # Workspace source is already bound by the source inventory.
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            add("cargo-crate", identity, ["https://static.crates.io/crates/" + name + "/" + name + "-" + version + ".crate"], sha(package.get("checksum")))
            if name + "_" + version not in facts:
                unsupported.append({"type": "rules-rs-crate-snapshot", "identity": identity,
                                    "reason": "locked Cargo package lacks matching rules_rs snapshot"})
        else:
            # Deliberately omit arbitrary source text from output: it may carry
            # authentication data in a future lock. Never derive a fetch URL.
            unsupported.append({"type": "cargo-git" if isinstance(source, str) and source.startswith("git+") else "cargo-nonpublic-source",
                                "identity": identity, "source_sha256": hashlib.sha256(str(source).encode()).hexdigest(),
                                "reason": "unsupported source needs a separate reviewed immutable input producer"})
    def repo_walk(value, identity="moduleExtensions", depth=0):
        require(depth <= 32, "module extension nesting exceeds bound")
        if isinstance(value, dict):
            attributes = value.get("attributes")
            if isinstance(attributes, dict):
                urls = attributes.get("urls")
                if urls is None and isinstance(attributes.get("url"), str):
                    urls = [attributes["url"]]
                if urls is not None:
                    require(isinstance(urls, list), "repository URLs must be a list")
                    add("generated-repository-download", identity, urls, sha(attributes.get("sha256"), attributes.get("integrity")))
            for key, child in value.items():
                repo_walk(child, identity + "/" + key, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                repo_walk(child, identity + "/" + str(index), depth + 1)
    repo_walk(module_lock.get("moduleExtensions", {}))
    for name, expected, prefix in ARCHIVES:
        add("audited-linux-tool-archive", name, [prefix + name], expected)
    # Repository rules and build scripts can introduce downloads not serialized
    # here. Enumerating locks is intentionally not a transitive fetch closure.
    unsupported.append({"type": "dynamic-repository-closure", "identity": "SDK Bazel graph",
                        "reason": "BCR source descriptors, auxiliary Cargo locks and repository-rule downloads require declared follow-on enumeration"})
    return {"schema_version": 1, "status": "source-dependency-descriptors-unfetched",
            "artifacts": [artifacts[key] for key in sorted(artifacts)], "rules_rs_snapshots": snapshots,
            "unsupported": sorted(unsupported, key=lambda row: (row["type"], row["identity"])),
            "closure_proved": False, "offline_analysis_proved": False, "native_support": False,
            "scope": "complete enumeration of descriptors embedded in the supplied primary lock and rules_rs snapshot; not the transitive SDK dependency closure"}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-receipt-sha256", required=True)
    args = parser.parse_args()
    validated = validate_source(args.source_root, args.source_receipt_sha256)
    module_fd = trusted_parent(Path(validated["source"]))
    cargo_fd = trusted_parent(Path(validated["source"]) / "codex-rs")
    try:
        module_sha, _, module = hash_regular(module_fd, "MODULE.bazel.lock", 32 * 1024 * 1024, True)
        cargo_sha, _, cargo = hash_regular(cargo_fd, "Cargo.lock", 8 * 1024 * 1024, True)
        report = derive(json.loads(module, object_pairs_hook=unique_object), tomllib.loads(cargo.decode()))
    finally:
        os.close(cargo_fd)
        os.close(module_fd)
    report["source_receipt_sha256"] = args.source_receipt_sha256
    report["module_lock_sha256"] = module_sha
    report["cargo_lock_sha256"] = cargo_sha
    # Detect source drift across descriptor enumeration before publication.
    validated = validate_source(args.source_root, args.source_receipt_sha256)
    report["source_inventory_verified"] = True
    report["physical_mode_policy"] = validated["physical_mode_policy"]
    report["git_mode_authority"] = validated["git_mode_authority"]
    report["physical_regular_modes"] = validated["physical_regular_modes"]
    require(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared dependency output required")
    parent = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
    fd = trusted_parent(parent)
    try:
        os.mkdir("codex-sdk-dependencies", mode=0o700, dir_fd=fd)
        output = os.open("codex-sdk-dependencies", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            descriptor = os.open("dependency-manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=output)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(output)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
