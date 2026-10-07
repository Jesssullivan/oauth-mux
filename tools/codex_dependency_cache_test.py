"""Offline digest/custody/metadata predicates; no fetch or SDK launch."""

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from codex_dependency_cache import EXPORT_MODE_POLICY, GIT_MODE_AUTHORITY, GRAPH, SOURCE_RECEIPT_SHA, descriptor_summary, module_descriptors, qualify
from codex_sdk_dependencies import EXACT_BCR_ARCHIVES, sha


def manifest(rows):
    return {"status": "source-dependency-descriptors-unfetched", "source_inventory_verified": True,
            "closure_proved": False, "artifacts": rows, "unsupported": [{"type": "cargo-git", "identity": "fixture"}]}


def row(value, kind="cargo-crate", identity="fixture", url="https://static.crates.io/crates/fixture/fixture-1.crate"):
    return {"sha256": hashlib.sha256(value).hexdigest(), "type": kind, "identity": identity, "urls": [url]}


def payload(root, entry, value=None, kind=None):
    parent = root / "content_addressable" / "sha256" / entry["sha256"]
    parent.mkdir(parents=True, mode=0o700)
    path = parent / "file"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        path.symlink_to("/unrelated")
    else:
        path.write_bytes(value)
    return path


class CacheTests(unittest.TestCase):
    def test_exact_bcr_metadata_pairs_derive_missing_archives_without_fetch(self):
        for url, integrity in EXACT_BCR_ARCHIVES.items():
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                registry = "https://bcr.bazel.build/modules/fixture/1/source.json"
                content = json.dumps({"url": url, "integrity": integrity}).encode()
                entry = row(content, "bazel-registry-file", registry, registry)
                payload(root, entry, content)
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    result = qualify(manifest([entry]), fd)
                finally:
                    os.close(fd)
                self.assertEqual(result["counts"]["verified"], 1)
                self.assertEqual(result["counts"]["missing"], 1)
                self.assertEqual(result["derived_module_descriptors"], [{"type": "bazel-module-archive",
                    "identity": registry, "urls": [url], "sha256": sha(None, integrity)}])
                self.assertEqual(result["missing"][0]["sha256"], sha(None, integrity))
                self.assertFalse(result["closure_proved"])

    def test_exception_digest_or_url_mismatch_refuses_metadata_and_cache_admission(self):
        registry = "https://bcr.bazel.build/modules/fixture/1/source.json"
        url = "https://mirrors.kernel.org/gnu/sed/sed-4.9.tar.xz"
        integrity = "sha256-biJrcy4c1zlGStaGK9Ghq6QteYKSLaelNRljHSSXUYE="
        wrong_integrity = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        for candidate, expected in ((url, wrong_integrity), (url + ".neighbor", integrity),
                                    (url + "?token=fixture-secret", integrity),
                                    (url.replace("https://", "https://fixture-secret@"), integrity)):
            rows, unresolved = module_descriptors(registry, json.dumps({"url": candidate, "integrity": expected}).encode())
            self.assertEqual(rows, [])
            self.assertNotIn("fixture-secret", str(unresolved))
            entry = {"type": "bazel-module-archive", "identity": registry,
                     "urls": [candidate], "sha256": sha(None, expected)}
            with tempfile.TemporaryDirectory() as directory:
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(ValueError, "URLs are not public"):
                        qualify(manifest([entry]), fd)
                finally:
                    os.close(fd)

    def test_digest_probe_binds_original_source_authority_and_emits_counts_only(self):
        files = {"public/" + str(index): {"mode": "100644", "sha256": "a" * 64} for index in range(8546)}
        source = {"tracked_files": 8546, "files": files,
                  "complete_inventory_sha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
        document = manifest([row(b"fixture")])
        document.update(schema_version=1, source_receipt_sha256=SOURCE_RECEIPT_SHA,
                        physical_mode_policy=EXPORT_MODE_POLICY, git_mode_authority=GIT_MODE_AUTHORITY,
                        module_lock_sha256=GRAPH["MODULE.bazel.lock"], cargo_lock_sha256=GRAPH["codex-rs/Cargo.lock"],
                        offline_analysis_proved=False, native_support=False, rules_rs_snapshots=[])
        result = descriptor_summary(document, "b" * 64, 123, source)
        self.assertEqual(result["descriptor_sha256"], "b" * 64)
        self.assertEqual(result["counts"]["artifacts"], {"cargo-crate": 1})
        self.assertNotIn("urls", result)
        document["source_receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "authority mismatch"):
            descriptor_summary(document, "b" * 64, 123, source)

    def test_verified_missing_and_digest_refused_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good, absent, bad = row(b"good"), row(b"absent", identity="absent"), row(b"expected", identity="bad")
            payload(root, good, b"good")
            payload(root, bad, b"wrong")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = qualify(manifest([good, absent, bad]), fd)
            finally:
                os.close(fd)
            self.assertEqual(result["counts"]["verified"], 1)
            self.assertEqual(result["counts"]["missing"], 1)
            self.assertEqual(result["counts"]["refused"], 1)
            self.assertFalse(result["closure_proved"])
            self.assertEqual(result["unresolved"], manifest([])["unsupported"])

    def test_fifo_symlink_and_writable_digest_directory_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo, link, writable = row(b"fifo"), row(b"link"), row(b"writable")
            payload(root, fifo, kind="fifo")
            payload(root, link, kind="symlink")
            payload(root, writable, b"writable").parent.chmod(0o777)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = qualify(manifest([fifo, link, writable]), fd)
            finally:
                os.close(fd)
            self.assertEqual(result["counts"]["refused"], 3)

    def test_verified_bcr_metadata_derives_archive_and_patch_without_fetch(self):
        url = "https://bcr.bazel.build/modules/example/1/source.json"
        sri = "sha256-" + base64.b64encode(bytes.fromhex("a" * 64)).decode()
        content = json.dumps({"url": "https://github.com/example/example/archive/v1.tar.gz", "integrity": sri,
                              "patches": {"fix.patch": sri}}).encode()
        entry = row(content, "bazel-registry-file", url, url)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload(root, entry, content)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = qualify(manifest([entry]), fd)
            finally:
                os.close(fd)
        self.assertEqual(result["counts"]["verified"], 1)
        self.assertEqual(result["counts"]["derived_module_descriptors"], 2)
        self.assertEqual(result["counts"]["missing"], 2)

    def test_query_urls_are_not_emitted_and_unsafe_patch_paths_refuse(self):
        url = "https://bcr.bazel.build/modules/example/1/source.json"
        sri = "sha256-" + base64.b64encode(bytes.fromhex("a" * 64)).decode()
        rows, unresolved = module_descriptors(url, json.dumps({"url": "https://github.com/example/archive?token=fixture-secret",
                                                              "integrity": sri}).encode())
        self.assertEqual(rows, [])
        self.assertNotIn("fixture-secret", str(unresolved))
        with self.assertRaises(ValueError):
            module_descriptors(url, json.dumps({"patches": {"../escape": sri}}).encode())


if __name__ == "__main__":
    unittest.main()
