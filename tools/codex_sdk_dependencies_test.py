"""Offline descriptor extraction, refusal and incompleteness predicates."""

import unittest

from codex_sdk_dependencies import CRATE_FACT, EXACT_BCR_ARCHIVES, derive, public_url, sha


class DependencyTests(unittest.TestCase):
    def test_exact_bcr_archive_pairs_require_the_bound_digest(self):
        expected_urls = {
            "https://www.alsa-project.org/files/pub/lib/alsa-lib-1.2.9.tar.bz2",
            "https://mirrors.kernel.org/gnu/gawk/gawk-5.3.2.tar.xz",
            "https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.27.tar.gz",
            "https://mirrors.kernel.org/gnu/sed/sed-4.9.tar.xz",
        }
        self.assertEqual(set(EXACT_BCR_ARCHIVES), expected_urls)
        for url, integrity in EXACT_BCR_ARCHIVES.items():
            digest = sha(None, integrity)
            with self.subTest(url=url):
                self.assertTrue(public_url(url, digest))
                for invalid in (None, "0" * 64, digest.upper(), integrity):
                    self.assertFalse(public_url(url, invalid))
                for invalid in (url + ".neighbor", url + "/extra", url + "?token=fixture",
                                url + "#fragment", url.replace("https://", "https://fixture@"),
                                url.replace("https://", "http://"), url + "?", url + "#",
                                url.replace(".org/", ".org:443/"),
                                url.rsplit("/", 1)[0] + "/neighbor.tar.gz",
                                url.rsplit("/", 1)[0] + "/../" + url.rsplit("/", 1)[1],
                                url.replace("1.2.9", "1.2.10").replace("5.3.2", "5.3.3")
                                   .replace("2.27", "2.28").replace("4.9", "4.10")):
                    self.assertFalse(public_url(invalid, digest))
        self.assertTrue(public_url("https://github.com/example/example/archive/v1.tar.gz"))
        self.assertTrue(public_url("https://static.crates.io/crates/fixture/fixture-1.crate", "0" * 64))

    def test_exact_archive_digest_is_propagated_during_descriptor_derivation(self):
        module, cargo = self.fixtures()
        url = "https://mirrors.kernel.org/gnu/gawk/gawk-5.3.2.tar.xz"
        integrity = "sha256-+MNIZQnecFGSE4sA7ywAu73Q6Eww1cB9I/xzqdxMycw="
        module["moduleExtensions"] = {"fixture": {"attributes": {"url": url, "integrity": integrity}}}
        result = derive(module, cargo)
        rows = [row for row in result["artifacts"] if row["type"] == "generated-repository-download"]
        self.assertEqual(rows, [{"type": "generated-repository-download", "identity": "moduleExtensions/fixture",
                                 "urls": [url], "sha256": sha(None, integrity)}])
        module["moduleExtensions"]["fixture"]["attributes"]["integrity"] = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        result = derive(module, cargo)
        self.assertFalse(any(row["type"] == "generated-repository-download" for row in result["artifacts"]))
        self.assertTrue(any(row["type"] == "generated-repository-download" for row in result["unsupported"]))
        self.assertFalse(result["closure_proved"])

    def fixtures(self):
        return ({"lockFileVersion": 26, "registryFileHashes": {},
                 "facts": {CRATE_FACT: {"fixture_1.0.0": "{}"}}},
                {"package": [{"name": "fixture", "version": "1.0.0",
                              "source": "registry+https://github.com/rust-lang/crates.io-index",
                              "checksum": "a" * 64}]})

    def test_crate_digest_and_snapshot_bind_without_claiming_closure(self):
        module, cargo = self.fixtures()
        result = derive(module, cargo)
        crate = next(row for row in result["artifacts"] if row["type"] == "cargo-crate")
        self.assertEqual(crate["sha256"], "a" * 64)
        self.assertEqual(crate["urls"], ["https://static.crates.io/crates/fixture/fixture-1.0.0.crate"])
        self.assertFalse(result["closure_proved"])
        self.assertFalse(result["offline_analysis_proved"])

    def test_git_and_nonpublic_sources_never_become_fetch_urls(self):
        module, cargo = self.fixtures()
        cargo["package"][0]["source"] = "git+https://credential@example.invalid/private"
        result = derive(module, cargo)
        self.assertTrue(any(row["type"] == "cargo-git" for row in result["unsupported"]))
        self.assertNotIn("credential", str(result))

    def test_query_source_json_and_unknown_snapshot_identities_are_redacted(self):
        module, cargo = self.fixtures()
        module["registryFileHashes"]["https://bcr.bazel.build/modules/example/1/source.json?token=fixture-secret"] = "b" * 64
        module["registryFileHashes"]["https://user:fixture-secret@bcr.bazel.build/modules/example/1/source.json"] = "c" * 64
        module["facts"][CRATE_FACT]["https://github.com/private?token=fixture-secret"] = "{}"
        module["moduleExtensions"] = {"fixture": {"attributes": {
            "url": "https://github.com/public/archive.tar.gz?token=fixture-secret", "sha256": "d" * 64}}}
        result = derive(module, cargo)
        self.assertNotIn("fixture-secret", str(result))
        self.assertTrue(any(row["type"] == "bazel-module-archive" and row["identity"].startswith("unsupported-identity-sha256:")
                            for row in result["unsupported"]))
        self.assertTrue(any(row["identity"].startswith("unsupported-identity-sha256:") for row in result["rules_rs_snapshots"]))

    def test_bcr_source_json_leaves_archive_enumeration_explicit(self):
        module, cargo = self.fixtures()
        module["registryFileHashes"]["https://bcr.bazel.build/modules/example/1/source.json"] = "b" * 64
        result = derive(module, cargo)
        self.assertTrue(any(row["type"] == "bazel-module-archive" for row in result["unsupported"]))

    def test_missing_snapshot_and_unsupported_lock_version_refuse(self):
        module, cargo = self.fixtures()
        module["facts"] = {}
        with self.assertRaises(ValueError):
            derive(module, cargo)
        module, cargo = self.fixtures()
        module["lockFileVersion"] = 99
        with self.assertRaises(ValueError):
            derive(module, cargo)


if __name__ == "__main__":
    unittest.main()
