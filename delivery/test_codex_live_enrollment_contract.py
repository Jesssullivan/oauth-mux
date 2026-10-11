"""Provider-free refusal/redaction contract for the real installed enrollment lane."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import test_installed_codex_live_enrollment as proof


class EnrollmentContract(unittest.TestCase):
    def test_sealed_metadata_queries_and_closed_predicate_phases(self):
        facts = {key: self.receipt()[key] for key in
                 ("source_handle", "account_handle", "grant_handle", "grant_generation")}
        with sqlite3.connect(":memory:") as metadata:
            metadata.execute("CREATE TABLE grants(account_id TEXT,grant_id TEXT,generation INTEGER,purpose TEXT,scope TEXT,renewal_owner TEXT,state TEXT,ciphertext BLOB)")
            metadata.execute("CREATE TABLE snapshot(metadata_json TEXT)")
            metadata.execute("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?)",
                             (facts["account_handle"], facts["grant_handle"], 1, "request",
                              "https://chatgpt.com", "external", "ready", b"OMUXG001" + bytes(64)))
            document = {"state": {"accounts": [{"identity": {"verified": True,
                        "provider": "codex", "issuer": "https://chatgpt.com"}}]}}
            metadata.execute("INSERT INTO snapshot VALUES(?)", (json.dumps(document),))
            self.assertEqual(len(proof.sealed_metadata_facts(metadata, facts)), 32)
            metadata.execute("UPDATE grants SET renewal_owner='omux'")
            with self.assertRaises(ValueError):
                proof.sealed_metadata_facts(metadata, facts)
            self.assertEqual(proof.PHASE, "sealed-grant-context")
            metadata.execute("UPDATE grants SET renewal_owner='external',ciphertext=?", (bytes(72),))
            with self.assertRaises(ValueError):
                proof.sealed_metadata_facts(metadata, facts)
            self.assertEqual(proof.PHASE, "sealed-grant-envelope")
            metadata.execute("UPDATE grants SET ciphertext=?", (b"OMUXG001" + bytes(64),))
            document["state"]["accounts"][0]["identity"]["verified"] = False
            metadata.execute("UPDATE snapshot SET metadata_json=?", (json.dumps(document),))
            with self.assertRaises(ValueError):
                proof.sealed_metadata_facts(metadata, facts)
            self.assertEqual(proof.PHASE, "sealed-identity-verification")
            metadata.execute("DELETE FROM grants")
            with self.assertRaises(ValueError):
                proof.sealed_metadata_facts(metadata, facts)
            self.assertEqual(proof.PHASE, "sealed-grant-cardinality")

    def receipt(self):
        return {**proof.FIXED_FACTS, "source_handle": "1" * 64, "account_handle": "2" * 64,
                "grant_handle": "3" * 64, "grant_generation": 1,
                "installed_bundle_sha256": "4" * 64}

    def snapshot(self):
        return {"accounts": [{"id": "2" * 64, "identity": {"provider": "codex", "verified": True},
                              "source_ids": ["1" * 64], "lifecycle": "active"}],
                "sources": [{"id": "1" * 64, "kind": "native_store", "status": "connected", "provider": "codex"}],
                "grants": [{"id": "3" * 64, "account_id": "2" * 64, "source_id": "1" * 64,
                            "credential_kind": "oauth_access", "ownership": "external", "status": "ready",
                            "purposes": ["request", "account_read"], "audience": "https://chatgpt.com",
                            "generation": 1, "provider_expires_at": 1000, "custody_expires_at": 1000}],
                "jobs": [{"kind": "enrollment", "status": "completed"}], "leases": [], "bindings": []}

    def test_receipt_exact_redacted_scope(self):
        receipt = self.receipt()
        self.assertEqual(proof.validate_receipt(receipt), receipt)
        for key in ("source_path", "raw_account_id", "email", "access_token", "refresh_token", "error"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.validate_receipt({**receipt, key: "private-field"})
        for key in proof.FIXED_FACTS:
            changed = copy.deepcopy(receipt)
            changed[key] = not changed[key] if type(changed[key]) is bool else "wrong"
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.validate_receipt(changed)
        for key in ("source_handle", "account_handle", "grant_handle"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.validate_receipt({**receipt, key: "provider-identifier"})
        with self.assertRaises(ValueError):
            proof.validate_receipt({**receipt, "grant_generation": True})

    def test_manifest_single_source_no_model_or_duplicate_fields(self):
        manifest = {"schema_version": 1, "authorized_source_paths": ["/authorized/native/auth.json"]}
        self.assertEqual(proof.validate_manifest(manifest), manifest)
        for value in ({**manifest, "model": "unneeded"}, {**manifest, "schema_version": True},
                      {**manifest, "authorized_source_paths": []},
                      {**manifest, "authorized_source_paths": manifest["authorized_source_paths"] * 2},
                      {**manifest, "authorized_source_paths": ["/authorized/../native/auth.json"]},
                      {**manifest, "authorized_source_paths": ["/authorized/native/other.json"]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proof.validate_manifest(value)
        with self.assertRaises(ValueError):
            json.loads('{"schema_version":1,"schema_version":1}', object_pairs_hook=proof.strict_object)

    def test_only_completed_external_access_authority_is_accepted(self):
        snapshot = self.snapshot()
        self.assertEqual(proof.enrollment_facts(snapshot, "1" * 64, 100)["grant_generation"], 1)
        for identity in ({"provider": "codex"},
                         {"provider": "codex", "verified": False},
                         {"provider": "codex", "verified": 1},
                         {"provider": "codex", "verified": "true"},
                         {"provider": "codex", "verified": None},
                         {"provider": "codex", "verified": True, "subject": "private-model"}):
            changed = copy.deepcopy(snapshot)
            changed["accounts"][0]["identity"] = identity
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                proof.enrollment_facts(changed, "1" * 64, 100)
        changes = (("grants", "credential_kind", "oauth_refresh"), ("grants", "ownership", "omux"),
                   ("grants", "status", "quarantined"), ("grants", "custody_expires_at", 100),
                   ("grants", "provider_expires_at", 100), ("grants", "generation", True),
                   ("jobs", "status", "failed"), ("sources", "status", "detached"),
                   ("accounts", "lifecycle", "paused"))
        for section, key, value in changes:
            changed = copy.deepcopy(snapshot)
            changed[section][0][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                proof.enrollment_facts(changed, "1" * 64, 100)
        with self.assertRaises(ValueError):
            proof.enrollment_facts({**snapshot, "accounts": []}, "1" * 64, 100)

    def test_manifest_destination_namespace_custody_and_replacement(self):
        manifest = {"schema_version": 1, "authorized_source_paths": ["/authorized/native/auth.json"]}
        with tempfile.TemporaryDirectory(prefix="enrollment-model-") as temporary:
            root = Path(temporary)
            parent = root / "omux-live-inputs"
            parent.mkdir(mode=0o755)
            target = parent / "input.json"
            target.write_text(json.dumps(manifest))
            target.chmod(0o600)
            self.assertEqual(proof.read_manifest_namespace(str(root)), manifest)
            target.chmod(0o400)
            self.assertEqual(proof.read_manifest_namespace(str(root)), manifest)
            target.chmod(0o644)
            with self.assertRaises(ValueError):
                proof.read_manifest_namespace(str(root))
            target.chmod(0o600)
            root.chmod(0o777)
            with self.assertRaises(ValueError):
                proof.read_manifest_namespace(str(root))
            root.chmod(0o700)
            parent.chmod(0o777)
            with self.assertRaises(ValueError):
                proof.read_manifest_namespace(str(root))
            parent.chmod(0o755)
            held = root / "held"
            parent.rename(held)
            parent.symlink_to(held, target_is_directory=True)
            with self.assertRaises(ValueError):
                proof.read_manifest_namespace(str(root))
            parent.unlink()
            held.rename(parent)
            target.rename(parent / "held.json")
            target.symlink_to(parent / "held.json")
            with self.assertRaises(ValueError):
                proof.read_manifest_namespace(str(root))
            target.unlink()
            (parent / "held.json").rename(target)
            original_read = os.read

            def replace_after_read(fd, count):
                raw = original_read(fd, count)
                replacement = parent / "replacement.json"
                replacement.write_text(json.dumps(manifest))
                replacement.chmod(0o600)
                replacement.replace(target)
                return raw

            with patch.object(proof.os, "read", side_effect=replace_after_read):
                with self.assertRaises(ValueError):
                    proof.read_manifest_namespace(str(root))
            self.assertEqual(proof.read_manifest_namespace(str(root)), manifest)

            def replace_parent_after_read(fd, count):
                raw = original_read(fd, count)
                parent.rename(held)
                parent.mkdir(mode=0o755)
                replacement = parent / "input.json"
                replacement.write_text(json.dumps(manifest))
                replacement.chmod(0o600)
                return raw

            with patch.object(proof.os, "read", side_effect=replace_parent_after_read):
                with self.assertRaises(ValueError):
                    proof.read_manifest_namespace(str(root))


if __name__ == "__main__":
    unittest.main()
