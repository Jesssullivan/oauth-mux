"""Declared artifact identity, bounded refusal and metadata agreement fixtures."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import artifact_receipt as receipt
from extension_metadata import metadata
import pack


class ArtifactReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.extension = self.root / "development.zip"
        self.manifest_bytes = json.dumps({"key": base64.b64encode(b"public fixture key" * 4).decode(),
                                          "version": "0.2.0"}).encode()
        self.channel_bytes = (b'export const CHANNEL = "development";\n'
                              b'export const INSTANCE = "dev";\n'
                              b'export const NATIVE_HOST = "ai.xoxd.omux.dev";\n')
        self.write_extension()
        self.metadata = self.root / "metadata.json"
        self.public = metadata(self.extension, "development", "a" * 40, True)
        self.write_metadata()

    def write_extension(self, manifest=None, channel=None, extra=()):
        with zipfile.ZipFile(self.extension, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", self.manifest_bytes if manifest is None else manifest)
            archive.writestr("shared/channel.mjs", self.channel_bytes if channel is None else channel)
            for name, data in extra:
                archive.writestr(name, data)

    def write_metadata(self):
        self.metadata.write_text(json.dumps(self.public, indent=2) + "\n")

    def bundle(self):
        binary, daemon, reference, systemd, launchd = [self.root / name for name in
                                                     ("binary", "daemon", "reference", "systemd", "launchd")]
        binary.write_bytes(b"fixture CLI")
        daemon.write_bytes(b"fixture daemon")
        reference.write_text(json.dumps({"schemaVersion": 1,
                                        "product": {"version": "0.2.0", "status": "experimental"},
                                        "provenance": {"sourceRevision": None, "sourceDirty": True}}))
        systemd.write_bytes(b"fixture service")
        launchd.write_bytes(b"fixture launchd")
        payload = pack.make_bundle(binary, daemon, reference, systemd, launchd,
                                   "x86_64-linux", "a" * 40, True)
        path = self.root / "fixture.tar.gz"
        path.write_bytes(payload)
        return path, payload

    def rewrite_bundle(self, payload, updates):
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload)), mode="r:") as archive:
            entries = [(member, archive.extractfile(member).read()) for member in archive]
        result = io.BytesIO()
        with gzip.GzipFile(fileobj=result, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for member, old in entries:
                    data = updates.get(member.name, old)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        return result.getvalue()

    def test_exact_bundle_whole_archive_manifest_and_public_artifact_facts(self):
        path, payload = self.bundle()
        facts = receipt.collect(bundles=[str(path)])["bundles"][0]
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload)), mode="r:") as archive:
            raw_manifest = archive.extractfile("release-manifest.json").read()
        manifest = json.loads(raw_manifest)
        self.assertEqual(facts["archive_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(facts["archive_bytes"], len(payload))
        self.assertEqual(facts["manifest_sha256"], hashlib.sha256(raw_manifest).hexdigest())
        self.assertEqual(facts["provenance"], {"sourceRevision": "a" * 40, "sourceDirty": True})
        self.assertEqual(facts["target"], "x86_64-linux")
        self.assertEqual(facts["distribution"], "development-nix-closure-required")
        self.assertIsNone(facts["channel"])
        self.assertEqual(facts["artifacts"], manifest["artifacts"])

    def test_exact_extension_bytes_and_generated_metadata_agree(self):
        facts = receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])
        extension = facts["extensions"][0]
        self.assertEqual(extension["archive_sha256"], self.public["artifact"]["sha256"])
        self.assertEqual(extension["archive_bytes"], self.public["artifact"]["bytes"])
        self.assertEqual(extension["extension_id"], self.public["extension"]["id"])
        self.assertEqual(extension["manifest_sha256"], hashlib.sha256(self.manifest_bytes).hexdigest())
        self.assertEqual(extension["channel_mjs"].encode(), self.channel_bytes)
        self.assertEqual(extension["channel_mjs_sha256"], hashlib.sha256(self.channel_bytes).hexdigest())
        self.assertEqual(facts["metadata"]["raw_sha256"], hashlib.sha256(self.metadata.read_bytes()).hexdigest())
        self.assertEqual(facts["metadata"]["value"], self.public)
        self.assertFalse(facts["metadata"]["source_provenance_verified"])

    def test_malformed_bundle_and_artifact_manifest_mismatch_are_refused(self):
        path, payload = self.bundle()
        for malformed in (b"not gzip", self.rewrite_bundle(payload, {"bin/omux": b"changed"})):
            with self.subTest(payload_length=len(malformed)):
                path.write_bytes(malformed)
                with self.assertRaises((ValueError, OSError)):
                    receipt.collect(bundles=[str(path)])

    def test_bundle_reference_provenance_mismatch_is_refused(self):
        path, payload = self.bundle()
        _, files = pack.verify_bundle(payload)
        reference = json.loads(files["share/omux/reference.json"])
        reference["provenance"]["sourceDirty"] = False
        files["share/omux/reference.json"] = pack.json_bytes(reference)
        manifest = json.loads(files["release-manifest.json"])
        for artifact in manifest["artifacts"]:
            data = files[artifact["path"]]
            artifact["size"], artifact["sha256"] = len(data), pack.digest(data)
        files["release-manifest.json"] = pack.json_bytes(manifest)
        files["SHA256SUMS"] = "".join(f"{pack.digest(data)}  {name}\n" for name, data in sorted(files.items())
                                      if name != "SHA256SUMS").encode()
        path.write_bytes(self.rewrite_bundle(payload, files))
        with self.assertRaisesRegex(ValueError, "source-reference provenance mismatch"):
            receipt.collect(bundles=[str(path)])

    def test_extension_manifest_channel_and_unsafe_member_refusals(self):
        cases = [dict(manifest=b"{}"), dict(manifest=b"not JSON"),
                 dict(channel=self.channel_bytes + b"// unexpected\n"),
                 dict(extra=[("../outside", b"fixture")]),
                 dict(extra=[("manifest.json", self.manifest_bytes)])]
        for case in cases:
            with self.subTest(case=list(case)):
                with patch("warnings.warn"):
                    self.write_extension(**case)
                with self.assertRaises((ValueError, KeyError)):
                    receipt.collect(extensions=[str(self.extension)])

    def test_extension_manifest_nonstring_version_refused(self):
        manifest = json.loads(self.manifest_bytes)
        for value in (None, 2, True, ["0.2.0"]):
            manifest["version"] = value
            self.write_extension(manifest=json.dumps(manifest).encode())
            with self.assertRaisesRegex(ValueError, "identity or version"):
                receipt.collect(extensions=[str(self.extension)])

    def test_strict_metadata_types_fields_and_claims_refused(self):
        changes = [lambda value: value.update(schema_version=True),
                   lambda value: value["source"].update(dirty="true"),
                   lambda value: value["extension"].update(version=2),
                   lambda value: value["artifact"].update(bytes=True),
                   lambda value: value["signing"].update(status="signed"),
                   lambda value: value["capability_limits"].update(native_continuity="supported"),
                   lambda value: value.update(unreviewed="fixture")]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                value = json.loads(json.dumps(self.public))
                change(value)
                self.metadata.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])

    def test_metadata_archive_identity_version_and_channel_mismatch_refused(self):
        changes = [lambda value: value["artifact"].update(sha256="0" * 64),
                   lambda value: value["artifact"].update(filename="other.zip"),
                   lambda value: value["extension"].update(version="9.9.9"),
                   lambda value: value["extension"].update(id="a" * 32),
                   lambda value: value.update(channel="release", instance="default", native_host="ai.xoxd.omux")]
        for change in changes:
            value = json.loads(json.dumps(self.public))
            change(value)
            self.metadata.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])

    def test_duplicate_json_and_nonfinite_values_refused(self):
        for data in (b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}'):
            self.metadata.write_bytes(data)
            with self.assertRaises(ValueError):
                receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])

    def test_count_per_file_metadata_and_expansion_bounds(self):
        with self.assertRaisesRegex(ValueError, "count"):
            receipt.collect(bundles=["absent"] * 4)
        with self.assertRaisesRegex(ValueError, "count"):
            receipt.collect(extensions=["absent"] * 3)
        with self.assertRaisesRegex(ValueError, "count"):
            receipt.collect(extensions=[str(self.extension)], metadata=["absent"] * 2)
        with self.extension.open("wb") as stream:
            stream.truncate(receipt.ARCHIVE_LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            receipt.collect(extensions=[str(self.extension)])
        self.write_extension()
        self.metadata.write_bytes(b" " * (receipt.METADATA_LIMIT + 1))
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])
        with patch.object(receipt, "ARCHIVE_LIMIT", 4096):
            self.write_extension(extra=[("large.txt", b"z" * 10000)])
            with self.assertRaisesRegex(ValueError, "expanded byte"):
                receipt.collect(extensions=[str(self.extension)])

    def test_aggregate_limit_duplicate_inode_and_fifo_refusal(self):
        with patch.object(receipt, "TOTAL_LIMIT", 1):
            with self.assertRaisesRegex(ValueError, "aggregate"):
                receipt.collect(extensions=[str(self.extension)])
        alias = self.root / "alias.zip"
        os.link(self.extension, alias)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            receipt.collect(extensions=[str(self.extension), str(alias)])
        fifo = self.root / "fixture.zip"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular"):
            receipt.collect(extensions=[str(fifo)])

    def test_later_input_read_cannot_hide_earlier_replacement(self):
        actual = receipt.read_input
        def replace_earlier(value, *args, **kwargs):
            result = actual(value, *args, **kwargs)
            if Path(value) == self.metadata:
                replacement = self.root / "replacement.zip"
                replacement.write_bytes(self.extension.read_bytes())
                replacement.replace(self.extension)
            return result
        with patch.object(receipt, "read_input", replace_earlier):
            with self.assertRaisesRegex(ValueError, "before receipt publication"):
                receipt.collect(extensions=[str(self.extension)], metadata=[str(self.metadata)])

    def test_only_test_outputs_receipt_is_written_and_proof_limits_remain_false(self):
        output = self.root / "outputs"
        output.mkdir()
        arguments = ["--extension", str(self.extension), "--metadata", str(self.metadata)]
        with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(output)}):
            with patch("sys.stdout", io.StringIO()):
                self.assertEqual(receipt.main(arguments), 0)
        files = list(output.rglob("*"))
        self.assertEqual(sorted(path.relative_to(output).as_posix() for path in files),
                         ["artifact-receipt", "artifact-receipt/receipt.json"])
        raw = (output / "artifact-receipt/receipt.json").read_text()
        value = json.loads(raw)
        self.assertEqual(value["claim"], "source_artifact_facts_only")
        for key in ("authentication_performed", "application_execution_performed",
                    "native_support_proved", "compiled_source_binding_proved", "payload_output"):
            self.assertFalse(value[key])
        self.assertNotIn(str(self.root), raw)
        self.assertNotIn(base64.b64encode(b"public fixture key" * 4).decode(), raw)

    def test_malformed_archive_cli_is_redacted_and_publishes_nothing(self):
        output = self.root / "outputs"
        output.mkdir()
        self.extension.write_bytes(b"not ZIP")
        stderr = io.StringIO()
        with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(output)}):
            with patch("sys.stderr", stderr):
                self.assertEqual(receipt.main(["--extension", str(self.extension)]), 1)
        self.assertEqual(list(output.iterdir()), [])
        self.assertNotIn(str(self.root), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
