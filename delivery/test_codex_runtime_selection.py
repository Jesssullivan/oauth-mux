"""Synthetic artifact qualification predicates; no native tools or processes."""
import copy
import gzip
import hashlib
import io
import json
import struct
import tarfile
import unittest
from unittest import mock

import codex_runtime_selection as selection

runtime = selection.runtime


def digest(value):
    return hashlib.sha256(value).hexdigest()


def elf(needed=(), interpreter=None, rpath=()):
    """Finite minimal ELF edges consumed by the actual package verifier."""
    strings, references = bytearray(b"\0"), []
    for tag, value in [(1, name) for name in needed] + ([(29, ":".join(rpath))] if rpath else []):
        references.append((tag, len(strings)))
        strings.extend(value.encode() + b"\0")
    count = 2 + (interpreter is not None)
    dynamic_offset = 64 + 56 * count
    dynamic_size = 16 * (len(references) + 3)
    string_offset = dynamic_offset + dynamic_size
    interp = b"" if interpreter is None else interpreter.encode() + b"\0"
    interp_offset = string_offset + len(strings)
    length, base = interp_offset + len(interp), 0x400000
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, length, length, 4096)
    phdrs += struct.pack("<IIQQQQQQ", 2, 4, dynamic_offset, base + dynamic_offset,
                         0, dynamic_size, dynamic_size, 8)
    if interpreter is not None:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_offset, base + interp_offset,
                             0, len(interp), len(interp), 1)
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in
                       references + [(5, base + string_offset), (10, len(strings)), (0, 0)])
    return header + phdrs + dynamic + strings + interp


class CodexRuntimeSelectionTest(unittest.TestCase):
    def setUp(self):
        self.source_hash, self.producer_hash = "a" * 64, "b" * 64
        backend = elf(("libc.so.6",), runtime.portable._BACKEND_INTERPRETER, ("$ORIGIN/../lib",))
        self.files = {
            selection.LAUNCHER: runtime.codex_launcher("ld-linux-x86-64.so.2"),
            runtime.BACKEND: backend,
            selection.LOADER: elf(),
            "lib/codex/lib/libc.so.6": elf(),
            runtime.CA: b"-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n",
        }
        self.manifest = {
            "schema_version": 1, "status": runtime.STATUS, "native_support": False,
            "target": "x86_64-linux",
            "candidate": {
                "upstream_commit": runtime.COMMIT,
                "current_configuration": "owner-linux-fastbuild",
                **{field: "c" * 64 for field in (
                    "patch_sha256", "base_sha256", "binary_overlay_sha256",
                    "validation_sha256", "complete_source_inventory_sha256")},
                "current_source_receipt_sha256": self.source_hash,
                **{field: "12345678-1234-1234-1234-123456789abc" for field in (
                    "compile_invocation_id", "source_verification_invocation_id",
                    "current_compile_invocation_id", "current_source_verification_invocation_id")},
            },
            "executable": {"backend_max_bytes": runtime.MAX_BACKEND_BYTES,
                **{phase + suffix: value for phase in ("original", "stripped", "packaged")
                   for suffix, value in (("_sha256", digest(backend)), ("_bytes", len(backend)))}},
            "runtime": {
                "loader": selection.LOADER,
                "dependencies": sorted((selection.LOADER, "lib/codex/lib/libc.so.6")),
                "backendInterpreter": runtime.portable._BACKEND_INTERPRETER,
                "caBundle": runtime.CA, "backend_max_bytes": runtime.MAX_BACKEND_BYTES,
            },
            "transformations": {"source_receipt_sha256": self.source_hash,
                                "producer_receipt_sha256": self.producer_hash},
        }

    def bundle(self, manifest=None, files=None, modes=None):
        manifest = copy.deepcopy(self.manifest if manifest is None else manifest)
        files = dict(self.files if files is None else files)
        manifest["files"] = {
            name: {"sha256": digest(value), "bytes": len(value),
                   "mode": (modes or {}).get(name, 0o644 if name == runtime.CA else 0o755)}
            for name, value in files.items()
        }
        metadata = runtime.json_bytes(manifest)
        archive = runtime.archive_bytes(files, manifest)
        if modes:
            # Keep archive and manifest internally consistent: these predicates
            # exercise executable role policy, not just archive tamper detection.
            raw = io.BytesIO()
            with gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as packed:
                    for name, value in sorted({**files, runtime.MANIFEST: metadata}.items()):
                        entry = tarfile.TarInfo(name)
                        entry.size = len(value)
                        entry.mode = 0o644 if name == runtime.MANIFEST else manifest["files"][name]["mode"]
                        packed.addfile(entry, io.BytesIO(value))
            archive = raw.getvalue()
        receipt = {
            "schema_version": 1, "status": runtime.STATUS, "native_support": False,
            "candidate": manifest["candidate"], "executable": manifest["executable"],
            "archive_sha256": digest(archive), "archive_bytes": len(archive),
            "manifest_sha256": digest(metadata),
        }
        return archive, metadata, runtime.json_bytes(receipt)

    def qualify(self, bundle=None, **pins):
        return selection.qualify_runtime(*(self.bundle() if bundle is None else bundle),
            expected_source_receipt_sha256=pins.get("source", self.source_hash),
            expected_producer_receipt_sha256=pins.get("producer", self.producer_hash))

    def test_qualified_exact_bytes_have_no_installation_or_peer_authority(self):
        bundle = self.bundle()
        result = self.qualify(bundle)
        value = result["selection"]
        self.assertEqual(value["target"], "x86_64-linux")
        self.assertEqual(value["archive"]["sha256"], digest(bundle[0]))
        self.assertEqual(value["runtime_receipt_sha256"], digest(bundle[2]))
        self.assertEqual(value["roles"]["backend"]["sha256"], digest(self.files[runtime.BACKEND]))
        self.assertEqual(value["roles"]["backend"]["maximum_bytes"], 512 * 1024 * 1024)
        self.assertEqual(value["launch_profile"], selection.PROFILE)
        self.assertEqual(value["installation_ownership"], "absent")
        self.assertEqual(value["channel_authority"], "absent")
        self.assertEqual(value["custody_binding"], "absent")
        self.assertEqual(value["executable_attribution"], "unproved")
        self.assertIs(value["native_support"], False)
        self.assertEqual(result["selection_sha256"], digest(selection.canonical_selection_bytes(value)))

    def test_archive_external_manifest_and_receipt_tampering_refuse(self):
        archive, manifest, receipt = self.bundle()
        for altered in ((archive + b"tamper", manifest, receipt),
                        (archive, manifest + b" ", receipt),
                        (archive, manifest, receipt.replace(b'"archive_sha256": "', b'"archive_sha256": "f', 1))):
            with self.subTest(kind=altered[0] is archive), self.assertRaises(ValueError):
                self.qualify(altered)
        changed = {**self.files, runtime.BACKEND: self.files[runtime.BACKEND] + b"changed"}
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(files=changed))

    def test_self_consistent_receipt_cannot_admit_malformed_compression_or_tar(self):
        archive, manifest, receipt = self.bundle()
        for malformed in (b"not gzip", archive[:20], gzip.compress(b"not a tar archive", mtime=0)):
            changed = json.loads(receipt)
            changed.update(archive_sha256=digest(malformed), archive_bytes=len(malformed))
            with self.subTest(size=len(malformed)), self.assertRaises(ValueError):
                self.qualify((malformed, manifest, runtime.json_bytes(changed)))

    def test_missing_malformed_and_independently_mismatched_receipt_references_refuse(self):
        for field in ("source_receipt_sha256", "producer_receipt_sha256"):
            for bad in (None, "", "f" * 63, "F" * 64, "0" * 64, False):
                manifest = copy.deepcopy(self.manifest)
                manifest["transformations"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    self.qualify(self.bundle(manifest))
            manifest = copy.deepcopy(self.manifest)
            del manifest["transformations"][field]
            with self.assertRaises(ValueError):
                self.qualify(self.bundle(manifest))
        manifest = copy.deepcopy(self.manifest)
        del manifest["transformations"]
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(manifest))
        for pins in ({"source": "d" * 64}, {"producer": "e" * 64}, {"source": None}):
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                self.qualify(**pins)
        manifest = copy.deepcopy(self.manifest)
        manifest["candidate"]["current_source_receipt_sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(manifest))

    def test_wrong_loader_launcher_modes_and_backend_interpreter_refuse(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["runtime"]["loader"] = "lib/codex/lib/libc.so.6"
        files = {**self.files, selection.LAUNCHER: runtime.codex_launcher("libc.so.6")}
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(manifest, files))
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(files={**self.files, selection.LAUNCHER: b"#!/bin/sh\nexit 0\n"}))
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(modes={runtime.BACKEND: 0o644}))
        files = {**self.files, runtime.BACKEND: elf(("libc.so.6",), "/foreign/loader", ("$ORIGIN/../lib",))}
        manifest = copy.deepcopy(self.manifest)
        manifest["executable"]["packaged_sha256"] = digest(files[runtime.BACKEND])
        manifest["executable"]["packaged_bytes"] = len(files[runtime.BACKEND])
        with self.assertRaises(ValueError):
            self.qualify(self.bundle(manifest, files))

    def test_finite_input_role_and_carrier_bounds(self):
        bundle = self.bundle()
        for module, name, limit in ((runtime, "MAX_ARCHIVE_BYTES", len(bundle[0]) - 1),
                                    (runtime, "MAX_METADATA_BYTES", len(bundle[1]) - 1),
                                    (selection, "MAX_LAUNCHER_BYTES", len(self.files[selection.LAUNCHER]) - 1),
                                    (selection, "MAX_LOADER_BYTES", len(self.files[selection.LOADER]) - 1),
                                    (selection, "MAX_SELECTION_BYTES", 1)):
            with self.subTest(name=name), mock.patch.object(module, name, limit), self.assertRaises(ValueError):
                self.qualify(bundle)
        with mock.patch.object(runtime, "MAX_BACKEND_BYTES", 1), self.assertRaises(ValueError):
            self.qualify(bundle)

    def test_duplicate_keys_boolean_schema_and_claimed_support_refuse(self):
        archive, manifest, receipt = self.bundle()
        with self.assertRaises(ValueError):
            self.qualify((archive, manifest, b'{"schema_version":1,' + receipt[1:]))
        for field, value in (("schema_version", True), ("native_support", True)):
            changed = copy.deepcopy(self.manifest)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.qualify(self.bundle(changed))
        changed_receipt = json.loads(receipt)
        changed_receipt["archive_bytes"] = True
        with self.assertRaises(ValueError):
            self.qualify((archive, manifest, runtime.json_bytes(changed_receipt)))

    def test_canonical_digest_and_unknown_channel_claims_do_not_promote(self):
        first = self.qualify()
        self.assertEqual(first, self.qualify())
        value = first["selection"]
        reordered = {key: value[key] for key in reversed(value)}
        self.assertEqual(selection.canonical_selection_bytes(value), selection.canonical_selection_bytes(reordered))
        changed = copy.deepcopy(self.manifest)
        changed.update(channel="release", native_version="peer-claimed", ownership="home-manager")
        checked = self.qualify(self.bundle(changed))["selection"]
        self.assertNotIn("channel", checked)
        self.assertNotIn("native_version", checked)
        self.assertEqual(checked["channel_authority"], "absent")
        self.assertEqual(checked["installation_ownership"], "absent")
        self.assertIs(checked["native_support"], False)
        self.assertNotEqual(first["selection"]["manifest_sha256"], checked["manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
