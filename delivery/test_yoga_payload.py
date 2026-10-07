"""Modeled public-byte packaging tests; no tools, Nix, transfer or activation.

The fixture uses an explicitly held temporary anchor instead of production's
root-to-input no-writable-ancestor rule. Actual regular-file descriptors, hashes,
directory replacement, archive validation and producer cleanup are exercised.
Runtime proof validation is real; only its public inventory pin is synthetic.
"""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import browser_runtime_authority as authority
import yoga_payload as payload


def source_archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(content), 0o644
            archive.addfile(member, io.BytesIO(content))
    return gzip.compress(stream.getvalue(), mtime=0)


def packed(manifest, files, *, extra=None, order=None):
    encoded = payload.canonical(manifest)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        payload.tar_member(archive, "manifest.json", len(encoded), io.BytesIO(encoded))
        for name in order or sorted(files):
            payload.tar_member(archive, name, len(files[name]), io.BytesIO(files[name]))
        if extra is not None:
            archive.addfile(extra, io.BytesIO(b"x") if extra.isfile() else None)
    return stream.getvalue(), payload.digest(encoded)


class PayloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original_parent = payload.parent
        self.parent_patch = patch.object(payload, "parent", self.anchored_parent)
        self.parent_patch.start(); self.addCleanup(self.parent_patch.stop)
        self.files = {name: ("# selected public source " + name + "\n").encode() for name in payload.SOURCE_FILES}
        self.files.update({"BUILD.bazel": b"# selected graph\n", "MODULE.bazel": b"# selected module\n",
                           "flake.nix": b"{}\n", "flake.lock": b"{}\n", "tools/gate.py": b"# selected gate\n"})
        graph = hashlib.sha256()
        for name in sorted({"BUILD.bazel", "MODULE.bazel", "flake.nix", "flake.lock", "tools/gate.py"}):
            graph.update(name.encode() + b"\0" + hashlib.sha256(self.files[name]).digest())
        browser_root = "/nix/store/" + "0" * 32 + "-chromium-147.0.7727.116"
        systemd = sorted("/nix/store/" + alias.split("/")[1] for alias in authority.SYSTEMD_ALIASES)
        rows = [{"path": browser_root, "narHash": "sha256:" + "a" * 64, "narSize": 42,
                 "references": sorted([authority.BLUEZ_ROOT, *systemd])}]
        rows += [{"path": name, "narHash": "sha256:" + "b" * 64, "narSize": 1, "references": []}
                 for name in [authority.BLUEZ_ROOT, *systemd]]
        inventory = {"schemaVersion": 1, "system": "x86_64-linux", "mode": "local-sqlite-readonly-snapshot",
            "contentRehashed": False, "realized": False, "published": False, "roots": [browser_root],
            "packages": {name: {"out": browser_root} for name in ("node", "python", "pnpm", "bash", "coreutils", "chromium")},
            "paths": rows}
        # The declared cached inventory preserves these public versions from
        # offline-site-roots.json alongside package roots.
        inventory["packages"]["node"]["version"] = "22.22.2"
        inventory["packages"]["pnpm"]["version"] = "10.33.2"
        inventory_bytes = payload.canonical(inventory)
        pin = patch.object(authority, "INVENTORY_SHA256", payload.digest(inventory_bytes))
        pin.start(); self.addCleanup(pin.stop)
        mapping = {"schemaVersion": 1, "passed": True, "mode": "shared-selection-offline-evaluation",
            "provenance": {"rootsSha256": authority.ROOTS_SHA256, "lockSha256": authority.LOCK_SHA256,
                           "selectionSha256": authority.SELECTION_SHA256, "flakeSha256": authority.FLAKE_SHA256},
            "sourceInputSha256": "1" * 64, "nixpkgsRevision": authority.REVISION,
            "nixpkgsSourceNarHash": authority.SOURCE_NAR_HASH, "sourceContentRehashed": True,
            "selectedOutputsMatched": True, "evaluationStore": "private-local-temporary",
            "evaluationStoreByteLimit": 1024**3, "wholeFlakeEvaluated": False, "realized": False, "browserExecuted": False}
        self.browser_proof = self.proof(payload.digest(inventory_bytes), len(rows), sum(row["narSize"] for row in rows))
        exclusions = payload.canonical({"schemaVersion": 1, "policy": authority.EXCLUSION_POLICY,
            "executionAuthority": False, "exclusions": [
                {"alias": "closure/" + authority.BLUEZ_ROOT.split("/")[-1] + "/etc/bluetooth/" + name + ".conf",
                 "policy": authority.EXCLUSION_POLICY, "reason": "inert host configuration link; excluded from execution inputs",
                 "target_class": "host-configuration", "target_followed": False} for name in ("input", "main", "network")]
            + [{"alias": alias, "reason": "operator runtime environment configuration; not an action input"}
               for alias in sorted(authority.SYSTEMD_ALIASES)]})
        # Arbitrary diagnostics are selected input bytes, but never exportable
        # receipt fields. This synthetic local fixture path must be projected out.
        browser_nar = str(self.root).encode() + b" fixture diagnostic\n" + payload.canonical(self.browser_proof) + b"\n"
        mapping_bytes = payload.canonical(mapping)
        runtime = authority.join(inventory_bytes, mapping_bytes, browser_nar, exclusions,
                                 payload.digest(mapping_bytes), payload.digest(browser_nar), payload.digest(exclusions))
        controller_inventory = payload.canonical({"schemaVersion": 1,
            "paths": [{"path": "/nix/store/" + "1" * 32 + "-controller", "narHash": "sha256:" + "c" * 64,
                       "narSize": 8, "references": []}]})
        self.controller_proof = self.proof(payload.digest(controller_inventory), 1, 8)
        contents = {name: ("declared public input " + name).encode() for name in payload.INPUTS}
        contents.update(runtime_authority=payload.canonical(runtime), source_archive=source_archive(self.files),
            browser_inventory=inventory_bytes, browser_nar=browser_nar, controller_inventory=controller_inventory,
            controller_nar=b"fixture diagnostic\n" + payload.canonical(self.controller_proof) + b"\n")
        self.paths = {}
        for name, data in contents.items():
            target = self.root / name
            target.write_bytes(data); target.chmod(0o644)
            self.paths[name] = target
        self.selected = {"schemaVersion": 1, "scope": "yoga-public-payload-selection-v1", "sourceGraphSha256": graph.hexdigest(),
            "sourceFilesSha256": {name: payload.digest(self.files[name]) for name in payload.SOURCE_FILES},
            "inputSha256": {name: payload.digest(contents[name]) for name in payload.INPUTS},
            "evidenceSha256": {name: payload.digest(contents[name]) for name in payload.EVIDENCE}}

    @staticmethod
    def proof(inventory_sha, paths, count):
        return {"schemaVersion": 1, "passed": True, "inventorySha256": inventory_sha, "descriptorSha256": "2" * 64,
            "verifiedPaths": paths, "verifiedRegularInputs": 1, "verifiedNarBytes": count, "contentRehashed": True,
            "linkTargetsFollowed": False, "executionAuthority": False, "flakeMappingVerified": False, "realized": False}

    def anchored_parent(self, path):
        relative = Path(path).relative_to(self.root)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for component in relative.parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                os.close(descriptor); descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def output(self, name="out"):
        output = self.root / name
        output.mkdir(mode=0o700)
        return output

    def export(self, name="out"):
        output = self.output(name)
        result = payload.produce(self.paths, self.selected, output)
        return result, output

    def unpack(self, output):
        with tarfile.open(output / "yoga-payload.tar", "r:") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
            files = {name: archive.extractfile(name).read() for name in manifest["members"]}
        return manifest, files

    def test_real_proof_validation_deterministic_fixed_members_and_public_projection(self):
        result, output = self.export()
        second, other = self.export("other")
        self.assertEqual(result, second)
        self.assertEqual((output / "yoga-payload.tar").read_bytes(), (other / "yoga-payload.tar").read_bytes())
        data = (output / "yoga-payload.tar").read_bytes()
        manifest = payload.validate_archive(data, result["manifestSha256"])
        self.assertEqual(result["archiveSha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["archiveBytes"], len(data))
        self.assertEqual(set(manifest["members"]), set(payload.MEMBERS.values()))
        self.assertNotIn(str(self.root).encode(), data)
        self.assertNotIn(b"fixture diagnostic", data)
        self.assertEqual(manifest["source"]["scope"], "source-inventory-only")
        self.assertIs(manifest["source"]["compiledArtifactCorrespondenceVerified"], False)
        for key in ("destinationRegistrationVerified", "storePayloadIncluded", "executionAuthority", "activationPerformed", "transferPerformed"):
            self.assertIs(manifest[key], False)
        for file in output.iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o444)

    def test_each_declared_input_and_evidence_digest_is_required_before_output(self):
        for name in sorted(self.paths):
            with self.subTest(name=name):
                selected = copy.deepcopy(self.selected)
                selected["inputSha256" if name in payload.INPUTS else "evidenceSha256"][name] = "f" * 64
                output = self.output("out-" + name)
                with self.assertRaisesRegex(payload.PayloadError, "digest_mismatch"):
                    payload.produce(self.paths, selected, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_exact_source_graph_and_runner_file_hashes_required(self):
        for key in ("sourceGraphSha256", *sorted(payload.SOURCE_FILES)):
            selected = copy.deepcopy(self.selected)
            if key == "sourceGraphSha256":
                selected[key] = "f" * 64
            else:
                selected["sourceFilesSha256"][key] = "f" * 64
            with self.subTest(key=key), self.assertRaisesRegex(payload.PayloadError, "source_binding"):
                payload.produce(self.paths, selected, self.output("source-" + key.replace("/", "-")))

    def test_capture_wide_earlier_same_size_write_is_refused(self):
        original = payload.Captured.bytes
        modified = False
        def later_read(item, maximum):
            nonlocal modified
            data = original(item, maximum)
            if not modified:
                modified = True
                target = self.paths["bundle"]
                with target.open("r+b") as stream:
                    stream.write(b"X" * target.stat().st_size)
            return data
        output = self.output()
        with patch.object(payload.Captured, "bytes", later_read), self.assertRaisesRegex(payload.PayloadError, "input_changed"):
            payload.produce(self.paths, self.selected, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_declared_alias_retarget_is_refused(self):
        alias = self.root / "declared-alias"
        alias.symlink_to(self.paths["bundle"])
        item = payload.Captured(alias, self.selected["inputSha256"]["bundle"], payload.MAX_FILE, time.monotonic() + 10)
        try:
            other = self.root / "alternate"
            other.write_bytes(self.paths["bundle"].read_bytes()); other.chmod(0o644)
            alias.unlink(); alias.symlink_to(other)
            with self.assertRaisesRegex(payload.PayloadError, "input_changed"):
                item.check()
        finally:
            item.close()

    def test_final_selector_drift_cleans_both_owned_outputs(self):
        output = self.output()
        def refused():
            raise payload.PayloadError("input_changed")
        with self.assertRaisesRegex(payload.PayloadError, "input_changed"):
            payload.produce(self.paths, self.selected, output, final_check=refused)
        self.assertEqual(list(output.iterdir()), [])

    def test_output_ancestor_symlink_swap_refuses_without_external_creation(self):
        output = self.output()
        external = self.output("external")
        moved = self.root / "retained-output"
        def replace():
            output.rename(moved); output.symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError):
            payload.produce(self.paths, self.selected, output, final_check=replace)
        self.assertEqual(list(external.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_descriptor_unwind_on_immediate_file_fstat_failure(self):
        observed = []
        real_open, real_fstat = os.open, os.fstat
        def record(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            observed.append(descriptor)
            return descriptor
        with patch.object(payload.os, "open", record), patch.object(payload.os, "fstat", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                payload.Captured(self.paths["bundle"], self.selected["inputSha256"]["bundle"], payload.MAX_FILE,
                                 time.monotonic() + 10)
        self.assertEqual(len(observed), 2)
        for descriptor in observed:
            with self.assertRaises(OSError):
                real_fstat(descriptor)

    def test_manifest_in_place_mutation_during_archive_write_is_refused(self):
        output = self.output()
        original = payload.CopyReader.finish
        changed = False
        def mutate(reader):
            nonlocal changed
            original(reader)
            if not changed:
                changed = True
                with (output / "yoga-payload.json").open("r+b") as stream:
                    stream.write(b"X")
        with patch.object(payload.CopyReader, "finish", mutate), self.assertRaisesRegex(payload.PayloadError, "output_invalid"):
            payload.produce(self.paths, self.selected, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_no_overwrite_of_existing_operator_output(self):
        output = self.output()
        (output / "yoga-payload.json").write_bytes(b"existing owned fixture")
        with self.assertRaises(FileExistsError):
            payload.produce(self.paths, self.selected, output)
        self.assertEqual((output / "yoga-payload.json").read_bytes(), b"existing owned fixture")
        self.assertFalse((output / "yoga-payload.tar").exists())

    def test_named_output_replacement_preserved_and_other_owned_output_removed(self):
        output = self.output()
        def replace():
            target = output / "yoga-payload.json"
            target.unlink(); target.write_bytes(b"foreign fixture replacement")
        with self.assertRaisesRegex(payload.PayloadError, "cleanup_incomplete"):
            payload.produce(self.paths, self.selected, output, final_check=replace)
        self.assertEqual((output / "yoga-payload.json").read_bytes(), b"foreign fixture replacement")
        self.assertFalse((output / "yoga-payload.tar").exists())

    def test_fifo_and_writable_regular_inputs_are_refused(self):
        for kind in ("fifo", "writable"):
            target = self.paths["bundle"]
            target.unlink()
            if kind == "fifo":
                os.mkfifo(target, 0o600)
            else:
                target.write_bytes(b"input"); target.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaisesRegex(payload.PayloadError, "input_invalid"):
                payload.produce(self.paths, self.selected, self.output(kind))

    def test_file_total_and_expired_deadline_bounds_refuse_without_output(self):
        for constant in ("MAX_FILE", "MAX_TOTAL"):
            output = self.output(constant)
            with patch.object(payload, constant, 1), self.assertRaisesRegex(payload.PayloadError, "byte_bound"):
                payload.produce(self.paths, self.selected, output)
            self.assertEqual(list(output.iterdir()), [])
        with self.assertRaisesRegex(payload.PayloadError, "deadline_exceeded"):
            payload.produce(self.paths, self.selected, self.output("deadline"), until=time.monotonic() - 1)

    def test_bad_nar_counters_claims_and_incomplete_reference_closure_refused(self):
        rows, total = payload.inventory(self.paths["controller_inventory"].read_bytes())
        for key, value in (("verifiedNarBytes", 9), ("verifiedPaths", 2), ("executionAuthority", True), ("realized", True)):
            proof = dict(self.controller_proof, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(payload.PayloadError, "runtime_binding"):
                payload.nar_proof(payload.canonical(proof), self.controller_proof["inventorySha256"], rows, total)
        value = json.loads(self.paths["controller_inventory"].read_bytes())
        value["paths"][0]["references"] = ["/nix/store/" + "2" * 32 + "-missing"]
        with self.assertRaisesRegex(payload.PayloadError, "inventory_invalid"):
            payload.inventory(payload.canonical(value))

    def test_inventory_preserved_verbatim_and_arbitrary_private_metadata_refused(self):
        original = self.paths["controller_inventory"].read_bytes()
        spaced = json.dumps(json.loads(original), indent=2).encode() + b"\n"
        self.paths["controller_inventory"].write_bytes(spaced)
        self.selected["evidenceSha256"]["controller_inventory"] = payload.digest(spaced)
        proof = dict(self.controller_proof, inventorySha256=payload.digest(spaced))
        self.paths["controller_nar"].write_bytes(payload.canonical(proof))
        self.selected["evidenceSha256"]["controller_nar"] = payload.digest(payload.canonical(proof))
        result, output = self.export()
        manifest, files = self.unpack(output)
        self.assertEqual(files["evidence/controller_inventory"], spaced)
        self.assertEqual(manifest["members"]["evidence/controller_inventory"]["sha256"], payload.digest(spaced))
        payload.validate_archive((output / "yoga-payload.tar").read_bytes(), result["manifestSha256"])
        altered = json.loads(spaced); altered["operatorPath"] = str(self.root)
        with self.assertRaisesRegex(payload.PayloadError, "inventory_invalid"):
            payload.inventory(payload.canonical(altered))

    def test_actual_package_versions_preserved_in_export_and_independent_digests(self):
        original = self.paths["browser_inventory"].read_bytes()
        inventory = json.loads(original)
        self.assertEqual(inventory["packages"]["node"]["version"], "22.22.2")
        self.assertEqual(inventory["packages"]["pnpm"]["version"], "10.33.2")
        self.assertEqual(set(inventory["packages"]["chromium"]), {"out"})
        result, output = self.export()
        manifest, files = self.unpack(output)
        self.assertEqual(files["evidence/browser_inventory"], original)
        self.assertEqual(manifest["members"]["evidence/browser_inventory"]["sha256"], payload.digest(original))
        self.assertEqual(manifest["selection"]["evidenceSha256"]["browser_inventory"], payload.digest(original))
        runtime = json.loads(files["inputs/runtime_authority"])
        self.assertEqual(runtime["packages"], inventory["packages"])
        payload.validate_archive((output / "yoga-payload.tar").read_bytes(), result["manifestSha256"])

    def test_package_version_is_bounded_public_token_and_no_extra_metadata(self):
        original = json.loads(self.paths["browser_inventory"].read_bytes())
        for version in (None, True, 22, "", "/home/operator", "22.22.2 private", "22.22.2\n", "\u00e9", "1" * 129):
            value = copy.deepcopy(original)
            value["packages"]["node"]["version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(payload.PayloadError, "inventory_invalid"):
                payload.inventory(payload.canonical(value))
        for field in ("operatorPath", "email", "privateMetadata"):
            value = copy.deepcopy(original)
            value["packages"]["node"][field] = "fixture"
            with self.subTest(field=field), self.assertRaisesRegex(payload.PayloadError, "inventory_invalid"):
                payload.inventory(payload.canonical(value))
        # Both allowed item forms remain valid, including a bounded public
        # prerelease token; no normalization changes the original bytes.
        value = copy.deepcopy(original)
        value["packages"]["node"]["version"] = "1" + "a" * 127
        value["packages"]["pnpm"]["version"] = "10.33.2+fixture~1_rc-2"
        payload.inventory(payload.canonical(value))

    def test_source_traversal_duplicate_symlink_and_private_state_are_refused(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), (".ssh/fixture", tarfile.REGTYPE)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                item = tarfile.TarInfo(name); item.type = kind; item.size = 1 if kind == tarfile.REGTYPE else 0
                archive.addfile(item, io.BytesIO(b"x") if item.size else None)
            with self.subTest(name=name), self.assertRaisesRegex(payload.PayloadError, "source_invalid"):
                payload.source_binding(gzip.compress(stream.getvalue(), mtime=0), self.selected, time.monotonic() + 10)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo("same"), io.BytesIO(b""))
        with self.assertRaisesRegex(payload.PayloadError, "source_invalid"):
            payload.source_binding(gzip.compress(stream.getvalue(), mtime=0), self.selected, time.monotonic() + 10)

    def test_source_full_expansion_hidden_tail_and_nonzero_padding_refused(self):
        original = self.paths["source_archive"].read_bytes()
        raw = gzip.decompress(original)
        padded = bytearray(raw)
        first_name = sorted(self.files)[0]
        padded[512 + len(self.files[first_name])] = 1
        cases = (original + gzip.compress(b"hidden unselected fixture", mtime=0),
                 original + gzip.compress(b"\0" * 10240, mtime=0), gzip.compress(bytes(padded), mtime=0))
        for data in cases:
            with self.subTest(bytes=len(data)), self.assertRaisesRegex(payload.PayloadError, "source_invalid"):
                payload.source_binding(data, self.selected, time.monotonic() + 10)
        with patch.object(payload, "MAX_SOURCE_EXPANDED", 512), self.assertRaisesRegex(payload.PayloadError, "byte_bound"):
            payload.source_binding(original, self.selected, time.monotonic() + 10)

    def test_archive_member_change_and_repin_selection_forgery_are_refused(self):
        _, output = self.export()
        manifest, files = self.unpack(output)
        files["inputs/bundle"] = b"forged payload"
        forged, pin = packed(manifest, files)
        with self.assertRaises(payload.PayloadError):
            payload.validate_archive(forged, pin)
        manifest["members"]["inputs/bundle"] = {"sha256": payload.digest(files["inputs/bundle"]),
                                                  "bytes": len(files["inputs/bundle"]), "mode": 0o444}
        forged, pin = packed(manifest, files)
        with self.assertRaisesRegex(payload.PayloadError, "digest_mismatch"):
            payload.validate_archive(forged, pin)

    def test_archive_extra_symlink_missing_reordered_and_trailing_bytes_refused(self):
        _, output = self.export()
        manifest, files = self.unpack(output)
        cases = []
        link = tarfile.TarInfo("inputs/escape"); link.type = tarfile.SYMTYPE; link.linkname = "/outside-fixture"
        cases.append(packed(manifest, files, extra=link))
        missing = dict(files); missing.pop("inputs/bundle")
        cases.append(packed(manifest, missing))
        cases.append(packed(manifest, files, order=list(reversed(sorted(files)))))
        original, pin = packed(manifest, files)
        cases += [(original + b"unselected tail", pin), (original + b"\0" * 10240, pin)]
        padded = bytearray(original)
        padded[512 + len(payload.canonical(manifest))] = 1
        cases.append((bytes(padded), pin))
        for data, pin in cases:
            with self.subTest(bytes=len(data)), self.assertRaisesRegex(payload.PayloadError, "archive_invalid"):
                payload.validate_archive(data, pin)

    def test_manifest_authority_broadening_and_noncanonical_projected_proof_refused(self):
        _, output = self.export()
        manifest, files = self.unpack(output)
        manifest["executionAuthority"] = True
        data, pin = packed(manifest, files)
        with self.assertRaisesRegex(payload.PayloadError, "archive_invalid"):
            payload.validate_archive(data, pin)
        manifest["executionAuthority"] = False
        name = "evidence/controller_nar"
        files[name] = b"fixture diagnostic\n" + files[name] + b"\n"
        manifest["members"][name] = {"sha256": payload.digest(files[name]), "bytes": len(files[name]), "mode": 0o444}
        data, pin = packed(manifest, files)
        with self.assertRaisesRegex(payload.PayloadError, "archive_invalid"):
            payload.validate_archive(data, pin)

    def test_selection_exact_keys_duplicate_json_and_public_no_session_metadata(self):
        for field in ("seat", "bootId", "deadlineMonotonicNs", "home", "activation"):
            selected = copy.deepcopy(self.selected); selected[field] = "fixture value"
            with self.subTest(field=field), self.assertRaisesRegex(payload.PayloadError, "selection_invalid"):
                payload.selection(selected)
        with self.assertRaises(ValueError):
            authority.parse(b'{"schemaVersion":1,"schemaVersion":2}')

    def test_production_parent_walk_refuses_mutable_shared_ancestor(self):
        with self.assertRaisesRegex(payload.PayloadError, "input_invalid"):
            descriptor = self.original_parent("/tmp/fixture-input")
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
