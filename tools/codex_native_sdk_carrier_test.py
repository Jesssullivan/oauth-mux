"""Real small SDK/registry/JDK bytes and carrier/NAR/custody adversarial models.

The only SDK seam is the synthetic selected JDK root. Existing SDK validators,
registry/module/link-absence logic, byte readers and canonical NAR run unchanged.
No model claims a genuine carrier producer, metadata or application qualification.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_sdk_carrier as carrier
import codex_retained_sdk_export as sdk


class CarrierModels(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.origin, self.jdk = self.root / "origin", self.root / "jdk-origin"
        self.origin.mkdir(mode=0o700)
        self.jdk.mkdir(mode=0o700)
        self.jdk_patch = patch.object(sdk, "JDK", str(self.jdk))
        self.jdk_patch.start()
        self.write(self.jdk / "ordinary", b"synthetic immutable JDK bytes")
        (self.jdk / "inert").symlink_to("/not-authorized/sdk-carrier-model")
        repositories = self.origin / "repositories"
        repositories.mkdir(mode=0o700)
        public, other = repositories / "public+", repositories / "other"
        public.mkdir(mode=0o700)
        other.mkdir(mode=0o700)
        self.write(public / "MODULE.bazel", b'module(name="public")\n')
        self.write(public / "tool", b"tool model\x00bytes", 0o555)
        (public / "missing").symlink_to("../other/absent")
        graph = self.origin / "graph"
        graph.mkdir(mode=0o700)
        registry_bytes = b'{"public":"registry"}\n'
        registry_pin = carrier.sha(registry_bytes)
        url = "https://bcr.bazel.build/bazel_registry.json"
        lock = sdk.canonical({"registryFileHashes": {url: registry_pin}})
        for name in sdk.GRAPH:
            self.write(graph / name, lock if name == "MODULE.bazel.lock" else b"graph model " + name.encode(), 0o400)
        cache = self.origin / "registry-cache"
        self.write(cache / "content_addressable/sha256" / registry_pin / "file", registry_bytes)
        self.seal_dirs(self.origin)
        self.seal_dirs(self.jdk)
        budget = lambda: sdk.Budget(time.time() + 120)
        rows = []
        for root in (other, public):
            files = sdk.inventory(root, budget(), sealed=True)
            rows.append({"canonical_name": root.name, "root_kind": "generated", "source_root": str(root),
                         "files": files, "inventory_sha256": carrier.sha(sdk.canonical(files)),
                         "absent_links": [] if root == other else [{"origin": "public+/missing", "target": "other/absent"}]})
        graph_pins = {name: {"sha256": carrier.sha((graph / name).read_bytes())} for name in sdk.GRAPH}
        registry = sdk.registry_metadata(graph / "MODULE.bazel.lock", graph_pins["MODULE.bazel.lock"]["sha256"],
                                         cache, budget(), sealed=True)
        receipt = {"schema": sdk.SCHEMA, "baseline_receipt_sha256": sdk.BASELINE_SHA,
                   "baseline_inventory_sha256": sdk.BASELINE_INVENTORY, "graph_files": graph_pins,
                   "repositories": rows, "inventory_sha256": carrier.sha(sdk.canonical(rows)),
                   "mapping_sha256": graph_pins["MODULE.bazel.lock"]["sha256"],
                   "excluded": ["_main", "bazel_tools", "*.marker"], "qualification_only": False,
                   "nix_store_roots": [sdk.JDK], "modules": {"public": {"canonical_name": "public+",
                       "module_file_sha256": graph_pins.get("MODULE.bazel", {}).get("sha256")}},
                   "nix_inventory": sdk.inventory(self.jdk, budget(), sealed=True), "registry_metadata": registry,
                   "selection_sha256": "3" * 64, "producer": "//tools:codex_retained_sdk_export_run",
                   "counts": {"entries_read": 3, "bytes_read": 1,
                              "inventory_passes": {"qualification": 1, "copy": 1, "sealed_readback": 1},
                              "max_entries_per_pass": sdk.MAX_FILES, "max_inventory_passes": 3}}
        receipt["modules"]["public"]["module_file_sha256"] = carrier.sha((public / "MODULE.bazel").read_bytes())
        self.origin.chmod(0o700)
        self.original = sdk.canonical(receipt)
        self.write(self.origin / "receipt.json", self.original, 0o400)
        self.origin.chmod(0o555)
        self.pin = carrier.sha(self.original)
        entry = time.monotonic_ns()
        self.context = {"mode": "native-sdk-carrier-seal-reserved",
                        "epoch": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/12345678-1234-1234-1234-123456789abc",
                        "source_commit": "1" * 40, "graph_sha256": "2" * 64,
                        "entry_monotonic_ns": entry, "deadline_monotonic_ns": entry + 1200 * 10**9,
                        "work_cutoff_monotonic_ns": entry + 1170 * 10**9}
        self.deadline = self.context["work_cutoff_monotonic_ns"] / 10**9

    @staticmethod
    def write(path, raw, mode=0o444):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)

    @staticmethod
    def seal_dirs(root):
        for path, _, _ in os.walk(root, topdown=False, followlinks=False):
            Path(path).chmod(0o555)

    def tearDown(self):
        self.jdk_patch.stop()
        for path, _, _ in os.walk(self.root, followlinks=False):
            Path(path).chmod(0o700)
        self.temporary.cleanup()

    def seal(self, name="carrier"):
        report = carrier.seal(self.origin, self.pin, self.root / name, self.deadline, producer_context=self.context)
        return self.root / name, report, carrier.sha(carrier.encoded(report))

    def rewrite(self, root, manifest=None, payload=None):
        root.chmod(0o700)
        receipt = json.loads((root / "receipt.json").read_bytes())
        if payload is not None:
            (root / "payload.bin").chmod(0o600)
            (root / "payload.bin").write_bytes(payload)
            (root / "payload.bin").chmod(0o444)
            receipt["payload_sha256"] = carrier.sha(payload)
            receipt["payload_bytes"] = len(payload)
        if manifest is not None:
            raw = carrier.encoded(manifest)
            self.write(root / "manifest.json", raw)
            receipt["manifest_sha256"], receipt["manifest_bytes"] = carrier.sha(raw), len(raw)
            receipt["entry_count"] = len(manifest["entries"])
        self.write(root / "receipt.json", carrier.encoded(receipt))
        root.chmod(0o555)
        return carrier.sha(carrier.encoded(receipt))

    def test_real_roundtrip_full_registry_graph_jdk_nar_and_distinct_custody(self):
        root, report, pin = self.seal()
        self.assertEqual(carrier.validate_binding(root, pin, self.deadline), report)
        publication = carrier.publication_report(root, pin, self.deadline)
        self.assertEqual({row["name"] for row in publication["files"]}, set(carrier.FILES))
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        self.assertEqual((output / "sdk/receipt.json").read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE((output / "sdk/receipt.json").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((output / "sdk/graph/MODULE.bazel.lock").stat().st_mode), 0o400)
        self.assertEqual((output / "jdk/ordinary").read_bytes(), (self.jdk / "ordinary").read_bytes())
        self.assertEqual(os.readlink(output / "jdk/inert"), "/not-authorized/sdk-carrier-model")
        self.assertFalse((output / "sdk/repositories/other/absent").exists())
        self.assertNotEqual(fresh["fresh_custody"]["sdk"]["root_identity"], report["origin_custody"]["sdk"]["root_identity"])
        self.assertFalse(fresh["original_inodes_reused"])
        self.assertFalse(fresh["metadata_qualified"])
        self.assertEqual(carrier.revalidate_extraction(root, pin, output, self.deadline,
                         pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(fresh))), fresh)

    def test_deterministic_content_with_original_clock_context(self):
        first, _, _ = self.seal("first")
        second, _, _ = self.seal("second")
        for name in carrier.FILES:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        wrong = {**self.context, "work_cutoff_monotonic_ns": self.context["work_cutoff_monotonic_ns"] + 1}
        with self.assertRaises(ValueError):
            carrier.seal(self.origin, self.pin, self.root / "renewed", self.deadline, producer_context=wrong)
        self.assertFalse((self.root / "renewed").exists())

    def test_extra_origin_member_and_hardlink_refuse_before_publication(self):
        public = self.origin / "repositories/public+"
        public.chmod(0o700)
        self.write(public / "extra", b"unselected")
        public.chmod(0o555)
        with self.assertRaises(ValueError):
            self.seal()
        self.assertFalse((self.root / "carrier").exists())
        public.chmod(0o700)
        (public / "extra").unlink()
        os.link(public / "tool", self.root / "foreign-hardlink")
        public.chmod(0o555)
        with self.assertRaises(ValueError):
            self.seal()

    def test_payload_corruption_truncation_and_unlisted_carrier_refuse(self):
        for change in ("corrupt", "truncate", "extra"):
            with self.subTest(change=change):
                root, _, pin = self.seal(change)
                if change == "extra":
                    root.chmod(0o700)
                    self.write(root / "undeclared", b"extra")
                    root.chmod(0o555)
                else:
                    path = root / "payload.bin"
                    data = path.read_bytes()
                    path.chmod(0o600)
                    path.write_bytes((bytes([data[0] ^ 1]) + data[1:]) if change == "corrupt" else data[:-1])
                    path.chmod(0o444)
                with self.assertRaises(ValueError):
                    carrier.extract(root, pin, self.root / (change + "-out"), self.deadline)
                self.assertFalse((self.root / (change + "-out")).exists())

    def test_duplicate_traversal_special_parent_and_offset_manifests_refuse(self):
        for change in ("duplicate", "traversal", "device", "parent", "offset", "nar"):
            with self.subTest(change=change):
                root, _, _ = self.seal(change)
                value = json.loads((root / "manifest.json").read_bytes())
                if change == "duplicate":
                    value["entries"].append(dict(value["entries"][-1]))
                elif change == "traversal":
                    value["entries"][-1]["path"] = "../../foreign"
                elif change == "device":
                    value["entries"][-1]["kind"] = "device"
                elif change == "parent":
                    row = next(row for row in value["entries"] if row["kind"] == "directory" and row["path"] == "repositories")
                    row.update(kind="symlink", target="/foreign")
                    row.pop("mode")
                elif change == "offset":
                    next(row for row in value["entries"] if row["kind"] == "file")["offset"] += 1
                else:
                    value["nars"]["sdk"]["narHash"] = "sha256:" + "0" * 64
                pin = self.rewrite(root, manifest=value)
                with self.assertRaises(ValueError):
                    carrier.extract(root, pin, self.root / (change + "-out"), self.deadline)

    def test_origin_same_byte_root_replacement_is_refused(self):
        original = carrier.nar_origins
        def mutate(roots, rows, clock):
            result = original(roots, rows, clock)
            self.origin.rename(self.root / "detached-origin")
            shutil.copytree(self.root / "detached-origin", self.origin, symlinks=True)
            return result
        with patch.object(carrier, "nar_origins", side_effect=mutate):
            with self.assertRaises(ValueError):
                self.seal()

    def test_extracted_same_bytes_new_inode_and_created_absence_refuse_readback(self):
        root, _, pin = self.seal()
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        receipt_pin = carrier.sha(carrier.encoded(fresh))
        leaf = output / "sdk/repositories/public+/tool"
        leaf.parent.chmod(0o700)
        raw = leaf.read_bytes()
        leaf.unlink()
        self.write(leaf, raw, 0o555)
        leaf.parent.chmod(0o555)
        with self.assertRaises(ValueError):
            carrier.revalidate_extraction(root, pin, output, self.deadline, pinned_extraction_receipt_sha256=receipt_pin)
        other = output / "sdk/repositories/other"
        other.chmod(0o700)
        self.write(other / "absent", b"formerly absent")
        other.chmod(0o555)
        with self.assertRaises(ValueError):
            carrier.revalidate_extraction(root, pin, output, self.deadline, pinned_extraction_receipt_sha256=receipt_pin)

    def test_chmod_intermediate_symlink_refuses_without_touching_foreign_mode(self):
        root, _, pin = self.seal()
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        original = carrier.Output.seal_directory
        mutated = False
        def replace(output, name):
            nonlocal mutated
            if name == "sdk/repositories/public+" and not mutated:
                mutated = True
                selected = output.path / "sdk/repositories"
                selected.rename(output.path / "sdk/detached")
                selected.symlink_to(foreign, target_is_directory=True)
            return original(output, name)
        with patch.object(carrier.Output, "seal_directory", new=replace):
            with self.assertRaises((ValueError, OSError)):
                carrier.extract(root, pin, self.root / "raced", self.deadline)
        self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o700)
        self.assertFalse((self.root / "raced/extraction-receipt.json").exists())

    def test_output_existing_foreign_root_and_expired_cutoff_are_untouched(self):
        root, _, pin = self.seal()
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        self.write(foreign / "keep", b"foreign bytes")
        with self.assertRaises(FileExistsError):
            carrier.extract(root, pin, foreign, self.deadline)
        self.assertEqual((foreign / "keep").read_bytes(), b"foreign bytes")
        with self.assertRaises(ValueError):
            carrier.extract(root, pin, self.root / "expired", time.monotonic()-1)
        self.assertFalse((self.root / "expired").exists())

    def test_oversized_origin_rows_refuse_before_hash_and_absence_allocations(self):
        repository_rows = json.loads(self.original)
        repository_rows["repositories"][0]["files"] = [
            {"path": "unselected", "kind": "file", "mode": 0o444, "sha256": "4" * 64}
        ] * 129
        nix_rows = json.loads(self.original)
        nix_rows["nix_inventory"] = [{"path": "unselected"}] * 129
        invalid_list = json.loads(self.original)
        invalid_list["repositories"][0]["files"] = {"unselected": True}
        with patch.object(carrier, "MAX_ENTRIES", 128), \
                patch.object(sdk, "canonical", side_effect=AssertionError("hashed before row bound")), \
                patch.object(sdk, "public_link_absences", side_effect=AssertionError("allocated before row bound")):
            for name, receipt in (("repositories", repository_rows), ("jdk", nix_rows), ("type", invalid_list)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    carrier.receipt_shape(receipt, carrier.Clock(self.deadline))

    def test_integer_original_cutoff_refuses_when_float_clock_still_before(self):
        clock = carrier.Clock(self.deadline)
        clock.until_ns = self.context["work_cutoff_monotonic_ns"]
        with (patch.object(carrier.time, "monotonic", return_value=self.deadline-0.001),
              patch.object(carrier.time, "monotonic_ns", return_value=clock.until_ns)):
            with self.assertRaisesRegex(ValueError, "integer-deadline"):
                clock.tick()

    def test_created_regular_leaf_same_bytes_replacement_refuses_before_ready(self):
        root, _, pin = self.seal()
        original = carrier.scan
        replaced = False
        def replace(roots, expected, clock):
            nonlocal replaced
            if roots["sdk"].path.parent.name == "raced-leaf" and not replaced:
                replaced = True
                leaf = roots["sdk"].path / "repositories/public+/tool"
                leaf.parent.chmod(0o700)
                raw = leaf.read_bytes()
                leaf.unlink()
                self.write(leaf, raw, 0o555)
                leaf.parent.chmod(0o555)
            return original(roots, expected, clock)
        with patch.object(carrier, "scan", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "created-member-identity"):
                carrier.extract(root, pin, self.root / "raced-leaf", self.deadline)
        self.assertFalse((self.root / "raced-leaf/extraction-receipt.json").exists())

    def test_published_metadata_mutation_refuses_api_return(self):
        write = carrier.Output.file
        def swap_manifest(output, name, raw):
            write(output, name, raw)
            if name == "receipt.json":
                target = output.path / "manifest.json"
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" ")
                target.chmod(0o444)
        with patch.object(carrier.Output, "file", swap_manifest), self.assertRaises(ValueError):
            self.seal("unaccepted-carrier")
        root, _, pin = self.seal()
        finish = carrier.Output.finish
        def swap_fresh_receipt(output):
            finish(output)
            target = output.path / "extraction-receipt.json"
            if target.exists():
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" ")
                target.chmod(0o444)
        with patch.object(carrier.Output, "finish", swap_fresh_receipt), self.assertRaises(ValueError):
            carrier.extract(root, pin, self.root / "unaccepted-extraction", self.deadline)

    def test_fresh_mutation_during_final_carrier_validation_refuses(self):
        root, _, pin = self.seal()
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        original, calls = carrier.binding, 0
        def mutate(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 2:
                leaf = output / "jdk/ordinary"
                leaf.chmod(0o600)
                leaf.write_bytes(b"mutated during long final carrier pass")
                leaf.chmod(0o444)
            return result
        with patch.object(carrier, "binding", side_effect=mutate):
            with self.assertRaises(ValueError):
                carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(fresh)))


if __name__ == "__main__":
    unittest.main()
