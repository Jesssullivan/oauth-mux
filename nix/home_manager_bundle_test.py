"""Modeled public bundle/custody tests; no genuine Nix or provider execution."""
import base64
from contextlib import ExitStack, redirect_stdout, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import home_manager_bundle as bundle
import home_manager_acquired_inputs as acquired
import home_manager_acquired_inputs_test as pair_fixtures
import home_manager_artifact as artifact
import home_manager_artifact_test as artifact_fixtures
import home_manager_inputs
import nar_descriptor
from evaluation_runner import EvaluationFailure


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.addCleanup(self.cleanup)
        self.fixture = pair_fixtures.AcquiredPairTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        # The production bundle permits contained inert links only. Rebind the
        # tiny modeled pair and pins after replacing its historical external link.
        for name in acquired.NAMES:
            root = Path(self.fixture.roots[name])
            root.chmod(0o700)
            (root / "inert-link").unlink()
            (root / "inert-link").symlink_to("lib/absent-target.nix")
            descriptor = nar_descriptor.describe(root)
            nar = nar_descriptor.hash_descriptor(descriptor)
            sri = "sha256-" + base64.b64encode(bytes.fromhex(nar["narHash"][7:])).decode()
            self.fixture.inventory["sources"][name] = {"nodes": descriptor["nodes"]}
            self.fixture.receipt["sources"][name].update(narHash=sri, narSize=nar["narSize"])
            self.fixture.pins[name] = (self.fixture.pins[name][0], sri)
            node = "hm" if name == "home-manager" else "np"
            self.fixture.lock["nodes"][node]["locked"]["narHash"] = sri
            root.chmod(0o555)
        self.lock, raw_pair, pair_sha, raw_inventory, roots = self.fixture.arguments()
        self.retained = self.base / "declared"
        self.retained.mkdir(mode=0o700)
        (self.retained / "pair").mkdir(mode=0o700)
        for name in acquired.NAMES:
            shutil.copytree(roots[name], self.retained / "pair" / name, symlinks=True)
        self.write(self.retained / "pair/receipt.json", raw_pair)
        self.write(self.retained / "pair/inventory.json", raw_inventory)
        art = artifact_fixtures.ArtifactTest("runTest")
        art.setUp()
        self.addCleanup(art.doCleanups)
        art.export()
        art_root, raw_artifact = art.retained()
        shutil.copytree(art_root, self.retained / "artifact")
        self.write(self.retained / "artifact-receipt.json", raw_artifact)
        self.outputs = self.base / "outputs"
        self.outputs.mkdir(mode=0o700)
        self.scratch = self.base / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.lock_path = self.base / "lock.json"
        self.write(self.lock_path, self.lock)
        self.modules = {}
        for name in bundle.evaluator.MODULES:
            path = self.base / name
            self.write(path, b"{} # modeled module; never executed\n")
            self.modules[name] = str(path)
        self.authority = ExitStack()
        self.addCleanup(self.authority.close)
        self.authority.enter_context(patch.dict(home_manager_inputs.PINS, self.fixture.pins, clear=True))
        self.authority.enter_context(patch.object(bundle, "PAIR_SHA", pair_sha))
        self.authority.enter_context(patch.object(bundle, "ARTIFACT_SHA", artifact.sha(raw_artifact)))
        self.authority.enter_context(patch.object(artifact, "FREE_FLOOR", 0))
        files = sorted(node["path"] for node in nar_descriptor.describe(self.retained / "artifact")["nodes"]
                       if node["type"] == "regular")
        layout = {"schemaVersion": 1, "pairReceipt": "pair/receipt.json", "pairInventory": "pair/inventory.json",
                  "pairReceiptSha256": bundle.PAIR_SHA, "artifactReceipt": "artifact-receipt.json",
                  "artifactManifest": "artifact/release-manifest.json", "artifactReceiptSha256": bundle.ARTIFACT_SHA,
                  "artifactFiles": files, "sourceWrapper": bundle.SOURCE_WRAPPER}
        self.layout = self.retained / "layout.json"
        self.write(self.layout, bundle.encoded(layout))

    def cleanup(self):
        for directory, _, _ in os.walk(self.base, followlinks=False):
            os.chmod(directory, 0o700)
        self.temp.cleanup()

    def write(self, path, data):
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(0o444)

    def pack(self, **changes):
        return bundle.pack(str(self.layout), str(self.lock_path), str(self.outputs), **changes)

    def consume(self, result, **changes):
        arguments = {"bundle": str(self.outputs / "bundle"), "frozen_bundle_sha": result["bundleSha256"],
                     "receipt_path": str(self.outputs / "receipt.json"), "frozen_receipt_sha": result["receiptSha256"],
                     "lock_path": str(self.lock_path), "nix": "/declared/native-nix", "modules": self.modules,
                     "scratch": str(self.scratch)}
        arguments.update(changes)
        return bundle.evaluate_bundle(**arguments)

    def model_nix(self):
        stack = ExitStack()
        stack.enter_context(patch.object(bundle.evaluator, "native_nix", return_value="/declared/native-nix"))
        stack.enter_context(patch.object(bundle.evaluator, "evaluate", return_value={
            name: True for name in bundle.evaluator.PREDICATES}))
        return stack

    def rewrite_compact_receipt(self, result, change):
        path = self.outputs / "receipt.json"
        value = json.loads(path.read_bytes())
        change(value)
        raw = bundle.encoded(value)
        self.write(path, raw)
        return {**result, "receiptSha256": bundle.sha(raw)}

    def retained_representation(self):
        # Only modeled fixture files are changed; production never walks input roots.
        for path in self.retained.rglob("*"):
            if path.is_file() and not path.is_symlink() and path != self.layout:
                path.chmod(0o555)

    def reconstruct(self, **changes):
        return bundle.reconstruct_retained(str(self.layout), str(self.lock_path), str(self.outputs), **changes)

    def test_reconstruction_restores_authenticated_modes_without_changing_retained_bytes_or_modes(self):
        original_result = self.pack()
        for name in ("bundle", "receipt.json"):
            (self.outputs / name).unlink()
        self.retained_representation()
        source = self.retained / "pair/home-manager/default.nix"
        before = (bundle.acquired.snapshot(source.stat()), source.read_bytes())
        strict_pack = bundle.pack
        observed = []
        def inspect(layout, lock, output, **kwargs):
            canonical = Path(layout).parent
            self.assertEqual(stat.S_IMODE((canonical / "pair/home-manager/default.nix").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((canonical / "artifact/release-manifest.json").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((canonical / "pair/home-manager").stat().st_mode), 0o555)
            observed.append(kwargs["deadline"])
            return strict_pack(layout, lock, output, **kwargs)
        with patch.object(bundle, "pack", side_effect=inspect):
            result = self.reconstruct()
        self.assertEqual(result["bundleSha256"], original_result["bundleSha256"])
        self.assertEqual(result["receiptSha256"], original_result["receiptSha256"])
        self.assertEqual(before, (bundle.acquired.snapshot(source.stat()), source.read_bytes()))
        self.assertEqual(len(observed), 1)
        self.assertFalse(result["retainedPhysicalNarVerified"])
        self.assertTrue(result["reconstructedCanonicalNarVerified"])
        self.assertTrue(result["privateTreesRemoved"])
        self.assertEqual(sorted(p.name for p in self.outputs.iterdir()), ["bundle", "receipt.json"])

    def test_reconstruction_does_not_disable_canonical_executable_bit_guard(self):
        self.retained_representation()
        strict_pack = bundle.pack
        def tamper(layout, *args, **kwargs):
            (Path(layout).parent / "pair/home-manager/default.nix").chmod(0o555)
            return strict_pack(layout, *args, **kwargs)
        with patch.object(bundle, "pack", side_effect=tamper), self.assertRaisesRegex(ValueError, "bundle-regular-metadata"):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_refuses_unqualified_transport_mode_even_if_canonical_mode_matches(self):
        self.retained_representation()
        (self.retained / "pair/home-manager/default.nix").chmod(0o444)
        with self.assertRaisesRegex(ValueError, "retained-0555-representation"):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_refuses_original_mode_change_after_canonical_pack(self):
        self.retained_representation()
        strict_pack = bundle.pack
        def tamper(*args, **kwargs):
            result = strict_pack(*args, **kwargs)
            (self.retained / "pair/home-manager/default.nix").chmod(0o444)
            return result
        with patch.object(bundle, "pack", side_effect=tamper), self.assertRaises(ValueError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_refuses_actual_canonical_link_change_after_strict_pack(self):
        self.retained_representation()
        strict_pack = bundle.pack
        def tamper(*args, **kwargs):
            result = strict_pack(*args, **kwargs)
            root = Path(args[0]).parent / "pair/home-manager"
            root.chmod(0o755)
            (root / "inert-link").unlink()
            (root / "inert-link").symlink_to("different-absent-target")
            root.chmod(0o555)
            return result
        with patch.object(bundle, "pack", side_effect=tamper), self.assertRaisesRegex(ValueError, "canonical-complete-inventory"):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_refuses_original_byte_change_after_canonical_pack(self):
        self.retained_representation()
        strict_pack = bundle.pack
        def tamper(*args, **kwargs):
            result = strict_pack(*args, **kwargs)
            source = self.retained / "pair/home-manager/default.nix"
            original = source.read_bytes()
            source.chmod(0o755)
            source.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            source.chmod(0o555)
            return result
        with patch.object(bundle, "pack", side_effect=tamper), self.assertRaises(ValueError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_joint_budget_counts_distinct_tree_and_bundle_inodes(self):
        from types import SimpleNamespace
        with patch.object(bundle.acquisition, "DISK_BUDGET", 1024):
            with self.assertRaisesRegex(ValueError, "joint-disk-budget"):
                bundle.ReconstructionBudget(1025, time.monotonic() + 30)
            budget = bundle.ReconstructionBudget(900, time.monotonic() + 30)
            budget.record(SimpleNamespace(st_dev=1, st_ino=1, st_blocks=1))
            budget.record(SimpleNamespace(st_dev=1, st_ino=1, st_blocks=1))
            self.assertEqual(budget.allocated, 512)
            with self.assertRaisesRegex(ValueError, "joint-disk-budget"):
                budget.record(SimpleNamespace(st_dev=1, st_ino=2, st_blocks=2))

    def test_reconstruction_cleanup_failure_withholds_final_receipt_and_removes_pending_bundle(self):
        self.retained_representation()
        private_tree = bundle.private_tree
        @contextmanager
        def cleanup_refusal(*args, **kwargs):
            with private_tree(*args, **kwargs) as worker:
                yield worker
            raise ValueError("modeled-cleanup-refusal")
        with patch.object(bundle, "private_tree", cleanup_refusal), self.assertRaises(ValueError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_rolls_back_bundle_after_final_rename_if_receipt_creation_fails(self):
        self.retained_representation()
        original_open = bundle.os.open
        def refusal(path, *args, **kwargs):
            if path == ".pending-receipt":
                raise OSError("modeled-create-refusal")
            return original_open(path, *args, **kwargs)
        with patch.object(bundle.os, "open", side_effect=refusal), self.assertRaises(OSError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_rolls_back_partial_receipt_and_bundle_after_write_failure(self):
        self.retained_representation()
        original_write = bundle.write_all
        def refusal(fd, data, deadline, directory):
            if directory.path == self.outputs:
                bundle.os.write(fd, data[:5])
                raise OSError("modeled-partial-write-refusal")
            return original_write(fd, data, deadline, directory)
        with patch.object(bundle, "write_all", side_effect=refusal), self.assertRaises(OSError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_rolls_back_final_pair_after_final_admission_tick_failure(self):
        self.retained_representation()
        original_tick = bundle.tick
        injected = []
        def refusal(deadline, directory=None):
            if not injected and directory is not None and directory.path == self.outputs and (self.outputs / "receipt.json").exists():
                injected.append(True)
                raise ValueError("modeled-final-admission-refusal")
            return original_tick(deadline, directory)
        with patch.object(bundle, "tick", side_effect=refusal), self.assertRaises(ValueError):
            self.reconstruct()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_close_failure_rolls_back_by_retained_inode_witness_and_closes_other_file(self):
        self.retained_representation()
        original_close = bundle.PublicationFile.close
        closed = []
        def refusal(owned):
            original_close(owned)
            closed.append(owned.name)
            if owned.name == "receipt.json":
                raise OSError("modeled-close-refusal-after-fd-release")
        with patch.object(bundle.PublicationFile, "close", refusal), self.assertRaises(OSError):
            self.reconstruct()
        self.assertEqual(closed, ["receipt.json", "bundle"])
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_parent_close_failure_requalifies_original_chain_for_exact_rollback(self):
        self.retained_representation()
        original_close = bundle.acquisition.HeldDirectory.close
        failed = []
        def refusal(owner):
            inject = owner.path == self.outputs and (self.outputs / "receipt.json").exists() and not failed
            original_close(owner)
            if inject:
                failed.append(True)
                raise OSError("modeled-parent-close-refusal")
        with patch.object(bundle.acquisition.HeldDirectory, "close", refusal), self.assertRaises(OSError):
            self.reconstruct()
        self.assertEqual(failed, [True])
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_rollback_quarantines_replaced_bundle_and_removes_independently_owned_receipt(self):
        self.retained_representation()
        original_tick = bundle.tick
        injected = []
        def refusal(deadline, directory=None):
            if not injected and directory is not None and directory.path == self.outputs and (self.outputs / "receipt.json").exists():
                injected.append(True)
                (self.outputs / "bundle").unlink()
                self.write(self.outputs / "bundle", b"replacement-must-remain")
                raise ValueError("modeled-final-admission-refusal")
            return original_tick(deadline, directory)
        with patch.object(bundle, "tick", side_effect=refusal), self.assertRaises(ValueError) as captured:
            self.reconstruct()
        self.assertEqual((self.outputs / "bundle").read_bytes(), b"replacement-must-remain")
        self.assertFalse((self.outputs / "receipt.json").exists())
        self.assertIn("reconstruction-publication-rollback-refused", captured.exception.cleanup_category)

    def test_reconstruction_atomic_promotions_preserve_every_preexisting_destination(self):
        self.retained_representation()
        primitive = bundle.publication_noreplace
        for target in (".pending-bundle", "bundle", "receipt.json"):
            with self.subTest(target=target):
                def collision(source, source_name, destination, name):
                    if name == target:
                        self.write(self.outputs / name, b"unowned-destination-must-remain")
                    return primitive(source, source_name, destination, name)
                with patch.object(bundle, "publication_noreplace", side_effect=collision), self.assertRaisesRegex(ValueError, "destination-exists") as captured:
                    self.reconstruct()
                self.assertEqual((self.outputs / target).read_bytes(), b"unowned-destination-must-remain")
                self.assertEqual(sorted(p.name for p in self.outputs.iterdir()), [target])
                self.assertIn("reconstruction-publication-rollback-refused", captured.exception.cleanup_category)
                (self.outputs / target).unlink()

    def test_reconstruction_promotion_then_interrupt_rolls_back_all_registered_candidate_names(self):
        self.retained_representation()
        primitive = bundle.publication_noreplace
        for target in (".pending-bundle", "bundle", "receipt.json"):
            with self.subTest(target=target):
                def interrupted(source, source_name, destination, name):
                    primitive(source, source_name, destination, name)
                    if name == target:
                        raise KeyboardInterrupt
                with patch.object(bundle, "publication_noreplace", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                    self.reconstruct()
                self.assertEqual(list(self.outputs.iterdir()), [])

    def test_reconstruction_closed_failure_diagnostic_never_serializes_unknown_exception_text(self):
        for error in (ValueError("private-path-must-not-escape"), OSError("private-os-detail"),
                      ValueError("bundle-regular-metadata", "private-other-arg")):
            diagnostic = bundle.reconstruction_failure(error, {"phase": "private-phase"})
            self.assertEqual(diagnostic, {"phase": "metadata", "refusal": "closed-input-or-execution-refused"})
        diagnostic = bundle.reconstruction_failure(ValueError("bundle-regular-metadata"), {"phase": "canonical-pack"})
        self.assertEqual(diagnostic, {"phase": "canonical-pack", "refusal": "bundle-regular-metadata"})

    def test_pack_emits_only_two_finite_files_preserving_failed_wrapper(self):
        result = self.pack()
        self.assertEqual(sorted(p.name for p in self.outputs.iterdir()), ["bundle", "receipt.json"])
        self.assertEqual(result["bundleSha256"], bundle.sha((self.outputs / "bundle").read_bytes()))
        self.assertEqual(result["bundleBytes"], (self.outputs / "bundle").stat().st_size)
        self.assertLess(len((self.outputs / "receipt.json").read_bytes()), 2048)
        self.assertEqual(result["sourceWrapper"]["controllerExit"], 3)
        self.assertEqual(result["sourceWrapper"]["workloadExit"], 3)
        self.assertFalse(result["evaluationExecuted"])
        self.assertEqual(result["activation"], "unproved")
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o444 for p in self.outputs.iterdir()))

    def test_modeled_consumer_runs_full_readonly_nar_and_custody_proof_then_removes_tree(self):
        result = self.pack()
        observed = []
        original = bundle.evaluator.evaluate_acquired_pair
        def inspect(*args, **kwargs):
            pair, art, home = Path(args[3]), Path(args[5]), Path(args[8])
            self.assertEqual(pair.parent.parent, self.scratch)
            self.assertEqual(stat.S_IMODE(pair.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(art.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
            self.assertFalse((pair / "home-manager/inert-link").exists())
            observed.append(kwargs["deadline"])
            return original(*args, **kwargs)
        with self.model_nix(), patch.object(bundle.evaluator, "evaluate_acquired_pair", side_effect=inspect):
            report = self.consume(result)
        self.assertEqual(len(observed), 1)
        self.assertTrue(report["sourceCustodyBeforeAfterMatched"])
        self.assertTrue(report["artifactCustodyBeforeAfterMatched"])
        self.assertTrue(report["privateTreesRemoved"])
        self.assertEqual(report["nativeContinuity"], "unproved")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_malformed_layout_and_duplicate_json_key_refuse_before_output(self):
        for raw in (b"{", b'{"schemaVersion":1,"schemaVersion":1}'):
            with self.subTest(raw=raw):
                self.write(self.layout, raw)
                with self.assertRaises(ValueError):
                    self.pack()
                self.assertEqual(list(self.outputs.iterdir()), [])

    def test_traversal_duplicates_special_nodes_and_file_bounds_refused(self):
        root = {"path": "", "type": "directory"}
        cases = [[root, {"path": "../escape", "type": "directory"}], [root, root],
                 [root, {"path": "fifo", "type": "fifo"}],
                 [root, {"path": "huge", "type": "regular", "size": acquired.MAX_FILE_BYTES + 1, "executable": False}],
                 [root, {"path": "leaf", "type": "regular", "size": True, "executable": False}]]
        for nodes in cases:
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                bundle.checked_nodes(nodes, "/declared/fixture")
        with patch.object(acquired, "MAX_NODES", 1), self.assertRaisesRegex(ValueError, "node-bound"):
            bundle.checked_nodes([root, {"path": "dir", "type": "directory"}], "/declared/fixture")

    def test_contained_inert_link_allowed_and_escape_links_refused(self):
        root = {"path": "", "type": "directory"}
        for target in ("/ambient", "../ambient", "x/../../ambient", "a\\b", "a\nb"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "link-escape"):
                bundle.checked_nodes([root, {"path": "link", "type": "symlink", "target": target}], "/declared/fixture")
        result = bundle.checked_nodes([root, {"path": "link", "type": "symlink", "target": "missing"}], "/declared/fixture")
        self.assertEqual(result["nodes"][1]["target"], "missing")

    def test_changed_declared_input_and_hardlink_are_refused(self):
        source = self.retained / "pair/home-manager/default.nix"
        inputs = bundle.Inputs(self.retained, time.monotonic() + 30)
        inputs.read("pair/home-manager/default.nix", 65536)
        source.chmod(0o600)
        source.write_bytes(b"changed\n")
        source.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "input-changed"):
            inputs.recheck()
        os.link(source, self.base / "hardlink")
        with self.assertRaisesRegex(ValueError, "input-custody"):
            self.pack()

    def test_digest_and_selected_failed_wrapper_provenance_cannot_be_laundered(self):
        result = self.pack()
        with self.assertRaisesRegex(ValueError, "selected-receipt"):
            self.consume(result, frozen_receipt_sha="0" * 64)
        altered = self.rewrite_compact_receipt(result, lambda value: value.update(sourceWrapper={
            **bundle.SOURCE_WRAPPER, "controllerExit": 0, "workloadExit": 0}))
        with patch.object(bundle.evaluator, "evaluate_acquired_pair") as evaluator, \
                self.assertRaisesRegex(ValueError, "selected-scope"):
            self.consume(altered)
        evaluator.assert_not_called()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_truncation_header_bound_magic_and_trailing_bytes_refuse_with_cleanup(self):
        result = self.pack()
        original = (self.outputs / "bundle").read_bytes()
        cases = [original[:-1], b"X" + original[1:],
                 bundle.MAGIC + struct.pack("<Q", acquired.MAX_RECEIPT_BYTES + 1) + original[len(bundle.MAGIC) + 8:],
                 original + b"x"]
        for raw in cases:
            with self.subTest(size=len(raw)):
                self.write(self.outputs / "bundle", raw)
                selected = self.rewrite_compact_receipt(result, lambda value: value.update(
                    bundleSha256=bundle.sha(raw), bundleBytes=len(raw)))
                selected["bundleSha256"] = bundle.sha(raw)
                with patch.object(bundle.evaluator, "evaluate_acquired_pair") as evaluator, self.assertRaises(ValueError):
                    self.consume(selected)
                evaluator.assert_not_called()
                self.assertEqual(list(self.scratch.iterdir()), [])

    def test_nonfinite_and_expired_deadlines_refuse_before_any_io(self):
        with patch.object(bundle.time, "monotonic", return_value=100.0):
            for value in (float("nan"), float("inf"), float("-inf"), True, 100, 160, 1001):
                with self.subTest(deadline=value), self.assertRaisesRegex(ValueError, "enclosing-deadline"):
                    self.pack(deadline=value)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_artifact_frame_uses_its_own_byte_and_file_bounds_before_writes(self):
        header = ((self.retained / "pair/receipt.json").read_bytes(),
                  (self.retained / "pair/inventory.json").read_bytes(),
                  (self.retained / "artifact-receipt.json").read_bytes())
        compact = {"pairReceiptSha256": bundle.PAIR_SHA, "artifactReceiptSha256": bundle.ARTIFACT_SHA}
        root = {"path": "", "type": "directory"}
        cases = [[root, {"path": "huge", "type": "regular", "size": artifact.MAX_BYTES + 1, "executable": False}],
                 [root] + [{"path": f"file-{i}", "type": "regular", "size": 0, "executable": False}
                           for i in range(artifact.pack.MAX_FILES + 1)]]
        for nodes in cases:
            metadata = (*header, bundle.encoded(nodes))
            raw = bundle.MAGIC + b"".join(struct.pack("<Q", len(part)) + part for part in metadata)
            with self.subTest(nodes=len(nodes)), bundle.private_tree(str(self.scratch), time.monotonic() + 30) as worker:
                with self.assertRaisesRegex(ValueError, "artifact-byte-bound"):
                    bundle.materialize(io.BytesIO(raw), lambda: None, worker, self.lock, compact, time.monotonic() + 20)
                self.assertEqual(list(worker.path.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_publication_fsync_failure_refuses_success(self):
        with patch.object(bundle.os, "fsync", side_effect=OSError("modeled publication failure")), \
                self.assertRaises(OSError):
            self.pack()
        self.assertFalse((self.outputs / "receipt.json").exists())

    def test_changed_bundle_after_evaluator_is_refused_and_private_tree_removed(self):
        result = self.pack()
        def evaluating(*args, **kwargs):
            path = self.outputs / "bundle"
            raw = path.read_bytes()
            self.write(path, raw[:-1] + bytes([raw[-1] ^ 1]))
            return {"passed": True}
        with patch.object(bundle.evaluator, "evaluate_acquired_pair", side_effect=evaluating), \
                self.assertRaisesRegex(ValueError, "input-changed"):
            self.consume(result)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_expired_original_cleanup_deadline_preserves_primary_and_records_refusal(self):
        clock, primary = [100.0], ValueError("primary")
        with patch.object(bundle.time, "monotonic", side_effect=lambda: clock[0]), \
                self.assertRaises(ValueError) as caught:
            with bundle.private_tree(str(self.scratch), 200.0):
                clock[0] = 200.0
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.cleanup_category, "bundle-owned-cleanup-refused")
        self.assertEqual(len(list(self.scratch.iterdir())), 1)

    def test_file_and_stream_close_faults_attempt_all_releases(self):
        actual_close, attempted = os.close, []
        first, second = os.open(self.lock_path, os.O_RDONLY), os.open(self.layout, os.O_RDONLY)
        class RefusingStream:
            def close(self):
                attempted.append("stream")
                raise OSError("modeled stream close")
        def close(fd):
            attempted.append(fd)
            actual_close(fd)
            if fd == first:
                raise OSError("modeled file close after release")
        primary = ValueError("primary")
        with patch.object(bundle.os, "close", side_effect=close), self.assertRaises(ValueError) as caught:
            try:
                raise primary
            finally:
                bundle.close_resources(first, second, streams=(RefusingStream(),))
        self.assertIs(caught.exception, primary)
        self.assertEqual(attempted, ["stream", first, second])
        self.assertEqual(primary.cleanup_category, "bundle-owned-close-refused")

    def test_enclosing_deadline_is_forwarded_without_renewal(self):
        result = self.pack()
        observed = []
        clock = [100.0]
        def evaluating(*args, **kwargs):
            observed.append(kwargs["deadline"])
            clock[0] += 20
            return {"passed": True, "activation": "unproved"}
        with patch.object(bundle.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(bundle.evaluator, "evaluate_acquired_pair", side_effect=evaluating):
            self.consume(result, deadline=250.0)
        self.assertEqual(observed, [190.0])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_evaluator_failure_cleans_owned_materialization_and_preserves_primary(self):
        result = self.pack()
        primary = EvaluationFailure("module-evaluation", "evaluation-deadline")
        with patch.object(bundle.evaluator, "evaluate_acquired_pair", side_effect=primary), \
                self.assertRaises(EvaluationFailure) as caught:
            self.consume(result)
        self.assertIs(caught.exception, primary)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_worker_constructor_failure_removes_only_empty_owned_leaf(self):
        original = bundle.acquisition.HeldDirectory
        def admit(path, **kwargs):
            if Path(path).name.startswith("omux-hm-bundle-"):
                raise ValueError("modeled-constructor-failure")
            return original(path, **kwargs)
        with patch.object(bundle.acquisition, "HeldDirectory", side_effect=admit), \
                self.assertRaisesRegex(ValueError, "constructor-failure"):
            with bundle.private_tree(str(self.scratch), time.monotonic() + 30):
                self.fail("admission must refuse")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_cleanup_failure_attaches_category_without_masking_primary(self):
        primary = ValueError("primary")
        with patch.object(bundle, "remove_owned", side_effect=OSError("modeled cleanup")), \
                self.assertRaises(ValueError) as caught:
            with bundle.private_tree(str(self.scratch), time.monotonic() + 30):
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.cleanup_category, "bundle-owned-cleanup-refused")

    def test_close_fault_attempts_every_descriptor_and_preserves_primary(self):
        selected = bundle.acquisition.HeldDirectory(str(self.scratch))
        owned = [item[2] for item in reversed(selected.chain)]
        actual_close, attempted = os.close, []
        def close(fd):
            attempted.append(fd)
            actual_close(fd)
            if len(attempted) == 1:
                raise OSError("modeled close fault after release")
        primary = ValueError("primary")
        with patch.object(bundle.acquisition.os, "close", side_effect=close), self.assertRaises(ValueError) as caught:
            with selected:
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(attempted, owned)
        self.assertEqual(primary.cleanup_category, "acquisition-held-close-refused")
        self.assertEqual(selected.chain, [])

    def test_sync_join_cleanup_failure_retains_primary_without_progress_context(self):
        owner = bundle.acquisition.FileSyncOwner(lambda: None, lambda *args: None)
        primary = ValueError("primary")
        with patch.object(owner.executor, "shutdown", side_effect=OSError("modeled join refusal")), \
                self.assertRaises(ValueError) as caught:
            with owner:
                raise primary
        # No work was admitted, so this modeled executor owns no worker FDs.
        owner.executor.shutdown(wait=True, cancel_futures=True)
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.cleanup_category, "acquisition-copy-sync-cleanup-refused")

    def test_pending_selection_refuses_real_loader_before_bundle_or_evaluator_io(self):
        configuration = {"schema_version": 1, "kind": "omux-home-manager-compact-input-configuration-v1",
                         "status": "awaiting-qualified-bundle", "selection": None}
        selected = self.base / "selection.json"
        self.write(selected, bundle.encoded(configuration))
        with patch.object(bundle, "evaluate_bundle", side_effect=AssertionError("selected input IO")) as run:
            with self.assertRaisesRegex(ValueError, "^bundle-selection-pending$"):
                bundle.evaluate_selection(str(selected), "/absent/bundle", "/absent/receipt.json",
                    str(self.lock_path), "/absent/nix", self.modules, str(self.scratch),
                    deadline=time.monotonic() + 900)
            run.assert_not_called()
        for change in ({"selection": {}}, {"schema_version": True}, {"extra": True}):
            with self.assertRaises(ValueError): bundle.selected_bundle({**configuration, **change})

    def test_selected_bundle_real_byte_join_and_configuration_mutation_refusal(self):
        result = self.pack()
        selected = self.base / "selection.json"
        row = {"root": str(self.outputs), "bundle_sha256": result["bundleSha256"],
               "receipt_sha256": result["receiptSha256"]}
        configuration = {"schema_version": 1, "kind": "omux-home-manager-compact-input-configuration-v1",
                         "status": "selected-bundle", "selection": row}
        raw = bundle.encoded(configuration)
        self.write(selected, raw)
        def run():
            return bundle.evaluate_selection(str(selected), str(self.outputs / "bundle"),
                str(self.outputs / "receipt.json"), str(self.lock_path), "/declared/native-nix",
                self.modules, str(self.scratch), deadline=time.monotonic() + 900)
        with patch.object(bundle, "CONFIG_ROOTS", (str(self.base) + "/",)), self.model_nix():
            self.assertTrue(run()["sourceCustodyBeforeAfterMatched"])
        def mutation(*args, **kwargs):
            self.write(selected, raw)  # Equal bytes cannot excuse changed custody.
            return {name: True for name in bundle.evaluator.PREDICATES}
        with patch.object(bundle, "CONFIG_ROOTS", (str(self.base) + "/",)), self.model_nix(), \
                patch.object(bundle.evaluator, "evaluate", side_effect=mutation):
            with self.assertRaisesRegex(ValueError, "bundle-selection-changed"): run()
        self.write(selected, bundle.encoded({**configuration, "selection": {**row, "bundle_sha256": "0" * 64}}))
        with patch.object(bundle, "CONFIG_ROOTS", (str(self.base) + "/",)), self.model_nix():
            with self.assertRaisesRegex(ValueError, "bundle-selected-scope"): run()

    def test_actual_pending_cli_reports_literal_refusal_without_selected_io(self):
        selected = self.base / "selection.json"
        self.write(selected, bundle.encoded({"schema_version": 1,
            "kind": "omux-home-manager-compact-input-configuration-v1",
            "status": "awaiting-qualified-bundle", "selection": None}))
        entry = time.monotonic_ns()
        environment = {"OMUX_EXECUTION_GUARD": "modeled", "TEST_TMPDIR": str(self.scratch),
            "OMUX_HM_ROOT_ENTRY_NS": str(entry), "OMUX_HM_ROOT_DEADLINE_NS": str(entry + 1200 * 10**9),
            "OMUX_HM_RESERVED_PROFILE": "home-manager-evaluation-reserved"}
        output = io.StringIO()
        arguments = ["evaluate", "--selection", str(selected), "--bundle", "/absent/bundle",
            "--bundle-receipt", "/absent/receipt.json", "--lock", str(self.lock_path), "--nix", "/absent/nix"]
        for name, path in self.modules.items(): arguments += ["--module", name + "=" + path]
        with patch.dict(os.environ, environment), redirect_stdout(output), \
                patch.object(bundle, "evaluate_bundle", side_effect=AssertionError("selected IO")) as run:
            self.assertEqual(bundle.main(arguments), 2)
            run.assert_not_called()
        row = json.loads(output.getvalue())
        self.assertIs(row["passed"], False)
        self.assertEqual(row["category"], "bundle-selection-pending")
        self.assertLess(len(output.getvalue()), 512)
        self.assertNotIn("/absent", output.getvalue())

    def test_original_action_clock_intersects_local_and_outer_cleanup_before_io(self):
        entry, end = 100 * 10**9, 1300 * 10**9
        environment = {"OMUX_HM_ROOT_ENTRY_NS": str(entry), "OMUX_HM_ROOT_DEADLINE_NS": str(end),
                       "OMUX_HM_RESERVED_PROFILE": "home-manager-evaluation-reserved"}
        self.assertEqual(bundle.action_deadline("evaluate", environment, clock=lambda: 200 * 10**9), 1100)
        self.assertEqual(bundle.action_deadline("evaluate", environment, clock=lambda: 1000 * 10**9), 1270)
        with patch.object(bundle.time, "monotonic", return_value=1000):
            self.assertEqual(bundle.bounds(1270), (1210, 1270))
        for changed, now in ((environment, 1210 * 10**9), (environment, entry - 1),
                ({**environment, "OMUX_HM_ROOT_DEADLINE_NS": str(end + 1)}, 200 * 10**9),
                ({**environment, "OMUX_HM_RESERVED_PROFILE": "standard"}, 200 * 10**9), ({}, 200 * 10**9)):
            with self.assertRaises(ValueError): bundle.action_deadline("evaluate", changed, clock=lambda: now)
        with patch.object(bundle.time, "monotonic", return_value=1210), \
                patch.object(bundle.acquisition.os, "mkdir", side_effect=AssertionError("late allocation")) as mkdir:
            with self.assertRaises(ValueError):
                with bundle.private_tree(self.scratch, 1270, admission_deadline=1210): pass
            mkdir.assert_not_called()

    def test_absolute_child_verifiers_refuse_expired_parent_before_metadata(self):
        with patch.object(acquired.time, "monotonic", return_value=100), \
                patch.object(acquired, "decode", side_effect=AssertionError("pair metadata")) as decode:
            with self.assertRaises(ValueError):
                acquired.verify_acquired_pair(b"", b"", "0" * 64, b"", {}, deadline_seconds=300, deadline=100)
            decode.assert_not_called()
        with patch.object(artifact.time, "monotonic", return_value=100), \
                patch.object(artifact, "validate_receipt", side_effect=AssertionError("artifact metadata")) as read:
            with self.assertRaises(ValueError): artifact.verify_artifact("/absent", b"", "0" * 64, deadline=100)
            read.assert_not_called()

    def test_real_materialize_refuses_clock_expiry_after_custody_before_namespace_writes(self):
        self.pack()
        compact = {"pairReceiptSha256": bundle.PAIR_SHA, "artifactReceiptSha256": bundle.ARTIFACT_SHA}
        for stage in ("worker-custody", "retained-custody"):
            with self.subTest(stage=stage):
                worker_root = self.base / ("late-" + stage)
                worker_root.mkdir(mode=0o700)
                with bundle.acquisition.HeldDirectory(worker_root) as worker:
                    original_check = worker.check
                    calls = [0]
                    with open(self.outputs / "bundle", "rb") as stream, \
                            patch.object(bundle.time, "monotonic", return_value=100) as clock:
                        def worker_check():
                            original_check()
                            calls[0] += 1
                            # The explicit check before local_tick remains timely.
                            # Expire inside local_tick's second real custody check.
                            if calls[0] == 2 and stage == "worker-custody":
                                clock.return_value = 200
                        def retained_check():
                            if calls[0] == 2 and stage == "retained-custody":
                                # Read the real retained fixture, then model its latency.
                                (self.outputs / "receipt.json").read_bytes()
                                clock.return_value = 200
                        with patch.object(worker, "check", side_effect=worker_check), \
                                patch.object(bundle.os, "mkdir", side_effect=AssertionError("late directory write")) as mkdir, \
                                patch.object(bundle.os, "open", wraps=bundle.os.open) as opened:
                            with self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                                bundle.materialize(stream, retained_check, worker, self.lock,
                                    compact, 200)
                            self.assertEqual(calls[0], 2)
                            mkdir.assert_not_called()
                            self.assertFalse(any(call.args[1] & os.O_CREAT for call in opened.call_args_list))
                self.assertEqual(list(worker_root.iterdir()), [])

    def test_real_materialize_refuses_receipt_create_after_held_pair_lookup_expires(self):
        self.pack()
        compact = {"pairReceiptSha256": bundle.PAIR_SHA, "artifactReceiptSha256": bundle.ARTIFACT_SHA}
        worker_root = self.base / "late-receipt-worker"
        worker_root.mkdir(mode=0o700)
        pair = worker_root / "pair"
        original_check = bundle.acquisition.HeldDirectory.check
        with bundle.acquisition.HeldDirectory(worker_root) as worker, \
                open(self.outputs / "bundle", "rb") as stream, \
                patch.object(bundle.time, "monotonic", return_value=100) as clock:
            pair_owners = []
            def expire_second_pair_lookup(held):
                original_check(held)
                if held.path == pair and all(held is not owner for owner in pair_owners):
                    pair_owners.append(held)
                    if len(pair_owners) == 2:
                        clock.return_value = 200
            original_open = bundle.os.open
            def observe_open(path, flags, *args, **kwargs):
                if flags & os.O_CREAT and path in ("receipt.json", "inventory.json"):
                    self.fail("receipt creation after expired held pair lookup")
                return original_open(path, flags, *args, **kwargs)
            with patch.object(bundle.acquisition.HeldDirectory, "check", new=expire_second_pair_lookup), \
                    patch.object(bundle.os, "open", side_effect=observe_open):
                with self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                    bundle.materialize(stream, lambda: None, worker, self.lock, compact, 200)
            self.assertEqual(len(pair_owners), 2)
        self.assertFalse((pair / "receipt.json").exists())
        self.assertFalse((pair / "inventory.json").exists())

    def test_real_materialize_refuses_directory_mode_after_descriptor_lookup_expires(self):
        self.pack()
        compact = {"pairReceiptSha256": bundle.PAIR_SHA, "artifactReceiptSha256": bundle.ARTIFACT_SHA}
        worker_root = self.base / "late-mode-worker"
        worker_root.mkdir(mode=0o700)
        original_dup = bundle.os.dup
        original_chmod = bundle.os.fchmod
        original_drain = bundle.acquisition.FileSyncOwner.drain
        original_parent_fd = bundle.parent_fd
        parent_lookup = [False]
        drained = [False]
        expired = [False]
        with bundle.acquisition.HeldDirectory(worker_root) as worker, \
                open(self.outputs / "bundle", "rb") as stream, \
                patch.object(bundle.time, "monotonic", return_value=100) as clock:
            def expire_root_lookup(fd):
                result = original_dup(fd)
                if drained[0] and not parent_lookup[0] and stat.S_ISDIR(os.fstat(fd).st_mode):
                    # After the real file-sync drain, materialize duplicates a
                    # source root immediately before its directory mode write.
                    clock.return_value = 200
                    expired[0] = True
                return result
            def observe_parent_lookup(fd, path):
                parent_lookup[0] = True
                try:
                    return original_parent_fd(fd, path)
                finally:
                    parent_lookup[0] = False
            def observe_drain(owner):
                result = original_drain(owner)
                drained[0] = True
                return result
            def observe_mode(fd, mode):
                self.assertFalse(expired[0], "mode write after expired descriptor lookup")
                return original_chmod(fd, mode)
            with patch.object(bundle.os, "dup", side_effect=expire_root_lookup), \
                    patch.object(bundle, "parent_fd", side_effect=observe_parent_lookup), \
                    patch.object(bundle.acquisition.FileSyncOwner, "drain", new=observe_drain), \
                    patch.object(bundle.os, "fchmod", side_effect=observe_mode):
                with self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                    bundle.materialize(stream, lambda: None, worker, self.lock, compact, 200)
            self.assertTrue(expired[0])

    def test_cli_failure_reports_finite_redacted_cleanup_and_no_success(self):
        primary = EvaluationFailure("module-evaluation", "evaluation-deadline",
                                    stderr=b"/private/path" + b"x" * 10000)
        primary.cleanup_category = "bundle-owned-cleanup-refused"
        output = io.StringIO()
        with patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "modeled", "TEST_UNDECLARED_OUTPUTS_DIR": str(self.outputs)}), \
                patch.object(bundle, "pack", side_effect=primary), redirect_stdout(output):
            status = bundle.main(["pack", "--layout", str(self.layout), "--lock", str(self.lock_path)])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertFalse(result["passed"])
        self.assertEqual(result["category"], "evaluation-deadline")
        self.assertEqual(result["cleanup_category"], "bundle-owned-cleanup-refused")
        self.assertLess(len(output.getvalue()), 512)
        self.assertNotIn("/private/path", output.getvalue())


if __name__ == "__main__":
    unittest.main()
