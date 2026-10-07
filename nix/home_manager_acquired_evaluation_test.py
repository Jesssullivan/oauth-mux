"""Modeled bridge predicates; genuine Nix evaluation is never executed here."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

import home_manager_acquired_evaluation as consumer
import home_manager_acquired_inputs as acquired
import home_manager_acquired_inputs_test as pair_fixtures
import home_manager_artifact as artifact
import home_manager_artifact_test as artifact_fixtures
import home_manager_inputs
from evaluation_runner import EvaluationFailure, evaluate


class AcquiredEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.addCleanup(self.cleanup)
        self.pair_fixture = pair_fixtures.AcquiredPairTests("runTest")
        self.pair_fixture.setUp()
        self.addCleanup(self.pair_fixture.tearDown)
        lock, receipt, receipt_sha, inventory, roots = self.pair_fixture.arguments()
        self.lock = lock
        self.pair_sha = receipt_sha
        self.pair = self.base / "pair"
        self.pair.mkdir(mode=0o700)
        for name in acquired.NAMES:
            shutil.copytree(roots[name], self.pair / name, symlinks=True)
        for name, value in (("receipt.json", receipt), ("inventory.json", inventory)):
            (self.pair / name).write_bytes(value)
            (self.pair / name).chmod(0o444)
        self.pair.chmod(0o555)
        self.artifact_fixture = artifact_fixtures.ArtifactTest("runTest")
        self.artifact_fixture.setUp()
        self.addCleanup(self.artifact_fixture.doCleanups)
        self.artifact_fixture.export()
        self.artifact_root, self.artifact_receipt = self.artifact_fixture.retained()
        self.artifact_sha = artifact.sha(self.artifact_receipt)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        declared = self.base / "declared-modules"
        declared.mkdir(mode=0o700)
        self.modules = {}
        for name in consumer.MODULES:
            path = declared / name
            path.write_bytes(b"{} # modeled byte input, no Nix execution\n")
            self.modules[name] = str(path)
        self.predicates = {name: True for name in consumer.PREDICATES}

    def cleanup(self):
        for directory, _, _ in os.walk(self.base, followlinks=False):
            os.chmod(directory, 0o700)
        self.temp.cleanup()

    def run_bridge(self, evaluator=None, **changes):
        arguments = {"nix": "/declared/native-nix", "modules": self.modules,
                     "lock_bytes": self.lock, "pair_root": str(self.pair),
                     "pair_receipt_sha256": self.pair_sha, "artifact_root": str(self.artifact_root),
                     "artifact_receipt_bytes": self.artifact_receipt,
                     "artifact_receipt_sha256": self.artifact_sha, "private_home": str(self.home)}
        arguments.update(changes)
        with patch.dict(home_manager_inputs.PINS, self.pair_fixture.pins, clear=True), \
                patch.object(consumer, "native_nix", return_value="/declared/native-nix"), \
                patch.object(consumer, "evaluate", side_effect=evaluator or (lambda *args, **kwargs: self.predicates)):
            return consumer.evaluate_acquired_pair(**arguments)

    def test_enclosing_deadline_is_forwarded_after_input_preparation_without_renewal(self):
        clock, observed = [100.0], []
        original_copy = consumer.copy_modules
        def copying(*args):
            result = original_copy(*args)
            clock[0] += 40
            return result
        def evaluating(argv, home, *, deadline):
            observed.append((clock[0], deadline))
            self.assertEqual(home, str(self.home))
            return self.predicates
        with patch.object(consumer.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(consumer, "copy_modules", side_effect=copying):
            report = self.run_bridge(evaluating)
        self.assertEqual(observed, [(140.0, 100.0 + consumer.MAX_SECONDS)])
        self.assertTrue(report["passed"])

    def test_expiry_at_final_input_fence_refuses_real_runner_before_spawn(self):
        clock = [100.0]
        original_check = consumer.check_envelope
        def checking(selected, capture, deadline, category):
            original_check(selected, capture, deadline, category)
            if category == "hm-evaluation-private-home-changed":
                clock[0] = deadline
        with patch.object(consumer.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(consumer, "check_envelope", side_effect=checking), \
                patch.object(consumer.subprocess, "Popen") as launched:
            with self.assertRaises(EvaluationFailure) as failure:
                self.run_bridge(evaluate)
            self.assertEqual(failure.exception.category, "evaluation-deadline")
            launched.assert_not_called()

    def test_cli_preserves_primary_and_finite_cleanup_refusal_after_owned_home_unwind(self):
        lock_path = self.base / "declared-lock.json"
        lock_path.write_bytes(self.lock)
        primary = EvaluationFailure("module-evaluation", "evaluation-output-bound",
                                    stderr=b"error: token=private-value at /private/source")
        primary.cleanup_category = "cleanup-deadline"
        arguments = ["--nix", "/declared/native-nix", "--lock", str(lock_path),
                     "--pair-root", str(self.pair), "--pair-receipt-sha256", self.pair_sha,
                     "--artifact-root", str(self.artifact_root),
                     "--artifact-receipt", str(self.artifact_root.parent / "receipt.json"),
                     "--artifact-receipt-sha256", self.artifact_sha]
        for name, path in self.modules.items():
            arguments.extend(["--module", name + "=" + path])
        output = io.StringIO()
        with patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "modeled-owned-guard", "TEST_TMPDIR": str(self.home)}), \
                patch.object(consumer, "evaluate_acquired_pair", side_effect=primary), redirect_stdout(output):
            self.assertEqual(consumer.main(arguments), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["category"], "evaluation-output-bound")
        self.assertEqual(report["cleanup_category"], "cleanup-deadline")
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertNotIn("private-value", output.getvalue())
        self.assertNotIn("/private", output.getvalue())

    def test_modeled_bridge_rehashes_actual_fixture_bytes_and_keeps_dirty_qualification(self):
        with patch.object(consumer.subprocess, "Popen", side_effect=AssertionError("no executable invocation")):
            report = self.run_bridge()
        self.assertEqual(report["scope"], "genuine-module-evaluation-only")
        self.assertEqual(report["activation"], "unproved")
        self.assertEqual(report["generatedBytes"], "unrealized-unverified")
        self.assertEqual(report["artifact"]["sourceQualification"], "caller-declared-dirty-development")
        self.assertTrue(report["artifact"]["sourceDirty"])
        self.assertTrue(report["sourceCustodyBeforeAfterMatched"])
        self.assertTrue(report["artifactCustodyBeforeAfterMatched"])
        self.assertFalse(report["compiledSourceBindingProved"])
        self.assertEqual(report["releaseProvenance"], "unproved")
        self.assertEqual(report["pairReceiptSha256"], self.pair_sha)
        self.assertEqual(report["artifactReceiptSha256"], self.artifact_sha)

    def test_command_is_offline_dummy_store_and_uses_only_copied_declared_modules(self):
        observed = []
        def evaluating(argv, home, *, deadline):
            observed.append(argv)
            self.assertEqual(argv[argv.index("--store") + 1], "dummy://?read-only=false")
            self.assertIn("--offline", argv)
            self.assertEqual(argv[argv.index("allow-import-from-derivation") + 1], "false")
            self.assertEqual(argv[argv.index("builders") + 1], "")
            self.assertEqual(argv[argv.index("substituters") + 1], "")
            self.assertEqual(argv[argv.index("max-jobs") + 1], "0")
            self.assertIn(str(self.home / "modules" / consumer.MODULES[0]), argv[-1])
            self.assertNotIn(str(Path(self.modules[consumer.MODULES[0]]).parent), argv[-1])
            self.assertNotIn("activationPackage", argv[-1])
            self.assertEqual(set(path.name for path in (self.home / "modules").iterdir()), set(consumer.MODULES))
            return self.predicates
        self.run_bridge(evaluating)
        self.assertEqual(len(observed), 1)

    def test_independently_frozen_pair_digest_required_before_evaluation(self):
        with self.assertRaisesRegex(ValueError, "acquired-receipt-binding"):
            self.run_bridge(pair_receipt_sha256="0" * 64)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_independently_frozen_artifact_digest_required_before_evaluation(self):
        with self.assertRaisesRegex(ValueError, "artifact-frozen-receipt-binding"):
            self.run_bridge(artifact_receipt_sha256="0" * 64)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_pair_byte_drift_during_evaluator_refuses_result(self):
        def evaluating(*args, **kwargs):
            path = self.pair / "home-manager/default.nix"
            size = path.stat().st_size
            path.chmod(0o644)
            path.write_bytes(b"x" * size)
            path.chmod(0o444)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "source-nar-mismatch"):
            self.run_bridge(evaluating)

    def test_identical_pair_bytes_rewritten_during_evaluator_fail_custody_commitment(self):
        def evaluating(*args, **kwargs):
            path = self.pair / "nixpkgs/default.nix"
            original = path.read_bytes()
            path.chmod(0o644)
            path.write_bytes(original)
            path.chmod(0o444)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "pair-changed-through-evaluator"):
            self.run_bridge(evaluating)

    def test_artifact_same_bytes_rewritten_during_evaluator_fail_custody_commitment(self):
        def evaluating(*args, **kwargs):
            path = self.artifact_root / "release-manifest.json"
            original = path.read_bytes()
            path.chmod(0o644)
            path.write_bytes(original)
            path.chmod(0o444)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "artifact-changed-through-evaluator"):
            self.run_bridge(evaluating)

    def test_pair_metadata_same_bytes_replaced_during_evaluator_is_refused(self):
        def evaluating(*args, **kwargs):
            path = self.pair / "receipt.json"
            original = path.read_bytes()
            self.pair.chmod(0o700)
            path.unlink()
            path.write_bytes(original)
            path.chmod(0o444)
            self.pair.chmod(0o555)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "pair-metadata-changed"):
            self.run_bridge(evaluating)

    def test_copied_private_module_drift_is_refused_even_when_declared_source_is_unchanged(self):
        def evaluating(*args, **kwargs):
            path = self.home / "modules/home-manager.nix"
            path.chmod(0o644)
            path.write_bytes(b"{} # changed private evaluator input\n")
            path.chmod(0o444)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "private-module-changed"):
            self.run_bridge(evaluating)

    def test_declared_module_drift_during_evaluator_is_refused(self):
        def evaluating(*args, **kwargs):
            Path(self.modules["service-witness.nix"]).write_bytes(b"{} # changed declaration\n")
            return self.predicates
        with self.assertRaisesRegex(ValueError, "declared-module-changed"):
            self.run_bridge(evaluating)

    def test_missing_or_unknown_predicate_never_implies_genuine_evaluation_success(self):
        for results in ({"fixture": True}, {**self.predicates, "fixture": True},
                        {**self.predicates, "genuineModule": False}):
            # Only one evaluation per fresh private home; remove our prior
            # copies without following any symlink targets.
            copied = self.home / "modules"
            if copied.exists():
                copied.chmod(0o700)
                shutil.rmtree(copied)
            with self.subTest(results=results), self.assertRaisesRegex(ValueError, "genuine-predicates"):
                self.run_bridge(lambda *args, **kwargs: results)

    def test_dummy_store_failure_propagates_without_live_store_retry(self):
        calls = []
        def evaluating(argv, home, *, deadline):
            calls.append(argv)
            raise EvaluationFailure("module-evaluation", "dummy-store-capability")
        with self.assertRaisesRegex(EvaluationFailure, "dummy-store-capability"):
            self.run_bridge(evaluating)
        self.assertEqual(len(calls), 1)

    def test_nonempty_home_and_incomplete_module_set_are_refused(self):
        (self.home / "ambient-cache").mkdir()
        with self.assertRaisesRegex(ValueError, "requires-fresh-home"):
            self.run_bridge()
        with self.assertRaisesRegex(ValueError, "metadata-fields"):
            self.run_bridge(modules={name: self.modules[name] for name in consumer.MODULES[:-1]})

    def test_fifo_declared_module_is_refused_without_read(self):
        fifo = self.base / "module-fifo"
        os.mkfifo(fifo)
        with patch.object(consumer.os, "read", side_effect=AssertionError("no FIFO read")), \
                self.assertRaisesRegex(ValueError, "input-custody"):
            consumer.read_declared(fifo, 65536, time.monotonic() + 10)

    def test_arbitrary_native_tool_and_other_platform_are_refused(self):
        with self.assertRaisesRegex(ValueError, "native-nix-pin"):
            consumer.native_nix(self.modules[consumer.MODULES[0]], time.monotonic() + 10)
        with self.assertRaisesRegex(ValueError, "platform-unqualified"):
            self.run_bridge(system="aarch64-linux")

    def test_clean_or_release_artifact_receipt_cannot_broaden_dirty_development_lane(self):
        original = json.loads(self.artifact_receipt)
        for changes in ({"sourceDirty": False}, {"channel": "release"}):
            raw = artifact.encoded({**original, **changes})
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "artifact-receipt-schema"):
                self.run_bridge(artifact_receipt_bytes=raw, artifact_receipt_sha256=artifact.sha(raw))

    def test_before_after_artifact_proof_interval_cannot_hide_late_pair_drift(self):
        original_verify = artifact.verify_artifact
        calls = 0
        def verifying(*args, **kwargs):
            nonlocal calls
            result = original_verify(*args, **kwargs)
            calls += 1
            if calls == 2:
                path = self.pair / "home-manager/default.nix"
                data = path.read_bytes()
                path.chmod(0o644)
                path.write_bytes(data)
                path.chmod(0o444)
            return result
        with patch.object(artifact, "verify_artifact", side_effect=verifying), \
                self.assertRaisesRegex(ValueError, "pair-changed-through-evaluator"):
            self.run_bridge()

    def test_restored_modules_directory_substitution_cannot_hide_alternate_evaluator_input(self):
        def evaluating(*args, **kwargs):
            selected = self.home / "modules"
            facts = {name: acquired.snapshot((selected / name).stat()) for name in consumer.MODULES}
            selected.rename(self.home / "saved-modules")
            selected.mkdir()
            for name in consumer.MODULES:
                (selected / name).write_bytes(b"{} # alternate evaluator input\n")
            self.assertNotEqual((selected / consumer.MODULES[0]).read_bytes(),
                                (self.home / "saved-modules" / consumer.MODULES[0]).read_bytes())
            shutil.rmtree(selected)
            (self.home / "saved-modules").rename(selected)
            self.assertEqual({name: acquired.snapshot((selected / name).stat())
                              for name in consumer.MODULES}, facts)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "private-home-changed"):
            self.run_bridge(evaluating)

    def test_restored_pair_envelope_substitution_cannot_hide_alternate_source(self):
        def evaluating(*args, **kwargs):
            path = self.pair / "home-manager/default.nix"
            original = acquired.snapshot(path.stat())
            saved = self.base / "saved-pair"
            self.pair.rename(saved)
            (self.pair / "home-manager").mkdir(parents=True)
            (self.pair / "home-manager/default.nix").write_bytes(b"{} # alternate source\n")
            self.assertNotEqual(path.read_bytes(), (saved / "home-manager/default.nix").read_bytes())
            shutil.rmtree(self.pair)
            saved.rename(self.pair)
            self.assertEqual(acquired.snapshot(path.stat()), original)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "pair-envelope-changed"):
            self.run_bridge(evaluating)

    def test_restored_private_home_substitution_cannot_hide_alternate_expression(self):
        def evaluating(argv, home, *, deadline):
            path = self.home / "modules" / consumer.MODULES[0]
            original = acquired.snapshot(path.stat())
            saved = self.base / "saved-home"
            self.home.rename(saved)
            (self.home / "modules").mkdir(parents=True)
            path.write_bytes(b"{} # alternate private expression\n")
            self.assertIn(str(path), argv[-1])
            self.assertNotEqual(path.read_bytes(), (saved / "modules" / consumer.MODULES[0]).read_bytes())
            shutil.rmtree(self.home)
            saved.rename(self.home)
            self.assertEqual(acquired.snapshot(path.stat()), original)
            return self.predicates
        with self.assertRaisesRegex(ValueError, "private-home-changed"):
            self.run_bridge(evaluating)

    def test_copied_modules_held_directory_detects_restore_even_without_home_witness(self):
        with consumer.acquisition.HeldDirectory(self.home) as home:
            _, _, captures, directory_capture = consumer.copy_modules(self.modules, home, time.monotonic() + 10)
            with consumer.acquisition.HeldDirectory(self.home / "modules", parent_anchor=home) as copied:
                self.home.joinpath("modules").rename(self.home / "saved-modules")
                (self.home / "saved-modules").rename(self.home / "modules")
                with self.assertRaisesRegex(ValueError, "private-module-directory-changed"):
                    consumer.check_copied_modules(home, copied, directory_capture, captures,
                                                  time.monotonic() + 10)

    def test_unexpected_private_home_cache_write_refuses_success(self):
        def evaluating(*args, **kwargs):
            (self.home / "ambient-cache").mkdir()
            return self.predicates
        with self.assertRaisesRegex(ValueError, "private-home-changed"):
            self.run_bridge(evaluating)


if __name__ == "__main__":
    unittest.main()
