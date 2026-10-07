"""Modeled acquisition/export predicates; never launch Nix or use the network."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import stat
import tempfile
import threading
import time
from types import SimpleNamespace
from contextlib import redirect_stderr, redirect_stdout
import unittest
from unittest.mock import patch

import home_manager_acquisition as acquisition
import home_manager_acquired_inputs as acquired
import home_manager_inputs
import nar_descriptor


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        # The verifier compares full ancestor snapshots. Other test targets
        # must not create/remove entries in this fixture's scratch parent.
        scratch = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
        with acquisition.HeldDirectory(scratch) as scratch_owner:
            self.temporary = tempfile.TemporaryDirectory(dir=str(scratch_owner.path))
            scratch_owner.check()
        self.base = Path(self.temporary.name).resolve()
        self.worker = self.base / "worker"
        self.worker.mkdir()
        self.outputs = self.base / "outputs"
        self.outputs.mkdir()
        self.pins = {}
        self.lock = {"root": "root", "nodes": {"root": {"inputs": {
            "home-manager": "hm", "nixpkgs": "np"}}}}
        for name, logical in (("home-manager", "hm"), ("nixpkgs", "np")):
            fixture = self.base / name
            self.tree(fixture, name)
            nar = nar_descriptor.hash_descriptor(nar_descriptor.describe(fixture))
            sri = "sha256-" + base64.b64encode(bytes.fromhex(nar["narHash"][7:])).decode()
            revision = home_manager_inputs.PINS[name][0]
            self.pins[name] = (revision, sri)
            self.lock["nodes"][logical] = {"locked": {"rev": revision, "narHash": sri}}
        self.lock["nodes"]["hm"]["inputs"] = {"nixpkgs": ["nixpkgs"]}

    def tearDown(self):
        # Change only directories within our fixture; inert links stay inert.
        for directory, _, _ in os.walk(self.base, followlinks=False):
            os.chmod(directory, 0o700)
        self.temporary.cleanup()

    @staticmethod
    def tree(path, name):
        path.mkdir(parents=True)
        (path / "lib").mkdir()
        (path / "default.nix").write_bytes(name.encode() + b" fixture\n")
        (path / "lib/helper.nix").write_bytes(b"{}\n")
        (path / "executable").write_bytes(b"modeled executable\n")
        (path / "external-link").symlink_to("/unavailable-modeled-source-target")
        (path / "default.nix").chmod(0o444)
        (path / "lib/helper.nix").chmod(0o444)
        (path / "executable").chmod(0o555)
        (path / "lib").chmod(0o555)
        path.chmod(0o555)

    def locked(self):
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True):
            return home_manager_inputs.paired_lock(self.lock)

    def fake_prefetch(self, argv, env, root, deadline):
        root = root.path if isinstance(root, acquisition.HeldDirectory) else root
        name = "home-manager" if "nix-community" in argv[-1] else "nixpkgs"
        digit = "0" if name == "home-manager" else "1"
        logical = "/nix/store/" + digit * 32 + "-source"
        self.tree(root / "private-store" / logical.lstrip("/"), name)
        return {"storePath": logical, "hash": self.pins[name][1]}

    def produce(self, prefetch=None):
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True), \
                patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition, "prefetch", side_effect=prefetch or self.fake_prefetch):
            return acquisition.produce(acquisition.PINNED_NIX, acquisition.PINNED_CA,
                acquisition.encoded(self.lock), self.locked(), self.worker, self.outputs)

    def test_exact_command_uses_private_store_unpacked_nar_and_literal_url(self):
        locked = self.locked()
        argv = acquisition.command(acquisition.PINNED_NIX, self.worker, "nixpkgs", locked["nixpkgs"])
        self.assertEqual(argv[1:3], ["--store", "local?root=" + str(self.worker / "private-store")])
        self.assertIn("--unpack", argv)
        self.assertEqual(argv[argv.index("--expected-hash") + 1], self.pins["nixpkgs"][1])
        self.assertEqual(argv[-1], "https://github.com/NixOS/nixpkgs/archive/"
                         + self.pins["nixpkgs"][0] + ".tar.gz")
        self.assertNotIn("build", argv)
        self.assertNotIn("--impure", argv)

    def test_cli_has_no_source_or_output_override_and_requires_containment(self):
        with self.assertRaises(SystemExit):
            acquisition.main(["--nix", "n", "--ca-file", "c", "--lock", "l", "--url", "x"])
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(output):
            self.assertEqual(acquisition.main(["--nix", "n", "--ca-file", "c", "--lock", "l"]), 2)
        self.assertEqual(json.loads(output.getvalue())["category"], "acquisition-contained-context-required")

    def test_lock_refuses_synthetic_hashes_with_actual_production_pins(self):
        path = self.base / "lock.json"
        path.write_bytes(acquisition.encoded(self.lock))
        with self.assertRaisesRegex(ValueError, "paired-lock-binding"):
            acquisition.read_lock(path)

    def test_environment_excludes_ambient_daemon_proxy_and_build_inputs(self):
        with patch.dict(os.environ, {"NIX_REMOTE": "daemon", "http_proxy": "ambient",
                                     "NIX_CONFIG": "builders = ambient"}):
            env = acquisition.environment(self.worker, acquisition.PINNED_CA)
        self.assertEqual(env["NIX_REMOTE"], "")
        self.assertEqual(env["PATH"], "")
        self.assertNotIn("http_proxy", env)
        self.assertIn("builders =\nsubstituters =\nmax-jobs = 0", env["NIX_CONFIG"])

    def test_native_input_refuses_arbitrary_local_binary_without_execution(self):
        candidate = self.base / "nix"
        candidate.write_bytes(b"\x7fELFfixture")
        candidate.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "native-input-pin"):
            acquisition.native_inputs(candidate, candidate)

    def test_complete_modeled_export_is_byte_verified_and_keeps_inert_links_and_modes(self):
        with patch.object(acquisition.subprocess, "Popen", side_effect=AssertionError("no Nix execution")):
            report = self.produce()
        bundle = self.outputs / "home-manager-pair"
        receipt_bytes = (bundle / "receipt.json").read_bytes()
        inventory_bytes = (bundle / "inventory.json").read_bytes()
        self.assertEqual(report["receiptSha256"], hashlib.sha256(receipt_bytes).hexdigest())
        self.assertEqual(report["inventorySha256"], hashlib.sha256(inventory_bytes).hexdigest())
        self.assertTrue(report["byteProof"]["contentRehashed"])
        self.assertFalse(report["evaluationExecuted"])
        self.assertFalse(report["byteProof"]["evaluationAuthority"])
        self.assertEqual(report["activation"], "unproved")
        for name in acquired.NAMES:
            self.assertEqual(os.readlink(bundle / name / "external-link"), "/unavailable-modeled-source-target")
            self.assertEqual(stat.S_IMODE((bundle / name / "executable").stat().st_mode), 0o555)
            self.assertEqual(report["byteProof"]["sources"][name]["sourceDirectory"], str(bundle / name))
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True):
            result = acquired.verify_acquired_pair(acquisition.encoded(self.lock), receipt_bytes,
                report["receiptSha256"], inventory_bytes, {name: str(bundle / name) for name in acquired.NAMES})
        self.assertTrue(result["completeInventoryMatched"])

    def test_source_preparation_past_300_still_requires_real_copied_nar_and_pair_proofs(self):
        clock, copied_proof_times = [0.0], []
        actual_serialize = acquired.serialize
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        def serializing(descriptor, *args, **kwargs):
            if observer.current[1] == "source-nar" and "copied-proof" in observer.stack:
                if not copied_proof_times:
                    clock[0] = 301.0
                copied_proof_times.append(clock[0])
            return actual_serialize(descriptor, *args, **kwargs)
        try:
            with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(acquired, "serialize", side_effect=serializing), \
                    patch.object(acquisition.subprocess, "Popen", side_effect=AssertionError("no Nix execution")):
                report = self.produce()
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(acquisition.SOURCE_SECONDS, 600)
        self.assertEqual(acquisition.MAX_SECONDS, 1200)
        self.assertEqual(acquired.MAX_SECONDS, 300)  # Consumer verifier allowance is unchanged.
        self.assertEqual(copied_proof_times, [301.0, 301.0])
        self.assertEqual(observer.counters["narPassCount"], 4)
        self.assertEqual(observer.counters["pairProofCount"], 2)
        self.assertEqual(observer.counters["fileSyncCount"], 9)
        self.assertTrue(report["byteProof"]["contentRehashed"])
        self.assertFalse(report["evaluationExecuted"])
        self.assertEqual(report["activation"], "unproved")

    def test_exact_600_source_deadline_refuses_copied_nar_before_publication(self):
        clock, proof_deadlines = [0.0], []
        actual_serialize = acquired.serialize
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        def serializing(descriptor, *args, **kwargs):
            if observer.current[1] == "source-nar" and "copied-proof" in observer.stack:
                proof_deadlines.append(kwargs["deadline"])
                clock[0] = 600.0
            return actual_serialize(descriptor, *args, **kwargs)
        try:
            with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(acquired, "serialize", side_effect=serializing), \
                    self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                self.produce()
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(proof_deadlines, [600.0])
        self.assertEqual(observer.failure["phase"], "source-nar")
        self.assertIn("copied-proof", observer.failure["phasePath"])
        self.assertEqual(observer.failure["source"], "home-manager")
        self.assertEqual(observer.counters["pairProofCount"], 0)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_exact_600_prefetch_deadline_retains_failure_and_cleans_owned_child(self):
        clock, deadlines = [0.0], []
        process, events = self.child_streams(b"{}")
        selector = self.polling_selector(clock, 1)
        actual_prefetch = acquisition.prefetch
        def expired_poll(timeout):
            selector.polls += 1
            clock[0] = 600.0
            return []
        def prefetching(argv, env, root, deadline):
            deadlines.append(deadline)
            return actual_prefetch(argv, env, root, deadline)
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        try:
            with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(selector, "select", side_effect=expired_poll), \
                    patch.object(acquisition.subprocess, "Popen", return_value=process) as launch, \
                    patch.object(acquisition.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                    patch.object(acquisition.os, "killpg", side_effect=lambda *args: events.append("kill-group")), \
                    self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                self.produce(prefetching)
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(deadlines, [600.0])
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(events, ["kill-group", "reap"])
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        self.assertEqual(observer.failure["phase"], "prefetch-monitor")
        self.assertEqual(observer.failure["source"], "home-manager")
        self.assertEqual(observer.failure["sourceElapsedMs"], 600000)
        self.assertEqual(observer.failure["remainingMs"], 0)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_second_source_preparation_is_clipped_by_unchanged_overall_budget(self):
        clock, deadlines, post_source_deadlines = [0.0], [], []
        actual_disk_check = acquisition.disk_check
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        def prefetching(argv, env, root, deadline):
            deadlines.append((clock[0], deadline))
            if len(deadlines) == 1:
                clock[0] = 599.0
            return self.fake_prefetch(argv, env, root, deadline)
        def disk_checking(root, deadline, **kwargs):
            if observer.current[0:2] == ("home-manager", "source"):
                post_source_deadlines.append(deadline)
                clock[0] = 1000.0  # This aggregate scan uses the overall, not source, timer.
            return actual_disk_check(root, deadline, **kwargs)
        try:
            with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(acquisition, "disk_check", side_effect=disk_checking):
                report = self.produce(prefetching)
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(post_source_deadlines, [1200.0])
        self.assertEqual(deadlines, [(0.0, 600.0), (1000.0, 1200.0)])
        self.assertTrue(report["byteProof"]["contentRehashed"])
        self.assertEqual(observer.counters["narPassCount"], 4)
        self.assertEqual(observer.counters["pairProofCount"], 2)

    def test_combined_preparation_cannot_publish_at_expired_overall_deadline(self):
        clock, deadlines = [0.0], []
        actual_publish = acquisition.publish_pair
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        def prefetching(argv, env, root, deadline):
            deadlines.append(deadline)
            clock[0] += 599.0
            return self.fake_prefetch(argv, env, root, deadline)
        def publishing(*args, **kwargs):
            self.assertEqual(clock[0], 1198.0)
            self.assertEqual(args[-1], 1200.0)
            clock[0] = 1200.0
            return actual_publish(*args, **kwargs)
        try:
            with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(acquisition, "publish_pair", side_effect=publishing), \
                    self.assertRaisesRegex(ValueError, "acquired-verification-deadline"):
                self.produce(prefetching)
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(deadlines, [600.0, 1199.0])
        self.assertEqual(observer.counters["narPassCount"], 4)
        self.assertEqual(observer.counters["pairProofCount"], 1)
        self.assertEqual(observer.failure["source"], "pair")
        self.assertEqual(observer.failure["phase"], "publication")
        self.assertEqual(observer.failure["remainingMs"], 0)
        self.assertTrue((self.worker / "pair/receipt.json").is_file())
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_publication_seals_only_owned_envelope_after_cross_parent_rename(self):
        actual_rename = os.rename
        actual_fchmod = os.fchmod
        envelope_inode = None
        phases = []
        def renaming(source, destination, *args, **kwargs):
            nonlocal envelope_inode
            if source == "pair" and destination == "home-manager-pair":
                before = os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False)
                envelope_inode = before.st_ino
                self.assertEqual(stat.S_IMODE(before.st_mode), 0o700)
                for name in acquired.NAMES:
                    root = self.worker / "pair" / name
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o555)
                    self.assertEqual(stat.S_IMODE((root / "default.nix").stat().st_mode), 0o444)
                phases.append("rename-owned-envelope")
            return actual_rename(source, destination, *args, **kwargs)
        def changing(fd, mode):
            if envelope_inode is not None and os.fstat(fd).st_ino == envelope_inode:
                phases.append(("seal-owned-envelope", mode))
            return actual_fchmod(fd, mode)
        with patch.object(acquisition.os, "rename", side_effect=renaming), \
                patch.object(acquisition.os, "fchmod", side_effect=changing):
            self.produce()
        self.assertEqual(phases, ["rename-owned-envelope", ("seal-owned-envelope", 0o555)])
        bundle = self.outputs / "home-manager-pair"
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        for name in acquired.NAMES:
            self.assertEqual(stat.S_IMODE((bundle / name).stat().st_mode), 0o555)

    def test_post_publication_source_drift_withdraws_only_owned_envelope(self):
        actual_fchmod = os.fchmod
        mutated = False
        def changing(fd, mode):
            nonlocal mutated
            result = actual_fchmod(fd, mode)
            bundle = self.outputs / "home-manager-pair"
            if not mutated and mode == 0o555 and bundle.exists() \
                    and os.fstat(fd).st_ino == bundle.stat().st_ino:
                mutated = True
                source = bundle / "home-manager/default.nix"
                size = source.stat().st_size
                source.chmod(0o644)
                source.write_bytes(b"x" * size)
                source.chmod(0o444)
            return result
        with patch.object(acquisition.os, "fchmod", side_effect=changing), \
                self.assertRaisesRegex(ValueError, "source-changed-through-publication"):
            self.produce()
        self.assertTrue(mutated)
        self.assertFalse((self.outputs / "home-manager-pair").exists())
        self.assertTrue((self.worker / "pair").is_dir())

    def test_rollback_refuses_leaf_substituted_during_envelope_permission_change(self):
        actual_fchmod = os.fchmod
        corrupted = False
        replaced = False
        retired = self.base / "retired-published-envelope"
        def changing(fd, mode):
            nonlocal corrupted, replaced
            result = actual_fchmod(fd, mode)
            bundle = self.outputs / "home-manager-pair"
            if bundle.exists() and os.fstat(fd).st_ino == bundle.stat().st_ino:
                if mode == 0o555 and not corrupted:
                    corrupted = True
                    source = bundle / "home-manager/default.nix"
                    size = source.stat().st_size
                    source.chmod(0o644)
                    source.write_bytes(b"x" * size)
                    source.chmod(0o444)
                elif mode == 0o700 and corrupted and not replaced:
                    replaced = True
                    bundle.rename(retired)
                    bundle.mkdir(mode=0o700)
                    (bundle / "unknown-replacement").write_bytes(b"leave this inode in place")
            return result
        with patch.object(acquisition.os, "fchmod", side_effect=changing), \
                self.assertRaisesRegex(ValueError, "rollback-envelope-replaced"):
            self.produce()
        self.assertTrue(corrupted and replaced)
        self.assertEqual((self.outputs / "home-manager-pair/unknown-replacement").read_bytes(),
                         b"leave this inode in place")
        self.assertFalse((self.worker / "pair").exists())
        self.assertTrue(retired.is_dir())

    def single_source_export(self, copy=None):
        staging = self.worker / "pair"
        staging.mkdir()
        reply = self.fake_prefetch(["modeled", "nix-community"], {}, self.worker, time.monotonic() + 10)
        pin = self.locked()["home-manager"]
        source = acquisition.retained_source(self.worker, reply, pin)
        source.parent.chmod(0o555)
        with patch.object(acquisition, "FREE_FLOOR", 0), \
                acquisition.HeldDirectory(self.worker) as root, acquisition.HeldDirectory(staging) as destination:
            if copy is None:
                result = acquisition.export_source(root, destination, "home-manager", reply, pin,
                                                   time.monotonic() + 10)
            else:
                with patch.object(acquisition, "copy_source_tree", side_effect=copy):
                    result = acquisition.export_source(root, destination, "home-manager", reply, pin,
                                                       time.monotonic() + 10)
        return source, staging / "home-manager", result

    def test_readonly_store_export_uses_distinct_inodes_and_never_chmods_or_moves_inputs(self):
        before = {}
        source_inodes = set()
        actual_copy = acquisition.copy_source_tree
        actual_fchmod = os.fchmod
        def copying(source_fd, output_fd, nodes, facts, root, staging, deadline):
            before["facts"] = acquired.scan(source_fd, deadline)
            before["parent"] = acquired.snapshot((root.path / "private-store/nix/store").stat())
            for fact in facts.values():
                source_inodes.add((fact[0], fact[1]))
            return actual_copy(source_fd, output_fd, nodes, facts, root, staging, deadline)
        def changing(fd, mode):
            info = os.fstat(fd)
            self.assertNotIn((info.st_dev, info.st_ino), source_inodes)
            return actual_fchmod(fd, mode)
        with patch.object(acquisition.os, "fchmod", side_effect=changing):
            source, output, result = self.single_source_export(copying)
        self.assertEqual(stat.S_IMODE(source.parent.stat().st_mode), 0o555)
        self.assertEqual(acquired.snapshot(source.parent.stat()), before["parent"])
        with acquisition.HeldDirectory(source) as source_root:
            self.assertEqual(acquired.scan(source_root.fd, time.monotonic() + 10), before["facts"])
        self.assertTrue(source.is_dir())
        self.assertNotEqual(source.stat().st_ino, output.stat().st_ino)
        self.assertNotEqual((source / "default.nix").stat().st_ino, (output / "default.nix").stat().st_ino)
        self.assertEqual((source / "default.nix").read_bytes(), (output / "default.nix").read_bytes())
        self.assertEqual(os.readlink(output / "external-link"), "/unavailable-modeled-source-target")
        self.assertEqual(stat.S_IMODE((output / "executable").stat().st_mode), 0o555)
        self.assertEqual(result[0]["nodes"], before["facts"][0])

    def test_source_drift_after_copy_refuses_export_even_when_copy_bytes_are_correct(self):
        actual_copy = acquisition.copy_source_tree
        def copying(source_fd, output_fd, nodes, facts, root, staging, deadline):
            actual_copy(source_fd, output_fd, nodes, facts, root, staging, deadline)
            source = root.path / "private-store/nix/store" / ("0" * 32 + "-source/default.nix")
            size = source.stat().st_size
            source.chmod(0o644)
            source.write_bytes(b"x" * size)
            source.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "export-source-changed"):
            self.single_source_export(copying)
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_copy_corruption_is_rehashed_against_expected_nar_before_export_receipt(self):
        actual_copy = acquisition.copy_source_tree
        def copying(source_fd, output_fd, nodes, facts, root, staging, deadline):
            actual_copy(source_fd, output_fd, nodes, facts, root, staging, deadline)
            output = staging.path / "home-manager/default.nix"
            size = output.stat().st_size
            output.chmod(0o644)
            output.write_bytes(b"x" * size)
            output.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "export-nar-mismatch"):
            self.single_source_export(copying)
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def copy_fixture(self, count=128):
        source = self.worker / "modeled-input"
        source.mkdir()
        for index in range(count):
            path = source / ("file-%04d" % index)
            path.write_bytes(b"modeled source bytes\n" * 4)
            path.chmod(0o444)
        source.chmod(0o555)
        staging = self.worker / "pair"
        staging.mkdir()
        output = staging / "home-manager"
        output.mkdir()
        return source, staging, output

    def copy_fixture_tree(self, paths, deadline):
        source, staging, output = paths
        with acquisition.HeldDirectory(source) as source_root, \
                acquisition.HeldDirectory(staging) as envelope, \
                acquisition.HeldDirectory(output) as destination, \
                acquisition.HeldDirectory(self.worker) as root:
            nodes, facts = acquired.scan(source_root.fd, deadline)
            acquisition.copy_source_tree(source_root.fd, destination.fd, nodes, facts,
                                         root, envelope, deadline)

    def test_many_file_copy_scans_private_tree_only_at_phase_boundaries(self):
        paths = self.copy_fixture()
        actual_usage = acquisition.usage
        clock = time.monotonic()
        def advancing():
            nonlocal clock
            clock += 0.01
            return clock
        with patch.object(acquisition.time, "monotonic", side_effect=advancing), \
                patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition, "usage", wraps=actual_usage) as scans, \
                patch.object(acquisition, "free_space_check", wraps=acquisition.free_space_check) as samples:
            self.copy_fixture_tree(paths, clock + 300)
        self.assertEqual(scans.call_count, 2)
        self.assertGreater(samples.call_count, 2)
        self.assertEqual(len(list(paths[2].iterdir())), 128)
        self.assertEqual((paths[0] / "file-0000").read_bytes(), (paths[2] / "file-0000").read_bytes())

    def test_copy_sampled_free_floor_refuses_without_whole_tree_rescan(self):
        paths = self.copy_fixture()
        clock = time.monotonic()
        def advancing():
            nonlocal clock
            clock += 0.01
            return clock
        with patch.object(acquisition, "FREE_FLOOR", 1), \
                patch.object(acquisition.time, "monotonic", side_effect=advancing), \
                patch.object(acquisition.os, "fstatvfs", side_effect=[
                    SimpleNamespace(f_bavail=1, f_frsize=4096),
                    SimpleNamespace(f_bavail=0, f_frsize=4096)]), \
                patch.object(acquisition, "usage", wraps=acquisition.usage) as scans, \
                self.assertRaisesRegex(ValueError, "free-floor"):
            self.copy_fixture_tree(paths, clock + 300)
        self.assertEqual(scans.call_count, 1)
        self.assertGreater(len(list(paths[2].iterdir())), 0)
        self.assertLess(len(list(paths[2].iterdir())), 128)

    def test_copy_incremental_private_node_and_allocation_limits_refuse(self):
        paths = self.copy_fixture(4)
        baseline = acquisition.usage(self.worker, time.monotonic() + 10, details=True)
        with patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition, "MAX_PRIVATE_NODES", baseline["nodes"]), \
                self.assertRaisesRegex(ValueError, "private-inventory-bound"):
            self.copy_fixture_tree(paths, time.monotonic() + 10)
        self.assertEqual(list(paths[2].iterdir()), [])
        with patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition, "MAX_PRIVATE_METADATA", baseline["metadata"]), \
                self.assertRaisesRegex(ValueError, "private-inventory-bound"):
            self.copy_fixture_tree(paths, time.monotonic() + 10)
        self.assertEqual(list(paths[2].iterdir()), [])
        with patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition, "DISK_BUDGET", max(baseline["logical"], baseline["allocated"])), \
                self.assertRaisesRegex(ValueError, "private-disk-budget"):
            self.copy_fixture_tree(paths, time.monotonic() + 10)
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_main_emits_one_bounded_redacted_failure_category(self):
        arguments = ["--nix", "n", "--ca-file", "c", "--lock", "l"]
        subprocess_timeout = acquisition.subprocess.TimeoutExpired("/private/source", 300)
        errors = (ValueError("acquired-verification-deadline"),
                  OSError("/private/source/path token=do-not-print"),
                  ValueError("https://private.example/token=do-not-print"),
                  subprocess_timeout)
        for error in errors:
            output = io.StringIO()
            with self.subTest(error=type(error).__name__), \
                    patch.object(acquisition, "run", side_effect=error), redirect_stdout(output):
                self.assertEqual(acquisition.main(arguments), 2)
            raw = output.getvalue()
            self.assertEqual(len(raw.splitlines()), 1)
            self.assertLessEqual(len(raw), 4096)
            self.assertNotIn("/private/", raw)
            self.assertNotIn("private.example", raw)
            self.assertNotIn("token", raw)
            self.assertNotIn("Traceback", raw)
            result = json.loads(raw)
            self.assertFalse(result["passed"])
            self.assertEqual(result["activation"], "unproved")
        self.assertEqual(acquisition.failure_category(errors[0]), "acquired-verification-deadline")
        self.assertEqual(acquisition.failure_category(subprocess_timeout), "acquisition-deadline")

    def test_diagnostics_refuse_injected_labels_values_and_unknown_failure_text(self):
        sink = io.StringIO()
        observer = acquisition.Progress(sink)
        token = acquisition.PROGRESS.set(observer)
        try:
            for arguments in ({"name": "/private/caller-phase"},
                              {"name": "copy", "source": "caller-account@example.invalid"},
                              {"name": "copy", "deadline": float("nan")},
                              {"name": "copy", "emit": "caller-value"}):
                with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, "diagnostic-phase"):
                    with acquisition.phase(**arguments):
                        self.fail("invalid diagnostic value was admitted")
            with self.assertRaisesRegex(ValueError, "diagnostic-event"):
                observer.event("caller-secret-event")
            for counter, amount in (("caller-secret", 1), ("copiedBytes", True),
                                    ("copiedBytes", -1), ("copiedBytes", acquisition.MAX_RETAINED_BYTES + 1)):
                with self.assertRaisesRegex(ValueError, "diagnostic-counter"):
                    observer.add(counter, amount)
            observer.capture(ValueError("acquisition-caller-private-secret"))
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertEqual(sink.getvalue(), "")
        self.assertEqual(observer.summary()["category"], "acquisition-bounded-input-or-custody-failed")
        self.assertNotIn("secret", acquisition.encoded(observer.summary()).decode())

    def test_diagnostic_events_have_hard_count_and_byte_bounds(self):
        sink = io.StringIO()
        observer = acquisition.Progress(sink)
        token = acquisition.PROGRESS.set(observer)
        try:
            for _ in range(100):
                with acquisition.phase("copy", source="home-manager", deadline=time.monotonic() + 300):
                    acquisition.count("copiedNodes")
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertLessEqual(observer.events, acquisition.MAX_DIAGNOSTIC_EVENTS)
        self.assertLessEqual(len(sink.getvalue().encode()), acquisition.MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(observer.bytes, len(sink.getvalue().encode()))
        self.assertEqual(observer.summary()["counters"]["copiedNodes"], 100)
        for raw in sink.getvalue().splitlines():
            event = json.loads(raw)
            self.assertIn(event["event"], ("begin", "end"))
            self.assertIn(event["source"], acquired.NAMES)
            self.assertIn(event["phase"], acquisition.PHASES)
            self.assertEqual(set(event["counters"]), acquisition.COUNTERS)
            self.assertNotIn("directory", event)

    def test_diagnostic_modeled_production_counts_real_scans_and_separate_proofs(self):
        sink = io.StringIO()
        observer = acquisition.Progress(sink)
        token = acquisition.PROGRESS.set(observer)
        try:
            report = self.produce()
        finally:
            acquisition.PROGRESS.reset(token)
        self.assertFalse(report["evaluationExecuted"])
        self.assertEqual(observer.counters["narPassCount"], 4)  # Original and copy for each source.
        self.assertEqual(observer.counters["pairProofCount"], 2)  # Readback and final publication proof.
        self.assertEqual(observer.counters["privateScanCount"], 7)
        self.assertEqual(observer.counters["copiedNodes"], 10)
        self.assertGreater(observer.counters["copiedBytes"], 0)
        self.assertIsNone(observer.failure)
        for raw in sink.getvalue().splitlines():
            event = json.loads(raw)
            self.assertIn(event["source"], (*acquired.NAMES, "pair"))
            self.assertTrue(all(name in acquisition.PHASES for name in event["phasePath"]))
        self.assertLessEqual(observer.events, acquisition.MAX_DIAGNOSTIC_EVENTS)
        self.assertLessEqual(observer.bytes, acquisition.MAX_DIAGNOSTIC_BYTES)

    def test_diagnostic_first_failure_phase_survives_owned_cleanup_failure(self):
        output, diagnostics = io.StringIO(), io.StringIO()
        def failing_run(args):
            with acquisition.HeldDirectory(self.worker) as scratch, acquisition.private_worker(scratch):
                with acquisition.phase("copy", source="nixpkgs", deadline=time.monotonic() - 1):
                    acquired.check_deadline(time.monotonic() - 1)
        with patch.object(acquisition, "run", side_effect=failing_run), \
                patch.object(acquisition, "restore_cleanup_directories", side_effect=OSError("/private/cleanup token=hidden")), \
                redirect_stdout(output), redirect_stderr(diagnostics):
            self.assertEqual(acquisition.main(["--nix", "n", "--ca-file", "c", "--lock", "l"]), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["category"], "acquired-verification-deadline")
        self.assertEqual(result["context"]["source"], "nixpkgs")
        self.assertEqual(result["context"]["phase"], "copy")
        self.assertEqual(result["context"]["phasePath"], ["inputs", "copy"])
        self.assertEqual(result["context"]["cleanupCategory"], "acquisition-filesystem-refusal")
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertLessEqual(len(output.getvalue()), 4096)
        self.assertLessEqual(len(diagnostics.getvalue().encode()), acquisition.MAX_DIAGNOSTIC_BYTES)
        self.assertNotIn("/private/", output.getvalue() + diagnostics.getvalue())
        self.assertNotIn("token", output.getvalue() + diagnostics.getvalue())
        self.assertIsNone(acquisition.PROGRESS.get())

    def test_child_failure_leaves_no_published_complete_pair(self):
        with self.assertRaisesRegex(ValueError, "modeled failure"):
            self.produce(lambda *args: (_ for _ in ()).throw(ValueError("modeled failure")))
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_export_refuses_matching_size_corrupt_bytes(self):
        def corrupted(*args):
            reply = self.fake_prefetch(*args)
            path = acquisition.retained_source(args[2], reply, self.locked()["home-manager"])
            file = path / "default.nix"
            file.chmod(0o644)
            file.write_bytes(b"x" * file.stat().st_size)
            file.chmod(0o444)
            return reply
        with self.assertRaisesRegex(ValueError, "export-nar-mismatch"):
            self.produce(corrupted)
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_reply_cannot_nominate_global_or_traversal_source(self):
        pin = self.locked()["nixpkgs"]
        for path in ("/tmp/arbitrary", "/nix/store/" + "0" * 32 + "-source/../../escape",
                     "/nix/store/" + "0" * 32 + "-wrong"):
            with self.assertRaisesRegex(ValueError, "private-source-path"):
                acquisition.retained_source(self.worker, {"storePath": path, "hash": pin["narHash"]}, pin)

    def test_reply_hash_and_extra_fields_are_refused(self):
        pin = self.locked()["nixpkgs"]
        reply = {"storePath": "/nix/store/" + "0" * 32 + "-source", "hash": "wrong"}
        with self.assertRaisesRegex(ValueError, "prefetch-hash"):
            acquisition.retained_source(self.worker, reply, pin)
        with self.assertRaisesRegex(ValueError, "metadata-fields"):
            acquisition.retained_source(self.worker, {**reply, "url": "arbitrary"}, pin)

    def test_usage_counts_pending_nested_fanout_before_retention(self):
        nested = self.worker / "a"
        nested.mkdir()
        (self.worker / "b").mkdir()
        (nested / "c").mkdir()
        (nested / "d").mkdir()
        with patch.object(acquisition, "MAX_PRIVATE_NODES", 4), \
                self.assertRaisesRegex(ValueError, "private-inventory-bound"):
            acquisition.usage(self.worker, time.monotonic() + 10)
        with patch.object(acquisition, "MAX_PRIVATE_METADATA", 128), \
                self.assertRaisesRegex(ValueError, "private-inventory-bound"):
            acquisition.usage(self.worker, time.monotonic() + 10)

    def test_usage_does_not_follow_link_targets_and_refuses_special_files(self):
        (self.worker / "inert").symlink_to("/unavailable-modeled-root")
        acquisition.usage(self.worker, time.monotonic() + 10)
        os.mkfifo(self.worker / "pipe")
        with self.assertRaisesRegex(ValueError, "private-special-file"):
            acquisition.usage(self.worker, time.monotonic() + 10)

    def test_file_and_sampled_disk_budget_and_deadline_refuse(self):
        (self.worker / "file").write_bytes(b"1234")
        with patch.object(acquired, "MAX_FILE_BYTES", 3), self.assertRaisesRegex(ValueError, "private-file-bound"):
            acquisition.usage(self.worker, time.monotonic() + 10)
        with patch.object(acquisition, "DISK_BUDGET", 3), self.assertRaisesRegex(ValueError, "disk-budget"):
            acquisition.usage(self.worker, time.monotonic() + 10)
        with self.assertRaisesRegex(ValueError, "deadline"):
            acquisition.usage(self.worker, time.monotonic() - 1)

    def test_inherited_hard_file_limit_is_never_raised(self):
        with patch.object(resource, "getrlimit", return_value=(1024, 2048)):
            self.assertEqual(acquisition.file_limits(), (1024, 1024))
        with patch.object(resource, "getrlimit", return_value=(0, 2048)), \
                self.assertRaisesRegex(ValueError, "inherited-file-limit"):
            acquisition.file_limits()

    def child_streams(self, payload, stderr=b""):
        streams = []
        for content in (payload, stderr):
            reader, writer = os.pipe()
            os.write(writer, content)
            os.close(writer)
            streams.append(os.fdopen(reader, "rb"))
        process = SimpleNamespace(pid=987654321, stdout=streams[0], stderr=streams[1], returncode=0)
        events = []
        process.wait = lambda timeout: events.append("reap")
        return process, events

    @staticmethod
    def polling_selector(clock, quiet_polls):
        class PollingSelector:
            def __init__(self):
                self.keys = {}
                self.polls = 0
            def register(self, stream, events, data):
                self.keys[stream] = SimpleNamespace(fileobj=stream, data=data)
            def unregister(self, stream):
                del self.keys[stream]
            def get_map(self):
                return self.keys
            def select(self, timeout):
                self.polls += 1
                clock[0] += timeout
                return [] if self.polls <= quiet_polls else [(key, None) for key in self.keys.values()]
            def close(self):
                self.keys.clear()
        return PollingSelector()

    def test_prefetch_scans_on_cadence_and_forces_completion_with_per_poll_floor(self):
        payload = {"storePath": "/nix/store/" + "0" * 32 + "-source", "hash": "modeled"}
        process, events = self.child_streams(acquisition.encoded(payload))
        clock = [1000.0]
        selector = self.polling_selector(clock, 25)
        scans, floors, scan_modes = [], [], []
        def scanning(*args, **kwargs):
            scans.append(clock[0])
            scan_modes.append(kwargs.get("quiescent", False))
            if scan_modes[-1]:
                self.assertEqual(events, ["kill-group", "reap"])
            clock[0] += 0.4  # A scan itself takes time: cadence starts at its end.
        actual_floor = acquisition.free_space_check
        def sampling(*args):
            floors.append(clock[0])
            return actual_floor(*args)
        with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(acquisition.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition.selectors, "DefaultSelector", return_value=selector), \
                patch.object(acquisition, "disk_check", side_effect=scanning), \
                patch.object(acquisition, "free_space_check", side_effect=sampling), \
                patch.object(acquisition.os, "waitid", side_effect=[None, None, None, SimpleNamespace(si_status=0)]), \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda *args: events.append("kill-group")):
            result = acquisition.prefetch(["declared-nix"], {}, self.worker, clock[0] + 300)
        self.assertEqual(result, payload)
        self.assertEqual(len(floors), selector.polls + 3)
        self.assertGreater(len(floors), len(scans) * 4)
        self.assertLessEqual(len(scans), 5)
        self.assertGreater(len(scans), 2)
        self.assertEqual(scan_modes[:-1], [False] * (len(scans) - 1))
        self.assertIs(scan_modes[-1], True)
        # Exclude the forced completion sample from the cadence spacing check.
        for before, after in zip(scans[:-2], scans[1:-1]):
            self.assertGreaterEqual(after - before + 1e-6, 1.4)
        self.assertGreaterEqual(scans[-1], floors[-1])
        self.assertEqual(events, ["kill-group", "reap"])

    def test_prefetch_deferred_scan_still_enforces_deadline_on_every_poll(self):
        process, events = self.child_streams(b"{}")
        clock = [1000.0]
        selector = self.polling_selector(clock, 25)
        with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition.selectors, "DefaultSelector", return_value=selector), \
                patch.object(acquisition, "disk_check") as scans, \
                patch.object(acquisition, "free_space_check", wraps=acquisition.free_space_check) as samples, \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda *args: events.append("kill-group")):
            observer = acquisition.Progress(io.StringIO())
            token = acquisition.PROGRESS.set(observer)
            try:
                with self.assertRaisesRegex(ValueError, "verification-deadline"), \
                        acquisition.phase("prefetch", source="nixpkgs", deadline=clock[0] + 0.35):
                    acquisition.prefetch(["declared-nix"], {}, self.worker, clock[0] + 0.35)
            finally:
                acquisition.PROGRESS.reset(token)
        self.assertEqual(scans.call_count, 1)  # Admission only; next full scan is not due.
        self.assertEqual(samples.call_count, 5)
        self.assertEqual(selector.polls, 4)
        self.assertEqual(events, ["kill-group", "reap"])
        context = observer.summary()
        self.assertEqual(context["source"], "nixpkgs")
        self.assertEqual(context["phase"], "prefetch-monitor")
        self.assertEqual(context["phasePath"], ["prefetch", "prefetch-monitor"])
        self.assertEqual(context["counters"]["monitorPolls"], 5)
        self.assertGreater(context["sourceElapsedMs"], 300)

    def test_prefetch_deferred_scan_still_refuses_per_poll_free_floor_loss(self):
        process, events = self.child_streams(b"{}")
        clock = [1000.0]
        selector = self.polling_selector(clock, 25)
        with patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(acquisition, "FREE_FLOOR", 1), \
                patch.object(acquisition.os, "fstatvfs", side_effect=[
                    SimpleNamespace(f_bavail=1, f_frsize=4096),
                    SimpleNamespace(f_bavail=0, f_frsize=4096)]), \
                patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition.selectors, "DefaultSelector", return_value=selector), \
                patch.object(acquisition, "disk_check") as scans, \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda *args: events.append("kill-group")), \
                self.assertRaisesRegex(ValueError, "free-floor"):
            acquisition.prefetch(["declared-nix"], {}, self.worker, clock[0] + 300)
        self.assertEqual(scans.call_count, 1)
        self.assertEqual(selector.polls, 1)
        self.assertEqual(events, ["kill-group", "reap"])

    def test_prefetch_bounds_output_and_cleans_only_created_process_group(self):
        process, events = self.child_streams(b"x" * 32)
        with patch.object(acquisition, "MAX_STDOUT", 16), \
                patch.object(acquisition.subprocess, "Popen", return_value=process) as launch, \
                patch.object(acquisition, "disk_check"), \
                patch.object(acquisition, "free_space_check"), \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda pid, sig: events.append((pid, sig))), \
                self.assertRaisesRegex(ValueError, "child-output-bound"):
            acquisition.prefetch(["declared-nix"], {"PATH": ""}, self.worker, time.monotonic() + 10)
        self.assertEqual(events, [(process.pid, acquisition.signal.SIGKILL), "reap"])
        self.assertTrue(launch.call_args.kwargs["start_new_session"])
        self.assertIs(launch.call_args.kwargs["preexec_fn"], acquisition.child_limit)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_prefetch_success_waits_unreaped_then_cleans_group_and_decodes_exact_bytes(self):
        payload = {"storePath": "/nix/store/" + "0" * 32 + "-source", "hash": "modeled"}
        process, events = self.child_streams(acquisition.encoded(payload))
        def waited(*args):
            events.append("unreaped")
            self.assertTrue(args[-1] & acquisition.os.WNOWAIT)
            return SimpleNamespace(si_status=0)
        with patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition, "disk_check"), \
                patch.object(acquisition, "free_space_check"), \
                patch.object(acquisition.os, "waitid", side_effect=waited), \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda pid, sig: events.append("kill-group")):
            result = acquisition.prefetch(["declared-nix"], {}, self.worker, time.monotonic() + 10)
        self.assertEqual(result, payload)
        self.assertEqual(events, ["unreaped", "kill-group", "reap"])

    def test_prefetch_deadline_after_spawn_still_cleans_group_and_reaps(self):
        process, events = self.child_streams(b"{}")
        with patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition, "disk_check"), \
                patch.object(acquisition, "free_space_check", side_effect=ValueError("modeled deadline")), \
                patch.object(acquisition.os, "getpgid", return_value=process.pid), \
                patch.object(acquisition.os, "killpg", side_effect=lambda pid, sig: events.append("kill-group")), \
                self.assertRaisesRegex(ValueError, "modeled deadline"):
            acquisition.prefetch(["declared-nix"], {}, self.worker, time.monotonic() + 10)
        self.assertEqual(events, ["kill-group", "reap"])
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_prefetch_refuses_foreign_group_without_signalling_it_and_reaps_owned_leader(self):
        process, events = self.child_streams(b"{}")
        with patch.object(acquisition.subprocess, "Popen", return_value=process), \
                patch.object(acquisition, "disk_check"), \
                patch.object(acquisition, "free_space_check"), \
                patch.object(acquisition.os, "waitid", return_value=SimpleNamespace(si_status=0)), \
                patch.object(acquisition.os, "getpgid", return_value=42), \
                patch.object(acquisition.os, "killpg") as kill, \
                self.assertRaisesRegex(ValueError, "child-live-group"):
            acquisition.prefetch(["declared-nix"], {}, self.worker, time.monotonic() + 10)
        kill.assert_not_called()
        self.assertEqual(events, ["reap"])
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_fifo_lock_is_refused_without_read_or_blocking_open(self):
        path = self.base / "lock-fifo"
        os.mkfifo(path)
        actual_open = os.open
        observed = []
        def opening(name, flags, *args, **kwargs):
            if name == path.name:
                observed.append(flags)
            return actual_open(name, flags, *args, **kwargs)
        with patch.object(acquisition.os, "open", side_effect=opening), \
                patch.object(acquisition.os, "read", side_effect=AssertionError("must not read FIFO")), \
                self.assertRaisesRegex(ValueError, "lock-regular-byte-bound"):
            acquisition.read_lock(path)
        self.assertTrue(observed[0] & os.O_NONBLOCK)
        self.assertTrue(observed[0] & os.O_NOFOLLOW)

    def test_regular_declared_lock_alias_is_bounded_and_retargeting_is_refused(self):
        path = self.base / "lock.json"
        path.write_bytes(acquisition.encoded(self.lock))
        alias = self.base / "declared-lock"
        alias.symlink_to(path)
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True):
            self.assertEqual(acquisition.read_lock(alias)[0], path.read_bytes())
        alternate = self.base / "alternate-lock.json"
        alternate.write_bytes(path.read_bytes())
        actual_read = os.read
        moved = False
        def reading(fd, size):
            nonlocal moved
            if not moved:
                moved = True
                alias.unlink()
                alias.symlink_to(alternate)
            return actual_read(fd, size)
        with patch.object(acquisition.os, "read", side_effect=reading), \
                self.assertRaisesRegex(ValueError, "lock-replaced"):
            acquisition.read_lock(alias)

    def test_usage_keeps_descent_under_held_ancestor_after_alias_substitution(self):
        ancestor = self.worker / "a"
        (ancestor / "b").mkdir(parents=True)
        outside = self.base / "outside"
        (outside / "b").mkdir(parents=True)
        (outside / "b/sentinel").write_bytes(b"outside")
        ancestor_inode = ancestor.stat().st_ino
        outside_inodes = {outside.stat().st_ino, (outside / "b").stat().st_ino}
        actual_scandir = os.scandir
        moved = False
        def scanning(fd):
            nonlocal moved
            inode = os.fstat(fd).st_ino
            self.assertNotIn(inode, outside_inodes)
            if inode == ancestor_inode and not moved:
                moved = True
                ancestor.rename(self.base / "retired-ancestor")
                ancestor.symlink_to(outside, target_is_directory=True)
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                self.assertRaisesRegex(ValueError, "private-directory-replaced"):
            acquisition.usage(self.worker, time.monotonic() + 10)
        self.assertTrue(moved)
        self.assertEqual((outside / "b/sentinel").read_bytes(), b"outside")

    def test_metadata_write_and_chmod_stay_on_held_directory_when_path_is_replaced(self):
        outside = self.base / "outside"
        outside.mkdir()
        sentinel = outside / "receipt.json"
        sentinel.write_bytes(b"outside")
        sentinel.chmod(0o600)
        retired = self.base / "retired-output"
        actual_fchmod = os.fchmod
        moved = False
        def changing(fd, mode):
            nonlocal moved
            if stat.S_ISREG(os.fstat(fd).st_mode) and not moved:
                moved = True
                self.outputs.rename(retired)
                self.outputs.symlink_to(outside, target_is_directory=True)
            return actual_fchmod(fd, mode)
        with acquisition.HeldDirectory(self.outputs) as target, \
                patch.object(acquisition.os, "fchmod", side_effect=changing), \
                self.assertRaisesRegex(ValueError, "held-directory-replaced"):
            acquisition.write_metadata(target, "receipt.json", {"fixture": True}, 100)
        self.assertEqual(sentinel.read_bytes(), b"outside")
        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((retired / "receipt.json").stat().st_mode), 0o444)

    def test_staging_substitution_after_metadata_cannot_chmod_or_publish_outside(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        actual_write = acquisition.write_metadata
        actual_disk_check = acquisition.disk_check
        substituted = False
        def writing(directory, name, value, maximum):
            nonlocal substituted
            payload = actual_write(directory, name, value, maximum)
            if name == "acquisition.json":
                directory.path.rename(self.base / "retired-pair")
                directory.path.symlink_to(outside, target_is_directory=True)
                substituted = True
            return payload
        def checking(*args, **kwargs):
            self.assertFalse(substituted, "staging refusal must precede another budget traversal")
            return actual_disk_check(*args, **kwargs)
        with patch.object(acquisition, "write_metadata", side_effect=writing), \
                patch.object(acquisition, "disk_check", side_effect=checking), \
                self.assertRaisesRegex(ValueError, "held-directory-replaced"):
            self.produce()
        self.assertTrue(substituted)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)
        self.assertFalse((self.outputs / "home-manager-pair").exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_final_source_byte_recheck_rejects_same_size_drift_during_report_write(self):
        actual_write = acquisition.write_metadata
        def writing(directory, name, value, maximum):
            payload = actual_write(directory, name, value, maximum)
            if name == "acquisition.json":
                source = directory.path / "home-manager/default.nix"
                size = source.stat().st_size
                source.chmod(0o644)
                source.write_bytes(b"x" * size)
                source.chmod(0o444)
            return payload
        with patch.object(acquisition, "write_metadata", side_effect=writing), \
                self.assertRaisesRegex(ValueError, "source-nar-mismatch"):
            self.produce()
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_destination_substitution_after_final_rehash_refuses_descriptor_publication(self):
        outside = self.base / "outside"
        outside.mkdir()
        actual_verify = acquired.verify_acquired_pair
        calls = 0
        def verifying(*args, **kwargs):
            nonlocal calls
            result = actual_verify(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.outputs.rename(self.base / "retired-output")
                self.outputs.symlink_to(outside, target_is_directory=True)
            return result
        with patch.object(acquired, "verify_acquired_pair", side_effect=verifying), \
                self.assertRaisesRegex(ValueError, "held-directory-replaced"):
            self.produce()
        self.assertEqual(calls, 2)
        self.assertEqual(list(outside.iterdir()), [])

    def test_published_receipt_bytes_are_witnessed_during_final_source_rehash(self):
        actual_verify = acquired.verify_acquired_pair
        calls = 0
        def verifying(*args, **kwargs):
            nonlocal calls
            result = actual_verify(*args, **kwargs)
            calls += 1
            if calls == 2:
                receipt = self.worker / "pair/receipt.json"
                size = receipt.stat().st_size
                receipt.chmod(0o644)
                receipt.write_bytes(b"x" * size)
                receipt.chmod(0o444)
            return result
        with patch.object(acquired, "verify_acquired_pair", side_effect=verifying), \
                self.assertRaisesRegex(ValueError, "metadata-changed-before-publication"):
            self.produce()
        self.assertEqual(calls, 2)
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_private_worker_fd_cleanup_removes_readonly_tree_without_following_inert_link(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"outside")
        with acquisition.HeldDirectory(self.worker) as scratch:
            with acquisition.private_worker(scratch) as worker:
                selected = worker.path
                self.tree(selected / "immutable", "modeled")
                (selected / "outside-link").symlink_to(outside, target_is_directory=True)
            self.assertFalse(selected.exists())
        self.assertEqual(sentinel.read_bytes(), b"outside")
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)

    def test_private_worker_cleanup_refuses_replaced_scratch_parent(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        with acquisition.HeldDirectory(self.worker) as scratch, \
                self.assertRaisesRegex(ValueError, "held-directory-replaced"):
            with acquisition.private_worker(scratch) as worker:
                selected = worker.path
                self.worker.rename(self.base / "retired-worker")
                self.worker.symlink_to(outside, target_is_directory=True)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)

    def test_streamed_metadata_bound_prevents_publication(self):
        with self.assertRaisesRegex(ValueError, "output-metadata-bound"):
            acquisition.write_metadata(self.outputs, "too-large.json", {"value": "x" * 100}, 20)
        self.assertFalse((self.outputs / "too-large.json").exists())

    def test_retained_sum_bound_refuses_before_complete_output(self):
        with patch.object(acquisition, "MAX_RETAINED_BYTES", 1), \
                self.assertRaisesRegex(ValueError, "retained-pair-bound"):
            self.produce()
        self.assertFalse((self.outputs / "home-manager-pair").exists())

    def test_borrowed_copy_anchor_walks_every_shared_link_once_and_keeps_fallback(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        with acquisition.HeldDirectory(self.worker) as root, \
                acquisition.HeldDirectory(staging_path, parent_anchor=root) as staging:
            actual_fstat, actual_stat = os.fstat, os.stat
            with patch.object(root, "check", wraps=root.check) as root_check, \
                    patch.object(staging, "check", wraps=staging.check) as stage_check, \
                    patch.object(acquisition.os, "fstat", wraps=actual_fstat) as fstats, \
                    patch.object(acquisition.os, "stat", wraps=actual_stat) as stats:
                acquisition.check_copy_anchors(root, staging)
            self.assertEqual(root_check.call_count, 0)
            self.assertEqual(stage_check.call_count, 1)
            self.assertEqual(fstats.call_count, len(staging.chain))
            self.assertEqual(stats.call_count, len(staging.chain) - 1)
            self.assertEqual(staging._parent_prefix, tuple(root.chain))
            self.assertIsNot(staging.chain, root.chain)
            with acquisition.HeldDirectory(staging_path) as independent:
                with patch.object(root, "check", wraps=root.check) as root_check, \
                        patch.object(independent, "check", wraps=independent.check) as stage_check:
                    acquisition.check_copy_anchors(root, independent)
                self.assertEqual(root_check.call_count, 1)
                self.assertEqual(stage_check.call_count, 1)

    def test_borrowed_child_close_preserves_parent_descriptors(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        with acquisition.HeldDirectory(self.worker) as root:
            parent_fds = [entry[2] for entry in root.chain]
            staging = acquisition.HeldDirectory(staging_path, parent_anchor=root)
            child_fd = staging.fd
            staging.close()
            root.check()
            for fd in parent_fds:
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
            with self.assertRaises(OSError):
                os.fstat(child_fd)
            with self.assertRaisesRegex(ValueError, "held-directory-closed"):
                staging.check()

    def test_borrowed_child_refuses_closed_parent_even_after_exact_fd_inode_reuse(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        root = acquisition.HeldDirectory(self.worker)
        staging = acquisition.HeldDirectory(staging_path, parent_anchor=root)
        old_fd, old_identity = root.fd, acquisition.directory_identity(os.fstat(root.fd))
        root.close()
        replacement = os.open(self.worker, os.O_RDONLY | os.O_DIRECTORY)
        if replacement != old_fd:
            os.dup2(replacement, old_fd)
            os.close(replacement)
        try:
            self.assertEqual(acquisition.directory_identity(os.fstat(old_fd)), old_identity)
            with patch.object(acquisition.os, "fstat", side_effect=AssertionError("lifetime first")), \
                    self.assertRaisesRegex(ValueError, "held-parent-lifetime"):
                staging.check()
            staging.close()
            self.assertEqual(acquisition.directory_identity(os.fstat(old_fd)), old_identity)
        finally:
            staging.close()
            os.close(old_fd)

    def test_borrowed_transitive_owner_and_reinitialized_parent_lifetimes_refuse(self):
        staging_path = self.worker / "pair"
        (staging_path / "nested").mkdir(parents=True)
        root = acquisition.HeldDirectory(self.worker)
        staging = acquisition.HeldDirectory(staging_path, parent_anchor=root)
        nested = acquisition.HeldDirectory(staging_path / "nested", parent_anchor=staging)
        root.close()
        root.__init__(self.worker)
        try:
            root.check()
            for child in (staging, nested):
                with self.assertRaisesRegex(ValueError, "held-parent-lifetime"):
                    child.check()
        finally:
            nested.close()
            staging.close()
            root.close()

    def test_borrowed_constructor_refusals_do_not_allocate_or_close_parent_fds(self):
        (self.worker / "intermediate").mkdir()
        with acquisition.HeldDirectory(self.worker) as root:
            parent_fds = [entry[2] for entry in root.chain]
            for selected in (self.worker, self.outputs):
                with patch.object(acquisition.os, "open", wraps=os.open) as opening, \
                        self.assertRaisesRegex(ValueError, "held-parent-scope"):
                    acquisition.HeldDirectory(selected, parent_anchor=root)
                self.assertEqual(opening.call_count, 0)
            actual_open = os.open
            opened = []
            def opening(*args, **kwargs):
                fd = actual_open(*args, **kwargs)
                opened.append(fd)
                return fd
            with patch.object(acquisition.os, "open", side_effect=opening), \
                    self.assertRaises(FileNotFoundError):
                acquisition.HeldDirectory(self.worker / "intermediate/missing", parent_anchor=root)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            root.check()
            for fd in parent_fds:
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))

    def test_borrowed_constructor_closes_new_fd_when_witness_capture_fails(self):
        (self.worker / "pair").mkdir()
        with acquisition.HeldDirectory(self.worker) as root:
            actual_open, actual_fstat = os.open, os.fstat
            opened = []
            def opening(*args, **kwargs):
                fd = actual_open(*args, **kwargs)
                opened.append(fd)
                return fd
            def witnessing(fd):
                if fd in opened:
                    raise OSError("modeled witness refusal")
                return actual_fstat(fd)
            with patch.object(acquisition.os, "open", side_effect=opening), \
                    patch.object(acquisition.os, "fstat", side_effect=witnessing), \
                    self.assertRaises(OSError):
                acquisition.HeldDirectory(self.worker / "pair", parent_anchor=root)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            root.check()

    def test_borrowed_copy_anchor_refuses_shared_ancestor_substitution(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        with acquisition.HeldDirectory(self.worker) as root, \
                acquisition.HeldDirectory(staging_path, parent_anchor=root) as staging:
            self.worker.rename(self.base / "retired-worker")
            self.worker.mkdir()
            (self.worker / "pair").mkdir()
            with self.assertRaisesRegex(ValueError, "held-directory-replaced"):
                acquisition.check_copy_anchors(root, staging)
            self.assertEqual(list((self.worker / "pair").iterdir()), [])

    def test_borrowed_copy_anchor_refuses_staging_substitution_and_permission_drift(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        with acquisition.HeldDirectory(self.worker) as root, \
                acquisition.HeldDirectory(staging_path, parent_anchor=root) as staging:
            self.worker.chmod(0o720)
            with self.assertRaisesRegex(ValueError, "held-directory-custody"):
                acquisition.check_copy_anchors(root, staging)
            self.worker.chmod(0o700)
            staging_path.rename(self.worker / "retired-pair")
            staging_path.mkdir()
            with self.assertRaisesRegex(ValueError, "held-directory-replaced"):
                acquisition.check_copy_anchors(root, staging)
            self.assertEqual(list(staging_path.iterdir()), [])

    def test_borrowed_copy_anchor_refuses_changed_owner_descriptor_and_prefix(self):
        staging_path = self.worker / "pair"
        staging_path.mkdir()
        with acquisition.HeldDirectory(self.worker) as root, \
                acquisition.HeldDirectory(staging_path, parent_anchor=root) as staging:
            original_fd = root.fd
            root.fd = staging.fd
            with self.assertRaisesRegex(ValueError, "held-parent-prefix"):
                acquisition.check_copy_anchors(root, staging)
            root.fd = original_fd
            entry = root.chain[0]
            root.chain[0] = (*entry[:3], (0, 0, 0))
            try:
                with self.assertRaisesRegex(ValueError, "held-directory-custody"):
                    acquisition.check_copy_anchors(root, staging)
            finally:
                root.chain[0] = entry
            acquisition.check_copy_anchors(root, staging)

    def test_modeled_production_keeps_all_source_scans_and_per_file_syncs(self):
        actual_scan, actual_fsync, actual_scandir = acquired.scan, os.fsync, os.scandir
        scans, synced = {}, []
        worker_inode = self.worker.stat().st_ino
        sibling_changes = 0
        def scanning(fd, *args, **kwargs):
            identity = acquisition.directory_identity(os.fstat(fd))
            scans[identity] = scans.get(identity, 0) + 1
            return actual_scan(fd, *args, **kwargs)
        def syncing(fd):
            info = os.fstat(fd)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            synced.append((info.st_dev, info.st_ino))
            return actual_fsync(fd)
        def scanning_directory(fd):
            nonlocal sibling_changes
            if os.fstat(fd).st_ino == worker_inode:
                sibling = self.base / "unrelated-sibling"
                sibling.mkdir()
                sibling.rmdir()
                sibling_changes += 1
            return actual_scandir(fd)
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        try:
            with patch.object(acquired, "scan", side_effect=scanning), \
                    patch.object(acquisition.os, "fsync", side_effect=syncing), \
                    patch.object(acquisition.os, "scandir", side_effect=scanning_directory):
                self.produce()
        finally:
            acquisition.PROGRESS.reset(token)
        for name, digit in (("home-manager", "0"), ("nixpkgs", "1")):
            original = self.worker / "private-store/nix/store" / (digit * 32 + "-source")
            retained = self.outputs / "home-manager-pair" / name
            self.assertEqual(scans[acquisition.directory_identity(original.stat())], 5)
            self.assertEqual(scans[acquisition.directory_identity(retained.stat())], 12)
        self.assertEqual(sum(scans.values()), 34)
        self.assertEqual(sibling_changes, 7)  # Every complete private budget scan stays present.
        self.assertEqual(len(synced), 9)  # Six copied files and three metadata files.
        self.assertEqual(len(set(synced)), 9)
        self.assertEqual(observer.counters["fileSyncCount"], 9)
        self.assertGreater(observer.counters["ancestryCheckCount"], 0)
        self.assertEqual(observer.counters["sourceExpectedNodes"], 5)
        expected_bytes = sum(path.stat().st_size for path in
            (self.base / "nixpkgs/default.nix", self.base / "nixpkgs/lib/helper.nix",
             self.base / "nixpkgs/executable"))
        self.assertEqual(observer.counters["sourceExpectedBytes"], expected_bytes)

    def sync_fixture(self, count=5):
        parent = self.worker / "sync-fixture"
        parent.mkdir()
        for index in range(count):
            path = parent / str(index)
            path.write_bytes(b"owned modeled output\n")
            path.chmod(0o444)
        return parent

    def test_sync_completion_wakes_full_queue_before_next_admission_without_poll_sleep(self):
        parent = self.sync_fixture()
        tasks, order, synced = [], [], []
        def syncing(fd):
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
            synced.append(os.fstat(fd).st_ino)
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "fsync", side_effect=syncing), \
                acquisition.FileSyncOwner(lambda: order.append("tick"),
                                          lambda *args: order.append("allocation")) as owner:
            def admitting(task):
                if len(tasks) == 4:
                    self.assertIsNone(first.fd)
                    self.assertIsNone(first.parent)
                    order.append("fifth-admission")
                tasks.append(task)  # Hold real leases pending at the admission fence.
            with patch.object(owner.executor, "submit", side_effect=admitting):
                for index in range(4):
                    fd = os.open(str(index), os.O_RDONLY, dir_fd=selected.fd)
                    try:
                        owner.submit(fd, selected.fd, str(index), 0)
                    finally:
                        os.close(fd)
                first = owner.pending[0]
                original_wait, original_close = first.finished.wait, first.close
                def waking(timeout):
                    self.assertEqual(timeout, 0.01)
                    order.append("wait")
                    tasks[0]()  # Complete and signal the exact retained lease.
                    self.assertTrue(first.finished.is_set())
                    return original_wait(timeout)
                def closing():
                    order.append("close")
                    return original_close()
                fd = os.open("4", os.O_RDONLY, dir_fd=selected.fd)
                try:
                    with patch.object(first.finished, "wait", side_effect=waking) as waiting, \
                            patch.object(first, "close", side_effect=closing), \
                            patch.object(acquisition.time, "sleep", side_effect=AssertionError("no admission poll sleep")):
                        owner.submit(fd, selected.fd, "4", 0)
                        waiting.assert_called_once_with(0.01)
                finally:
                    os.close(fd)
                    for task in tasks:
                        task()
                self.assertEqual(len(owner.pending), 4)
                self.assertNotIn(first, owner.pending)
                self.assertLess(order.index("wait"), order.index("allocation"))
                self.assertLess(order.index("allocation"), order.index("close"))
                self.assertLess(order.index("close"), order.index("fifth-admission"))
                owner.drain()
        self.assertEqual(len(synced), 5)
        self.assertEqual(len(set(synced)), 5)
        self.assertEqual(len(owner.pending), 0)

    def test_sync_unfinished_event_wait_keeps_original_deadline_and_drains_owned_leases(self):
        parent = self.sync_fixture()
        tasks, leases, clock = [], [], [0.0]
        deadline = acquisition.SOURCE_SECONDS
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "fsync", return_value=None), \
                patch.object(acquisition.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, "verification-deadline"):
                with acquisition.FileSyncOwner(lambda: acquired.check_deadline(deadline), lambda *args: None) as owner:
                    with patch.object(owner.executor, "submit", side_effect=tasks.append) as admitting:
                        for index in range(4):
                            fd = os.open(str(index), os.O_RDONLY, dir_fd=selected.fd)
                            try:
                                owner.submit(fd, selected.fd, str(index), 0)
                            finally:
                                os.close(fd)
                        leases = list(owner.pending)
                        def expiring(timeout):
                            self.assertEqual(timeout, 0.01)
                            self.assertFalse(leases[0].finished.is_set())
                            clock[0] = deadline
                            return False
                        fd = os.open("4", os.O_RDONLY, dir_fd=selected.fd)
                        try:
                            with patch.object(leases[0].finished, "wait", side_effect=expiring) as waiting:
                                owner.submit(fd, selected.fd, "4", 0)
                        finally:
                            os.close(fd)
                            self.assertEqual(admitting.call_count, 4)
                            waiting.assert_called_once_with(0.01)
                            for task in tasks:
                                task()  # Join completed real leases through error cleanup.
            self.assertEqual(clock[0], deadline)
            self.assertTrue(all(lease.finished.is_set() and lease.fd is None
                                and lease.parent is None for lease in leases))
            self.assertEqual(len(owner.pending), 0)

    def test_sync_event_wait_observes_later_failure_before_fifth_admission(self):
        parent = self.sync_fixture()
        tasks, leases = [], []
        failing_inode = (parent / "1").stat().st_ino
        def syncing(fd):
            if os.fstat(fd).st_ino == failing_inode:
                raise OSError("modeled later flush refusal")
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "fsync", side_effect=syncing):
            with self.assertRaisesRegex(OSError, "later flush refusal"):
                with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                    with patch.object(owner.executor, "submit", side_effect=tasks.append) as admitting:
                        for index in range(4):
                            fd = os.open(str(index), os.O_RDONLY, dir_fd=selected.fd)
                            try:
                                owner.submit(fd, selected.fd, str(index), 0)
                            finally:
                                os.close(fd)
                        leases = list(owner.pending)
                        def failing(timeout):
                            self.assertEqual(timeout, 0.01)
                            tasks[1]()  # Oldest stays unfinished while a later lease fails.
                            self.assertFalse(leases[0].finished.is_set())
                            self.assertTrue(leases[1].finished.is_set())
                            return False
                        fd = os.open("4", os.O_RDONLY, dir_fd=selected.fd)
                        try:
                            with patch.object(leases[0].finished, "wait", side_effect=failing) as waiting:
                                owner.submit(fd, selected.fd, "4", 0)
                        finally:
                            os.close(fd)
                            self.assertEqual(admitting.call_count, 4)
                            waiting.assert_called_once_with(0.01)
                            for task in tasks:
                                task()
            self.assertTrue(all(lease.finished.is_set() and lease.fd is None
                                and lease.parent is None for lease in leases))
            self.assertEqual(len(owner.pending), 0)

    def test_sync_owner_bounds_total_pending_work_and_retains_fds_until_completion(self):
        parent = self.sync_fixture()
        gate = threading.Event()
        lock = threading.Lock()
        active = peak = calls = 0
        duplicated = []
        actual_dup = os.dup
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        def syncing(fd):
            nonlocal active, peak, calls
            with lock:
                active += 1
                calls += 1
                peak = max(peak, active)
                if active == 4:
                    gate.set()
            if not gate.wait(5):
                raise OSError("modeled bounded worker gate failed")
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
            with lock:
                active -= 1
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating), \
                patch.object(acquisition.os, "fsync", side_effect=syncing), \
                acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
            for index in range(5):
                fd = os.open(str(index), os.O_RDONLY, dir_fd=selected.fd)
                try:
                    owner.submit(fd, selected.fd, str(index), 0)
                    self.assertLessEqual(len(owner.pending), 4)
                finally:
                    os.close(fd)
            owner.drain()
        self.assertEqual(calls, 5)
        self.assertEqual(peak, 4)
        self.assertEqual(active, 0)
        for fd in set(duplicated):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_copy_has_one_writer_and_drains_every_file_sync_before_final_scan(self):
        paths = self.copy_fixture(8)
        main_thread = threading.get_ident()
        writing_threads, syncing_threads = set(), set()
        completed = set()
        actual_write, actual_fsync, actual_disk_check = os.write, os.fsync, acquisition.disk_check
        lock = threading.Lock()
        def writing(*args):
            writing_threads.add(threading.get_ident())
            return actual_write(*args)
        def syncing(fd):
            syncing_threads.add(threading.get_ident())
            result = actual_fsync(fd)
            with lock:
                completed.add(acquisition.directory_identity(os.fstat(fd)))
            return result
        def final_check(*args, **kwargs):
            self.assertEqual(len(completed), 8)
            return actual_disk_check(*args, **kwargs)
        with patch.object(acquisition, "FREE_FLOOR", 0), \
                patch.object(acquisition.os, "write", side_effect=writing), \
                patch.object(acquisition.os, "fsync", side_effect=syncing), \
                patch.object(acquisition, "disk_check", side_effect=final_check):
            self.copy_fixture_tree(paths, time.monotonic() + 30)
        self.assertEqual(writing_threads, {main_thread})
        self.assertTrue(syncing_threads)
        self.assertNotIn(main_thread, syncing_threads)
        self.assertLessEqual(len(syncing_threads), 4)

    def test_sync_error_stops_admission_while_oldest_worker_is_blocked(self):
        parent = self.sync_fixture(3)
        release, failed = threading.Event(), threading.Event()
        first = None
        def syncing(fd):
            if os.fstat(fd).st_ino == first:
                if not release.wait(5):
                    raise OSError("modeled blocked sync")
            else:
                failed.set()
                raise OSError("modeled first sync refusal")
        with acquisition.HeldDirectory(parent) as selected:
            first = (parent / "0").stat().st_ino
            with patch.object(acquisition.os, "fsync", side_effect=syncing), \
                    self.assertRaisesRegex(OSError, "first sync refusal"):
                with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                    try:
                        for index in (0, 1):
                            fd = os.open(str(index), os.O_RDONLY, dir_fd=selected.fd)
                            try:
                                owner.submit(fd, selected.fd, str(index), 0)
                            finally:
                                os.close(fd)
                        self.assertTrue(failed.wait(5))
                        # Wait until the worker result itself is observable.
                        for lease in owner.pending:
                            if lease is not owner.pending[0]:
                                self.assertTrue(lease.finished.wait(5))
                        with patch.object(owner.executor, "submit", wraps=owner.executor.submit) as admission:
                            fd = os.open("2", os.O_RDONLY, dir_fd=selected.fd)
                            try:
                                with self.assertRaisesRegex(OSError, "first sync refusal"):
                                    owner.submit(fd, selected.fd, "2", 0)
                                self.assertEqual(admission.call_count, 0)
                            finally:
                                os.close(fd)
                        owner.drain()
                    finally:
                        release.set()

    def test_sync_deadline_keeps_first_phase_and_drains_before_fd_close(self):
        parent = self.sync_fixture(1)
        started, release = threading.Event(), threading.Event()
        duplicated = []
        actual_dup = os.dup
        expire = False
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        def syncing(fd):
            started.set()
            if not release.wait(5):
                raise OSError("modeled worker wait failure")
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
            raise OSError("modeled later cleanup sync refusal")
        def tick():
            if expire:
                release.set()
                acquired.check_deadline(time.monotonic() - 1)
        observer = acquisition.Progress(io.StringIO())
        token = acquisition.PROGRESS.set(observer)
        try:
            with acquisition.HeldDirectory(parent) as selected, \
                    patch.object(acquisition.os, "dup", side_effect=duplicating), \
                    patch.object(acquisition.os, "fsync", side_effect=syncing), \
                    self.assertRaisesRegex(ValueError, "verification-deadline"):
                with acquisition.phase("copy", source="nixpkgs", deadline=time.monotonic() + 30):
                    with acquisition.FileSyncOwner(tick, lambda *args: None) as owner:
                        fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                        try:
                            owner.submit(fd, selected.fd, "0", 0)
                        finally:
                            os.close(fd)
                        self.assertTrue(started.wait(5))
                        expire = True
                        owner.drain()
        finally:
            release.set()
            acquisition.PROGRESS.reset(token)
        self.assertEqual(observer.failure["phase"], "copy")
        self.assertEqual(observer.failure["source"], "nixpkgs")
        self.assertEqual(observer.failure["category"], "acquired-verification-deadline")
        self.assertEqual(observer.cleanup_category, "acquisition-filesystem-refusal")
        self.assertEqual(observer.counters["fileSyncCount"], 1)
        for fd in set(duplicated):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_sync_retained_leaf_replacement_refuses_before_copy_proof(self):
        parent = self.sync_fixture(1)
        gate = threading.Event()
        def syncing(fd):
            if not gate.wait(5):
                raise OSError("modeled gate timeout")
            self.assertEqual(os.read(fd, 4096), b"owned modeled output\n")
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "fsync", side_effect=syncing), \
                self.assertRaisesRegex(ValueError, "copy-file-replaced"):
            with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                try:
                    owner.submit(fd, selected.fd, "0", 0)
                finally:
                    os.close(fd)
                (parent / "0").unlink()
                (parent / "0").write_bytes(b"foreign replacement\n")
                gate.set()
                owner.drain()
        self.assertEqual((parent / "0").read_bytes(), b"foreign replacement\n")

    def test_sync_duplicate_failure_closes_only_new_owned_fd(self):
        parent = self.sync_fixture(1)
        actual_dup = os.dup
        duplicated = []
        def duplicating(fd):
            if duplicated:
                raise OSError("modeled duplicate refusal")
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating):
            fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
            try:
                with self.assertRaisesRegex(OSError, "duplicate refusal"):
                    with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                        owner.submit(fd, selected.fd, "0", 0)
                self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
                selected.check()
            finally:
                os.close(fd)
        with self.assertRaises(OSError):
            os.fstat(duplicated[0])

    def test_sync_partial_submit_failure_joins_worker_before_duplicates_can_be_reused(self):
        parent = self.sync_fixture(1)
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        duplicated = []
        actual_dup = os.dup
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        def syncing(fd):
            started.set()
            if not release.wait(5):
                raise OSError("modeled active flush timeout")
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
            finished.set()
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating), \
                patch.object(acquisition.os, "fsync", side_effect=syncing), \
                self.assertRaisesRegex(OSError, "ambiguous submission"):
            with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                submit, cleanup = owner.executor.submit, owner.cleanup_lease
                def ambiguous(*args, **kwargs):
                    submit(*args, **kwargs)
                    self.assertTrue(started.wait(5))
                    raise OSError("modeled ambiguous submission")
                def joining(lease):
                    release.set()
                    return cleanup(lease)
                with patch.object(owner.executor, "submit", side_effect=ambiguous), \
                        patch.object(owner, "cleanup_lease", side_effect=joining):
                    fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                    try:
                        owner.submit(fd, selected.fd, "0", 0)
                    finally:
                        os.close(fd)
        self.assertTrue(finished.is_set())
        for fd in set(duplicated):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_sync_registration_failure_precedes_worker_admission(self):
        parent = self.sync_fixture(1)
        duplicated = []
        actual_dup = os.dup
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        class RefusingPending(acquisition.deque):
            def append(self, item):
                super().append(item)  # Registration may retain before raising.
                raise MemoryError("modeled registration refusal")
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating), \
                patch.object(acquisition.os, "fsync", side_effect=AssertionError("no worker admission")), \
                self.assertRaisesRegex(MemoryError, "registration refusal"):
            with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                owner.pending = RefusingPending()
                with patch.object(owner.executor, "submit", wraps=owner.executor.submit) as submitting:
                    fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                    try:
                        owner.submit(fd, selected.fd, "0", 0)
                    finally:
                        os.close(fd)
                        self.assertEqual(submitting.call_count, 0)
        self.assertEqual(len(owner.pending), 0)
        for fd in set(duplicated):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_sync_cancelled_ambiguous_callable_cannot_use_reused_fd(self):
        parent = self.sync_fixture(1)
        retained, duplicated = [], []
        actual_dup = os.dup
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        def queued(callable):
            retained.append(callable)
            raise OSError("modeled queued submission refusal")
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating):
            with self.assertRaisesRegex(OSError, "queued submission refusal"):
                with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                    with patch.object(owner.executor, "submit", side_effect=queued):
                        fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                        try:
                            owner.submit(fd, selected.fd, "0", 0)
                        finally:
                            os.close(fd)
            self.assertEqual(len(retained), 1)
            replacement = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
            selected_fd = duplicated[0]
            if replacement != selected_fd:
                os.dup2(replacement, selected_fd)
                os.close(replacement)
            try:
                with patch.object(acquisition.os, "fsync", side_effect=AssertionError("no reused FD use")):
                    retained[0]()
                self.assertTrue(stat.S_ISREG(os.fstat(selected_fd).st_mode))
            finally:
                os.close(selected_fd)
            selected.check()

    def test_sync_permanent_shutdown_refusal_is_finite_after_safe_lease_release(self):
        parent = self.sync_fixture(1)
        duplicated = []
        actual_dup = os.dup
        def duplicating(fd):
            result = actual_dup(fd)
            duplicated.append(result)
            return result
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "dup", side_effect=duplicating):
            owner = acquisition.FileSyncOwner(lambda: None, lambda *args: None)
            actual_shutdown = owner.executor.shutdown
            try:
                with patch.object(owner.executor, "shutdown", side_effect=RuntimeError("modeled permanent refusal")) as shutting, \
                        self.assertRaisesRegex(RuntimeError, "permanent refusal"):
                    with owner:
                        fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                        try:
                            owner.submit(fd, selected.fd, "0", 0)
                        finally:
                            os.close(fd)
                        owner.drain()
                self.assertEqual(shutting.call_count, 1)
                self.assertEqual(len(owner.pending), 0)
                for fd in set(duplicated):
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                selected.check()
            finally:
                actual_shutdown(wait=True, cancel_futures=True)

    def test_sync_owner_cannot_report_clean_exit_with_unflushed_lease(self):
        parent = self.sync_fixture(1)
        queued = []
        with acquisition.HeldDirectory(parent) as selected, \
                patch.object(acquisition.os, "fsync", side_effect=AssertionError("cancelled lease cannot flush")), \
                self.assertRaisesRegex(ValueError, "copy-sync-owner"):
            with acquisition.FileSyncOwner(lambda: None, lambda *args: None) as owner:
                with patch.object(owner.executor, "submit", side_effect=lambda callable: queued.append(callable)):
                    fd = os.open("0", os.O_RDONLY, dir_fd=selected.fd)
                    try:
                        owner.submit(fd, selected.fd, "0", 0)
                    finally:
                        os.close(fd)
        self.assertEqual(len(owner.pending), 0)
        self.assertEqual(len(queued), 1)
        with patch.object(acquisition.os, "fsync", side_effect=AssertionError("cancelled lease cannot reuse FD")):
            queued[0]()

    def test_main_redacts_pool_runtime_and_allocation_failures_in_original_phase(self):
        for failure in (RuntimeError("private /source/worker token=hidden"),
                        MemoryError("private /source/lease token=hidden")):
            output, diagnostics = io.StringIO(), io.StringIO()
            def failing_run(args):
                with acquisition.phase("copy", source="nixpkgs"):
                    raise failure
            with self.subTest(kind=type(failure).__name__), \
                    patch.object(acquisition, "run", side_effect=failing_run), \
                    redirect_stdout(output), redirect_stderr(diagnostics):
                self.assertEqual(acquisition.main(["--nix", "n", "--ca-file", "c", "--lock", "l"]), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["context"]["phase"], "copy")
            self.assertEqual(result["category"], "acquisition-bounded-input-or-custody-failed")
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertLessEqual(len(output.getvalue().encode()), 4096)
            self.assertNotIn("/source", output.getvalue() + diagnostics.getvalue())
            self.assertNotIn("token", output.getvalue() + diagnostics.getvalue())

    def test_quiescent_usage_keeps_complete_totals_with_directory_bound_ancestry_walks(self):
        parent = self.worker / "many"
        parent.mkdir()
        for index in range(128):
            (parent / str(index)).write_bytes(b"bounded modeled retained bytes")
        (self.worker / "inert").symlink_to("/unavailable-modeled-source-target")
        with acquisition.HeldDirectory(self.worker) as root:
            with patch.object(root, "check", wraps=root.check) as checks:
                live = acquisition.usage(root, time.monotonic() + 30, details=True)
            live_count = checks.call_count
            with patch.object(root, "check", wraps=root.check) as checks:
                quiet = acquisition.usage(root, time.monotonic() + 30, details=True, quiescent=True)
            self.assertEqual(quiet, live)
            self.assertEqual(quiet["nodes"], 131)
            self.assertGreater(live_count, 128)
            self.assertLessEqual(checks.call_count, 6)  # Two directory boundaries plus outer fences.

    def test_quiescent_usage_stays_on_held_descendants_after_root_path_substitution(self):
        (self.worker / "nested").mkdir()
        (self.worker / "nested/original").write_bytes(b"owned")
        outside = self.base / "outside"
        (outside / "nested").mkdir(parents=True)
        (outside / "nested/sentinel").write_bytes(b"foreign")
        worker_inode = self.worker.stat().st_ino
        outside_inodes = {outside.stat().st_ino, (outside / "nested").stat().st_ino}
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            inode = os.fstat(fd).st_ino
            self.assertNotIn(inode, outside_inodes)
            if inode == worker_inode and not changed:
                changed = True
                self.worker.rename(self.base / "retired-worker")
                self.worker.symlink_to(outside, target_is_directory=True)
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                self.assertRaisesRegex(ValueError, "held-directory-replaced"):
            acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
        self.assertTrue(changed)
        self.assertEqual((outside / "nested/sentinel").read_bytes(), b"foreign")

    def test_quiescent_usage_detects_root_rename_restore_with_unchanged_descendants(self):
        (self.worker / "original").write_bytes(b"owned source")
        before = acquired.snapshot((self.worker / "original").stat())
        worker_inode = self.worker.stat().st_ino
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            if os.fstat(fd).st_ino == worker_inode and not changed:
                changed = True
                self.worker.rename(self.base / "saved-worker")
                self.worker.mkdir()
                (self.worker / "foreign").write_bytes(b"alternate namespace")
                (self.worker / "foreign").unlink()
                self.worker.rmdir()
                (self.base / "saved-worker").rename(self.worker)
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                self.assertRaisesRegex(ValueError, "private-ancestor-changed"):
            acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
        self.assertTrue(changed)
        self.assertEqual(acquired.snapshot((self.worker / "original").stat()), before)

    def test_quiescent_usage_allows_unrelated_shared_ancestor_sibling_activity(self):
        (self.worker / "original").write_bytes(b"owned source")
        before = acquired.snapshot(self.worker.stat())
        ancestor_before = acquired.snapshot(self.base.stat())
        expected = acquisition.usage(self.worker, time.monotonic() + 10, details=True)
        worker_inode = self.worker.stat().st_ino
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            if os.fstat(fd).st_ino == worker_inode and not changed:
                changed = True
                sibling = self.base / "unrelated-sibling"
                sibling.mkdir()
                (sibling / "unrelated-bytes").write_bytes(b"shared parent activity")
                (sibling / "unrelated-bytes").unlink()
                sibling.rmdir()
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning):
            actual = acquisition.usage(self.worker, time.monotonic() + 10, details=True, quiescent=True)
        self.assertTrue(changed)
        self.assertEqual(actual, expected)
        self.assertEqual(acquired.snapshot(self.worker.stat()), before)
        self.assertNotEqual(acquired.snapshot(self.base.stat()), ancestor_before)

    def test_quiescent_usage_retains_external_named_ancestor_replacement_refusal(self):
        (self.worker / "original").write_bytes(b"owned source")
        worker_inode = self.worker.stat().st_ino
        saved = self.base.parent / (self.base.name + "-saved")
        actual_scandir = os.scandir
        changed = False
        foreign_inode = None
        def scanning(fd):
            nonlocal changed, foreign_inode
            inode = os.fstat(fd).st_ino
            self.assertNotEqual(inode, foreign_inode)
            if inode == worker_inode and not changed:
                self.base.rename(saved)
                changed = True
                self.base.mkdir()
                self.worker.mkdir()
                (self.worker / "foreign").write_bytes(b"foreign namespace")
                foreign_inode = self.worker.stat().st_ino
            return actual_scandir(fd)
        try:
            with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                    self.assertRaisesRegex(ValueError, "held-directory-replaced"):
                acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
            self.assertTrue(changed)
            self.assertEqual((self.worker / "foreign").read_bytes(), b"foreign namespace")
            self.assertEqual((saved / "worker/original").read_bytes(), b"owned source")
        finally:
            if changed:
                (self.worker / "foreign").unlink()
                self.worker.rmdir()
                self.base.rmdir()
                saved.rename(self.base)

    def test_quiescent_usage_retains_current_shared_ancestor_permission_refusal(self):
        (self.worker / "original").write_bytes(b"owned source")
        worker_inode = self.worker.stat().st_ino
        original_mode = stat.S_IMODE(self.base.stat().st_mode)
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            if os.fstat(fd).st_ino == worker_inode and not changed:
                changed = True
                self.base.chmod(0o720)
            return actual_scandir(fd)
        try:
            with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                    self.assertRaisesRegex(ValueError, "held-directory-custody"):
                acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
            self.assertTrue(changed)
        finally:
            self.base.chmod(original_mode)

    def test_quiescent_usage_detects_restored_mode_state(self):
        (self.worker / "original").write_bytes(b"owned source")
        worker_inode = self.worker.stat().st_ino
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            if os.fstat(fd).st_ino == worker_inode and not changed:
                changed = True
                os.fchmod(fd, 0o720)
                os.fchmod(fd, 0o700)
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                self.assertRaisesRegex(ValueError, "private-ancestor-changed"):
            acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
        self.assertTrue(changed)
        self.assertEqual(stat.S_IMODE(self.worker.stat().st_mode), 0o700)

    def test_quiescent_usage_preserves_every_entry_deadline_and_budget_refusal(self):
        (self.worker / "original").write_bytes(b"owned source")
        future = time.monotonic() + 30
        with patch.object(acquisition, "MAX_PRIVATE_NODES", 1), \
                self.assertRaisesRegex(ValueError, "private-inventory-bound"):
            acquisition.usage(self.worker, future, quiescent=True)
        with patch.object(acquisition, "DISK_BUDGET", 0), \
                self.assertRaisesRegex(ValueError, "private-disk-budget"):
            acquisition.usage(self.worker, future, quiescent=True)
        actual_scandir = os.scandir
        expired = False
        def scanning(fd):
            nonlocal expired
            expired = True
            return actual_scandir(fd)
        actual_deadline = acquired.check_deadline
        def checking(deadline):
            return actual_deadline(time.monotonic() - 1 if expired else deadline)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                patch.object(acquired, "check_deadline", side_effect=checking), \
                self.assertRaisesRegex(ValueError, "verification-deadline"):
            acquisition.usage(self.worker, future, quiescent=True)
        self.assertTrue(expired)

    def test_quiescent_usage_refuses_descendant_directory_substitution(self):
        child = self.worker / "nested"
        (child / "sub").mkdir(parents=True)
        outside = self.base / "outside"
        (outside / "sub").mkdir(parents=True)
        outside_inodes = {outside.stat().st_ino, (outside / "sub").stat().st_ino}
        child_inode = child.stat().st_ino
        actual_scandir = os.scandir
        changed = False
        def scanning(fd):
            nonlocal changed
            inode = os.fstat(fd).st_ino
            self.assertNotIn(inode, outside_inodes)
            if inode == child_inode and not changed:
                changed = True
                child.rename(self.base / "retired-child")
                child.symlink_to(outside, target_is_directory=True)
            return actual_scandir(fd)
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                self.assertRaisesRegex(ValueError, "private-directory-replaced"):
            acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
        self.assertTrue(changed)

    def test_quiescent_usage_refuses_closed_reinitialized_anchor_lifetime(self):
        (self.worker / "original").write_bytes(b"owned source")
        worker_inode = self.worker.stat().st_ino
        actual_scandir = os.scandir
        with acquisition.HeldDirectory(self.worker) as root:
            changed = False
            def scanning(fd):
                nonlocal changed
                if os.fstat(fd).st_ino == worker_inode and not changed:
                    changed = True
                    root.close()
                    root.__init__(self.worker)
                    self.assertEqual(root.fd, fd)  # Exact number+inode reuse cannot replace lifetime.
                return actual_scandir(fd)
            with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                    self.assertRaisesRegex(ValueError, "private-ancestor-changed"):
                acquisition.usage(root, time.monotonic() + 10, quiescent=True)
            self.assertTrue(changed)
            root.check()

    def test_quiescent_usage_retains_current_root_owner_predicate(self):
        (self.worker / "original").write_bytes(b"owned source")
        worker_inode = self.worker.stat().st_ino
        actual_fstat, actual_scandir = os.fstat, os.scandir
        tampered = False
        def scanning(fd):
            nonlocal tampered
            if actual_fstat(fd).st_ino == worker_inode:
                tampered = True
            return actual_scandir(fd)
        def witnessing(fd):
            info = actual_fstat(fd)
            if tampered and info.st_ino == worker_inode:
                fields = {name: getattr(info, name) for name in (
                    "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
                    "st_mtime_ns", "st_ctime_ns", "st_blocks")}
                fields["st_uid"] = os.getuid() + 1
                return SimpleNamespace(**fields)
            return info
        with patch.object(acquisition.os, "scandir", side_effect=scanning), \
                patch.object(acquisition.os, "fstat", side_effect=witnessing), \
                self.assertRaisesRegex(ValueError, "held-directory-custody"):
            acquisition.usage(self.worker, time.monotonic() + 10, quiescent=True)
        self.assertTrue(tampered)


if __name__ == "__main__":
    unittest.main()
