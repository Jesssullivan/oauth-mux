"""Actual declared aliases/body/NAR/restore/readback; external receipts are models.

Nix children and their physical /nix/store model namespace are injected. These
tests establish neither a successful real producer nor a native build seed.
"""
from contextlib import ExitStack
import copy
import errno
import os
import re
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import nar_descriptor as nar
import native_flake_seed_plan_inputs as inputs
import native_flake_seed_plan_qualification as carrier
import native_flake_seed_plan_test as models
import nix_private_store_seed as seed
import verify_declared_nars as declared

EPOCH = "00000000-0000-4000-8000-000000000001"


class JoinedFixture:
    def __init__(self, directory):
        self.root = Path(directory)
        self.stack = ExitStack()
        self.model_root = self.root/"model"
        self.model_root.mkdir()
        self.model = self.stack.enter_context(models.PlanFixture(self.model_root))
        self.coordination = self.root/"coordination"
        self.epoch = self.coordination/EPOCH
        self.epoch.mkdir(parents=True)
        self.stack.enter_context(patch.object(inputs, "COORDINATORS", (str(self.coordination),)))
        self.output_base = self.epoch/"output-base"
        self.output = self.output_base/"execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_schedule_qualification/test.outputs"
        self.output.mkdir(parents=True)
        self.generated = self.output/"generated"
        self.generated.mkdir()
        self.wrapper = b"{ projectSource, nixpkgsSource, utilsSource, systemsSource }: {}"
        runtime = self.model.model.runtime
        self.runtime_metadata = {"native": runtime.raw_native, "paths": runtime.raw_paths,
            "registration": runtime.raw_registration, "inventory": inputs.encode({"files": runtime.value["files"]})}
        self.model.body["seed_file_inventory_sha256"] = seed.sha(self.runtime_metadata["inventory"])
        self.model.body["guard_epoch"] = EPOCH
        self.body_raw = inputs.encode(self.model.body)
        self.project_sources = {}
        project = self.root/"project"
        project.mkdir()
        for name, content in self.model.model.project.items():
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            self.project_sources[name] = str(path)
        for logical, item in self.model.body["generated"].items():
            if "artifact_root" in item:
                models.plan.schedule.copy_tree(item["descriptor"], self.output/item["artifact_root"],
                    self.model.opener, float(time.monotonic()+60))
                for node in item["descriptor"]["nodes"]:
                    if node["type"] == "regular":
                        physical = self.output/item["artifact_root"]
                        os.chmod(physical/node["path"] if node["path"] else physical,0o555)
        (self.output/"native-flake-obligations.json").write_bytes(self.body_raw)
        os.chmod(self.output/"native-flake-obligations.json",0o555)
        self.receipt = {"id": EPOCH, "artifact_epoch": EPOCH,
            "unit": "omux-execution-"+EPOCH+".service", "profile": "standard", "manager": "system",
            "exit": 0, "workload_exit": 0, "controller_failure": None, "descendants_empty": True,
            "cleanup": {"state": "empty"}, "source_dirty": "false", "source_commit": "a"*40,
            "graph_sha256": "b"*64, "verb": "test", "targets": [inputs.TARGET],
            "epoch_start_ns": 1, "output_base": str(self.output_base),
            "observed_properties": {**inputs.RESOURCE_PROPERTIES, "RuntimeMaxUSec": "20min"}}
        self.raw = {"obligations": self.body_raw, "log": b"public modeled successful evaluation\n",
            "xml": b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>\n'}
        evidence_directory = self.epoch/"test-evidence"
        evidence_directory.mkdir()
        self.pins = {}
        for name in ("log", "xml"):
            path = evidence_directory/(seed.sha(self.raw[name])+".evidence")
            path.write_bytes(self.raw[name])
            self.pins[name] = self.file_pin(path)
        evidence = {"schema": 1, "bazel_exit": 0, "epoch_start_ns": 1,
            "targets": [inputs.TARGET], "results": [{"target": inputs.TARGET, "state": "observed",
                "files": [{"source": member, "state": "copied", "file": Path(self.pins[name]["path"]).name,
                    "sha256": self.pins[name]["sha256"], "bytes": self.pins[name]["bytes"]}
                    for name, member in (("log", "test.log"), ("xml", "test.xml"))]}]}
        self.raw["evidence"] = inputs.encode(evidence)
        evidence_file = self.epoch/"test-evidence.json"
        evidence_file.write_bytes(self.raw["evidence"])
        self.receipt["test_evidence"] = {"state": "preserved", "sha256": seed.sha(self.raw["evidence"])}
        self.raw["receipt"] = inputs.encode(self.receipt)
        receipt_file = self.epoch/"receipt.json"
        receipt_file.write_bytes(self.raw["receipt"])
        self.selected = {"schema_version": 1, "kind": inputs.SELECTION_KIND,
            "producer": {"receipt": self.file_pin(receipt_file), "evidence": self.file_pin(evidence_file),
                **self.pins, "source_commit": "a"*40, "graph_sha256": "b"*64},
            "obligations": self.file_pin(self.output/"native-flake-obligations.json"), "candidates": None}
        self.real_open, self.real_describe = nar.open_regular, nar.describe
        self.physical = {**runtime.physical, **self.model.physical}
        for item in self.model.model.bundle["sources"]:
            logical = self.model.body["target"]["sourcePaths"][item["role"]]
            self.physical[item["descriptor"]["root"]] = self.model.physical[logical]
        self.stack.enter_context(patch.object(nar, "open_regular", side_effect=self.redirect))
        # The declared opener binds this symbol at import time; redirect only
        # its synthetic /nix/store namespace, retaining actual FD/alias checks.
        self.stack.enter_context(patch.object(declared, "open_regular", side_effect=self.redirect))
        self.stack.enter_context(patch.object(nar, "describe", side_effect=self.describe))
        self.stack.enter_context(patch.object(models.missing.proof, "run", side_effect=self.model.runner))
        self.repository = self.root/"repository"
        self.repository.mkdir()
        self.bundle_path = self.repository/"inputs.json"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()

    def file_pin(self, path):
        raw = Path(path).read_bytes()
        return {"path": str(path), "sha256": seed.sha(raw), "bytes": len(raw)}

    def redirect(self, root, relative):
        if str(root).startswith("/nix/store/"):
            parts = Path(root).parts
            logical = str(Path(*parts[:4]))
            require = seed.require
            require(logical in self.physical)
            name = "/".join(parts[4:]+Path(relative).parts) if relative else "/".join(parts[4:])
            return self.real_open(str(self.physical[logical]), name)
        return self.real_open(root, relative)

    def describe(self, path):
        if str(path) in self.physical:
            value = self.real_describe(self.physical[str(path)])
            value["root"] = str(path)
            return value
        return self.real_describe(path)

    def generate(self):
        self.selected_raw = inputs.encode(self.selected)
        self.report = inputs.generate(self.selected_raw, seed.sha(self.selected_raw),
            self.model.runtime_raw, self.model.model.descriptors, self.project_sources,
            self.repository, float(time.monotonic()+60))
        (self.repository/"regular").mkdir()
        for row in self.report["regularInputs"]:
            (self.repository/row["alias"]).symlink_to(row["source"])
        self.bundle_raw = self.bundle_path.read_bytes()
        self.model.selected = {}

    def qualify(self, runner=None, deadline=None):
        return carrier.qualify(self.selected_raw, seed.sha(self.selected_raw), self.bundle_raw,
            self.report["mapping_sha256"], self.bundle_path, self.model.runtime_raw, self.runtime_metadata,
            self.model.model.descriptors, self.model.model.descriptor_path,
            self.model.model.project, self.wrapper, self.model.model.root,
            float(time.monotonic()+60) if deadline is None else deadline,
            implementation=self.model.body["implementation_sha256"],
            runner=self.model.runner if runner is None else runner)


class CarrierModels(unittest.TestCase):
    def test_watch_mapper_covers_every_leaf_and_excludes_symlink_subtrees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"safe").mkdir()
            (root/"unsafe").mkdir()
            (root/"safe/a").write_bytes(b"synthetic")
            (root/"safe/b").write_bytes(b"synthetic")
            (root/"unsafe/c").write_bytes(b"synthetic")
            (root/"unsafe/link").symlink_to("/synthetic-unopened-outside")
            descriptor = nar.describe(root)
            mapped = {node["path"]: {"source": str(root/node["path"])}
                      for node in descriptor["nodes"] if node["type"] == "regular"}
            # Only custody is synthetic; traversal, no-follow checks and tree
            # selection operate on actual disposable files/descriptors.
            with patch.object(seed, "STORE", re.escape(str(root))), \
                    patch.object(inputs, "watch_custody", return_value=True), \
                    patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                selected = inputs.watch_plan(descriptor, str(root), mapped, 100.0)
            self.assertEqual(selected, [{"kind": "tree", "path": str(root/"safe")},
                                        {"kind": "file", "path": str(root/"unsafe/c")}])
            for item in mapped.values():
                self.assertEqual(sum(item["source"] == row["path"] if row["kind"] == "file"
                                     else item["source"].startswith(row["path"]+"/") for row in selected), 1)

    def test_watch_mapper_extra_link_or_mutable_root_falls_back_to_exact_files(self):
        for fault in ("extra-link", "mutable", "retained"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/"a").write_bytes(b"synthetic")
                descriptor = nar.describe(root)
                mapped = {"a": {"source": str(root/"a")}}
                if fault == "extra-link":
                    (root/"inserted").symlink_to("/synthetic-unopened-outside")
                with patch.object(seed, "STORE", re.escape(str(root)) if fault != "retained" else r"/nix/store/never"), \
                        patch.object(inputs, "watch_custody", return_value=fault != "mutable"), \
                        patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                    selected = inputs.watch_plan(descriptor, str(root), mapped, 100.0)
                self.assertEqual(selected, [{"kind": "file", "path": str(root/"a")}])

    def test_watch_mapper_refuses_missing_or_misbound_leaf_and_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"a").write_bytes(b"synthetic")
            descriptor = nar.describe(root)
            with patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                with self.assertRaises(ValueError):
                    inputs.watch_plan(descriptor, str(root), {}, 100.0)
            with patch.object(seed, "STORE", re.escape(str(root))), \
                    patch.object(inputs, "watch_custody", return_value=True), \
                    patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                with self.assertRaises(ValueError):
                    inputs.watch_plan(descriptor, str(root), {"a": {"source": str(root/"other")}}, 100.0)
            with patch.object(seed, "STORE", re.escape(str(root))), \
                    patch.object(inputs.proof.time, "monotonic", return_value=100.0):
                with self.assertRaises(ValueError):
                    inputs.watch_plan(descriptor, str(root), {"a": {"source": str(root/"a")}}, 100.0)

    def test_watch_mapper_replaced_directory_is_not_traversed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/"selected"
            root.mkdir()
            (root/"child").mkdir()
            (root/"child/a").write_bytes(b"synthetic")
            descriptor = nar.describe(root)
            moved = Path(directory)/"moved"
            (root/"child").rename(moved)
            (root/"child").symlink_to(moved, target_is_directory=True)
            with patch.object(seed, "STORE", re.escape(str(root))), \
                    patch.object(inputs, "watch_custody", return_value=True), \
                    patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                selected = inputs.watch_plan(descriptor, str(root),
                    {"child/a": {"source": str(root/"child/a")}}, 100.0)
            self.assertEqual(selected, [{"kind": "file", "path": str(root/"child/a")}])

    def test_batch_materializes_exact_aliases_without_changing_source_or_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/"public-input"
            source.write_bytes(b"synthetic-public-byte-proof")
            source.chmod(0o444)
            before = inputs.witness(source.stat())
            repository = root/"repository"
            repository.mkdir()
            regular = [{"alias": "regular/"+str(index).zfill(8), "source": str(source)}
                       for index in range(64)]
            with patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                inputs.materialize_regular(repository, regular, 100.0)
            self.assertEqual(sorted(path.name for path in (repository/"regular").iterdir()),
                             [str(index).zfill(8) for index in range(64)])
            for item in regular:
                alias = repository/item["alias"]
                self.assertTrue(alias.is_symlink())
                self.assertEqual(os.readlink(alias), str(source))
                self.assertEqual(alias.read_bytes(), b"synthetic-public-byte-proof")
            self.assertEqual(inputs.witness(source.stat()), before)

    def test_batch_refuses_noncontiguous_or_redirected_input_without_aliases(self):
        for fault in ("alias", "source-link"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root/"public-input"
                source.write_bytes(b"synthetic-public")
                selected = source
                if fault == "source-link":
                    selected = root/"redirected"
                    selected.symlink_to(source)
                regular = [{"alias": "regular/00000001" if fault == "alias" else "regular/00000000",
                            "source": str(selected)}]
                repository = root/"repository"
                repository.mkdir()
                with patch.object(inputs.proof.time, "monotonic", return_value=0.0):
                    with self.assertRaises(ValueError):
                        inputs.materialize_regular(repository, regular, 100.0)
                self.assertEqual(list(repository.iterdir()), [])

    def test_batch_expiry_or_source_replacement_preserves_primary_and_cleans_owned_aliases(self):
        for fault in ("deadline", "source-replaced", "link-failure"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root/"public-input"
                source.write_bytes(b"synthetic-public")
                repository = root/"repository"
                repository.mkdir()
                sentinel = repository/"prior"
                sentinel.write_bytes(b"retain")
                regular = [{"alias": "regular/"+str(index).zfill(8), "source": str(source)}
                           for index in range(2)]
                now = [0.0]
                real_symlink = os.symlink
                primary = OSError("synthetic-link-failure")
                def symlink(*args, **kwargs):
                    if fault == "link-failure" and args[1] == "00000001":
                        raise primary
                    real_symlink(*args, **kwargs)
                    if fault == "deadline":
                        now[0] = 100.0
                    elif fault == "source-replaced":
                        replacement = root/"replacement"
                        replacement.write_bytes(b"synthetic-public")
                        replacement.replace(source)
                with patch.object(inputs.proof.time, "monotonic", side_effect=lambda: now[0]), \
                        patch.object(inputs.os, "symlink", side_effect=symlink):
                    with self.assertRaises(OSError if fault == "link-failure" else ValueError) as caught:
                        inputs.materialize_regular(repository, regular, 100.0)
                if fault == "link-failure":
                    self.assertIs(caught.exception, primary)
                self.assertEqual(list(repository.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"retain")

    def test_valid_producer_identity_is_a_boolean_predicate_and_keeps_all_joined_pins(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            self.assertIs(inputs.selection(fixture.selected), fixture.selected)
            self.assertEqual(inputs.producer_success(fixture.selected, fixture.raw), fixture.receipt)
            self.assertEqual(fixture.selected["producer"]["source_commit"], fixture.receipt["source_commit"])
            self.assertEqual(fixture.selected["producer"]["graph_sha256"], fixture.receipt["graph_sha256"])
            self.assertEqual(fixture.selected["producer"]["receipt"],
                fixture.file_pin(fixture.epoch/"receipt.json"))
            self.assertEqual(fixture.selected["obligations"],
                fixture.file_pin(fixture.output/"native-flake-obligations.json"))
            self.assertEqual(fixture.raw["obligations"], inputs.encode(fixture.model.body))
            for field, value in (("source_commit", "a"*39), ("source_commit", "g"*40),
                    ("source_commit", True), ("graph_sha256", "b"*63),
                    ("graph_sha256", "g"*64), ("graph_sha256", True)):
                selected = copy.deepcopy(fixture.selected)
                selected["producer"][field] = value
                with self.subTest(field=field, value_type=type(value).__name__), \
                        self.assertRaises(ValueError):
                    inputs.selection(selected)
            self.assertEqual(fixture.model.calls, [])

    def test_valid_candidate_path_is_boolean_without_reading_or_promoting_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            selected = copy.deepcopy(fixture.selected)
            root = "/nix/store/"+"b"*32+"-modeled-candidate-metadata"
            selected["candidates"] = {role: {"path": root+"/"+leaf,
                "sha256": "1"*64, "bytes": 1}
                for role, leaf in (("registration", "registration"), ("paths", "store-paths"))}
            with patch.object(inputs, "selected_bytes", side_effect=AssertionError("candidate byte IO")):
                self.assertIs(inputs.selection(selected), selected)
                for role in ("registration", "paths"):
                    invalid = copy.deepcopy(selected)
                    invalid["candidates"][role]["path"] += "-unselected"
                    with self.subTest(role=role), self.assertRaises(ValueError):
                        inputs.selection(invalid)
            self.assertEqual(fixture.model.calls, [])

    def test_many_leaf_opens_reuse_admitted_descriptor_but_keep_actual_fd_checks(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
            opener = inputs.bundle_opener(bundle, fixture.bundle_path)
            with patch.object(inputs.nar, "validate_descriptor", side_effect=AssertionError("full descriptor revalidated per leaf")):
                for _ in range(100):
                    with opener(models.SCRIPT, "") as stream:
                        self.assertEqual(stream.read(), fixture.model.physical[models.SCRIPT].read_bytes())
            os.chmod(bundle["roots"][models.SCRIPT]["regularInputs"][""]["source"], 0o444)
            with self.assertRaises(ValueError):
                opener(models.SCRIPT, "")

    def test_restore_child_refusals_preserve_primary_identity_and_real_owned_cleanup(self):
        cases = (("--load-db", "registration-load"),
            ("--dump-db", "registration-readback"),
            ("derivation", "derivation-graph"), ("--dry-run", "missing-query"))
        for token, operation in cases:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
                fixture.generate()
                before = {name: path.read_bytes() for name, path in fixture.physical.items() if path.is_file()}
                refused = ValueError("private untrusted diagnostic bait")
                deadlines = []
                def runner(*args, **kwargs):
                    deadlines.append(args[3])
                    if token in args[0]:
                        raise refused
                    return fixture.model.runner(*args, **kwargs)
                with patch.object(models.missing.proof, "run", side_effect=runner):
                    with self.assertRaises(ValueError) as caught:
                        fixture.qualify(runner=runner)
                self.assertIs(caught.exception, refused)
                self.assertEqual(refused.args, ("private untrusted diagnostic bait",))
                self.assertEqual(carrier.PHASE, "fresh-private-missing-plan")
                self.assertEqual(carrier.plan.restore_failure(refused), operation)
                self.assertEqual(len(set(deadlines)), 1)
                self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])
                self.assertEqual({name: fixture.physical[name].read_bytes() for name in before}, before)

    def test_restore_original_byte_refusal_stays_before_private_creation_and_children(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            refused = OSError("private original-byte bait")
            with patch.object(carrier.plan, "object_hash", side_effect=refused):
                with self.assertRaises(OSError) as caught:
                    fixture.qualify()
            self.assertIs(caught.exception, refused)
            self.assertEqual(carrier.plan.restore_failure(refused), "original-byte-proof")
            self.assertEqual(fixture.model.calls, [])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_restore_cleanup_failure_has_its_own_operation_and_keeps_original_tail(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original_close = carrier.plan.proof.OwnedRoot.close
            refused = OSError("private cleanup bait")
            deadlines = []
            def close(root, deadline):
                deadlines.append(deadline)
                original_close(root, deadline)
                raise refused
            with patch.object(carrier.plan.proof.OwnedRoot, "close", close):
                with self.assertRaises(OSError) as caught:
                    fixture.qualify()
            self.assertIs(caught.exception, refused)
            self.assertEqual(carrier.plan.restore_failure(refused), "cleanup")
            self.assertEqual(deadlines, [fixture.model.calls[0][1]+carrier.plan.proof.CLEANUP_SECONDS])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_restore_projection_accepts_only_exact_closed_operation_strings(self):
        for value in (None, "private bait", "cleanup/private", 1, ["copy"]):
            error = ValueError("private bait")
            error.native_plan_operation = value
            self.assertIsNone(carrier.plan.restore_failure(error))
        class Poisoned(str):
            pass
        error = ValueError("private bait")
        error.native_plan_operation = Poisoned("copy")
        self.assertIsNone(carrier.plan.restore_failure(error))
        self.assertIsNone(carrier.plan.restore_failure(ValueError("copy")))

    def test_disposable_restore_reaches_real_query_and_readbacks_without_copy_fsync(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original_copy = carrier.plan.schedule.copy_tree
            copied = []
            before = {name: path.read_bytes() for name, path in fixture.physical.items() if path.is_file()}
            def copy(*args, **kwargs):
                with patch.object(carrier.plan.schedule.os, "fsync", side_effect=AssertionError("disposable copy fsync")):
                    result = original_copy(*args, **kwargs)
                for node in args[0]["nodes"]:
                    if node["type"] == "regular":
                        self.assertEqual((args[1]/node["path"]).stat().st_mode & 0o777,
                            0o555 if node["executable"] else 0o444)
                copied.append((args[3], result))
                return result
            with patch.object(carrier.plan.schedule, "copy_tree", side_effect=copy):
                result = fixture.qualify()
            self.assertEqual(len(copied), result["verified_roots"])
            self.assertTrue(copied)
            self.assertEqual(len({deadline for deadline, _ in copied}), 1)
            self.assertEqual({deadline for deadline, _ in copied}, {deadline for _, deadline in fixture.model.calls})
            self.assertEqual(result["verified_nar_bytes"], sum(row["narSize"] for _, row in copied))
            self.assertTrue(result["original_and_copied_bytes_rechecked"])
            self.assertTrue(result["input_metadata_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertEqual(result["plan"]["willBuild"], sorted({models.DRV, models.CHILD}))
            self.assertTrue(all(result[name] is False for name in
                ("realized", "complete_build_seed_verified", "native_runtime_qualified", "sdk_qualified", "execution_authority")))
            self.assertEqual({name: fixture.physical[name].read_bytes() for name in before}, before)
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_disposable_restore_real_copy_flush_failure_keeps_primary_and_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original_copy = carrier.plan.schedule.copy_tree
            original_fdopen = carrier.plan.schedule.os.fdopen
            refused = OSError("private flush diagnostic bait")
            before = {name: path.read_bytes() for name, path in fixture.physical.items() if path.is_file()}
            class FlushFailure:
                def __init__(self, stream):
                    self.stream = stream
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    self.stream.close()
                def write(self, raw):
                    return self.stream.write(raw)
                def flush(self):
                    raise refused
                def fileno(self):
                    return self.stream.fileno()
            def fdopen(fd, mode, *args, **kwargs):
                stream = original_fdopen(fd, mode, *args, **kwargs)
                return FlushFailure(stream) if mode == "wb" else stream
            def copy(*args, **kwargs):
                with patch.object(carrier.plan.schedule.os, "fdopen", side_effect=fdopen):
                    return original_copy(*args, **kwargs)
            with patch.object(carrier.plan.schedule, "copy_tree", side_effect=copy):
                with self.assertRaises(OSError) as caught:
                    fixture.qualify()
            self.assertIs(caught.exception, refused)
            self.assertEqual(carrier.plan.restore_failure(refused), "copy")
            self.assertEqual(fixture.model.calls, [])
            self.assertEqual({name: fixture.physical[name].read_bytes() for name in before}, before)
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_final_readback_refusals_identify_actual_region_and_preserve_primary_cleanup(self):
        cases = (("original", "original-byte-readback"),
            ("metadata", "copied-metadata-readback"), ("copied", "copied-byte-readback"))
        for fault, operation in cases:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
                fixture.generate()
                original_hash = carrier.plan.object_hash
                original_describe = carrier.plan.proof.describe_root
                before = {name: path.read_bytes() for name, path in fixture.physical.items() if path.is_file()}
                refused = (OSError(errno.EIO, "private metadata bait", "/private/untrusted")
                    if fault == "metadata" else ValueError("nar-output-or-deadline-bound"))
                readbacks = []
                def queried():
                    return any("--dry-run" in command for command, _ in fixture.model.calls)
                def hashed(*args, **kwargs):
                    if queried():
                        readbacks.append(args[3])
                        if (fault == "original" and len(readbacks) == 1
                                or fault == "copied" and len(readbacks) == 2):
                            raise refused
                    return original_hash(*args, **kwargs)
                def described(*args, **kwargs):
                    if queried() and fault == "metadata":
                        raise refused
                    return original_describe(*args, **kwargs)
                with patch.object(carrier.plan, "object_hash", side_effect=hashed), \
                        patch.object(carrier.plan.proof, "describe_root", side_effect=described):
                    with self.assertRaises((ValueError, OSError)) as caught:
                        fixture.qualify()
                self.assertIs(caught.exception, refused)
                self.assertEqual(carrier.PHASE, "fresh-private-missing-plan")
                self.assertEqual(carrier.plan.restore_failure(refused), operation)
                self.assertEqual(carrier.plan.restore_failure_reason(refused),
                    "os-io" if fault == "metadata" else "nar-bound-or-deadline")
                self.assertTrue(queried())
                self.assertEqual({deadline for deadline in readbacks},
                    {deadline for _, deadline in fixture.model.calls})
                self.assertEqual({name: fixture.physical[name].read_bytes() for name in before}, before)
                self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_restore_reasons_never_echo_raw_message_paths_or_untyped_errno(self):
        expected = ((ValueError("nar-input-truncated"), "nar-truncated"),
            (ValueError("nar-input-grew"), "nar-grew"),
            (ValueError("descriptor-input-metadata-changed"), "input-metadata-changed"),
            (ValueError("private-store seed contract"), "contract-predicate"),
            (ValueError("private bait"), "value-predicate"),
            (OSError(errno.ENOSPC, "private bait", "/private/bait"), "os-no-space"),
            (OSError(errno.EACCES, "private bait", "/private/bait"), "os-access"),
            (TypeError("private bait"), "other"))
        for error, reason in expected:
            self.assertEqual(carrier.plan.restore_failure_reason(error), reason)
        class Poisoned(str):
            pass
        self.assertEqual(carrier.plan.restore_failure_reason(ValueError(Poisoned("nar-input-grew"))),
            "value-predicate")
        for code in (None, True, "private bait", 999999):
            error = OSError("private bait")
            error.errno = code
            self.assertEqual(carrier.plan.restore_failure_reason(error), "os-other")

    def test_real_restore_hashes_validate_once_before_leaf_io_and_keep_all_readbacks(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original_hash = carrier.plan.object_hash
            original_validate = nar.validate_descriptor
            counts = []
            before = {name: path.read_bytes() for name, path in fixture.physical.items() if path.is_file()}
            def hashed(*args, **kwargs):
                count = []
                original_open = nar.open_regular
                def validate(*values, **options):
                    result = original_validate(*values, **options)
                    count.append(True)
                    return result
                def opened(*values, **options):
                    self.assertEqual(len(count), 1)
                    return original_open(*values, **options)
                with patch.object(nar, "validate_descriptor", side_effect=validate), \
                        patch.object(nar, "open_regular", side_effect=opened):
                    result = original_hash(*args, **kwargs)
                self.assertEqual(len(count), 1)
                counts.append(args[3])
                return result
            with patch.object(carrier.plan, "object_hash", side_effect=hashed):
                result = fixture.qualify()
            self.assertEqual(len(counts), result["verified_roots"]*3)
            self.assertEqual(set(counts), {deadline for _, deadline in fixture.model.calls})
            self.assertTrue(result["original_and_copied_bytes_rechecked"])
            self.assertTrue(result["input_metadata_rechecked"])
            self.assertTrue(result["graph_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertEqual({name: fixture.physical[name].read_bytes() for name in before}, before)
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])
            self.assertTrue(all(result[name] is False for name in
                ("realized", "complete_build_seed_verified", "native_runtime_qualified", "sdk_qualified", "execution_authority")))

    def test_lazy_hash_schema_and_wrong_root_refuse_before_any_source_opener(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"payload"
            source.write_bytes(b"synthetic declared hash bytes")
            source.chmod(0o444)
            descriptor = nar.describe(source)
            proof = nar.hash_descriptor(descriptor)
            row = {"record": [str(source), proof["narHash"], str(proof["narSize"])]}
            cases = []
            bad = copy.deepcopy(descriptor); bad["unknown"] = True
            cases.append((bad, row, "descriptor-schema"))
            bad = copy.deepcopy(descriptor); bad["nodes"].append(copy.deepcopy(bad["nodes"][0]))
            cases.append((bad, row, "descriptor-duplicate"))
            bad = copy.deepcopy(descriptor); bad["nodes"].append({"path": "child", "type": "regular", "size": 1, "executable": False})
            cases.append((bad, row, "descriptor-parent-not-directory"))
            bad = copy.deepcopy(descriptor); bad["nodes"][0]["executable"] = "private bait"
            cases.append((bad, row, "descriptor-regular"))
            bad = copy.deepcopy(descriptor); bad["root"] = str(source.with_name("foreign-never-created"))
            cases.append((bad, row, "private-store seed contract"))
            bad = copy.deepcopy(descriptor); bad["unknown"] = True
            cases.append((bad, {}, "descriptor-schema"))
            for selected, record, message in cases:
                with self.subTest(message=message):
                    with self.assertRaises(ValueError) as caught:
                        carrier.plan.object_hash(selected, record,
                            lambda *_: self.fail("source opened before full schema/root admission"), float(time.monotonic()+30))
                    self.assertEqual(caught.exception.args, (message,))

    def test_lazy_hash_keeps_real_byte_mode_refusal_and_nonregular_root_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"payload"
            source.write_bytes(b"synthetic bytes"); source.chmod(0o444)
            descriptor = nar.describe(source)
            proof = nar.hash_descriptor(descriptor)
            row = {"record": [str(source), proof["narHash"], str(proof["narSize"])]}
            for fault in ("mode", "bytes"):
                with self.subTest(fault=fault):
                    source.chmod(0o644); source.write_bytes(b"synthetic bytes"); source.chmod(0o444)
                    if fault == "mode": source.chmod(0o555)
                    else:
                        source.chmod(0o644); source.write_bytes(b"different bytes"); source.chmod(0o444)
                    with self.assertRaises(ValueError):
                        carrier.plan.object_hash(descriptor, row, nar.open_regular, float(time.monotonic()+30))
            for node in ({"path": "", "type": "directory"},
                    {"path": "", "type": "symlink", "target": "/unfollowed/synthetic"}):
                value = {"schemaVersion": 1, "root": str(source), "nodes": [node]}
                hashed = nar.hash_descriptor(value)
                record = {"record": [str(source), hashed["narHash"], str(hashed["narSize"])]}
                self.assertEqual(carrier.plan.object_hash(value, record,
                    lambda *_: self.fail("inert metadata root opened"), float(time.monotonic()+30)), hashed["narSize"])

    def test_reserved_work_cutoff_is_narrowed_for_actual_source_verifier(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original = float(time.monotonic()+1140)
            # The actual unchanged source helper refuses the wider reserved cutoff.
            with self.assertRaisesRegex(ValueError, "^native-source-deadline$"):
                carrier.sources.verify(fixture.model.model.project["flake.lock"],
                    fixture.model.model.descriptors, fixture.model.model.descriptor_path.parent,
                    declared.metadata_alias_roots(fixture.model.model.descriptor_path), deadline=original)
            # The real complete caller now performs both real source verifications
            # and retains the same original cutoff for restore and final readbacks.
            result = fixture.qualify(deadline=original)
            self.assertTrue(result["locked_sources_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertEqual({deadline for _, deadline in fixture.model.calls}, {original})

    def test_source_failure_projection_is_closed_and_original_expiry_still_refuses(self):
        self.assertEqual(carrier.source_failure(ValueError("native-source-deadline")), "native-source-deadline")
        self.assertEqual(carrier.source_failure(ValueError("native-source-nar-mismatch")), "native-source-nar-mismatch")
        for error in (ValueError("private path or arbitrary message"), OSError("private path"),
                      KeyError("native-source-deadline")):
            self.assertIsNone(carrier.source_failure(error))
        with patch.object(carrier.sources, "verify", side_effect=AssertionError("no verifier after expiry")) as verify:
            with self.assertRaises(ValueError):
                carrier.verify_locked_sources(b"", b"", Path("/not-opened"), time.monotonic()-1)
        verify.assert_not_called()

    def test_joined_generator_declared_aliases_actual_restore_and_readback(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            result = fixture.qualify()
            self.assertTrue(result["private_root_removed"])
            self.assertTrue(result["input_metadata_rechecked"])
            self.assertTrue(result["locked_sources_rechecked"])
            self.assertEqual(result["qualification_provider_requests"], 0)
            self.assertEqual(result["plan"]["willBuild"], sorted({models.DRV, models.CHILD}))
            self.assertTrue(all(result[name] is False for name in
                ("realized", "complete_build_seed_verified", "native_runtime_qualified", "sdk_qualified", "execution_authority")))
            self.assertEqual(len({deadline for _, deadline in fixture.model.calls}), 1)
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_actual_declared_metadata_extent_refusal_is_distinct_from_producer_truth(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
            item = bundle["metadata"][sorted(bundle["metadata"])[0]]
            metadata_file = fixture.repository/item["alias"]
            mode = metadata_file.stat().st_mode & 0o777
            os.chmod(metadata_file, 0o644)
            metadata_file.write_bytes(b"x")
            os.chmod(metadata_file, mode)
            carrier.phase("admission")
            with self.assertRaises(ValueError) as caught:
                fixture.qualify()
            self.assertEqual(carrier.PHASE, "declared-metadata")
            self.assertEqual(inputs.metadata_failure(caught.exception),
                {"role": sorted(bundle["metadata"])[0], "reason": "declared-regular-metadata-changed"})
            self.assertEqual(fixture.model.calls, [])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_actual_metadata_alias_refusal_identifies_closed_role_without_target_io(self):
        for role in ("receipt", "xml"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
                fixture.generate()
                bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
                alias = fixture.repository/bundle["metadata"][role]["alias"]
                alias.unlink()
                alias.symlink_to(fixture.root/"unselected-never-created")
                with self.assertRaises(ValueError) as caught:
                    fixture.qualify()
                self.assertEqual(carrier.PHASE, "declared-metadata")
                self.assertEqual(inputs.metadata_failure(caught.exception),
                    {"role": role, "reason": "undeclared-label-alias"})
                self.assertEqual(fixture.model.calls, [])
                self.assertNotIn(str(fixture.root), inputs.encode(inputs.metadata_failure(caught.exception)).decode())

    def test_declared_repository_directory_alias_uses_exact_canonical_metadata_siblings(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
            actual = fixture.repository.with_name("canonical-repository")
            fixture.repository.rename(actual)
            fixture.repository.symlink_to(actual, target_is_directory=True)
            item = bundle["metadata"]["evidence"]
            label = fixture.repository/item["alias"]
            roots = declared.metadata_alias_roots(fixture.bundle_path)
            canonical = fixture.bundle_path.resolve(strict=True).parent
            self.assertEqual(canonical, actual)
            self.assertTrue(label.is_file())
            with self.assertRaises(OSError):
                declared.open_declared(label, [root/item["alias"] for root in roots], item["pin"]["path"],
                    {"size": item["pin"]["bytes"], "executable": False})
            result = fixture.qualify()
            self.assertTrue(result["input_metadata_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertFalse(result["execution_authority"])

    def test_canonical_metadata_sibling_selection_keeps_undeclared_leaf_and_directory_hops_denied(self):
        for fault in ("leaf", "directory"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
                fixture.generate()
                bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
                alias = fixture.repository/bundle["metadata"]["evidence"]["alias"]
                if fault == "leaf":
                    alias.unlink()
                    alias.symlink_to(fixture.root/"unselected-never-created")
                else:
                    held = alias.parent.with_name("unselected-metadata")
                    alias.parent.rename(held)
                    alias.parent.symlink_to(held, target_is_directory=True)
                with self.assertRaises(ValueError if fault == "leaf" else OSError):
                    fixture.qualify()
                self.assertEqual(carrier.PHASE, "declared-metadata")
                self.assertEqual(fixture.model.calls, [])

    def test_mapping_retarget_between_authorized_roots_and_canonical_selection_refuses(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            unselected = fixture.root/"unselected"
            unselected.mkdir()
            replacement = unselected/"inputs.json"
            replacement.write_bytes(fixture.bundle_raw)
            original = inputs.metadata_alias_roots
            captured = []
            def retarget(path):
                roots = original(path)
                captured.append(roots)
                # First capture belongs to bundle_opener; second is the
                # declared_metadata capture immediately before sibling selection.
                if len(captured) == 2:
                    self.assertNotIn(unselected, roots)
                    fixture.bundle_path.unlink()
                    fixture.bundle_path.symlink_to(replacement)
                return roots
            carrier.phase("admission")
            with patch.object(inputs, "metadata_alias_roots", side_effect=retarget), \
                    patch.object(inputs, "open_declared", side_effect=AssertionError("external sibling read")) as opened:
                with self.assertRaises(ValueError) as refused:
                    fixture.qualify()
                self.assertEqual(refused.exception.args, ("private-store seed contract",))
                opened.assert_not_called()
            self.assertEqual(len(captured), 2)
            self.assertEqual(carrier.PHASE, "declared-metadata")
            self.assertEqual(fixture.model.calls, [])

    def test_metadata_projection_refuses_unbounded_attributes_and_unrelated_errors(self):
        error = ValueError("private arbitrary exception text")
        error.metadata_role, error.metadata_reason = "/private/role", "private arbitrary exception text"
        self.assertIsNone(inputs.metadata_failure(error))

    def test_partial_or_poisoned_roles_refuse_before_referenced_io(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            for name in ("receipt", "obligations", "candidate", "partial"):
                value = copy.deepcopy(fixture.selected)
                if name == "receipt":
                    value["producer"]["receipt"]["path"] = "/private/receipt.json"
                elif name == "obligations":
                    value["obligations"]["path"] = str(fixture.output/"unrelated.json")
                elif name == "candidate":
                    value["candidates"] = {"paths": {"path": "/private/store-paths", "bytes": 1, "sha256": "1"*64},
                        "registration": {"path": "/private/registration", "bytes": 1, "sha256": "1"*64}}
                else:
                    value["producer"].pop("graph_sha256")
                raw = inputs.encode(value)
                with self.subTest(name=name), patch.object(inputs, "selected_bytes",
                    side_effect=AssertionError("role read")), self.assertRaises(ValueError):
                    inputs.generate(raw, seed.sha(raw), fixture.model.runtime_raw,
                        fixture.model.model.descriptors, fixture.project_sources, fixture.repository,
                        float(time.monotonic()+60))

    def test_failed_outer_receipt_refuses_before_obligations_or_sidecars(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            original = inputs.selected_bytes
            for name, value in (("exit", True), ("workload_exit", 1), ("descendants_empty", False)):
                receipt = copy.deepcopy(fixture.receipt)
                receipt[name] = value
                path = Path(fixture.selected["producer"]["receipt"]["path"])
                path.write_bytes(inputs.encode(receipt))
                fixture.selected["producer"]["receipt"] = fixture.file_pin(path)
                calls = []
                def read(pin, deadline):
                    calls.append(pin["path"])
                    return original(pin, deadline)
                raw = inputs.encode(fixture.selected)
                with self.subTest(name=name), patch.object(inputs, "selected_bytes", side_effect=read), \
                        self.assertRaises(ValueError):
                    inputs.generate(raw, seed.sha(raw), fixture.model.runtime_raw,
                        fixture.model.model.descriptors, fixture.project_sources, fixture.repository,
                        float(time.monotonic()+60))
                self.assertNotIn(fixture.selected["obligations"]["path"], calls)
                self.assertEqual(fixture.model.calls, [])

    def test_actual_plan_producer_accepts_ordered_systemd_duration_without_restamping(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            receipt=copy.deepcopy(fixture.receipt)
            receipt["observed_properties"]["RuntimeMaxUSec"]="19min 29s"
            raw=dict(fixture.raw);raw["receipt"]=inputs.encode(receipt)
            selected=copy.deepcopy(fixture.selected)
            selected["producer"]["receipt"]["sha256"]=seed.sha(raw["receipt"])
            selected["producer"]["receipt"]["bytes"]=len(raw["receipt"])
            self.assertEqual(inputs.producer_success(selected,raw),receipt)
            for value in ("20min 1s","19min 60s","19min 29s 1s","29s 19min", "19min  29s",
                          "19min\t29s","-1s","0s","1h","999999999999999999999s", "infinity"):
                with self.subTest(value=value),self.assertRaises(ValueError):inputs.duration(value)
            self.assertEqual(inputs.duration("20min"),1200)
            self.assertEqual(inputs.duration("19min 29s"),1169)

    def test_actual_receipt_output_namespace_and_observed_caps_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            for mutate in ("output", "caps", "graph", "xml"):
                receipt, raw = copy.deepcopy(fixture.receipt), dict(fixture.raw)
                if mutate == "output":
                    receipt["output_base"] = str(fixture.coordination/("1"*64)/"output-base")
                elif mutate == "caps":
                    receipt["observed_properties"]["TasksMax"] = "1024"
                elif mutate == "graph":
                    receipt["graph_sha256"] = "0"*64
                else:
                    raw["xml"] = b'<testsuite tests="1" failures="1" errors="0" skipped="0"/>'
                raw["receipt"] = inputs.encode(receipt)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    inputs.producer_success(fixture.selected, raw)

    def test_retained_generated_symlink_cannot_be_declared_as_regular_data(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            item = fixture.model.body["generated"][models.SCRIPT]
            path = fixture.output/item["artifact_root"]
            path.unlink()
            path.symlink_to(fixture.root/"private-unselected")
            with self.assertRaises(ValueError):
                fixture.generate()
            self.assertEqual(fixture.model.calls, [])

    def test_mapping_digest_refuses_tampered_source_before_regular_opener(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
            logical = next(root for root, row in bundle["roots"].items() if row["regularInputs"])
            item = next(iter(bundle["roots"][logical]["regularInputs"].values()))
            item["source"] = "/private/unselected"
            fixture.bundle_raw = inputs.encode(bundle)
            with patch.object(inputs, "bundle_opener", side_effect=AssertionError("opened")), self.assertRaises(ValueError):
                fixture.qualify()
            self.assertEqual(fixture.model.calls, [])

    def test_runtime_metadata_inventory_substitution_refuses_before_first_child(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            fixture.runtime_metadata["inventory"] = b"changed public inventory"
            with self.assertRaises(ValueError):
                fixture.qualify()
            self.assertEqual(fixture.model.calls, [])

    def test_expired_original_deadline_never_reaches_child_or_creates_private_root(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            with self.assertRaises(ValueError):
                fixture.qualify(deadline=float(time.monotonic()-1))
            self.assertEqual(fixture.model.calls, [])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_after_query_selected_metadata_change_refuses_without_success_promotion(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw, inputs.MAX_MAPPING)
            metadata_file = fixture.repository/bundle["metadata"]["log"]["alias"]
            def changed(*args, **kwargs):
                result = fixture.model.runner(*args, **kwargs)
                if "derivation" in args[0]:
                    os.chmod(metadata_file, 0o644)
                    metadata_file.write_bytes(b"x"*metadata_file.stat().st_size)
                return result
            with self.assertRaises(ValueError):
                fixture.qualify(runner=changed)
            self.assertTrue(fixture.model.calls)
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")), [])

    def test_retained_0555_materializes_logical_modes_and_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            item = fixture.model.body["generated"][models.SCRIPT]
            source = fixture.output/item["artifact_root"]
            before = source.stat()
            payload = source.read_bytes()
            self.assertFalse(item["descriptor"]["nodes"][0]["executable"])
            fixture.generate()
            reached = []
            def runner(command,*args,**kwargs):
                if command[-1] == "--load-db":
                    private = Path(command[command.index("--store")+1].removeprefix("local?root="))
                    copied = private/"nix/store"/models.SCRIPT.rsplit("/",1)[1]
                    self.assertEqual(copied.stat().st_mode & 0o777,0o444)
                    self.assertEqual(copied.read_bytes(),payload)
                    reached.append(True)
                return fixture.model.runner(command,*args,**kwargs)
            result = fixture.qualify(runner=runner)
            self.assertEqual(reached,[True])
            self.assertTrue(result["original_and_copied_bytes_rechecked"])
            self.assertEqual(inputs.witness(source.stat()),inputs.witness(before))
            self.assertEqual(source.read_bytes(),payload)
            self.assertFalse(result["complete_build_seed_verified"])

    def test_retained_same_byte_inode_replacement_after_proof_refuses_before_child(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            original = models.plan.proof.OwnedRoot
            item = fixture.model.body["generated"][models.SCRIPT]
            source = fixture.output/item["artifact_root"]
            def replace(parent):
                owned = original(parent)
                payload = source.read_bytes()
                source.rename(source.with_name(source.name+"-held"))
                source.write_bytes(payload)
                os.chmod(source,0o555)
                return owned
            with patch.object(models.plan.proof,"OwnedRoot",side_effect=replace),self.assertRaises(ValueError):
                fixture.qualify()
            self.assertEqual(fixture.model.calls,[])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")),[])

    def test_transport_scope_cannot_normalize_runtime_or_imported_source(self):
        with tempfile.TemporaryDirectory() as directory, JoinedFixture(directory) as fixture:
            fixture.generate()
            bundle = inputs.decode(fixture.bundle_raw,inputs.MAX_MAPPING)
            root = fixture.model.runtime["roots"][0]
            bundle["roots"][root]["retained_transport"] = inputs.RETAINED_TRANSPORT
            fixture.bundle_raw = inputs.encode(bundle)
            fixture.report["mapping_sha256"] = seed.sha(fixture.bundle_raw)
            with self.assertRaises(ValueError):
                fixture.qualify()
            self.assertEqual(fixture.model.calls,[])
            self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")),[])

    def test_retained_wrong_mode_and_same_size_bytes_are_not_normalized_to_success(self):
        for change in ("mode","bytes"):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory,JoinedFixture(directory) as fixture:
                fixture.generate()
                item = fixture.model.body["generated"][models.SCRIPT]
                source = fixture.output/item["artifact_root"]
                os.chmod(source,0o644)
                if change == "bytes":
                    source.write_bytes(b"x"*source.stat().st_size)
                    os.chmod(source,0o555)
                with self.assertRaises(ValueError):
                    fixture.qualify()
                self.assertEqual(fixture.model.calls,[])
                self.assertEqual(list(fixture.model.model.root.glob("nix-private-build-*")),[])


class ReservedEnvelopeModels(unittest.TestCase):
    def test_delayed_entry_keeps_private_tail_before_original_outer_reserve(self):
        entry,deadline=100*10**9,1300*10**9
        environment={"OMUX_NATIVE_SEED_RESERVED_PROFILE":"native-seed-plan-reserved",
            "OMUX_NATIVE_SEED_ROOT_ENTRY_NS":str(entry),
            "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS":str(deadline)}
        work,record=carrier.work_envelope(1000.0,"1200",environment)
        self.assertAlmostEqual(work,1240.0)
        self.assertLess(work,1240.0)
        self.assertEqual(record["original_entry_monotonic_ns"],entry)
        self.assertEqual(record["outer_work_deadline_monotonic_ns"],1270*10**9)
        self.assertLessEqual(record["private_cleanup_deadline_monotonic_ns"],1270*10**9)
        self.assertLess(work,1000+min(carrier.schedule.MAX_SECONDS,1170))
        self.assertEqual(carrier.work_envelope(1000.0,"1200",{}),
            (float(1000+min(carrier.schedule.MAX_SECONDS,1170)),None))

    def test_reserved_readback_after_old_ceiling_obeys_actual_test_work_cutoff(self):
        environment={"OMUX_NATIVE_SEED_RESERVED_PROFILE":"native-seed-plan-reserved",
            "OMUX_NATIVE_SEED_ROOT_ENTRY_NS":str(100*10**9),
            "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS":str(1300*10**9)}
        work,record=carrier.work_envelope(100.0,"900",environment)
        legacy,_=carrier.work_envelope(100.0,"900",{})
        self.assertEqual(work,970.0)
        self.assertEqual(legacy,700.0)
        self.assertEqual(record["private_cleanup_deadline_monotonic_ns"],1000*10**9)
        # Exercise the actual clock predicate used throughout the full
        # original/copy/provenance readbacks; no NAR predicate is bypassed.
        with patch.object(carrier.proof.time,"monotonic",return_value=701.0):
            carrier.proof.tick(work)
            with self.assertRaises(ValueError):carrier.proof.tick(legacy)
        with patch.object(carrier.proof.time,"monotonic",return_value=work):
            with self.assertRaises(ValueError):carrier.proof.tick(work)

    def test_reserved_test_timeout_cannot_borrow_the_original_outer_cleanup(self):
        environment={"OMUX_NATIVE_SEED_RESERVED_PROFILE":"native-seed-plan-reserved",
            "OMUX_NATIVE_SEED_ROOT_ENTRY_NS":str(100*10**9),
            "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS":str(1300*10**9)}
        for timeout in ("31","90","900"):
            with self.subTest(timeout=timeout):
                work,record=carrier.work_envelope(100.0,timeout,environment)
                self.assertEqual(work,100.0+int(timeout)-30)
                self.assertLessEqual(record["private_cleanup_deadline_monotonic_ns"],
                    (100+int(timeout))*10**9)
                self.assertLessEqual(record["private_cleanup_deadline_monotonic_ns"],1270*10**9)

    def test_delayed_reserved_start_cannot_reset_original_root_budget(self):
        environment={"OMUX_NATIVE_SEED_RESERVED_PROFILE":"native-seed-plan-reserved",
            "OMUX_NATIVE_SEED_ROOT_ENTRY_NS":str(100*10**9),
            "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS":str(1300*10**9)}
        work,record=carrier.work_envelope(1100.0,"900",environment)
        self.assertLess(work,1240.0)
        self.assertLess(work,1100+870)
        self.assertEqual(record["original_entry_monotonic_ns"],100*10**9)
        self.assertEqual(record["original_deadline_monotonic_ns"],1300*10**9)
        self.assertLessEqual(record["private_cleanup_deadline_monotonic_ns"],1270*10**9)
        with patch.object(carrier.proof.time,"monotonic",return_value=1240.0):
            with self.assertRaises(ValueError):carrier.proof.tick(work)
        for entry in (1240.0,1300.0,1301.0):
            with self.subTest(entry=entry),self.assertRaises(ValueError):
                carrier.work_envelope(entry,"900",environment)

    def test_nonreserved_schedule_ceiling_and_short_test_timeout_are_unchanged(self):
        for timeout in ("31","90","900","1200"):
            with self.subTest(timeout=timeout):
                work,record=carrier.work_envelope(100.0,timeout,{})
                self.assertEqual((work,record),
                    (float(100+min(carrier.schedule.MAX_SECONDS,int(timeout)-30)),None))
        for timeout in ("0","30","-1","900x",""):
            with self.subTest(timeout=timeout),self.assertRaises(ValueError):
                carrier.work_envelope(100.0,timeout,{})

    def test_partial_wrong_profile_longer_clock_and_late_start_do_not_renew(self):
        good={"OMUX_NATIVE_SEED_RESERVED_PROFILE":"native-seed-plan-reserved",
            "OMUX_NATIVE_SEED_ROOT_ENTRY_NS":str(100*10**9),
            "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS":str(1300*10**9)}
        for key in good:
            wrong=dict(good);wrong.pop(key)
            with self.assertRaises(ValueError):carrier.work_envelope(1000.0,"1200",wrong)
        for key,value in (("OMUX_NATIVE_SEED_RESERVED_PROFILE","standard"),
            ("OMUX_NATIVE_SEED_RESERVED_PROFILE","native-seed-plan-reserved-models"),
            ("OMUX_NATIVE_SEED_ROOT_ENTRY_NS",True),("OMUX_NATIVE_SEED_ROOT_ENTRY_NS","0"),
            ("OMUX_NATIVE_SEED_ROOT_DEADLINE_NS",str(1301*10**9))):
            with self.assertRaises(ValueError):
                carrier.work_envelope(1000.0,"1200",{**good,key:value})
        with self.assertRaises(ValueError):carrier.work_envelope(1240.0,"1200",good)
        with self.assertRaises(ValueError):carrier.work_envelope(99.0,"1200",good)


if __name__ == "__main__":
    unittest.main()
