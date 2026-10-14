"""Real copy/NAR/owned-store contracts; only external Nix is injected."""
from contextlib import ExitStack
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import nar_descriptor as nar
import native_flake_missing_plan as missing
import native_flake_schedule_test as schedule_models
import native_flake_seed_plan as plan
import nix_private_store_seed as seed

CHILD = "/nix/store/"+"b"*32+"-dependency.drv"
OTHER = "/nix/store/"+"a"*32+"-unrelated"
OUT = schedule_models.OUT
DRV = schedule_models.DRV
DEPENDENCY = schedule_models.DEPENDENCY
SCRIPT = schedule_models.SCRIPT


class PlanFixture:
    def __init__(self, directory):
        self.stack = ExitStack()
        # The old schedule fixture's arbitrary 'e' hash isn't Nix base32.
        self.stack.enter_context(patch.object(schedule_models, "CHILD", CHILD))
        self.model = schedule_models.Fixture(directory)
        self.body, payloads = self.model.operate()
        self.body.update(platform={"nonroot": True, "no_new_privileges": True,
            "effective_capabilities_empty": True}, guard_epoch="00000000-0000-4000-8000-000000000001",
            seed_file_inventory_sha256="1"*64, source_descriptors_sha256=seed.sha(self.model.descriptors),
            implementation_sha256={name: "1"*64 for name in (
                "native_flake_schedule.py", "native_flake_sources.py", "nix_private_store_seed.py",
                "nix_private_store_qualification.py", "nar_descriptor.py", "verify_declared_nars.py",
                "verify_cached_nars.py", "nix_source_probe.py", "nix_interpreter_closure.py")})
        self.raw = seed.encoded(self.body)
        self.runtime_raw = seed.encoded(self.model.runtime.value)
        self.runtime = self.model.runtime.value
        self.records = plan.producer_objects(self.body, self.runtime)
        self.descriptors = dict(self.runtime["descriptors"])
        self.physical = {}
        for logical, item in self.body["generated"].items():
            descriptor = item["descriptor"]
            self.descriptors[logical] = descriptor
            physical = self.model.root/("mapped-"+str(len(self.physical)))
            if "artifact_root" in item:
                opener = lambda _, relative, item=item: io.BytesIO(payloads[(item["artifact_root"],relative)])
                plan.schedule.copy_tree(descriptor, physical, opener, float(time.monotonic()+60))
            elif item["source_role"] == "project":
                plan.schedule.project_copy(self.model.project, physical, float(time.monotonic()+60))
            else:
                source = next(row for row in self.model.bundle["sources"] if row["role"] == item["source_role"])
                opener = lambda _, relative, source=source: nar.open_regular(
                    str(self.model.labels/source["regularInputs"][relative]), "")
                plan.schedule.copy_tree(descriptor, physical, opener, float(time.monotonic()+60))
            self.physical[logical] = physical
        self.candidate_records = {}
        self.calls = []
        self.registration = None
        self.missing = {DRV, CHILD}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()

    def opener(self, root, relative):
        if root in self.physical:
            return nar.open_regular(str(self.physical[root]), relative)
        seed.require(root in self.runtime["descriptors"])
        return self.model.runtime.opener(root, relative)

    def add_candidate(self, logical, *, refs=()):
        physical = self.model.root/("candidate-"+str(len(self.candidate_records)))
        physical.write_bytes(b"public-selected-candidate")
        os.chmod(physical, 0o444)
        descriptor = nar.describe(physical)
        descriptor["root"] = logical
        hashed = nar.hash_descriptor(descriptor, opener=lambda _, relative: nar.open_regular(str(physical),relative))
        row = [logical, hashed["narHash"], str(hashed["narSize"]), "", str(len(refs)), *refs]
        self.candidate_records.update(seed.validate(self.runtime))
        self.candidate_records[logical] = {"record": row, "references": list(refs)}
        self.descriptors[logical], self.physical[logical] = descriptor, physical

    def runner(self, command, env, cwd, deadline, *, tool_fd, input_file=None,
               output_limit=None, capture_stderr=False):
        self.calls.append((command,deadline))
        assert os.fstat(tool_fd).st_mode & 0o100
        assert env == plan.proof.environment(cwd)
        if command[-1] == "--load-db":
            self.registration = input_file.read().decode("ascii")
            return b""
        if command[-1] == "--dump-db":
            roots = sorted(set(self.records) | set(self.selected))
            rows = seed.registrations(self.registration, roots, current_flake_paths=True)
            wire = ""
            for root in roots:
                record = list(rows[root]["record"])
                record[1] = seed.expected_hash(record[1])
                wire += "\n".join(record)+"\n"
            return wire.encode("ascii")
        if "derivation" in command:
            return self.model.raw_graph
        if "--dry-run" in command:
            assert capture_stderr is True and output_limit == plan.proof.MAX_OUTPUT
            paths = sorted(self.missing)
            header = "this derivation will be built:" if len(paths)==1 else "these "+str(len(paths))+" derivations will be built:"
            raw = (header+"\n"+"".join("  "+path+"\n" for path in paths)).encode() if paths else b""
            return b"", raw
        raise AssertionError("unexpected Nix operation")

    def restore(self, *, runner=None):
        _, self.selected = plan.candidates(self.body, self.candidate_records)
        wanted = set(self.records) | set(self.selected)
        with patch.object(missing.proof, "run", side_effect=self.runner):
            return plan.restore_plan(self.body, self.runtime, self.records, self.selected,
                {root:self.descriptors[root] for root in wanted}, self.opener,
                self.model.root, float(time.monotonic()+60), runner=self.runner if runner is None else runner)


class SeedPlanModels(unittest.TestCase):
    def test_actual_schema_join_and_literal_failure_flags_refuse(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            def join(raw):
                return plan.join_obligations(raw,seed.sha(raw),fixture.runtime_raw,
                    fixture.body["source_proof"],fixture.model.project,fixture.body["wrapper_sha256"])
            value, runtime, records = join(fixture.raw)
            self.assertEqual(value, fixture.body)
            self.assertEqual(runtime, fixture.runtime)
            self.assertEqual(records, fixture.records)
            for key, value in (("private_root_removed", 1), ("realized", 0),
                               ("complete_build_seed_verified", True), ("schema_version", True)):
                changed = copy.deepcopy(fixture.body)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    join(seed.encoded(changed))
            with self.assertRaises(ValueError):
                plan.join_obligations(fixture.raw,"0"*64,fixture.runtime_raw,
                    fixture.body["source_proof"],fixture.model.project,fixture.body["wrapper_sha256"])

    def test_generated_role_hash_and_sidecar_alias_changes_refuse(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            for kind in ("role", "hash", "alias"):
                changed = copy.deepcopy(fixture.body)
                if kind == "role":
                    logical = changed["target"]["sourcePaths"]["systems"]
                    changed["generated"][logical]["source_role"] = "nixpkgs"
                elif kind == "hash":
                    changed["generated"][DRV]["narHash"] = "sha256:"+"0"*64
                else:
                    changed["generated"][DRV]["artifact_root"] = "generated/../private"
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    plan.producer_objects(changed, fixture.runtime)

    def test_candidate_selection_exact_output_identity_and_closed_refs_only(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            reference = fixture.runtime["roots"][0]
            fixture.add_candidate(DEPENDENCY, refs=(reference,))
            fixture.add_candidate(OTHER)
            ready, selected = plan.candidates(fixture.body, fixture.candidate_records)
            self.assertEqual(ready, [DEPENDENCY])
            self.assertIn(reference, selected)
            self.assertNotIn(OTHER, selected)
            bad = copy.deepcopy(fixture.candidate_records)
            bad[DEPENDENCY]["record"][-1] = OTHER+"-absent"
            bad[DEPENDENCY]["references"] = [OTHER+"-absent"]
            with self.assertRaises(ValueError):
                plan.candidates(fixture.body, bad)

    def test_ready_pruning_does_not_require_input_sources_of_skipped_derivation(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            body = copy.deepcopy(fixture.body)
            body["derivations"][CHILD]["inputSrcs"] = [OTHER]
            records = dict(fixture.records)
            records[DEPENDENCY] = {"synthetic": "byte-qualified ready output"}
            result = plan.readiness(body,missing.MissingPlan(frozenset({DRV}),frozenset(),frozenset(),()),records)
            self.assertEqual(result["missing_input_sources"], [])
            self.assertTrue(result["required_input_paths_present"])
            self.assertFalse(result["complete_build_seed_verified"])
            result = plan.readiness(body,missing.MissingPlan(frozenset({DRV,CHILD}),frozenset(),frozenset(),()),records)
            self.assertEqual(result["missing_input_sources"], [OTHER])

    def test_zero_plan_needs_actual_registered_target_and_never_implies_seed_success(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            zero = missing.MissingPlan(frozenset(),frozenset(),frozenset(),())
            with self.assertRaises(ValueError):
                plan.readiness(fixture.body,zero,fixture.records)
            records = dict(fixture.records)
            records[OUT] = {"synthetic": "byte-qualified ready target"}
            result = plan.readiness(fixture.body,zero,records)
            self.assertTrue(result["requested_target_ready"])
            self.assertFalse(result["complete_build_seed_verified"])
            for value in (missing.MissingPlan(frozenset(),None,frozenset(),()),
                          missing.MissingPlan(frozenset({OTHER}),frozenset(),frozenset(),())):
                with self.assertRaises(ValueError):
                    plan.readiness(fixture.body,value,records)

    def test_real_copy_registration_graph_query_and_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            result = fixture.restore()
            self.assertEqual(result["plan"]["willBuild"], sorted({DRV,CHILD}))
            self.assertTrue(result["graph_rechecked"])
            self.assertTrue(result["original_and_copied_bytes_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertFalse(result["complete_build_seed_verified"])
            self.assertFalse(result["realized"])
            self.assertEqual(len({deadline for _,deadline in fixture.calls}),1)
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])
            dry = [command for command,_ in fixture.calls if "--dry-run" in command]
            self.assertEqual(dry[0][-1],DRV+"!out")
            self.assertFalse(any("build" in command for command,_ in fixture.calls))

    def test_actual_candidate_target_ready_bytes_are_rehashed_then_zero_plan(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            fixture.add_candidate(OUT)
            fixture.missing = set()
            result = fixture.restore()
            self.assertTrue(result["plan"]["requested_target_ready"])
            self.assertEqual(result["plan"]["willBuild"],[])
            self.assertFalse(result["complete_build_seed_verified"])

    def test_changed_candidate_bytes_refuse_before_private_namespace(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            fixture.add_candidate(DEPENDENCY)
            path = fixture.physical[DEPENDENCY]
            os.chmod(path,0o644)
            path.write_bytes(b"same-selected-size-bad!!!!")
            with patch.object(plan.proof,"OwnedRoot",side_effect=AssertionError("root opened")), self.assertRaises(ValueError):
                fixture.restore()
            self.assertEqual(fixture.calls,[])




    def test_generated_mutation_after_preproof_never_reaches_first_runner(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            original = plan.proof.OwnedRoot
            def mutate(parent):
                root = original(parent)
                path = fixture.physical[SCRIPT]
                payload = path.read_bytes()
                os.chmod(path,0o644)
                path.write_bytes(b"x"*len(payload))
                return root
            with patch.object(plan.proof,"OwnedRoot",side_effect=mutate), self.assertRaises(ValueError):
                fixture.restore()
            self.assertEqual(fixture.calls,[])
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])

    def test_tool_mutation_after_preproof_never_reaches_first_runner(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            original = plan.proof.OwnedRoot
            def mutate(parent):
                root = original(parent)
                logical = fixture.runtime["tools"]["nix"]
                root_name = "/".join(logical.split("/")[:4])
                relative = "/".join(logical.split("/")[4:])
                path = fixture.model.runtime.physical[root_name]/relative
                payload = path.read_bytes()
                os.chmod(path,0o755)
                path.write_bytes(b"x"*len(payload))
                return root
            with patch.object(plan.proof,"OwnedRoot",side_effect=mutate), self.assertRaises(ValueError):
                fixture.restore()
            self.assertEqual(fixture.calls,[])
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])

    def test_same_byte_named_tool_replacement_is_not_adopted_before_runner(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            original = plan.proof.OwnedRoot
            def replace(parent):
                root = original(parent)
                logical = fixture.runtime["tools"]["nix"]
                root_name = "/".join(logical.split("/")[:4])
                relative = "/".join(logical.split("/")[4:])
                path = fixture.model.runtime.physical[root_name]/relative
                payload = path.read_bytes()
                path.rename(path.with_name(path.name+"-held"))
                path.write_bytes(payload)
                os.chmod(path,0o555)
                return root
            with patch.object(plan.proof,"OwnedRoot",side_effect=replace), self.assertRaises(ValueError):
                fixture.restore()
            self.assertEqual(fixture.calls,[])
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])

    def test_same_bytes_wrong_executable_mode_refuse_before_private_namespace(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            os.chmod(fixture.physical[SCRIPT],0o555)
            with patch.object(plan.proof,"OwnedRoot",side_effect=AssertionError("root opened")), self.assertRaises(ValueError):
                fixture.restore()
            self.assertEqual(fixture.calls,[])

    def test_unlisted_copied_source_leaf_refuses_after_child_and_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            def changed(*args, **kwargs):
                result = fixture.runner(*args, **kwargs)
                if "derivation" in args[0]:
                    command = args[0]
                    private = Path(command[command.index("--store")+1].removeprefix("local?root="))
                    logical = fixture.body["target"]["sourcePaths"]["project"]
                    path = private/"nix/store"/logical.rsplit("/",1)[1]/"unlisted"
                    path.write_bytes(b"public unlisted copy")
                return result
            with self.assertRaises(ValueError):
                fixture.restore(runner=changed)
            self.assertTrue(fixture.calls)
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])

    def test_copied_bytes_mutated_by_query_refuse_and_only_owned_root_is_removed(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            def changed(*args, **kwargs):
                result = fixture.runner(*args, **kwargs)
                if "derivation" in args[0]:
                    command = args[0]
                    private = Path(command[command.index("--store")+1].removeprefix("local?root="))
                    path = private/"nix/store"/SCRIPT.rsplit("/",1)[1]
                    os.chmod(path,0o644)
                    path.write_bytes(b"mutated public generated object")
                return result
            with self.assertRaises(ValueError):
                fixture.restore(runner=changed)
            self.assertTrue(fixture.calls)
            self.assertEqual(list(fixture.model.root.glob("nix-private-build-*")),[])
            self.assertTrue(fixture.physical[SCRIPT].exists())

    def test_actual_canonical_target_roundtrip_refuses_wire_or_ambiguous_target(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            def join(body):
                raw = seed.encoded(body)
                return plan.join_obligations(raw, seed.sha(raw), fixture.runtime_raw,
                    body["source_proof"], fixture.model.project, body["wrapper_sha256"])
            self.assertEqual(join(fixture.body)[0]["target"], fixture.body["target"])
            for variant in ("wire", "both", "extra"):
                body = copy.deepcopy(fixture.body)
                if variant == "wire":
                    body["target"]["outputPath"] = body["target"].pop("outPath")
                elif variant == "both":
                    body["target"]["outputPath"] = body["target"]["outPath"]
                else:
                    body["target"]["unselected"] = "value"
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    join(body)

    def test_actual_generated_record_count_4319_roundtrip_and_4609_refusal(self):
        with tempfile.TemporaryDirectory() as directory, PlanFixture(directory) as fixture:
            body = copy.deepcopy(fixture.body)
            records = dict(fixture.records)
            source = copy.deepcopy(body["generated"][SCRIPT])
            for count in (4319, 4608, 4609):
                while len(records) < count:
                    index = len(records)
                    logical = "/nix/store/"+"c"*32+"-extra-"+str(index)
                    item = copy.deepcopy(source)
                    item["descriptor"]["root"] = logical
                    item["artifact_root"] = "generated/"+str(100000+index).zfill(8)
                    body["generated"][logical] = item
                    row = copy.deepcopy(fixture.records[SCRIPT])
                    row["record"][0] = logical
                    records[logical] = row
                wire = ""
                for logical in sorted(records):
                    row = list(records[logical]["record"])
                    row[1] = seed.expected_hash(row[1])
                    wire += "\n".join(row)+"\n"
                body["registration"] = wire
                body["registration_sha256"] = seed.sha(wire.encode("ascii"))
                if count <= 4608:
                    self.assertEqual(set(plan.producer_objects(body,fixture.runtime)),set(records))
                else:
                    with self.assertRaises(ValueError):
                        plan.producer_objects(body,fixture.runtime)
            self.assertEqual(plan.MAX_CANDIDATE_ROOTS,4096)
            with self.assertRaises(ValueError):
                plan.candidates(fixture.body,{str(i):{} for i in range(4097)})

    def test_missing_plan_derivations_share_exact_pinned_name_grammar(self):
        from nix_interpreter_closure import current_flake_path_refusal
        good = (".drv", "input?=source.drv", "x"*207+".drv")
        for name in good:
            path = "/nix/store/"+"a"*32+"-"+name
            self.assertIsNone(current_flake_path_refusal(path,drv=True))
            self.assertEqual(missing.allowed_paths(frozenset({path})),frozenset({path}))
            raw = ("this derivation will be built:\n  "+path+"\n").encode("ascii")
            self.assertEqual(missing.parse(raw,allowed_drvs=frozenset({path})).willBuild,frozenset({path}))
        for name in (".-bad.drv", "..-bad.drv", "x"*208+".drv", "bad!name.drv", "missing"):
            path = "/nix/store/"+"a"*32+"-"+name
            self.assertIsNotNone(current_flake_path_refusal(path,drv=True))
            with self.assertRaises(ValueError):
                missing.allowed_paths(frozenset({path}))


if __name__ == "__main__":
    unittest.main()
