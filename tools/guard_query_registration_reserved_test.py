"""Actual admission/command/SQLite/FD models; no host DB or reserved action proof."""
import copy
import math
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_query_registration_reserved as reserved
import guard_native_seed_plan_reserved as kernel
import guard_native_seed_plan_reserved_test as kernel_models
import codex_query_registration as collector
import codex_query_registration_test as registration_models
import codex_query_registration_reserved_producer as producer
import codex_protocol_history_query_tools as query


def selected_reserved(fixture, witness):
    top, raw, receipt, report = registration_models.selected_candidate(fixture)
    receipt.update(profile=reserved.PROFILE, targets=[reserved.LABEL], cache_policy=None, cache_key=None,
        isolation={"PrivateNetwork":"yes"},
        limits=reserved.properties(guard.PROPERTIES), query_registration_reservation=reserved.projection(
            witness.entry, witness.deadline, True, witness.complete(0, True, True, True)))
    receipt["observed_properties"].update(reserved.properties(guard.PROPERTIES))
    receipt["observed_properties"]["RuntimeMaxUSec"] = "700s"
    evidence=collector.json.loads(raw["candidate_evidence"])
    evidence["targets"]=[reserved.LABEL]
    evidence["results"][0]["target"]=reserved.LABEL
    registration_models.rebind(top, raw, "evidence", evidence)
    receipt["test_evidence"]["sha256"]=top["candidates"]["producer"]["evidence"]["sha256"]
    registration_models.rebind(top, raw, "receipt", receipt)
    output=receipt["output_base"]+"/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"+reserved.LABEL.split(":")[1]+"/test.outputs/"
    top["candidates"]["kind"] = collector.RESERVED_CANDIDATE_KIND
    for name, leaf in (("registration","registration"),("paths","store-paths"),("report","query-registration.json")):
        top["candidates"][name]["path"]=output+leaf
    return top, raw, receipt, report


class QueryReservationModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=reserved.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a"*40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_singleton_and_mixed_selectors_refuse_before_guard_tool_reads(self):
        self.assertTrue(reserved.request(self.args(), reserved.ARGUMENTS))
        for arguments in (["test", collector.TARGET], ["build", reserved.LABEL], ["run", reserved.LABEL],
            [*reserved.ARGUMENTS, "//:docs_check"], ["test", "--test_arg=--database=/tmp/db", reserved.LABEL]):
            with self.assertRaises(ValueError): reserved.request(self.args(), arguments)
        for key, value in (("manager", "user"), ("reuse_owned_cache", True), ("source_dirty", "true"),
            ("resident_manifest", Path("/model/private.json")), ("native_mode", "schema"),
            ("repository_cache", Path("/model/cache"))):
            args=self.args(); setattr(args, key, value)
            with self.assertRaises(ValueError): reserved.request(args, reserved.ARGUMENTS)
        with patch.object(guard, "immutable", side_effect=AssertionError("tool IO")) as tools:
            for arguments in (["test", collector.TARGET], [*reserved.ARGUMENTS, "//:omux"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", reserved.PROFILE, "--manager", "system",
                        "--source-commit", "a"*40, "--source-dirty", "false", "--", *arguments])
            tools.assert_not_called()
        self.assertNotIn(reserved.PROFILE, kernel.PROFILES)
        self.assertEqual(kernel.selected(kernel.MODEL_PROFILE, kernel.REGISTRATION_RESERVED_MODELS), {"PrivateNetwork":"yes"})
        for arguments in ([*kernel.REGISTRATION_RESERVED_MODELS, "//:omux"],
            list(reversed(kernel.REGISTRATION_RESERVED_MODELS)), reserved.ARGUMENTS):
            with self.assertRaises(ValueError): kernel.selected(kernel.MODEL_PROFILE, arguments)
        for cohort in (kernel.MODELS, kernel.RECOVERY_MODELS, kernel.QUERY_MODELS,
            kernel.ARCHIVE_MODELS, kernel.REGISTRATION_MODELS):
            self.assertEqual(kernel.selected(kernel.MODEL_PROFILE, cohort), {"PrivateNetwork":"yes"})

    def test_actual_command_is_fresh_offline_and_binds_only_query_clock(self):
        with patch.object(kernel.time, "monotonic_ns", return_value=200*10**9):
            command=reserved.command(guard.bazel_command, "bazel", Path("/model/epoch"), reserved.ARGUMENTS,
                reserved.PROFILE, 100*10**9, 1300*10**9, source_commit="a"*40, source_dirty="false")
            self.assertEqual(command[-1], reserved.LABEL)
            self.assertEqual(command.count("test"), 1)
            for value in ("--output_base=/model/epoch/output-base", "--repository_disable_download",
                "--repo_contents_cache=", "--disk_cache=", "--remote_cache=", "--remote_executor=",
                "--sandbox_default_allow_network=false", "--lockfile_mode=error",
                "--test_env="+reserved.MODE+"="+reserved.PROFILE,
                "--test_env="+reserved.ENTRY+"=100000000000", "--test_env="+reserved.DEADLINE+"=1300000000000"):
                self.assertIn(value, command)
            self.assertFalse(any(part.startswith("--test_env="+kernel.MODE+"=") for part in command))
            with self.assertRaises(ValueError):
                reserved.command(guard.bazel_command, "bazel", Path("/model/epoch"), reserved.ARGUMENTS,
                    reserved.PROFILE, 100*10**9, 1300*10**9, output_base=Path("/old/cache"))
        builder=Mock()
        with patch.object(kernel.time, "monotonic_ns", return_value=1270*10**9), self.assertRaises(ValueError):
            reserved.command(builder, "bazel", Path("/model/epoch"), reserved.ARGUMENTS,
                reserved.PROFILE, 100*10**9, 1300*10**9)
        builder.assert_not_called()

    def test_actual_caps_and_kernel_pidfd_reservation_reject_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name, value in guard.CGROUP.items():
                (root/name).write_text({"memory.max":str(reserved.MEMORY),"pids.max":"480"}.get(name,value))
            (root/"cpu.max").write_text("190000 100000\n")
            actual={**reserved.properties(guard.PROPERTIES), **guard.SANDBOX, "RuntimeMaxUSec":"17s",
                "TemporaryFileSystem":guard.system_masks(profile="standard"),
                "UnsetEnvironment":" ".join(guard.DELEGATION_ENV)}
            guard.verify(actual, root, "system", guard.SANDBOX, reserved.PROFILE, runtime_seconds=17)
            self.assertEqual(guard.workload_pids_observation(None, reserved.PROFILE).expected_limit, 480)
            for key, value in (("TasksMax","512"),("MemoryMax","4294967296"),("CPUQuotaPerSecUSec","2s")):
                with self.assertRaises(ValueError):
                    guard.verify({**actual,key:value},root,"system",guard.SANDBOX,reserved.PROFILE,runtime_seconds=17)
        with kernel_models.Fixture() as fixture:
            self.assertIs(reserved.Witness, kernel.Witness)
            observed=fixture.witness.complete(0, True, True, True)
            self.assertIs(observed["custody_observed"],False)
            (fixture.root/"cpu.max").write_text("10001 100000\n")
            with self.assertRaises(ValueError): fixture.witness.complete(0, True, True, True)

    def test_worker_terminal_authority_and_no_standard_profile_adoption(self):
        fixture=kernel_models.ProofWorkerModels()
        witness=fixture.worker(); witness.alive=Mock(side_effect=[True, False, False])
        now=[0.0]; read=Mock(side_effect=fixture.terminal)
        result=reserved.monitor(reserved.PROFILE,witness,read,10,lambda:None,
            clock=lambda:now[0],pause=lambda seconds:now.__setitem__(0,now[0]+seconds))
        self.assertEqual(result,0);read.assert_called_once()
        read=Mock()
        with self.assertRaises(ValueError):
            reserved.monitor("standard",witness,read,10,lambda:None,clock=lambda:0)
        read.assert_not_called()
        witness=fixture.worker();witness.alive=Mock(return_value=False)
        with self.assertRaises(ValueError):
            reserved.monitor(reserved.PROFILE,witness,
                lambda:fixture.terminal(InvocationID="b"*32),10,lambda:None,clock=lambda:0)

    def test_real_sqlite_report_and_supplied_reserved_evidence_join_without_legacy_change(self):
        with tempfile.TemporaryDirectory() as temporary, kernel_models.Fixture() as kernel_fixture:
            fixture=registration_models.Fixture(temporary)
            top,raw,receipt,report=selected_reserved(fixture,kernel_fixture.witness)
            self.assertIs(query.selection(top),top)
            records=collector.validate_success(top["candidates"],raw,fixture.project,top["plan"])
            self.assertEqual(sorted(records),fixture.paths)
            self.assertIs(report["nar_verified"],False)
            for cpu in ("1.900000s","1900ms","1900000us"):
                equivalent=copy.deepcopy(receipt);equivalent["observed_properties"]["CPUQuotaPerSecUSec"]=cpu
                re_raw=copy.deepcopy(raw);re_top=copy.deepcopy(top)
                registration_models.rebind(re_top,re_raw,"receipt",equivalent)
                self.assertEqual(collector.validate_success(re_top["candidates"],re_raw,fixture.project,re_top["plan"]),records)
            old_top,old_raw,old_receipt,_=registration_models.selected_candidate(fixture)
            self.assertIs(query.selection(old_top),old_top)
            self.assertEqual(collector.validate_success(old_top["candidates"],old_raw,fixture.project,old_top["plan"]),records)
            self.assertEqual(old_receipt["profile"],"standard")
            for section,key,value in ((None,"profile","standard"),(None,"targets",[collector.TARGET]),
                (None,"workload_exit",1),(None,"descendants_empty",False),(None,"cache_reuse_requested",True),
                (None,"source_commit","f"*40),(None,"graph_sha256","e"*64),
                ("cleanup","state","unproved"),("query_registration_reservation","verified_after_cleanup",False),
                ("query_registration_reservation","original_entry_monotonic_ns",True),
                ("query_registration_reservation","original_deadline_monotonic_ns",kernel_fixture.witness.deadline+1),
                ("query_registration_reservation","collector_max_seconds",True),
                ("query_registration_reservation","native_runtime_qualified",True),
                ("observed_properties","MemoryMax","4294967296"),("observed_properties","CPUQuotaPerSecUSec","2s"),
                ("observed_properties","RuntimeMaxUSec","1171s"),("observed_properties","NoNewPrivileges","no"),
                ("limits","TasksMax","512"),("isolation","PrivateNetwork","no")):
                changed=copy.deepcopy(receipt);(changed if section is None else changed[section])[key]=value
                re_raw=copy.deepcopy(raw);re_top=copy.deepcopy(top)
                registration_models.rebind(re_top,re_raw,"receipt",changed)
                with self.subTest(section=section,key=key),self.assertRaises(ValueError):
                    collector.validate_success(re_top["candidates"],re_raw,fixture.project,re_top["plan"])

    def test_mixed_output_target_or_evidence_cannot_promote_reserved_metadata(self):
        with tempfile.TemporaryDirectory() as temporary, kernel_models.Fixture() as kernel_fixture:
            fixture=registration_models.Fixture(temporary)
            top,raw,receipt,_=selected_reserved(fixture,kernel_fixture.witness)
            mixed=copy.deepcopy(top)
            mixed["candidates"]["registration"]["path"]=mixed["candidates"]["registration"]["path"].replace(
                reserved.LABEL.split(":")[1],collector.TARGET.split(":")[1])
            with self.assertRaises(ValueError):query.selection(mixed)
            re_raw=copy.deepcopy(raw);re_top=copy.deepcopy(top)
            evidence=collector.json.loads(raw["candidate_evidence"]);evidence["targets"]=[collector.TARGET]
            registration_models.rebind(re_top,re_raw,"evidence",evidence)
            changed=copy.deepcopy(receipt);changed["test_evidence"]["sha256"]=re_top["candidates"]["producer"]["evidence"]["sha256"]
            registration_models.rebind(re_top,re_raw,"receipt",changed)
            with self.assertRaises(ValueError):collector.validate_success(re_top["candidates"],re_raw,fixture.project,re_top["plan"])
            raw_bad=copy.deepcopy(raw);raw_bad["candidate_xml"]+=b" "
            with self.assertRaises(ValueError):collector.validate_success(top["candidates"],raw_bad,fixture.project,top["plan"])

    def test_collector_clock_cannot_reset_outer_deadline_or_borrow_seed_profile(self):
        env={reserved.MODE:reserved.PROFILE,reserved.ENTRY:str(100*10**9),reserved.DEADLINE:str(1300*10**9)}
        self.assertEqual(reserved.collector_deadline(env,200*10**9),math.nextafter(230.0,-math.inf))
        self.assertEqual(reserved.collector_deadline(env,1260*10**9),math.nextafter(1270.0,-math.inf))
        odd={**env,reserved.ENTRY:str(100*10**9+1),reserved.DEADLINE:str(1300*10**9+1)}
        for now in (200*10**9+17,1260*10**9+17):
            cutoff=reserved.collector_deadline(odd,now)
            numerator,denominator=cutoff.as_integer_ratio()
            self.assertLessEqual(numerator*10**9,(1270*10**9+1)*denominator)
            self.assertLessEqual(numerator*10**9,(now+30*10**9)*denominator)
        for now in (99*10**9,1270*10**9,True):
            with self.assertRaises(ValueError):reserved.collector_deadline(env,now)
        for key,value in ((reserved.MODE,kernel.PROFILE),(reserved.ENTRY,"0"),
            (reserved.ENTRY,True),(reserved.DEADLINE,str(1300*10**9+1))):
            with self.assertRaises(ValueError):reserved.collector_deadline({**env,key:value},200*10**9)
        with patch.dict(os.environ,env,clear=True),patch.object(producer.time,"monotonic_ns",return_value=1260*10**9), \
            patch.object(collector,"main") as run:
            producer.main()
            run.assert_called_once_with(absolute_deadline=math.nextafter(1270.0,-math.inf))
        with patch.dict(os.environ,{},clear=True),patch.object(collector,"main") as run,self.assertRaises(ValueError):
            producer.main()
        run.assert_not_called()

    def test_actual_collector_sqlite_and_sealed_fd_publication_use_supplied_cutoff(self):
        for bound,expected in ((None,130.0),(105.0,105.0)):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);fixture=registration_models.Fixture(root)
                project=root/"project";project.mkdir();outputs=root/"outputs";outputs.mkdir()
                paths=[]
                for index,(name,data) in enumerate(fixture.project.items()):
                    path=project/str(index);path.write_bytes(data);paths.append(path)
                argv=["collector","--flake",str(paths[0]),"--lock",str(paths[1]),
                    "--zig-index",str(paths[2]),"--archives",str(paths[3])]
                seen=[]
                def collect(project,deadline,epoch):
                    self.assertEqual(project,fixture.project);seen.append(deadline)
                    return fixture.collect(deadline)
                env={"TEST_UNDECLARED_OUTPUTS_DIR":str(outputs),"TEST_TIMEOUT":"60",
                    "OMUX_EXECUTION_GUARD":collector.COORDINATORS[0]+"/"+registration_models.EPOCH}
                with patch.dict(os.environ,env,clear=True),patch.object(collector.sys,"argv",argv), \
                    patch.object(collector.time,"monotonic",return_value=100.0),patch.object(collector,"collect",side_effect=collect):
                    collector.main(absolute_deadline=bound)
                self.assertEqual(seen,[expected])
                self.assertEqual(sorted(path.name for path in outputs.iterdir()),["query-registration.json","registration","store-paths"])
                self.assertTrue(all(path.stat().st_mode&0o777==0o444 for path in outputs.iterdir()))
        with patch.object(collector.time,"monotonic",return_value=100.0), \
            patch.object(collector,"read_project") as read,patch.object(collector,"collect") as collect, \
            patch.object(collector.sys,"argv",["collector","--flake","f","--lock","l","--zig-index","z","--archives","a"]), \
            patch.dict(os.environ,{"TEST_UNDECLARED_OUTPUTS_DIR":"/model/out","TEST_TIMEOUT":"60"},clear=True):
            for bound in (99.0,float("nan"),True):
                with self.assertRaises(ValueError):collector.main(absolute_deadline=bound)
            read.assert_not_called();collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
