"""Disposable SQLite, supplied receipt and real byte-proof models only."""
import base64
import copy
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import cached_nix_inventory as cached
import codex_query_registration as collector
import codex_protocol_history_query_tools as query
import codex_protocol_history_query_tools_test as query_models

EPOCH="00000000-0000-4000-8000-000000000003"


class Fixture:
    def __init__(self,directory):
        self.directory=Path(directory)
        self.database=self.directory/"public.sqlite"
        self.project={name:("public "+name+"\n").encode() for name in collector.PROJECT_FILES}
        self.paths=list(collector.TOOL_ROOTS)+["/nix/store/"+"b"*32+"-query-shared"]
        self.paths.sort()
        connection=sqlite3.connect(self.database)
        try:
            connection.execute("CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY,path TEXT,hash TEXT,narSize INTEGER)")
            connection.execute("CREATE TABLE Refs(referrer INTEGER,reference INTEGER)")
            for index,path in enumerate(self.paths):
                digest="sha256:"+("a" if index%2 else "b")*64
                connection.execute("INSERT INTO ValidPaths VALUES(?,?,?,?)",(index,path,digest,index+100))
            child=self.paths.index("/nix/store/"+"b"*32+"-query-shared")
            for index in range(len(self.paths)):
                connection.execute("INSERT INTO Refs VALUES(?,?)",(index,child))
            connection.commit()
        finally:connection.close()

    def collect(self,deadline=None):
        # External fixed public DB ancestry is synthetic here. The SQLite
        # transaction, exact rows, references and registration parser are real.
        with patch.object(collector,"database_scope"):
            return collector.collect(self.project,float(time.monotonic()+30) if deadline is None else deadline,EPOCH,
                database=self.database,exists=lambda path:path in self.paths)

    def execute_sql(self,statement,values=()):
        connection=sqlite3.connect(self.database)
        try:connection.execute(statement,values);connection.commit()
        finally:connection.close()


def selected_candidate(fixture):
    report,registration,paths=fixture.collect()
    raw={"candidate_report":collector.encode(report),"candidate_registration":registration,"candidate_paths":paths,
        "candidate_log":b"public fixed metadata test log\n",
        "candidate_xml":b'<testsuite tests="1" errors="0" failures="0" skipped="0"/>\n'}
    parent=query.inputs.COORDINATORS[0]+"/"+EPOCH
    pin=lambda path,data:{"path":str(path),"bytes":len(data),"sha256":collector.sha(data)}
    producer={name:pin(parent+"/test-evidence/"+collector.sha(raw["candidate_"+name])+".evidence",
        raw["candidate_"+name]) for name in ("log","xml")}
    evidence={"schema":1,"bazel_exit":0,"epoch_start_ns":7,"targets":[collector.TARGET],
        "results":[{"target":collector.TARGET,"state":"observed","files":[
            {"source":"test."+name,"state":"copied","file":Path(producer[name]["path"]).name,
                "sha256":producer[name]["sha256"],"bytes":producer[name]["bytes"]} for name in ("log","xml")]}]}
    raw["candidate_evidence"]=collector.encode(evidence)
    receipt={"id":EPOCH,"artifact_epoch":EPOCH,"unit":"omux-execution-"+EPOCH+".service",
        "profile":"standard","manager":"system","verb":"test","targets":[collector.TARGET],
        "exit":0,"workload_exit":0,"controller_failure":None,"descendants_empty":True,
        "cleanup":{"state":"empty"},"source_dirty":"false","cache_reuse_requested":False,
        "output_base":parent+"/output-base","source_commit":"c"*40,"graph_sha256":"d"*64,
        "epoch_start_ns":7,"test_evidence":{"state":"preserved","sha256":collector.sha(raw["candidate_evidence"])},
        "observed_properties":{**query.inputs.RESOURCE_PROPERTIES,"CPUQuotaPerSecUSec":"2.000000s",
            "NoNewPrivileges":"yes","CapabilityBoundingSet":"","AmbientCapabilities":"",
            "RuntimeMaxUSec":"20min"}}
    raw["candidate_receipt"]=collector.encode(receipt)
    producer.update(receipt=pin(parent+"/receipt.json",raw["candidate_receipt"]),
        evidence=pin(parent+"/test-evidence.json",raw["candidate_evidence"]),
        source_commit="c"*40,graph_sha256="d"*64)
    output=parent+"/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"+collector.TARGET.split(":")[1]+"/test.outputs/"
    candidate={"kind":collector.CANDIDATE_KIND,"producer":producer}
    for name,leaf in (("registration","registration"),("paths","store-paths"),("report","query-registration.json")):
        candidate[name]=pin(output+leaf,raw["candidate_"+name])
    top=query_models.QueryToolModels().selection();top["candidates"]=candidate
    return top,raw,receipt,report


def rebind(top,raw,name,value):
    key="candidate_"+name;raw[key]=collector.encode(value)
    pin=top["candidates"]["producer"][name] if name in ("receipt","evidence","log","xml") else top["candidates"][name]
    pin.update(bytes=len(raw[key]),sha256=collector.sha(raw[key]))


class RegistrationModels(unittest.TestCase):
    def test_fixed_roots_reference_cycle_snapshot_is_readonly_and_provisional(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);before=fixture.database.read_bytes()
            report,registration,paths=fixture.collect()
            records=collector.validate_report(report,registration,paths,fixture.project,EPOCH)
            self.assertEqual(fixture.database.read_bytes(),before)
            self.assertEqual(len(records),7)
            self.assertEqual(report["tool_roots"],list(collector.TOOL_ROOTS))
            self.assertEqual(report["guard_epoch"],EPOCH)
            for name in ("content_rehashed","nar_verified","query_tools_qualified","realized",
                    "complete_build_seed_verified","native_runtime_qualified","sdk_qualified","execution_authority"):
                self.assertIs(report[name],False)

    def test_missing_fixed_root_is_explicit_before_database_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary)
            with patch.object(cached,"snapshot_inventory",side_effect=AssertionError("unexpected DB IO")):
                with self.assertRaises(collector.MissingRoots) as caught:
                    collector.collect(fixture.project,float(time.monotonic()+30),EPOCH,
                        database=fixture.database,exists=lambda root:root!=collector.TOOL_ROOTS[0])
            self.assertEqual(caught.exception.roles,["python"])

    def test_absent_registration_and_unresolved_reference_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary)
            fixture.execute_sql("DELETE FROM ValidPaths WHERE path=?",(collector.TOOL_ROOTS[0],))
            with self.assertRaises(ValueError):fixture.collect()
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary)
            fixture.execute_sql("INSERT INTO Refs VALUES(0,999)")
            with self.assertRaises(ValueError):fixture.collect()

    def test_sri_hash_normalizes_to_canonical_registration_wire(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary)
            sri="sha256-"+base64.b64encode(bytes(range(32))).decode()
            fixture.execute_sql("UPDATE ValidPaths SET hash=? WHERE path=?",(sri,collector.TOOL_ROOTS[0]))
            report,registration,paths=fixture.collect()
            records=collector.validate_report(report,registration,paths,fixture.project,EPOCH)
            self.assertEqual(records[collector.TOOL_ROOTS[0]]["record"][1],"sha256:"+bytes(range(32)).hex())

    def test_invalid_hash_and_zero_or_overflow_size_refuse(self):
        for field,value in (("hash","sha256:bad"),("narSize",0),("narSize",collector.MAX_BYTES+1)):
            with tempfile.TemporaryDirectory() as temporary:
                fixture=Fixture(temporary)
                fixture.execute_sql("UPDATE ValidPaths SET "+field+"=? WHERE path=?",(value,collector.TOOL_ROOTS[0]))
                with self.assertRaises(ValueError):fixture.collect()

    def test_bool_size_and_reference_or_output_bounds_are_not_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary)
            rows=cached.snapshot_inventory(fixture.database,fixture.paths,exists=lambda root:root in fixture.paths)
            rows[0]["narSize"]=True
            with self.assertRaises(ValueError):collector.normalize(rows,float(time.monotonic()+30))
            rows[0]["narSize"]=100
            rows[0]["references"]=[fixture.paths[0]]*4097
            with self.assertRaises(ValueError):collector.normalize(rows,float(time.monotonic()+30))
            report,registration,paths=fixture.collect()
            with self.assertRaises(ValueError):
                collector.validate_report(report,b"x"*(collector.MAX_OUTPUT+1),paths,fixture.project,EPOCH)
            bad=copy.deepcopy(report);bad["counts"]["roots"]=True
            with self.assertRaises(ValueError):collector.validate_report(bad,registration,paths,fixture.project,EPOCH)

    def test_original_absolute_clock_reaches_snapshot_unchanged_and_expiry_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);deadline=float(time.monotonic()+30)
            original=cached.snapshot_inventory;seen=[]
            def snapshot(*args,**kwargs):
                seen.append(kwargs["absolute_deadline"]);return original(*args,**kwargs)
            with patch.object(cached,"snapshot_inventory",side_effect=snapshot):fixture.collect(deadline)
            self.assertEqual(seen,[deadline])
            with patch.object(cached,"snapshot_inventory",side_effect=AssertionError("unexpected IO")):
                with self.assertRaises(ValueError):fixture.collect(float(time.monotonic()-1))
            for deadline in (True,float("inf"),float(time.monotonic()+31)):
                with self.assertRaises(ValueError):
                    cached.snapshot_inventory(fixture.database,fixture.paths,absolute_deadline=deadline)

    def test_metadata_database_redirection_refuses_before_sqlite(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);alias=Path(temporary)/"alias";alias.symlink_to(fixture.database)
            with patch.object(cached.sqlite3,"connect",side_effect=AssertionError("unexpected DB IO")):
                with self.assertRaises(ValueError):
                    collector.collect(fixture.project,float(time.monotonic()+30),EPOCH,database=alias,exists=lambda root:True)


    def test_sqlite_setup_failure_still_closes_the_own_connection(self):
        from unittest.mock import Mock
        connection=Mock();connection.execute.side_effect=sqlite3.OperationalError("modeled setup refusal")
        with patch.object(cached.sqlite3,"connect",return_value=connection):
            with self.assertRaises(sqlite3.OperationalError):
                cached.snapshot_inventory(Path("/public/db"),list(collector.TOOL_ROOTS))
        connection.close.assert_called_once_with()

    def test_persisted_metadata_files_are_exclusive_and_byte_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            values={"query-registration.json":b"{}\n","registration":b"public\n","store-paths":b"public\n"}
            collector.persist(root,values,float(time.monotonic()+30))
            for name,raw in values.items():
                self.assertEqual((root/name).read_bytes(),raw)
                self.assertEqual((root/name).stat().st_mode&0o777,0o444)
            with self.assertRaises(FileExistsError):
                collector.persist(root,values,float(time.monotonic()+30))


    def test_late_final_fsync_or_directory_close_refuses_original_deadline(self):
        for fault in ("fsync","close"):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);clock=[10.0];calls=[0]
                original=getattr(collector.os,fault)
                def late(fd):
                    calls[0]+=1
                    result=original(fd)
                    if (fault=="fsync" and calls[0]==4) or fault=="close":clock[0]=41.0
                    return result
                values={"query-registration.json":b"{}\n","registration":b"public\n","store-paths":b"public\n"}
                with patch.object(collector.time,"monotonic",side_effect=lambda:clock[0]),patch.object(
                        collector.os,fault,side_effect=late):
                    with self.assertRaises(ValueError):collector.persist(root,values,40.0)
                self.assertGreater(calls[0],0)
                self.assertEqual(len(list(root.iterdir())),3)

    def test_optional_sqlite_busy_budget_reference_iteration_and_release_use_original_clock(self):
        from unittest.mock import Mock
        root=collector.TOOL_ROOTS[0];clock=[10.0];connection=Mock()
        metadata=Mock();metadata.fetchone.return_value=(1,"sha256:"+"a"*64,100)
        refs=Mock()
        def cursor():
            yield (root,)
            clock[0]=11.0
            yield (root,)
        refs.__iter__=Mock(side_effect=cursor)
        def execute(statement,*args):
            if statement.startswith("SELECT id"):return metadata
            if statement.startswith("SELECT v.path"):return refs
            return Mock()
        connection.execute.side_effect=execute
        with patch.object(cached.time,"monotonic",side_effect=lambda:clock[0]),patch.object(
                cached.sqlite3,"connect",return_value=connection) as connected:
            with self.assertRaises(ValueError):
                cached.snapshot_inventory(Path("/public/db"),[root],exists=lambda path:True,absolute_deadline=10.25)
        self.assertEqual(connected.call_args.kwargs["timeout"],0.25)
        connection.close.assert_called_once_with()
        self.assertTrue(any(call.args[0]=="PRAGMA busy_timeout=250" for call in connection.execute.call_args_list))

    def test_optional_snapshot_rechecks_after_own_connection_close(self):
        from unittest.mock import Mock
        root=collector.TOOL_ROOTS[0];clock=[10.0];connection=Mock()
        metadata=Mock();metadata.fetchone.return_value=(1,"sha256:"+"a"*64,100)
        refs=Mock();refs.__iter__=Mock(return_value=iter([]))
        def execute(statement,*args):
            if statement.startswith("SELECT id"):return metadata
            if statement.startswith("SELECT v.path"):return refs
            return Mock()
        connection.execute.side_effect=execute
        connection.close.side_effect=lambda:clock.__setitem__(0,41.0)
        with patch.object(cached.time,"monotonic",side_effect=lambda:clock[0]),patch.object(
                cached.sqlite3,"connect",return_value=connection):
            with self.assertRaises(ValueError):
                cached.snapshot_inventory(Path("/public/db"),[root],exists=lambda path:True,absolute_deadline=40.0)
        connection.close.assert_called_once_with()


    def test_fixed_public_database_permissions_refuse_writable_or_nonroot_sidecar_context(self):
        from types import SimpleNamespace
        import stat
        db=Path("/public-root/db.sqlite")
        def info(path):
            if str(path).endswith(("-wal","-shm")):raise FileNotFoundError
            return SimpleNamespace(st_uid=0,st_mode=(stat.S_IFREG|0o644 if path==db else stat.S_IFDIR|0o755),
                st_nlink=1)
        with patch.object(Path,"resolve",lambda self,**kwargs:self),patch.object(collector.os,"getuid",return_value=1000):
            with patch.object(collector.os,"lstat",side_effect=info):
                collector.database_scope(db)
            for bad in (SimpleNamespace(st_uid=1000,st_mode=stat.S_IFREG|0o644,st_nlink=1),
                        SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o664,st_nlink=1),
                        SimpleNamespace(st_uid=0,st_mode=stat.S_IFLNK|0o777,st_nlink=1)):
                def altered(path):
                    if str(path)==str(db)+"-shm":return bad
                    return info(path)
                with patch.object(collector.os,"lstat",side_effect=altered):
                    with self.assertRaises(ValueError):collector.database_scope(db)
            def owned(path):
                if path==db:return SimpleNamespace(st_uid=1000,st_mode=stat.S_IFREG|0o644,st_nlink=1)
                return info(path)
            with patch.object(collector.os,"lstat",side_effect=owned):
                with self.assertRaises(ValueError):collector.database_scope(db)
        with patch.object(collector.os,"getuid",return_value=0),patch.object(
                collector.os,"lstat",side_effect=AssertionError("unexpected privileged DB IO")):
            with self.assertRaises(ValueError):collector.database_scope(db)

    def test_privileged_producer_or_unqualified_reader_context_cannot_supply_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);original,original_raw,receipt,report=selected_candidate(fixture)
            for name,value in (("NoNewPrivileges","no"),("CapabilityBoundingSet","cap_dac_override"),
                    ("AmbientCapabilities","cap_dac_override")):
                top=copy.deepcopy(original);raw=dict(original_raw);bad=copy.deepcopy(receipt)
                bad["observed_properties"][name]=value;rebind(top,raw,"receipt",bad)
                with self.assertRaises(ValueError):query.candidate_records(top,raw,fixture.project)
            top=copy.deepcopy(original);raw=dict(original_raw);bad=copy.deepcopy(report)
            bad["reader_context"]["root_owned_nonwritable_ancestry"]=False
            rebind(top,raw,"report",bad)
            with self.assertRaises(ValueError):query.candidate_records(top,raw,fixture.project)

    def test_query_root_constants_and_declared_project_scope_match(self):
        self.assertEqual(collector.TOOL_ROOTS,tuple(sorted({"/".join(path.split("/")[:4])
            for path in query.TOOLS.values()}|{query.JAVA})))
        self.assertEqual(collector.PROJECT_FILES,query.FILES)
        with self.assertRaises(ValueError):collector.guard_epoch("/private/receipt.json")
        self.assertEqual(collector.guard_epoch(query.inputs.COORDINATORS[0]+"/"+EPOCH),EPOCH)


class ProducerJoinModels(unittest.TestCase):
    def test_genuine_supplied_metadata_output_namespace_and_full_role_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);top,raw,receipt,report=selected_candidate(fixture)
            self.assertIs(query.selection(top),top)
            records=query.candidate_records(top,raw,fixture.project)
            self.assertEqual(len(records),7)
            with patch.object(query.inputs,"metadata_roles",return_value={}):
                roles=query.roles(top,{})
            self.assertEqual({name for name in roles if name.startswith("candidate_")},set(raw))

    def test_foreign_epoch_cache_or_controller_identity_cannot_supply_registration(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);original,original_raw,receipt,report=selected_candidate(fixture)
            for base in (query.inputs.COORDINATORS[0]+"/cache-v2-"+"a"*64+"/output-base",
                    query.inputs.COORDINATORS[0]+"/00000000-0000-4000-8000-000000000004/output-base"):
                top=copy.deepcopy(original);top["candidates"]["registration"]["path"]=base+"/registration"
                with self.assertRaises(ValueError):query.selection(top)
            for key,value in (("cache_reuse_requested",True),("cache_reuse_requested",0),
                    ("source_commit","e"*40),("graph_sha256","f"*64),("artifact_epoch","foreign"),
                    ("profile","native-seed-plan-reserved"),("exit",False),("descendants_empty",False)):
                top=copy.deepcopy(original);raw=dict(original_raw);bad=copy.deepcopy(receipt);bad[key]=value
                rebind(top,raw,"receipt",bad)
                with self.assertRaises(ValueError):query.candidate_records(top,raw,fixture.project)

    def test_copied_evidence_xml_and_literal_false_claims_remain_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(temporary);original,original_raw,receipt,report=selected_candidate(fixture)
            for change in ({"nar_verified":True},{"guard_epoch":"00000000-0000-4000-8000-000000000004"},
                    {"project_sha256":{**report["project_sha256"],"flake.lock":"a"*64}}):
                top=copy.deepcopy(original);raw=dict(original_raw);rebind(top,raw,"report",{**report,**change})
                with self.assertRaises(ValueError):query.candidate_records(top,raw,fixture.project)
            top=copy.deepcopy(original);raw=dict(original_raw)
            evidence=copy.deepcopy(query.decode(raw["candidate_evidence"]))
            evidence["results"][0]["files"][0]["state"]="missing";rebind(top,raw,"evidence",evidence)
            bad=copy.deepcopy(receipt);bad["test_evidence"]["sha256"]=top["candidates"]["producer"]["evidence"]["sha256"]
            rebind(top,raw,"receipt",bad)
            with self.assertRaises(ValueError):query.candidate_records(top,raw,fixture.project)

    def test_provisional_snapshot_never_waives_real_nar_byte_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=query_models.ToolFixture(temporary);fixture.verify()
            file=fixture.physical[fixture.extra]/"runtime";raw=file.read_bytes()
            file.chmod(0o600);file.write_bytes(b"X"+raw[1:]);file.chmod(0o444)
            with self.assertRaises(ValueError):fixture.verify()


if __name__=="__main__":
    unittest.main()
