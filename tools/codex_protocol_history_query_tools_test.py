"""Real FD/NAR and supplied-receipt contract models; no Nix/native action.

External evaluation/guard observations are synthetic. They never establish that
six real query roots exist or that a real missing-plan action succeeded.
"""
import copy
import ast
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_protocol_history_query_tools as query
import native_flake_seed_plan_carrier_test as carrier_models
import nar_descriptor as nar
import nix_private_store_seed as seed
import native_flake_sources_test as source_models


class ConsumerDeadlineModels(unittest.TestCase):
    CALLERS = (
        "codex_metadata_query_tools_descriptor_test.py",
        "codex_protocol_history_metadata_producer.py",
        "codex_owner_status_persistence_metadata_producer.py",
        "codex_native_acquisition_metadata.py",
        "codex_protocol_history_sdk_export.py",
        "codex_owner_status_persistence_sdk_export.py",
        "codex_native_acquisition_sdk_export.py",
        "codex_native_acquisition_preflight.py",
        "codex_native_acquisition_compilation.py",
    )

    def test_unmodified_source_admission_refuses_840_and_accepts_retained_600(self):
        # Genuine three-role descriptor and lock; no admission predicate stub.
        content, bundle, _, _ = source_models.NativeFlakeSourcesTest().fixture()
        raw = json.dumps(bundle).encode()
        with patch.object(query.time, "monotonic", return_value=100.0):
            with self.assertRaisesRegex(ValueError, "native-source-deadline"):
                query.sources.admit(content, raw, deadline=940.0)
            deadline = query.consumer_deadline(100.0, 840)
            self.assertEqual(deadline, 700.0)
            admitted = query.sources.admit(content, raw, deadline=deadline)
            self.assertEqual(admitted[3], {"regular/00000000", "regular/00000001", "regular/00000002"})
        with patch.object(query.time, "monotonic", return_value=699.0):
            self.assertEqual(query.sources.admit(content, raw, deadline=deadline)[3], admitted[3])
        with patch.object(query.time, "monotonic", return_value=700.0):
            with self.assertRaisesRegex(ValueError, "native-source-deadline"):
                query.sources.admit(content, raw, deadline=deadline)
            with self.assertRaises(ValueError):query.consumer_deadline(100.0, 840)

    def test_smaller_original_budget_elapsed_entry_and_invalid_values(self):
        with patch.object(query.time, "monotonic", return_value=110.0):
            self.assertEqual(query.consumer_deadline(100.0, 30), 130.0)
            self.assertEqual(query.consumer_deadline(100.0, 840), 700.0)
            for entry, seconds in ((100,840),(True,840),(float('nan'),840),
                    (float('inf'),840),(111.0,840),(-1.0,840),(100.0,0),
                    (100.0,841),(100.0,True),(100.0,600.0),(100.0,10)):
                with self.subTest(entry=entry,seconds=seconds), self.assertRaises(ValueError):
                    query.consumer_deadline(entry,seconds)

    def test_all_consumer_main_prefixes_capture_original_entry_once(self):
        # Execute each actual main's initialization prefix only. The remaining
        # source/query/SDK/compiler body is excluded, not replaced with success.
        for filename in self.CALLERS:
            tree = ast.parse((Path(__file__).parent/filename).read_text())
            main = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'main')
            prefix = []
            for node in main.body:
                if isinstance(node,(ast.Import,ast.ImportFrom)):continue
                prefix.append(node)
                if isinstance(node,ast.Assign) and any(isinstance(call,ast.Call)
                        and isinstance(call.func,ast.Attribute) and call.func.attr == 'consumer_deadline'
                        for call in ast.walk(node.value)):
                    result = ast.parse(ast.unparse(node.targets[0]),mode='eval').body
                    prefix.append(ast.Return(value=result));break
            else:self.fail(filename+' lacks shared consumer deadline initialization')
            main.body = prefix
            namespace = {'os':SimpleNamespace(umask=lambda _:None,environ={'TEST_TIMEOUT':'900'}),
                'sys':SimpleNamespace(argv=['model']), 'time':time, 'float':float, 'query_tools':query,
                'producer':SimpleNamespace(query_tools=query,require=query.require),
                'metadata':SimpleNamespace(query_tools=query), 'require':query.require}
            definition = ast.fix_missing_locations(ast.Module(body=[main],type_ignores=[]))
            exec(compile(definition,'<actual-consumer-entry-prefix>','exec'),namespace)
            for timeout,now,expected in (('900',150.0,700.0),('90',110.0,130.0)):
                namespace['os'].environ['TEST_TIMEOUT']=timeout
                with self.subTest(caller=filename,timeout=timeout), \
                        patch.object(query.time,'monotonic',side_effect=[100.0,now]), \
                        patch.object(query,'consumer_deadline',wraps=query.consumer_deadline) as capture:
                    value=namespace['main']('plan') if main.args.args else namespace['main']()
                    self.assertEqual(value,expected)
                    capture.assert_called_once_with(100.0,min(840,int(timeout)-60))

    def test_actual_metadata_main_final_verifier_refuses_after_original_cutoff(self):
        tree=ast.parse((Path(__file__).parent/'codex_protocol_history_metadata_producer.py').read_text())
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        clock=[100.0];seen=[]
        with tempfile.TemporaryDirectory() as temporary:
            namespace={'os':SimpleNamespace(umask=lambda _:None,environ={'TEST_TIMEOUT':'900',
                    'TEST_TMPDIR':temporary,'TEST_UNDECLARED_OUTPUTS_DIR':temporary}),
                'time':time,'Path':Path,'query_tools':query,'require':query.require,
                'PHASE':'selection','DEADLINE':None,'QUERY_REPOSITORY':None}
            def selection():
                seen.append(namespace['DEADLINE'])
                namespace['QUERY_REPOSITORY']=Path(temporary)
                return {},'model-pin'
            def produced(*args,absolute_deadline):
                seen.append(absolute_deadline);clock[0]=701.0
            namespace.update(declared_selection=selection,produce=produced)
            exec(compile(ast.Module(body=[main],type_ignores=[]),'<actual-metadata-main>','exec'),namespace)
            with patch.object(query.time,'monotonic',side_effect=lambda:clock[0]), \
                    patch.object(query,'consumer_deadline',wraps=query.consumer_deadline) as capture, \
                    patch.object(query,'repository_read',side_effect=AssertionError('expired verifier opened metadata')):
                with self.assertRaises(ValueError):namespace['main']()
                capture.assert_called_once_with(100.0,840)
            self.assertEqual(seen,[700.0,700.0])
            self.assertEqual(namespace['DEADLINE'],700.0)


class BootstrapMetadataModels(unittest.TestCase):
    def methods(self):
        # Execute only actual Python-compatible production function definitions;
        # adapt the Starlark type builtin, never mirror the admission predicate.
        raw=(Path(__file__).parent/'protocol_history_query_tools_repository.bzl').read_text()
        tree=ast.parse(raw)
        selected=[node for node in tree.body if isinstance(node,ast.FunctionDef)
                  and node.name in ('_absolute','_leaf','bootstrap_metadata_shape','_bootstrap_metadata')]
        self.assertEqual(len(selected),4)
        def fail(message):raise ValueError(message)
        namespace={'type':lambda value:'string' if isinstance(value,str) else 'other','fail':fail}
        exec(compile(ast.Module(body=selected,type_ignores=[]),'<actual-bootstrap-metadata-functions>','exec'),namespace)
        return namespace

    def test_actual_role_shape_accepts_closure_info_only_for_paths(self):
        methods=self.methods();shape=methods['bootstrap_metadata_shape']
        native='/nix/store/r43fs1sxk8yrlnga45ww7d2nz855cv23-native.json'
        paths='/nix/store/h3cgn5i0817m39vxpl0bq925gbapv5ma-closure-info/store-paths'
        self.assertTrue(shape('native.json',native));self.assertTrue(shape('store-paths',paths))
        for role,value in (('native.json',paths),('other',paths),('store-paths',paths+'/extra'),
                ('store-paths',paths.replace('closure-info','foreign')),('store-paths',paths.replace('store-paths','registration')),
                ('store-paths',paths.replace('/nix/store/','/other/store/')),('store-paths',paths.replace('h3cgn','ZZZZZ'))):
            with self.subTest(role=role,value=value):self.assertFalse(shape(role,value))

    def test_actual_bootstrap_helper_watches_alias_and_physical_and_operator_leaf_stays_strict(self):
        methods=self.methods()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);physical=root/'store-paths';physical.write_text('/nix/store/model\n')
            alias=root/'alias';alias.symlink_to(physical)
            claimed='/nix/store/h3cgn5i0817m39vxpl0bq925gbapv5ma-closure-info/store-paths'
            class Leaf:
                def __init__(self,path,real):self.path=path;self.realpath=real
                @property
                def exists(self):return self.path.exists()
                @property
                def is_dir(self):return self.path.is_dir()
            class Context:
                def __init__(self):self.watched=[];self.redirect=False
                def path(self,value):
                    if value=='/nix/store/'+'a'*32+'-bootstrap/store-paths':return Leaf(alias,claimed)
                    if value==claimed:return Leaf(physical,claimed if not self.redirect else claimed+'/redirect')
                    raise AssertionError('undeclared path')
                def watch(self,value):self.watched.append(value)
            ctx=Context();logical='/nix/store/'+'a'*32+'-bootstrap/store-paths'
            got=methods['_bootstrap_metadata'](ctx,logical,'store-paths')
            self.assertEqual(got.path.read_text(),'/nix/store/model\n');self.assertEqual(len(ctx.watched),2)
            with self.assertRaises(ValueError):methods['_leaf'](ctx,logical)
            ctx.redirect=True
            with self.assertRaises(ValueError):methods['_bootstrap_metadata'](ctx,logical,'store-paths')
            ctx.redirect=False;physical.unlink();physical.mkdir()
            with self.assertRaises(ValueError):methods['_bootstrap_metadata'](ctx,logical,'store-paths')


class ToolFixture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.roots = sorted({"/".join(path.split("/")[:4]) for path in query.TOOLS.values()} | {query.JAVA})
        self.extra = "/nix/store/"+"b"*32+"-query-reference"
        self.physical, self.objects, self.records = {}, {}, {}
        binaries = {"/".join(path.split("/")[:4]): path.rsplit("/",1)[1] for path in query.TOOLS.values()}
        binaries[query.JAVA] = "java"
        for index, root in enumerate(self.roots+[self.extra]):
            physical = self.directory/str(index);physical.mkdir()
            self.physical[root] = physical
            if root in binaries:
                (physical/"bin").mkdir()
                (physical/"bin"/binaries[root]).write_bytes(b"public modeled tool bytes\n")
                (physical/"bin"/binaries[root]).chmod(0o555)
            else:
                (physical/"runtime").write_bytes(b"public reference bytes\n")
                (physical/"runtime").chmod(0o444)
            descriptor = nar.describe(str(physical));descriptor["root"] = root
            result = nar.hash_descriptor(descriptor,opener=self.opener,deadline=float(time.monotonic()+60))
            refs = [self.extra] if root != self.extra else [self.extra]
            self.records[root] = {"references":refs,"record":[root,result["narHash"],
                str(result["narSize"]),"",str(len(refs)),*refs]}
            self.objects[root] = {"descriptor":descriptor,"regularInputs":{
                node["path"]:{} for node in descriptor["nodes"] if node["type"]=="regular"}}
        self.body = {"derivations":{"/nix/store/"+"c"*32+"-query.drv":{
            "outputs":{str(i):{"path":root} for i,root in enumerate(self.roots)}}}}
        self.descriptor,self.selected = query.choose(self.body,self.records)

    def opener(self, root, relative):
        return nar.open_regular(str(self.physical[root]),relative)

    def verify(self, deadline=None):
        return query.verify_objects(self.descriptor,self.selected,self.objects,self.opener,
            float(time.monotonic()+60) if deadline is None else deadline)


class QueryToolModels(unittest.TestCase):
    def test_full_six_root_reference_closure_rehashes_actual_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            result=fixture.verify()
            self.assertEqual(result["roots"],7)
            self.assertGreater(result["nar_bytes"],0)
            self.assertEqual(fixture.descriptor["tools"],query.TOOLS)
            self.assertIn(fixture.extra,fixture.descriptor["roots"])

    def test_six_roots_must_be_exact_current_graph_outputs_and_registered(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            body=copy.deepcopy(fixture.body)
            row=next(iter(body["derivations"].values()))
            del row["outputs"]["0"]
            with self.assertRaises(ValueError):query.choose(body,fixture.records)
            records=dict(fixture.records);del records[fixture.roots[0]]
            with self.assertRaises(ValueError):query.choose(fixture.body,records)

    def test_same_size_reference_byte_change_fails_complete_nar(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            path=fixture.physical[fixture.extra]/"runtime"
            raw=path.read_bytes();path.chmod(0o600)
            path.write_bytes(b"X"+raw[1:]);path.chmod(0o444)
            with self.assertRaises(ValueError):fixture.verify()

    def test_missing_reference_and_extra_descriptor_fail_before_leaf_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            records=dict(fixture.records);del records[fixture.extra]
            with self.assertRaises((ValueError,KeyError)):query.choose(fixture.body,records)
            objects={**fixture.objects,"/unselected":{}}
            with patch.object(fixture,"opener",side_effect=AssertionError("unexpected payload IO")):
                with self.assertRaises(ValueError):
                    query.verify_objects(fixture.descriptor,fixture.selected,objects,fixture.opener,
                        float(time.monotonic()+60))

    def test_expired_original_deadline_never_gets_new_root_allowance(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            with self.assertRaises(ValueError):fixture.verify(float(time.monotonic()-1))

    def test_executable_link_can_only_resolve_inside_complete_declared_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=ToolFixture(temporary)
            root=fixture.roots[0]
            binary=next(iter((fixture.physical[root]/"bin").iterdir()))
            raw=binary.read_bytes();binary.unlink()
            target=fixture.physical[fixture.extra]/"tool"
            target.write_bytes(raw);target.chmod(0o555)
            binary.symlink_to(fixture.extra+"/tool")
            for selected in (root,fixture.extra):
                descriptor=nar.describe(str(fixture.physical[selected]));descriptor["root"]=selected
                actual=nar.hash_descriptor(descriptor,opener=fixture.opener,deadline=float(time.monotonic()+60))
                fixture.objects[selected]={"descriptor":descriptor,"regularInputs":{
                    node["path"]:{} for node in descriptor["nodes"] if node["type"]=="regular"}}
                row=fixture.records[selected]["record"]
                row[1:3]=[actual["narHash"],str(actual["narSize"])]
            fixture.verify()
            descriptor=copy.deepcopy(fixture.objects[root]["descriptor"])
            for node in descriptor["nodes"]:
                if node["type"]=="symlink":node["target"]="/outside/tool"
            fixture.objects[root]["descriptor"]=descriptor
            actual=nar.hash_descriptor(descriptor,opener=fixture.opener,deadline=float(time.monotonic()+60))
            fixture.records[root]["record"][1:3]=[actual["narHash"],str(actual["narSize"])]
            with self.assertRaises(ValueError):fixture.verify()

    def test_repository_metadata_redirect_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/"metadata.json"
            path.write_bytes(b"public");path.chmod(0o444)
            self.assertEqual(query.repository_read(root,"metadata.json",100,float(time.monotonic()+60)),b"public")
            path.rename(root/"original");path.symlink_to(root/"original")
            with self.assertRaises(ValueError):
                query.repository_read(root,"metadata.json",100,float(time.monotonic()+60))

    def test_repository_metadata_same_byte_inode_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/"metadata.json"
            path.write_bytes(b"public");path.chmod(0o444)
            calls=[];tick=query.proof.tick
            def replace(deadline):
                tick(deadline);calls.append(None)
                if len(calls)==3:
                    path.rename(root/"original")
                    path.write_bytes(b"public");path.chmod(0o444)
            with patch.object(query.proof,"tick",side_effect=replace):
                with self.assertRaises(ValueError):
                    query.repository_read(root,"metadata.json",100,float(time.monotonic()+60))

    def test_unconfigured_repository_cannot_claim_qualified_byte_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/"query-tools-unconfigured.json").write_text('{"configured":false}\n')
            with self.assertRaises(OSError):query.verify_repository(root,float(time.monotonic()+60))

    def test_actual_declared_alias_nar_readback_requires_all_pinned_tool_bytes(self):
        # Outer producer lineage is deliberately injected here. Alias opening,
        # metadata byte pins, six-root selection and full NARs are real methods.
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);physical=directory/"physical";physical.mkdir()
            fixture=ToolFixture(physical);repository=directory/"repository";repository.mkdir()
            (repository/"metadata").mkdir();(repository/"regular").mkdir()
            top=self.selection();top["inputs"]["sha256"]=seed.sha(b"{}")
            selected={};expected={"seed_selection":top["inputs"]}
            (repository/"metadata/00000000").write_bytes(b"{}")
            (repository/"metadata/00000000").chmod(0o444)
            objects=copy.deepcopy(fixture.objects);index=0
            for root,row in sorted(objects.items()):
                for relative in sorted(row["regularInputs"]):
                    source=root+"/"+relative;alias="regular/"+str(index).zfill(8);index+=1
                    row["regularInputs"][relative]={"source":source,"alias":alias}
                    (repository/alias).symlink_to(source)
            bundle={"schema_version":1,"kind":query.KIND,"selection_sha256":seed.sha(query.inputs.encode(top)),
                "query_tools":fixture.descriptor,"metadata":{"seed_selection":{
                    "alias":"metadata/00000000","pin":top["inputs"]}},"objects":objects}
            raw=query.inputs.encode(bundle);path=repository/"query-inputs.json";path.write_bytes(raw)
            original=nar.open_regular
            def open_model(root,relative):
                for logical,physical_root in fixture.physical.items():
                    if root==logical or root.startswith(logical+"/"):
                        member=root[len(logical):].lstrip("/")
                        return original(str(physical_root),"/".join(part for part in (member,relative) if part))
                return original(root,relative)
            with patch.object(query.inputs,"selection",return_value=selected),patch.object(query,"roles",
                    return_value=expected),patch.object(query,"lineage",return_value=fixture.body),patch.object(
                    query,"candidate_records",return_value=fixture.records),patch.object(nar,"open_regular",
                    side_effect=open_model),patch("verify_declared_nars.open_regular",side_effect=open_model):
                def qualify():
                    return query.qualify(query.inputs.encode(top),seed.sha(query.inputs.encode(top)),raw,
                        seed.sha(raw),path,b"",b"",{},b"",{},float(time.monotonic()+60))
                report=qualify()
                self.assertIs(report["inputs_rechecked"],True)
                self.assertEqual(report["counts"]["roots"],7)
                self.assertTrue(all(report[name] is False for name in ("realized","complete_build_seed_verified",
                    "sdk_qualified","native_runtime_qualified","execution_authority")))
                node=fixture.physical[fixture.extra]/"runtime"
                old=node.read_bytes();node.chmod(0o600);node.write_bytes(b"X"+old[1:]);node.chmod(0o444)
                with self.assertRaises(ValueError):qualify()

    def test_unknown_metadata_role_refuses_before_referenced_opener(self):
        # Pre-IO shape gate; no physical source/tool namespace is inspected.
        top=self.selection()
        bundle={"schema_version":1,"kind":query.KIND,"selection_sha256":seed.sha(query.inputs.encode(top)),
            "query_tools":{},"metadata":{"seed_selection":{"alias":"metadata/00000000","pin":top["inputs"]},
                "outside":{"alias":"metadata/00000001","pin":top["inputs"]}},"objects":{}}
        raw=query.inputs.encode(bundle)
        selected={"producer":{"receipt":{}}}
        with patch.object(query.inputs,"selection",return_value=selected),patch.object(query,"roles",
                return_value={"seed_selection":top["inputs"]}),patch.object(query,"metadata_alias_roots",
                return_value=[]),patch.object(query,"open_declared") as opened:
            opened.return_value.__enter__.return_value.read.side_effect=[b"{}",b""]
            with self.assertRaises(ValueError):
                query.qualify(query.inputs.encode(top),seed.sha(query.inputs.encode(top)),raw,seed.sha(raw),
                    Path("/public/query-inputs.json"),b"",b"",{},b"",{},float(time.monotonic()+60))
            self.assertEqual(opened.call_count,1)

    def selection(self):
        parent=query.inputs.COORDINATORS[0]+"/00000000-0000-4000-8000-000000000002"
        pin=lambda path:{"path":path,"sha256":seed.sha(b"{}"),"bytes":2}
        return {"schema_version":1,"kind":query.SELECTION_KIND,
            "inputs":pin(parent+"/native-flake-seed-plan-selection.json"),
            "plan":{"receipt":pin(parent+"/receipt.json"),"evidence":pin(parent+"/test-evidence.json"),
                "log":pin(parent+"/test-evidence/"+"a"*64+".evidence"),
                "xml":pin(parent+"/test-evidence/"+"b"*64+".evidence"),
                "result":pin(parent+"/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                    +"native_flake_seed_plan_qualification/test.outputs/native-flake-seed-plan.json"),
                "source_commit":"c"*40,"graph_sha256":"d"*64},
            "candidates":{"registration":pin("/nix/store/"+"b"*32+"-candidate/registration"),
                "paths":pin("/nix/store/"+"b"*32+"-candidate/store-paths")}}

    def test_closed_selector_rejects_unknown_private_roles_without_io(self):
        top=self.selection();self.assertIs(query.selection(top),top)
        for change in ({"extra":True},{"candidates":None},
                {"inputs":{**top["inputs"],"path":"/private/factor"}}):
            with self.assertRaises(ValueError):query.selection({**top,**change})


class ReservedPlanModels(unittest.TestCase):
    def plan(self, fixture):
        fixture.generate()
        report=fixture.qualify()
        epoch="00000000-0000-4000-8000-000000000002"
        parent=fixture.coordination/epoch
        target=parent/"output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_seed_plan_qualification/test.outputs/native-flake-seed-plan.json"
        entry=10**9;deadline=entry+1200*10**9;work=entry+600*10**9
        report.update(platform={"nonroot":True,"no_new_privileges":True,"effective_capabilities_empty":True},
            guard_epoch=epoch,original_entry_monotonic_ns=entry,original_work_deadline_monotonic_ns=work,
            declared_files_rechecked=True,producer_implementation_rechecked=True,
            reserved_execution_envelope={"profile":"native-seed-plan-reserved",
                "original_entry_monotonic_ns":entry,"original_deadline_monotonic_ns":deadline,
                "outer_work_deadline_monotonic_ns":deadline-30*10**9,
                "private_cleanup_deadline_monotonic_ns":work+30*10**9})
        raw={"plan_result":query.inputs.encode(report),"plan_log":b"modeled bounded plan log\n",
            "plan_xml":b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>\n',
            # The real declared query input bundle includes the entire producer
            # role map, including obligations and any selected candidates.
            **{"producer_"+name:fixture.raw[name] for name in query.inputs.metadata_roles(fixture.selected)}}
        pin=lambda path,data:{"path":str(path),"sha256":seed.sha(data),"bytes":len(data)}
        plan={name:pin(parent/"test-evidence"/(seed.sha(raw["plan_"+name])+".evidence"),raw["plan_"+name])
            for name in ("log","xml")}
        plan["result"]=pin(target,raw["plan_result"])
        evidence={"schema":1,"bazel_exit":0,"epoch_start_ns":2,"targets":[query.TARGET],
            "results":[{"target":query.TARGET,"state":"observed","files":[
                {"source":"test."+name,"state":"copied","file":Path(plan[name]["path"]).name,
                    "sha256":plan[name]["sha256"],"bytes":plan[name]["bytes"]} for name in ("log","xml")]}]}
        raw["plan_evidence"]=query.inputs.encode(evidence)
        resident={"scope":"sampled-fixed-default-cgroup-kernel-reservation-v1",
            "kernel_bounds":{"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"},
            "observations":1,"initial_direct_processes_retained":True,"initial_direct_process_count":1,
            "outer_pid_namespace_matched":True,"hierarchical_caps":True,
            **{name:False for name in ("descendant_process_inventory","installation_qualified","health_observed",
                "custody_observed","resident_signalled","whole_host_reservation")}}
        receipt={"id":epoch,"artifact_epoch":epoch,"unit":"omux-execution-"+epoch+".service",
            "profile":"native-seed-plan-reserved","manager":"system","verb":"test","targets":[query.TARGET],
            "exit":0,"workload_exit":0,"controller_failure":None,"descendants_empty":True,
            "cleanup":{"state":"empty"},"source_dirty":"false","cache_reuse_requested":False,
            "source_commit":"c"*40,"graph_sha256":"d"*64,
            "epoch_start_ns":2,"output_base":str(parent/"output-base"),
            "test_evidence":{"state":"preserved","sha256":seed.sha(raw["plan_evidence"])},
            "observed_properties":{**query.inputs.RESOURCE_PROPERTIES,"MemoryMax":"4026531840","TasksMax":"480",
                "CPUQuotaPerSecUSec":"1.900000s","RuntimeMaxUSec":"20min"},
            "native_seed_plan_reservation":{"scope":"native-seed-plan-reserved-v1","mode":"qualification",
                "verified_after_cleanup":True,"seed_qualification":False,
                "seed_qualification_requires_matching_outer_success":True,"native_runtime_qualified":False,
                "complete_build_seed_qualified":False,"resident":resident,
                "original_entry_monotonic_ns":entry,"original_deadline_monotonic_ns":deadline}}
        raw["plan_receipt"]=query.inputs.encode(receipt)
        plan.update(receipt=pin(parent/"receipt.json",raw["plan_receipt"]),
            evidence=pin(parent/"test-evidence.json",raw["plan_evidence"]),source_commit="c"*40,graph_sha256="d"*64)
        top={"schema_version":1,"kind":query.SELECTION_KIND,
            "inputs":pin(fixture.epoch/"native-flake-seed-plan-selection.json",fixture.selected_raw),
            "plan":plan,"candidates":{"registration":pin("/nix/store/"+"b"*32+"-candidate/registration",b"metadata"),
                "paths":pin("/nix/store/"+"b"*32+"-candidate/store-paths",b"metadata")}}
        records=query.restored.producer_objects(fixture.model.body,query.decode(fixture.model.runtime_raw,seed.MAX_METADATA))
        return top,raw,receipt,report,records

    def test_real_method_plan_report_and_numeric_cpu_join(self):
        with tempfile.TemporaryDirectory() as directory,carrier_models.JoinedFixture(directory) as fixture:
            top,raw,receipt,report,records=self.plan(fixture)
            self.assertEqual(query.plan_success(top,fixture.selected,raw,fixture.model.body,records),report)
            for cpu in ("1.900001s","1899999us"):
                bad=copy.deepcopy(receipt);bad["observed_properties"]["CPUQuotaPerSecUSec"]=cpu
                with self.assertRaises(ValueError):
                    query.plan_success(top,fixture.selected,{**raw,"plan_receipt":query.inputs.encode(bad)},
                        fixture.model.body,records)

    def test_reserved_output_must_be_own_epoch_with_literal_no_cache_reuse(self):
        with tempfile.TemporaryDirectory() as directory,carrier_models.JoinedFixture(directory) as fixture:
            top,raw,receipt,report,records=self.plan(fixture)
            for value in (True,0,"false"):
                bad=copy.deepcopy(receipt);bad["cache_reuse_requested"]=value
                with self.assertRaises(ValueError):
                    query.plan_success(top,fixture.selected,{**raw,"plan_receipt":query.inputs.encode(bad)},
                        fixture.model.body,records)
            for base in (fixture.coordination/("cache-v2-"+"a"*64)/"output-base",
                    fixture.coordination/"00000000-0000-4000-8000-000000000003"/"output-base"):
                bad=copy.deepcopy(receipt);bad["output_base"]=str(base)
                selected=copy.deepcopy(top)
                selected["plan"]["result"]["path"]=str(base)+"/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_seed_plan_qualification/test.outputs/native-flake-seed-plan.json"
                # Supply rewritten matching result/receipt pins: exact UUID
                # namespace, not a stale byte-pin accident, must reject this.
                changed_raw=query.inputs.encode(bad)
                selected["plan"]["receipt"].update(sha256=seed.sha(changed_raw),bytes=len(changed_raw))
                with self.assertRaises(ValueError):query.selection(selected)
                with self.assertRaises(ValueError):
                    query.plan_success(selected,fixture.selected,{**raw,"plan_receipt":changed_raw},
                        fixture.model.body,records)

    def test_failed_bool_epoch_clock_resident_or_claim_cannot_supply_tools(self):
        with tempfile.TemporaryDirectory() as directory,carrier_models.JoinedFixture(directory) as fixture:
            top,raw,receipt,report,records=self.plan(fixture)
            cases=[]
            for name,value in (("exit",False),("workload_exit",125),("descendants_empty",False),
                    ("artifact_epoch","00000000-0000-4000-8000-000000000003")):
                bad=copy.deepcopy(receipt);bad[name]=value;cases.append(bad)
            for name,value in (("original_entry_monotonic_ns",True),("verified_after_cleanup",False),
                    ("complete_build_seed_qualified",True)):
                bad=copy.deepcopy(receipt);bad["native_seed_plan_reservation"][name]=value;cases.append(bad)
            bad=copy.deepcopy(receipt);bad["native_seed_plan_reservation"]["resident"]["whole_host_reservation"]=True
            cases.append(bad)
            for bad in cases:
                with self.assertRaises(ValueError):
                    query.plan_success(top,fixture.selected,{**raw,"plan_receipt":query.inputs.encode(bad)},
                        fixture.model.body,records)
            for change in ({"realized":True},{"plan":{**report["plan"],"unknown":["/unselected"]}},
                    {"platform":{"nonroot":1,"no_new_privileges":True,"effective_capabilities_empty":True}}):
                bad={**report,**change}
                with self.assertRaises(ValueError):
                    query.plan_success(top,fixture.selected,{**raw,"plan_result":query.inputs.encode(bad)},
                        fixture.model.body,records)


if __name__=="__main__":
    unittest.main()
