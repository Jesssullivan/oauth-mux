"""Metadata orchestration models; no generator/native success is fabricated."""
import json
from contextlib import ExitStack
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import codex_live_source as source
import codex_live_source_test as source_models
import codex_protocol_history_source as history
import codex_protocol_history_metadata as metadata
import codex_protocol_history_metadata_producer as producer


class ProtocolHistoryMetadataTests(unittest.TestCase):
    def hub(self):
        row={"aliases":{metadata.ROLLOUT:"codex_rollout",metadata.HISTORY:"codex_history"},
            "binaries":{},"build_deps":[],"build_deps_by_platform":{},
            "crate_features":[],"crate_features_by_platform":{},
            "deps":[metadata.HISTORY,metadata.ROLLOUT],"deps_by_platform":{},
            "dev_deps":[],"dev_deps_by_platform":{},"shared_libraries":{}}
        data={metadata.PACKAGE:row,"codex-rs/core":{**row,"deps":[metadata.ROLLOUT]}}
        return {"BUILD.bazel":b"retained generated aliases\n",
            "defs.bzl":b"retained actual all_crate_deps wrapper\n",
            "REPO.bazel":b"","data.bzl":("DEP_DATA = "+repr(data)+"\n").encode()}

    def changed(self,hub):
        data=metadata.dep_data(hub["data.bzl"])
        data[metadata.PACKAGE]["deps"].remove(metadata.ROLLOUT)
        del data[metadata.PACKAGE]["aliases"][metadata.ROLLOUT]
        return {**hub,"data.bzl":("DEP_DATA = "+repr(data)+"\n").encode()}

    def test_only_actual_protocol_normal_dependency_and_alias_may_change(self):
        old=self.hub();new=self.changed(old)
        self.assertIs(metadata.verify_hub_delta(old,new),True)
        self.assertIn(metadata.ROLLOUT,metadata.dep_data(new["data.bzl"])["codex-rs/core"]["deps"])
        with self.assertRaises(ValueError):metadata.verify_hub_delta(old,old)

    def test_other_packages_features_platforms_and_generated_outputs_cannot_drift(self):
        old=self.hub();new=self.changed(old)
        for name in ("BUILD.bazel","defs.bzl","REPO.bazel"):
            with self.assertRaises(ValueError):
                metadata.verify_hub_delta(old,{**new,name:new[name]+b"unqualified change"})
        for package,field,value in (("codex-rs/core","deps",[]),
                (metadata.PACKAGE,"crate_features",["changed"]),
                (metadata.PACKAGE,"deps_by_platform",{"@platform//:other":["//other"]}),
                (metadata.PACKAGE,"dev_deps",[metadata.ROLLOUT])):
            data=metadata.dep_data(new["data.bzl"]);data[package][field]=value
            with self.assertRaises(ValueError):
                metadata.verify_hub_delta(old,{**new,"data.bzl":("DEP_DATA = "+repr(data)).encode()})

    def test_generated_metadata_is_literal_bounded_and_duplicate_free(self):
        for raw in (b"DEP_DATA = execute_private_function()\n",
                b"DEP_DATA = {}\nSECOND = 1\n",
                b"DEP_DATA = {'duplicate': {}, 'duplicate': {}}\n",
                b"DEP_DATA = {'private': __import__('os')}\n"):
            with self.assertRaises(ValueError):metadata.dep_data(raw)
        with patch.object(metadata,"MAX_HUB_FILE",2):
            with self.assertRaises(ValueError):metadata.dep_data(b"DEP_DATA = {}")

    def test_only_the_exact_crates_hub_override_is_omitted(self):
        root="/public/selected-sdk"
        names=[metadata.HUB,"rules_rs+","rules_rs++crate+crates__fixture-1",
            "rules_rs++crate+argument_comment_lint_crates","rules_rs++toolchains+rs_rust_host_tools"]
        repos={name:root+"/repositories/"+name for name in names}
        selected=metadata.retained_overrides(repos,root)
        self.assertEqual(set(selected),set(names)-{metadata.HUB})
        for bad in ({name:path for name,path in repos.items() if name!=metadata.HUB},
                {**repos,"rules_rs+":"/unselected/private"},
                {**repos,"../outside":root+"/repositories/../outside"}):
            with self.assertRaises(ValueError):metadata.retained_overrides(bad,root)


class QueryToolsBindingModels(unittest.TestCase):
    def input_alias_fixture(self, root, stack):
        runfiles=root/'producer.sh.runfiles';runfiles.mkdir()
        canonical='+metadata_inputs+'+producer.INPUT_NAME
        declared=runfiles/canonical;declared.mkdir()
        repository=root/'output-base/external'/canonical;repository.mkdir(parents=True)
        if hasattr(producer,'binding'):
            # Inert binding bytes; replace only source-lineage reconstruction.
            # The family's actual parse_selection digest predicate stays real.
            binding_document={'fixture':'public-binding-metadata'}
            data=source.encoded(binding_document)
            selected={'fixture':'selected-document'}
            stack.enter_context(patch.object(producer,'BINDING_SHA',source.sha(data)))
            if hasattr(producer,'BINDING_BYTES'):
                stack.enter_context(patch.object(producer,'BINDING_BYTES',len(data)))
            stack.enter_context(patch.object(producer.binding,'bind',return_value=binding_document))
            stack.enter_context(patch.object(producer,'selected_document',return_value=selected))
        else:
            selected={'kind':producer.KIND,
                'source_root':'/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/'
                    '00000000-0000-4000-8000-000000000001/output-base/execroot/_main/bazel-out/'
                    'k8-fastbuild/testlogs/tools/codex_protocol_history_source_producer/test.outputs/protocol-history-source',
                'source_receipt_sha256':'a'*64,'export_root':str(producer.EXPORT_ROOT),
                'export_receipt_sha256':producer.EXPORT_SHA}
            data=source.encoded(selected)
        digest=source.sha(data)
        aliases=[]
        for name,raw in (('metadata-input.json',data),('metadata-input.sha256',(digest+'\n').encode())):
            physical=repository/name;physical.write_bytes(raw);physical.chmod(0o644)
            alias=declared/name;alias.symlink_to(physical);aliases.append(alias)
        rows=[['',producer.INPUT_NAME,canonical]]
        (runfiles/'_repo_mapping').write_text(','.join(rows[0])+'\n')
        deadline=float(producer.time.monotonic()+60)
        stack.enter_context(patch.object(producer,'DEADLINE',deadline))
        stack.enter_context(patch.object(source,'DEADLINE',deadline))
        stack.enter_context(patch.object(producer.sys,'argv',['model']))
        stack.enter_context(patch.dict(os.environ,{'TEST_SRCDIR':str(runfiles),
            'TEST_UNDECLARED_OUTPUTS_DIR':str(root),'TEST_TIMEOUT':'900'}))
        # Query-tool proof is independently covered; this fixture isolates the
        # actual selection mapper, physical readers and family digest/parser.
        stack.enter_context(patch.object(producer,'declared_query_tools',return_value=True))
        return runfiles,repository,aliases,data,digest,selected,rows

    def test_input_invocation_accepts_valid_context_and_refuses_missing_or_extra_inputs(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root=Path(temporary)
            _,_,_,_,digest,selected,_=self.input_alias_fixture(root,stack)
            # The real strict require must accept ordinary nonempty string
            # values, then the real mapper/readers/family parser must run.
            self.assertEqual(producer.declared_selection(),(selected,digest))
            actual_read=source.read
            for argv in ([],['model','unexpected']):
                with self.subTest(argv=argv),patch.object(producer.sys,'argv',argv), \
                        patch.object(producer,'declared_query_tools',side_effect=AssertionError('invalid invocation reached query proof')), \
                        patch.object(source,'read',side_effect=AssertionError('invalid invocation read metadata')):
                    with self.assertRaises(ValueError):producer.declared_selection()
            for name in ('TEST_SRCDIR','TEST_UNDECLARED_OUTPUTS_DIR','TEST_TIMEOUT'):
                for absent in (True,False):
                    environment=dict(os.environ)
                    if absent:environment.pop(name,None)
                    else:environment[name]=''
                    with self.subTest(variable=name,absent=absent),patch.dict(os.environ,environment,clear=True), \
                            patch.object(producer,'declared_query_tools',side_effect=AssertionError('invalid invocation reached query proof')), \
                            patch.object(source,'read',side_effect=AssertionError('invalid invocation read metadata')):
                        with self.assertRaises(ValueError):producer.declared_selection()
            # Restoration is checked through real IO, not a mocked success.
            with patch.object(source,'read',wraps=actual_read) as reads:
                self.assertEqual(producer.declared_selection(),(selected,digest))
                self.assertEqual([call.args[1] for call in reads.call_args_list],
                    ['metadata-input.json','metadata-input.sha256'])

    def test_materialized_input_alias_pair_requires_one_exact_mapped_repository(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root=Path(temporary)
            runfiles,repository,aliases,data,digest,selected,rows=self.input_alias_fixture(root,stack)
            self.assertEqual(producer.declared_selection(),(selected,digest))
            for mapping in ([],rows+rows,[['foreign',producer.INPUT_NAME,rows[0][2]]],
                    [['',producer.INPUT_NAME,'../escape']],[['',producer.INPUT_NAME,'wrong-repository']]):
                (runfiles/'_repo_mapping').write_text(''.join(','.join(row)+'\n' for row in mapping))
                with self.subTest(mapping=mapping),self.assertRaises(ValueError):producer.declared_selection()
            (runfiles/'_repo_mapping').write_text(','.join(rows[0])+'\n')
            for index,location in ((0,root/'outside'/rows[0][2]/'metadata-input.json'),
                    (0,repository/'wrong.json'),(0,repository.parent/'wrong-canonical'/'metadata-input.json'),
                    (1,root/'another-output/external'/rows[0][2]/'metadata-input.sha256')):
                location.parent.mkdir(parents=True,exist_ok=True)
                location.write_bytes(data if index==0 else (digest+'\n').encode());location.chmod(0o644)
                aliases[index].unlink();aliases[index].symlink_to(location)
                with self.subTest(location=location),self.assertRaises(ValueError):producer.declared_selection()
                aliases[index].unlink();aliases[index].symlink_to(repository/aliases[index].name)

    def test_input_alias_pair_preserves_independent_sha_custody_and_readback_deadline(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root=Path(temporary)
            _,repository,aliases,data,digest,_,rows=self.input_alias_fixture(root,stack)
            selection=repository/'metadata-input.json';pin=repository/'metadata-input.sha256'
            for changed in (b'0'*64+b'\n',b'unconfigured\n',b'0'*64):
                pin.write_bytes(changed)
                with self.subTest(pin=changed),self.assertRaises(ValueError):producer.declared_selection()
            pin.write_bytes((digest+'\n').encode())
            selection.write_bytes(data.replace(b'"',b'\'',1))
            with self.assertRaises(ValueError):producer.declared_selection()
            selection.write_bytes(data)
            for physical in (selection,pin):
                physical.chmod(0o666)
                with self.subTest(writable=physical),self.assertRaises(ValueError):producer.declared_selection()
                physical.chmod(0o644)
            pin.unlink();pin.mkdir()
            with self.assertRaises(ValueError):producer.declared_selection()
            pin.rmdir();pin.write_bytes((digest+'\n').encode());pin.chmod(0o644)
            aliases[0].unlink();aliases[0].symlink_to(repository/'missing')
            with self.assertRaises(OSError):producer.declared_selection()
            aliases[0].unlink();aliases[0].symlink_to(selection)
            actual_parser=producer.parse_selection
            other=root/'different-output/external'/rows[0][2]/pin.name
            other.parent.mkdir(parents=True);other.write_bytes((digest+'\n').encode());other.chmod(0o644)
            def redirect(raw,sha):
                document=actual_parser(raw,sha)
                aliases[1].unlink();aliases[1].symlink_to(other)
                return document
            with patch.object(producer,'parse_selection',side_effect=redirect),self.assertRaises(ValueError):
                producer.declared_selection()
            aliases[1].unlink();aliases[1].symlink_to(pin)
            clock=[producer.time.monotonic()]
            def expire(raw,sha):
                document=actual_parser(raw,sha);clock[0]=producer.DEADLINE;return document
            with patch.object(producer.time,'monotonic',side_effect=lambda:clock[0]), \
                    patch.object(producer,'parse_selection',side_effect=expire),self.assertRaises(ValueError):
                producer.declared_selection()

    def descriptor(self):
        paths = producer.LOCKED_PATH.split(":")
        tools = dict(zip(("bash", "coreutils", "python", "git"),
            (directory+"/"+binary for directory,binary in zip(paths,("bash","env","python3","git")))))
        tools["bazel"] = producer.BAZEL
        return {"schemaVersion":1,"kind":"omux-codex-metadata-query-tools-v1","tools":tools,
            "path":paths,"java_home":producer.sdk.JDK,
            "roots":sorted({"/".join(path.split("/")[:4]) for path in list(tools.values())+[producer.sdk.JDK]})}

    def test_actual_query_constants_match_closed_declared_tool_descriptor(self):
        self.assertIs(producer.validate_query_tools(self.descriptor()), True)
        for change in ({"schemaVersion":True}, {"kind":"old-full-closure"}, {"roots":[]},
                {"path":self.descriptor()["path"]+["/usr/bin"]}, {"java_home":"/private/jdk"},
                {"tools":{**self.descriptor()["tools"],"bazel":"/nix/store/"+"a"*32+"-other/bin/bazel"}},
                {"extra":True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                producer.validate_query_tools({**self.descriptor(),**change})

    def test_missing_query_manifest_or_repository_mapping_has_no_old_closure_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/"external";root.mkdir()
            repository = root/producer.query_tools.REPOSITORY;repository.mkdir()
            rows = [["_main",producer.query_tools.REPOSITORY,producer.query_tools.REPOSITORY]]
            self.addCleanup(setattr,producer,"DEADLINE",None)
            self.addCleanup(setattr,producer,"QUERY_REPOSITORY",None)
            producer.DEADLINE=float(producer.time.monotonic()+60)
            with self.assertRaises(OSError): producer.declared_query_tools(root, rows)
            with self.assertRaises(ValueError): producer.declared_query_tools(root, [])
            manifest = repository/"codex-metadata-query-tools.json"
            manifest.write_bytes(source.encoded(self.descriptor()));manifest.chmod(0o444)
            # This mapping model stubs the external byte gate only. The new
            # query-tool suite exercises real NAR/reference/readback methods.
            with patch.object(producer.query_tools,"verify_repository",return_value={
                    "status":"declared-fixed-query-tools-byte-qualified",
                    "inputs_rechecked":True,"query_tools":self.descriptor()}) as verified:
                self.assertIs(producer.declared_query_tools(root, rows), True)
                verified.assert_called_once_with(repository,producer.DEADLINE)
            with patch.object(producer.query_tools,"verify_repository",return_value={
                    "status":"declared-fixed-query-tools-byte-qualified",
                    "inputs_rechecked":False,"query_tools":self.descriptor()}):
                with self.assertRaises(ValueError):producer.declared_query_tools(root,rows)
            manifest.unlink();manifest.symlink_to(repository/"missing")
            with self.assertRaises(OSError): producer.declared_query_tools(root, rows)

    def test_materialized_runfiles_descriptor_alias_binds_the_exact_physical_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runfiles = root/"test.sh.runfiles";runfiles.mkdir()
            canonical = "+protocol_history_query_tools_repository+"+producer.query_tools.REPOSITORY
            declared = runfiles/canonical;declared.mkdir()
            external = root/"output-base/external";external.mkdir(parents=True)
            repository = external/canonical;repository.mkdir()
            manifest = repository/"codex-metadata-query-tools.json"
            manifest.write_bytes(source.encoded(self.descriptor()));manifest.chmod(0o444)
            alias = declared/manifest.name;alias.symlink_to(manifest)
            rows = [["",producer.query_tools.REPOSITORY,canonical]]
            self.addCleanup(setattr,producer,"DEADLINE",None)
            self.addCleanup(setattr,producer,"QUERY_REPOSITORY",None)
            producer.DEADLINE=float(producer.time.monotonic()+60)
            # Only the independent byte gate is stubbed. Mapping, real symlink
            # resolution, nofollow physical read and descriptor parsing are real.
            result = {"status":"declared-fixed-query-tools-byte-qualified",
                "inputs_rechecked":True,"query_tools":self.descriptor()}
            with patch.object(producer.query_tools,"verify_repository",return_value=result) as verified:
                self.assertIs(producer.declared_query_tools(runfiles,rows),True)
                verified.assert_called_once_with(repository,producer.DEADLINE)
                self.assertEqual(producer.QUERY_REPOSITORY,repository)
            for bad_rows in ([],rows+rows,[["",producer.query_tools.REPOSITORY,"../outside"]]):
                with self.subTest(rows=bad_rows), self.assertRaises(ValueError):
                    producer.declared_query_tools(runfiles,bad_rows)
            for location in (external/"different-repository"/manifest.name,
                    root/"outside"/canonical/manifest.name,
                    repository/"different-descriptor.json"):
                location.parent.mkdir(parents=True,exist_ok=True)
                location.write_bytes(source.encoded(self.descriptor()));location.chmod(0o444)
                alias.unlink();alias.symlink_to(location)
                with self.subTest(location=location),patch.object(
                        producer.query_tools,"verify_repository",return_value=result) as verified:
                    with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)
                    verified.assert_not_called()
            alias.unlink();alias.symlink_to(manifest)
            for bad in ({**result,"inputs_rechecked":False},
                    {**result,"status":"unqualified"},
                    {**result,"query_tools":{**self.descriptor(),"roots":[]}}):
                with self.subTest(result=bad),patch.object(
                        producer.query_tools,"verify_repository",return_value=bad):
                    with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)
            redirected = root/"other-output-base/external"/canonical
            redirected.mkdir(parents=True)
            other = redirected/manifest.name
            other.write_bytes(source.encoded(self.descriptor()));other.chmod(0o444)
            def redirect(parent,deadline):
                self.assertEqual((parent,deadline),(repository,producer.DEADLINE))
                alias.unlink();alias.symlink_to(other)
                return result
            with patch.object(producer.query_tools,"verify_repository",side_effect=redirect):
                with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)

    def test_declared_descriptor_alias_keeps_physical_leaf_custody_and_deadline_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runfiles = root/"runfiles";runfiles.mkdir()
            canonical = "+protocol_history_query_tools_repository+"+producer.query_tools.REPOSITORY
            declared = runfiles/canonical;declared.mkdir()
            repository = root/"external"/canonical;repository.mkdir(parents=True)
            manifest = repository/"codex-metadata-query-tools.json"
            manifest.write_bytes(source.encoded(self.descriptor()));manifest.chmod(0o666)
            alias = declared/manifest.name;alias.symlink_to(manifest)
            rows = [["_main",producer.query_tools.REPOSITORY,canonical]]
            self.addCleanup(setattr,producer,"DEADLINE",None)
            self.addCleanup(setattr,producer,"QUERY_REPOSITORY",None)
            producer.DEADLINE=float(producer.time.monotonic()+60)
            with patch.object(producer.query_tools,"verify_repository") as verified:
                with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)
                verified.assert_not_called()
            manifest.chmod(0o444)
            producer.DEADLINE=float(producer.time.monotonic()-1)
            with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)
            producer.DEADLINE=float(producer.time.monotonic()+60)
            alias.unlink();alias.symlink_to(repository/"missing")
            with self.assertRaises(OSError):producer.declared_query_tools(runfiles,rows)
            manifest.unlink();manifest.mkdir()
            alias.unlink();alias.symlink_to(manifest)
            with self.assertRaises(ValueError):producer.declared_query_tools(runfiles,rows)


class MetadataProducerModels(unittest.TestCase):
    hub = ProtocolHistoryMetadataTests.hub
    changed = ProtocolHistoryMetadataTests.changed
    def fixture(self, root):
        before = source_models.ProtocolHistorySourceTests().fixture()
        parent = {"patches":[{"patch_sha256":pin,"paths":[]} for pin in history.PARENT_PATCHES],
            "baseline_graph_files":{name:{"sha256":source.sha(before[name][1])} for name in source.GRAPH}}
        patchfile = root/history.PATCH_NAME
        patchfile.write_bytes(history.PATCH_BYTES);patchfile.chmod(0o600)
        selected = root/"selected"
        with patch.object(history,"load_parent",return_value=(before,parent)),patch.object(history,"PATCH_DIRECTORY",root):
            report = history.produce(selected,60)
        # Model the observed retained Bazel output, without changing its writer.
        (selected/"source-receipt.json").chmod(0o555)
        export = root/"sdk";export.mkdir(mode=0o700)
        (export/"repositories").mkdir(mode=0o700)
        old = self.hub();hub = export/"repositories"/metadata.HUB
        hub.mkdir(mode=0o700)
        for name,value in old.items():
            (hub/name).write_bytes(value);(hub/name).chmod(0o444)
        repositories = {name:str(export/"repositories"/name) for name in
            (metadata.HUB,"rules_rs+","rules_rs++crate+crates__fixture-1")}
        document={"kind":producer.KIND,"source_root":str(selected),
            "source_receipt_sha256":source.sha((selected/"source-receipt.json").read_bytes()),
            "export_root":str(export),"export_receipt_sha256":producer.EXPORT_SHA}
        exported={"repositories":repositories,"registry_cache":str(export/"registry-cache"),
            "inventory_sha256":"e"*64}
        return before,parent,document,export,exported,old

    def run_producer(self, root, fixture, query=None, sdk_reader=None, absolute_deadline=None):
        before,parent,document,export,exported,old=fixture
        def generate(plan, output):
            hub=root/"work/output-base/external"/metadata.HUB
            hub.mkdir(parents=True,mode=0o700)
            for directory in (hub.parent,hub.parent.parent):directory.chmod(0o700)
            for name,value in self.changed(old).items():
                (hub/name).write_bytes(value);(hub/name).chmod(0o444)
            for name in ("stdout","stderr"):
                (output/("query."+name)).write_bytes(b"");(output/("query."+name)).chmod(0o444)
            if query:query()
            return 0
        with patch.object(producer,"EXPORT_ROOT",export),patch.object(producer,"SOURCE_SCOPE",
                re.compile(re.escape(document["source_root"]))),patch.object(history,"load_parent",
                return_value=(before,parent)),patch.object(producer.sdk,"validate_export",
                side_effect=sdk_reader or (lambda *args,**kwargs:exported)),patch.object(producer,"execute_query",
                side_effect=generate):
            return producer.produce(document,"f"*64,root/"work",root/"result",60,
                absolute_deadline=absolute_deadline)

    def clean(self, root):
        for directory,_,_ in os.walk(root):
            Path(directory).chmod(0o700)
        source.DEADLINE=None;producer.DEADLINE=None

    def test_noargs_selection_has_closed_fields_scope_and_independent_pin(self):
        document={"kind":producer.KIND,"source_root":"/home/jess/.local/state/omux-execution-20261005/"
            +"cache-v2-"+"a"*64+"/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
            +"codex_protocol_history_source_producer/test.outputs/protocol-history-source",
            "source_receipt_sha256":"b"*64,"export_root":str(producer.EXPORT_ROOT),
            "export_receipt_sha256":producer.EXPORT_SHA}
        raw=source.encoded(document)
        self.assertEqual(producer.parse_selection(raw,source.sha(raw)),document)
        for bad in ({**document,"source_root":"/private/credentials"},
                {**document,"unknown":True},{**document,"source_receipt_sha256":True},
                {**document,"export_receipt_sha256":"c"*64}):
            value=source.encoded(bad)
            with self.assertRaises(ValueError):producer.parse_selection(value,source.sha(value))
            with patch.object(producer,"hold_root") as held:
                with self.assertRaises(ValueError):
                    producer.produce(bad,"f"*64,Path("/not-read/work"),Path("/not-read/out"),60)
                held.assert_not_called()
        with self.assertRaises(ValueError):producer.parse_selection(raw,"0"*64)

    def test_fixed_query_retains_every_override_except_one_and_uses_locked_offline_tools(self):
        root=producer.EXPORT_ROOT
        repositories={name:str(root/"repositories"/name) for name in
            (metadata.HUB,"rules_rs+","rules_rs++crate+crates__fixture-1",
             "rules_rs++toolchains+rs_rust_host_tools")}
        plan=producer.query_plan(Path("/owned-work"),Path("/owned-source"),
            {"repositories":repositories,"registry_cache":str(root/"registry-cache")})
        overrides=[arg for arg in plan["argv"] if arg.startswith("--override_repository=")]
        self.assertEqual(overrides,["--override_repository="+name+"="+repositories[name]
            for name in sorted(repositories) if name!=metadata.HUB])
        self.assertEqual(plan["argv"][-2:],["--output=build","@crates//:all"])
        for flag in ("--lockfile_mode=error","--repository_disable_download",
                "--repo_contents_cache=","--repo_env=CARGO_NET_OFFLINE=true"):
            self.assertEqual(plan["argv"].count(flag),1)
        self.assertEqual(plan["argv"][0],producer.BAZEL)
        self.assertEqual(plan["environment"]["USE_BAZEL_VERSION"],"9.0.1")
        self.assertEqual(set(plan["environment"]),{"PATH","USE_BAZEL_VERSION","CARGO_NET_OFFLINE",
            "HOME","CARGO_HOME","XDG_CACHE_HOME","XDG_CONFIG_HOME","XDG_STATE_HOME","LANG","LC_ALL"})
        self.assertFalse(any(arg.startswith("--override_module=") for arg in plan["argv"]))

    def test_actual_sealed_source_and_hub_io_emits_only_metadata_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                fixture=self.fixture(root)
                report=self.run_producer(root,fixture)
                self.assertEqual(report["kind"],producer.OUTPUT_KIND)
                self.assertIs(report["source_and_export_rechecked"],True)
                for field in ("sdk_export_qualified","native_compile_passed","native_support","provider_evaluation"):
                    self.assertIs(report[field],False)
                self.assertEqual(json.loads((root/"result/metadata-receipt.json").read_bytes()),report)
                self.assertEqual((root/"result").stat().st_mode&0o777,0o555)
                self.assertEqual((root/"result/hub/data.bzl").stat().st_mode&0o777,0o444)
                self.assertEqual(source.sha((root/"selected/source-receipt.json").read_bytes()),
                    fixture[2]["source_receipt_sha256"])
            finally:self.clean(root)

    def test_retained_source_receipt_requires_exact_mode_and_independent_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                before,parent,document,*_=self.fixture(root)
                receipt=root/"selected/source-receipt.json"
                raw=receipt.read_bytes()
                with patch.object(history,"load_parent",return_value=(before,parent)) as loaded:
                    report,files,actual_parent=producer.load_candidate(document)
                    self.assertEqual(report,json.loads(raw))
                    self.assertEqual(files,history.transform(before,history.PATCH_BYTES))
                    self.assertEqual(actual_parent,parent)
                    loaded.assert_called_once_with()
                for mode in (0o444,0o644,0o777):
                    receipt.chmod(mode)
                    with patch.object(history,"load_parent") as loaded:
                        with self.assertRaises(ValueError):producer.load_candidate(document)
                        loaded.assert_not_called()
                receipt.chmod(0o600);receipt.write_bytes(raw+b" ");receipt.chmod(0o555)
                with patch.object(history,"load_parent") as loaded:
                    with self.assertRaises(ValueError):producer.load_candidate(document)
                    loaded.assert_not_called()
            finally:self.clean(root)

    def test_retained_source_receipt_custody_keeps_full_claim_and_tree_checks(self):
        for claim_drift in (True,False):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    before,parent,document,*_=self.fixture(root)
                    receipt=root/"selected/source-receipt.json"
                    if claim_drift:
                        report=json.loads(receipt.read_bytes())
                        report["native_compile_passed"]=True
                        receipt.chmod(0o600);receipt.write_bytes(source.encoded(report));receipt.chmod(0o555)
                        document={**document,"source_receipt_sha256":source.sha(receipt.read_bytes())}
                    else:
                        path=root/"selected/source/retained/source.rs"
                        path.chmod(0o600);path.write_bytes(b"unqualified source drift");path.chmod(0o555)
                    with patch.object(history,"load_parent",return_value=(before,parent)):
                        with self.assertRaises(ValueError):producer.load_candidate(document)
                finally:self.clean(root)

    def test_retained_source_receipt_redirect_refuses_before_parent_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                _,_,document,*_=self.fixture(root)
                selected=root/"selected";selected.chmod(0o700)
                receipt=selected/"source-receipt.json"
                receipt.rename(root/"original-receipt")
                receipt.symlink_to(root/"original-receipt")
                with patch.object(history,"load_parent") as loaded:
                    with self.assertRaises(OSError):producer.load_candidate(document)
                    loaded.assert_not_called()
            finally:self.clean(root)

    def test_selected_exact_absolute_deadline_reaches_the_query_without_renewal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                fixture=self.fixture(root);deadline=producer.time.monotonic()+59
                def observe():self.assertEqual(producer.DEADLINE,deadline)
                self.run_producer(root,fixture,query=observe,absolute_deadline=deadline)
            finally:self.clean(root)

    def test_source_same_path_same_bytes_inode_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                fixture=self.fixture(root)
                def replace():
                    selected=root/"selected"
                    selected.rename(root/"old-selected")
                    import shutil
                    shutil.copytree(root/"old-selected",selected,symlinks=True)
                with self.assertRaises(ValueError):self.run_producer(root,fixture,query=replace)
                self.assertFalse((root/"result/metadata-receipt.json").exists())
            finally:self.clean(root)

    def test_post_query_sdk_or_source_byte_drift_cannot_emit_success(self):
        for source_drift in (True,False):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    fixture=self.fixture(root)
                    calls=[]
                    def sdk_reader(*args,**kwargs):
                        calls.append(None)
                        return fixture[4] if len(calls)==1 else {**fixture[4],"inventory_sha256":"9"*64}
                    def mutate_source():
                        path=root/"selected/source/retained/source.rs"
                        path.chmod(0o600);path.write_bytes(b"changed selected source");path.chmod(0o555)
                    with self.assertRaises(ValueError):
                        self.run_producer(root,fixture,query=mutate_source if source_drift else None,
                            sdk_reader=None if source_drift else sdk_reader)
                    self.assertFalse((root/"result/metadata-receipt.json").exists())
                finally:self.clean(root)

    def test_selector_constructor_or_close_failure_still_reaps_owned_child_and_pipes(self):
        from unittest.mock import Mock
        for construction in (True,False):
            child=Mock()
            child.stdout=Mock();child.stderr=Mock()
            child.stdout.fileno.return_value=71;child.stderr.fileno.return_value=72
            child.poll.return_value=None if construction else 0
            child.wait.return_value=0
            selector=Mock()
            selector.get_map.return_value={}
            selector.close.side_effect=OSError("synthetic close fault")
            plan={"argv":["/fixed/tool"],"cwd":"/fixed/source","environment":{}}
            producer.DEADLINE=producer.time.monotonic()+200
            with patch.object(producer.subprocess,"Popen",return_value=child),patch.object(
                    producer.selectors,"DefaultSelector",side_effect=OSError("synthetic constructor fault")
                    if construction else None,return_value=selector),patch.object(producer.os,"set_blocking"):
                with self.assertRaises((OSError,ValueError)):
                    producer.execute_query(plan,Path("/unused"))
            if construction:
                child.kill.assert_called_once()
                child.wait.assert_called_once_with(timeout=5)
            child.stdout.close.assert_called_once();child.stderr.close.assert_called_once()
        producer.DEADLINE=None

    def test_receipt_source_link_and_held_root_redirects_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            held=None
            try:
                target=root/"physical";target.mkdir(mode=0o700)
                held=producer.hold_root(target)
                target.rename(root/"original");target.mkdir(mode=0o700)
                with self.assertRaises(ValueError):producer.recheck_root(target,held)
                (root/"link").symlink_to(target,target_is_directory=True)
                with self.assertRaises(OSError):producer.hold_root(root/"link")
            finally:
                if held:os.close(held[0])
                self.clean(root)


if __name__ == "__main__":
    unittest.main()
