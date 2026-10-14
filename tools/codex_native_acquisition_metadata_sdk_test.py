"""Bounded metadata/SDK source models; no actual artifact or native tools read."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock
from contextlib import ExitStack, contextmanager

import codex_live_source as source
import codex_protocol_history_metadata as metadata
import codex_native_acquisition_metadata as producer
import codex_native_acquisition_sdk_export as selected
import codex_retained_sdk_export as sdk
import codex_protocol_history_metadata_test as alias_models


class AcquisitionDeclaredAliasModels(alias_models.QueryToolsBindingModels):
    def setUp(self):
        # Reuse the genuine runfiles/physical-leaf models against this family's
        # own production validator; only the independent byte gate is stubbed.
        binding = patch.object(alias_models, 'producer', producer)
        binding.start();self.addCleanup(binding.stop)


class AcquisitionMetadataSdkTests(unittest.TestCase):
    def setUp(self):
        self.document = {'kind':producer.KIND,'source_root':'/isolated-source',
            'source_receipt_sha256':'1'*64,'source_inventory_sha256':'2'*64,
            'binding_receipt_sha256':'3'*64,'export_root':str(producer.EXPORT_ROOT),
            'export_receipt_sha256':producer.EXPORT_SHA}
        for mocked in (patch.object(producer.binding,'selected_document',return_value=self.document),
                patch.object(producer,'BINDING_SHA','3'*64),
                patch.object(producer,'configure_selection')):
            mocked.start();self.addCleanup(mocked.stop)
        self.addCleanup(setattr, source, 'DEADLINE', None)
        self.addCleanup(setattr, producer, 'DEADLINE', None)

    def test_real_metadata_and_sdk_copy_replaces_only_hub_with_fresh_source_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            material = root / "retained"
            (material / "repositories" / metadata.HUB).mkdir(parents=True)
            spoke = material / "repositories/spoke"
            spoke.mkdir()
            (spoke / "public-file").write_bytes(b"unchanged spoke\n")
            (spoke / "public-file").chmod(0o444)
            row = {field: [] for field in metadata.LISTS}
            row.update({field: {} for field in metadata.PLATFORMS | metadata.MAPS})
            row["deps"] = [metadata.ROLLOUT, metadata.HISTORY]
            row["aliases"] = {metadata.ROLLOUT: "codex_rollout", metadata.HISTORY: "codex_history"}
            app = copy.deepcopy(row)
            app['deps'] = []
            app['aliases'] = {}
            app['dev_deps'] = ['@crates//:hmac-0.12.1']
            data = {metadata.PACKAGE: row, 'codex-rs/app-server':app}
            old = {"BUILD.bazel": b"# bounded hub\n", "defs.bzl": b"# unchanged\n",
                "data.bzl": ("DEP_DATA = " + repr(data) + "\n").encode()}
            fresh = copy.deepcopy(data)
            fresh[metadata.PACKAGE]["deps"].remove(metadata.ROLLOUT)
            del fresh[metadata.PACKAGE]["aliases"][metadata.ROLLOUT]
            fresh['codex-rs/app-server']['dev_deps'] = []
            fresh['codex-rs/app-server']['deps'] = ['@crates//:hmac-0.12.1','@crates//:libc-0.2.186','@crates//:zeroize-1.8.2']
            generated = {**old, "data.bzl": ("DEP_DATA = " + repr(fresh) + "\n").encode()}
            for name, value in old.items():
                path = material / "repositories" / metadata.HUB / name
                path.write_bytes(value)
                path.chmod(0o444)
            registry = material / "registry-cache"
            registry.mkdir()
            (registry / "public").write_bytes(b"registry\n")
            (registry / "public").chmod(0o444)
            for directory, _, _ in os.walk(material, topdown=False):
                Path(directory).chmod(0o555)
            budget = sdk.Budget(sdk.time.time() + 60)
            repositories = []
            for name in (metadata.HUB, "spoke"):
                rows = sdk.inventory(material / "repositories" / name, budget, sealed=True)
                repositories.append({"canonical_name": name, "files": rows,
                    "inventory_sha256": sdk.digest(sdk.canonical(rows)), "absent_links": []})
            retained = {"repositories": repositories, "modules": {}, "registry_metadata": {"isolated": True},
                "nix_store_roots": [sdk.JDK], "nix_inventory": []}
            material.chmod(0o700)
            (material / "receipt.json").write_bytes(source.encoded(retained))
            (material / "receipt.json").chmod(0o444)
            material.chmod(0o555)
            files = {"MODULE.bazel.lock": ("100644", b"isolated-lock\n"), "native.rs": ("100644", b"native\n")}
            graph = {name: {"sha256": source.sha(value)} for name, (_, value) in files.items()}
            report = {"inventory_sha256": "isolated-inventory", "graph_files": graph}
            document = {"kind": producer.KIND, "source_root": str(root), "source_receipt_sha256": "isolated-source",
                "source_inventory_sha256": report["inventory_sha256"], "binding_receipt_sha256": producer.BINDING_SHA,
                "export_root": str(material), "export_receipt_sha256": source.sha(source.encoded(retained))}
            exported = {"repositories": {name: str(material / "repositories" / name) for name in (metadata.HUB, "spoke")},
                "registry_cache": str(registry), "inventory_sha256": "isolated-retained"}
            def query(plan, output):
                hub = root / "work/output-base/external" / metadata.HUB
                hub.mkdir(parents=True)
                for name, value in generated.items():
                    (hub / name).write_bytes(value)
                    (hub / name).chmod(0o444)
                return 0
            real_inventory = sdk.inventory
            def inventory(path, *args, **kwargs):
                return [] if Path(path) == Path(sdk.JDK) else real_inventory(path, *args, **kwargs)
            previous = os.umask(0o077)
            try:
                with patch.multiple(producer, EXPORT_ROOT=material, EXPORT_SHA=document["export_receipt_sha256"], INPUT_CONTROL=root / "isolated-binding"), patch.object(producer, "selected_document", return_value=document), patch.object(producer, "load_candidate", return_value=(report, files, {"baseline_graph_files": {}})), patch.object(sdk, "validate_export", return_value=exported), patch.object(producer, "execute_query", side_effect=query), patch.object(sdk, "inventory", side_effect=inventory), patch.object(sdk, "registry_metadata", return_value=retained["registry_metadata"]):
                    deadline = producer.time.monotonic() + 60
                    producer.produce(document, producer.BINDING_SHA, root / "work", root / "metadata", 60, absolute_deadline=deadline)
                    result = selected.export(document, root / "metadata", root / "sdk", deadline)
                    drift = root / "metadata/hub/defs.bzl"
                    drift.chmod(0o600)
                    drift.write_bytes(b"unqualified generated wrapper\n")
                    drift.chmod(0o444)
                    with self.assertRaises(ValueError):
                        selected.export(document, root / "metadata", root / "refused-sdk", deadline)
                    self.assertFalse((root / "refused-sdk/receipt.json").exists())
                self.assertEqual(result["kind"], selected.KIND)
                self.assertEqual((root / "sdk/repositories/spoke/public-file").read_bytes(), b"unchanged spoke\n")
                self.assertEqual((root / "sdk/repositories" / metadata.HUB / "data.bzl").read_bytes(), generated["data.bzl"])
                self.assertEqual((material / "repositories" / metadata.HUB / "data.bzl").read_bytes(), old["data.bzl"])
                self.assertEqual(result["graph_files"], graph)
                self.assertIs(result["sdk_export_qualified"], True)
                for field in ("schema_producer_qualified", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                    self.assertIs(result[field], False)
            finally:
                os.umask(previous)
                source.DEADLINE = None
                producer.DEADLINE = None
                for directory, _, _ in os.walk(root):
                    Path(directory).chmod(0o700)

    def test_selected_document_is_closed_actual_ninth_and_not_fourth(self):
        document = producer.selected_document()
        self.assertEqual(producer.validate_document(document), document)
        for field, value in (("kind", "omux-protocol-history-metadata-input-v1"),
            ("source_root", "/different"), ("source_receipt_sha256", "0" * 64),
            ("source_inventory_sha256", "0" * 64), ("binding_receipt_sha256", "0" * 64),
            ("export_root", "/different"), ("export_receipt_sha256", "0" * 64), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                producer.validate_document({**document, field: value})

    def test_ninth_pin_and_exact_reconstructed_binding_refuse_rehashed_claims(self):
        document = {"kind": "isolated-source-only", "native_support": False}
        raw = source.encoded(document)
        with patch.multiple(producer, BINDING_SHA=source.sha(raw)), patch.object(producer.binding, "bind", return_value=document):
            self.assertEqual(producer.parse_selection(raw, source.sha(raw)), producer.selected_document())
            for changed, digest in ((raw + b"\n", source.sha(raw)), (raw, "0" * 64)):
                with self.assertRaises(ValueError):
                    producer.parse_selection(changed, digest)
            changed = source.encoded({**document, "native_support": True})
            with patch.multiple(producer, BINDING_SHA=source.sha(changed)), self.assertRaises(ValueError):
                producer.parse_selection(changed, source.sha(changed))

    def test_candidate_reads_sealed_ninth_and_actual_reconstruction_then_rechecks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receipt-root"
            root.mkdir()
            path = root / "binding.json"
            bound = {"isolated": "exact"}
            raw = source.encoded(bound)
            path.write_bytes(raw)
            path.chmod(0o444)
            root.chmod(0o555)
            report, files, parent = {"inventory_sha256": "isolated"}, {"native.rs": ("100644", b"native\n")}, {"baseline_graph_files": {}}
            try:
                with patch.multiple(producer, INPUT_CONTROL=path, BINDING_SHA=source.sha(raw)), patch.object(producer.binding, "bind", return_value=bound), patch.object(producer.binding, "load_verified_source", return_value=(report, files, parent)) as loaded, patch.object(producer.history, "load_parent", return_value=({}, parent)):
                    self.assertEqual(producer.load_candidate(producer.selected_document()), (report, files, parent))
                    loaded.assert_called_once_with(producer.selected_document())
                    path.chmod(0o555)
                    with self.assertRaises(ValueError):
                        producer.load_candidate(producer.selected_document())
            finally:
                root.chmod(0o700)

    def test_fixed_offline_query_omits_only_hub_and_retains_locked_tool_plan(self):
        names = (metadata.HUB, "rules_rs+", "rules_rs++crate+crates__fixture-1")
        repositories = {name: str(producer.EXPORT_ROOT / "repositories" / name) for name in names}
        plan = producer.query_plan(Path("/owned-work"), Path("/owned-source"),
            {"repositories": repositories, "registry_cache": str(producer.EXPORT_ROOT / "registry-cache")})
        self.assertEqual([row for row in plan["argv"] if row.startswith("--override_repository=")],
            ["--override_repository=" + name + "=" + repositories[name] for name in sorted(names) if name != metadata.HUB])
        for flag in ("--lockfile_mode=error", "--repository_disable_download", "--repo_contents_cache=", "--repo_env=CARGO_NET_OFFLINE=true"):
            self.assertEqual(plan["argv"].count(flag), 1)
        self.assertEqual(plan["argv"][-2:], ["--output=build", "@crates//:all"])
        self.assertEqual(plan["argv"][0], producer.BAZEL)
        self.assertEqual(plan["environment"]["PATH"], producer.LOCKED_PATH)
        self.assertFalse(any(row.startswith("--override_module=") for row in plan["argv"]))

    def test_sealed_real_copy_rechecks_every_file_and_refuses_changed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            origin = root / "origin"
            origin.mkdir()
            (origin / "file").write_bytes(b"bounded material\n")
            (origin / "file").chmod(0o444)
            origin.chmod(0o555)
            budget = sdk.Budget(sdk.time.time() + 60)
            expected = sdk.inventory(origin, budget, sealed=True)
            budget.authorize_export_passes()
            try:
                selected.copy_tree(origin, root / "copy", expected, budget)
                self.assertEqual((root / "copy/file").read_bytes(), b"bounded material\n")
                changed = copy.deepcopy(expected)
                changed[0]["sha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    selected.copy_tree(origin, root / "refused", changed, budget)
            finally:
                for directory, _, _ in os.walk(root):
                    Path(directory).chmod(0o700)

    def test_deadline_never_extended_and_unconfigured_query_repo_refuses_main(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"TEST_TIMEOUT": "900", "TEST_TMPDIR": str(root), "TEST_UNDECLARED_OUTPUTS_DIR": str(root)}
            document = producer.selected_document()
            repository = root / "declared-query-tools"
            def declare():
                producer.QUERY_REPOSITORY = repository
                return document, producer.BINDING_SHA
            with patch.dict(os.environ, env), patch.object(selected.os, "umask"), patch.object(producer, "declared_selection", side_effect=declare), patch.object(selected.time, "monotonic", return_value=100.0), patch.object(producer, "produce") as generated, patch.object(selected, "export") as exported, patch.object(producer.query_tools, "verify_repository", return_value={"inputs_rechecked": True}) as verified:
                selected.main()
                self.assertEqual(generated.call_args.kwargs["absolute_deadline"], 700.0)
                self.assertEqual(exported.call_args.args[-1], 700.0)
                verified.assert_called_once_with(repository, 700.0)
            with patch.dict(os.environ, env), patch.object(selected.os, "umask"), patch.object(producer, "declared_selection", return_value=(document, producer.BINDING_SHA)), patch.object(producer, "produce") as generated, patch.object(selected, "export") as exported, self.assertRaises(ValueError):
                selected.main()
            generated.assert_not_called()
            exported.assert_not_called()
            with patch.object(producer, "hold_root") as held:
                for deadline in (producer.time.monotonic() - 1, producer.time.monotonic() + 841, True):
                    with self.assertRaises(ValueError):
                        selected.export(document, root / "metadata", root / "sdk", deadline)
                held.assert_not_called()


class NinthBindingTests(unittest.TestCase):
    def test_pending_configuration_refuses_before_any_selected_or_producer_read(self):
        raw=source.encoded({'schema_version':1,'kind':'omux-native-source-acquisition-input-configuration-v1',
            'status':'awaiting-actual-ninth-source-and-binding',
            **{role:None for role in ('source','binding','metadata','sdk','compile')}})
        with patch.object(producer.binding.ninth.parent,'declared',return_value=raw), \
                patch.object(producer.binding,'actual_source') as opened, \
                patch.object(producer.binding.protocol,'producer_pin') as receipt:
            with self.assertRaises(ValueError):producer.binding.config()
            opened.assert_not_called();receipt.assert_not_called()

    def test_real_literal_hub_delta_preserves_every_other_package_feature_platform_and_alias(self):
        row={field:[] for field in metadata.LISTS}
        row.update({field:{} for field in metadata.PLATFORMS | metadata.MAPS})
        history=copy.deepcopy(row);history['deps']=[metadata.ROLLOUT,metadata.HISTORY]
        history['aliases']={metadata.ROLLOUT:'codex_rollout',metadata.HISTORY:'codex_history'}
        app=copy.deepcopy(row);app['dev_deps']=['@crates//:hmac-0.12.1']
        original={metadata.PACKAGE:history,'codex-rs/app-server':app,'fixture':copy.deepcopy(row)}
        expected=copy.deepcopy(original)
        expected[metadata.PACKAGE]['deps'].remove(metadata.ROLLOUT)
        del expected[metadata.PACKAGE]['aliases'][metadata.ROLLOUT]
        expected['codex-rs/app-server']['dev_deps']=[]
        expected['codex-rs/app-server']['deps']=['@crates//:hmac-0.12.1','@crates//:libc-0.2.186','@crates//:zeroize-1.8.2']
        def hub(value):return {'BUILD.bazel':b'# fixed\n','defs.bzl':b'# fixed\n','data.bzl':('DEP_DATA = '+repr(value)+'\n').encode()}
        self.assertIs(producer.binding.verify_hub_delta(hub(original),hub(expected)),True)
        for field in ('deps','dev_deps','crate_features','aliases'):
            changed=copy.deepcopy(expected)
            changed['fixture'][field]=['unrelated'] if type(changed['fixture'][field]) is list else {'unrelated':'change'}
            with self.subTest(field=field),self.assertRaises(ValueError):
                producer.binding.verify_hub_delta(hub(original),hub(changed))
        changed=copy.deepcopy(expected);changed['codex-rs/app-server']['deps'][1]='@crates//:libc-0.2.182'
        with self.assertRaises(ValueError):producer.binding.verify_hub_delta(hub(original),hub(changed))
        with self.assertRaises(ValueError):producer.binding.verify_hub_delta(hub(original),{**hub(expected),'defs.bzl':b'# drift\n'})


class SourceProofSessionTests(unittest.TestCase):
    def setUp(self):
        self.binding=producer.binding
        original_deadline=source.DEADLINE;original_phase=self.binding.PHASE
        self.addCleanup(setattr,source,'DEADLINE',original_deadline)
        self.addCleanup(setattr,self.binding,'PHASE',original_phase)
        source.DEADLINE=float(producer.time.monotonic()+60)

    def sealed(self,root,files,report):
        fd=source.write_source(root,files)
        try:
            raw=source.encoded(report)
            writer=os.open('source-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(writer,'wb') as stream:
                stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o555)
            os.fchmod(fd,0o555)
        finally:os.close(fd)
        return source.sha(raw),len(raw)

    @contextmanager
    def fixture(self):
        """Real sealed IO/session/main; external lineage construction is a fixture seam."""
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            files={'plain':('100644',b'public source\n'),
                'nested/run':('100755',b'public executable fixture\n'),
                'nested/link':('120000',b'run')}
            report={'graph_files':{'plain':{'sha256':source.sha(files['plain'][1])}},
                'patch_sha256':['a'*64]*9}
            roots={name:root/name for name in ('third','fifth','sixth','seventh','ninth')}
            pins={name:self.sealed(path,files,report) for name,path in roots.items()}
            def witness(path,regular=False):
                fd=source.directory(path) if not regular else os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                try:return self.binding.ninth.binding.identity(fd,regular)
                finally:os.close(fd)
            n5_config={'root':str(roots['seventh']),'receipt_sha256':pins['seventh'][0],
                'receipt_bytes':pins['seventh'][1]}
            n5_witness={'root_identity':witness(roots['seventh']),
                'source_root_identity':witness(roots['seventh']/'source'),
                'receipt_identity':witness(roots['seventh']/'source-receipt.json',True)}
            n9_witness={'root':str(roots['ninth']),'receipt_bytes':pins['ninth'][1],
                'root_identity':self.binding.identity(os.stat(roots['ninth'])),
                'source_root_identity':self.binding.identity(os.stat(roots['ninth']/'source')),
                'receipt_identity':self.binding.identity(os.stat(roots['ninth']/'source-receipt.json'))}
            value={'source':{'root':str(roots['ninth']),'receipt_sha256':pins['ninth'][0],
                'inventory_sha256':'b'*64,'producer':{'fixture_only':'not-actual-evidence'}},
                'binding':None,'metadata':None,'sdk':None,'compile':None}
            control={'value':value}
            patch_reader=Mock(return_value=b'fixed public patch fixture\n')
            constructed=[]
            def construct(proof):
                constructed.append(proof)
                for name,path in roots.items():
                    self.binding.phase(name)
                    captured=proof.capture(name,path,pins[name][0],size=pins[name][1])
                    captured.accept(report,files)
                    if name=='seventh':proof.join_n5(captured)
                    elif name=='ninth':proof.join_n9(captured)
                proof.patch(patch_reader)
                proof.source_report=copy.deepcopy(report);proof.source_files=proof.snapshots[-1][1].files
                proof.baseline={'fixture_only':'not-actual-lineage'}
                proof.report=self.binding.binding_report(proof.value,report)
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(self.binding,'config',side_effect=lambda:copy.deepcopy(control['value'])))
                    stack.enter_context(patch.object(self.binding.ninth.binding,'load',return_value=(n5_config,n5_witness)))
                    stack.enter_context(patch.object(self.binding,'n9_witness',return_value=n9_witness))
                    reconstruction=stack.enter_context(patch.object(self.binding.SourceProofSession,'construct',autospec=True,side_effect=construct))
                    guardian=stack.enter_context(patch.object(self.binding.SourceProofSession,'guardian',autospec=True,side_effect=lambda proof:proof.tick()))
                    sweeps=stack.enter_context(patch.object(source,'verify_written',wraps=source.verify_written))
                    yield {'root':root,'roots':roots,'files':files,'report':report,'value':value,
                        'control':control,'patch':patch_reader,'constructed':constructed,
                        'reconstruction':reconstruction,'guardian':guardian,'sweeps':sweeps}
            finally:
                # Only this disposable public fixture; never a selected real root.
                for directory,_,_ in os.walk(root,followlinks=False):Path(directory).chmod(0o700)

    def test_real_finish_sweeps_every_ancestor_once_without_reconstruction_or_clock_reset(self):
        with self.fixture() as fixture:
            deadline=source.DEADLINE
            with self.binding.SourceProofSession(fixture['value']) as proof:
                original=proof.initial_report();changed=proof.initial_report()
                changed['source_graph']['plain']['sha256']='c'*64
                with self.assertRaises(TypeError):proof.source_files['unknown']=('100644',b'poison')
                self.assertEqual(proof.finish(),original)
                self.assertEqual(fixture['sweeps'].call_count,10)
                self.assertEqual(fixture['reconstruction'].call_count,1)
                self.assertEqual(fixture['guardian'].call_count,2)
                self.assertEqual(fixture['patch'].call_count,3)
                self.assertEqual(source.DEADLINE,deadline)
                with self.assertRaises(ValueError):proof.finish()
            with self.assertRaises(ValueError):proof.initial_report()
            self.assertTrue(all(row.held is row.tree is row.receipt is None for _,row in proof.snapshots))

    def test_final_sweep_refuses_real_ancestor_bytes_mode_extra_member_and_link_mutation(self):
        for mutation in ('bytes','mode','extra','link'):
            with self.subTest(mutation=mutation),self.fixture() as fixture:
                with self.binding.SourceProofSession(fixture['value']) as proof:
                    nested=fixture['roots']['third']/'source/nested'
                    if mutation in ('bytes','mode'):
                        path=nested/'run';path.chmod(0o600)
                        if mutation=='bytes':path.write_bytes(b'changed public fixture\n');path.chmod(0o555)
                    else:
                        nested.chmod(0o700)
                        if mutation=='extra':(nested/'extra').write_bytes(b'unselected\n');(nested/'extra').chmod(0o555)
                        else:(nested/'link').unlink();(nested/'link').symlink_to('different')
                        nested.chmod(0o555)
                    with self.assertRaises(ValueError):proof.finish()
                    self.assertEqual(self.binding.PHASE,'third-readback')
                    self.assertFalse(proof.finished)
                    self.assertEqual(fixture['guardian'].call_count,1)

    def test_held_snapshot_refuses_named_root_replacement_and_receipt_replacement(self):
        for mutation in ('root','receipt'):
            with self.subTest(mutation=mutation),self.fixture() as fixture:
                with self.binding.SourceProofSession(fixture['value']) as proof:
                    root=fixture['roots']['third']
                    if mutation=='root':
                        root.rename(root.with_name('retained-old-third'))
                        self.sealed(root,fixture['files'],fixture['report'])
                    else:
                        root.chmod(0o700)
                        (root/'source-receipt.json').rename(root/'old-receipt.json')
                        (root/'source-receipt.json').write_bytes(source.encoded(fixture['report']))
                        (root/'source-receipt.json').chmod(0o555);root.chmod(0o555)
                    with self.assertRaises(ValueError):proof.finish()
                    self.assertEqual(self.binding.PHASE,'third-readback')

    def test_changed_fixed_patch_or_selected_configuration_refuses_before_cached_tree_use(self):
        for mutation in ('patch','configuration'):
            with self.subTest(mutation=mutation),self.fixture() as fixture:
                with self.binding.SourceProofSession(fixture['value']) as proof:
                    if mutation=='patch':fixture['patch'].return_value=b'changed public patch fixture\n'
                    else:fixture['control']['value']={**fixture['value'],'sdk':{'unreviewed':True}}
                    with self.assertRaises(ValueError):proof.finish()
                    self.assertEqual(self.binding.PHASE,'input-readback')
                    self.assertEqual(fixture['sweeps'].call_count,5)
                    self.assertFalse(proof.finished)

    def test_original_deadline_exhaustion_and_clock_replacement_refuse_before_final_io(self):
        for mutation in ('expired','replacement'):
            with self.subTest(mutation=mutation),self.fixture() as fixture:
                with self.binding.SourceProofSession(fixture['value']) as proof:
                    if mutation=='replacement':
                        source.DEADLINE=proof.deadline+1
                        with self.assertRaises(ValueError):proof.finish()
                        source.DEADLINE=proof.deadline
                    else:
                        with patch.object(source.time,'monotonic',return_value=proof.deadline),self.assertRaises(ValueError):proof.finish()
                    self.assertEqual(fixture['sweeps'].call_count,5)
                    self.assertFalse(proof.finished)

    def test_actual_main_keeps_partial_receipt_unqualified_when_final_ancestor_readback_refuses(self):
        with self.fixture() as fixture:
            original=self.binding.SourceProofSession.initial_report
            def changed_after_report(proof):
                result=original(proof)
                file=fixture['roots']['third']/'source/nested/run'
                file.chmod(0o600);file.write_bytes(b'changed after initial proof\n');file.chmod(0o555)
                return result
            with patch.object(self.binding.SourceProofSession,'initial_report',autospec=True,side_effect=changed_after_report), \
                    patch.object(self.binding.sys,'argv',['binding.py']), \
                    patch.dict(os.environ,{'TEST_TIMEOUT':'900','TEST_UNDECLARED_OUTPUTS_DIR':str(fixture['root'])}):
                with self.assertRaises(ValueError):self.binding.main()
            partial=fixture['root']/'native-acquisition-binding'
            self.assertTrue((partial/'receipt.json').is_file())
            self.assertEqual(partial.stat().st_mode & 0o777,0o700)
            self.assertIsNone(source.DEADLINE)
            self.assertEqual(self.binding.PHASE,'third-readback')
            self.assertTrue(all(row.held is row.tree is row.receipt is None
                for proof in fixture['constructed'] for _,row in proof.snapshots))

    def test_phase_projection_is_closed_and_never_formats_untrusted_values(self):
        class Poison:
            def __str__(self):raise AssertionError('untrusted formatting')
        for value in (Poison(),'unrecognized-path-or-exception-text',None):
            with patch.object(self.binding,'PHASE',value):
                self.assertEqual(self.binding.refusal_message(),'ninth source binding refused at input')
        for value in self.binding.PHASES:
            self.binding.phase(value)
            self.assertEqual(self.binding.refusal_message(),'ninth source binding refused at '+value)
        with self.assertRaises(ValueError):self.binding.phase('not-a-public-stage')


if __name__ == "__main__":
    unittest.main()
