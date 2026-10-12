"""Closed cold-selector/full-target/evidence predicates; no Rust/provider execution."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
import codex_native_siwc_catalog_models as model


class CatalogDriverTests(unittest.TestCase):
    def setUp(self):
        self.deadline = model.source.DEADLINE
        model.source.DEADLINE = time.monotonic()+120
    def tearDown(self): model.source.DEADLINE = self.deadline

    def log(self,names,ignored=()):
        rows = ['running '+str(len(names)+len(ignored))+' tests']
        rows += ['test '+name+' ... ok' for name in names]
        rows += ['test '+name+' ... ignored, upstream declared ignore' for name in ignored]
        rows += ['test result: ok. '+str(len(names))+' passed; 0 failed; '+str(len(ignored))+' ignored; 0 measured; 0 filtered out; finished in 0.01s']
        return ('\n'.join(rows)+'\n').encode()

    def test_exact_twenty_and_preserved_fifteen_are_bound_to_their_normal_target(self):
        expected = model.expected_tests()
        self.assertEqual(tuple(expected),model.TARGETS)
        self.assertEqual(tuple(map(len,expected.values())),(30,4,1,0))
        self.assertEqual(len({name for names in expected.values() for name in names}),35)
        for target,names in expected.items():
            report = model.accept_log(self.log(names+('ordinary::regression',)),names)
            self.assertEqual(report['required_passed'],list(names))
            self.assertEqual(report['passed'],len(names)+1)

    def test_missing_duplicate_failed_or_ignored_required_method_refuses(self):
        names = model.expected_tests()[model.TARGETS[0]]
        good = self.log(names)
        wrong = [self.log(names[:-1]), self.log(names+(names[0],)),
            good.replace(('test '+names[0]+' ... ok').encode(),('test '+names[0]+' ... FAILED').encode()),
            self.log(names[1:],(names[0],)),good.replace(b'0 filtered out',b'1 filtered out'),
            good.replace(b'running 30 tests',b'running 29 tests')]
        for raw in wrong:
            with self.assertRaises(ValueError): model.accept_log(raw,names)
        unrelated = model.accept_log(self.log(names,('ordinary::explicitly_ignored',)),names)
        self.assertEqual(unrelated['ignored'],1)
        self.assertEqual(unrelated['passed'],30)

    def test_pending_or_mismatched_catalog_selector_never_constructs_ready_source(self):
        raw = json.dumps({'schema_version':1,'kind':'omux-native-siwc-catalog-model-selection-v1',
            'status':'PENDING-GENUINE-SOURCE-QUALIFICATION','catalog_controls_sha256':model.catalog.CONTROL_SHA,'source':None}).encode()
        with self.assertRaises(ValueError): model.selection(raw)
        value = json.loads(raw)
        for changed in ({**value,'source':{'root':'/synthetic/not-authority'}},
                {**value,'catalog_controls_sha256':'a'*64}, {**value,'status':'ready'}):
            with self.assertRaises(ValueError): model.selection(json.dumps(changed).encode())

    def test_normal_native_command_is_same_locked_builder_empty_filter_and_original_remaining_cutoff(self):
        # The real builder is tested without invoking it as a process. All query
        # qualification remains an explicit seam; this is argv policy only.
        report = {'kind':model.catalog.KIND,'patch_sha256':['a'*64]*12,
            'inventory_sha256':'b'*64,'generated_hub':{},**{name:False for name in model.catalog.previous.FALSE_FLAGS}}
        mapping = {'repositories':{model.family.binding.metadata.HUB:str(model.family.query.EXPORT_ROOT/'repositories'/model.family.binding.metadata.HUB)},
            'module_overrides':{},'registry_cache':str(model.family.query.EXPORT_ROOT/'registry-cache'),
            'inventory_sha256':'c'*64,'mapping_sha256':'d'*64}
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary); work=base/'work'
            published=Mock(active=True,path=base/'source',hub={})
            sdk=Mock();sdk.mapping.return_value=mapping
            tools={'status':'declared-fixed-query-tools-byte-qualified','inputs_rechecked':True,
                'query_tools':{'tools':{'bash':'/nix/store/'+'a'*32+'-bash-fixture/bin/bash','bazel':model.native.BAZEL}}}
            cutoff=time.monotonic()+300
            with patch.object(model.family.query_tools,'verify_repository',return_value=tools):
                plan=model.native_plan(published,sdk,report,work,cutoff)
            self.assertEqual(tuple(plan['argv'][-4:]),model.TARGETS)
            self.assertIn('--test_sharding_strategy=disabled',plan['argv'])
            self.assertEqual(plan['argv'].count('--test_filter='),1)
            self.assertFalse(any(row.startswith('--test_arg=') for row in plan['argv']))
            timeout=[row for row in plan['argv'] if row.startswith('--test_timeout=')]
            self.assertEqual(len(timeout),1);self.assertLessEqual(int(timeout[0].split('=')[1]),210)
            self.assertEqual(plan['argv'][0],model.native.BAZEL)
            self.assertIn('--repository_disable_download',plan['argv'])
            self.assertIn('--flaky_test_attempts=1',plan['argv'])
            self.assertEqual(plan['environment']['CARGO_NET_OFFLINE'],'true')
            self.assertIn('--override_repository='+model.family.binding.metadata.HUB+'='+str(published.path/'hub/source'),plan['argv'])

    def test_actual_role_alias_same_byte_replacement_refuses_without_re_resolving_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/'core-unit-tests';directory.mkdir()
            physical=directory/'body';physical.write_bytes(b'public libtest fixture');physical.chmod(0o444)
            alias=directory/'test.log';alias.symlink_to('body')
            with model.family.HeldControls() as owner:
                raw,captured=model.shared.read_actual(alias,owner)
                self.assertEqual(raw,b'public libtest fixture');self.assertEqual(captured,physical)
                alias.unlink();alias.symlink_to('body')
                with self.assertRaises(ValueError):owner.fence()

    def test_selected_source_close_drains_all_three_owned_descriptors_after_first_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'public';path.write_bytes(b'fixture')
            owner=model.SelectedSource(Path(temporary),'a'*64)
            fds=[os.open(path,os.O_RDONLY) for unused in range(3)]
            owner.receipt,owner.tree,owner.held=fds
            actual=os.close
            def close(fd):
                actual(fd)
                if fd==fds[0]:raise OSError('public close fault')
            with patch.object(model.os,'close',side_effect=close):
                with self.assertRaises(OSError):owner.__exit__(None,None,None)
            self.assertTrue(all(getattr(owner,name) is None for name in ('receipt','tree','held')))
            for fd in fds:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_actual_selected_source_and_tree_bind_only_held_readonly_444_or_555_receipt(self):
        # Actual publisher/held descriptor/tree predicate, not a transport claim
        # or qualified8557-member/source guardian fixture.
        for mode in (0o444,0o555):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)/'selected'
                files={'codex-rs/public.rs':('100644',b'public readonly source fixture\n')}
                report={'public':'bounded physical receipt fixture'}
                raw=model.source.encoded(report)
                output=model.source.write_source(root,files)
                receipt=None;tree=None
                try:
                    receipt,unused=model.family.publish_receipt(output,raw)
                    os.fchmod(receipt,mode);os.fchmod(output,0o555)
                    with model.SelectedSource(root,model.source.sha(raw),size=len(raw),modes=(0o444,0o555)) as owner:
                        owner.accept(report,files)
                        observed=model.stat.S_IMODE(os.fstat(owner.receipt).st_mode)
                        self.assertEqual(observed,mode)
                        members={'source/'+name:row for name,row in files.items()}
                        members['source-receipt.json']=('100644',raw)
                        tree=model.family.tenth.TreeWitness(root,members,
                            receipt_name='source-receipt.json' if observed==0o444 else None)
                        tree.check()
                        # A subsequent writable/changed mode refuses against
                        # original held/named full-nine anchors in both layouts.
                        os.fchmod(receipt,0o644)
                        with self.assertRaises(ValueError):owner.check()
                        with self.assertRaises(ValueError):tree.check()
                    with self.assertRaises(ValueError):
                        with model.SelectedSource(root,model.source.sha(raw),size=len(raw),modes=(0o444,0o555)):
                            self.fail('writable receipt admitted')
                finally:
                    if tree is not None:tree.close()
                    if receipt is not None:os.close(receipt)
                    os.close(output)
                    # Only owned fixture directories become removable; no
                    # custody predicate is altered while the owners are live.
                    for directory in (root,root/'source',root/'source/codex-rs'):
                        directory.chmod(0o700)

    def test_extra_owner_retires_streams_input_and_result_even_after_stream_close_failure(self):
        extra=model.ExtraOwners();extra.streams=Mock()
        extra.streams.close.side_effect=OSError('public failure')
        extra.stack=Mock();extra.evidence=Mock()
        with tempfile.TemporaryDirectory() as temporary:
            extra.output_parent=model.source.directory(Path(temporary));fd=extra.output_parent
            with self.assertRaises(OSError):extra.close()
            extra.evidence.close.assert_called_once();extra.stack.close.assert_called_once()
            with self.assertRaises(OSError):os.fstat(fd)

    def test_actual_main_cold_selector_closes_all_inputs_before_any_sdk_or_native_child(self):
        # Real current pinned control bytes and actual main/retainer/FD owners.
        # Only the heavy Inputs/native-child entrypoints are negative seams.
        real_root=Path(__file__).parent.parent
        controls=[model.family.CONFIG,model.catalog.previous.CONTROLS,
            model.catalog.previous.BASE+'native-siwc-v4.patch',
            model.catalog.previous.BASE+'native-delta-manifest.json',
            model.catalog.previous.BASE+'expected-tests.json',model.catalog.CONTROLS,
            model.catalog.BASE+'native-catalog-v3.patch',model.catalog.BASE+'native-delta-manifest.json',
            model.catalog.BASE+'expected-tests.json',model.SELECTION]
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);root=base/'declared';root.mkdir()
            runfiles=base/'runfiles';runfiles.mkdir()
            outputs=base/'outputs';outputs.mkdir()
            cache=base/'tmp';cache.mkdir()
            for name in controls:
                leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True)
                body = (json.dumps({'schema_version':1,'kind':'omux-native-siwc-catalog-model-selection-v1',
                    'status':'PENDING-GENUINE-SOURCE-QUALIFICATION','catalog_controls_sha256':model.catalog.CONTROL_SHA,'source':None}).encode()
                    if name == model.SELECTION else (real_root/name).read_bytes())
                leaf.write_bytes(body);leaf.chmod(0o444)
            (runfiles/'_repo_mapping').write_bytes(b'_main,unused,unused\n')
            (runfiles/'_repo_mapping').chmod(0o444)
            entry=time.monotonic_ns()
            env={'TEST_SRCDIR':str(runfiles),'TEST_UNDECLARED_OUTPUTS_DIR':str(outputs),
                'TEST_TMPDIR':str(cache),'TEST_TIMEOUT':'840',
                'OMUX_NATIVE_FILE_WRITER_MODELS_MODE':'native-file-writer-models-reserved',
                'OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS':str(entry),
                'OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS':str(entry+1200*10**9),
                'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH':'/home/jess/.local/state/omux-execution-20261005/12345678-1234-1234-1234-123456789abc',
                'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT':'a'*40,
                'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256':'b'*64}
            model.source.DEADLINE=None;model.family.query.DEADLINE=None
            before=set(os.listdir('/proc/self/fd'))
            with patch.dict(os.environ,env),patch.object(model.family.binding.ninth.parent,'ROOT',root), \
                    patch.object(model.sys,'argv',['public-driver']), \
                    patch.object(model.catalog.previous,'Inputs',side_effect=AssertionError('source/SDK opened')) as inputs, \
                    patch.object(model.shared,'run_once',side_effect=AssertionError('native child')) as child, \
                    patch('builtins.print') as marker:
                with self.assertRaises(ValueError):model.main()
            inputs.assert_not_called();child.assert_not_called();marker.assert_not_called()
            self.assertEqual(set(os.listdir('/proc/self/fd')),before)
            self.assertIsNone(model.source.DEADLINE);self.assertIsNone(model.family.query.DEADLINE)

    def test_declared_cold_repository_and_driver_graph_include_all_actual_owners(self):
        root=Path(__file__).parent.parent
        rule=(root/'tools/codex_native_siwc_catalog_model_inputs.bzl').read_text()
        macro=(root/'tools/codex_native_siwc_catalog_models_targets.bzl').read_text()
        self.assertIn('PENDING-GENUINE-SOURCE-QUALIFICATION',rule)
        self.assertIn('len(paths) == 8564 + len(hub)',rule)
        self.assertIn('native-siwc-catalog-source-reserved',rule)
        self.assertIn('@omux_native_siwc_catalog_model_inputs//:inputs',macro)
        shared_macro=(root/'tools/codex_native_siwc_catalog_content_source_targets.bzl').read_text()
        self.assertIn('catalog_content_source_data()',macro)
        for repo in ('omux_original_native_sdk_inputs','omux_native_n10_content_inputs',
                'omux_native_sdk_carrier_inputs','omux_native_sdk_carrier_proof_inputs','omux_protocol_history_query_tools'):
            self.assertIn('@'+repo+'//:inputs',shared_macro)
        for old in ('omux_codex_owner_status_source_inputs','omux_codex_owner_status_persistence_source_inputs',
                'omux_native_carrier_source_inputs','omux_native_file_writer_model_source_inputs'):
            self.assertNotIn('@'+old+'//:inputs',shared_macro)
        for name in ('codex_native_file_writer_models.py','codex_native_siwc_catalog_models.py'):
            self.assertIn(name,macro)

    def test_content_selector_binds_new_exact_source_role_without_constructor_readiness(self):
        producer = model.family.configuration()[1]['parent']['producer']
        epoch = Path(producer['receipt']).parent
        prefix = epoch / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools'
        selected = {'schema_version': 1, 'kind': 'omux-native-siwc-catalog-model-selection-v1',
            'catalog_controls_sha256': model.catalog.CONTROL_SHA,
            'status': 'qualified-catalog-content-source-hub-uncompiled',
            'source': {'root': str(prefix / 'codex_native_siwc_catalog_content_source_producer/test.outputs/native-siwc-catalog-content-source'),
                'receipt_sha256': 'a' * 64, 'receipt_bytes': 1, 'inventory_sha256': 'b' * 64,
                'producer': producer}}
        # This validates only closed typed syntax. No path/read/guardian/source
        # proof or ready authority is constructed by this fixture.
        self.assertEqual(model.selection(json.dumps(selected).encode()), selected)
        wrong = copy.deepcopy(selected)
        wrong['source']['root'] = str(prefix / 'codex_native_siwc_catalog_source_producer/test.outputs/native-siwc-catalog-source')
        with self.assertRaises(ValueError): model.selection(json.dumps(wrong).encode())
        wrong = copy.deepcopy(selected); wrong['status'] = 'verified-by-caller'
        with self.assertRaises(ValueError): model.selection(json.dumps(wrong).encode())
        self.assertEqual(model.SOURCE_ROUTES[selected['status']][:2],
            (model.content_catalog, model.content_source_guard))
        self.assertEqual(model.SOURCE_ROUTES['qualified-catalog-source-hub-uncompiled'][:2],
            (model.catalog, model.source_guard))

    def test_receipt_only_content_method_refuses_before_sdk_plan_or_native_work(self):
        report = {'kind': model.content_catalog.KIND, 'status': model.content_catalog.STATUS,
            'patch_sha256': ['a' * 64] * 12, 'historical_ancestor_reexecution': False,
            'native_runtime_qualified': False, 'source_intake': {'method': 'receipt-only'},
            **{name: False for name in model.catalog.previous.FALSE_FLAGS}}
        with tempfile.TemporaryDirectory() as temporary:
            published, sdk = Mock(active=True), Mock()
            with self.assertRaises(ValueError):
                model.native_plan(published, sdk, report, Path(temporary) / 'work', model.source.DEADLINE)
            sdk.check.assert_not_called(); published.full.assert_not_called()

    def test_actual_driver_owns_original_clock_after_nested_return_and_on_every_refusal(self):
        # Actual main/admission/route/execute/short/finally. The heavyweight
        # controller/source/SDK/native IO is a seam here and real controller
        # intake/child lifetime is exercised by the content-source test.
        for fault in ('none', 'nested-refusal', 'short-refusal'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); outputs = root / 'outputs'; outputs.mkdir()
                entry = time.monotonic_ns(); until = entry + 1200*10**9
                cutoff = float((entry + 600*10**9) / 10**9)
                env = {model.family.MODE: model.family.PROFILE, model.family.ENTRY: str(entry),
                    model.family.UNTIL: str(until), 'TEST_TIMEOUT': '840', 'TEST_UNDECLARED_OUTPUTS_DIR': str(outputs),
                    'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab',
                    'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT': 'a'*40, 'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256': 'b'*64}
                phases = []
                def clock(phase):
                    self.assertEqual((model.source.DEADLINE, model.family.query.DEADLINE), (cutoff, cutoff))
                    self.assertEqual(model.family.producer_context()['entry_monotonic_ns'], entry)
                    self.assertEqual(model.family.producer_context()['deadline_monotonic_ns'], until)
                    phases.append(phase)
                class Extra:
                    def __enter__(self): clock('outer-enter'); return self
                    def __exit__(self, *args): clock('outer-close')
                    def retain(self, owner): raise AssertionError('explicit nested IO seam')
                    def short(self):
                        clock('post-return-short')
                        if fault == 'short-refusal': raise ValueError('public short refusal')
                def nested(**kwargs):
                    clock('nested-enter')
                    self.assertEqual(model.family.reuse_admission(kwargs['_admitted']), (entry, until, cutoff))
                    kwargs['_child'](None, None, None, None, None, entry, until, cutoff)
                    clock('nested-return')
                    if fault == 'nested-refusal': raise ValueError('public nested refusal')
                def child(*args): clock('child'); return {'public': 'result seam'}
                selected = {'status': 'qualified-catalog-content-source-hub-uncompiled'}
                model.source.DEADLINE = model.family.query.DEADLINE = None
                with patch.dict(os.environ, env, clear=True), patch.object(model.sys, 'argv', ['public-driver']), \
                        patch.object(model.family, 'declared', return_value=b'public selected syntax seam'), \
                        patch.object(model, 'selection', return_value=selected), patch.object(model, 'ExtraOwners', Extra), \
                        patch.object(model.content_catalog, 'main', side_effect=nested), \
                        patch.object(model, 'native_child', side_effect=child), patch('builtins.print') as marker:
                    if fault == 'none': model.main()
                    else:
                        with self.assertRaises(ValueError): model.main()
                self.assertEqual(phases[:4], ['outer-enter', 'nested-enter', 'child', 'nested-return'])
                self.assertIn('outer-close', phases)
                self.assertEqual('post-return-short' in phases, fault != 'nested-refusal')
                self.assertEqual(marker.called, fault == 'none')
                self.assertIsNone(model.source.DEADLINE); self.assertIsNone(model.family.query.DEADLINE)

    def test_nested_clock_reuse_refuses_changed_context_cutoff_or_expiry_without_clearing_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            entry = time.monotonic_ns(); until = entry + 1200*10**9
            cutoff = float((entry + 600*10**9) / 10**9)
            env = {model.family.MODE: model.family.PROFILE, model.family.ENTRY: str(entry),
                model.family.UNTIL: str(until), 'TEST_TIMEOUT': '840', 'TEST_UNDECLARED_OUTPUTS_DIR': temporary,
                'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab',
                'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT': 'a'*40, 'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256': 'b'*64}
            model.source.DEADLINE = model.family.query.DEADLINE = cutoff
            try:
                with patch.dict(os.environ, env, clear=True):
                    valid = (entry, until, cutoff, model.source.encoded(model.family.producer_context()))
                    self.assertEqual(model.family.reuse_admission(valid), (entry, until, cutoff))
                    for bad in ((entry, until, cutoff+1.0, valid[3]), (entry, until+1, cutoff, valid[3]),
                            (entry, until, cutoff, b'public wrong context'), list(valid)):
                        with self.assertRaises(ValueError): model.family.reuse_admission(bad)
                    with patch.object(model.family.time, 'monotonic_ns', return_value=entry+600*10**9):
                        with self.assertRaises(ValueError): model.family.reuse_admission(valid)
                self.assertEqual((model.source.DEADLINE, model.family.query.DEADLINE), (cutoff, cutoff))
            finally: model.source.DEADLINE = model.family.query.DEADLINE = None


if __name__ == '__main__':unittest.main()
