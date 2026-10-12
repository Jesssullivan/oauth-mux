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
        self.assertIn('@omux_original_native_sdk_inputs//:inputs',macro)
        for name in ('codex_native_file_writer_models.py','codex_native_siwc_catalog_models.py'):
            self.assertIn(name,macro)


if __name__ == '__main__':unittest.main()
