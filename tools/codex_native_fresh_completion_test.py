"""Provider-free refusal models for the separate fresh completion admission."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_native_fresh_completion as fresh
import codex_native_profile as native


class FreshAdmissionModels(unittest.TestCase):
    def args(self, selector=fresh.SELECTOR, attempt=9):
        return SimpleNamespace(profile='codex-native', manager='system',
            state_dir=native.STATE, source_dirty='false', source_commit='1'*40,
            native_mode=native.COMBINED_MODE if attempt == 9 else 'schema',
            native_fresh_completion=selector, native_fresh_completion_sha256='a'*64,
            native_global_attempt=attempt, native_owned_candidate_cache=False,
            native_cache_attempt=None, native_cache_transition=None,
            native_cache_transition_sha256=None, native_cache_phase2=None,
            native_cache_phase2_sha256=None, reuse_owned_cache=False,
            native_aggregate_seconds=3600, native_deadline=None,
            native_source_root=Path(fresh.INPUTS['source_root']),
            native_source_sha256=fresh.INPUTS['source_receipt_sha256'],
            native_export_root=Path(fresh.INPUTS['export_root']),
            native_export_sha256=fresh.INPUTS['export_receipt_sha256'],
            native_patch_sha256=list(fresh.INPUTS['patch_sha256']))

    def test_only_global_nine_and_conditional_ten_complete_selector_allowed(self):
        self.assertTrue(fresh.selected(self.args()))
        self.assertTrue(fresh.selected(self.args(attempt=10)))
        for field, value in (('native_global_attempt',1), ('native_global_attempt',11),
                ('native_global_attempt',True), ('native_mode','cli-opt'),
                ('native_fresh_completion',Path('/private/native-fresh-completion.json')),
                ('native_fresh_completion_sha256',None), ('source_dirty','true'),
                ('manager','user'), ('native_owned_candidate_cache',True),
                ('native_cache_attempt',1), ('reuse_owned_cache',True),
                ('native_cache_phase2',Path('/public/phase2.json'))):
            args = self.args()
            setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                fresh.selected(args)

    def test_foreign_input_refuses_before_any_selected_source_or_export_read(self):
        args = self.args()
        args.native_export_root = Path('/private/credential-directory')
        with patch.object(native, 'verify_inputs') as read:
            with self.assertRaises(ValueError):
                fresh.bindings(args, {}, ('a'*64,[]), '/nix/store/locked/bin', 'system')
            read.assert_not_called()

    def test_closed_document_and_codegen_reject_substitution(self):
        selected = {'kind':fresh.KIND, 'core_codegen':fresh.fixed_codegen()}
        document = {'schema_version':1,'kind':fresh.KIND,'bindings':selected,
            'controller_inventory':{'tools/example.py':'a'*64},
            'previous_dispatches':fresh.consumed_dispatches()}
        fresh.validate_document(document, selected, document['controller_inventory'])
        for alter in (lambda d:d.update(extra='ignored'),
                lambda d:d.update(schema_version=True),
                lambda d:d['previous_dispatches'].pop(),
                lambda d:d['previous_dispatches'][-1].update(sha256='0'*64),
                lambda d:d['bindings']['core_codegen']['policy']['options'].append('-Clto=fat')):
            changed = copy.deepcopy(document)
            alter(changed)
            with self.assertRaises(ValueError):
                fresh.validate_document(changed, selected, document['controller_inventory'])
        policy = native.core_codegen_policy()
        policy['policy']['options'].append('-Copt-level=3')
        with patch.object(native, 'core_codegen_policy', return_value=policy):
            with self.assertRaises(ValueError):
                fresh.fixed_codegen()
        history = fresh.consumed_dispatches()
        history[-1]['sha256'] = '0'*64
        self.assertEqual(fresh.consumed_dispatches()[-1]['sha256'],
            '12543b3f84d6db2fd4c70074248da87627f5666df14c783f281ab7bc5f2013c0')

    def historical(self, row):
        last = row['attempt'] == 6
        return {'id':row['id'],'profile':'codex-native','manager':'system',
            'unit':'omux-execution-'+row['id']+'.service','exit':125 if last else 124,
            'workload_exit':9 if last else 124,'descendants_empty':True,
            'test_evidence':{'state':'preservation-failed'},
            'native_sdk':{'source_and_export_verified_after_cleanup':False if last else True},
            'native_candidate_cache':{'key':row['cache_key'],'attempt':row['attempt'],
                'transition_verified_after_cleanup':None if last else True}}

    def test_all_eight_failures_are_consumed_without_promoting_false_null_to_success(self):
        seen = []
        def read(row, deadline):
            seen.append(row['id'])
            return self.historical(row)
        with patch.object(fresh, 'read_receipt', side_effect=read):
            fresh.historical_receipts(None, lambda receipt: True)
        self.assertEqual(seen, [row['id'] for row in fresh.consumed_dispatches()])
        for field, value in (('exit',0), ('exit',False), ('workload_exit',None),
                ('descendants_empty',False)):
            def changed(row, deadline):
                result = self.historical(row)
                if row['id'] == fresh.consumed_dispatches()[-1]['id']:
                    result[field] = value
                return result
            with patch.object(fresh, 'read_receipt', side_effect=changed):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    fresh.historical_receipts(None, lambda receipt: True)
        def forged_integrity(row, deadline):
            result = self.historical(row)
            if row['id'] == fresh.consumed_dispatches()[-1]['id']:
                result['native_sdk']['source_and_export_verified_after_cleanup'] = True
            return result
        with patch.object(fresh, 'read_receipt', side_effect=forged_integrity):
            with self.assertRaises(ValueError):
                fresh.historical_receipts(None, lambda receipt: True)
        with patch.object(fresh, 'read_receipt', side_effect=lambda row, deadline:self.historical(row)):
            with self.assertRaises(ValueError):
                fresh.historical_receipts(None, lambda receipt: False)

    def fixture(self, state, attempt=9):
        args = self.args(state/'native-fresh-completion.json', attempt)
        args.state_dir = state
        graph = ('a'*64, [])
        provenance = {'kind':fresh.KIND, 'core_codegen':fresh.fixed_codegen(),
            'source_commit':args.source_commit}
        document = {'schema_version':1,'kind':fresh.KIND,'bindings':provenance,
            'controller_inventory':{},'previous_dispatches':fresh.consumed_dispatches()}
        raw = fresh.canonical(document)+b'\n'
        selector = state/'native-fresh-completion.json'
        selector.write_bytes(raw)
        selector.chmod(0o600)
        args.native_fresh_completion_sha256 = hashlib.sha256(raw).hexdigest()
        key = hashlib.sha256(fresh.canonical(provenance)).hexdigest()
        run = state/'12345678-1234-4234-8234-123456789abc'
        run.mkdir(mode=0o700,exist_ok=True)
        return args, graph, provenance, key, run

    def copy_source(self, root, receipt, target):
        source = target/'native-input/source'
        source.mkdir(mode=0o700,parents=True)
        item = source/'fixture.rs'
        item.write_bytes(b'qualified fixture source\n')
        # The actual sealed producer gives every regular file mode0555;
        # original Git modes remain separately pinned in the inventory.
        item.chmod(0o555)
        source.chmod(0o555)
        return source

    def admitted(self, state, attempt=9):
        args, graph, provenance, key, run = self.fixture(state, attempt)
        inventory = {'fixture.rs':{'mode':'100644',
            'sha256':hashlib.sha256(b'qualified fixture source\n').hexdigest()}}
        # Only temporary shared ancestor qualification, complete external input
        # qualification and live unit query are substituted. The real private
        # root/journal/lock/sourcecopy/empty output checks still execute.
        with patch.object(fresh, 'bindings', return_value=provenance), \
                patch.object(fresh, 'controller_inventory', return_value={}), \
                patch.object(fresh, 'historical_receipts'), \
                patch.object(fresh, 'trusted_parent',
                    side_effect=lambda path:os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)), \
                patch.object(native, 'validate_source', return_value={'source_inventory':inventory}), \
                patch.object(native, 'copy_source', side_effect=self.copy_source):
            return fresh.Admission(args,run,{},graph,'/nix/store/locked/bin','system',
                lambda previous:True)

    def cleanup_fixture(self, state):
        for root, _, _ in os.walk(state):
            Path(root).chmod(0o700)

    def test_copied_source_refuses_unsealed_regular_mode(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state = Path(temp)
            admission = self.admitted(state)
            try:
                (admission.source/'fixture.rs').chmod(0o444)
                inventory = {'fixture.rs':{'mode':'100644',
                    'sha256':hashlib.sha256(b'qualified fixture source\n').hexdigest()}}
                with patch.object(native,'validate_source',return_value={'source_inventory':inventory}), \
                        patch.object(fresh,'trusted_parent',side_effect=lambda path:os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)):
                    with self.assertRaises(ValueError):
                        admission.verify_source_copy()
            finally:
                admission.close()
                self.cleanup_fixture(state)

    def test_fresh_root_creation_is_empty_and_preexisting_root_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state = Path(temp)
            admission = self.admitted(state)
            try:
                self.assertEqual(os.listdir(admission.output_fd), [])
                self.assertEqual(admission.facts()['global_attempt'],9)
                self.assertEqual(admission.facts()['key'],admission.facts()['provenance_sha256'])
                self.assertIsNone(admission.facts()['verified_after_cleanup'])
                marker = admission.root/'owner.json'
                self.assertFalse(marker.exists())
            finally:
                admission.close()
                self.cleanup_fixture(state)
            with self.assertRaises(FileExistsError):
                self.admitted(state)
            self.assertFalse(marker.exists())

    def test_schemas_refuse_pending_fresh_journal_without_opening_predecessor(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state = Path(temp)
            admission = self.admitted(state)
            admission.close()
            with patch.object(fresh, 'read_receipt') as read:
                with self.assertRaises(ValueError):
                    self.admitted(state,10)
                read.assert_not_called()
            self.cleanup_fixture(state)

    def successful_receipt(self, admission):
        facts = admission.facts()
        facts.update(verified_before_launch=True, verified_after_cleanup=True)
        return {'id':admission.run.name,'profile':'codex-native','manager':'system',
            'exit':0,'workload_exit':0,'controller_failure':None,'descendants_empty':True,
            'unit':'omux-execution-'+admission.run.name+'.service',
            'output_base':str(admission.lease.output_base),
            'native_candidate_cache':None, 'native_fresh_completion':facts,
            'graph_sha256':admission.graph[0],'source_commit':admission.args.source_commit,
            'source_dirty':'false','targets':list(native.MODES[native.COMBINED_MODE][1]),
            'test_evidence':{'state':'preserved'},
            'native_sdk':{'mode':native.COMBINED_MODE,
                'source_and_export_verified_after_cleanup':True,
                'source_receipt_sha256':admission.args.native_source_sha256,
                'export_receipt_sha256':admission.args.native_export_sha256,
                'aggregate_seconds':3600,'original_entry_monotonic_ns':100*10**9,
                'original_deadline_monotonic_ns':3700*10**9,
                'plan':{'core_codegen':fresh.fixed_codegen(),
                    'source_inventory_sha256':fresh.INPUTS['source_inventory_sha256'],
                    'export_inventory_sha256':fresh.INPUTS['export_inventory_sha256'],
                    'mapping_sha256':fresh.INPUTS['mapping_sha256'],
                    'cwd':str(admission.source),
                    'environment':{'USE_BAZEL_VERSION':native.BAZEL_VERSION},
                    'argv':native.core_codegen_arguments()+[
                        '--lockfile_mode=error','--repository_disable_download',
                        '--sandbox_default_allow_network=false','--jobs=1',
                        '--host_jvm_args=-Xmx768m','--repo_contents_cache=',
                        '--disk_cache=','--remote_executor=','--remote_cache=',
                        '--local_test_jobs=1'],
                    'candidate_output_base':str(admission.lease.output_base)}}}

    def test_success_requires_actual_zero_positive_cleanup_policy_and_original_deadline(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state=Path(temp); admission=self.admitted(state)
            try:
                receipt=self.successful_receipt(admission)
                facts=receipt['native_fresh_completion']
                def verify(value):
                    fresh.verify_success(value,facts,admission.graph,
                        admission.args.native_source_sha256,admission.args.native_export_sha256,
                        native.COMBINED_MODE)
                verify(receipt)
                mutations=(lambda r:r.update(exit=False),lambda r:r.update(workload_exit=None),
                    lambda r:r.update(exit=125,workload_exit=9),
                    lambda r:r.update(descendants_empty=False),
                    lambda r:r.update(unit='foreign.service'),
                    lambda r:r.update(output_base='/foreign/output-base'),
                    lambda r:r['native_sdk']['plan']['argv'].remove('--repository_disable_download'),
                    lambda r:r['native_sdk'].update(source_and_export_verified_after_cleanup=False),
                    lambda r:r.update(test_evidence={'state':'preservation-failed'}),
                    lambda r:r['native_sdk'].update(original_deadline_monotonic_ns=7300*10**9),
                    lambda r:r['native_sdk']['plan']['core_codegen']['policy']['options'].append('-Clto=fat'))
                for alter in mutations:
                    value=copy.deepcopy(receipt); alter(value)
                    with self.assertRaises(ValueError):verify(value)
            finally:
                admission.close(); self.cleanup_fixture(state)

    def test_controller_inventory_matches_real_graph_and_rejects_changed_bytes(self):
        from guard_cache import graph_digest
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('BUILD.bazel','tools/a.py','tools/deep/b.bzl'):
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((name+'\n').encode())
            graph=graph_digest(root)
            with patch.object(fresh,'trusted_parent',side_effect=lambda path:
                    os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)):
                inventory=fresh.controller_inventory(root,graph,None)
                self.assertEqual(set(inventory),set(graph[1]))
                (root/'tools/a.py').write_bytes(b'changed controller\n')
                with self.assertRaises(ValueError):fresh.controller_inventory(root,graph,None)

    def test_fresh_copy_mutation_refuses_real_inventory_readback(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state=Path(temp); admission=self.admitted(state)
            expected={'fixture.rs':{'mode':'100644',
                'sha256':hashlib.sha256(b'qualified fixture source\n').hexdigest()}}
            try:
                item=admission.source/'fixture.rs'; item.chmod(0o644)
                item.write_bytes(b'changed copied native source\n'); item.chmod(0o444)
                with patch.object(native,'validate_source',return_value={'source_inventory':expected}), \
                        patch.object(fresh,'trusted_parent',side_effect=lambda path:
                            os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)):
                    with self.assertRaises(ValueError):admission.verify_source_copy()
            finally:
                admission.close(); self.cleanup_fixture(state)

    def test_terminal_write_failure_is_redacted_failed_actual_guard_receipt(self):
        receipt={'exit':0, 'workload_exit':0, 'native_fresh_completion':{'kind':fresh.KIND}}
        seen=[]
        successful=SimpleNamespace(finish=lambda value,pin:seen.append((copy.deepcopy(value),pin)))
        raw=fresh.terminal_receipt(successful,receipt)
        self.assertEqual(seen[0][1],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(json.loads(raw)['exit'],0)
        failed=SimpleNamespace(finish=lambda value,pin:(_ for _ in ()).throw(
            ValueError('model-private-diagnostic')))
        raw=fresh.terminal_receipt(failed,copy.deepcopy(receipt))
        self.assertEqual(json.loads(raw)['exit'],125)
        self.assertEqual(json.loads(raw)['native_fresh_completion']['terminal_record'],'uncommitted')
        self.assertNotIn('model-private-diagnostic',raw)

    def test_final_journal_failure_or_guard_failure_never_grants_schema(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'):
            state=Path(temp); admission=self.admitted(state)
            try:
                admission.verified_after_cleanup=True
                receipt=self.successful_receipt(admission)
                receipt.update(exit=125,workload_exit=9)
                admission.finish(receipt,'c'*64)
                raw=(admission.root/fresh.JOURNAL).read_bytes()
                self.assertEqual(json.loads(raw)['status'],'closed')
                with patch.object(fresh,'verify_qualification',side_effect=ValueError('missing named gates')) as named:
                    with self.assertRaises(ValueError):
                        admission.finish(self.successful_receipt(admission),'d'*64)
                    named.assert_called_once()
                self.assertEqual(json.loads((admission.root/fresh.JOURNAL).read_bytes())['status'],'closed')
            finally:
                admission.close(); self.cleanup_fixture(state)


    def test_schema_join_rechecks_production_named_evidence_and_actual_cli_bytes(self):
        # Synthetic logs/ELF exercise the real custody/hash/join code only.
        # Complete external sealed inputs and resident queries are substituted
        # by admitted(); this model makes no compilation or support claim.
        with tempfile.TemporaryDirectory() as temp, patch.object(native,'STATE',Path(temp)), \
                patch.object(fresh,'SELECTOR',Path(temp)/'native-fresh-completion.json'), \
                patch.object(native,'trusted_parent',side_effect=lambda path:
                    os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)), \
                patch.object(fresh,'trusted_parent',side_effect=lambda path:
                    os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)):
            state=Path(temp); admission=self.admitted(state)
            try:
                admission.verified_after_cleanup=True
                receipt=self.successful_receipt(admission)
                run=admission.run
                (run/'test-evidence').mkdir(mode=0o700)
                rows=[]
                for index,(target,names) in enumerate(native.QUALIFICATION_GATES.items()):
                    raw=('\n'.join('test '+name+' ... ok' for name in names)
                        +'\ntest result: ok. %d passed; 0 failed; 0 ignored;\n'%len(names)).encode()
                    name='log%d'%index
                    (run/'test-evidence'/name).write_bytes(raw)
                    (run/'test-evidence'/name).chmod(0o600)
                    rows.append({'target':target,'files':[{'source':'test.log','state':'copied',
                        'file':name,'sha256':hashlib.sha256(raw).hexdigest()}]})
                rows.append({'target':native.CLI,'state':'missing-test-directory','files':[]})
                manifest={'targets':list(native.MODES[native.COMBINED_MODE][1]),'results':rows}
                raw=(json.dumps(manifest,sort_keys=True)+'\n').encode()
                (run/'test-evidence.json').write_bytes(raw)
                (run/'test-evidence.json').chmod(0o600)
                receipt['test_evidence']['sha256']=hashlib.sha256(raw).hexdigest()
                context={'invocation_id':run.name,'output_base':str(admission.lease.output_base),
                    'source_receipt_sha256':admission.args.native_source_sha256,
                    'export_receipt_sha256':admission.args.native_export_sha256,
                    'source_inventory_sha256':fresh.INPUTS['source_inventory_sha256'],
                    'export_inventory_sha256':fresh.INPUTS['export_inventory_sha256'],
                    'candidate_cache_key':admission.key,'candidate_provenance_sha256':admission.key,
                    'controller_graph_sha256':admission.graph[0],'bazel':native.BAZEL,
                    'workload_exit':0,'descendants_empty':True,
                    'source_and_export_verified_after_cleanup':True}
                cli=admission.lease.output_base/'execroot/_main/bazel-out/k8-opt/bin/codex-rs/cli/codex'
                cli.parent.mkdir(mode=0o700,parents=True)
                cli.write_bytes(b'\x7fELFmodel-only-qualified-file');cli.chmod(0o500)
                native.qualification_evidence(run,manifest,context)
                fresh.verify_qualification(run,receipt,None)
                admission.finish(receipt,'d'*64)
                self.assertEqual(json.loads((admission.root/fresh.JOURNAL).read_bytes())['status'],
                    'qualified-completion')
                log=run/'test-evidence/log0'; log.write_bytes(b'changed named test log\n')
                with self.assertRaises(ValueError):fresh.verify_qualification(run,receipt,None)
                raw=fresh.terminal_receipt(admission,receipt)
                self.assertEqual(json.loads(raw)['exit'],125)
                self.assertEqual(json.loads((admission.root/fresh.JOURNAL).read_bytes())['status'],'closed')
            finally:
                admission.close();self.cleanup_fixture(state)


if __name__ == '__main__':
    unittest.main()
