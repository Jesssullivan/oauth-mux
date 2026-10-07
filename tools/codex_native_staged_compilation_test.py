"""Synthetic held-IO/state-machine refusals; no native executable is invoked.

The fixture substitutes external sealed input qualification, controller graph
inventory and live unit queries. Root/output/source/anchor/journal/artifact IO
and the production parser/hash/state logic operate on owned temporary bytes.
"""
import copy
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import shutil
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_native_staged_compilation as staged
import codex_native_profile as native


class StagedAdmissionModels(unittest.TestCase):
    def args(self, stage=1, commit='1'*40):
        return SimpleNamespace(profile='codex-native',manager='system',state_dir=native.STATE,
            source_dirty='false',source_commit=commit,native_mode=staged.STAGES[stage][0],
            native_staged_compilation=staged.SELECTOR,
            native_staged_compilation_sha256='a'*64,native_stage=stage,
            native_owned_candidate_cache=False,reuse_owned_cache=False,native_cache_attempt=None,
            native_cache_transition=None,native_cache_transition_sha256=None,
            native_cache_phase2=None,native_cache_phase2_sha256=None,
            native_fresh_completion=None,native_fresh_completion_sha256=None,native_global_attempt=None,
            native_aggregate_seconds=3600,native_deadline=None,
            native_source_root=Path(staged.INPUTS['source_root']),
            native_source_sha256=staged.INPUTS['source_receipt_sha256'],
            native_export_root=Path(staged.INPUTS['export_root']),
            native_export_sha256=staged.INPUTS['export_receipt_sha256'],
            native_patch_sha256=list(staged.INPUTS['patch_sha256']))

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as mocks:
            self.state=Path(temp)
            mocks.enter_context(patch.object(native,'STATE',self.state))
            mocks.enter_context(patch.object(staged,'SELECTOR',self.state/'native-staged-compilation.json'))
            mocks.enter_context(patch.object(staged,'CHAIN',self.state/'native-staged-compilation-chain.json'))
            self.source_meta={'inventory_sha256':staged.INPUTS['source_inventory_sha256'],
                'graph_files':{name:{'sha256':'b'*64} for name in native.GRAPH}}
            self.export_meta={'inventory_sha256':staged.INPUTS['export_inventory_sha256'],
                'mapping_sha256':staged.INPUTS['mapping_sha256'],
                'registry_cache':staged.INPUTS['export_root']+'/registry-cache',
                'repositories':{},'module_overrides':{}}
            self.source_inventory={'fixture.rs':{'mode':'100644',
                'sha256':hashlib.sha256(b'qualified model source\n').hexdigest()}}
            self.tools={name:'/nix/store/model-'+name+'/bin/'+name for name in (
                'bazel','python','systemd_run','systemctl','bootstrap','closure','java','bash')}
            self.tools['bazel']=native.BAZEL
            self.tools['bash']='/nix/store/i27rhb3nr65rkrwz36bchkwmav6ggsmn-bash-5.3p9/bin/bash'
            self.locked_path='/nix/store/model-tools/bin'
            self.graph=('a'*64,['tools/fixture.py'])
            self.inventory={'tools/fixture.py':'b'*64}
            mocks.enter_context(patch.object(native,'verify_inputs',
                return_value=(self.source_meta,self.export_meta)))
            mocks.enter_context(patch.object(native,'validate_source',
                return_value={'source_inventory':self.source_inventory}))
            mocks.enter_context(patch.object(native,'copy_source',side_effect=self.copy_source))
            mocks.enter_context(patch.object(staged,'controller_inventory',return_value=self.inventory))
            mocks.enter_context(patch.object(staged,'historical_receipts'))
            try:yield
            finally:
                for directory,_,_ in os.walk(self.state):
                    Path(directory).chmod(0o700)
                chain=self.state/staged.CHAIN.name
                if chain.exists():chain.chmod(0o600)

    def copy_source(self,root,receipt,target):
        parent=target/'native-input';parent.mkdir(mode=0o700)
        source=parent/'source';source.mkdir(mode=0o700)
        (source/'fixture.rs').write_bytes(b'qualified model source\n')
        (source/'fixture.rs').chmod(0o444)
        source.chmod(0o555);parent.chmod(0o555)
        return source

    def admit(self,stage=1,commit='1'*40):
        args=self.args(stage,commit)
        expected=staged.bindings(args,self.tools,self.graph,self.locked_path,'system')
        document={'schema_version':1,'kind':staged.KIND,'bindings':expected,
            'controller_inventory':self.inventory,'previous_dispatches':staged.consumed_dispatches()}
        raw=staged.canonical(document)+b'\n'
        staged.SELECTOR.write_bytes(raw);staged.SELECTOR.chmod(0o600)
        args.native_staged_compilation_sha256=hashlib.sha256(raw).hexdigest()
        epoch=('%08d-1234-4234-8234-123456789abc'%stage)
        run=self.state/epoch;run.mkdir(mode=0o700,exist_ok=True)
        return staged.Admission(args,run,self.tools,self.graph,self.locked_path,'system',lambda value:True)

    def receipt(self,admission):
        if not hasattr(admission,'_model_plan'):
            admission._model_plan=native.command(admission.args,admission.run,self.locked_path,
                self.tools['bash'],admission)
        return {'id':admission.run.name,'unit':'omux-execution-'+admission.run.name+'.service',
            'profile':'codex-native','manager':'system','source_commit':admission.args.source_commit,
            'source_dirty':'false','graph_sha256':self.graph[0],'output_base':str(admission.lease.output_base),
            'exit':0,'workload_exit':0,'controller_failure':None,'descendants_empty':True,
            'native_candidate_cache':None,'native_fresh_completion':None,
            'native_staged_compilation':admission.facts(),
            'targets':list(staged.STAGES[admission.stage][2]),
            'test_evidence':{'state':'preserved' if admission.stage==3 else 'not-applicable'},
            'observed_properties':{'MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'512',
                'CPUQuotaPerSecUSec':'2s','PrivateNetwork':'yes','RuntimeMaxUSec':'58min'},
            'native_sdk':{'mode':staged.STAGES[admission.stage][0],'aggregate_seconds':3600,
                'original_entry_monotonic_ns':100*10**9,'original_deadline_monotonic_ns':3700*10**9,
                'source_receipt_sha256':admission.args.native_source_sha256,
                'export_receipt_sha256':admission.args.native_export_sha256,
                'source_and_export_verified_after_cleanup':True,'plan':copy.deepcopy(admission._model_plan)}}

    def libraries(self,admission):
        for package,crate in (('config','codex_config'),('login','codex_login'),
                ('app-server-protocol','codex_app_server_protocol')):
            path=admission.lease.output_base/'execroot/_main/bazel-out/k8-opt/bin/codex-rs'/package/('lib'+crate+'-123.rlib')
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(b'!<arch>\nmodel selected target archive\n');path.chmod(0o444)

    def cli(self,admission):
        path=admission.lease.output_base/'execroot/_main/bazel-out/k8-opt/bin/codex-rs/cli/codex'
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_bytes(b'\x7fELFmodel-only-no-execution');path.chmod(0o500)
        return path

    def qualify(self,admission,receipt):
        run=admission.run;(run/'test-evidence').mkdir(mode=0o700)
        rows=[]
        for index,(target,names) in enumerate(native.QUALIFICATION_GATES.items()):
            raw=('\n'.join('test '+name+' ... ok' for name in names)
                +'\ntest result: ok. %d passed; 0 failed; 0 ignored;\n'%len(names)).encode()
            file='log%d'%index
            (run/'test-evidence'/file).write_bytes(raw);(run/'test-evidence'/file).chmod(0o600)
            rows.append({'target':target,'files':[{'source':'test.log','state':'copied',
                'file':file,'sha256':hashlib.sha256(raw).hexdigest()}]})
        rows.append({'target':native.CLI,'state':'missing-test-directory','files':[]})
        manifest={'targets':list(staged.STAGES[3][2]),'results':rows}
        raw=(json.dumps(manifest,sort_keys=True)+'\n').encode()
        (run/'test-evidence.json').write_bytes(raw);(run/'test-evidence.json').chmod(0o600)
        receipt['test_evidence']['sha256']=hashlib.sha256(raw).hexdigest()
        native.qualification_evidence(run,manifest,staged.cli_context(receipt))

    def schemas(self,admission):
        root=admission.lease.output_base/'execroot/_main/bazel-out/k8-opt/bin/bazel/schema'
        root.mkdir(mode=0o700,parents=True)
        config={'definitions':{'OmuxBrokerContextMode':{'enum':['full_native','text_transcript_v1']},
            'OmuxBrokerConfig':{'properties':{'context_mode':{'default':'full_native'}}}}}
        path=root/'native-config.schema.json';path.write_text(json.dumps(config));path.chmod(0o444)
        for mode in ('stable','experimental'):
            directory=root/('public-schema-bundle.'+mode)/'json'
            directory.mkdir(mode=0o700,parents=True)
            path=directory/'ClientRequest.json';path.write_bytes(b'{"type":"object"}\n');path.chmod(0o444)

    def complete(self,admission):
        admission.verify_after_cleanup((self.source_meta,self.export_meta))
        receipt=self.receipt(admission)
        if admission.stage==1:self.libraries(admission)
        elif admission.stage==2:self.cli(admission)
        elif admission.stage==3:self.qualify(admission,receipt)
        else:self.schemas(admission)
        raw=staged.terminal_receipt(admission,receipt)
        self.assertEqual(json.loads(raw)['exit'],0)
        fd=os.open(admission.run/'receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        parent=os.open(admission.run,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
        return json.loads(raw)

    def test_selected_rejects_partial_mixed_oldflags_types_modes_before_io(self):
        with self.fixture():
            self.assertTrue(staged.selected(self.args()))
            self.assertTrue(staged.selected(self.args(4)))
            for field,value in (('native_stage',True),('native_stage',0),('native_stage',5),
                    ('native_mode','production8'),('native_staged_compilation_sha256',None),
                    ('native_staged_compilation',Path('/private/credentials.json')),
                    ('native_owned_candidate_cache',True),('native_fresh_completion',Path('/private/old.json')),
                    ('native_global_attempt',9),('native_cache_attempt',1),('reuse_owned_cache',True),
                    ('manager','user'),('source_dirty','true')):
                args=self.args();setattr(args,field,value)
                with patch.object(native,'verify_inputs') as read:
                    with self.subTest(field=field),self.assertRaises(ValueError):
                        staged.Admission(args,self.state/'11111111-1234-4234-8234-123456789abc',
                            self.tools,self.graph,self.locked_path,'system',lambda row:True)
                    read.assert_not_called()

    def test_anchor_blocks_second_A_even_when_graph_and_key_change(self):
        with self.fixture():
            first=self.admit()
            key=first.key;original=staged.CHAIN.read_bytes()
            self.assertEqual(os.listdir(first.output_fd),[])
            self.assertEqual(staged.CHAIN.stat().st_mode&0o777,0o400)
            first.close()
            with self.assertRaises(FileExistsError):self.admit(commit='2'*40)
            self.assertEqual(staged.CHAIN.read_bytes(),original)
            self.assertTrue((self.state/('cache-v2-'+key)).is_dir())
            self.assertEqual(len([path for path in self.state.iterdir() if path.name.startswith('cache-v2-')]),1)

    def test_pending_closed_skip_or_repeat_stage_cannot_continue(self):
        with self.fixture():
            first=self.admit();first.close()
            with self.assertRaises(ValueError):self.admit(2)
            with self.assertRaises(ValueError):self.admit(3)
            with self.assertRaises(FileExistsError):self.admit(1)
        with self.fixture():
            first=self.admit();self.complete(first);first.close()
            second=self.admit(2)
            failed=self.receipt(second);failed.update(exit=124,workload_exit=124)
            raw=staged.terminal_receipt(second,failed)
            self.assertEqual(json.loads(raw)['exit'],124)
            self.assertEqual(json.loads((second.root/staged.JOURNAL).read_bytes())['status'],'closed')
            second.close()
            with self.assertRaises(ValueError):self.admit(2)
            with self.assertRaises(ValueError):self.admit(3)

    def test_same_bytes_replaced_output_inode_refuses_before_prior_artifact_reads(self):
        with self.fixture():
            first=self.admit();self.complete(first);root=first.root
            first.close()
            old=root/'output-base';outside=self.state/'preserved-output';old.rename(outside)
            shutil.copytree(outside,old)
            old.chmod(0o700)
            # Same byte-for-byte output files and modes, different directory
            # inode: refuse before any predecessor artifact is opened.
            with patch.object(staged,'verify_artifacts') as read:
                with self.assertRaises(ValueError):self.admit(2)
                read.assert_not_called()

    def test_additional_variant_does_not_invalidate_exact_A_but_changed_pin_does(self):
        with self.fixture():
            first=self.admit();receipt=self.complete(first)
            envelope=json.loads((first.run/staged.ARTIFACTS).read_bytes())
            selected=Path(envelope['artifacts']['libraries'][staged.LIBRARIES[0]]['path'])
            extra=selected.with_name('libcodex_config-456.rlib')
            extra.write_bytes(b'!<arch>\nunrelated variant\n');extra.chmod(0o444)
            staged.verify_artifacts(first.run,receipt,None)
            with self.assertRaises(ValueError):staged.library_artifacts(first.lease.output_base,None)
            selected.chmod(0o644);selected.write_bytes(b'!<arch>\nchanged selected artifact\n');selected.chmod(0o444)
            with self.assertRaises(ValueError):staged.verify_artifacts(first.run,receipt,None)
            first.close()

    def test_actual_method_rejects_foreign_args_changed_selector_closed_custody(self):
        with self.fixture():
            first=self.admit()
            self.assertIs(first.authorize_native_mode(first.args),True)
            with self.assertRaises(ValueError):first.authorize_native_mode(copy.copy(first.args))
            first.args.native_source_sha256='0'*64
            with self.assertRaises(ValueError):first.authorize_native_mode(first.args)
            first.args.native_source_sha256=staged.INPUTS['source_receipt_sha256']
            staged.SELECTOR.write_bytes(b'{"changed":true}\n')
            with self.assertRaises(ValueError):first.authorize_native_mode(first.args)
            first.close()
            with self.assertRaises(ValueError):first.authorize_native_mode(first.args)

    def test_full_A_B_C_D_chain_requires_actual_named_artifact_receipts(self):
        with self.fixture():
            receipts=[]
            for stage in range(1,5):
                current=self.admit(stage)
                receipts.append(self.complete(current))
                self.assertEqual(len(receipts[-1]['native_staged_compilation']['stage_history']),stage-1)
                self.assertEqual(len(receipts[-1]['native_staged_compilation']['previous_dispatches']),9)
                current.close()
            facts=[row['native_staged_compilation'] for row in receipts]
            self.assertTrue(all(row['custody']==facts[0]['custody'] for row in facts))
            self.assertTrue(all(row['chain_sha256']==facts[0]['chain_sha256'] for row in facts))
            self.assertEqual(json.loads((self.state/('cache-v2-'+facts[0]['key'])/staged.JOURNAL).read_bytes())['status'],'closed')
            with self.assertRaises(ValueError):self.admit(4)

    def test_literal_success_clock_caps_and_duplicate_plan_flags_refuse(self):
        with self.fixture():
            first=self.admit();receipt=self.complete(first)
            def verify(row):
                staged.verify_success(row,receipt['native_staged_compilation'],self.graph,
                    first.args.native_source_sha256,first.args.native_export_sha256,1)
            verify(receipt)
            mutations=(lambda r:r.update(exit=False),lambda r:r.update(workload_exit=None),
                lambda r:r.update(descendants_empty=1),
                lambda r:r['native_staged_compilation'].update(stage=True),
                lambda r:r['native_staged_compilation']['bindings']['limits'].update(swap=False),
                lambda r:r['native_sdk'].update(original_entry_monotonic_ns=True),
                lambda r:r['native_sdk'].update(original_deadline_monotonic_ns=7300*10**9),
                lambda r:r['observed_properties'].update(MemoryMax='8589934592'),
                lambda r:r['native_sdk']['plan']['argv'].append('--jobs=2'),
                lambda r:r['native_sdk']['plan']['argv'].append('--remote_cache=https://outside.invalid'),
                lambda r:r['native_sdk']['plan']['argv'].append('--norepository_disable_download'),
                lambda r:r['native_sdk']['plan']['environment'].update(RUSTFLAGS='-Clto=fat'))
            for alter in mutations:
                changed=copy.deepcopy(receipt);alter(changed)
                with self.assertRaises(ValueError):verify(changed)
            first.close()

    def test_terminal_missing_artifact_or_journal_failure_cannot_promote_zero(self):
        with self.fixture():
            first=self.admit()
            first.verify_after_cleanup((self.source_meta,self.export_meta))
            raw=staged.terminal_receipt(first,self.receipt(first))
            self.assertEqual(json.loads(raw)['exit'],125)
            self.assertEqual(json.loads(raw)['workload_exit'],0)
            self.assertEqual(json.loads((first.root/staged.JOURNAL).read_bytes())['status'],'closed')
            first.close()
        with self.fixture():
            first=self.admit();first.verify_after_cleanup((self.source_meta,self.export_meta))
            receipt=self.receipt(first);self.libraries(first)
            with patch.object(first,'finish',side_effect=ValueError('model-private-diagnostic')):
                raw=staged.terminal_receipt(first,receipt)
            self.assertEqual(json.loads(raw)['exit'],125)
            self.assertNotIn('model-private-diagnostic',raw)
            first.close()

    def test_changed_held_source_or_policy_anchor_refuses(self):
        with self.fixture():
            first=self.admit()
            path=first.source/'fixture.rs';path.chmod(0o644);path.write_bytes(b'changed source\n');path.chmod(0o444)
            with self.assertRaises(ValueError):first.authorize_native_mode(first.args)
            staged.CHAIN.chmod(0o600);staged.CHAIN.write_bytes(b'changed reservation\n');staged.CHAIN.chmod(0o400)
            with self.assertRaises(ValueError):first.check_chain()
            first.close()

    def test_history_receipt_artifact_or_boolean_stage_mutation_refuses(self):
        for mutate in (
                lambda j:j['stage_history'][0].update(sha256='0'*64),
                lambda j:j['stage_history'][0].update(artifacts_sha256='0'*64),
                lambda j:j.update(stage=True),
                lambda j:j['custody']['output_base'].update(inode=j['custody']['output_base']['inode']+1)):
            with self.fixture():
                first=self.admit();self.complete(first)
                journal=first.root/staged.JOURNAL;first.close()
                value=json.loads(journal.read_bytes());mutate(value)
                journal.write_bytes(staged.canonical(value)+b'\n');journal.chmod(0o600)
                with self.assertRaises(ValueError):self.admit(2)

    def test_ninth_timeout_is_consumed_failure_not_success(self):
        row=dict(staged.FAILED_NINE)
        value={'id':row['id'],'profile':'codex-native','manager':'system',
            'unit':'omux-execution-'+row['id']+'.service','exit':125,'workload_exit':124,
            'descendants_empty':True,'native_candidate_cache':None,
            'native_fresh_completion':{'kind':staged.prior.KIND,'key':row['cache_key'],
                'global_attempt':9,'verified_before_launch':True,'verified_after_cleanup':True},
            'native_sdk':{'mode':native.COMBINED_MODE,'source_and_export_verified_after_cleanup':True},
            'test_evidence':{'state':'preservation-failed'}}
        with patch.object(staged.prior,'historical_receipts'),patch.object(staged.prior,'read_receipt',return_value=value):
            staged.historical_receipts(None,lambda receipt:True)
            for field,data in (('exit',0),('workload_exit',False),('descendants_empty',None)):
                changed=copy.deepcopy(value);changed[field]=data
                with patch.object(staged.prior,'read_receipt',return_value=changed):
                    with self.assertRaises(ValueError):staged.historical_receipts(None,lambda receipt:True)
            changed=copy.deepcopy(value);changed['test_evidence']['state']='preserved'
            with patch.object(staged.prior,'read_receipt',return_value=changed):
                with self.assertRaises(ValueError):staged.historical_receipts(None,lambda receipt:True)


if __name__=='__main__':
    unittest.main()
