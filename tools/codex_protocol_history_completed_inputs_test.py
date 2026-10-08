"""Completed native-chain models with real held files and named evidence.

External source/SDK qualification and actual native work are synthetic. Receipt
plans, owned journals, custody, copied test logs, schemas and archive validators
use their real methods. This does not establish a native build or live proof.
"""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_protocol_history_native as protocol
import codex_protocol_history_native_test as old_models
import codex_protocol_history_cli as cli
import codex_protocol_history_completed_inputs as subject

A=old_models.EPOCH_A
B=old_models.EPOCH_B
C='10000000-0000-4000-8000-000000000003'


def encoded(value):
    return (json.dumps(value,sort_keys=True)+'\n').encode()


class CompletedFixture:
    """Public reusable actual-method fixture for package/guard models."""
    def __init__(self,root, *, with_cli=False):
        self.root=Path(root);self.model=old_models.SelectedNativeModels()
        self.real_collect=protocol.collect_artifacts
        self.stack,self.document,self.tools=self.model.owner_fixture(self.root)
        self.document['controller_graph_sha256']=subject.transition_graph({'public.py':'1'*64})[0]
        original=self.root/'protocol-history-native-selection.json'
        original.chmod(0o600);original.write_bytes(old_models.source.encoded(self.document));original.chmod(0o400)
        self.tools['bazel']=protocol.BAZEL
        self.tools['bash']='/nix/store/'+'0'*32+'-bash-5.3/bin/bash'
        self.boot={'boot_id':A,'host':'declared-model','uid':os.getuid(),'gid':os.getgid()}
        for file in (Path(self.document['source']['root']),Path(self.document['sdk']['root']),
                self.root/'retained-sdk'):file.chmod(0o555)
        self.qualified=({'source_inventory':{'plain.txt':{'mode':'100644',
            'sha256':protocol.sha(b'public synthetic source\n')}},
            'inventory_sha256':self.document['source']['inventory_sha256']},
            {'inventory_sha256':self.document['sdk']['inventory_sha256'],
                'mapping_sha256':'8'*64,'registry_cache':str(Path(self.document['sdk']['root'])/'registry-cache'),
                'repositories':{},'module_overrides':{}})
        self.with_cli=with_cli;self.receipts={};self.envelopes={}

    def __enter__(self):
        self.stack.__enter__()
        self.stack.enter_context(patch.object(protocol,'verify_inputs',return_value=self.qualified))
        self.stack.enter_context(patch.object(protocol,'collect_artifacts',self.real_collect))
        self.stack.enter_context(patch.object(subject,'STATE',self.root))
        self.stack.enter_context(patch.object(subject,'boot_host',return_value=self.boot))
        self.entry=time.monotonic_ns()
        for stage,epoch in ((1,A),(2,B)):
            run=self.root/epoch;run.mkdir(mode=0o700)
            args=self.model.args(self.root,self.document,stage)
            owner=protocol.Admission(args,run,self.tools,(self.document['controller_graph_sha256'],['public.py']),
                '/nix/store/model/bin','system',lambda receipt:True,self.entry+(stage-1)*10**9)
            try:
                owner.verified_after_cleanup=True
                if stage==1:self.logs(run,protocol.GATES,list(protocol.MODES[protocol.STAGES[1]][1]))
                else:self.schemas(owner.lease.output_base)
                receipt=self.receipt(owner,protocol,stage)
                raw=protocol.terminal_receipt(owner,receipt)
                if receipt['exit']!=0:raise AssertionError('fixture protocol terminal refused')
                (run/'receipt.json').write_text(raw);(run/'receipt.json').chmod(0o600)
                self.receipts[stage]=receipt
                self.envelopes[stage]=json.loads((run/protocol.ARTIFACTS).read_bytes())
            finally:owner.close()
        self.selection={'schema_version':1,'kind':subject.KIND,'inputs':self.document,
            'input_selection_sha256':protocol.sha((self.root/'protocol-history-native-selection.json').read_bytes()),
            'predecessors':{str(stage):{'id':receipt['id'],
                'sha256':protocol.sha((self.root/receipt['id']/'receipt.json').read_bytes()),
                'artifacts_sha256':receipt['native_protocol_history']['artifacts_sha256']}
                for stage,receipt in self.receipts.items()}}
        if self.with_cli:self.create_cli()
        return self

    def __exit__(self,*error):
        try:return self.stack.__exit__(*error)
        finally:self.model.clean(self.root)

    def logs(self,run,gates,targets):
        evidence=run/'test-evidence';evidence.mkdir(mode=0o700)
        results=[]
        for target,names in gates.items():
            raw=('\n'.join('test '+name+' ... ok' for name in names)+'\n'
                +'test result: ok. '+str(len(names))+' passed; 0 failed; 0 ignored;\n').encode()
            name=protocol.sha(target.encode())+'.evidence'
            (evidence/name).write_bytes(raw);(evidence/name).chmod(0o600)
            results.append({'target':target,'state':'observed','files':[{
                'source':'test.log','state':'copied','file':name,'sha256':protocol.sha(raw),'bytes':len(raw)}]})
        if cli.CLI in targets:results.append({'target':cli.CLI,'state':'missing-test-directory','files':[]})
        manifest={'schema':1,'bazel_exit':0,'epoch_start_ns':123,'targets':targets,'results':results}
        (run/'test-evidence.json').write_bytes(encoded(manifest));(run/'test-evidence.json').chmod(0o600)

    def schemas(self,output):
        base=output/'execroot/_main/bazel-out/k8-opt/bin/bazel/schema'
        base.mkdir(mode=0o700,parents=True)
        config={'definitions':{'OmuxBrokerContextMode':{'enum':['full_native','text_transcript_v1']},
            'OmuxBrokerConfig':{'properties':{'context_mode':{'default':'full_native'}}}}}
        (base/'native-config.schema.json').write_bytes(encoded(config))
        (base/'native-config.schema.json').chmod(0o444)
        for mode in ('stable','experimental'):
            root=base/('public-schema-bundle.'+mode)/'json';root.mkdir(mode=0o700,parents=True)
            (root/'Thread.json').write_bytes(b'{}\n');(root/'Thread.json').chmod(0o444)

    def receipt(self,owner,module,stage):
        mode=module.STAGES[stage]
        plan=module.native.command_from_verified_inputs(owner.args,owner.run,owner.locked_path,
            self.tools['bash'],owner,self.qualified,module.MODES,module.GATES if stage==1 else None,prepare=False)
        evidence={'state':'not-applicable'}
        if stage==1:evidence={'state':'preserved','sha256':protocol.sha((owner.run/'test-evidence.json').read_bytes())}
        return {'id':owner.run.name,'unit':'omux-execution-'+owner.run.name+'.service',
            'profile':'codex-native','manager':'system','exit':0,'workload_exit':0,'controller_failure':None,
            'descendants_empty':True,'cleanup':{'state':'empty'},'source_dirty':'false',
            'source_commit':self.document['controller_source_commit'],'graph_sha256':self.document['controller_graph_sha256'],
            'targets':list(module.MODES[mode][1]),'verb':module.MODES[mode][0],
            'output_base':str(owner.lease.output_base),'epoch_start_ns':123,'test_evidence':evidence,
            'observed_properties':{'MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'512',
                'PrivateNetwork':'yes','CPUQuotaPerSecUSec':'2s','RuntimeMaxUSec':'3000s'},
            'native_candidate_cache':None,'native_fresh_completion':None,'native_staged_compilation':None,
            'native_protocol_history':owner.facts() if module is protocol else None,
            'native_protocol_history_cli':owner.facts() if module is cli else None,
            'native_sdk':{'mode':mode,'plan':plan,'aggregate_seconds':3600,
                'original_entry_monotonic_ns':owner.original_entry_ns,
                'original_deadline_monotonic_ns':owner.original_deadline_ns,
                'source_receipt_sha256':self.document['source']['receipt_sha256'],
                'export_receipt_sha256':self.document['sdk']['receipt_sha256'],
                'source_and_export_verified_after_cleanup':True}}

    def create_cli(self):
        for name,value in (('STATE',self.root),('SELECTOR',self.root/'protocol-history-cli-selection.json'),
                ('CHAIN',self.root/'protocol-history-cli-chain.json')):
            self.stack.enter_context(patch.object(cli,name,value))
        self.stack.enter_context(patch.object(cli,'boot_host',return_value=self.boot))
        self.stack.enter_context(patch.object(cli,'controller_inventory',return_value={'public.py':'1'*64}))
        self.stack.enter_context(patch.object(cli,'verify_inputs',return_value=self.qualified))
        def qualified(selection,patches,deadline,verify_previous=None):
            return self.qualified,subject.validate_completed_receipts(selection,self.receipts,
                self.envelopes,self.qualified[1],deadline)
        self.stack.enter_context(patch.object(subject,'load_completed_inputs',side_effect=qualified))
        selector=cli.SELECTOR;selector.write_bytes(encoded(self.selection));selector.chmod(0o400)
        run=self.root/C;run.mkdir(mode=0o700)
        args=SimpleNamespace(**vars(self.model.args(self.root,self.document)))
        args.native_protocol_history=args.native_protocol_history_sha256=args.native_protocol_stage=None
        args.native_protocol_cli=selector;args.native_protocol_cli_sha256=protocol.sha(selector.read_bytes())
        args.native_mode=cli.COMBINED_MODE
        owner=cli.Admission(args,run,self.tools,(self.document['controller_graph_sha256'],['public.py']),'/nix/store/model/bin',
            'system',lambda receipt:True,time.monotonic_ns())
        try:
            owner.verified_after_cleanup=True
            self.logs(run,cli.GATES,list(cli.MODES[cli.COMBINED_MODE][1]))
            output=owner.lease.output_base/'execroot/_main/bazel-out/k8-opt/bin/codex-rs/cli'
            output.mkdir(mode=0o700,parents=True)
            (output/'codex').write_bytes(b'\x7fELF'+b'public synthetic native workload output')
            (output/'codex').chmod(0o555)
            receipt=self.receipt(owner,cli,1);facts=receipt['native_protocol_history_cli']
            context={'invocation_id':C,'output_base':str(owner.lease.output_base),
                'source_receipt_sha256':self.document['source']['receipt_sha256'],
                'export_receipt_sha256':self.document['sdk']['receipt_sha256'],
                'source_inventory_sha256':self.document['source']['inventory_sha256'],
                'export_inventory_sha256':self.document['sdk']['inventory_sha256'],
                'candidate_cache_key':facts['key'],'candidate_provenance_sha256':facts['provenance_sha256'],
                'controller_graph_sha256':self.document['controller_graph_sha256'],'bazel':cli.BAZEL,'workload_exit':0,
                'descendants_empty':True,'source_and_export_verified_after_cleanup':True}
            cli.source_io.DEADLINE=owner.args.native_deadline
            cli.meaningful_tests(run,json.loads((run/'test-evidence.json').read_bytes()),cli.COMBINED_MODE,context)
            raw=cli.terminal_receipt(owner,receipt)
            if receipt['exit']!=0:raise AssertionError('fixture CLI terminal refused')
            (run/'receipt.json').write_text(raw);(run/'receipt.json').chmod(0o600)
            self.cli_receipt=receipt;self.cli_envelope=json.loads((run/cli.ARTIFACTS).read_bytes())
        finally:owner.close()


class CompletedInputsModels(unittest.TestCase):
    def test_actual_completed_chain_after_original_deadline_uses_new_bounded_io_only(self):
        with tempfile.TemporaryDirectory() as temporary,CompletedFixture(Path(temporary)) as fixture:
            original=fixture.receipts[1]['native_protocol_history']
            future=original['original_deadline_monotonic_ns']/10**9+1
            with patch.object(protocol.time,'monotonic',return_value=future):
                result=subject.validate_completed_receipts(fixture.selection,fixture.receipts,
                    fixture.envelopes,fixture.qualified[1],future+60)
            self.assertEqual(result['original_entry_monotonic_ns'],original['original_entry_monotonic_ns'])
            self.assertEqual(result['original_deadline_monotonic_ns'],original['original_deadline_monotonic_ns'])
            with patch.object(protocol.time,'monotonic',return_value=future),self.assertRaises(ValueError):
                subject.validate_completed_receipts(fixture.selection,fixture.receipts,
                    fixture.envelopes,fixture.qualified[1],future)

    def test_archived_receipt_changes_cannot_hide_under_a_new_pin(self):
        for change in ('clock','custody_bool','source','duplicate_flag','failed','controller'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary,\
                    CompletedFixture(Path(temporary)) as fixture:
                receipt=copy.deepcopy(fixture.receipts[2]);facts=receipt['native_protocol_history']
                if change=='clock':facts['original_deadline_monotonic_ns']+=10**9
                elif change=='custody_bool':facts['custody']['output']['device']=True
                elif change=='source':receipt['native_sdk']['source_receipt_sha256']='0'*64
                elif change=='duplicate_flag':receipt['native_sdk']['plan']['argv'].append('--jobs=2')
                elif change=='failed':receipt['exit']=False
                else:receipt['graph_sha256']='0'*64
                with self.assertRaises(ValueError):
                    subject.verify_archived_protocol(receipt,fixture.document,2,fixture.qualified[1],time.monotonic()+60)

    def test_same_path_directory_replacement_refuses_before_artifact_io(self):
        with tempfile.TemporaryDirectory() as temporary,CompletedFixture(Path(temporary)) as fixture:
            output=Path(fixture.receipts[2]['output_base'])
            output.rename(output.parent/'replaced-output');output.mkdir(mode=0o700)
            with patch.object(protocol,'collect_artifacts') as artifacts,self.assertRaises(ValueError):
                subject.validate_completed_receipts(fixture.selection,fixture.receipts,
                    fixture.envelopes,fixture.qualified[1],time.monotonic()+60)
            artifacts.assert_not_called()

    def test_changed_actual_named_log_and_extra_physical_schema_are_refused(self):
        for change in ('log','schema'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary,\
                    CompletedFixture(Path(temporary)) as fixture:
                if change=='log':
                    row=next(iter(fixture.envelopes[1]['artifacts']['logs'].values()))
                    file=Path(row['path']);file.write_bytes(b'test wrong ... ok\n')
                else:
                    tree=Path(fixture.envelopes[2]['artifacts']['protocol_schema_roots']['stable'])
                    (tree/'extra.binary').write_bytes(b'unselected')
                with self.assertRaises(ValueError):
                    subject.validate_completed_receipts(fixture.selection,fixture.receipts,
                        fixture.envelopes,fixture.qualified[1],time.monotonic()+60)

    def test_one_shot_cli_archival_success_and_closed_custody_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temporary,CompletedFixture(Path(temporary),with_cli=True) as fixture:
            deadline=time.monotonic()+60
            cli.validate_completed_success(fixture.cli_receipt,fixture.selection,fixture.qualified,deadline)
            self.assertTrue(cli.recheck_closed_custody(fixture.cli_receipt,fixture.selection,deadline))
            self.assertEqual(cli.collect_artifacts(fixture.root/C,fixture.cli_receipt,deadline),fixture.cli_envelope)
            root=Path(fixture.cli_receipt['output_base']).parent
            journal=root/cli.JOURNAL
            value=json.loads(journal.read_bytes());value['status']='pending'
            journal.write_bytes(encoded(value))
            with self.assertRaises(ValueError):
                cli.recheck_closed_custody(fixture.cli_receipt,fixture.selection,deadline)


if __name__=='__main__':unittest.main()
