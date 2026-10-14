"""Real selected inventory, exact-test and fresh-journal models; no native tools."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_protocol_history_sdk_export_test as export_models
import codex_protocol_history_metadata_test as metadata_models
import codex_protocol_history_native as subject
import codex_retained_sdk_export as sdk

EPOCH_A='10000000-0000-4000-8000-000000000001'
EPOCH_B='10000000-0000-4000-8000-000000000002'


class SelectedNativeModels(unittest.TestCase):
    def document(self,root,source_root,sdk_root,source_pin='a'*64,sdk_pin='b'*64):
        def producer(epoch):
            return {'receipt':str(root/epoch/'receipt.json'),'sha256':'c'*64,
                'source_commit':'d'*40,'graph_sha256':'e'*64}
        return {'schema_version':1,'kind':subject.SELECTION_KIND,
            'source':{'root':str(source_root),'receipt_sha256':source_pin,'inventory_sha256':'1'*64,
                'producer':producer(EPOCH_A)},
            'sdk':{'root':str(sdk_root),'receipt_sha256':sdk_pin,'inventory_sha256':'2'*64,
                'producer':producer(EPOCH_B)},
            'controller_source_commit':'f'*40,'controller_graph_sha256':'3'*64}

    def selected_export(self,root):
        model=export_models.SelectedSdkModels()
        fixture=model.fixture(root)
        fixture[2]['registry_metadata']['inventory_sha256']='4'*64
        next(row for row in fixture[2]['repositories'] if row['canonical_name']!=subject.delta.HUB)['source_root']=\
            '/public/original-cached-repository-source'
        retained_file=fixture[1][3]/'receipt.json'
        retained_file.chmod(0o600);retained_file.write_bytes(source.encoded(fixture[2]));retained_file.chmod(0o444)
        retained_pin=subject.sha(retained_file.read_bytes())
        fixture[1][2]['export_receipt_sha256']=retained_pin
        fixture=(fixture[0],fixture[1],fixture[2],retained_pin)
        report=model.export(root,fixture)
        before,parent,metadata_document,retained_root,qualified,old=fixture[1]
        source_root=Path(metadata_document['source_root']);export_root=root/'selected-sdk'
        raw=(export_root/'receipt.json').read_bytes()
        document=self.document(root,source_root,export_root,
            metadata_document['source_receipt_sha256'],subject.sha(raw))
        document['source']['inventory_sha256']=report['source_inventory_sha256']
        document['sdk']['inventory_sha256']=report['inventory_sha256']
        # Canonical export output siblings are contractually required. Move the
        # real metadata tree to that path rather than mocking its byte reader.
        (root/'result').rename(root/'protocol-history-metadata')
        report['repositories'][next(i for i,row in enumerate(report['repositories'])
            if row['canonical_name']==subject.delta.HUB)]['source_root']=str(root/'protocol-history-metadata/hub')
        report['inventory_sha256']=sdk.digest(sdk.canonical(report['repositories']))
        raw=source.encoded(report)
        (export_root/'receipt.json').chmod(0o600);(export_root/'receipt.json').write_bytes(raw)
        (export_root/'receipt.json').chmod(0o444)
        document['sdk']['receipt_sha256']=subject.sha(raw)
        document['sdk']['inventory_sha256']=report['inventory_sha256']
        source_report=json.loads((source_root/'source-receipt.json').read_bytes())
        stack=ExitStack()
        stack.enter_context(patch.object(subject.inputs,'EXPORT_ROOT',retained_root))
        stack.enter_context(patch.object(subject.inputs,'EXPORT_SHA',fixture[3]))
        stack.enter_context(patch.object(subject.inputs.history,'load_parent',return_value=(before,parent)))
        stack.enter_context(patch.object(sdk,'validate_export',return_value=qualified))
        stack.enter_context(patch.object(sdk,'registry_metadata',return_value=fixture[2]['registry_metadata']))
        real_inventory=sdk.inventory
        stack.enter_context(patch.object(sdk,'inventory',side_effect=lambda path,*args,**kwargs:
            [] if Path(path)==Path(sdk.JDK) else real_inventory(path,*args,**kwargs)))
        # Only external original source/SDK/JDK qualification is mocked. The
        # selected exported tree, metadata, hub delta and sealed IO are real.
        return stack,document,source_report,report,export_root

    def reseal_report(self,document,report,root):
        raw=source.encoded(report)
        (root/'receipt.json').chmod(0o600);(root/'receipt.json').write_bytes(raw)
        (root/'receipt.json').chmod(0o444)
        document['sdk']['receipt_sha256']=subject.sha(raw)
        document['sdk']['inventory_sha256']=report['inventory_sha256']

    def test_actual_selected_sdk_inventory_passes_and_retained_validator_is_not_broadened(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,source_report,report,export_root=self.selected_export(root)
                with stack:
                    result=subject.verify_selected_export(export_root,document['sdk']['receipt_sha256'],
                        source_report,document,time.monotonic()+60)
                self.assertEqual(result['inventory_sha256'],report['inventory_sha256'])
                self.assertEqual(result['graph_files'],source_report['graph_files'])
                # A new-kind receipt cannot be passed to the historical schema
                # even with matching caller pins. Restore its actual method.
                with self.assertRaises((KeyError,ValueError)):
                    sdk.validate_export(export_root,document['sdk']['receipt_sha256'],
                        source_report['inventory_sha256'],source_report['graph_files'])
            finally:metadata_models.MetadataProducerModels().clean(root)

    def test_rehashed_sdk_receipt_cannot_change_source_graph_or_unrelated_repository(self):
        for change in ('source','repository','kind','unknown'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    stack,document,source_report,report,export_root=self.selected_export(root)
                    if change=='source':report['source_inventory_sha256']='0'*64
                    elif change=='repository':
                        row=next(row for row in report['repositories'] if row['canonical_name']!=subject.delta.HUB)
                        row['source_root']=str(root/'unqualified-identical-name')
                        report['inventory_sha256']=sdk.digest(sdk.canonical(report['repositories']))
                    elif change=='kind':report['kind']='omux-retained-sdk-export-v1'
                    else:report['future_claim']=True
                    self.reseal_report(document,report,export_root)
                    with stack,self.assertRaises(ValueError):
                        subject.verify_selected_export(export_root,document['sdk']['receipt_sha256'],
                            source_report,document,time.monotonic()+60)
                finally:metadata_models.MetadataProducerModels().clean(root)

    def test_changed_actual_selected_hub_is_rejected_even_when_caller_rehashes_sdk_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,source_report,report,export_root=self.selected_export(root)
                file=export_root/'repositories'/subject.delta.HUB/'defs.bzl'
                file.chmod(0o600);file.write_bytes(b'changed wrapper, not the allowed dependency deletion')
                file.chmod(0o444)
                row=next(row for row in report['repositories'] if row['canonical_name']==subject.delta.HUB)
                row['files']=sdk.inventory(file.parent,sdk.Budget(time.time()+60),sealed=True)
                row['source_files']=copy.deepcopy(row['files'])
                row['inventory_sha256']=row['source_inventory_sha256']=sdk.digest(sdk.canonical(row['files']))
                report['inventory_sha256']=sdk.digest(sdk.canonical(report['repositories']))
                self.reseal_report(document,report,export_root)
                with stack,self.assertRaises(ValueError):
                    subject.verify_selected_export(export_root,document['sdk']['receipt_sha256'],
                        source_report,document,time.monotonic()+60)
            finally:metadata_models.MetadataProducerModels().clean(root)

    def test_exact_names_cannot_be_replaced_by_counts_substrings_or_ignored_cases(self):
        for target,names in subject.GATES.items():
            raw=('\n'.join('test '+name+' ... ok' for name in names)+'\n'
                +'test result: ok. '+str(len(names))+' passed; 0 failed; 0 ignored;\n').encode()
            self.assertEqual(subject.named_log(raw,target),sorted(names))
            bad=(raw.replace(names[0].encode(),(names[0]+'_nearby').encode()),
                raw.replace(b' ... ok',b' ... ignored',1),raw+('test '+names[0]+' ... ok\n').encode(),
                raw.replace(b'0 ignored',b'1 ignored'),raw.split(b'\n')[-2])
            for value in bad:
                with self.assertRaises(ValueError):subject.named_log(value,target)

    def test_outer_producer_bytes_cleanup_and_actual_output_namespace_are_independent_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);run=root/EPOCH_A;run.mkdir(mode=0o700)
            evidence=run/'test-evidence';evidence.mkdir(mode=0o700)
            target='//tools:codex_protocol_history_sdk_export_producer'
            entries=[]
            for member,raw in (('test.log',b'public fixture producer output\n'),('test.xml',
                b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="actual"/></testsuite>')):
                name=subject.sha(member.encode())+'.evidence'
                (evidence/name).write_bytes(raw);(evidence/name).chmod(0o600)
                entries.append({'source':member,'state':'copied','file':name,'bytes':len(raw),'sha256':subject.sha(raw)})
            manifest={'schema':1,'bazel_exit':0,'epoch_start_ns':123,'targets':[target],
                'results':[{'target':target,'state':'observed','files':entries}]}
            raw=source.encoded(manifest);(run/'test-evidence.json').write_bytes(raw)
            (run/'test-evidence.json').chmod(0o600)
            receipt={'id':EPOCH_A,'unit':'omux-execution-'+EPOCH_A+'.service','profile':'standard','manager':'system',
                'exit':0,'workload_exit':0,'controller_failure':None,'descendants_empty':True,'cleanup':{'state':'empty'},
                'source_dirty':'false','source_commit':'d'*40,'graph_sha256':'e'*64,'verb':'test','targets':[target],
                'epoch_start_ns':123,'output_base':str(run/'output-base'),
                'observed_properties':{'MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'512',
                    'PrivateNetwork':'yes','CPUQuotaPerSecUSec':'2s','RuntimeMaxUSec':'1200s'},
                'test_evidence':{'state':'preserved','sha256':subject.sha(raw)}}
            selected={'root':str(run/'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
                'codex_protocol_history_sdk_export_producer/test.outputs/protocol-history-sdk-export'),
                'producer':{'receipt':str(run/'receipt.json'),'sha256':'0'*64,
                    'source_commit':'d'*40,'graph_sha256':'e'*64}}
            def publish():
                raw=source.encoded(receipt);(run/'receipt.json').write_bytes(raw);(run/'receipt.json').chmod(0o600)
                selected['producer']['sha256']=subject.sha(raw)
            publish()
            self.assertEqual(subject.producer_success(selected,target,'protocol-history-sdk-export',time.monotonic()+60),receipt)
            for field,value in (('exit',124),('exit',False),('workload_exit',125),('descendants_empty',False),
                ('graph_sha256','0'*64),('controller_failure',{'reason':'unclassified'})):
                before=receipt[field];receipt[field]=value;publish()
                with self.assertRaises(ValueError):
                    subject.producer_success(selected,target,'protocol-history-sdk-export',time.monotonic()+60)
                receipt[field]=before
            publish();original=selected['root'];selected['root']=str(root/'identical-copied-sdk')
            with self.assertRaises(ValueError):
                subject.producer_success(selected,target,'protocol-history-sdk-export',time.monotonic()+60)
            selected['root']=original
            (evidence/entries[1]['file']).write_bytes(b'<testsuite tests="0" failures="0" errors="0"/>')
            with self.assertRaises(ValueError):
                subject.producer_success(selected,target,'protocol-history-sdk-export',time.monotonic()+60)

    def test_real_schema_outputs_are_complete_json_and_config_policy_is_retained(self):
        for mutation in (None,'extra','symlink','policy'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);output=root/'output-base'
                directory=output/'execroot/_main/bazel-out/k8-opt/bin/bazel/schema'
                directory.mkdir(mode=0o700,parents=True)
                config={'definitions':{'OmuxBrokerContextMode':{'enum':['full_native','text_transcript_v1']},
                    'OmuxBrokerConfig':{'properties':{'context_mode':{'default':'full_native'}}}}}
                config_file=directory/'native-config.schema.json'
                config_file.write_bytes(source.encoded(config));config_file.chmod(0o444)
                for mode in ('stable','experimental'):
                    tree=directory/('public-schema-bundle.'+mode)/'json';tree.mkdir(mode=0o700,parents=True)
                    (tree/'Thread.json').write_bytes(b'{}\n');(tree/'Thread.json').chmod(0o444)
                stable=directory/'public-schema-bundle.stable/json'
                if mutation=='extra':(stable/'unknown.binary').write_bytes(b'not a schema')
                elif mutation=='symlink':(stable/'Outside.json').symlink_to(root/'unselected')
                elif mutation=='policy':
                    config['definitions']['OmuxBrokerConfig']['properties']['context_mode']['default']='text_transcript_v1'
                    config_file.chmod(0o600);config_file.write_bytes(source.encoded(config));config_file.chmod(0o444)
                receipt={'native_protocol_history':{'stage':2},'test_evidence':{'state':'not-applicable'},
                    'output_base':str(output),'id':EPOCH_A,'native_sdk':{
                        'source_receipt_sha256':'a'*64,'export_receipt_sha256':'b'*64},'graph_sha256':'c'*64}
                if mutation:
                    with self.assertRaises(ValueError):subject.collect_artifacts(root,receipt,time.monotonic()+60)
                else:
                    actual=subject.collect_artifacts(root,receipt,time.monotonic()+60)
                    self.assertEqual(set(actual['artifacts']['protocol_schema_files']),{
                        'stable/Thread.json','experimental/Thread.json'})
                    self.assertEqual(actual['artifacts']['config_schema']['sha256'],subject.sha(config_file.read_bytes()))

    def args(self,root,document,stage=1):
        return SimpleNamespace(profile='codex-native',manager='system',state_dir=root,
            source_commit=document['controller_source_commit'],source_dirty='false',
            native_protocol_history=root/'protocol-history-native-selection.json',
            native_protocol_history_sha256=subject.sha(source.encoded(document)),native_protocol_stage=stage,
            native_mode=subject.STAGES[stage],native_source_root=Path(document['source']['root']),
            native_source_sha256=document['source']['receipt_sha256'],native_export_root=Path(document['sdk']['root']),
            native_export_sha256=document['sdk']['receipt_sha256'],native_patch_sha256=['1'*64]*4,
            native_owned_candidate_cache=False,reuse_owned_cache=False,native_aggregate_seconds=3600,
            native_deadline=time.monotonic()+3600)

    def test_actual_guard_parser_rejects_new_fields_on_standard_and_mixed_old_selectors(self):
        import execution_guard
        for arguments in (['--profile','standard','--native-protocol-stage','1'],
            ['--profile','codex-native','--native-protocol-stage','1'],
            ['--profile','codex-native','--native-protocol-history',str(subject.SELECTOR),
                '--native-protocol-history-sha256','a'*64,'--native-protocol-stage','1',
                '--native-mode',subject.STAGES[1],'--manager','system','--state-dir',str(subject.STATE),
                '--native-staged-compilation',str(subject.STATE/'native-staged-compilation.json')]):
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):execution_guard.main(arguments)

    def owner_fixture(self,root):
        source_root=root/'selected-source';source_root.mkdir(mode=0o700)
        source_tree=source_root/'source';source_tree.mkdir(mode=0o700)
        (source_tree/'plain.txt').write_bytes(b'public synthetic source\n');(source_tree/'plain.txt').chmod(0o555)
        source_tree.chmod(0o555)
        sdk_root=root/'selected-sdk';sdk_root.mkdir(mode=0o700)
        retained=root/'retained-sdk';retained.mkdir(mode=0o700)
        document=self.document(root,source_root,sdk_root)
        (root/'protocol-history-native-selection.json').write_bytes(source.encoded(document))
        (root/'protocol-history-native-selection.json').chmod(0o400)
        inventory={'plain.txt':{'mode':'100644','sha256':subject.sha(b'public synthetic source\n')}}
        qualified=({'source_inventory':inventory,'inventory_sha256':document['source']['inventory_sha256']},
            {'inventory_sha256':document['sdk']['inventory_sha256']})
        stack=ExitStack()
        for name,value in (('STATE',root),('SELECTOR',root/'protocol-history-native-selection.json'),
            ('CHAIN',root/'protocol-history-native-chain.json')):stack.enter_context(patch.object(subject,name,value))
        stack.enter_context(patch.object(subject,'SOURCE_SCOPE',re.compile(re.escape(str(source_root))+r'\Z')))
        stack.enter_context(patch.object(subject,'SDK_SCOPE',re.compile(re.escape(str(sdk_root))+r'\Z')))
        stack.enter_context(patch.object(subject,'PRODUCER_SCOPE',re.compile(re.escape(str(root))+
            r'/[0-9a-f-]{36}/receipt\.json\Z')))
        stack.enter_context(patch.object(subject.inputs,'EXPORT_ROOT',retained))
        stack.enter_context(patch.object(subject,'verify_inputs',return_value=qualified))
        stack.enter_context(patch.object(subject,'producer_success',return_value={'model_external_qualification':True}))
        stack.enter_context(patch.object(subject,'controller_inventory',return_value={'public.py':'1'*64}))
        stack.enter_context(patch.object(subject,'boot_host',return_value={
            'boot_id':EPOCH_A,'host':'declared-model','uid':os.getuid(),'gid':os.getgid()}))
        stack.enter_context(patch.object(subject,'verify_success'))
        stack.enter_context(patch.object(subject,'collect_artifacts',return_value={'actual_native_evidence_mock':True}))
        tools={name:'/nix/store/'+'0'*32+'-'+name+'/bin/'+name for name in (
            'bazel','python','systemd_run','systemctl','bootstrap','closure','java','bash')}
        return stack,document,tools

    def test_poisoned_role_paths_refuse_before_input_holds_or_artifact_reads(self):
        for role,field,value in (('source','root','/private/working-native-profile'),
            ('sdk','root','/private/browser-storage'),
            ('source','producer','/private/'+EPOCH_A+'/receipt.json'),
            ('sdk','producer','/private/'+EPOCH_B+'/receipt.json')):
            with self.subTest(role=role,field=field),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    stack,document,tools=self.owner_fixture(root)
                    if field=='producer':document[role]['producer']['receipt']=value
                    else:document[role][field]=value
                    run=root/EPOCH_A;run.mkdir(mode=0o700)
                    with stack,patch.object(subject,'read_json',return_value=document) as reader,\
                            patch.object(subject.inputs,'hold_root') as hold:
                        with self.assertRaises(ValueError):
                            subject.Admission(self.args(root,document),run,tools,('3'*64,['public.py']),
                                '/nix/store/model/bin','system',lambda receipt:True,time.monotonic_ns())
                        hold.assert_not_called()
                        self.assertEqual(len(reader.call_args_list),1)
                        self.assertEqual(reader.call_args.args[0],subject.SELECTOR)
                finally:self.clean(root)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,tools=self.owner_fixture(root);run=root/EPOCH_A;run.mkdir(mode=0o700)
                with stack,patch.object(subject,'producer_success',side_effect=ValueError('actual outer output_base differs')),\
                        patch.object(subject.inputs,'hold_root') as hold,patch.object(subject,'verify_inputs') as artifacts:
                    with self.assertRaises(ValueError):
                        subject.Admission(self.args(root,document),run,tools,('3'*64,['public.py']),
                            '/nix/store/model/bin','system',lambda receipt:True,time.monotonic_ns())
                    hold.assert_not_called();artifacts.assert_not_called()
            finally:self.clean(root)

    def admit(self,root,document,tools,stage,entry):
        epoch=EPOCH_A if stage==1 else EPOCH_B
        run=root/epoch;run.mkdir(mode=0o700,exist_ok=True)
        args=self.args(root,document,stage)
        return subject.Admission(args,run,tools,('3'*64,['public.py']),'/nix/store/model/bin','system',
            lambda receipt:True,entry)

    def complete(self,admission,exit=0):
        receipt={'id':admission.run.name,'exit':exit,'native_protocol_history':admission.facts()}
        raw=subject.terminal_receipt(admission,receipt)
        (admission.run/'receipt.json').write_text(raw)
        (admission.run/'receipt.json').chmod(0o600)
        return receipt

    def clean(self,root):
        metadata_models.MetadataProducerModels().clean(root)

    def test_actual_fresh_chain_stage2_inherits_original_clock_and_no_third_position(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,tools=self.owner_fixture(root)
                start=time.monotonic_ns()
                with stack:
                    first=self.admit(root,document,tools,1,start)
                    try:
                        self.complete(first)
                        first_custody=copy.deepcopy(first.custody)
                    finally:first.close()
                    second=self.admit(root,document,tools,2,start+100*10**9)
                    try:
                        self.assertEqual(second.custody,first_custody)
                        self.assertEqual(second.original_entry_ns,start)
                        self.assertEqual(second.original_deadline_ns,start+3600*10**9)
                        self.assertEqual(subject.completion_deadline(second.args,second.action_entry_ns,second),
                            (start+3600*10**9)/10**9)
                        self.complete(second)
                    finally:second.close()
                    with self.assertRaises((ValueError,FileExistsError)):
                        self.admit(root,document,tools,2,start+200*10**9)
                    with self.assertRaises((ValueError,FileExistsError)):
                        self.admit(root,document,tools,1,start+200*10**9)
            finally:self.clean(root)

    def test_failed_first_stage_and_pending_journal_cannot_be_continued(self):
        for terminal in (True,False):
            with self.subTest(terminal=terminal),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    stack,document,tools=self.owner_fixture(root)
                    start=time.monotonic_ns()
                    with stack:
                        first=self.admit(root,document,tools,1,start)
                        try:
                            if terminal:self.complete(first,124)
                        finally:first.close()
                        with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+10**9)
                        with self.assertRaises((ValueError,FileExistsError)):
                            self.admit(root,document,tools,1,start+10**9)
                finally:self.clean(root)

    def test_actual_terminal_validator_failure_cannot_promote_zero_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,tools=self.owner_fixture(root)
                start=time.monotonic_ns()
                with stack:
                    first=self.admit(root,document,tools,1,start)
                    try:
                        with patch.object(subject,'verify_success',side_effect=ValueError('exact native evidence refused')):
                            receipt=self.complete(first)
                        self.assertEqual(receipt['exit'],125)
                        self.assertEqual(json.loads((first.root/subject.JOURNAL).read_bytes())['status'],'closed')
                        self.assertFalse((first.run/subject.ARTIFACTS).exists())
                    finally:first.close()
                    with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+10**9)
            finally:self.clean(root)

    def test_actual_chain_content_changed_host_and_original_deadline_refuse_before_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,tools=self.owner_fixture(root)
                start=time.monotonic_ns()
                with stack:
                    first=self.admit(root,document,tools,1,start)
                    try:self.complete(first)
                    finally:first.close()
                    with patch.object(subject,'boot_host',return_value={'boot_id':EPOCH_B,'host':'another',
                            'uid':os.getuid(),'gid':os.getgid()}),patch.object(subject,'verify_inputs') as inputs:
                        with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+10**9)
                        inputs.assert_not_called()
                    with patch.object(subject.time,'monotonic',return_value=(start+3600*10**9)/10**9),\
                            patch.object(subject,'verify_inputs') as inputs:
                        with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+3600*10**9)
                        inputs.assert_not_called()
                    chain=root/'protocol-history-native-chain.json'
                    document_chain=json.loads(chain.read_bytes())
                    document_chain['original_deadline_monotonic_ns']+=10**9
                    chain.chmod(0o600);chain.write_bytes(source.encoded(document_chain));chain.chmod(0o400)
                    with patch.object(subject,'verify_inputs') as inputs:
                        with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+10**9)
                        inputs.assert_not_called()
            finally:self.clean(root)

    def test_same_path_replaced_successful_output_base_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                stack,document,tools=self.owner_fixture(root)
                start=time.monotonic_ns()
                with stack:
                    first=self.admit(root,document,tools,1,start)
                    try:self.complete(first);output=first.lease.output_base
                    finally:first.close()
                    output.rename(output.parent/'replaced-output-base')
                    output.mkdir(mode=0o700)
                    with self.assertRaises(ValueError):self.admit(root,document,tools,2,start+10**9)
            finally:self.clean(root)


if __name__=='__main__':unittest.main()
