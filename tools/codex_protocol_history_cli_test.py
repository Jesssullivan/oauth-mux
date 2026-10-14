"""Actual one-shot journal, immutable plan and evidence models; no native process."""
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
import codex_protocol_history_completed_inputs as completed
import codex_protocol_history_cli as subject

A=old_models.EPOCH_A
B=old_models.EPOCH_B
C='10000000-0000-4000-8000-000000000003'
D='10000000-0000-4000-8000-000000000004'


def encoded(value):
    return (json.dumps(value,sort_keys=True)+'\n').encode()


def identity(file):
    info=file.stat()
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
        'gid':info.st_gid,'mode':info.st_mode & 0o777}


def fixture(root):
    model=old_models.SelectedNativeModels()
    stack,document,tools=model.owner_fixture(root)
    document['controller_graph_sha256']=completed.transition_graph({'public.py':'1'*64})[0]
    original=root/'protocol-history-native-selection.json'
    original.chmod(0o600);original.write_bytes(old_models.source.encoded(document));original.chmod(0o400)
    tools['bazel']=subject.BAZEL
    tools['bash']='/nix/store/'+'0'*32+'-bash-5.3/bin/bash'
    selected_root=Path(document['source']['root'])
    sdk_root=Path(document['sdk']['root'])
    for file in (selected_root,sdk_root,root/'retained-sdk'):file.chmod(0o555)
    selection={'schema_version':1,'kind':completed.KIND,'inputs':document,
        'input_selection_sha256':subject.sha(original.read_bytes()),
        'predecessors':{'1':{'id':A,'sha256':'4'*64,'artifacts_sha256':'5'*64},
            '2':{'id':B,'sha256':'6'*64,'artifacts_sha256':'7'*64}}}
    qualified=({'source_inventory':{'plain.txt':{'mode':'100644',
        'sha256':subject.sha(b'public synthetic source\n')}},
        'inventory_sha256':document['source']['inventory_sha256']},
        {'inventory_sha256':document['sdk']['inventory_sha256'],'mapping_sha256':'8'*64,
            'registry_cache':str(sdk_root/'registry-cache'),'repositories':{},'module_overrides':{}})
    boot={'boot_id':A,'host':'declared-model','uid':os.getuid(),'gid':os.getgid()}
    old_bindings={'controller_inventory':{'public.py':'1'*64},
        'controller_graph':[document['controller_graph_sha256'],['public.py']],'tools':tools,
        'locked_path':'/nix/store/model/bin','boot_host':boot,
        'source_sdk_custody':{str(file):identity(file) for file in (
            selected_root,sdk_root,root/'retained-sdk')}}
    prior=root/A;prior.mkdir(mode=0o700)
    (prior/'receipt.json').write_bytes(encoded({'native_protocol_history':{'bindings':old_bindings}}))
    (prior/'receipt.json').chmod(0o600)
    selection['predecessors']['1']['sha256']=subject.sha((prior/'receipt.json').read_bytes())
    (root/'protocol-history-cli-selection.json').write_bytes(encoded(selection))
    (root/'protocol-history-cli-selection.json').chmod(0o400)
    for name,value in (('STATE',root),('SELECTOR',root/'protocol-history-cli-selection.json'),
            ('CHAIN',root/'protocol-history-cli-chain.json')):
        stack.enter_context(patch.object(subject,name,value))
    stack.enter_context(patch.object(completed,'STATE',root))
    stack.enter_context(patch.object(subject,'boot_host',return_value=boot))
    stack.enter_context(patch.object(completed,'boot_host',return_value=boot))
    stack.enter_context(patch.object(subject,'verify_inputs',return_value=qualified))
    stack.enter_context(patch.object(subject,'controller_inventory',return_value={'public.py':'1'*64}))
    stack.enter_context(patch.object(completed,'load_completed_inputs',
        return_value=(qualified,{'explicit_external_completed_evidence_model':True})))
    return model,stack,selection,tools,qualified


def args(root,selection):
    document=selection['inputs']
    return SimpleNamespace(profile='codex-native',manager='system',state_dir=root,
        native_protocol_cli=root/'protocol-history-cli-selection.json',
        native_protocol_cli_sha256=subject.sha(encoded(selection)),native_mode=subject.COMBINED_MODE,
        native_source_root=Path(document['source']['root']),native_source_sha256=document['source']['receipt_sha256'],
        native_export_root=Path(document['sdk']['root']),native_export_sha256=document['sdk']['receipt_sha256'],
        native_patch_sha256=['1'*64]*4,source_commit=document['controller_source_commit'],
        source_dirty='false',native_owned_candidate_cache=False,reuse_owned_cache=False,
        native_aggregate_seconds=3600,native_deadline=time.monotonic()+3600)


class CliOwnerModels(unittest.TestCase):
    def admit(self,root,selection,tools,epoch=C,entry=None):
        run=root/epoch;run.mkdir(mode=0o700)
        return subject.Admission(args(root,selection),run,tools,(selection['inputs']['controller_graph_sha256'],['public.py']),
            '/nix/store/model/bin','system',lambda receipt:True,
            time.monotonic_ns() if entry is None else entry)

    def complete(self,owner,exit=0):
        owner.verified_after_cleanup=True
        receipt={'id':owner.run.name,'exit':exit,'native_protocol_history_cli':owner.facts()}
        with patch.object(subject,'validate_completed_success'),patch.object(subject,'collect_artifacts',
                return_value={'external_native_artifacts_model':True}):
            raw=subject.terminal_receipt(owner,receipt)
        (owner.run/'receipt.json').write_text(raw);(owner.run/'receipt.json').chmod(0o600)
        return receipt

    def test_single_fresh_output_and_closed_position_never_reopens(self):
        for result in (0,124,None):
            with self.subTest(result=result),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
                try:
                    with stack:
                        owner=self.admit(root,selection,tools)
                        try:
                            self.assertEqual(owner.lease.output_base,root/('protocol-history-cli-'+owner.key)/'output-base')
                            self.assertEqual(os.listdir(owner.output_fd),[])
                            self.assertFalse('cache-v2-' in str(owner.root))
                            if result is not None:self.complete(owner,result)
                        finally:owner.close()
                        with self.assertRaises((FileExistsError,ValueError)):
                            self.admit(root,selection,tools,epoch=D)
                        self.assertFalse((root/'protocol-history-native-stage2.json').exists())
                finally:model.clean(root)

    def test_failed_predecessor_refuses_before_new_reservation_or_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                with stack,patch.object(subject,'verify_inputs',side_effect=ValueError('closed predecessor failure')),\
                        patch.object(subject.native,'copy_source') as copy_source:
                    with self.assertRaises(ValueError):self.admit(root,selection,tools)
                    copy_source.assert_not_called()
                    self.assertFalse((root/'protocol-history-cli-chain.json').exists())
                    self.assertFalse(any(file.name.startswith('protocol-history-cli-')
                        for file in root.iterdir() if file.is_dir()))
            finally:model.clean(root)

    def test_changed_actual_predecessor_bytes_refuse_before_new_reservation_or_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                # Whitespace preserves the parsed document while invalidating
                # the byte pin that was independently written into selection.
                prior=root/A/'receipt.json';prior.write_bytes(prior.read_bytes()+b'\n')
                with stack,patch.object(subject.native,'copy_source') as copy_source:
                    with self.assertRaisesRegex(ValueError,'selected metadata bytes/witness changed'):
                        self.admit(root,selection,tools)
                    copy_source.assert_not_called()
                    self.assertFalse((root/'protocol-history-cli-chain.json').exists())
                    self.assertFalse(any(file.name.startswith('protocol-history-cli-')
                        for file in root.iterdir() if file.is_dir()))
            finally:model.clean(root)

    def test_changed_controller_cannot_reserve_new_position(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                with stack,patch.object(subject,'controller_inventory',return_value={'public.py':'9'*64}):
                    with self.assertRaises(ValueError):self.admit(root,selection,tools)
                    self.assertFalse((root/'protocol-history-cli-chain.json').exists())
            finally:model.clean(root)

    def test_one_original_clock_and_runtime_cannot_be_renewed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                with stack:
                    entry=time.monotonic_ns();owner=self.admit(root,selection,tools,entry=entry)
                    try:
                        self.assertEqual(subject.completion_deadline(owner.args,entry,owner),(entry+3600*10**9)/10**9)
                        owner.args.native_deadline+=3600
                        with self.assertRaises(ValueError):owner.authorize_native_mode(owner.args)
                        with patch.object(subject.protocol.time,'monotonic',return_value=(entry+3600*10**9)/10**9):
                            with self.assertRaises(ValueError):
                                subject.completion_deadline(owner.args,entry,owner)
                    finally:owner.close()
            finally:model.clean(root)

    def test_same_path_replaced_cli_output_and_terminal_validator_failure_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                with stack:
                    owner=self.admit(root,selection,tools)
                    try:
                        owner.verified_after_cleanup=True
                        receipt={'id':C,'exit':0,'native_protocol_history_cli':owner.facts()}
                        with patch.object(subject,'validate_completed_success',side_effect=ValueError('not actual fourteen gates')),\
                                patch.object(subject,'collect_artifacts') as collector:
                            subject.terminal_receipt(owner,receipt)
                        self.assertEqual(receipt['exit'],125);collector.assert_not_called()
                        self.assertEqual(json.loads((owner.root/subject.JOURNAL).read_bytes())['status'],'closed')
                        output=owner.lease.output_base
                        output.rename(output.parent/'foreign-replacement');output.mkdir(mode=0o700)
                        with self.assertRaises(ValueError):owner.check_directories()
                    finally:owner.close()
            finally:model.clean(root)

    def test_actual_guard_parser_rejects_partial_standard_and_old_mixed_selectors(self):
        import execution_guard
        for values in (['--profile','standard','--native-protocol-cli-sha256','a'*64],
            ['--profile','codex-native','--native-protocol-cli',str(subject.SELECTOR)],
            ['--profile','codex-native','--manager','system','--state-dir',str(subject.STATE),
                '--native-mode','qualification-cli','--native-protocol-cli',str(subject.SELECTOR),
                '--native-protocol-cli-sha256','a'*64,'--native-protocol-stage','2']):
            with self.subTest(values=values),self.assertRaises(ValueError):execution_guard.main(values)

    def test_actual_fixed_cli_builder_preserves_all_fourteen_exact_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);model,stack,selection,tools,qualified=fixture(root)
            try:
                with stack:
                    owner=self.admit(root,selection,tools)
                    try:
                        plan=subject.command(owner.args,owner.run,owner.locked_path,tools['bash'],owner)
                        self.assertEqual(plan['argv'][-4:],list(subject.MODES[subject.COMBINED_MODE][1]))
                        self.assertEqual([value for value in plan['argv'] if value.startswith('--test_arg=')],
                            ['--test_arg=--exact','--test_arg=--format=pretty','--test_arg=--color=never']
                            +['--test_arg='+name for names in subject.GATES.values() for name in names])
                        self.assertEqual(sum(len(names) for names in subject.GATES.values()),14)
                        self.assertEqual(plan['candidate_output_base'],str(owner.lease.output_base))
                    finally:owner.close()
            finally:model.clean(root)


if __name__=='__main__':unittest.main()
