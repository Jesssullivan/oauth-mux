"""Real filesystem receiver seams, synthetic success receipts, no browser/vault.

Only the declared Bazel action may execute these models. Passing synthetic
producer metadata never qualifies a real retained artifact or human consent.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
import yoga_public_artifact_prepare as prepared
import yoga_public_artifact_receive as receiver
import test_yoga_public_artifact_prepare as fixture


class ReceiverModels(unittest.TestCase):
    def setUp(self):
        self.f=fixture.PreparationModels(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        # Match the declared generated File and control alias used by the real
        # receiver, rather than borrow the older fixture's arbitrary filename.
        raw=self.f.declaration.read_bytes();self.f.declaration.unlink()
        generated=self.f.physical/'yoga_public_artifact_inputs.json'
        generated.write_bytes(raw);generated.chmod(0o555)
        self.f.declaration=self.f.controls/'_main/delivery/yoga_public_artifact_inputs.json'
        self.f.declaration.symlink_to(generated)
        self.artifact=self.f.prepare();self.creator=copy.deepcopy(self.f.context)
        self.product=self.f.output/'yoga-public-toolbar'
        self.receipt={'id':self.f.epoch.name,'verb':'test','targets':[prepared.LABEL],
            'exit':0,'workload_exit':0,'source_commit':self.creator['sourceCommit'],'source_dirty':'false',
            'graph_sha256':self.creator['graphSha256'],'output_base':str(self.f.base),
            'descendants_empty':True,'controller_failure':None,'profile':'standard','manager':'system',
            'cache_reuse_requested':False,'yoga_public_artifact_preparation':{
                'scope':'yoga-current-public-toolbar-retained-v1','cached_candidate_input_only':True,
                'verified_after_cleanup':True,'original_entry_monotonic_ns':self.creator['entryNs'],
                'original_deadline_monotonic_ns':self.creator['deadlineNs'],'action_jobs':1,
                'original_runfiles_retained_only':True,'fresh_consumer_qualification_required':True,
                'execution_authority':False,'seat_qualified':False,'toolbar_consent_proved':False}}
        self.retirement={'schema':1,'policy':'bounded-post-terminal-fixed-owned-children-v2',
            'state':'complete','reason':'qualified-terminal','receipt_sha256':'',
            'retained_output_contract':[prepared.LABEL],'children':{'output-base':'retained-declared-producer'},
            'retained_physical_root':{'device':self.f.base.stat().st_dev,'inode':self.f.base.stat().st_ino},
            'budget':{'original_entry_monotonic_ns':self.creator['entryNs'],
                'original_deadline_monotonic_ns':self.creator['deadlineNs']}}
        self.selection_path=self.f.root/'receiver-selection.json'
        self.current=dict(self.creator,epoch=str(self.f.epoch.with_name('22345678-1234-4234-8234-123456789abc')),
            entryNs=5000*10**9,deadlineNs=6200*10**9,sourceCommit='c'*40,graphSha256='d'*64)
        self.f.now=self.current['entryNs']+10**9
        self.seal()

    def write(self,path,value):
        path=Path(path)
        if path.exists():path.chmod(0o600)
        raw=prepared.canonical(value);path.write_bytes(raw);path.chmod(0o600)
        return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

    def seal(self):
        receipt=self.write(self.f.epoch/'receipt.json',self.receipt)
        self.retirement['receipt_sha256']=receipt['sha256']
        retirement=self.write(self.f.epoch/'test-evidence-retirement.json',self.retirement)
        raw=(self.product/'artifact.json').read_bytes()
        selected={'schemaVersion':1,'scope':'yoga-public-toolbar-receiver-selection-v1',
            'producerContext':self.creator,'artifact':{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},
            'producerReceipt':receipt,'retirement':retirement}
        self.selection=self.write(self.selection_path,selected)

    def qualify(self):return receiver.qualify(self.selection_path,self.selection['sha256'],self.current)

    def test_real_full_rehash_succeeds_on_fresh_clock_after_creator_clock_expired_without_authority(self):
        self.assertGreater(self.f.now,self.creator['deadlineNs'])
        result=self.qualify()
        self.assertEqual(result['producerContext'],self.creator)
        self.assertEqual(result['currentContext'],self.current)
        self.assertTrue(result['fullBytesRehashed'] and result['originalPhysicalRootsMatched'])
        self.assertEqual(result['verifiedDirectoryCount'],4)
        self.assertEqual(result['inventorySha256'],self.artifact['inventorySha256'])
        self.assertTrue(all(result[name] is False for name in prepared.FALSE))
        self.assertFalse(result['candidateRunnerExecuted'])
        self.assertTrue(result['humanToolbarConsentRequired'])

    def test_failed_or_unretired_or_wrong_original_producer_receives_no_credit(self):
        for change in ('exit','verified','label','unretired','inode','deadline'):
            receipt=copy.deepcopy(self.receipt);retirement=copy.deepcopy(self.retirement)
            if change=='exit':self.receipt['exit']=125
            elif change=='verified':self.receipt['yoga_public_artifact_preparation']['verified_after_cleanup']=False
            elif change=='label':self.receipt['targets']=['//delivery:yoga_public_artifact_prepare_test']
            elif change=='unretired':self.retirement['state']='prepared'
            elif change=='inode':self.retirement['retained_physical_root']['inode']+=1
            else:self.retirement['budget']['original_deadline_monotonic_ns']+=1
            self.seal()
            with self.subTest(change=change),self.assertRaises(ValueError):self.qualify()
            self.receipt=receipt;self.retirement=retirement

    def test_changed_metadata_and_legacy_descriptor_refuse_even_if_selection_resealed(self):
        original=copy.deepcopy(self.artifact)
        for change in ('legacy','false','wirehash','root','source'):
            value=copy.deepcopy(original)
            if change=='legacy':value['schemaVersion']=1;value.pop('directoryWitnesses')
            elif change=='false':value['toolbarConsentProved']=True
            elif change=='wirehash':value['inventorySha256']='0'*64
            elif change=='root':value['directoryWitnesses'][0]['witness'][1]+=1
            else:value['context']['sourceCommit']='e'*40
            self.write(self.product/'artifact.json',value);self.seal()
            with self.subTest(change=change),self.assertRaises(ValueError):self.qualify()
        self.write(self.product/'artifact.json',original)

    def test_same_content_replacement_of_original_control_directory_refuses(self):
        retired=self.f.controls.with_name('old-control-root')
        self.f.controls.rename(retired);shutil.copytree(retired,self.f.controls,symlinks=True)
        self.assertNotEqual(self.f.controls.stat().st_ino,retired.stat().st_ino)
        with self.assertRaises(ValueError):self.qualify()

    def test_same_content_replacement_of_original_runner_directory_refuses(self):
        retired=self.f.runner.with_name('old-runner-root')
        self.f.runner.rename(retired);shutil.copytree(retired,self.f.runner,symlinks=True)
        with self.assertRaises(ValueError):self.qualify()

    def test_actual_changed_leaf_and_alias_refuse_without_new_borrowed_source(self):
        self.f.mutate_fixture('dbus_session',self.f.data['dbus_session']+b'changed')
        with self.assertRaises(ValueError):self.qualify()
        self.f.mutate_fixture('dbus_session',self.f.data['dbus_session'])
        # Restoring bytes never restores original full-nine physical witnesses.
        with self.assertRaises(ValueError):self.qualify()

    def test_changed_alias_during_later_actual_tuple_io_and_all_fds_are_retired(self):
        real_open=os.open;real_close=os.close;real_read=os.read
        opened=[];closed=[];changed=False;inode=self.f.paths['bundle'].stat().st_ino
        alias=self.f.runner/self.f.roles['observer']
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):closed.append(fd);return real_close(fd)
        def read(fd,count):
            nonlocal changed
            block=real_read(fd,count)
            if block and not changed and os.fstat(fd).st_ino==inode:
                alias.unlink();alias.symlink_to(self.f.paths['recorder']);changed=True
            return block
        with patch.object(prepared.os,'open',side_effect=opening),patch.object(prepared.os,'close',side_effect=closing),\
                patch.object(prepared.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.qualify()
        self.assertTrue(changed);self.assertEqual(sorted(opened),sorted(closed))
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)

    def test_original_receiver_cutoff_during_actual_file_read_refuses_and_drains(self):
        real=os.read;changed=False;inode=self.f.paths['bundle'].stat().st_ino
        def read(fd,count):
            nonlocal changed
            block=real(fd,count)
            if block and os.fstat(fd).st_ino==inode:
                self.f.now=self.current['deadlineNs']-30*10**9;changed=True
            return block
        with patch.object(prepared.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.qualify()
        self.assertTrue(changed)

    def test_metadata_call_entry_and_slot_insertion_refusal_open_nothing_or_close_once(self):
        real_open=os.open;real_close=os.close;real_append=prepared.Owned.append
        for phase in ('entry','before','after'):
            opened=[];closed=[]
            def opening(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            def closing(fd):closed.append(fd);return real_close(fd)
            def append(owner,slot):
                if phase=='before':raise MemoryError('synthetic preregistration')
                real_append(owner,slot)
                raise MemoryError('synthetic postregistration')
            seam=patch.object(prepared.Owned,'empty_directory',side_effect=MemoryError('synthetic entry')) if phase=='entry' else patch.object(prepared.Owned,'append',new=append)
            with self.subTest(phase=phase),seam,patch.object(prepared.os,'open',side_effect=opening),\
                    patch.object(prepared.os,'close',side_effect=closing):
                with self.assertRaises(MemoryError):self.qualify()
            self.assertEqual(opened,[]);self.assertEqual(closed,[])

    def test_metadata_same_byte_replacement_at_last_fd_close_refuses_success(self):
        real=os.close;changed=False;path=self.f.epoch/'receipt.json';raw=path.read_bytes()
        def close(fd):
            nonlocal changed
            if not changed:
                copy=path.with_name('replacement-receipt.json');copy.write_bytes(raw);copy.chmod(0o600);copy.replace(path);changed=True
            return real(fd)
        with patch.object(prepared.os,'close',side_effect=close):
            with self.assertRaises(ValueError):self.qualify()
        self.assertTrue(changed)

    def test_receiver_main_late_stdout_refuses_original_deadline_without_claiming_marker_acceptance(self):
        fields={'EPOCH':self.current['epoch'],'ENTRY_NS':str(self.current['entryNs']),
            'DEADLINE_NS':str(self.current['deadlineNs']),'SOURCE_COMMIT':self.current['sourceCommit'],
            'GRAPH_SHA256':self.current['graphSha256'],'SOURCE_ROOT':self.current['sourceRoot'],
            'SELECTION_PATH':str(self.selection_path),'SELECTION_SHA256':self.selection['sha256']}
        class Output(io.StringIO):
            def flush(output):self.f.now=self.current['deadlineNs']-30*10**9
        with patch.dict(os.environ,{receiver.VARIABLE+name:value for name,value in fields.items()},clear=True),\
                patch.object(sys,'argv',['receiver']),patch.object(sys,'stdout',Output()):
            with self.assertRaises(ValueError):receiver.main()


    def test_source_root_convenience_link_metadata_changes_are_freshly_fenced_not_original_inode_changes(self):
        old=next(row for row in self.artifact['directoryWitnesses'] if row['path']==str(self.f.source))
        (self.f.source/'bazel-bin').symlink_to(self.f.physical,target_is_directory=True)
        fresh=list(prepared.witness(self.f.source.lstat()))
        self.assertEqual(fresh[:5],old['witness'][:5]);self.assertNotEqual(fresh,old['witness'])
        result=self.qualify()
        self.assertTrue(result['originalDirectoryIdentityMatched'])
        self.assertEqual(next(row['witness'] for row in result['freshDirectoryWitnesses']
            if row['path']==str(self.f.source)),fresh)
        self.assertEqual(self.artifact['directoryWitnesses'],prepared.decode(
            (self.product/'artifact.json').read_bytes())['directoryWitnesses'])

    def test_same_content_original_source_directory_replacement_is_not_a_timestamp_transition(self):
        retired=self.f.source.with_name('prior-source')
        self.f.source.rename(retired);shutil.copytree(retired,self.f.source,symlinks=True)
        self.assertNotEqual(self.f.source.stat().st_ino,retired.stat().st_ino)
        with self.assertRaises(ValueError):self.qualify()

    def test_current_source_root_child_mutation_during_actual_bytes_refuses_and_drains(self):
        real_read=os.read;real_open=os.open;real_close=os.close
        opened=[];closed=[];changed=False;inode=self.f.paths['bundle'].stat().st_ino
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):closed.append(fd);return real_close(fd)
        def read(fd,count):
            nonlocal changed
            block=real_read(fd,count)
            if block and not changed and os.fstat(fd).st_ino==inode:
                (self.f.source/'new-convenience-link').symlink_to(self.f.physical);changed=True
            return block
        with patch.object(prepared.os,'open',side_effect=opening),patch.object(prepared.os,'close',side_effect=closing),\
                patch.object(prepared.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.qualify()
        self.assertTrue(changed);self.assertEqual(sorted(opened),sorted(closed))
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)


    def assert_last_metadata_close_mutation_refuses(self,domain):
        real_open=os.open;real_close=os.close;root=os.stat('/')
        opened=[];closed=[];changed=False;inputs_finished=False
        leaf=self.f.paths['observer'];original=leaf.read_bytes()
        alias=self.f.runner/self.f.roles['observer']
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        actual_inputs_close=prepared.Inputs.close
        def inputs_close(owner,primary=None):
            nonlocal inputs_finished
            actual_inputs_close(owner,primary);inputs_finished=True
        def closing(fd):
            nonlocal changed
            info=os.fstat(fd)
            # The first metadata '/' owner is drained LAST. No later FD close
            # remains; Inputs have already finished their own named readback.
            if inputs_finished and not changed and len(closed)==len(opened)-1:
                self.assertEqual((info.st_dev,info.st_ino),(root.st_dev,root.st_ino))
                if domain=='leaf':
                    replacement=leaf.with_name('same-byte-input-replacement')
                    replacement.write_bytes(original);replacement.chmod(0o555);replacement.replace(leaf)
                else:
                    alias.unlink();alias.symlink_to(self.f.paths['recorder'])
                changed=True
            closed.append(fd);return real_close(fd)
        with patch.object(prepared.os,'open',side_effect=opening),\
                patch.object(prepared.os,'close',side_effect=closing),\
                patch.object(prepared.Inputs,'close',new=inputs_close):
            with self.assertRaises(ValueError):self.qualify()
        self.assertTrue(inputs_finished);self.assertTrue(changed)
        self.assertEqual(sorted(opened),sorted(closed))
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)

    def test_last_metadata_close_same_byte_input_leaf_replacement_refuses_after_all_drains(self):
        self.assert_last_metadata_close_mutation_refuses('leaf')

    def test_last_metadata_close_input_alias_change_refuses_after_all_drains(self):
        self.assert_last_metadata_close_mutation_refuses('alias')


    def test_action_selection_parent_755_refuses_before_selector_bytes_with_all_fds_closed(self):
        parent=self.selection_path.parent;self.assertEqual(parent.stat().st_mode&0o777,0o700)
        real_open=os.open;real_close=os.close;opened=[];closed=[]
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):closed.append(fd);return real_close(fd)
        parent.chmod(0o755)
        try:
            with patch.object(prepared.os,'open',side_effect=opening),\
                    patch.object(prepared.os,'close',side_effect=closing),\
                    patch.object(prepared.os,'read',wraps=os.read) as reads:
                with self.assertRaises(ValueError):self.qualify()
                reads.assert_not_called()
            self.assertGreater(len(opened),0);self.assertEqual(sorted(opened),sorted(closed))
            for fd in set(opened):
                with self.assertRaises(OSError):os.fstat(fd)
        finally:parent.chmod(0o700)


    def test_selection_parent_mode_change_at_later_fstat_cannot_replace_checked_private_witness(self):
        parent=self.selection_path.parent;identity=(parent.stat().st_dev,parent.stat().st_ino)
        actual_fstat=os.fstat;real_open=os.open;real_close=os.close
        selected_calls=0;changed=False;opened=[];closed=[]
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):closed.append(fd);return real_close(fd)
        def fstat(fd):
            nonlocal selected_calls,changed
            info=actual_fstat(fd)
            if (info.st_dev,info.st_ino)==identity:
                selected_calls+=1
                # First: acquisition's held/named join. Second: private-policy
                # observation. Third: V2's unchecked replacement baseline, or
                # V3's actual fresh held recheck after selector content IO.
                if selected_calls==3:
                    parent.chmod(0o755);changed=True;info=actual_fstat(fd)
            return info
        try:
            with patch.object(prepared.os,'open',side_effect=opening),\
                    patch.object(prepared.os,'close',side_effect=closing),\
                    patch.object(prepared.os,'fstat',side_effect=fstat):
                with self.assertRaises(ValueError):self.qualify()
            self.assertTrue(changed);self.assertGreaterEqual(selected_calls,3)
            self.assertEqual(sorted(opened),sorted(closed))
            for fd in set(opened):
                with self.assertRaises(OSError):actual_fstat(fd)
        finally:parent.chmod(0o700)


if __name__=='__main__':
    fixture.ZIP=Path(sys.argv.pop(1)).read_bytes();fixture.RULE=Path(sys.argv.pop(1)).read_bytes()
    unittest.main()
