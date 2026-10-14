"""Real descriptor/namespace/publication predicates; no fixture authority claim."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import yoga_wrapper_companion as producer
import yoga_wrapper_companion_inputs as inputs
import yoga_python_role_alias as alias


class Models(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Production ancestry is unchanged. Unsafe Bazel fixture parents refuse.
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as tmp:
            root = Path(tmp); root.chmod(0o700)
            with patch.object(inputs, 'PUBLIC', (str(root),)):
                yield root

    def request(self, root):
        first = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        second = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        pin = lambda epoch: {'epoch': epoch, 'path': str(root/epoch/'receipt.json'), 'sha256': 'a'*64, 'bytes': 10}
        data = lambda epoch, name: {'path': str(root/epoch/name), 'sha256': 'b'*64, 'bytes': 10}
        return {'schemaVersion': 1, 'scope': inputs.SCOPE, 'selector': pin(first),
            'controllerNarProducer': pin(second), 'selectedData': data(first,'selection.json'),
            'controllerNarProof': data(second,'proof.json')}

    def held(self, root):
        path = root/'request.json'; raw = producer.canonical(self.request(root)); path.write_bytes(raw); path.chmod(0o600)
        return inputs.HeldRequest(path, hashlib.sha256(raw).hexdigest(), time.monotonic_ns()+90*10**9), path, raw

    def test_actual_request_descriptor_recheck_and_release(self):
        with self.fixture() as root:
            held, _, _ = self.held(root); descriptors = [held.fd, *(row[1] for row in held.chain)]
            self.assertEqual(held.facts()['request_sha256'], held.sha)
            held.recheck(); held.close()
            for fd in descriptors:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_same_bytes_leaf_replacement_refuses_held_request(self):
        with self.fixture() as root:
            held, path, raw = self.held(root)
            try:
                path.rename(root/'old'); path.write_bytes(raw); path.chmod(0o600)
                with self.assertRaises(ValueError): held.recheck()
            finally: held.close()

    def test_same_bytes_ancestor_rebinding_refuses_held_request(self):
        with self.fixture() as root:
            private = root/'private'; private.mkdir(mode=0o700)
            held, path, raw = self.held(private)
            try:
                private.rename(root/'old'); private.mkdir(mode=0o700)
                path.write_bytes(raw); path.chmod(0o600)
                with self.assertRaises(ValueError): held.recheck()
            finally: held.close()

    def test_raw_edit_hardlink_and_cleanup_deadline_are_refused(self):
        for change in ('edit','link','expiry'):
            with self.fixture() as root:
                held, path, raw = self.held(root)
                try:
                    if change == 'edit': path.write_bytes(raw+b' ')
                    elif change == 'link': os.link(path, root/'other')
                    else: held.deadline = time.monotonic_ns()-1
                    with self.assertRaises(ValueError): held.recheck(cleanup=True)
                finally: held.close()

    def test_request_does_not_admit_authority_clock_command_or_other_namespace(self):
        with self.fixture() as root:
            good = self.request(root)
            for name in ('controllerTools','passed','deadline','command','endpoint'):
                bad = dict(good, **{name: True})
                with self.assertRaises(ValueError): inputs.schema(producer.canonical(bad))
            for mutate in (lambda v:v['selectedData'].update(path='/tmp/selection.json'),
                lambda v:v['selectedData'].update(path=str(root/'outside.json')),
                lambda v:v['controllerNarProducer'].update(epoch=v['selector']['epoch']),
                lambda v:v.update(schemaVersion=True)):
                bad = copy.deepcopy(good); mutate(bad)
                with self.assertRaises(ValueError): inputs.schema(producer.canonical(bad))
            with self.assertRaises(ValueError): inputs.decode(b'{"scope":1,"scope":2}')

    def test_captured_log_row_join_requires_one_actual_matching_target_log(self):
        epoch = Path(inputs.PUBLIC[0])/'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        row = {'target': producer.SELECTOR, 'state': 'observed', 'configuration': 'k8-fastbuild',
            'files': [{'source':'test.log','state':'copied','file':'a'*64+'.evidence','sha256':'b'*64,'bytes':100}]}
        good = {'schema':1,'bazel_exit':0,'targets':[producer.SELECTOR],'results':[row]}
        self.assertEqual(producer.log_pin(good, producer.SELECTOR, epoch)['path'], str(epoch/'test-evidence'/('a'*64+'.evidence')))
        for mutate in (lambda v:v.update(bazel_exit=3), lambda v:v.update(results=[row,row]),
            lambda v:v['results'][0]['files'][0].update(file='../other'),
            lambda v:v['results'][0]['files'][0].update(state='stale')):
            bad=copy.deepcopy(good); mutate(bad)
            with self.assertRaises(ValueError): producer.log_pin(bad,producer.SELECTOR,epoch)
        value={'scope':'model-emission','sha256':'a'*64}
        self.assertEqual(producer.emitted(producer.canonical(value),lambda v:v.get('scope')=='model-emission'),value)
        with self.assertRaises(ValueError): producer.emitted(producer.canonical(value)+b'\n'+producer.canonical(value),lambda _:True)

    def test_byte_proof_flags_counts_and_inventory_are_all_required(self):
        inventory={'paths':[{'narSize':10}]}
        value={'schemaVersion':1,'passed':True,'inventorySha256':'a'*64,'descriptorSha256':'b'*64,
            'verifiedPaths':1,'verifiedRegularInputs':2,'verifiedNarBytes':10,'contentRehashed':True,
            'linkTargetsFollowed':False,'executionAuthority':False,'flakeMappingVerified':False,'realized':False}
        producer.proof(value,inventory,'a'*64)
        for key,replacement in (('passed',False),('contentRehashed',False),('verifiedPaths',True),
            ('verifiedNarBytes',9),('inventorySha256','c'*64),('executionAuthority',True),('realized',True)):
            bad=dict(value,**{key:replacement})
            with self.assertRaises(ValueError): producer.proof(bad,inventory,'a'*64)

    def test_actual_terminal_receipt_rejects_failed_work_and_reused_or_unowned_cleanup(self):
        selected={'epoch':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}
        value={'id':selected['epoch'],'artifact_epoch':selected['epoch'],'exit':0,'workload_exit':0,
            'verb':'test','targets':[producer.BYTE_PROOF],'manager':'system','source_dirty':'false',
            'cache_reuse_requested':False,'descendants_empty':True,'controller_failure':None,'rejection':None,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},
            'profile':'standard','source_commit':'a'*40,'limits':producer.guard.PROPERTIES,
            'test_evidence':{'state':'preserved','manifest':'test-evidence.json','sha256':'b'*64}}
        self.assertEqual(producer.receipt(value,selected,producer.BYTE_PROOF),value['test_evidence'])
        for mutate in (lambda v:v.update(exit=True),lambda v:v.update(workload_exit=3),
            lambda v:v.update(cache_reuse_requested=True),lambda v:v.update(artifact_epoch='other'),
            lambda v:v['cleanup'].update(ownership='unknown'),lambda v:v['cleanup'].update(readback_attempts=1),
            lambda v:v['test_evidence'].update(state='preservation-incomplete'),
            lambda v:v.update(targets=[producer.BYTE_PROOF,'//tools:other'])):
            bad=copy.deepcopy(value);mutate(bad)
            with self.assertRaises(ValueError):producer.receipt(bad,selected,producer.BYTE_PROOF)

    def test_real_declared_python_alias_retains_same_inode_and_bytes(self):
        role=alias.RoleIdentity(alias.PHYSICAL,{'packages':{'python':{'out':alias.ROOT}}},time.monotonic_ns()+90*10**9)
        try:
            self.assertEqual(os.fstat(role.fds[0]).st_ino,os.fstat(role.fds[1]).st_ino)
            self.assertEqual(role.hash(role.fds[0]),role.hash(role.fds[1]))
            tools=dict(producer.settings.TOOLS)
            self.assertEqual(role.logical_tools(tools)['python'],alias.LOGICAL)
            with self.assertRaises(ValueError):role.logical_tools(dict(tools,python='/usr/bin/python3'))
        finally:role.close()
        for physical in ('/usr/bin/python3',alias.ROOT+'/bin/other',alias.LOGICAL):
            with self.assertRaises(ValueError):alias.RoleIdentity(physical,{'packages':{'python':{'out':alias.ROOT}}},time.monotonic_ns()+90*10**9)

    def test_real_registry_snapshot_refuses_missing_or_changed_row(self):
        with self.fixture() as root:
            database=root/'registry.sqlite'; path=alias.PHYSICAL
            with sqlite3.connect(database) as connection:
                connection.executescript('CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY,path TEXT,hash TEXT,narSize INTEGER);CREATE TABLE Refs(referrer INTEGER,reference INTEGER);')
                connection.execute('INSERT INTO ValidPaths VALUES(1,?,?,?)',(path,'sha256:model',10))
            rows=[{'path':path,'narHash':'sha256:model','narSize':10,'references':[]}]
            producer.custody.registered_rows(rows,time.monotonic_ns()+90*10**9,database=str(database))
            with sqlite3.connect(database) as connection:connection.execute('UPDATE ValidPaths SET narSize=11')
            with self.assertRaises(ValueError):producer.custody.registered_rows(rows,time.monotonic_ns()+90*10**9,database=str(database))

    def test_actual_publication_preserves_existing_leaf_and_cleans_own_partial(self):
        # Only publication mechanics are modeled. This object has no authority
        # fields or genuine Producer initialization and never validates a grant.
        with self.fixture() as root:
            value=producer.Producer.__new__(producer.Producer)
            value.entry=time.monotonic_ns(); value.deadline=value.entry+1200*10**9
            value.content=b'{"scope":"publication-model"}\n'; value.metadata={'executionAuthority':False}
            output=root/'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'/'output-base'/'execroot'/'_main'/'bazel-out'/'k8-fastbuild'/'testlogs'/'tools'/'yoga_wrapper_companion'/'test.outputs'
            output.mkdir(parents=True,mode=0o700)
            with patch.object(inputs,'OUTPUT_STATE',str(root)), patch.object(value,'check'):
                self.assertEqual(value.publish(output),value.metadata)
                self.assertEqual((output/'wrapper-companion.json').read_bytes(),value.content)
                (output/'wrapper-companion.json').unlink()
                existing=(output/'wrapper-companion-production.json').read_bytes()
                with self.assertRaises(FileExistsError):value.publish(output)
                self.assertFalse((output/'wrapper-companion.json').exists())
                self.assertEqual((output/'wrapper-companion-production.json').read_bytes(),existing)


    def test_only_exact_internal_state_bazel_target_output_layouts_are_admitted(self):
        state=inputs.OUTPUT_STATE
        epoch='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        role='bazel-out/k8-fastbuild/testlogs/tools/yoga_wrapper_companion/test.outputs'
        for layout in ('execroot/_main/', 'sandbox/linux-sandbox/1/execroot/_main/'):
            path=state+'/'+epoch+'/output-base/'+layout+role
            self.assertEqual(inputs.output_path(path),Path(path))
            # Internal output admission grants no public request namespace.
            with self.assertRaises(ValueError):inputs.selected_path(path)
        for path in (state+'/'+epoch+'/output-base/execroot/_main/'+role+'/extra',
            state+'/'+epoch+'/output-base/execroot/_main/'+role.replace('yoga_wrapper_companion','other'),
            state+'/other/output-base/execroot/_main/'+role,
            inputs.PUBLIC[0]+'/'+epoch+'/output-base/execroot/_main/'+role,
            state+'/'+epoch+'/output-base/sandbox/linux-sandbox/0/execroot/_main/'+role):
            with self.assertRaises(ValueError):inputs.output_path(path)


if __name__=='__main__':unittest.main()
