"""Real closed-manifest, file-custody and exact admission regressions."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import yoga_sealed_transfer_schema as schema
import yoga_sealed_transfer_receiver as receiver
import yoga_sealed_transfer_stage as stage
import guard_yoga_sealed_transfer_profile as profile
import execution_guard as guard
from yoga_install_inputs_stage_test import FixtureDirectory

def fixture():
    uid='01234567-89ab-cdef-0123-456789abcdef'
    sha=hashlib.sha256(b'x').hexdigest()
    required=('MODULE.bazel','BUILD.bazel','tools/BUILD.bazel','installed-launcher.sh',
        'execution_guard.sh','yoga_reserved_session_qualification.sh','browser-inventory.json',
        'controller-inventory.json','tools/guard_yoga_toolbar_reserved.py',
        'tools/guard_yoga_installed_workspace.py','yoga_local_console_qualification.sh',
        'tools/yoga_local_console_qualification.py','tools/yoga_local_console_scope.py')
    root='/nix/store/'+'0'*32+'-fixture'
    value={'schemaVersion':1,'scope':schema.SCOPE,'transferId':uid,'producerSourceCommit':'a'*40,
        'producerGraphSha256':'b'*64,'workspaceReceipt':{'sha256':sha,'bytes':1},
        'selectedData':{'sha256':sha,'bytes':1},
        'workspaceFiles':{name:{'sha256':sha,'bytes':1,'mode':0o444} for name in required},
        'evidence':{'controller-nar-proof.json':{'path':schema.PUBLIC[0]+'/'+uid+
            '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/verify_declared_nars/test.outputs/receipt.json',
            'sha256':sha,'bytes':1}},
        'narRows':[{'path':root,'narSha256':sha,'narSize':1,'references':[root]}],
        'bootstrapSha256':{name:sha for name in schema.BOOTSTRAP},
        'destination':{'host':'yoga','user':'jsullivan2','parent':schema.PARENT,
            'workspace':schema.PARENT+'/'+uid+'/workspace'}}
    for key,epoch in (('selector',uid),('workspaceProducer','11234567-89ab-cdef-0123-456789abcdef')):
        value[key]={'epoch':epoch,'path':schema.PUBLIC[0]+'/'+epoch+'/receipt.json','sha256':sha,'bytes':1}
    return value

def checked(value):
    raw=schema.canonical(value)
    return schema.manifest(raw,hashlib.sha256(raw).hexdigest())

class TransferModels(unittest.TestCase):
    def test_digest_and_exact_manifest_members(self):
        value=fixture(); checked(value)
        raw=schema.canonical(value)
        with self.assertRaises(ValueError): schema.manifest(raw,'0'*64)
        for mutate in (lambda v:v.update(password='forbidden'),
            lambda v:v['workspaceFiles'].update({'../escape':{'sha256':'a'*64,'bytes':1,'mode':0o444}}),
            lambda v:v['workspaceFiles']['MODULE.bazel'].update(mode=0o600),
            lambda v:v['workspaceFiles'].update({'installed-workspace.json':{'sha256':'a'*64,'bytes':1,'mode':0o444}})):
            bad=copy.deepcopy(value); mutate(bad)
            with self.assertRaises(ValueError): checked(bad)

    def test_empty_declared_files_preserved(self):
        value=fixture(); value['workspaceFiles']['empty']={'sha256':hashlib.sha256(b'').hexdigest(),'bytes':0,'mode':0o444}
        self.assertIn(('workspace/empty',0,hashlib.sha256(b'').hexdigest(),0o444),schema.member_rows(checked(value)))

    def test_exact_destination_and_closed_store_topology(self):
        value=fixture()
        for mutation in (lambda v:v['destination'].update(workspace='/home/jsullivan2/workspace'),
            lambda v:v['destination'].update(user='other'),
            lambda v:v['narRows'][0]['references'].append('/nix/store/'+'1'*32+'-undeclared'),
            lambda v:v['narRows'][0].update(path='/home/jsullivan2/.config/private')):
            bad=copy.deepcopy(value); mutation(bad)
            with self.assertRaises(ValueError): checked(bad)

    def test_producer_outer_failure_cleanup_source_and_epoch_refuse(self):
        value=fixture(); selected=value['selector']
        receipt={'id':selected['epoch'],'artifact_epoch':selected['epoch'],'source_commit':value['producerSourceCommit'],
            'source_dirty':'false','graph_sha256':value['producerGraphSha256'],'profile':'yoga-installed-selection-reserved',
            'targets':['//delivery:yoga_installed_selection'],'verb':'test','exit':0,'workload_exit':0,
            'controller_failure':None,'rejection':None,'descendants_empty':True,
            'cleanup':{'ownership':'verified','state':'empty','readback_attempts':2},
            'output_base':str(Path(selected['path']).parent/'output-base'),
            'yoga_installed_reservation':{'mode':'selection','verified_after_cleanup':True,'browser_invoked':False,'provider_invoked':False}}
        schema.producer(receipt,selected,value,'selector')
        for mutation in (lambda r:r.update(exit=125),lambda r:r.update(source_commit='c'*40),
            lambda r:r.update(artifact_epoch=value['workspaceProducer']['epoch']),
            lambda r:r['cleanup'].update(readback_attempts=1)):
            bad=copy.deepcopy(receipt); mutation(bad)
            with self.assertRaises(ValueError): schema.producer(bad,selected,value,'selector')

    def test_selected_data_join_requires_actual_after_cleanup(self):
        value=fixture(); selection={'schemaVersion':2,'controllerPackage':{'root':str(stage.installed.support.TOOLS),'files':{'a.py':{'sha256':'d'*64}}},
            'inputSha256':{'fixture':'e'*64},'nativeManifestSha256':'f'*64}
        record={'controllerPackageSha256':{'a.py':'d'*64},'inputSha256':{'fixture':'e'*64},'nativeManifestSha256':'f'*64}
        row={'selection_sha256':value['selectedData']['sha256']}
        receipt={'yoga_installed_producer_input':{'before':row,'after':row,'verified_after_cleanup':True}}
        schema.selected_join(selection,record,receipt,value,controller_root=str(stage.installed.support.TOOLS))
        receipt['yoga_installed_producer_input']['after']={'selection_sha256':'0'*64}
        with self.assertRaises(ValueError): schema.selected_join(selection,record,receipt,value,controller_root=str(stage.installed.support.TOOLS))

    def test_selected_join_rejects_mixed_controller_roots(self):
        value=fixture(); expected=str(stage.installed.support.TOOLS)
        selection={'schemaVersion':2,'controllerPackage':{'root':expected,'files':{'a.py':{'sha256':'d'*64}}},
            'inputSha256':{'fixture':'e'*64},'nativeManifestSha256':'f'*64}
        record={'controllerPackageSha256':{'a.py':'d'*64},'inputSha256':{'fixture':'e'*64},'nativeManifestSha256':'f'*64}
        row={'selection_sha256':value['selectedData']['sha256']}
        receipt={'yoga_installed_producer_input':{'before':row,'after':row,'verified_after_cleanup':True}}
        schema.selected_join(selection,record,receipt,value,controller_root=expected)
        for foreign in (str(stage.ROOT.parent/(stage.ROOT.name+'-foreign')/'tools'),
                        '/srv/fast-local/jess/git/oauth-mux-protocol-sdk-20261008/tools'):
            if foreign == expected: continue
            bad=copy.deepcopy(selection);bad['controllerPackage']['root']=foreign
            with self.assertRaises(ValueError):
                schema.selected_join(bad,record,receipt,value,controller_root=expected)

    def test_bootstrap_reads_only_declared_executing_source_members_and_pins(self):
        self.assertEqual(stage.ROOT,Path(stage.__file__).resolve().parent.parent)
        self.assertEqual(stage.ROOT,stage.installed.support.ROOT)
        raw=b'# synthetic declared bootstrap member\n'; digest=hashlib.sha256(raw).hexdigest()
        value={'bootstrapSha256':{name:digest for name in schema.BOOTSTRAP}}
        seen=[];rechecked=[];closed=[]
        class Held:
            def __init__(self,path,deadline,maximum):
                self.path=path;self.raw=raw;seen.append((path,deadline,maximum))
            def recheck(self): rechecked.append(self.path)
            def close(self): closed.append(self.path)
        deadline=time.monotonic_ns()+60*10**9
        with mock.patch.object(stage.owned,'PublicFile',Held),mock.patch.dict(stage.os.environ,
                {'OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256':'a'*64}):
            source=stage.bootstrap_source(value,deadline)
            expected=[stage.ROOT/'tools'/(name+'.py') for name in schema.BOOTSTRAP]
            self.assertEqual(seen,[(path,deadline,256*1024) for path in expected])
            self.assertEqual(rechecked,expected);self.assertEqual(closed,expected)
            self.assertIn(repr(list(schema.BOOTSTRAP)),source)
            seen.clear();rechecked.clear();closed.clear()
            bad=copy.deepcopy(value);bad['bootstrapSha256'][schema.BOOTSTRAP[0]]='0'*64
            with self.assertRaises(ValueError): stage.bootstrap_source(bad,deadline)
            self.assertEqual([row[0] for row in seen],expected[:1])
            self.assertEqual(rechecked,[]);self.assertEqual(closed,expected[:1])

    def test_real_transaction_rehash_no_replace_and_extra_member(self):
        value=fixture(); raw=schema.canonical(value); digest=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(receiver.base,'Directory',FixtureDirectory), mock.patch.object(receiver,'PARENT',directory), \
                mock.patch.object(receiver,'INPUT_SHA256',digest):
            transaction=receiver.Transaction(time.monotonic_ns()+60*10**9,raw,value['transferId'])
            try:
                transaction.create()
                for name,size,sha,mode in transaction.rows: transaction.leaf(name,size,sha,mode,raw=b'x')
                transaction.leaf('transfer-input.json',len(raw),digest,0o444,raw=raw)
                transaction.readback(); transaction.published=True
                self.assertEqual(receiver.destination_readback(value['transferId'],transaction.deadline),value)
                with self.assertRaises(ValueError): receiver.Transaction(transaction.deadline,raw,value['transferId'])
                extra=Path(directory)/value['transferId']/'workspace'/'unexpected'
                extra.write_bytes(b'x')
                with self.assertRaises(ValueError): receiver.destination_readback(value['transferId'],transaction.deadline)
                extra.unlink()
                target=Path(directory)/value['transferId']/'workspace'/'MODULE.bazel'
                target.chmod(0o644); target.write_bytes(b'y'); target.chmod(0o444)
                with self.assertRaises(ValueError): receiver.destination_readback(value['transferId'],transaction.deadline)
            finally: transaction.close()

    def test_real_symlink_destination_parent_refused(self):
        value=fixture(); raw=schema.canonical(value); digest=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory)/'alias'; parent.symlink_to(directory,target_is_directory=True)
            with mock.patch.object(receiver.base,'Directory',FixtureDirectory), mock.patch.object(receiver,'PARENT',str(parent)),mock.patch.object(receiver,'INPUT_SHA256',digest):
                with self.assertRaises(OSError): receiver.Transaction(time.monotonic_ns()+60*10**9,raw,value['transferId'])

    def test_new_finite_profile_preserves_standard_and_old_stage_refusals(self):
        self.assertEqual(profile.selected(['run',profile.LABEL]),{'PrivateNetwork':'no'})
        for vector in (['run','//tools:yoga_install_inputs_stage'],['run',profile.LABEL,'--','arbitrary']):
            with self.assertRaises(ValueError): profile.selected(vector)
        with self.assertRaises(ValueError): guard.bazel_command('/nix/store/fixture/bin/bazel',Path('/tmp/fixture'),['run',profile.LABEL])
        profile.effective_runtime('10s',10)
        with self.assertRaises(ValueError): profile.effective_runtime('9s',10)

    def test_changed_nar_stream_never_yields_matching_digest(self):
        import nar_descriptor as nar
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'store'; root.mkdir(); leaf=root/'file'; leaf.write_bytes(b'original')
            descriptor=nar.describe(root); first=nar.hash_descriptor(descriptor)
            leaf.write_bytes(b'modified')
            self.assertNotEqual(nar.hash_descriptor(descriptor)['narHash'],first['narHash'])

    def test_remote_unit_parent_caps_and_exact_runtime(self):
        from yoga_install_inputs_stage_test import ReceiverTest,TOKEN
        actual=ReceiverTest().effective()
        actual['ReadWritePaths']=receiver.PARENT
        receiver.verify_unit(actual,TOKEN,10*1000000)
        for key,value in (('ReadWritePaths',receiver.base.PARENT),('MemoryMax','536870912'),
            ('RuntimeMaxUSec','9s'),('TasksMax','64'),('PrivateNetwork','no')):
            bad=dict(actual); bad[key]=value
            with self.assertRaises(ValueError): receiver.verify_unit(bad,TOKEN,10*1000000)

    def test_go_digest_refuses_before_any_destination_allocation(self):
        import signal
        value=fixture(); deadline=time.monotonic_ns()+60*10**9
        with mock.patch.object(receiver.base,'line',return_value={'go':value['transferId'],'scope':receiver.SCOPE,'inputSha256':'a'*64}), \
                mock.patch.object(receiver,'INPUT_SHA256','b'*64),mock.patch.object(receiver.os,'set_blocking'), \
                mock.patch.object(signal,'signal'),mock.patch.object(receiver,'Transaction') as transaction:
            with self.assertRaises(ValueError): receiver.worker(value['transferId'],deadline)
            transaction.assert_not_called()

    def test_closed_result_boolean_numbers_and_extra_data_refuse(self):
        value=fixture()
        with mock.patch.object(receiver,'INPUT_SHA256','a'*64):
            expected=receiver.result(value,'complete')
        schema.exact_result(expected,expected)
        for change in ({'destinationRehashed':1},{'files':True},{'unexpectedPath':'forbidden'}):
            bad=dict(expected); bad.update(change)
            with self.assertRaises(ValueError): schema.exact_result(bad,expected)

    def test_single_argument_budget_is_closed_without_launch(self):
        code=stage.program('worker=None\n',{}, {})
        self.assertLessEqual(len(code.encode()),120*1024)
        with self.assertRaises(ValueError): stage.program('x'*120*1024,{}, {})

    def test_reserved_model_actual_guard_cap_runtime_and_cgroup_readbacks(self):
        import guard_yoga_sealed_transfer_models_reserved as reserved
        import guard_resident_observation as resident
        caps=reserved.properties(guard.PROPERTIES)
        # Exercise the same helper attributes read before the real guard launches.
        caps.update(MemoryMax=str(reserved.MEMORY),TasksMax=str(reserved.TASKS),
            CPUQuotaPerSecUSec=str(reserved.CPU*10000)+'us')
        self.assertEqual(reserved.MEMORY+resident.RESIDENT_MEMORY,4*1024**3)
        self.assertEqual(reserved.TASKS+resident.RESIDENT_TASKS,512)
        self.assertEqual(reserved.CPU+resident.RESIDENT_CPU_PERCENT,200)
        self.assertEqual(caps['MemorySwapMax'],'0')
        self.assertEqual(guard.CONTROLLER_TIMEOUT,15)
        self.assertEqual(guard.workload_pids_observation(None,reserved.PROFILE).expected_limit,reserved.TASKS)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            expected={**guard.CGROUP,'memory.max':str(reserved.MEMORY),'pids.max':str(reserved.TASKS),
                'cpu.max':str(reserved.CPU*1000)+' 100000'}
            for name,value in expected.items(): (root/name).write_text(value)
            actual={**caps,**guard.SANDBOX,'RuntimeMaxUSec':'17s',
                'TemporaryFileSystem':guard.system_masks(profile='standard'),
                'UnsetEnvironment':' '.join(guard.DELEGATION_ENV)}
            readback=Path.read_text; observed=[]
            def read(path,*args,**kwargs):
                observed.append(path)
                return readback(path,*args,**kwargs)
            with mock.patch.object(Path,'read_text',autospec=True,side_effect=read):
                guard.verify(actual,root,'system',guard.SANDBOX,reserved.PROFILE,runtime_seconds=17)
            self.assertEqual(observed,[root/name for name in expected])
            for key,value in (('MemoryMax','4294967296'),('TasksMax','512'),
                    ('CPUQuotaPerSecUSec','2s'),('MemorySwapMax','1'),('PrivateNetwork','no'),
                    ('RuntimeMaxUSec','16s'),('RuntimeMaxUSec','18s'),('RuntimeMaxUSec','infinity')):
                with self.subTest(service_property=key,value=value),self.assertRaises(ValueError):
                    guard.verify({**actual,key:value},root,'system',guard.SANDBOX,reserved.PROFILE,runtime_seconds=17)
            for name,value in (('memory.max','4294967296'),('pids.max','512'),('memory.swap.max','1'),
                    ('cpu.max','200000 100000'),('cpu.max','180000 100000'),('cpu.max','max 100000')):
                (root/name).write_text(value)
                try:
                    with self.subTest(cgroup_file=name,value=value),self.assertRaises(ValueError):
                        guard.verify(actual,root,'system',guard.SANDBOX,reserved.PROFILE,runtime_seconds=17)
                finally: (root/name).write_text(expected[name])

    def test_reserved_model_shared_lifetime_and_original_deadline(self):
        import guard_yoga_sealed_transfer_models_reserved as reserved
        import guard_native_seed_plan_reserved as kernel
        for name in ('MEMORY','TASKS','CPU','properties','Witness','WorkloadWitness','monitor',
                'cleanup_retained','release_worker','remaining'):
            self.assertIs(getattr(reserved,name),getattr(kernel,name))
        entry,deadline=100*10**9,1300*10**9
        with mock.patch.object(kernel.time,'monotonic_ns',return_value=entry):
            self.assertEqual(reserved.remaining(entry,deadline),1170)
            self.assertEqual(reserved.remaining(entry,deadline,cleanup=True),1200)
            with self.assertRaises(ValueError): reserved.remaining(entry,deadline+1)
        with mock.patch.object(kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
            with self.assertRaises(ValueError): reserved.remaining(entry,deadline)
            self.assertEqual(reserved.remaining(entry,deadline,cleanup=True),30)
        with mock.patch.object(kernel.time,'monotonic_ns',return_value=deadline):
            with self.assertRaises(ValueError): reserved.remaining(entry,deadline,cleanup=True)
        self.assertTrue(reserved.release_worker(None))

if __name__=='__main__': unittest.main()
