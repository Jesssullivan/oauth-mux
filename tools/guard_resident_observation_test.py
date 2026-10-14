"""Synthetic metadata/filesystem models; no manager, IPC, provider or vault calls."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import guard_resident_observation as observation
import guard_resident_dispatch as dispatch
import guard_resident_continuity_profile as continuity
import guard_resident_namespace_profile as namespace

EPOCH='11111111-1111-4111-8111-111111111111'
def pins(cache=False):
    root=observation.PUBLIC_ROOTS[0]
    base=root/('cache-v2-'+'a'*64 if cache else EPOCH)/'output-base'
    return {'archive':{'path':str(base/'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz'),
        'sha256':'1'*64,'bytes':1},'manifest_sha256':'2'*64,
        'qualification':{'path':str(root/EPOCH/'receipt.json'),'sha256':'3'*64,'bytes':1},
        'source_commit':'4'*40,'graph_sha256':'5'*64}
def build_receipt(cache=False):
    selected=pins(cache)
    return {'id':EPOCH,'artifact_epoch':EPOCH,'profile':'standard','verb':'build',
        'targets':['//delivery:default_instance_archive'],'exit':0,'workload_exit':0,
        'descendants_empty':True,'cleanup':{'state':'empty'},'controller_failure':None,
        'source_dirty':'false','source_commit':'4'*40,'graph_sha256':'5'*64,
        'cache_reuse_requested':cache,'cache_policy':2 if cache else None,'cache_key':'a'*64 if cache else None,
        'output_base':selected['archive']['path'].split('/execroot/')[0]}
def arguments(profile='resident-namespace'):
    result=SimpleNamespace(profile=profile,manager='system',resident_manifest=Path('/public/input.json'),
        resident_epoch=EPOCH,resident_producer_sha256='1'*64,resident_observer_sha256='2'*64,
        resident_runtime_selection=None,resident_runtime_sha256=None,resident_runtime_bytes=None,
        resident_native_version=None,reuse_owned_cache=False,source_commit='3'*40,source_dirty='false',
        repository_cache=None,nixpkgs_source=None)
    return result

class MetadataModels(unittest.TestCase):
    def test_mountpoint_constructor_fault_closes_exact_owned_fd(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path=Path(temporary)/'bus'; captured=[]
            original=observation.regular_mountpoint
            def create(selected):
                held=original(selected); captured.append(held); return held
            with patch.object(observation,'regular_mountpoint',side_effect=create), \
                 patch.object(observation,'regular_mountpoint_witness',side_effect=ValueError('refused')):
                with self.assertRaises(ValueError): observation.held_mountpoint(path)
            self.assertEqual(len(captured),1)
            self.assertTrue(captured[0].closed)
            self.assertEqual(path.read_bytes(),b'')

    def test_actual_producer_string_and_both_exact_output_pointer_branches(self):
        for cached in (False,True):
            value=build_receipt(cached); selected=pins(cached)
            self.assertEqual(str(observation.qualification(value,selected)),value['output_base'])
            for key,bad in (('verb','test'),('source_dirty',False),('source_dirty','true'),
                ('source_dirty',0),('source_dirty','False'),('id','2'*36),('artifact_epoch','2'*36),
                ('exit',True),('workload_exit',125),('descendants_empty',False),
                ('output_base',str(observation.PUBLIC_ROOTS[0]/'foreign/output-base')),
                ('cache_policy',True),('cache_reuse_requested',1)):
                wrong=copy.deepcopy(value); wrong[key]=bad
                with self.subTest(cached=cached,key=key,bad=bad),self.assertRaises(ValueError):
                    observation.qualification(wrong,selected)

    def test_role_shape_and_public_namespace_refuse_before_archive_reads(self):
        for role in ('archive','qualification'):
            selected=pins(); selected[role]['path']='/home/jess/.private/never-open'
            with patch.object(observation.os,'open') as opened,self.assertRaises(ValueError):
                observation.installation_selection(selected)
            opened.assert_not_called()
        for bad in (True,0,-1):
            selected=pins(); selected['archive']['bytes']=bad
            with self.assertRaises(ValueError): observation.installation_selection(selected)

    def test_resident_effective_caps_and_real_cgroup_drift(self):
        properties={'MemoryMax':'268435456','MemorySwapMax':'0','TasksMax':'32','CPUQuotaPerSecUSec':'100ms'}
        readback={'memory.max':'268435456','memory.swap.max':'0','pids.max':'32','cpu.max':'10000 100000'}
        self.assertTrue(observation.check_resident_bounds(properties,readback))
        for key,bad in (('memory.max','268435457'),('memory.swap.max','1'),('pids.max','33'),('cpu.max','10001 100000')):
            with self.assertRaises(ValueError): observation.check_resident_bounds(properties,{**readback,key:bad})
        for bad in ('101ms','NaNs','0s','0.100001s'):
            with self.assertRaises(ValueError): observation.check_resident_bounds({**properties,'CPUQuotaPerSecUSec':bad},readback)

    def test_optional_secret_absence_is_explicit_and_every_present_role_is_owned(self):
        identity={'uid':os.getuid(),'pid':123,'start_ticks':456}
        value={'schema_version':1,'broker':identity,'manager':{'owner':':1.2',**identity},'secret_service':None}
        self.assertIs(observation.validate_session_observation(value,True),value)
        with self.assertRaises(ValueError): observation.validate_session_observation(value)
        value['secret_service']={'owner':':1.3',**identity}
        observation.validate_session_observation(value)
        for key,bad in (('uid',os.getuid()+1),('pid',0),('start_ticks',True),('owner','org.freedesktop.secrets')):
            wrong=copy.deepcopy(value); wrong['secret_service'][key]=bad
            with self.assertRaises(ValueError): observation.validate_session_observation(wrong,True)

    def test_held_metadata_refuses_same_bytes_replacement_and_parent_replacement(self):
        # Actual owned HOME temporary files, not a production /tmp custody exception.
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            parent=Path(temporary)/'selected'; parent.mkdir(mode=0o700)
            path=parent/'public.json'; path.write_bytes(b'public\n'); path.chmod(0o600)
            pin={'path':str(path),'sha256':hashlib.sha256(b'public\n').hexdigest(),'bytes':7}
            witness=observation.PinnedMetadata(pin,10**30)
            try:
                witness.recheck()
                parent.rename(Path(temporary)/'old'); parent.mkdir(mode=0o700)
                path.write_bytes(b'public\n'); path.chmod(0o600)
                with self.assertRaises(ValueError): witness.recheck()
            finally: witness.close()
            witness=observation.PinnedMetadata(pin,10**30)
            try:
                replacement=parent/'replacement'; replacement.write_bytes(b'public\n'); replacement.chmod(0o600)
                replacement.replace(path)
                with self.assertRaises(ValueError): witness.recheck()
            finally: witness.close()

    def test_original_work_reserve_and_collection_use_same_original_clock(self):
        admission=observation.Admission.__new__(observation.Admission); admission.deadline_ns=100*10**9
        with patch.object(observation.time,'monotonic_ns',return_value=20*10**9):
            self.assertEqual(admission.runtime_seconds(),50)
        metadata=observation.PinnedMetadata.__new__(observation.PinnedMetadata); metadata.deadline=70*10**9
        observer=SimpleNamespace(deadline=70*10**9,installation=SimpleNamespace(resources=[metadata]))
        with patch.object(observation.time,'monotonic_ns',return_value=80*10**9):
            with self.assertRaises(ValueError): admission.runtime_seconds()
            observation.collection_deadline(observer,[],100*10**9)
            self.assertEqual(metadata.deadline,100*10**9)
            self.assertEqual(observer.deadline,100*10**9)
        with patch.object(observation.time,'monotonic_ns',return_value=100*10**9):
            with self.assertRaises(ValueError): observation.collection_deadline(observer,[],100*10**9)

class DispatchModels(unittest.TestCase):
    def test_exact_namespace_early_selection_and_partial_foreign_selectors_refuse(self):
        self.assertIs(dispatch.select(arguments(),['run',namespace.LABEL]),namespace)
        for changes in ({'resident_epoch':None},{'resident_runtime_bytes':1},{'reuse_owned_cache':True},
            {'manager':'user'},{'profile':'standard'},{'native_mode':'cli-opt'},
            {'repository_cache':dispatch.REPOSITORY_CACHE}):
            value=arguments(); vars(value).update(changes)
            with self.assertRaises(ValueError): dispatch.select(value,['run',namespace.LABEL])
        for command in (['test',namespace.LABEL],['run',continuity.LABEL],['run',namespace.LABEL,'--']):
            with self.assertRaises(ValueError): dispatch.select(arguments(),command)

    def test_leaf_requests_join_suffix_free_readback_and_recursive_directories(self):
        leaf='/source/bus:/private/bus'; directory='/source/tree:/private/tree'
        self.assertEqual(observation.normalize_binds(leaf+':norbind '+directory,(leaf,)),[leaf,directory])
        self.assertEqual(observation.normalize_binds(leaf+' '+directory+':rbind',(leaf,),readback=True),[leaf,directory])
        for wrong in (leaf+':norbind '+directory+':rbind',leaf+':rbind '+directory+':rbind',leaf+' '+directory):
            with self.assertRaises(ValueError): observation.normalize_binds(wrong,(leaf,),readback=True)

    def test_exact_cache_recursive_readback_projection_and_writable_dedup(self):
        admission=SimpleNamespace(verify_bindings=Mock(),writable_binding=lambda:'/owned:/owned')
        cache=str(dispatch.REPOSITORY_CACHE)+':'+str(dispatch.REPOSITORY_CACHE)+':rbind'
        dispatch.verify_bindings(admission,{'BindReadOnlyPaths':cache+' /a:/b:rbind'},Path('/owned'),dispatch.REPOSITORY_CACHE)
        admission.verify_bindings.assert_called_once_with({'BindReadOnlyPaths':'/a:/b:rbind'},Path('/owned'))
        self.assertEqual(dispatch.writable_bindings(admission,Path('/owned')),['/owned:/owned'])
        for wrong in (cache+' '+cache,cache.removesuffix(':rbind'),cache.replace(':rbind',':norbind')):
            with self.assertRaises(ValueError): dispatch.verify_bindings(admission,{'BindReadOnlyPaths':wrong},Path('/owned'),dispatch.REPOSITORY_CACHE)

    def test_closed_failures_and_copied_redaction_never_format_private_error(self):
        class PrivateError(OSError):
            def __str__(self): raise AssertionError('must never format selected private path')
        actual={'BindReadOnlyPaths':'/private/input:/alias','BindPaths':'/private/proof:/proof'}
        projection=observation.projection(actual)
        self.assertEqual(actual['BindReadOnlyPaths'],'/private/input:/alias')
        self.assertNotIn('/private',str(projection))
        self.assertEqual(observation.rejection(PrivateError()),'resident-observation-refused')
        selected=SimpleNamespace(Admission=Mock(side_effect=PrivateError()))
        with self.assertRaisesRegex(ValueError,'^resident-admission-refused$'):
            dispatch.admit(selected,arguments(),Path('/public'),Path('/nix/store/public/bin/systemctl'),100*10**9)

if __name__=='__main__': unittest.main()
