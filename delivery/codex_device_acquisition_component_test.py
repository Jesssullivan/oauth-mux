"""Synthetic provider-free byte/ownership/receipt models, no native invocation."""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock
import uuid
import codex_device_acquisition_component as subject

EPOCH='12345678-1234-4234-8234-123456789abc'
SOURCE='a'*40
GRAPH='b'*64

def selected(base):
    return {'path':str(base/EPOCH/'receipt.json'),'sha256':'c'*64,'bytes':900,
        'source_commit':SOURCE,'graph_sha256':GRAPH}

def receipt(base,cached=False):
    return {'id':EPOCH,'artifact_epoch':EPOCH,'source_commit':SOURCE,'source_dirty':'false',
        'graph_sha256':GRAPH,'profile':'standard','manager':'system','verb':'test','targets':[subject.DEVICE],
        'exit':0,'workload_exit':0,'descendants_empty':True,'controller_failure':None,
        'cleanup':{'state':'empty','ownership':'unproved'},'test_evidence':{'state':'preserved'},
        'limits':dict(subject.LIMITS),'observed_properties':dict(subject.LIMITS,PrivateNetwork='yes',
            NoNewPrivileges='yes',ProtectControlGroups='yes',RestrictSUIDSGID='yes'),
        'original_cgroup_identity':{'device':1,'inode':2},
        'cache_reuse_requested':cached,'cache_policy':2 if cached else None,'cache_key':'d'*64 if cached else None,
        'output_base':str(base/('cache-v2-'+'d'*64 if cached else EPOCH)/'output-base')}

class ContractTests(unittest.TestCase):
    def test_genuine_producer_shape_uncached_and_cache_namespace(self):
        base=subject.COORDS[0]
        for cached in (False,True):
            value=receipt(base,cached)
            result=subject.outer(value,selected(base),subject.DEVICE)
            self.assertEqual(result,Path(value['output_base'])/'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_retained_device_api_qualification/test.outputs')
    def test_failed_other_purpose_dirty_type_and_guessed_pointer_refused(self):
        base=subject.COORDS[0]
        changes=({'targets':[subject.PRODUCER]},{'verb':'run'},{'exit':False},{'workload_exit':1},
            {'source_dirty':False},{'source_dirty':'true'},{'descendants_empty':False},
            {'controller_failure':'failure'},{'cache_reuse_requested':None},
            {'cache_reuse_requested':True,'cache_policy':True,'cache_key':'d'*64},
            {'artifact_epoch':'87654321-1234-4234-8234-123456789abc'},
            {'output_base':'/home/jess/.ssh/output-base'})
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):
                subject.outer(receipt(base)|change,selected(base),subject.DEVICE)

    def test_reserved_producer_receipt_requires_its_exact_limits_and_original_output_join(self):
        base=subject.COORDS[0]
        for profile,limits in ((subject.FULL_PROFILE,subject.LIMITS),
                (subject.RESERVED_PROFILE,subject.RESERVED_LIMITS)):
            value=receipt(base)
            value.update(profile=profile,targets=[subject.PRODUCER],limits=dict(limits))
            value['observed_properties']=dict(limits,PrivateNetwork='yes',NoNewPrivileges='yes',
                ProtectControlGroups='yes',RestrictSUIDSGID='yes',RuntimeMaxUSec='19min')
            value['codex_device_component']={'verified_after_cleanup':True,
                'original_entry_monotonic_ns':1,'original_deadline_monotonic_ns':1+1200*10**9,
                'input':{'action':'produce','scope':'provider-free-codex-device-component','manifest_sha256':'e'*64,
                    'provider_request_performed':False,'native_execution_performed':False,'resident_effects_authorized':False,
                    'continuity_qualified':False,'credential_contents_read':False},
                'output':{'action':'produce','action_epoch':EPOCH,'controller_graph_sha256':GRAPH,'manifest_sha256':'e'*64,
                    'provider_request_performed':False,'resident_enrollment_completed':False,'continuity_qualified':False}}
            expected=Path(value['output_base'])/'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/codex_device_acquisition_component/test.outputs'
            self.assertEqual(subject.outer(value,selected(base),subject.PRODUCER),expected)
            if profile==subject.RESERVED_PROFILE:
                for cpu in ('1.900000s','1900ms','1900000us'):
                    equivalent=copy.deepcopy(value);equivalent['observed_properties']['CPUQuotaPerSecUSec']=cpu
                    self.assertEqual(subject.outer(equivalent,selected(base),subject.PRODUCER),expected)
                for cpu in ('1900001us','1899999us','1900000',True,'1.900000s\\n'):
                    changed=copy.deepcopy(value);changed['observed_properties']['CPUQuotaPerSecUSec']=cpu
                    with self.subTest(cpu=cpu),self.assertRaises(ValueError):
                        subject.outer(changed,selected(base),subject.PRODUCER)
            wrong_profile=subject.FULL_PROFILE if profile==subject.RESERVED_PROFILE else subject.RESERVED_PROFILE
            for change in ({'profile':wrong_profile},{'profile':'standard'},
                    {'limits':dict(subject.LIMITS if profile==subject.RESERVED_PROFILE else subject.RESERVED_LIMITS)},
                    {'output_base':'/private/guessed/output-base'},{'targets':[subject.PRODUCER,subject.DEVICE]},
                    {'source_commit':'f'*40},{'exit':False},{'descendants_empty':False}):
                with self.subTest(profile=profile,change=change),self.assertRaises(ValueError):
                    subject.outer(value|change,selected(base),subject.PRODUCER)
            for key,bad in (('MemoryMax','4294967296' if profile==subject.RESERVED_PROFILE else '4026531840'),
                    ('TasksMax','512' if profile==subject.RESERVED_PROFILE else '480'),
                    ('CPUQuotaPerSecUSec','2s' if profile==subject.RESERVED_PROFILE else '1.9s'),
                    ('PrivateNetwork','no'),('RuntimeMaxUSec','20min 1us')):
                changed=copy.deepcopy(value);changed['observed_properties'][key]=bad
                with self.subTest(profile=profile,key=key),self.assertRaises(ValueError):
                    subject.outer(changed,selected(base),subject.PRODUCER)
        changed=receipt(base);changed['profile']=subject.RESERVED_PROFILE
        changed['limits']=dict(subject.RESERVED_LIMITS)
        with self.assertRaises(ValueError):subject.outer(changed,selected(base),subject.DEVICE)

    def test_public_before_read_receipt_namespace(self):
        for path in ('/home/jess/.ssh/receipt.json','/run/user/1000/receipt.json',
            str(subject.COORDS[0]/'not-an-epoch/receipt.json')):
            with self.subTest(path=path),self.assertRaises(ValueError):subject.public_receipt(path)
    def test_complete_device_descriptor_has_no_continuity_or_renewal_transfer(self):
        files=subject.inventory()|{'native-source-receipt.json':{'sha256':'1'*64,'bytes':200,'mode':0o444},
            'qualification.json':{'sha256':'2'*64,'bytes':300,'mode':0o444}}
        value={'schema_version':1,'scope':subject.SCOPE,'purpose':'device-account-acquisition',
            'system':'x86_64-linux','backend_sha256':subject.BACKEND,'files':files,
            'qualification':{'inner':{'sha256':'1'*64,'bytes':200},'outer':{
                'sha256':'2'*64,'bytes':300,'id':EPOCH,'source_commit':SOURCE,'graph_sha256':GRAPH}},
            'version':'codex 0.0.0','renewal_owner':'native','native_support':False,
            'text_continuity':False,'provider_evaluation':False}
        subject.validate_component(value)
        for change in ({'purpose':'continuity'},{'renewal_owner':'omux'},{'native_support':True},
            {'provider_evaluation':True},{'version':'future'},{'files':files|{'capsule':files['codex']}}):
            with self.subTest(change=change),self.assertRaises(ValueError):subject.validate_component(value|change)
        for name in subject.inventory():
            altered=copy.deepcopy(value);altered['files'][name]['sha256']='f'*64
            with self.subTest(name=name),self.assertRaises(ValueError):subject.validate_component(altered)
    def test_no_duplicate_canonical_json_or_unsafe_selector(self):
        for raw in (b'{"a":1,"a":2}',b'{"a": 1}'):
            with self.assertRaises(ValueError):subject.parsed(raw,True)
        for value in ('/home/jess/../private','/home/jess/a:b','/home/jess/a\\b','/home/jess/a\nb'):
            with self.assertRaises(ValueError):subject.canonical(value)
    def test_declared_producer_output_has_exact_epoch_target_and_sandbox_shape(self):
        run=subject.COORDS[1]/EPOCH
        suffix='execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/codex_device_acquisition_component/test.outputs'
        for middle in ('','sandbox/processwrapper-sandbox/12/','sandbox/linux-sandbox/0/'):
            value=run/'output-base'/(middle+suffix)
            self.assertEqual(subject.output_parent(value,run),value)
        for value in (run/'output-base/test.outputs',run/'output-base'/suffix.replace('component/','other/'),
            subject.COORDS[1]/'cache-v2-'/'output-base'/suffix,run/'output-base'/('sandbox/unknown/12/'+suffix)):
            with self.assertRaises(ValueError):subject.output_parent(value,run)
    def test_no_clock_renewal_or_missing_clock(self):
        for deadline in (0,True,time.monotonic_ns()-1):
            with self.assertRaises(ValueError):subject.tick(deadline)

class FixtureDirectory(subject.Directory):
    """Only model TEST_TMPDIR ancestry exemption; production nofollow stays strict.

    Bazel may place TEST_TMPDIR beneath sticky /tmp. Only that canonical ancestor
    may be writable here; every fixture directory/leaf remains exact owned.
    """
    allowed=None
    def __init__(self,path,mode=None):
        self.path,self.fd=subject.canonical(str(path)),-1
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        self.chain=[subject.identity(os.fstat(fd),True)[:4]]
        try:
            current=Path('/')
            for part in self.path.parts[1:]:
                current/=part
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                os.close(fd);fd=child;info=os.fstat(fd)
                sticky=(current==Path('/tmp') and stat.S_IMODE(info.st_mode)==0o1777 and info.st_uid==0
                    and self.allowed.is_relative_to(current) and self.path.is_relative_to(self.allowed))
                subject.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,os.getuid())
                    and (sticky or not stat.S_IMODE(info.st_mode)&0o022))
                self.chain.append(subject.identity(info,True)[:4])
            info=os.fstat(fd)
            subject.require(mode is None or (info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==mode))
            self.fd,self.fence=fd,subject.identity(info,True)
        except BaseException:os.close(fd);raise

class FileOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('TEST_TMPDIR'))
        self.base=Path(self.tmp.name);os.chmod(self.base,0o700)
        FixtureDirectory.allowed=self.base
        self.directory_patch=mock.patch.object(subject,'Directory',FixtureDirectory);self.directory_patch.start()
        self.deadline=time.monotonic_ns()+30*10**9
    def tearDown(self):
        for parent,dirs,files in os.walk(self.base):os.chmod(parent,0o700)
        self.directory_patch.stop();self.tmp.cleanup()
    def leaf(self):
        root=self.base/'component';root.mkdir(mode=0o700)
        raw=b'public-model-backend'
        (root/'codex').write_bytes(raw);os.chmod(root/'codex',0o555);os.chmod(root,0o555)
        return root,{'codex':{'sha256':subject.sha(raw),'bytes':len(raw),'mode':0o555}}

    def test_bazel_source_mode_roles_pin_bytes_and_keep_installed_modes_strict(self):
        root,rows=self.leaf()
        os.chmod(root,0o700)
        for name in ('native-source-receipt.json','qualification.json','component.json',
                'runtime/lib/codex/share/ca-bundle.crt','unrelated-metadata.json'):
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o555)
            # This is a tiny public mode fixture, not API/provider qualification.
            if path.parent!=root:os.chmod(path.parent,0o700)
            raw=b'public-non-executable-role'
            path.write_bytes(raw);os.chmod(path,0o444)
            rows[name]={'sha256':subject.sha(raw),'bytes':len(raw),'mode':0o444}
        for parent,dirs,files in os.walk(root):os.chmod(parent,0o555)
        normal=subject.Tree(root,rows,self.deadline,bazel_sealed_source=True);normal.close()
        for name in subject.BAZEL_READ_ONLY_ROLES:os.chmod(root/name,0o555)
        source=subject.Tree(root,rows,self.deadline,bazel_sealed_source=True)
        try:
            for name in subject.BAZEL_READ_ONLY_ROLES:
                self.assertEqual(source.files[name].fence[4],0o555)
                self.assertEqual(source.files[name].row['mode'],0o444)
            with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline)
            # Source seal acceptance is an initial predicate; later changes fail.
            os.chmod(root/'native-source-receipt.json',0o444)
            with self.assertRaises(ValueError):source.recheck()
        finally:source.close()
        os.chmod(root/'native-source-receipt.json',0o555)
        os.chmod(root/'unrelated-metadata.json',0o555)
        with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline,bazel_sealed_source=True)
        os.chmod(root/'unrelated-metadata.json',0o444)
        for mode in (0o400,0o554,0o644,0o755):
            os.chmod(root/'runtime/lib/codex/share/ca-bundle.crt',mode)
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                subject.Tree(root,rows,self.deadline,bazel_sealed_source=True)
        os.chmod(root/'runtime/lib/codex/share/ca-bundle.crt',0o555)
        altered=copy.deepcopy(rows);altered['qualification.json']['sha256']='f'*64
        with self.assertRaises(ValueError):subject.Tree(root,altered,self.deadline,bazel_sealed_source=True)
        os.chmod(root,0o700);(root/'extra-capsule').write_bytes(b'not-authorized');os.chmod(root,0o555)
        with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline,bazel_sealed_source=True)

    def test_qualified_api_and_component_seals_copy_to_strict_installed_rows(self):
        self.qualified_sources(subject.FULL_PROFILE)

    def test_qualified_reserved_component_sources_copy_to_strict_installed_rows(self):
        self.qualified_sources(subject.RESERVED_PROFILE)

    def qualified_sources(self,profile):
        # Real File/Tree/Qualified/materialize paths; only enormous fixed bytes
        # and inner API validation are synthetic. Actual outer joins stay real.
        bases=(self.base/'device-coordinator',self.base/'component-coordinator')
        raws=[];pins=[]
        for base in bases:
            epoch=base/EPOCH;epoch.mkdir(parents=True,mode=0o700)
            value=receipt(base)
            value['codex_owner_runtime_input']={'verified_after_cleanup':True}
            raws.append(value)
        raws[1]['profile']=profile;raws[1]['targets']=[subject.PRODUCER]
        limits=subject.RESERVED_LIMITS if profile==subject.RESERVED_PROFILE else subject.LIMITS
        raws[1]['limits']=dict(limits)
        raws[1]['observed_properties']=dict(limits,PrivateNetwork='yes',NoNewPrivileges='yes',
            ProtectControlGroups='yes',RestrictSUIDSGID='yes')
        if profile==subject.RESERVED_PROFILE:
            raws[1]['observed_properties']['CPUQuotaPerSecUSec']='1.900000s'
        raws[1]['codex_device_component']={'verified_after_cleanup':True,
            'original_entry_monotonic_ns':1,'original_deadline_monotonic_ns':1+1200*10**9,
            'input':{'action':'produce','scope':'provider-free-codex-device-component','manifest_sha256':'e'*64,
                'provider_request_performed':False,'native_execution_performed':False,'resident_effects_authorized':False,
                'continuity_qualified':False,'credential_contents_read':False},
            'output':{'action':'produce','action_epoch':EPOCH,'controller_graph_sha256':GRAPH,'manifest_sha256':'e'*64,
                'provider_request_performed':False,'resident_enrollment_completed':False,'continuity_qualified':False}}
        for base,value in zip(bases,raws):
            raw=subject.encoded(value);(base/EPOCH/'receipt.json').write_bytes(raw)
            os.chmod(base/EPOCH/'receipt.json',0o600)
            pins.append(selected(base)|{'sha256':subject.sha(raw),'bytes':len(raw)})
        backend=b'tiny-synthetic-backend';ca=b'tiny-synthetic-public-ca';report=b'{"public":"mode-fixture"}\n'
        tiny={'codex':{'sha256':subject.sha(backend),'bytes':len(backend),'mode':0o555},
            'runtime/lib/codex/share/ca-bundle.crt':{'sha256':subject.sha(ca),'bytes':len(ca),'mode':0o444}}
        with mock.patch.object(subject,'COORDS',bases),mock.patch.object(subject,'inventory',return_value=tiny),\
                mock.patch.object(subject,'inner') as validate_inner:
            api_root=subject.outer(raws[0],pins[0],subject.DEVICE)/subject.BACKEND
            api_root.mkdir(parents=True,mode=0o700)
            ca_path=api_root/'runtime/lib/codex/share/ca-bundle.crt'
            ca_path.parent.mkdir(parents=True,mode=0o700)
            for path,raw in ((api_root/'codex',backend),(ca_path,ca),(api_root/'native-source-receipt.json',report)):
                path.write_bytes(raw);os.chmod(path,0o555)
            for parent,dirs,files in os.walk(api_root):os.chmod(parent,0o555)
            produce={'action':'produce','qualification':pins[0],
                'runtime_directory':str(api_root),'device_receipt':{'sha256':subject.sha(report),'bytes':len(report)}}
            qualified=subject.Qualified(produce,self.deadline)
            package=installed=None
            try:
                self.assertEqual(qualified.report.fence[4],0o555)
                self.assertEqual(qualified.component['files']['native-source-receipt.json']['mode'],0o444)
                component_parent=subject.outer(raws[1],pins[1],subject.PRODUCER)/'component'
                component_parent.mkdir(parents=True,mode=0o700)
                component_root=component_parent/subject.BACKEND
                subject.materialize(component_root,qualified,self.deadline)
                # Reproduce Bazel's observed executable read-only output seal.
                for name in subject.BAZEL_READ_ONLY_ROLES:os.chmod(component_root/name,0o555)
                descriptor=(component_root/'component.json').read_bytes()
                install={'action':'install','producer':pins[1],
                    'component_directory':str(component_root),'component_sha256':subject.sha(descriptor)}
                package=subject.Qualified(install,self.deadline)
                self.assertEqual(package.descriptor.fence[4],0o555)
                self.assertEqual(package.descriptor.row['mode'],0o444)
                destination=self.base/'installed'
                rows=subject.materialize(destination,package,self.deadline)
                self.assertTrue(all(rows[name]['mode']==0o444 for name in subject.BAZEL_READ_ONLY_ROLES))
                installed=subject.Tree(destination,rows,self.deadline)
                installed.recheck()
                self.assertTrue(all(stat.S_IMODE(os.stat(destination/name).st_mode)==0o444
                    for name in subject.BAZEL_READ_ONLY_ROLES))
                os.chmod(destination/'component.json',0o555)
                with self.assertRaises(ValueError):subject.Tree(destination,rows,self.deadline)
                self.assertEqual(validate_inner.call_count,2)
            finally:subject.close_all((installed,package,qualified))

    def test_historical_three_target_device_receipt_is_not_singleton_qualification(self):
        base=subject.COORDS[0]
        value=receipt(base)|{'targets':[subject.DEVICE,'//:docs_check','//tools:runtime_source_receipt']}
        with self.assertRaises(ValueError):subject.outer(value,selected(base),subject.DEVICE)

    def test_actual_tree_bytes_named_custody_and_extra_capsule_refusal(self):
        root,rows=self.leaf();tree=subject.Tree(root,rows,self.deadline)
        try:
            tree.recheck()
            os.chmod(root,0o700);(root/'capsule').write_bytes(b'not-authorized');os.chmod(root,0o555)
            with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline)
        finally:tree.close()
    def test_actual_mutation_hardlink_symlink_and_mode_refusal(self):
        root,rows=self.leaf()
        for mode in (0o755,0o444):
            os.chmod(root/'codex',mode)
            with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline)
        os.chmod(root/'codex',0o555);os.chmod(root,0o700)
        os.link(root/'codex',self.base/'hardlink')
        with self.assertRaises(ValueError):subject.Tree(root,rows,self.deadline)
        os.unlink(self.base/'hardlink');os.unlink(root/'codex');os.symlink(self.base/'foreign',root/'codex');os.chmod(root,0o555)
        with self.assertRaises((ValueError,OSError)):subject.Tree(root,rows,self.deadline)
    def test_held_parent_replacement_refuses(self):
        root,rows=self.leaf();tree=subject.Tree(root,rows,self.deadline)
        try:
            os.rename(root,self.base/'old');root.mkdir(mode=0o555)
            with self.assertRaises(ValueError):tree.recheck()
        finally:tree.close()
    def test_unchanged_leaf_transplanted_through_replaced_ancestor_refuses(self):
        parent=self.base/'parent';parent.mkdir(mode=0o700)
        root=parent/'leaf';root.mkdir(mode=0o555)
        held=subject.Directory(root,0o555)
        try:
            os.rename(parent,self.base/'retired-parent');parent.mkdir(mode=0o700)
            # Permit the owned model directory's cross-parent transplant, then
            # restore its original sealed mode before checking custody.
            os.chmod(self.base/'retired-parent/leaf',0o700)
            os.rename(self.base/'retired-parent/leaf',root)
            os.chmod(root,0o555)
            self.assertEqual(subject.identity(os.stat(root),True),held.fence)
            with self.assertRaises(ValueError):held.recheck()
        finally:held.close()
    def test_shared_lease_blocks_install_and_lock_alias_replacement(self):
        parent=subject.Directory(self.base,0o700)
        shared=subject.Lease(parent,False)
        try:
            with self.assertRaises(BlockingIOError):subject.Lease(parent,True)
            os.rename(self.base/'.lock',self.base/'old-lock')
            (self.base/'.lock').write_bytes(b'');os.chmod(self.base/'.lock',0o600)
            with self.assertRaises(ValueError):shared.recheck()
        finally:shared.close();parent.close()
    def test_unrecorded_partial_or_existing_other_component_never_adopted(self):
        data=self.base/'data';state=self.base/'state';data.mkdir(mode=0o700);state.mkdir(mode=0o700)
        held_data=subject.Directory(data,0o700);held_state=subject.Directory(state,0o700)
        try:
            (data/'current.json').write_bytes(b'{}');os.chmod(data/'current.json',0o600)
            with self.assertRaises(ValueError):subject.installed(held_data,held_state,{},self.deadline)
            (data/'unowned').mkdir(mode=0o700)
            with self.assertRaises(ValueError):subject.Lease(held_data)
        finally:held_data.close();held_state.close()
    def test_materialize_refuses_existing_destination_without_write(self):
        root,rows=self.leaf()
        qualified=mock.Mock();qualified.component={'files':rows};qualified.value={'action':'produce'}
        before=(root/'codex').read_bytes()
        with self.assertRaises(FileExistsError):subject.materialize(root,qualified,self.deadline)
        self.assertEqual((root/'codex').read_bytes(),before)
    def test_owned_tree_removal_leaves_foreign_profile_and_root_parent(self):
        root,rows=self.leaf();tree=subject.Tree(root,rows,self.deadline)
        foreign=self.base/'native-login-profile';foreign.mkdir(mode=0o700)
        try:subject.remove_tree(tree)
        finally:tree.close()
        self.assertFalse(root.exists());self.assertTrue(foreign.is_dir())

    def test_actual_synthetic_install_idempotence_no_replace_and_remove(self):
        # Tiny public byte fixture replaces only the enormous known native map;
        # this proves file/record/lease lifecycle, not runtime/API qualification.
        base=self.base/'coordinator';epoch=base/EPOCH;epoch.mkdir(parents=True,mode=0o700)
        raw_producer=receipt(base);raw_producer['targets']=[subject.PRODUCER]
        raw_producer['profile']='codex-device-component'
        raw_producer['codex_device_component']={'verified_after_cleanup':True,
            'original_entry_monotonic_ns':1,'original_deadline_monotonic_ns':1+1200*10**9,
            'input':{'action':'produce','scope':'provider-free-codex-device-component','manifest_sha256':'e'*64,
                'provider_request_performed':False,'native_execution_performed':False,'resident_effects_authorized':False,
                'continuity_qualified':False,'credential_contents_read':False},
            'output':{'action':'produce','action_epoch':EPOCH,'controller_graph_sha256':GRAPH,'manifest_sha256':'e'*64,
                'provider_request_performed':False,'resident_enrollment_completed':False,'continuity_qualified':False}}
        producer_raw=subject.encoded(raw_producer)
        (epoch/'receipt.json').write_bytes(producer_raw);os.chmod(epoch/'receipt.json',0o600)
        producer_pin=selected(base)|{'sha256':subject.sha(producer_raw),'bytes':len(producer_raw)}
        root=epoch/'component';root.mkdir(mode=0o700)
        backend=b'synthetic-backend';report=b'{"synthetic":"provider-free-model"}\n'
        old=receipt(base);old['codex_owner_runtime_input']={'verified_after_cleanup':True}
        old_raw=subject.encoded(old)
        rows={'codex':{'sha256':subject.sha(backend),'bytes':len(backend),'mode':0o555},
            'native-source-receipt.json':{'sha256':subject.sha(report),'bytes':len(report),'mode':0o444},
            'qualification.json':{'sha256':subject.sha(old_raw),'bytes':len(old_raw),'mode':0o444}}
        for name,raw in (('codex',backend),('native-source-receipt.json',report),('qualification.json',old_raw)):
            (root/name).write_bytes(raw);os.chmod(root/name,rows[name]['mode'])
        component={'schema_version':1,'scope':subject.SCOPE,'purpose':'device-account-acquisition',
            'system':'x86_64-linux','backend_sha256':subject.BACKEND,'files':rows,
            'qualification':{'inner':{key:rows['native-source-receipt.json'][key] for key in ('sha256','bytes')},
                'outer':{'sha256':subject.sha(old_raw),'bytes':len(old_raw),'id':EPOCH,
                    'source_commit':SOURCE,'graph_sha256':GRAPH}},'version':'codex 0.0.0',
            'renewal_owner':'native','native_support':False,'text_continuity':False,'provider_evaluation':False}
        descriptor=subject.encoded(component);(root/'component.json').write_bytes(descriptor)
        os.chmod(root/'component.json',0o444);os.chmod(root,0o555)
        data_home=self.base/'share';state_home=self.base/'state'
        for home in (data_home,state_home):(home/'omux-acquisition/codex').mkdir(parents=True,mode=0o700)
        value={'schema_version':1,'scope':subject.INPUT,'action':'install','data_home':str(data_home),
            'state_home':str(state_home),'component_directory':str(root),'component_sha256':subject.sha(descriptor),
            'producer':producer_pin}
        qualified=subject.Qualified.__new__(subject.Qualified)
        qualified.value=value;qualified.deadline=self.deadline;qualified.component=component;qualified.report=None
        qualified.receipt=subject.File(epoch/'receipt.json',self.deadline,producer_pin,0o600)
        qualified.descriptor=subject.File(root/'component.json',self.deadline,mode=0o444)
        qualified.tree=subject.Tree(root,rows|{'component.json':qualified.descriptor.row},self.deadline)
        try:
            with mock.patch.object(subject,'COORDS',(base,)):
                subject.install(value,qualified,self.deadline)
                selected_path=data_home/'omux-acquisition/codex/current.json'
                before=selected_path.read_bytes()
                subject.install(value,qualified,self.deadline)
                self.assertEqual(selected_path.read_bytes(),before)
                with self.assertRaises(ValueError):subject.install(value|{'component_sha256':'f'*64},qualified,self.deadline)
                self.assertEqual(selected_path.read_bytes(),before)
                foreign=state_home/'omux-native-sources';foreign.mkdir(mode=0o700)
                subject.install(value|{'action':'remove'},qualified,self.deadline)
                self.assertEqual(set((data_home/'omux-acquisition/codex').iterdir()),{data_home/'omux-acquisition/codex/.lock'})
                self.assertEqual(list((state_home/'omux-acquisition/codex').iterdir()),[])
                self.assertTrue(foreign.is_dir())
        finally:qualified.close()

    def test_cleanup_fault_still_closes_every_remaining_input(self):
        first=mock.Mock();second=mock.Mock();first.close.side_effect=OSError('synthetic-close-fault')
        with self.assertRaises(OSError):subject.close_all((first,second))
        first.close.assert_called_once_with();second.close.assert_called_once_with()

    def test_self_consistent_other_purpose_and_over_budget_receipt_refuse(self):
        base=subject.COORDS[0]
        for change in ({'observed_properties':dict(subject.LIMITS,PrivateNetwork='no',NoNewPrivileges='yes',
                ProtectControlGroups='yes',RestrictSUIDSGID='yes')},
            {'limits':dict(subject.LIMITS,MemoryMax='8589934592')},
            {'observed_properties':dict(subject.LIMITS,RuntimeMaxUSec='20min 0.000001s',PrivateNetwork='yes',
                NoNewPrivileges='yes',ProtectControlGroups='yes',RestrictSUIDSGID='yes')},
            {'original_cgroup_identity':{'device':False,'inode':2}}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                subject.outer(receipt(base)|change,selected(base),subject.DEVICE)

if __name__=='__main__':unittest.main()
