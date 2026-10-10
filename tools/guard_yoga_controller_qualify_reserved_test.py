"""Reserved prerequisite and distinct unchanged standard receipt authority."""
from pathlib import Path
from contextlib import contextmanager
import hashlib
import os
import tempfile
import copy
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import execution_guard as guard
import guard_yoga_controller_qualify_reserved as route
import yoga_delivery_settings as readonly

class PrerequisiteModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=route.PROFILE,manager='system',source_commit='a'*40,
            source_dirty='false',state_dir=route.STATE,coordination_dir=route.COORDINATION)

    def test_exact_role_state_lock_and_clean_source(self):
        self.assertTrue(route.request(self.args(),route.ARGUMENTS))
        for vector in (['run','//tools:yoga_controller_verify'],['run','//tools:yoga_sealed_transfer_stage'],
            ['test','//tools:yoga_controller_qualify'],route.ARGUMENTS+['--','other']):
            with self.assertRaises(ValueError):route.selected(route.PROFILE,vector)
        for key,value in (('manager','user'),('state_dir',Path('/srv/other')),('state_dir',None),
            ('coordination_dir',Path('/srv/other')),('source_dirty','true'),('source_commit','unknown'),
            ('yoga_delivery_epoch','a'),('reuse_owned_cache',True)):
            args=self.args();setattr(args,key,value)
            with self.assertRaises(ValueError):route.request(args,route.ARGUMENTS)

    def test_real_state_preparation_reuses_only_fixed_delivery_coordination(self):
        with patch.object(guard,'private'),patch.object(guard,'check_free_space'):
            self.assertEqual(guard.prepare_state(route.STATE,route.STATE_PROFILE,route.COORDINATION,
                arguments=route.ARGUMENTS),route.COORDINATION)
            with self.assertRaises(ValueError):
                guard.prepare_state(route.STATE,'standard',route.COORDINATION,arguments=route.ARGUMENTS)

    def receipt(self):
        epoch='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';lock={'fixture':True}
        resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1','observations':2,
            'initial_direct_processes_retained':True,'outer_pid_namespace_matched':True,
            'hierarchical_caps':True,'resident_signalled':False,
            'kernel_bounds':{'memory.max':'268435456','memory.swap.max':'0','pids.max':'32','cpu.max':'10000 100000'}}
        count=sum(required for _,required in route.http_inputs.DECLARED)
        inputs={'scope':'fixed-yoga-controller-locked-http-snapshot-v1',
            'module_sha256':route.http_inputs.MODULE_SHA256,'lock_sha256':route.http_inputs.LOCK_SHA256,
            'declared_inputs':len(route.http_inputs.DECLARED),'copied_files':count,'copied_bytes':count,
            'missing_optional_inputs':len(route.http_inputs.DECLARED)-count,'snapshot_sha256':'e'*64,
            'verified_after_cleanup':True,'custody_released':True,'downloads_allowed':False,
            'complete_dependency_closure_proved':False}
        receipt={'id':epoch,'artifact_epoch':epoch,'source_commit':'a'*40,'source_dirty':'false',
            'exit':0,'workload_exit':0,'descendants_empty':True,'controller_failure':None,'rejection':None,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},'verb':'run',
            'targets':['//tools:yoga_controller_qualify'],'profile':route.PROFILE,'manager':'system',
            'coordination_directory':str(route.COORDINATION),'coordination_lock':str(route.COORDINATION/'execution.lock'),
            'graph_sha256':'b'*64,'limits':route.properties(guard.PROPERTIES),
            'closure_manifest_sha256':readonly.NATIVE,'bootstrap_manifest_sha256':readonly.executable.BOOTSTRAP_SHA,
            'yoga_controller_http_inputs':inputs,
            'reserved_failure':None,'yoga_controller_qualify_reservation':route.projection(1,1+1200*10**9,True,resident),
            'yoga_delivery':{'source_verified_after_cleanup':True,'controller_tools':readonly.TOOLS,'mode':'qualify',
                'coordination_lock_witness':lock,'remote_owned_containment_verified':False,'copy_performed':False,
                'remote_cleanup':'unknown','qualification':{'path':'qualification.json','sha256':'c'*64}}}
        return receipt,epoch,lock

    def test_real_prior_outer_cleanup_graph_caps_and_resident_predicates(self):
        receipt,epoch,lock=self.receipt()
        self.assertEqual(route.prior_receipt(receipt,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40),'c'*64)
        for mutation in (lambda r:r.update(exit=125),lambda r:r.update(workload_exit=3),
            lambda r:r.update(graph_sha256='d'*64),lambda r:r.update(source_commit='d'*40),
            lambda r:r.update(limits=guard.PROPERTIES),
            lambda r:r['cleanup'].update(readback_attempts=1),lambda r:r.update(source_dirty='true'),
            lambda r:r['yoga_controller_qualify_reservation'].update(verified_after_cleanup=False),
            lambda r:r['yoga_controller_qualify_reservation']['resident'].update(resident_signalled=True),
            lambda r:r['yoga_controller_qualify_reservation']['resident']['kernel_bounds'].update(**{'pids.max':'64'}),
            lambda r:r['yoga_delivery'].update(coordination_lock_witness={'other':True}),
            lambda r:r['yoga_controller_http_inputs'].update(verified_after_cleanup=False),
            lambda r:r['yoga_controller_http_inputs'].update(custody_released=False),
            lambda r:r['yoga_controller_http_inputs'].update(downloads_allowed=True),
            lambda r:r['yoga_controller_http_inputs'].update(module_sha256='0'*64),
            lambda r:r['yoga_controller_http_inputs'].update(snapshot_sha256='unknown'),
            lambda r:r['yoga_controller_http_inputs'].update(copied_files=True)):
            bad=copy.deepcopy(receipt);mutation(bad)
            with self.assertRaises(ValueError):route.prior_receipt(bad,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40)

    def test_standard_receipt_policy_is_distinct_and_unchanged(self):
        receipt,epoch,lock=self.receipt()
        historical=dict(receipt,profile=readonly.profile.PROFILE,limits=guard.PROPERTIES)
        self.assertEqual(readonly.prior_receipt(historical,epoch,'b'*64,guard.PROPERTIES,lock),'c'*64)
        with self.assertRaises(ValueError):route.prior_receipt(historical,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40)
        with self.assertRaises(ValueError):readonly.prior_receipt(receipt,epoch,'b'*64,guard.PROPERTIES,lock)

    def test_constructor_offline_flags_and_original_deadline(self):
        entry=time.monotonic_ns();deadline=entry+1200*10**9
        with patch.object(guard,'yoga_delivery_command',return_value=(['bazel','run',route.ARGUMENTS[1]],{})) as constructor:
            result=route.command(None,'bazel',Path('/fixed/run'),route.ARGUMENTS,route.PROFILE,entry,deadline,
                source_commit='a'*40,source_dirty='false',repository_cache=None,nixpkgs_source=None)
        self.assertEqual(result,['bazel','run','--repository_disable_download','--repo_contents_cache=',
            '--repository_cache=/fixed/run/yoga-controller-http-inputs',route.ARGUMENTS[1]])
        self.assertEqual(constructor.call_args.args[3],deadline)
        with self.assertRaises(ValueError):guard.bazel_command('/fixed/bazel',Path('/fixed/run'),route.ARGUMENTS)

    def test_exact_runtime_and_non_delivery_projection(self):
        route.verify_runtime('10s',10)
        for value in ('9s','11s','infinity'):
            with self.assertRaises(ValueError):route.verify_runtime(value,10)
        value=route.projection(1,1+1200*10**9,False,{'observations':1})
        self.assertFalse(value['verified_after_cleanup'])
        for key in ('copy_performed','installation_qualified','seat_qualified','toolbar_consent_proved','credential_acquisition'):
            self.assertIs(value[key],False)

    def test_real_shared_deadline_and_complete_qualified_delivery_interfaces(self):
        self.assertIs(route.CLEANUP_RESERVE_NS,readonly.CLEANUP_RESERVE_NS)
        self.assertEqual(route.CLEANUP_RESERVE_NS,15*10**9)
        for name in ('finite','tools','budget','lock_witness','finish'):
            self.assertIs(getattr(route,name),getattr(readonly,name))
        for name in ('MEMORY','TASKS','CPU','Witness','WorkloadWitness','monitor',
                'cleanup_retained','release_worker','properties','remaining'):
            self.assertIs(getattr(route,name),getattr(route.kernel,name))
        entry,deadline=100*10**9,1300*10**9
        # This is the actual shared calculation called by guard main. It has no
        # clock read or validation of its own; the existing admission owns those.
        with patch.object(guard.time,'monotonic',side_effect=AssertionError('clock-reset')):
            self.assertEqual(guard.delivery_monitor_deadline(deadline,route),1285)
            self.assertEqual(guard.delivery_monitor_deadline(deadline,readonly),1285)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=entry):
            self.assertEqual(route.kernel.envelope(entry,deadline),1270*10**9)
            self.assertEqual(route.runtime_seconds(deadline),1170)
            self.assertEqual(route.remaining(entry,deadline),1170)
            self.assertEqual(route.budget(deadline,30*10**9),1170)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=1270*10**9):
            with self.assertRaises(ValueError):route.runtime_seconds(deadline)
            with self.assertRaises(ValueError):route.remaining(entry,deadline)
            self.assertEqual(route.remaining(entry,deadline,cleanup=True),30)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=deadline):
            with self.assertRaises(ValueError):route.remaining(entry,deadline,cleanup=True)
            with self.assertRaises(ValueError):route.budget(deadline)
        # Retain the existing kernel's exact integer/original-envelope predicates.
        for changed_entry,changed_deadline in ((True,deadline),(entry,True),(entry,deadline+1),(0,1200*10**9)):
            with self.assertRaises(ValueError):route.kernel.envelope(changed_entry,changed_deadline)

    def test_real_qualification_constructor_and_readonly_dispatch_without_launch(self):
        entry,deadline=100*10**9,1300*10**9
        with patch.object(route.kernel.time,'monotonic_ns',return_value=entry), \
                patch.object(guard,'controller_run',side_effect=AssertionError('controller-launch')):
            route.finite(route.ARGUMENTS,'system',None,())
            route.tools(dict(readonly.TOOLS),readonly.NATIVE,readonly.executable.BOOTSTRAP_SHA)
            command=route.command(None,'/fixed/bazel',Path('/fixed/run'),route.ARGUMENTS,route.PROFILE,
                entry,deadline,source_commit='a'*40,source_dirty='false')
            self.assertEqual(command[command.index('run')+1:command.index('run')+3],
                ['--repository_disable_download','--repo_contents_cache='])
            self.assertEqual(command[-1],route.ARGUMENTS[1])
            self.assertEqual(command.count('--repository_cache=/fixed/run/yoga-controller-http-inputs'),1)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_DEADLINE_NS='+str(deadline),command)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_MODE=qualify',command)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256=',command)
            self.assertIn('--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=',command)
            self.assertIn('--output_base=/fixed/run/output-base',command)
            for value in ('--remote_executor=','--remote_cache=','--lockfile_mode=error'):
                self.assertIn(value,command)
            with self.assertRaises(ValueError):route.finite(route.ARGUMENTS,'system','a'*36,())
            with self.assertRaises(ValueError):route.tools(dict(readonly.TOOLS,bazel='/other'),
                readonly.NATIVE,readonly.executable.BOOTSTRAP_SHA)
            unproved=route.finish(Path('/unused'),route.ARGUMENTS,125,True,True,deadline,{'fixture':True})
            self.assertEqual(unproved['mode'],'qualify')
            self.assertIsNone(unproved['qualification'])
            self.assertIs(unproved['copy_performed'],False)

    def test_actual_guard_qualification_caps_and_exact_runtime_readback(self):
        import tempfile
        import guard_resident_observation as resident
        caps=route.properties(guard.PROPERTIES)
        caps.update(MemoryMax=str(route.MEMORY),TasksMax=str(route.TASKS),
            CPUQuotaPerSecUSec=str(route.CPU*10000)+'us')
        self.assertEqual(route.MEMORY+resident.RESIDENT_MEMORY,4*1024**3)
        self.assertEqual(route.TASKS+resident.RESIDENT_TASKS,512)
        self.assertEqual(route.CPU+resident.RESIDENT_CPU_PERCENT,200)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,value in guard.CGROUP.items():
                (root/name).write_text({'memory.max':str(route.MEMORY),'pids.max':str(route.TASKS)}.get(name,value))
            (root/'cpu.max').write_text(str(route.CPU*1000)+' 100000')
            actual={**caps,**route.selected(route.PROFILE,route.ARGUMENTS),**guard.SANDBOX,
                'PrivateNetwork':'no','RuntimeMaxUSec':'17s',
                'TemporaryFileSystem':guard.system_masks(profile='standard'),
                'UnsetEnvironment':' '.join(guard.DELEGATION_ENV)}
            isolation={**guard.SANDBOX,**route.selected(route.PROFILE,route.ARGUMENTS)}
            guard.verify(actual,root,'system',isolation,route.PROFILE,runtime_seconds=17)
            for key,value in (('MemoryMax','4294967296'),('TasksMax','512'),('CPUQuotaPerSecUSec','2s'),
                    ('RuntimeMaxUSec','16s'),('RuntimeMaxUSec','18s'),('RuntimeMaxUSec','infinity'),
                    ('PrivateNetwork','yes')):
                with self.subTest(property=key,value=value),self.assertRaises(ValueError):
                    guard.verify({**actual,key:value},root,'system',isolation,route.PROFILE,runtime_seconds=17)

    def readonly_args(self,profile,epoch='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'):
        args=self.args();args.profile=profile;args.yoga_delivery_epoch=epoch
        return args

    def test_readonly_roles_require_exact_target_epoch_and_no_caller_authority(self):
        for profile in route.READONLY_PROFILES:
            arguments=['run',route.ROLES[profile]]
            self.assertTrue(route.request(self.readonly_args(profile),arguments))
            route.finite(arguments,'system','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',())
            with patch.object(guard,'private'),patch.object(guard,'check_free_space'):
                self.assertEqual(guard.prepare_state(route.STATE,route.STATE_PROFILE,route.COORDINATION,
                    arguments=arguments),route.COORDINATION)
            for other in route.PROFILES:
                if other!=profile:
                    with self.assertRaises(ValueError):route.selected(profile,['run',route.ROLES[other]])
            for vector in (['build',arguments[1]],['run','//tools:yoga_sealed_transfer_stage'],
                    arguments+['--','unselected'],['run','//tools:yoga_controller_delivery']):
                with self.assertRaises(ValueError):route.selected(profile,vector)
            for epoch in (None,True,'unknown','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/../other'):
                with self.assertRaises(ValueError):route.request(self.readonly_args(profile,epoch),arguments)
            for key,value in (('manager','user'),('source_dirty','true'),('source_commit','unknown'),
                    ('yoga_qualification','/other'),('yoga_qualification_sha256','c'*64),
                    ('yoga_deadline_monotonic_ns',1200),('repository_cache','/other'),
                    ('nixpkgs_source','/other'),('reuse_owned_cache',True)):
                args=self.readonly_args(profile);setattr(args,key,value)
                with self.assertRaises(ValueError):route.request(args,arguments)
            with self.assertRaises(ValueError):route.finite(arguments,'system',None,())
            with self.assertRaises(ValueError):route.finite(arguments,'system',
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',('unrelated',))
        args=self.args();args.yoga_delivery_epoch='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        with self.assertRaises(ValueError):route.request(args,route.ARGUMENTS)

    def qualification(self):
        return {'schemaVersion':1,'scope':'yoga-authenticated-OS-executable-qualification-v1',
            'bootstrapManifestSha256':readonly.executable.BOOTSTRAP_SHA,'inventorySha256':readonly.INVENTORY,
            'sourceReceiptSha256':readonly.SOURCE_RECEIPT,'sshPath':readonly.executable.SSH,'sshSha256':'a'*64,
            'remote':dict(schemaVersion=1,hostAlias='yoga',system='x86_64-linux',bootstrapTrust=readonly.executable.TRUST,
                machineIdSha256='a'*64,bootIdSha256='b'*64,uid=1000,labSourceRevision='f'*40,
                labGenerationMarkerSha256='a'*64,labDeploymentIdSha256='b'*64,
                homeManagerGeneration='/nix/store/'+'c'*32+'-home-manager-generation',
                remoteNixPath='/nix/store/'+'d'*32+'-nix/bin/nix',remoteNixSha256='e'*64,remoteNixBytes=42)}

    @contextmanager
    def raw_prior_fixture(self):
        receipt,epoch,lock=self.receipt();entry,deadline=100*10**9,1300*10**9
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            state=Path(temporary);run=state/epoch;run.mkdir(mode=0o700)
            raw=readonly.canonical(self.qualification())
            receipt['yoga_delivery']['qualification']['sha256']=hashlib.sha256(raw).hexdigest()
            def write(record=receipt,content=raw):
                for name,value in (('receipt.json',readonly.canonical(record)),('qualification.json',content)):
                    target=run/name;target.write_bytes(value);target.chmod(0o600)
            write()
            # Only the fixed fixture root and clock are substituted. Production
            # trusted_directory/read_owned hold and recheck real complete ancestry.
            with patch.object(readonly.profile,'STATE',state),patch.object(route,'STATE',state), \
                    patch.object(route.kernel.time,'monotonic_ns',return_value=entry):
                yield receipt,epoch,lock,entry,deadline,run,write

    def test_real_raw_prior_to_both_offline_commands_and_no_launch(self):
        with self.raw_prior_fixture() as (receipt,epoch,lock,entry,deadline,run,write), \
                patch.object(guard,'controller_run',side_effect=AssertionError('controller-launch')):
            prior=route.select_prior(epoch,'b'*64,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
            route.recheck(prior,'b'*64,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
            self.assertEqual(prior['producer_receipt_sha256'],hashlib.sha256((run/'receipt.json').read_bytes()).hexdigest())
            self.assertEqual(prior['sha256'],hashlib.sha256((run/'qualification.json').read_bytes()).hexdigest())
            for profile in route.READONLY_PROFILES:
                arguments=['run',route.ROLES[profile]]
                command=route.command(None,'/fixed/bazel',Path('/fixed/new-run'),arguments,profile,
                    entry,deadline,prior=prior,source_commit='a'*40,source_dirty='false')
                self.assertEqual(command[-1],arguments[1])
                for option in ('--repository_disable_download','--repo_contents_cache=',
                        '--repository_cache=/fixed/new-run/yoga-controller-http-inputs',
                        '--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION='+prior['path'],
                        '--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256='+prior['sha256'],
                        '--run_env=OMUX_YOGA_DELIVERY_DEADLINE_NS='+str(deadline),
                        '--run_env=OMUX_YOGA_DELIVERY_MODE='+readonly.profile.MODES[arguments[1]],
                        '--output_base=/fixed/new-run/output-base','--remote_executor=','--remote_cache=',
                        '--lockfile_mode=error'):
                    self.assertEqual(command.count(option),1)
                with self.assertRaises(ValueError):guard.bazel_command('/fixed/bazel',Path('/fixed/new-run'),arguments)
                for bad in (None,{},dict(prior,path='/other/qualification.json'),dict(prior,sha256='unknown'),
                        dict(prior,producer_epoch='unknown'),dict(prior,producer_receipt_sha256='unknown'),
                        dict(prior,undeclared=True)):
                    with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',Path('/fixed/new-run'),
                        arguments,profile,entry,deadline,prior=bad)
                for kw in ({'repository_cache':'/mutable'},{'nixpkgs_source':'/unselected'}):
                    with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',Path('/fixed/new-run'),
                        arguments,profile,entry,deadline,prior=prior,**kw)
            with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',Path('/fixed/new-run'),
                route.ARGUMENTS,route.PROFILE,entry,deadline,prior=prior)
            with patch.object(route.kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
                for profile in route.READONLY_PROFILES:
                    with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',Path('/fixed/new-run'),
                        ['run',route.ROLES[profile]],profile,entry,deadline,prior=prior)

    def test_raw_reserved_prior_refuses_source_graph_caps_lock_bytes_and_role_drift(self):
        for mutation in ('source','graph','caps','lock','mode','profile','http-module','raw-bytes','failed-cleanup'):
            with self.subTest(mutation=mutation),self.raw_prior_fixture() as fixture:
                receipt,epoch,lock,entry,deadline,run,write=fixture
                prior=route.select_prior(epoch,'b'*64,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
                bad=copy.deepcopy(receipt)
                if mutation=='source':bad['source_commit']='d'*40
                elif mutation=='graph':bad['graph_sha256']='d'*64
                elif mutation=='caps':bad['limits']=guard.PROPERTIES
                elif mutation=='lock':bad['yoga_delivery']['coordination_lock_witness']={'other':True}
                elif mutation=='mode':bad['yoga_delivery']['mode']='inspect'
                elif mutation=='profile':bad['profile']=route.INSPECT_PROFILE
                elif mutation=='http-module':bad['yoga_controller_http_inputs']['module_sha256']='0'*64
                elif mutation=='failed-cleanup':bad['cleanup']['state']='unproved'
                if mutation=='raw-bytes':write(content=b'{}')
                else:write(record=bad)
                with self.assertRaises(ValueError):route.select_prior(epoch,'b'*64,guard.PROPERTIES,
                    deadline,lock,source_commit='a'*40)
                with self.assertRaises(ValueError):route.recheck(prior,'b'*64,guard.PROPERTIES,
                    deadline,lock,source_commit='a'*40)

    def test_raw_reserved_prior_refuses_inode_rebind_and_private_file_custody_drift(self):
        for mutation in ('rebound','permissions','symlink','hardlink'):
            with self.subTest(mutation=mutation),self.raw_prior_fixture() as fixture:
                receipt,epoch,lock,entry,deadline,run,write=fixture
                prior=route.select_prior(epoch,'b'*64,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
                target=run/'qualification.json'
                if mutation=='rebound':
                    target.rename(run/'retained-old');write()
                elif mutation=='permissions':target.chmod(0o644)
                elif mutation=='symlink':
                    target.rename(run/'retained-old');target.symlink_to('retained-old')
                else:os.link(target,run/'unselected-hardlink')
                with self.assertRaises((ValueError,OSError)):route.recheck(prior,'b'*64,guard.PROPERTIES,
                    deadline,lock,source_commit='a'*40)

    def test_actual_guard_readonly_caps_runtime_and_distinct_terminal_projection(self):
        caps=route.properties(guard.PROPERTIES)
        caps.update(MemoryMax=str(route.MEMORY),TasksMax=str(route.TASKS),
            CPUQuotaPerSecUSec=str(route.CPU*10000)+'us')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,value in guard.CGROUP.items():
                (root/name).write_text({'memory.max':str(route.MEMORY),'pids.max':str(route.TASKS)}.get(name,value))
            (root/'cpu.max').write_text(str(route.CPU*1000)+' 100000')
            for profile in route.READONLY_PROFILES:
                isolation={**guard.SANDBOX,**route.selected(profile,['run',route.ROLES[profile]])}
                actual={**caps,**isolation,'RuntimeMaxUSec':'17s',
                    'TemporaryFileSystem':guard.system_masks(profile='standard'),
                    'UnsetEnvironment':' '.join(guard.DELEGATION_ENV)}
                guard.verify(actual,root,'system',isolation,profile,runtime_seconds=17)
                self.assertEqual(guard.workload_pids_observation(None,profile).expected_limit,480)
                for key,value in (('MemoryMax','4294967296'),('TasksMax','512'),('CPUQuotaPerSecUSec','2s'),
                        ('RuntimeMaxUSec','16s'),('RuntimeMaxUSec','18s'),('PrivateNetwork','yes')):
                    with self.assertRaises(ValueError):guard.verify({**actual,key:value},root,'system',
                        isolation,profile,runtime_seconds=17)
                terminal=route.readonly_projection(profile,1,1+1200*10**9,True,{'observations':1})
                self.assertEqual(terminal['mode'],readonly.profile.MODES[route.ROLES[profile]])
                self.assertEqual(terminal['scope'],'fixed-yoga-controller-readonly-reservation-v1')
                for key in ('copy_performed','installation_qualified','seat_qualified','toolbar_consent_proved','credential_acquisition'):
                    self.assertIs(terminal[key],False)
                record=route.finish(root,['run',route.ROLES[profile]],0,True,True,1300*10**9,{'fixture':True})
                self.assertIsNone(record['qualification'])
        with self.assertRaises(ValueError):route.readonly_projection(route.PROFILE,1,1+1200*10**9,True,{})

    @contextmanager
    def readonly_go_fixture(self):
        import fcntl
        with self.raw_prior_fixture() as (receipt,epoch,_,entry,deadline,producer,write):
            state=producer.parent;coordination=state/'coordination';coordination.mkdir(mode=0o700)
            source=state/'source';source.mkdir(mode=0o700);(source/'tools').mkdir(mode=0o700)
            (source/'BUILD.bazel').write_text('# fixture declared graph')
            (source/'tools'/'fixture.py').write_text('# fixture controller source')
            run=state/'fresh-run';run.mkdir(mode=0o700)
            graph=guard.graph_digest(source)[0]
            descriptor=os.open(coordination/'execution.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(readonly.profile,'COORDINATION',coordination), \
                        patch.object(route,'COORDINATION',coordination):
                    lock=route.lock_witness(descriptor,deadline)
                    receipt.update(coordination_directory=str(coordination),
                        coordination_lock=str(coordination/'execution.lock'),graph_sha256=graph)
                    receipt['yoga_delivery']['coordination_lock_witness']=lock;write()
                    prior=route.select_prior(epoch,graph,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
                    yield source,run,descriptor,prior,graph,lock,entry,deadline,receipt,write
            finally:os.close(descriptor)

    def test_actual_final_readonly_go_reopens_prior_graph_and_original_lock_before_publish(self):
        for profile in route.READONLY_PROFILES:
            with self.subTest(profile=profile),self.readonly_go_fixture() as fixture:
                source,run,descriptor,prior,graph,lock,entry,deadline,receipt,write=fixture
                events=[];actual_graph=guard.graph_digest;actual_lock=route.lock_witness;actual_prior=route.recheck
                def observe(name,operation,*args,**kwargs):
                    self.assertFalse((run/'go').exists());events.append(name)
                    return operation(*args,**kwargs)
                with patch.object(guard,'graph_digest',side_effect=lambda *a,**k:observe('graph',actual_graph,*a,**k)), \
                        patch.object(route,'lock_witness',side_effect=lambda *a,**k:observe('lock',actual_lock,*a,**k)), \
                        patch.object(route,'recheck',side_effect=lambda *a,**k:observe('prior',actual_prior,*a,**k)), \
                        patch.object(guard,'controller_run',side_effect=AssertionError('controller-launch')):
                    guard.yoga_controller_readonly_go(route,profile,run,source,'a'*40,prior,
                        graph,lock,descriptor,entry,deadline)
                self.assertEqual(events,['graph','lock','prior'])
                self.assertEqual((run/'go').stat().st_mode&0o777,0o600)
                with self.assertRaises(FileExistsError):guard.yoga_controller_readonly_go(route,profile,
                    run,source,'a'*40,prior,graph,lock,descriptor,entry,deadline)

    def test_actual_final_readonly_go_refuses_post_readiness_drift_without_publishing(self):
        mutations=('graph','lock-rebound','lock-mode','receipt-source','receipt-rebound',
            'qualification-bytes','source-argument','deadline-reset','expired-work','wrong-role')
        for profile in route.READONLY_PROFILES:
            for mutation in mutations:
                with self.subTest(profile=profile,mutation=mutation),self.readonly_go_fixture() as fixture:
                    source,run,descriptor,prior,graph,lock,entry,deadline,receipt,write=fixture
                    selected_source='a'*40;selected_deadline=deadline;selected_profile=profile
                    if mutation=='graph':(source/'tools'/'fixture.py').write_text('# changed after readiness')
                    elif mutation=='lock-rebound':
                        path=Path(readonly.profile.COORDINATION)/'execution.lock';path.rename(path.with_name('old-lock'))
                        path.write_bytes(b'');path.chmod(0o600)
                    elif mutation=='lock-mode':(Path(readonly.profile.COORDINATION)/'execution.lock').chmod(0o644)
                    elif mutation=='receipt-source':receipt['source_commit']='d'*40;write()
                    elif mutation=='receipt-rebound':
                        producer=Path(prior['path']).parent
                        (producer/'receipt.json').rename(producer/'old-receipt');write()
                    elif mutation=='qualification-bytes':write(content=b'{}')
                    elif mutation=='source-argument':selected_source='d'*40
                    elif mutation=='deadline-reset':selected_deadline+=1
                    elif mutation=='wrong-role':selected_profile=route.PROFILE
                    observed=deadline-30*10**9 if mutation=='expired-work' else entry
                    with patch.object(route.kernel.time,'monotonic_ns',return_value=observed), \
                            self.assertRaises(ValueError):
                        guard.yoga_controller_readonly_go(route,selected_profile,run,source,selected_source,prior,
                            graph,lock,descriptor,entry,selected_deadline)
                    self.assertFalse((run/'go').exists())

    @contextmanager
    def http_fixture(self):
        http=route.http_inputs
        entry,deadline=100*10**9,1300*10**9
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            root=Path(temporary)
            source=root/'source';source.mkdir(mode=0o700)
            module,lock=b'locked-module',b'locked-module-lock'
            (source/'MODULE.bazel').write_bytes(module);(source/'MODULE.bazel.lock').write_bytes(lock)
            cache=root/'cache';payloads=cache/'content_addressable'/'sha256';payloads.mkdir(parents=True)
            rows=[]
            for payload,required,present in ((b'registry',True,True),(b'archive',False,True),(b'absent',False,False)):
                sha=hashlib.sha256(payload).hexdigest();rows.append((sha,required))
                if present:
                    parent=payloads/sha;parent.mkdir();(parent/'file').write_bytes(payload)
            run=root/'epoch';run.mkdir(mode=0o700)
            with patch.object(http,'SOURCE_ROOT',source),patch.object(http,'CACHE',cache), \
                    patch.object(http,'MODULE_SHA256',hashlib.sha256(module).hexdigest()), \
                    patch.object(http,'LOCK_SHA256',hashlib.sha256(lock).hexdigest()), \
                    patch.object(http,'DECLARED',tuple(rows)), \
                    patch.object(http,'CANONICAL_IDS',((rows[1][0],'https://fixture.example/first https://fixture.example/second'),)), \
                    patch.object(http.kernel.time,'monotonic_ns',return_value=entry):
                yield http,root,run,source,payloads,rows,entry,deadline

    def test_http_snapshot_copies_only_pinned_bytes_and_actual_derived_command(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            unrelated=payloads/('f'*64);unrelated.mkdir();(unrelated/'file').write_bytes(b'undeclared')
            snapshot=http.Snapshot(run,entry,deadline)
            try:
                self.assertEqual(snapshot.facts()['copied_files'],2)
                self.assertEqual(snapshot.facts()['missing_optional_inputs'],1)
                self.assertFalse(snapshot.facts()['complete_dependency_closure_proved'])
                for sha,_,descriptor,before in snapshot.rows:
                    self.assertEqual(http.digest_file(descriptor,snapshot.budget,http.MAX_FILE)[0],sha)
                    self.assertEqual(before[2]&0o777,0o444)
                command=route.command(None,'/fixed/bazel',run,route.ARGUMENTS,route.PROFILE,entry,deadline,
                    source_commit='a'*40,source_dirty='false')
                self.assertEqual(command.count('--repository_cache='+str(snapshot.path)),1)
                self.assertIn('--repository_disable_download',command)
                self.assertIn('--repo_contents_cache=',command)
                self.assertNotIn(str(http.CACHE),command)
                snapshot.verify_binding({'BindReadOnlyPaths':snapshot.binding(),'BindPaths':''})
                for bad in ({'BindReadOnlyPaths':str(http.CACHE),'BindPaths':''},
                    {'BindReadOnlyPaths':snapshot.binding(),'BindPaths':'/other'},
                    {'BindReadOnlyPaths':snapshot.binding()+' /other','BindPaths':''}):
                    with self.assertRaises(ValueError):snapshot.verify_binding(bad)
                with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',run,route.ARGUMENTS,
                    route.PROFILE,entry,deadline,repository_cache=http.CACHE)
                snapshot.recheck(content=True,cleanup=True)
                self.assertTrue(snapshot.facts()['verified_after_cleanup'])
                self.assertFalse(snapshot.facts()['downloads_allowed'])
            finally:snapshot.close()
            self.assertTrue(snapshot.facts()['custody_released'])

    def test_held_http_snapshot_is_the_actual_readonly_command_cache(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline), \
                self.raw_prior_fixture() as (receipt,epoch,lock,_,_,prior_run,write):
            snapshot=http.Snapshot(run,entry,deadline)
            try:
                prior=route.select_prior(epoch,'b'*64,guard.PROPERTIES,deadline,lock,source_commit='a'*40)
                for profile in route.READONLY_PROFILES:
                    command=route.command(None,'/fixed/bazel',run,['run',route.ROLES[profile]],profile,
                        entry,deadline,prior=prior,source_commit='a'*40,source_dirty='false')
                    self.assertEqual(command.count('--repository_cache='+str(snapshot.path)),1)
                    self.assertIn('--repository_disable_download',command)
                    snapshot.verify_binding({'BindReadOnlyPaths':snapshot.binding(),'BindPaths':''})
                snapshot.recheck(content=True,cleanup=True)
            finally:snapshot.close()
            self.assertTrue(snapshot.facts()['custody_released'])

    def test_http_snapshot_missing_mismatched_linked_or_rebound_source_refuses(self):
        import os
        for mutation in ('required-missing','changed-payload','symlink-payload','hardlink-payload','source-lock'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                target=payloads/rows[0][0]/'file'
                if mutation=='required-missing':
                    target.unlink();target.parent.rmdir()
                elif mutation=='changed-payload':target.write_bytes(b'changed')
                elif mutation=='symlink-payload':
                    target.unlink();target.symlink_to(source/'MODULE.bazel')
                elif mutation=='hardlink-payload':os.link(target,root/'extra-link')
                else:(source/'MODULE.bazel.lock').write_bytes(b'other-lock')
                with self.assertRaises((ValueError,OSError)):http.Snapshot(run,entry,deadline)

    def test_http_snapshot_rechecks_actual_namespace_without_trusting_mode_only(self):
        for mutation in ('byte-change','extra-member','rebound-directory'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                snapshot=http.Snapshot(run,entry,deadline)
                try:
                    hashes=snapshot.path/'content_addressable'/'sha256';target=hashes/rows[0][0]/'file'
                    if mutation=='byte-change':
                        target.chmod(0o644);target.write_bytes(b'changed');target.chmod(0o444)
                    elif mutation=='extra-member':
                        hashes.chmod(0o755);(hashes/'undeclared').write_bytes(b'x');hashes.chmod(0o555)
                    else:
                        hashes.chmod(0o755)
                        parent=target.parent;parent.rename(hashes/'retained-old')
                        parent.mkdir(mode=0o755);(parent/'file').write_bytes(b'registry')
                        (parent/'file').chmod(0o444);parent.chmod(0o555);hashes.chmod(0o555)
                    with self.assertRaises(ValueError):snapshot.recheck(content=True)
                finally:snapshot.close()

    def test_http_snapshot_preserves_original_work_and_cleanup_deadlines(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            snapshot=http.Snapshot(run,entry,deadline)
            try:
                with patch.object(http.kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
                    with self.assertRaises(ValueError):snapshot.recheck()
                    snapshot.recheck(content=True,cleanup=True)
                with patch.object(http.kernel.time,'monotonic_ns',return_value=deadline):
                    with self.assertRaises(ValueError):snapshot.recheck(content=True,cleanup=True)
            finally:snapshot.close()

    def test_real_canonical_id_marker_binds_exact_url_order_and_pinned_payload(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            sha=rows[0][0]
            first='https://fixture.example/first https://fixture.example/second'
            second='https://fixture.example/second https://fixture.example/first'
            source_marker=payloads/sha/http.canonical_marker(first)
            self.assertFalse(source_marker.exists())  # Legacy CAS file alone is not a canonical-ID hit.
            snapshots=[]
            try:
                for index,canonical in enumerate((first,second)):
                    epoch=root/('canonical-epoch-'+str(index));epoch.mkdir(mode=0o700)
                    with patch.object(http,'CANONICAL_IDS',((sha,canonical),)):
                        snapshot=http.Snapshot(epoch,entry,deadline);snapshots.append(snapshot)
                    marker=snapshot.path/'content_addressable'/'sha256'/sha/http.canonical_marker(canonical)
                    self.assertTrue(marker.is_file());self.assertEqual(marker.read_bytes(),b'')
                    self.assertEqual(marker.stat().st_mode&0o777,0o444)
                    self.assertEqual(marker.stat().st_nlink,1)
                    expected='id-'+hashlib.sha256(canonical.encode('utf-8')).hexdigest()
                    self.assertEqual(marker.name,expected)
                    self.assertFalse(marker.with_name(http.canonical_marker(second if index==0 else first)).exists())
                    snapshot.recheck(content=True,cleanup=True)
                    self.assertEqual(http.digest_file(snapshot.rows[0][2],snapshot.budget,http.MAX_FILE)[0],sha)
                self.assertNotEqual(snapshots[0].facts()['snapshot_sha256'],snapshots[1].facts()['snapshot_sha256'])
                self.assertEqual(snapshots[0].facts()['copied_bytes'],snapshots[1].facts()['copied_bytes'])
                self.assertFalse(snapshots[0].facts()['complete_dependency_closure_proved'])
            finally:
                for snapshot in snapshots:snapshot.close()
            self.assertTrue(all(snapshot.facts()['custody_released'] for snapshot in snapshots))

    def test_real_canonical_id_marker_custody_refuses_missing_extra_or_changed_leaves(self):
        for mutation in ('missing','extra','nonempty','symlink','hardlink','rebound'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                snapshot=http.Snapshot(run,entry,deadline)
                try:
                    sha,_,name,_,_=snapshot.marker_rows[0]
                    parent=snapshot.path/'content_addressable'/'sha256'/sha
                    target=parent/name;parent.chmod(0o755)
                    if mutation=='missing':target.unlink()
                    elif mutation=='extra':target.with_name('id-'+'0'*64).write_bytes(b'')
                    elif mutation=='nonempty':
                        target.chmod(0o644);target.write_bytes(b'x');target.chmod(0o444)
                    elif mutation=='symlink':
                        target.unlink();target.symlink_to(parent/'file')
                    elif mutation=='hardlink':os.link(target,root/'extra-marker-link')
                    else:
                        target.rename(root/'retained-marker');target.write_bytes(b'');target.chmod(0o444)
                    parent.chmod(0o555)
                    with self.assertRaises((ValueError,OSError)):snapshot.recheck(content=True,cleanup=True)
                finally:snapshot.close()

if __name__=='__main__':unittest.main()
