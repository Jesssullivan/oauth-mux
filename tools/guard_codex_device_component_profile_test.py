"""Exact provider-free admission/command/budget models; no executable dispatch."""
from pathlib import Path
from types import SimpleNamespace
import time
import tempfile
import unittest
from unittest import mock
import execution_guard as execution
import guard_codex_device_component_profile as subject

def args(**changes):
    manifest=subject.MANIFEST_BASE/('1'*32)/'input.json'
    values={'profile':subject.PROFILE,'manager':'system','arguments':['test',subject.component.PRODUCER],
        'codex_component_manifest':manifest,'codex_component_manifest_sha256':'2'*64,
        'source_commit':'3'*40,'source_dirty':'false','reuse_owned_cache':False,
        'repository_cache':None,'nixpkgs_source':None}
    return SimpleNamespace(**(values|changes))

class ProfileTests(unittest.TestCase):
    def test_exact_two_provider_free_verbs_and_isolation(self):
        for arguments in (['test',subject.component.PRODUCER],['run',subject.component.INSTALLER]):
            selected=subject.select(args(arguments=arguments),arguments)
            self.assertEqual(selected.finite(arguments,'system',selected.manifest,False),{'PrivateNetwork':'yes'})
            self.assertEqual((selected.PROOF_MEMORY,selected.PROOF_TASKS,selected.PROOF_CPU_PERCENT),(4294967296,512,200))
    def test_wrong_labels_profile_verb_partial_pins_cache_and_other_authority_refuse_before_io(self):
        cases=({'arguments':['run',subject.component.PRODUCER]},
            {'arguments':['test',subject.component.INSTALLER]},
            {'arguments':['run','//delivery:native_account_login']},
            {'arguments':['run',subject.component.INSTALLER,'--','install']},
            {'profile':'standard'},{'manager':'user'},{'reuse_owned_cache':True},
            {'codex_component_manifest_sha256':None},{'codex_component_manifest_sha256':'wrong'},
            {'source_dirty':False},{'resident_manifest':Path('/private/input.json')},
            {'native_login_directory':Path('/private/native')},{'codex_fresh_runtime_selection':Path('/private/fresh')},
            {'codex_component_manifest':Path('/home/jess/.ssh/input.json')},
            {'repository_cache':subject.acquisition.REPOSITORY_CACHE},
            {'repository_cache':Path('/tmp/cache'),'nixpkgs_source':subject.acquisition.NIXPKGS})
        with mock.patch.object(subject.component,'File') as opening:
            for changes in cases:
                selected=args(**changes)
                with self.subTest(changes=changes),self.assertRaises(ValueError):subject.select(selected,selected.arguments)
            opening.assert_not_called()
    def test_inactive_default_and_cross_profile_selector_refusal(self):
        value=args(profile='standard',codex_component_manifest=None,codex_component_manifest_sha256=None)
        self.assertIsNone(subject.select(value,['test','//tools:execution_guard_test']))
        with self.assertRaises(ValueError):subject.select(args(profile='codex-login'),['run','//delivery:native_account_login'])
    def admission(self,action='produce',cache=None,profile=subject.PROFILE):
        selected=args(profile=profile,repository_cache=cache,nixpkgs_source=subject.acquisition.NIXPKGS if cache else None)
        result=subject.Admission.__new__(subject.Admission)
        result.settings=subject.Settings(selected.codex_component_manifest,profile)
        result.manifest=selected.codex_component_manifest;result.value={'action':action}
        result.repository_cache=cache;result.nixpkgs_source=selected.nixpkgs_source
        result.manifest_sha256=selected.codex_component_manifest_sha256
        result.environment=lambda:{subject.component.DEADLINE:'1200000000000',subject.component.NSID:'1:2',
            subject.component.VARIABLE:subject.component.DESTINATION,subject.component.EPOCH:'/public/owned-epoch'}
        return result
    def test_real_bazel_command_test_and_install_are_fixed_offline_original_environment(self):
        run=Path('/public/owned-epoch')
        for profile in subject.PROFILES:
            for action,verb,label in (('produce','test',subject.component.PRODUCER),('install','run',subject.component.INSTALLER)):
                with self.subTest(profile=profile,action=action):
                    value=self.admission(action,subject.acquisition.REPOSITORY_CACHE,profile)
                    actual=subject.command(execution.bazel_command,'/nix/store/model-bazel/bin/bazel',run,[verb,label],value,
                        source_commit='3'*40,source_dirty='false',repository_cache=value.repository_cache,nixpkgs_source=value.nixpkgs_source)
                    self.assertIn(verb,actual);self.assertEqual(actual[-1],label)
                    self.assertEqual([item for item in actual if item.startswith('//')],[label])
                    self.assertIn('--spawn_strategy=linux-sandbox',actual)
                    self.assertNotIn('--disable_download',actual)
                    self.assertEqual(actual.count('--repository_disable_download'),1)
                    self.assertEqual(actual.count('--repo_contents_cache='),1)
                    self.assertEqual([item for item in actual if item.startswith('--repo_contents_cache=')],['--repo_contents_cache='])
                    self.assertLess(actual.index('--repository_disable_download'),actual.index(label))
                    self.assertLess(actual.index('--repo_contents_cache='),actual.index(label))
                    self.assertEqual([item for item in actual if item.startswith('--repository_cache=')],
                        ['--repository_cache='+str(value.repository_cache)])
                    self.assertEqual([item for item in actual if item.startswith('--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE=')],
                        ['--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE='+str(value.nixpkgs_source)])
                    self.assertIn('--remote_executor=',actual);self.assertIn('--remote_cache=',actual)
                    self.assertIn('--jobs=2',actual);self.assertIn('--host_jvm_args=-Xmx1536m',actual)
                    prefix='--test_env=' if action=='produce' else '--run_env='
                    self.assertIn(prefix+subject.component.DEADLINE+'=1200000000000',actual)
                    self.assertNotIn('--sandbox_default_allow_network=true',actual)
                    self.assertNotIn('--norepository_disable_download',actual)
                    self.assertFalse(any('resident_enrollment' in item or 'native_account_login' in item for item in actual))
    def test_command_rejects_duck_admission_or_cross_action_no_rebuild(self):
        builder=mock.Mock()
        for value,arguments in ((SimpleNamespace(),['run',subject.component.INSTALLER]),
            (self.admission('produce'),['run',subject.component.INSTALLER]),
            (self.admission('install'),['test',subject.component.PRODUCER])):
            with self.assertRaises(ValueError):subject.command(builder,'bazel',Path('/public/run'),arguments,value)
        builder.assert_not_called()
    def test_original_clock_setup_consumed_and_cleanup_only_after_exact_success(self):
        value=subject.Admission.__new__(subject.Admission)
        value.original_deadline=1200*10**9;value.work_deadline=1170*10**9;value.collecting=False
        with mock.patch.object(subject.time,'monotonic_ns',return_value=900*10**9):self.assertEqual(value.runtime_seconds(),270)
        with mock.patch.object(subject.time,'monotonic_ns',return_value=1170*10**9):
            with self.assertRaises(ValueError):value.runtime_seconds()
        value.run=Path('/public/epoch');value.recheck=mock.Mock()
        for status,cleaned in ((125,True),(0,False),(False,True)):
            with self.assertRaises(ValueError):value.completed(status,cleaned,'epoch',None,'f'*64)
        self.assertFalse(value.collecting);value.recheck.assert_not_called()
    def test_exact_directory_readback_extra_recursive_duplicates_and_writable_refuse(self):
        expected='/public/input:/omux-codex-component /public/output:/public/output'
        actual='/public/input:/omux-codex-component:rbind /public/output:/public/output:rbind'
        self.assertEqual(subject.normalized(expected),subject.normalized(actual,True))
        for raw in (expected,actual+' '+actual.split()[0],actual.replace(':rbind',':norbind',1)):
            with self.assertRaises(ValueError):subject.normalized(raw,True)
        value=self.admission();value.run=Path('/public/run');value.repository_cache=None
        value.bindings=lambda:['/public/input:/omux-codex-component']
        value.writable_bindings=lambda run:['/public/run:/public/run']
        correct={'BindReadOnlyPaths':'/public/input:/omux-codex-component:rbind','BindPaths':'/public/run:/public/run:rbind'}
        value.verify_bindings(correct,value.run,None)
        for change in ({'BindPaths':correct['BindPaths']+' /home/jess:/home/jess:rbind'},
                {'BindReadOnlyPaths':correct['BindReadOnlyPaths']+' /run:/run:rbind'},
                {'BindPaths':correct['BindPaths'].replace(':rbind','')}):
            with self.assertRaises(ValueError):value.verify_bindings(correct|change,value.run,None)

    def test_reserved_selection_receipt_limits_and_fixed_offline_commands(self):
        import guard_resident_dispatch as dispatch
        for profile,bounds in ((subject.PROFILE,(4294967296,512,200)),
                (subject.RESERVED_PROFILE,(4026531840,480,190))):
            for action,verb,label in (('produce','test',subject.component.PRODUCER),
                    ('install','run',subject.component.INSTALLER)):
                arguments=[verb,label]
                selected=dispatch.select(args(profile=profile,arguments=arguments),arguments)
                self.assertIs(type(selected),subject.Settings)
                self.assertEqual(selected.PROFILE,profile)
                self.assertEqual((selected.PROOF_MEMORY,selected.PROOF_TASKS,selected.PROOF_CPU_PERCENT),bounds)
                limits=dispatch.proof_properties(execution.PROPERTIES,selected)
                self.assertEqual((limits['MemoryMax'],limits['TasksMax'],limits['CPUQuotaPerSecUSec']),
                    (str(bounds[0]),str(bounds[1]),'1.9s' if profile==subject.RESERVED_PROFILE else '2s'))
                self.assertEqual(limits['RuntimeMaxUSec'],'20min')
                value=self.admission(action,profile=profile)
                command=dispatch.command(execution.bazel_command,'/nix/store/model-bazel/bin/bazel',
                    Path('/public/owned-epoch'),arguments,value,source_commit='3'*40,source_dirty='false')
                self.assertEqual(command[-1],label)
                self.assertIn('--spawn_strategy=linux-sandbox',command)
                self.assertNotIn('--disable_download',command)
                self.assertEqual(command.count('--repository_disable_download'),1)
                self.assertNotIn('--repo_contents_cache=',command)
                self.assertNotIn('--norepository_disable_download',command)
                self.assertIn('--jobs=2',command)
        for change in ({'reuse_owned_cache':True},{'manager':'user'},
                {'resident_enrollment_manifest':Path('/private/input.json')},
                {'arguments':['test',subject.component.PRODUCER,'//tools:execution_guard_test']},
                {'codex_component_manifest_sha256':None}):
            selected=args(profile=subject.RESERVED_PROFILE,**change)
            with self.subTest(change=change),self.assertRaises(ValueError):
                subject.select(selected,selected.arguments)

    def test_actual_verify_correlates_component_profile_properties_kernel_caps_and_original_runtime(self):
        import guard_resident_dispatch as dispatch
        for profile in subject.PROFILES:
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                selected=subject.select(args(profile=profile),['test',subject.component.PRODUCER])
                expected=dispatch.proof_properties(execution.PROPERTIES,selected)
                for key,value in execution.CGROUP.items():
                    (root/key).write_text({'memory.max':expected['MemoryMax'],'pids.max':expected['TasksMax']}.get(key,value))
                reserved=profile==subject.RESERVED_PROFILE
                (root/'cpu.max').write_text('190000 100000' if reserved else '200000 100000')
                isolation={**execution.SANDBOX,'PrivateNetwork':'yes'}
                actual={**expected,**isolation,'RuntimeMaxUSec':'19min',
                    'TemporaryFileSystem':execution.system_masks(profile='standard'),
                    'UnsetEnvironment':' '.join(subject.acquisition.unset_environment(execution.DELEGATION_ENV))}
                execution.verify(actual,root,'system',isolation,profile,1150)
                other=subject.PROFILE if reserved else subject.RESERVED_PROFILE
                with self.assertRaises(ValueError):execution.verify(actual,root,'system',isolation,other,1150)
                for field,bad in (('MemoryMax','4294967296' if reserved else '4026531840'),
                        ('TasksMax','512' if reserved else '480'),
                        ('CPUQuotaPerSecUSec','2s' if reserved else '1.9s'),
                        ('RuntimeMaxUSec','20min'),('MemorySwapMax','1')):
                    with self.subTest(field=field),self.assertRaises(ValueError):
                        execution.verify(actual|{field:bad},root,'system',isolation,profile,1150)
                for name,bad in (('memory.max','4294967296' if reserved else '4026531840'),
                        ('pids.max','512' if reserved else '480'),
                        ('cpu.max','190001 100000' if reserved else '200001 100000')):
                    path=root/name;old=path.read_text();path.write_text(bad)
                    try:
                        with self.subTest(name=name),self.assertRaises(ValueError):
                            execution.verify(actual,root,'system',isolation,profile,1150)
                    finally:path.write_text(old)
                if reserved:
                    (root/'cpu.max').write_text('189999 100000')
                    with self.assertRaises(ValueError):
                        execution.verify(actual,root,'system',isolation,profile,1150)
                missing={**actual,'UnsetEnvironment':' '.join(key for key in actual['UnsetEnvironment'].split()
                    if key!='DBUS_SESSION_BUS_ADDRESS')}
                with self.assertRaises(ValueError):
                    execution.verify(missing,root,'system',isolation,profile,1150)


    def test_actual_selected_pids_observation_uses_reserved_kernel_limit(self):
        for profile,limit in ((subject.PROFILE,512),(subject.RESERVED_PROFILE,480)):
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                (root/'pids.current').write_text(str(limit-1))
                (root/'pids.max').write_text(str(limit))
                (root/'pids.events').write_text('max 0')
                selected=subject.select(args(profile=profile),['test',subject.component.PRODUCER])
                observation=execution.workload_pids_observation(selected,profile)
                pin=execution.CgroupPin(root)
                try:
                    observation.sample(pin,'baseline')
                    (root/'pids.current').write_text(str(limit))
                    observation.sample(pin,'monitor')
                    result=observation.receipt()
                    self.assertEqual(result['last_monitor']['pids_limit'],'verified'+str(limit))
                    self.assertEqual(result['last_monitor']['pids_sample'],'at')
                    self.assertTrue(result['observed_at_or_over_verified_limit'])
                    if profile==subject.RESERVED_PROFILE:
                        changed=execution.workload_pids_observation(selected,profile)
                        (root/'pids.max').write_text('512')
                        changed.sample(pin,'baseline')
                        self.assertEqual(changed.receipt()['baseline']['pids_limit'],'changed')
                        self.assertFalse(changed.receipt()['observed_at_or_over_verified_limit'])
                finally:pin.close()

    def test_immediate_receipt_copy_redaction_and_exception_no_reflection(self):
        settings=subject.Settings(Path('/private/input.json'))
        properties={'BindPaths':'/private/target:/private/target','BindReadOnlyPaths':'/private/input:/private/input'}
        projected=settings.projection(properties)
        self.assertNotIn('/private',str(projected));self.assertIn('/private',str(properties))
        class PrivateError(Exception):
            def __str__(self):raise AssertionError('exception reflection')
        self.assertEqual(settings.rejection(PrivateError()),'codex-device-component-refused')

if __name__=='__main__':unittest.main()
