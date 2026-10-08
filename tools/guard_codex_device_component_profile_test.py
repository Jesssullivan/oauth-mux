"""Exact provider-free admission/command/budget models; no executable dispatch."""
from pathlib import Path
from types import SimpleNamespace
import time
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
    def admission(self,action='produce',cache=None):
        selected=args(repository_cache=cache,nixpkgs_source=subject.acquisition.NIXPKGS if cache else None)
        result=subject.Admission.__new__(subject.Admission)
        result.settings=subject.Settings(selected.codex_component_manifest)
        result.manifest=selected.codex_component_manifest;result.value={'action':action}
        result.repository_cache=cache;result.nixpkgs_source=selected.nixpkgs_source
        result.manifest_sha256=selected.codex_component_manifest_sha256
        result.environment=lambda:{subject.component.DEADLINE:'1200000000000',subject.component.NSID:'1:2',
            subject.component.VARIABLE:subject.component.DESTINATION,subject.component.EPOCH:'/public/owned-epoch'}
        return result
    def test_real_bazel_command_test_and_install_are_fixed_offline_original_environment(self):
        run=Path('/public/owned-epoch')
        for action,verb,label in (('produce','test',subject.component.PRODUCER),('install','run',subject.component.INSTALLER)):
            value=self.admission(action,subject.acquisition.REPOSITORY_CACHE)
            actual=subject.command(execution.bazel_command,'/nix/store/model-bazel/bin/bazel',run,[verb,label],value,
                source_commit='3'*40,source_dirty='false',repository_cache=value.repository_cache,nixpkgs_source=value.nixpkgs_source)
            self.assertIn(verb,actual);self.assertEqual(actual[-1],label)
            self.assertIn('--spawn_strategy=linux-sandbox',actual)
            self.assertIn('--repository_disable_download',actual);self.assertIn('--disable_download',actual)
            self.assertIn('--repo_contents_cache=',actual)
            self.assertIn('--repository_cache='+str(value.repository_cache),actual)
            self.assertIn('--remote_executor=',actual);self.assertIn('--remote_cache=',actual)
            self.assertIn('--jobs=2',actual);self.assertIn('--host_jvm_args=-Xmx1536m',actual)
            prefix='--test_env=' if action=='produce' else '--run_env='
            self.assertIn(prefix+subject.component.DEADLINE+'=1200000000000',actual)
            self.assertNotIn('--sandbox_default_allow_network=true',actual)
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
    def test_immediate_receipt_copy_redaction_and_exception_no_reflection(self):
        settings=subject.Settings(Path('/private/input.json'))
        properties={'BindPaths':'/private/target:/private/target','BindReadOnlyPaths':'/private/input:/private/input'}
        projected=settings.projection(properties)
        self.assertNotIn('/private',str(projected));self.assertIn('/private',str(properties))
        class PrivateError(Exception):
            def __str__(self):raise AssertionError('exception reflection')
        self.assertEqual(settings.rejection(PrivateError()),'codex-device-component-refused')

if __name__=='__main__':unittest.main()
