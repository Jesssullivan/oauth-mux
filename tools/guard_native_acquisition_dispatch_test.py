"""Provider-free current-controller acquisition admission models; no native/UI IO."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock
import guard_native_acquisition_dispatch as acquisition
import guard_codex_login_profile as login
import guard_native_login_ui_profile as ui
import guard_resident_dispatch as resident
import execution_guard as guard

def arguments(profile='codex-login'):
    value = argparse.Namespace(profile=profile,manager='system',source_commit='a'*40,
        source_dirty='false',repository_cache=None,nixpkgs_source=None,reuse_owned_cache=False)
    for field in acquisition.FIELDS:
        setattr(value,field,None)
    fields = acquisition.LOGIN_FIELDS if profile == 'codex-login' else acquisition.UI_FIELDS
    for field in fields:
        setattr(value,field,'b'*64 if field.endswith('sha256') else Path('/private/operator/'+field))
    return value

def admitted(profile='codex-login'):
    value = acquisition.Admission.__new__(acquisition.Admission)
    selected = login if profile == 'codex-login' else ui
    value.settings = acquisition.Settings(profile,selected,Path('/private/input.json'))
    value.manifest = value.settings.manifest
    value.manifest_sha256 = 'b'*64
    value.original_deadline = 1200*10**9
    value.work_deadline = value.original_deadline-acquisition.RESERVE_NS
    value.collecting = False
    value.run = Path('/private/epoch')
    value.home = Path('/home/model')
    value.repository_cache = value.nixpkgs_source = None
    value.inner = mock.Mock(directory=Path('/private/'+'a'*64),parent=Path('/private/fresh'),
        value={'enrollment':{'model':'synthetic-template'}},namespace_fd=21,output_fd=22)
    value.facts = {'scope':'synthetic-model'}
    return value

class AcquisitionModels(unittest.TestCase):
    def test_exact_two_labels_and_complete_independent_selection(self):
        for profile,selected in (('codex-login',login),('native-login-ui',ui)):
            args = arguments(profile)
            settings = acquisition.select(args,['run',selected.LABEL])
            self.assertIs(type(settings),acquisition.Settings)
            self.assertEqual(settings.finite(['run',selected.LABEL],'system',settings.manifest,False),
                {'PrivateNetwork':'no'})
            for field in acquisition.LOGIN_FIELDS if profile == 'codex-login' else acquisition.UI_FIELDS:
                changed = copy.copy(args); setattr(changed,field,None)
                with self.subTest(field=field),self.assertRaises(ValueError):
                    acquisition.select(changed,['run',selected.LABEL])
            for command in (['test',selected.LABEL],['run',selected.LABEL,'--'],
                    ['run','//...'],['run',selected.LABEL,selected.LABEL],
                    ['run',ui.LABEL if profile=='codex-login' else login.LABEL]):
                with self.subTest(command=command),self.assertRaises(ValueError):
                    acquisition.select(args,command)

    def test_wrong_profile_old_flags_bad_pins_user_manager_dirty_and_cache_refuse(self):
        args = arguments()
        for field,value in (('manager','user'),('reuse_owned_cache',True),
                ('source_dirty',False),('source_dirty','true'),('native_mode','cli-opt'),
                ('codex_fresh_runtime_selection','/private/fresh-runtime-selection.json'),
                ('resident_enrollment_manifest',Path('/private/resident/input.json')),
                ('ui_prepare_manifest',Path('/private/ui/input.json')),
                ('native_login_sha256',True),('native_login_sha256','X'*64)):
            changed = copy.copy(args); setattr(changed,field,value)
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                acquisition.select(changed,['run',login.LABEL])
        for profile in ('standard','codex-native','codex-live','resident-enrollment','yoga-toolbar'):
            changed = copy.copy(args); changed.profile = profile
            with self.subTest(profile=profile),self.assertRaises(ValueError):
                acquisition.select(changed,['run',login.LABEL])
        with self.assertRaises(ValueError):
            acquisition.repositories(acquisition.REPOSITORY_CACHE,None)

    def test_acquisition_does_not_invoke_resident_admission(self):
        args = arguments()
        settings = acquisition.select(args,['run',login.LABEL])
        with mock.patch.object(acquisition,'admit',return_value='only-acquisition') as acquire:
            self.assertEqual(resident.admit(settings,args,Path('/public/source'),
                '/nix/store/systemctl',1200*10**9),'only-acquisition')
        acquire.assert_called_once_with(settings,args,Path('/public/source'),1200*10**9)
        self.assertEqual(resident.proof_properties(guard.PROPERTIES,settings),guard.PROPERTIES)
        self.assertEqual(resident.proof_properties(guard.PROPERTIES)['TasksMax'],'480')

    def test_actual_standard_builder_keeps_offline_cache_and_explicit_repo_selection(self):
        value = admitted()
        value.environment = lambda: {login.VARIABLE:login.DESTINATION}
        value.repository_cache,value.nixpkgs_source = acquisition.REPOSITORY_CACHE,acquisition.NIXPKGS
        command = acquisition.command(guard.bazel_command,'/nix/store/bazel',value.run,
            ['run',login.LABEL],value,source_commit='a'*40,source_dirty='false',
            repository_cache=value.repository_cache,nixpkgs_source=value.nixpkgs_source)
        for flag in ('--batch','--jobs=2','--host_jvm_args=-Xmx1536m','--disable_download',
                '--repository_disable_download','--repo_contents_cache=',
                '--repository_cache='+str(acquisition.REPOSITORY_CACHE),
                '--spawn_strategy=linux-sandbox','--sandbox_default_allow_network=false',
                '--repo_env='+login.DIRECTORY_VARIABLE+'='+str(value.inner.directory),
                '--run_env='+login.VARIABLE+'='+login.DESTINATION):
            self.assertIn(flag,command)
        self.assertEqual(command[-1],login.LABEL)
        self.assertEqual(command.count('run'),1)
        for changed in (['run','//...'],['run',login.LABEL,'--']):
            with self.assertRaises(ValueError):
                acquisition.command(guard.bazel_command,'/nix/store/bazel',value.run,changed,value,
                    source_commit='a'*40,source_dirty='false')

    def test_ui_command_clears_ambient_native_selector_and_contains_no_resident_action(self):
        value = admitted('native-login-ui')
        value.environment = lambda: {ui.VARIABLE:ui.DESTINATION}
        command = acquisition.command(guard.bazel_command,'/nix/store/bazel',value.run,
            ['run',ui.LABEL],value,source_commit='a'*40,source_dirty='false')
        self.assertIn('--repo_env='+login.DIRECTORY_VARIABLE+'=',command)
        self.assertNotIn(login.LABEL,command)
        for field in ('source.connect','enrollment.start','resident-enrollment','auth.json'):
            self.assertNotIn(field,' '.join(command))

    def test_absolute_work_clock_and_reserved_collection_never_renew(self):
        value = admitted()
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1100*10**9):
            self.assertEqual(value.runtime_seconds(),70)
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1170*10**9):
            with self.assertRaises(ValueError): value.runtime_seconds()
        value.collecting = True
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1199*10**9):
            value.tick()
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1200*10**9):
            with self.assertRaises(ValueError): value.tick()
        self.assertEqual(value.original_deadline,1200*10**9)

    def test_only_zero_exit_verified_empty_cleanup_enters_collection(self):
        for status,cleaned in ((1,True),(125,True),(False,True),(0,False),(0,1),(0,None)):
            value = admitted()
            with self.subTest(status=status,cleaned=cleaned),self.assertRaises(ValueError):
                value.completed(status,cleaned,'epoch',None,'a'*64)
            self.assertFalse(value.collecting)
            value.inner.completed.assert_not_called()

    def test_generated_existing_selector_is_independently_checked_without_resident_effects(self):
        value = admitted()
        value.recheck = mock.Mock(return_value=value.facts)
        facts = {'selector_ready':True,'identity_verified':False,
            'resident_enrollment_completed':False,'renewal_owner':'native','native_support':False}
        import native_login_enrollment_selector as selector
        with mock.patch.object(selector,'verify_generated',return_value=facts) as verify:
            result = value.completed(0,True,'epoch',None,'a'*64)
        verify.assert_called_once_with(value.inner.parent,value.inner.value['enrollment'],
            value.home,1200*10**9)
        self.assertEqual(result,{'action_epoch':'epoch','controller_graph_sha256':'a'*64,
            'manifest_sha256':'b'*64,'result':facts})
        value.inner.completed.assert_not_called()
        self.assertEqual(value.inner.deadline,1200*10**9)
        self.assertEqual(value.recheck.call_count,2)
        for changed in ({**facts,'resident_enrollment_completed':True},
                {**facts,'source_path':'/private/auth.json'},{**facts,'identity_verified':True}):
            value = admitted(); value.recheck = mock.Mock(return_value={})
            with mock.patch.object(selector,'verify_generated',return_value=changed),self.assertRaises(ValueError):
                value.completed(0,True,'epoch',None,'a'*64)

    def test_generated_manifest_matches_current_consumer_without_start_or_replay(self):
        import native_login_enrollment_selector as selector
        import guard_resident_enrollment_profile as installed
        home = Path('/home/model')
        epoch = '11111111-1111-4111-8111-111111111111'
        execution = home/'.local/state/omux-execution-20261005'
        template = {'ownership':'omux-installation','instance':'default',
            'prefix':str(home/'.local/share/omux'),'records':str(home/'.local/state/omux-install'),
            'runtime_state':str(home/'.local/state/omux'),
            'service_path':str(home/'.local/share/omux/units/ai.xoxd.omux.service'),
            'existing_archive':{'archive_path':str(execution/epoch/'output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz'),
                'archive_sha256':'a'*64,'archive_bytes':1234,'manifest_sha256':'b'*64,
                'qualification':{'path':str(execution/epoch/'receipt.json'),'sha256':'c'*64,
                    'bytes':1024,'source_commit':'d'*40,'graph_sha256':'e'*64}}}
        source = home/('.local/state/model-native/native-login-'+'f'*32)
        # Path syntax only, synthetic independently pinned archive fields; no IO.
        result = selector.generated(template,source,home)
        installed.manifest_schema(result,home)
        self.assertEqual(result['action'],'enroll-existing')
        self.assertTrue(result['permissions']['connect_source'])
        self.assertFalse(result['permissions']['activate_service'])
        self.assertFalse(result['permissions']['restart_daemon'])

    def test_environment_preserves_original_namespace_epoch_and_unsets_ambient_authority(self):
        value = admitted('native-login-ui')
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1),mock.patch.object(
                acquisition.os,'fstat',side_effect=lambda fd:mock.Mock(st_dev=17,st_ino=fd)):
            environment = value.environment()
        self.assertEqual(environment['OMUX_NATIVE_LOGIN_UI_NAMESPACE_ID'],'17:21')
        self.assertEqual(environment['OMUX_NATIVE_LOGIN_UI_OUTPUT_ID'],'17:22')
        self.assertEqual(environment['OMUX_NATIVE_LOGIN_UI_ORIGINAL_DEADLINE_NS'],'1200000000000')
        self.assertIn('DBUS_SESSION_BUS_ADDRESS',acquisition.unset_environment(guard.DELEGATION_ENV))
        for key in ('SYSTEMD_HOST','SYSTEMD_MACHINE','SSH_AUTH_SOCK','CODEX_HOME','LD_PRELOAD'):
            self.assertIn(key,acquisition.unset_environment(guard.DELEGATION_ENV))

    def test_private_evidence_projection_never_mutates_or_renders_failure(self):
        value = acquisition.Settings('codex-login',login,Path('/private/input.json'))
        actual = {'BindReadOnlyPaths':'/private/auth-route:/private/input',
            'BindPaths':'/private/state:/private/state'}
        before = dict(actual)
        class PrivateFailure(OSError):
            def __str__(self): raise AssertionError('must not render')
        projected = value.projection(actual)
        self.assertEqual(actual,before)
        self.assertNotIn('/private',json.dumps(projected))
        self.assertEqual(value.rejection(PrivateFailure()),'native-acquisition-refused')

    def test_actual_verify_keeps_standard_full_caps_and_exact_CPU_cgroup(self):
        # Synthetic readback/cgroup only. No manager/process invocation.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for key,value in guard.CGROUP.items(): (root/key).write_text(value)
            (root/'cpu.max').write_text('200000 100000')
            actual = {**guard.PROPERTIES,**guard.SANDBOX,
                'PrivateNetwork':'no','RuntimeMaxUSec':'70s',
                'TemporaryFileSystem':guard.system_masks(profile='standard'),
                'UnsetEnvironment':' '.join(acquisition.unset_environment(guard.DELEGATION_ENV))}
            guard.verify(actual,root,'system',{'PrivateNetwork':'no'},'codex-login',70)
            for field,value in (('CPUQuotaPerSecUSec','1.9s'),('TasksMax','480'),('MemoryMax','4026531840')):
                changed = {**actual,field:value}
                with self.subTest(field=field),self.assertRaises(ValueError):
                    guard.verify(changed,root,'system',{'PrivateNetwork':'no'},'codex-login',70)
            (root/'cpu.max').write_text('200001 100000')
            with self.assertRaises(ValueError):
                guard.verify(actual,root,'system',{'PrivateNetwork':'no'},'codex-login',70)

    def test_active_login_v1_refuses_and_constructor_closes_owned_inputs(self):
        args = arguments(); args.state_dir = Path('/private/state')
        settings = acquisition.select(args,['run',login.LABEL])
        inner = mock.Mock(value={'schema_version':1})
        with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1),mock.patch.object(
                login,'Admission',return_value=inner),self.assertRaises(ValueError):
            acquisition.Admission(settings,args,Path('/public/source'),1200*10**9)
        inner.close.assert_called_once()

    def test_bound_owned_run_refuses_replacement_and_public_modes(self):
        # bind_run only inspects the epoch leaf; outer guard owns its ancestors.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); run = root/'epoch'; run.mkdir(mode=0o700)
            value = admitted(); value.run = None
            value.verify_manifest_pin = mock.Mock()
            with mock.patch.object(acquisition.time,'monotonic_ns',return_value=1):
                value.bind_run(run); value.recheck()
                run.rename(root/'prior'); run.mkdir(mode=0o700)
                with self.assertRaises(ValueError): value.recheck()
            value = admitted(); value.run = None
            run.chmod(0o755)
            with self.assertRaises(ValueError): value.bind_run(run)

    def test_both_readbacks_require_exact_output_epoch_and_recursive_directories(self):
        for profile,selected in (('codex-login',login),('native-login-ui',ui)):
            value = admitted(profile)
            value.inner.writable_binding.return_value = '/private/ui:/omux-native-login-ui-output'
            expected = value.writable_bindings(value.run)
            actual = {'BindPaths':' '.join(token+':rbind' for token in expected),
                'BindReadOnlyPaths':''}
            value.verify_bindings(actual,value.run,None)
            for changed in ({**actual,'BindPaths':' '.join(expected)},
                    {**actual,'BindPaths':actual['BindPaths']+' /private/extra:/private/extra:rbind'}):
                with self.subTest(profile=profile),self.assertRaises(ValueError):
                    value.verify_bindings(changed,value.run,None)
            value.inner.verify_bindings.assert_called_once()
            projected = value.inner.verify_bindings.call_args.args[0]
            self.assertEqual(projected['BindPaths'],
                value.inner.writable_binding()+':rbind' if profile=='native-login-ui' else '')

if __name__ == '__main__':
    unittest.main()
