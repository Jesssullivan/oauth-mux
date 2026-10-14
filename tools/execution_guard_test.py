"""Pure fake-controller predicates; run only through the declared Bazel target.

Live acceptance still requires bounded declared stress actions: exceed 512 tasks,
4 GiB memory, 8 MiB output, runtime deadline and cancellation, then read back
empty descendants. These tests do not perform those workloads or call systemd.
"""
import tempfile
import contextlib
import sys
import shlex
import io
import stat
import hashlib
import json
import os
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch, Mock
from pathlib import Path
import unittest
from execution_guard import (PROPERTIES, SANDBOX, DELEGATION_ENV, CGROUP,
                             blocked_paths, bazel_command, properties, verify)
from execution_guard import validate_become_metadata, system_identity, selected_site_source, selected_site_inventory
from execution_guard import await_startup


class RetainedSDKTerminalWrapperModels(unittest.TestCase):
    @contextlib.contextmanager
    def diagnostic_state(self):
        import guard_native_sdk_tree_reserved as tree
        import uuid
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary).resolve();state.chmod(0o700)
            checkout=state/'checkout';checkout.mkdir(mode=0o700)
            entry=time.monotonic_ns()
            with patch.object(tree.kernel.resident,'PUBLIC_ROOTS',(state,)):
                lease=tree.SDKTreeDependencyLease(state,'3'*64,str(uuid.uuid4()),checkout=checkout,
                    source_commit='4'*40,graph_sha256='5'*64,entry=entry,deadline=entry+1200*10**9,
                    profile=tree.PRODUCER)
                # Wrapper-only synthetic terminal stage; no entered lease, receipt,
                # SDK success, selector, provider or current execution authority.
                try:yield tree,lease
                finally:
                    import execution_guard as guard
                    guard._SDK_TERMINAL_LEASE=None;lease.close()

    def test_actual_main_maps_unqualified_unknown_and_confirmed_reply_failures(self):
        import execution_guard as guard
        for stage,expected in [('committed','committed-unqualified'),('commit-unknown','commit-unknown'),
                ('qualification-observed','qualified-confirmation-delivery-unknown'),('qualified','committed-reply-failed')]:
            with self.diagnostic_state() as (tree,lease):
                primary=OSError('model-reply-after-publication')
                def body(*args):guard._SDK_TERMINAL_LEASE=lease;lease.terminal_stage=stage;raise primary
                with patch.object(guard,'_main',side_effect=body):
                    with self.assertRaises(tree.TerminalPostCommitError) as found:guard.main([])
                self.assertEqual(found.exception.state,expected)
                self.assertIs(found.exception.__cause__,primary);self.assertEqual(lease.terminal_stage,stage)

    def test_actual_main_exitstack_close_failure_does_not_acknowledge_confirmed_success(self):
        import execution_guard as guard
        with self.diagnostic_state() as (tree,lease):
            primary=OSError('model-post-confirmation-exitstack-close');closes=[]
            def close():closes.append(True);raise primary
            def body(argv,admission,retirement):
                guard._SDK_TERMINAL_LEASE=lease;lease.terminal_stage='qualified'
                retirement.callback(close);return 0
            with patch.object(guard,'_main',side_effect=body):
                with self.assertRaises(tree.TerminalPostCommitError) as found:guard.main([])
            self.assertEqual(closes,[True]);self.assertEqual(found.exception.state,'committed-reply-failed')
            self.assertIs(found.exception.__cause__,primary)

    def test_actual_main_preserves_original_precommit_refusal(self):
        import execution_guard as guard
        with self.diagnostic_state() as (tree,lease):
            primary=ValueError('model-original-precommit-refusal')
            def body(*args):guard._SDK_TERMINAL_LEASE=lease;raise primary
            with patch.object(guard,'_main',side_effect=body):
                with self.assertRaises(ValueError) as found:guard.main([])
            self.assertIs(found.exception,primary);self.assertIsNone(found.exception.__cause__)


class HomeManagerOwnedRequestModels(unittest.TestCase):
    def test_only_exact_existing_system_dependency_vector_has_owned_retention(self):
        import execution_guard as guard
        from guard_dependency_profile import HOME_MANAGER_FETCH_LABEL,HOME_MANAGER_STATE,COORDINATION_DIRECTORY
        args=SimpleNamespace(profile='dependency-prefetch',manager='system',source_commit='a'*40,
            source_dirty='false',state_dir=HOME_MANAGER_STATE,coordination_dir=COORDINATION_DIRECTORY,reuse_owned_cache=False)
        entry=100*10**9;deadline=entry+1200*10**9
        with patch.object(guard.time,'monotonic_ns',return_value=entry+10**9):
            self.assertTrue(guard.home_manager_owned_request(args,['test',HOME_MANAGER_FETCH_LABEL],entry,deadline))
            for arguments in (['run',HOME_MANAGER_FETCH_LABEL],['test',HOME_MANAGER_FETCH_LABEL,HOME_MANAGER_FETCH_LABEL],
                    ['test',HOME_MANAGER_FETCH_LABEL,'//:docs_check'],['test',HOME_MANAGER_FETCH_LABEL,'--test_arg=x']):
                with self.assertRaises(ValueError):guard.home_manager_owned_request(args,arguments,entry,deadline)
            for field,value in (('manager','user'),('source_dirty','true'),('reuse_owned_cache',True),
                    ('state_dir',Path('/other')),('coordination_dir',None),('nixpkgs_source',Path('/other'))):
                changed=SimpleNamespace(**{**vars(args),field:value})
                with self.assertRaises(ValueError):guard.home_manager_owned_request(changed,['test',HOME_MANAGER_FETCH_LABEL],entry,deadline)
            self.assertFalse(guard.home_manager_owned_request(args,['test','//tools:fetch_codex_archives_bundle'],entry,deadline))
            args.profile='standard'
            self.assertFalse(guard.home_manager_owned_request(args,['test',HOME_MANAGER_FETCH_LABEL],entry,deadline))

    def test_exact_original_root_work_cutoff_refuses_without_a_new_clock_or_cleanup_credit(self):
        import execution_guard as guard
        from guard_dependency_profile import HOME_MANAGER_FETCH_LABEL,HOME_MANAGER_STATE,COORDINATION_DIRECTORY
        args=SimpleNamespace(profile='dependency-prefetch',manager='system',source_commit='a'*40,
            source_dirty='false',state_dir=HOME_MANAGER_STATE,coordination_dir=COORDINATION_DIRECTORY,reuse_owned_cache=False)
        entry=100*10**9;deadline=entry+1200*10**9
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9):
            with self.assertRaises(ValueError):guard.home_manager_owned_request(args,['test',HOME_MANAGER_FETCH_LABEL],entry,deadline)
        summary=guard.cleanup_owned(deadline=15,readback=Mock(),authorize=Mock(),stop=Mock(),observe=lambda:'empty',clock=lambda:0)
        self.assertEqual(summary,{'state':'empty','stop':'not-requested','ownership':'unproved','readback_attempts':0})
        self.assertFalse(guard.home_manager_owned_complete(None,summary,None))


class CompleteStageDispatchModels(unittest.TestCase):
    def test_only_exact_standard_system_test_gets_original_entry_marker_without_run_widening(self):
        import execution_guard as guard
        entry,deadline = 10,10+1200*10**9
        selected = ['test',guard.DEV_STAGE_LABEL]
        with patch.object(guard.time,'monotonic_ns',return_value=entry+10**9):
            self.assertTrue(guard.dev_stage_request('standard','system',selected,False,entry,deadline))
            run = Path('/owned/5102699b-2ebf-44f1-a454-62b098e49658')
            baseline = guard.bazel_command('/bazel',run,selected)
            command = guard.dev_stage_command(baseline,run,entry,deadline)
            self.assertEqual([value for value in command if value.startswith('--test_env=OMUX_')],
                ['--test_env=OMUX_EXECUTION_GUARD='+str(run),
                 '--test_env=OMUX_DEV_STAGE_ENTRY_NS='+str(entry),
                 '--test_env=OMUX_DEV_STAGE_DEADLINE_NS='+str(deadline)])
            self.assertEqual(command[-1],guard.DEV_STAGE_LABEL)
            self.assertEqual(baseline[-1],guard.DEV_STAGE_LABEL)
            for profile,manager,args,reuse in (
                ('standard','user',selected,False),('site','system',selected,False),
                ('standard','system',['run',guard.DEV_STAGE_LABEL],False),
                ('standard','system',['build',guard.DEV_STAGE_LABEL],False),
                ('standard','system',selected+['//:docs_check'],False),
                ('standard','system',selected+['--root=/arbitrary'],False),
                ('standard','system',selected,True)):
                with self.assertRaises(ValueError):
                    guard.dev_stage_request(profile,manager,args,reuse,entry,deadline)
            for label in ('//delivery:dev_stage','//delivery:dev_stage_complete'):
                with self.assertRaises(ValueError): guard.bazel_command('/bazel',run,['run',label])
            self.assertFalse(guard.dev_stage_request('standard','user',['test','//:docs_check'],True,entry,deadline))
            self.assertEqual(guard.bazel_command('/bazel',run,['test','//:docs_check'])[-1],'//:docs_check')

    def test_original_remaining_runtime_clamp_and_exclusive_graph_admission(self):
        import execution_guard as guard
        entry,deadline = 10,10+1200*10**9
        with patch.object(guard.time,'monotonic_ns',return_value=entry+100*10**9):
            self.assertEqual(guard.dev_stage_budget(entry,deadline),1070)
            with tempfile.TemporaryDirectory() as temporary:
                run = Path(temporary)
                guard.dev_stage_admission(run,'f'*64,entry,deadline)
                raw = (run/'dev-stage-admission.json').read_bytes()
                value = json.loads(raw)
                self.assertEqual(value['entryMonotonicNs'],entry)
                self.assertEqual(value['deadlineMonotonicNs'],deadline)
                self.assertEqual(value['graphSha256'],'f'*64)
                self.assertEqual((run/'dev-stage-admission.json').stat().st_mode & 0o777,0o600)
                with self.assertRaises(FileExistsError): guard.dev_stage_admission(run,'f'*64,entry,deadline)
                self.assertEqual((run/'dev-stage-admission.json').read_bytes(),raw)
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9):
            with self.assertRaises(ValueError): guard.dev_stage_budget(entry,deadline)
        with patch.object(guard.time,'monotonic_ns',return_value=entry+1):
            with self.assertRaises(ValueError): guard.dev_stage_budget(entry,deadline+1)
            with self.assertRaises(ValueError): guard.dev_stage_budget(True,deadline)


    def test_fractional_stage_budget_produces_integer_service_limit_verified_against_actual_bounds(self):
        import execution_guard as guard
        entry,deadline = 10,10+1200*10**9
        with patch.object(guard.time,'monotonic_ns',return_value=entry+100*10**9+194687000):
            budget = guard.dev_stage_budget(entry,deadline)
            maximum = guard.dev_stage_runtime(entry,deadline)
            self.assertIs(type(maximum),int)
            self.assertEqual(maximum,1069)
            self.assertLessEqual(maximum,budget)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                service = FakeService(root)
                service.actual['TemporaryFileSystem'] = guard.system_masks()
                service.actual['RuntimeMaxUSec'] = str(maximum)+'s'
                guard.verify(service.actual,root,manager='system',profile='standard',runtime_seconds=maximum)
                with self.assertRaisesRegex(ValueError,'delivery-effective-runtime-invalid'):
                    guard.verify(service.actual,root,manager='system',profile='standard',runtime_seconds=budget)
                for value in ('1070s','20min','1069.000001s'):
                    with self.subTest(value=value),self.assertRaises(ValueError):
                        guard.verify({**service.actual,'RuntimeMaxUSec':value},root,
                            manager='system',profile='standard',runtime_seconds=maximum)
                with self.assertRaises(ValueError):
                    guard.verify({**service.actual,'MemoryMax':'4294967297'},root,
                        manager='system',profile='standard',runtime_seconds=maximum)
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9-1):
            self.assertGreater(guard.dev_stage_budget(entry,deadline),0)
            with self.assertRaises(ValueError): guard.dev_stage_runtime(entry,deadline)
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9-10**9):
            self.assertEqual(guard.dev_stage_runtime(entry,deadline),1)
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9):
            with self.assertRaises(ValueError): guard.dev_stage_runtime(entry,deadline)

    def test_actual_final_source_readback_crossing_original_deadline_refuses(self):
        import execution_guard as guard
        entry,deadline = 10,10+1200*10**9
        expected = ('a'*64,['fixed-source'])
        calls = []
        def readback():
            calls.append('measured')
            return expected
        with patch.object(guard.time,'monotonic_ns',side_effect=[deadline-1,deadline]):
            with self.assertRaises(ValueError):
                guard.dev_stage_source_after(entry,deadline,expected,readback)
        self.assertEqual(calls,['measured'])
        calls.clear()
        with patch.object(guard.time,'monotonic_ns',return_value=deadline):
            with self.assertRaises(ValueError):
                guard.dev_stage_source_after(entry,deadline,expected,readback)
        self.assertEqual(calls,[])
        with patch.object(guard.time,'monotonic_ns',return_value=deadline-1):
            self.assertTrue(guard.dev_stage_source_after(entry,deadline,expected,readback))
            self.assertFalse(guard.dev_stage_source_after(entry,deadline,expected,lambda:('b'*64,[])))


class FakeService:
    def __init__(self, root):
        self.root = root
        self.actual = {**PROPERTIES, **SANDBOX,
                       'InaccessiblePaths': ' '.join(blocked_paths()),
                       'UnsetEnvironment': ' '.join(DELEGATION_ENV)}
        for name, value in CGROUP.items():
            (root / name).write_text(value)
        (root / 'cpu.max').write_text('200000 100000')

    def admit(self):
        verify(self.actual, self.root)


class ResidentLifecycleCollectorModels(unittest.TestCase):
    def test_exact_resident_collector_after_final_verdict_preserves_failed_status_and_legacy_routes(self):
        import execution_guard as guard
        calls = []
        def observe(value,clock):
            calls.append((value['exit'],clock))
            return {'state':'recorded','outcome':'failed_admitted'}
        admission = SimpleNamespace(lifecycle_attempt=observe)
        receipt = {'profile':'resident-continuity','exit':125,'resident_continuity':{}}
        guard.record_resident_lifecycle(receipt,admission,clock=lambda:7)
        self.assertEqual(calls,[(125,7)])
        self.assertEqual(receipt['exit'],125)
        self.assertEqual(receipt['resident_continuity']['lifecycle_attempt']['outcome'],'failed_admitted')
        for profile in ('resident-namespace','standard','codex-live'):
            legacy = {'profile':profile}
            guard.record_resident_lifecycle(legacy,admission,clock=lambda: (_ for _ in ()).throw(AssertionError('clock read')))
            self.assertEqual(legacy,{'profile':profile})
        self.assertEqual(calls,[(125,7)])

    def test_measurement_failure_is_explicit_missing_and_never_changes_actual_guard_outcome(self):
        import execution_guard as guard
        def refused(*arguments): raise ValueError('fixed refusal')
        admission = SimpleNamespace(lifecycle_attempt=refused)
        receipt = {'profile':'resident-continuity','exit':0,'resident_continuity':{}}
        guard.record_resident_lifecycle(receipt,admission,clock=lambda:7)
        self.assertEqual(receipt['exit'],0)
        fact = receipt['resident_continuity']['lifecycle_attempt']
        self.assertEqual(fact['state'],'unavailable')
        self.assertFalse(fact['native_proof_admitted'])
        self.assertFalse(fact['complete_supported_demand_coverage'])

class ResidentGuardModels(unittest.TestCase):
    def test_full_effective_properties_and_cgroup_preserve_complementary_caps(self):
        import guard_resident_dispatch as resident
        import guard_resident_namespace_profile as namespace
        for profile in resident.PROFILES:
            isolation = {**SANDBOX, **namespace.finite(['run',namespace.LABEL],'system','/public/input.json',False)}
            if profile == 'resident-continuity': isolation['PrivateNetwork'] = 'no'
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for key,value in CGROUP.items():
                    (root/key).write_text({'memory.max':'4026531840','pids.max':'480'}.get(key,value))
                (root/'cpu.max').write_text('190000 100000')
                actual = {**resident.proof_properties(PROPERTIES),**isolation,
                    'TemporaryFileSystem':__import__('execution_guard').system_masks(),
                    'UnsetEnvironment':' '.join(resident.unset_environment(DELEGATION_ENV))}
                for quota in ('1.900000s','1900ms','1900000us'):
                    actual['CPUQuotaPerSecUSec'] = quota
                    verify(actual,root,'system',isolation,profile)
                for quota in ('1.900001s','1.899999s','NaNs','infs','1900000','-1s'):
                    with self.assertRaises(ValueError): verify({**actual,'CPUQuotaPerSecUSec':quota},root,'system',isolation,profile)
                for key,bad in (('memory.max','4026531841'),('memory.swap.max','1'),('pids.max','481'),('cpu.max','190001 100000')):
                    old=(root/key).read_text(); (root/key).write_text(bad)
                    with self.assertRaises(ValueError): verify(actual,root,'system',isolation,profile)
                    (root/key).write_text(old)
                for key,bad in (('PrivatePIDs','yes'),('NoNewPrivileges','no'),('TasksMax','512'),('MemoryMax','4294967296')):
                    with self.assertRaises(ValueError): verify({**actual,key:bad},root,'system',isolation,profile)
                for key in ('SYSTEMD_BUS_ADDRESS','SYSTEMD_HOST','SYSTEMD_MACHINE','DBUS_SYSTEM_BUS_ADDRESS'):
                    wrong={**actual,'UnsetEnvironment':' '.join(v for v in actual['UnsetEnvironment'].split() if v!=key)}
                    with self.assertRaises(ValueError): verify(wrong,root,'system',isolation,profile)
        # Existing standard/native CPU property remains exact 2s.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for key,value in CGROUP.items(): (root/key).write_text(value)
            (root/'cpu.max').write_text('200000 100000')
            actual={**PROPERTIES,**SANDBOX,'TemporaryFileSystem':__import__('execution_guard').system_masks(),
                'UnsetEnvironment':' '.join(DELEGATION_ENV)}
            for profile in ('standard','codex-native'):
                verify(actual,root,'system',SANDBOX,profile,runtime_seconds=1200)
                with self.assertRaises(ValueError): verify({**actual,'CPUQuotaPerSecUSec':'1.9s'},root,'system',SANDBOX,profile,runtime_seconds=1200)

    def test_actual_standard_command_builder_only_changes_exact_resident_run(self):
        import guard_resident_dispatch as resident
        import guard_resident_namespace_profile as namespace
        import guard_resident_continuity_profile as continuity
        import guard_codex_fresh_live_profile as fresh
        run=Path('/private/11111111-1111-4111-8111-111111111111')
        # Only command assembly is modeled; no installation/runtime admission
        # or provider capability is inferred from these synthetic fields.
        for selected in (namespace,continuity):
            scope=namespace.SCOPE if selected is namespace else 'resident-continuity'
            admission=SimpleNamespace(facts={'scope':scope},manifest=Path('/public/input.json'),
                environment=lambda:{'OMUX_RESIDENT_NAMESPACE_EPOCH':run.name},
                fresh=SimpleNamespace(selection_path=Path('/public/fresh-runtime-selection.json'),
                    selection_pin={'sha256':'2'*64,'bytes':123}))
            for cache,nixpkgs in ((None,None),(resident.REPOSITORY_CACHE,resident.NIXPKGS)):
                with self.subTest(profile=selected.PROFILE,cache=cache):
                    command=resident.command(bazel_command,'/nix/store/public/bin/bazel',run,
                        ['run',selected.LABEL],admission,source_commit='1'*40,source_dirty='false',
                        repository_cache=cache,nixpkgs_source=nixpkgs)
                    self.assertEqual(command.count('run'),1); self.assertNotIn('build',command)
                    self.assertEqual(command[-1],selected.LABEL)
                    self.assertNotIn('--disable_download',command)
                    self.assertEqual(command.count('--repository_disable_download'),1)
                    for flag in ('--batch','--spawn_strategy=linux-sandbox','--disk_cache=',
                            '--sandbox_default_allow_network=false','--run_env=OMUX_RESIDENT_NAMESPACE_EPOCH='+run.name):
                        self.assertIn(flag,command)
                    if cache is None:
                        self.assertNotIn('--repo_contents_cache=',command)
                    else:
                        self.assertIn('--repo_contents_cache=',command)
                        self.assertIn('--repository_cache='+str(cache),command)
                    for key,value in ((fresh.VARIABLE,str(admission.fresh.selection_path)),
                            (fresh.SHA_VARIABLE,'2'*64),(fresh.BYTES_VARIABLE,'123')):
                        rows=[part for part in command if part.startswith('--repo_env='+key+'=')]
                        self.assertEqual(rows,['--repo_env='+key+'='+(value if selected is continuity else '')])
            with self.assertRaises(ValueError):
                resident.command(bazel_command,'/nix/store/public/bin/bazel',run,
                    ['run',selected.LABEL,'--'],admission,source_commit='1'*40,source_dirty='false')
            for cache,nixpkgs in ((resident.REPOSITORY_CACHE,None),(None,resident.NIXPKGS),
                                  (Path('/foreign/cache'),resident.NIXPKGS)):
                with self.assertRaises(ValueError):
                    resident.command(bazel_command,'/nix/store/public/bin/bazel',run,
                        ['run',selected.LABEL],admission,source_commit='1'*40,source_dirty='false',
                        repository_cache=cache,nixpkgs_source=nixpkgs)

    def test_partial_or_foreign_resident_cli_refuses_before_immutable_tools(self):
        from execution_guard import main
        complete=['--profile','resident-namespace','--manager','system','--resident-manifest','/public/input.json',
            '--resident-epoch','11111111-1111-4111-8111-111111111111','--resident-producer-sha256','1'*64,
            '--resident-observer-sha256','2'*64,'--source-commit','3'*40,'--source-dirty','false']
        for command in (complete[:-2],complete+['--reuse-owned-cache'],complete+['--native-mode','cli-opt'],
            complete+['--resident-runtime-bytes','1'],complete+['--','run','//:unit_tests'],
            ['--profile','standard','--resident-manifest','/public/input.json','--','test','//:unit_tests']):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError): main(command if command[-1]=='//:unit_tests' else command+['--','run','//delivery:resident_namespace_qualification'])
                reader.assert_not_called()


class FakeClock:
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class GuardTest(unittest.TestCase):
    def test_staged_native_inputs_refuse_before_operator_tool_reads(self):
        from execution_guard import main
        import codex_native_profile as native
        baseline = ['--profile', 'codex-native', '--manager', 'system',
            '--state-dir', str(native.STATE), '--source-commit', '1' * 40,
            '--source-dirty', 'false', '--native-mode', 'staged-libraries',
            '--native-source-root', '/public/source', '--native-source-sha256', 'a' * 64,
            '--native-export-root', '/public/export', '--native-export-sha256', 'b' * 64,
            '--native-patch-sha256', 'c' * 64, '--native-patch-sha256', 'd' * 64,
            '--native-patch-sha256', 'e' * 64]
        selector = ['--native-staged-compilation',
            str(native.STATE / 'native-staged-compilation.json'),
            '--native-staged-compilation-sha256', 'f' * 64, '--native-stage', '1']
        cases = [
            baseline,
            baseline + selector[:2],
            baseline + selector + ['--native-global-attempt', '9'],
            baseline + selector + ['--native-owned-candidate-cache', '--native-cache-attempt', '1'],
            baseline + selector + ['--native-fresh-completion', str(native.STATE / 'native-fresh-completion.json'),
                '--native-fresh-completion-sha256', 'a' * 64, '--native-global-attempt', '9'],
            baseline + selector + ['--native-stage', '2'],
            baseline + selector + ['--native-stage', '5'],
            baseline + selector + ['--', 'build', '//codex-rs/cli:codex'],
            ['--profile', 'standard'] + selector + ['--', 'test', '//:unit_tests'],
        ]
        for request in cases:
            with self.subTest(request=request), patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(request)
                reader.assert_not_called()

    def test_sdk_export_run_is_one_exact_guarded_writer(self):
        run = Path('/private/12345678-1234-1234-1234-123456789abc')
        args = ['run','//tools:codex_retained_sdk_export_run']
        command = bazel_command('/store/bazel',run,args)
        self.assertIn('--run_env=OMUX_SDK_EXPORT_EPOCH='+str(run),command)
        self.assertIn('--run_env=OMUX_EXECUTION_GUARD='+str(run),command)
        self.assertNotIn('--nozip_undeclared_test_outputs',command)
        self.assertEqual(command[-1],args[-1])
        for changed in (args+['//:extra'],args+['--','--output=/tmp'],['run','//tools:codex_retained_sdk_qualify']):
            with self.assertRaises(ValueError): bazel_command('/store/bazel',run,changed)
        with self.assertRaises(ValueError): bazel_command('/store/bazel',run,args,profile='codex-live')
        test = bazel_command('/store/bazel',run,['test','//tools:codex_retained_sdk_export'])
        self.assertFalse(any(arg.startswith('--run_env=OMUX_SDK_EXPORT_EPOCH=') for arg in test))
    def test_pids_metadata_is_bounded_canonical_and_closed(self):
        from execution_guard import parse_pids_metadata
        self.assertEqual(parse_pids_metadata(b'512\n', 'pids.max'), 512)
        self.assertEqual(parse_pids_metadata(b'max\n', 'pids.max'), 'max')
        self.assertEqual(parse_pids_metadata(b'max 7\n', 'pids.events'), 7)
        for data in (b'', b'01\n', b'-1', b'1\nprivate', b'1\n\n', b'\xff',
                     b'18446744073709551616', b'1' * 4097):
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeError)):
                parse_pids_metadata(data, 'pids.current')
        for data in (b'max 1\nmax 1\n', b'max 1\nother 2\n', b'private 1\n'):
            with self.assertRaises(ValueError): parse_pids_metadata(data, 'pids.events')

    def test_pids_sampling_uses_held_directory_and_nofollow_fixed_files(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'group'; root.mkdir()
            for name, text in (('pids.current', '3\n'), ('pids.max', '512\n'), ('pids.events', 'max 4\n')):
                (root / name).write_text(text)
            pin = CgroupPin(root)
            try:
                original_open = os.open
                calls = []
                def opening(path, flags, *args, **kwargs):
                    calls.append((path, flags, kwargs.get('dir_fd')))
                    return original_open(path, flags, *args, **kwargs)
                with patch('execution_guard.os.open', side_effect=opening):
                    row = pin.pids_snapshot()
                self.assertEqual(row, {'custody': 'same', 'current': 3, 'limit': 512, 'max_events': 4})
                self.assertEqual(calls[0][0], '.')
                self.assertEqual(calls[0][2], pin.descriptor)
                self.assertEqual([call[0] for call in calls[1:]], ['pids.current', 'pids.max', 'pids.events'])
                self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in calls))
                self.assertTrue(all(flags & os.O_NONBLOCK for _, flags, _ in calls[1:]))
                (root / 'pids.current').unlink()
                (Path(temporary) / 'private').write_text('private-secret-value')
                (root / 'pids.current').symlink_to(Path(temporary) / 'private')
                self.assertIsNone(pin.pids_snapshot()['current'])
            finally: pin.close()

    def test_pids_replaced_missing_or_closed_pin_is_unknown(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'group'; root.mkdir()
            pin = CgroupPin(root)
            try:
                root.rename(Path(temporary) / 'original')
                self.assertEqual(pin.pids_snapshot()['custody'], 'absent')
                root.mkdir()
                self.assertEqual(pin.pids_snapshot(), {'custody': 'changed', 'current': None, 'limit': None, 'max_events': None})
            finally: pin.close()
            self.assertEqual(pin.pids_snapshot()['custody'], 'unavailable')

    def test_pids_short_read_private_tail_and_file_replacement_are_unknown(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in (('pids.current', '1\nprivate-tail'), ('pids.max', '512'), ('pids.events', 'max 0')):
                (root / name).write_text(text)
            pin = CgroupPin(root)
            original_read = os.read
            try:
                with patch('execution_guard.os.read', side_effect=lambda fd, bound: original_read(fd, min(bound, 1))):
                    self.assertIsNone(pin.pids_snapshot()['current'])
                (root / 'pids.current').write_text('1')
                replaced = False
                def replacing(fd, bound):
                    nonlocal replaced
                    data = original_read(fd, bound)
                    if not replaced:
                        (root / 'pids.current').rename(root / 'old-current')
                        (root / 'pids.current').write_text('512'); replaced = True
                    return data
                with patch('execution_guard.os.read', side_effect=replacing):
                    row = pin.pids_snapshot()
                self.assertIsNone(row['current'])
                self.assertEqual(row['limit'], 512)
            finally: pin.close()

    def test_pids_release_failure_remains_unknown_and_preserves_cancellation(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in (('pids.current', '1'), ('pids.max', '512'), ('pids.events', 'max 0')):
                (root / name).write_text(text)
            pin = CgroupPin(root)
            original_close = os.close; released = []
            def closing(fd):
                released.append(fd); original_close(fd)
                raise OSError('private-close-error')
            try:
                with patch('execution_guard.os.close', side_effect=closing):
                    row = pin.pids_snapshot()
                self.assertEqual(row['custody'], 'unavailable')
                self.assertEqual(len(released), 4)
                self.assertNotIn(pin.descriptor, released)
                cancellation = KeyboardInterrupt()
                released.clear()
                with patch('execution_guard.os.read', side_effect=cancellation), \
                        patch('execution_guard.os.close', side_effect=closing):
                    with self.assertRaises(KeyboardInterrupt) as raised: pin.pids_snapshot()
                self.assertIs(raised.exception, cancellation)
                self.assertEqual(len(released), 2)
            finally: pin.close()

    def test_pids_changed_during_read_is_not_other_group_measurement(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'group'; root.mkdir()
            for name, text in (('pids.current', '3'), ('pids.max', '512'), ('pids.events', 'max 0')):
                (root / name).write_text(text)
            pin = CgroupPin(root)
            original_read = os.read
            moved = False
            def reading(fd, bound):
                nonlocal moved
                data = original_read(fd, bound)
                if not moved:
                    root.rename(Path(temporary) / 'original'); root.mkdir(); moved = True
                return data
            try:
                with patch('execution_guard.os.read', side_effect=reading):
                    self.assertEqual(pin.pids_snapshot()['custody'], 'changed')
            finally: pin.close()

    def test_pids_secondary_close_control_flow_preserves_original_and_all_releases(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in (('pids.current', '1'), ('pids.max', '512'), ('pids.events', 'max 0')):
                (root / name).write_text(text)
            pin = CgroupPin(root)
            original_close = os.close
            try:
                for primary, secondary in ((KeyboardInterrupt(), SystemExit(17)),
                                           (SystemExit(9), KeyboardInterrupt())):
                    released = []
                    def closing(fd):
                        released.append(fd); original_close(fd); raise secondary
                    with patch('execution_guard.os.read', side_effect=primary), \
                            patch('execution_guard.os.close', side_effect=closing):
                        with self.assertRaises(type(primary)) as raised: pin.pids_snapshot()
                    self.assertIs(raised.exception, primary)
                    self.assertEqual(len(released), 2)
                    self.assertNotIn(pin.descriptor, released)
            finally: pin.close()

    def test_pids_partial_unavailable_and_private_tail_are_explicit(self):
        from execution_guard import CgroupPin, PidsObservation
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'pids.current').write_text('3\nprivate-secret-value')
            (root / 'pids.max').write_text('512')
            pin = CgroupPin(root)
            try:
                observations = PidsObservation(); observations.sample(pin, 'baseline')
                record = observations.receipt()
                self.assertIsNone(record['baseline']['current'])
                self.assertIsNone(record['baseline']['max_events'])
                self.assertEqual(record['baseline']['pids_limit'], 'verified512')
                self.assertTrue(record['observed_unknown'])
                self.assertNotIn('private-secret-value', json.dumps(record))
                self.assertNotIn(temporary, json.dumps(record))
            finally: pin.close()

    def test_pids_whole_workload_window_deltas_peak_and_decrease(self):
        from execution_guard import PidsObservation
        pin = Mock()
        pin.pids_snapshot.side_effect = [
            {'custody': 'same', 'current': 4, 'limit': 512, 'max_events': 900},
            {'custody': 'same', 'current': 512, 'limit': 512, 'max_events': 901},
            {'custody': 'same', 'current': 513, 'limit': 512, 'max_events': 899},
            {'custody': 'same', 'current': 2, 'limit': 512, 'max_events': 903}]
        observations = PidsObservation(); observations.sample(pin, 'baseline')
        self.assertEqual(observations.baseline['max_event_delta'], 0)
        observations.sample(pin, 'monitor'); observations.sample(pin, 'monitor'); observations.finish(pin)
        record = observations.receipt()
        self.assertEqual(record['scope'], 'whole-owned-workload-cgroup')
        self.assertEqual(record['attribution'], 'none')
        self.assertEqual(record['sampled_peak_current'], 513)
        self.assertEqual(record['last_monitor']['pids_sample'], 'over')
        self.assertEqual(record['last_monitor']['max_event_delta'], -1)
        self.assertEqual(record['pre_cleanup']['max_event_delta'], 3)
        self.assertTrue(record['observed_at_or_over_verified_limit'])
        self.assertTrue(record['observed_max_event_increase'])
        self.assertTrue(record['observed_max_event_decrease'])

    def test_pids_monitor_keeps_cadence_and_samples_before_cleanup_even_on_failure(self):
        from execution_guard import PidsObservation, monitor_workload, observe_pids_before_cleanup
        sequence = []; clock = FakeClock()
        pin = Mock()
        def snapshot():
            sequence.append('sample')
            return {'custody': 'same', 'current': 1, 'limit': 512, 'max_events': 0}
        pin.pids_snapshot.side_effect = snapshot
        observations = PidsObservation(); observations.sample(pin, 'baseline')
        replies = iter([{'ActiveState': 'active'}, {'ActiveState': 'inactive', 'Result': 'success', 'ExecMainStatus': '0'}])
        read_times = []
        def read():
            read_times.append(clock())
            return next(replies)
        pauses = []
        def pause(seconds): pauses.append(seconds); clock.advance(seconds)
        def iteration(): observations.sample(pin, 'monitor'); sequence.append('iteration')
        result = monitor_workload(read, 10, iteration, clock=clock, pause=pause)
        self.assertIsNone(observe_pids_before_cleanup(observations, pin))
        sequence.append('cleanup'); observations.finish(pin)
        self.assertEqual(result, 0); self.assertEqual(pauses, [0.5] * 4)
        self.assertEqual(read_times, [0, 2.0])
        self.assertEqual(sequence, ['sample'] + ['sample', 'iteration'] * 5 + ['sample', 'cleanup'])
        self.assertEqual(observations.receipt()['monitor_samples'], 5)
        original = OSError('private-exception-value')
        failed = PidsObservation(); failed.sample(pin, 'baseline')
        with self.assertRaises(OSError) as raised:
            try:
                monitor_workload(Mock(side_effect=original), 10,
                    lambda: failed.sample(pin, 'monitor'), clock=clock, pause=pause)
            finally:
                self.assertIsNone(observe_pids_before_cleanup(failed, pin, original))
        self.assertIs(raised.exception, original)
        self.assertEqual(failed.pre_cleanup['sample_timing'], 'pre-cleanup')
        self.assertNotIn('private-exception-value', json.dumps(failed.receipt()))

    def test_monitor_original_deadline_bounds_samples_queries_and_terminal_result(self):
        from execution_guard import monitor_workload
        clock = FakeClock(); sample_times = []; read_times = []; pauses = []
        def read():
            read_times.append(clock())
            return {'ActiveState': 'active'}
        def pause(seconds):
            pauses.append(seconds); clock.advance(seconds)
        result = monitor_workload(read, 1.25, lambda: sample_times.append(clock()),
                                  clock=clock, pause=pause)
        self.assertEqual(result, 124)
        self.assertEqual(sample_times, [0, 0.5, 1.0])
        self.assertEqual(read_times, [0])
        self.assertEqual(pauses, [0.5, 0.5, 0.25])
        self.assertEqual(clock(), 1.25)

        clock = FakeClock(); unread = Mock()
        def expired_iteration(): clock.advance(1)
        self.assertEqual(monitor_workload(unread, 1, expired_iteration,
                                         clock=clock, pause=Mock()), 124)
        unread.assert_not_called()
        for terminal in ({'ActiveState': 'inactive', 'Result': 'success', 'ExecMainStatus': '0'},
                         {'ActiveState': 'failed', 'Result': 'exit-code', 'ExecMainStatus': '3'}):
            clock = FakeClock(); no_pause = Mock()
            def late_read(): clock.advance(1); return terminal
            self.assertEqual(monitor_workload(late_read, 1, lambda: None,
                                             clock=clock, pause=no_pause), 124)
            no_pause.assert_not_called()

    def test_pids_cleanup_continues_and_deferred_control_flow_keeps_primary(self):
        from execution_guard import PidsObservation, observe_pids_before_cleanup
        for error in (ValueError('private-classifier-value'), OSError('private-read-value'), KeyboardInterrupt(), SystemExit(9)):
            observations = PidsObservation(); observations.finish = Mock(side_effect=error)
            cleanup = Mock(return_value={'state': 'empty'})
            deferred = observe_pids_before_cleanup(observations, None)
            self.assertEqual(cleanup()['state'], 'empty')
            cleanup.assert_called_once()
            self.assertTrue(observations.observed_unknown)
            self.assertIsNone(observations.pre_cleanup['current'])
            self.assertNotIn('private-', json.dumps(observations.receipt()))
            if isinstance(error, Exception): self.assertIsNone(deferred)
            else:
                self.assertIs(deferred, error)
                reported_controller_status = 125
                if isinstance(error, SystemExit):
                    self.assertEqual(error.code, 9)
                    self.assertNotEqual(error.code, reported_controller_status)
                with self.assertRaises(type(error)) as raised: raise deferred
                self.assertIs(raised.exception, error)
            original = OSError('private-original-error')
            self.assertIsNone(observe_pids_before_cleanup(observations, None, original))
            self.assertIsNone(observe_pids_before_cleanup(observations, None, prior_failure=True))
        observations = PidsObservation()
        with patch.object(observations, 'classify', side_effect=ValueError('private-classifier-error')):
            self.assertIsNone(observe_pids_before_cleanup(observations, None))
        self.assertIs(observations.pre_cleanup, observations.unknown_pre_cleanup)
        self.assertTrue(observations.observed_unknown)
        observations = PidsObservation()
        with patch.object(observations, 'classify', side_effect=ValueError('private-classifier-error')):
            observations.sample(None, 'baseline'); observations.sample(None, 'monitor')
        self.assertEqual(observations.monitor_samples, 1)
        self.assertIsNone(observations.baseline['current'])
        self.assertIsNone(observations.last_monitor['current'])

    def test_pids_unavailable_cannot_manufacture_delta_or_continuous_proof(self):
        from execution_guard import PidsObservation, unknown_pids_snapshot
        pin = Mock(); pin.pids_snapshot.side_effect = OSError('private-value')
        observations = PidsObservation(); observations.sample(pin, 'baseline')
        pin.pids_snapshot.side_effect = None
        pin.pids_snapshot.return_value = {'custody': 'same', 'current': 1, 'limit': 'max', 'max_events': 80}
        observations.sample(pin, 'monitor'); observations.finish(pin)
        record = observations.receipt()
        self.assertEqual(record['pre_cleanup']['pids_limit'], 'changed')
        self.assertIsNone(record['pre_cleanup']['max_event_delta'])
        self.assertFalse(record['observed_max_event_increase'])
        self.assertTrue(record['observed_unknown'])
        self.assertEqual(unknown_pids_snapshot()['custody'], 'unavailable')

    def test_yoga_delivery_command_binds_original_deadline_and_clears_prior_authority(self):
        from execution_guard import yoga_delivery_command
        args = ['run','//tools:yoga_controller_qualify']
        with patch('time.monotonic_ns',return_value=100*10**9):
            command,values = yoga_delivery_command('/nix/store/fixed-bazel',Path('/owned/epoch'),args,1200*10**9)
        self.assertEqual(command[-1],args[-1]); self.assertEqual(command.count('run'),1)
        self.assertIn('--run_env=OMUX_YOGA_DELIVERY_DEADLINE_NS='+str(1200*10**9),command)
        self.assertIn('--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256=',command)
        self.assertIn('--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=',command)
        for flag in ('--batch','--nosystem_rc','--nohome_rc','--noworkspace_rc','--jobs=2',
                     '--legacy_globbing_threads=2', '--experimental_fsvc_threads=2',
                     '--remote_executor=','--remote_cache=','--disk_cache=','--lockfile_mode=error'):
            self.assertIn(flag,command)
        prior = {'path':'/home/jess/.local/state/omux-yoga-delivery-20261006/prior/qualification.json','sha256':'a'*64}
        with patch('time.monotonic_ns',return_value=100*10**9):
            command,_ = yoga_delivery_command('/nix/store/fixed-bazel',Path('/owned/epoch'),
                ['run','//tools:yoga_controller_verify'],1200*10**9,prior)
        self.assertIn('--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION='+prior['path'],command)
        self.assertIn('--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256='+prior['sha256'],command)
        self.assertEqual(blocked_paths('yoga-controller-delivery'),blocked_paths('standard'))
        # General run and unrelated dependency producers remain refused.
        for arguments in (['run','//tools:yoga_controller_qualify'],['run','//...']):
            with self.assertRaises(ValueError): bazel_command('/nix/store/fixed-bazel',Path('/owned/epoch'),arguments)

    def test_delivery_scope_rejects_unrelated_inputs_before_tool_reads(self):
        import execution_guard as guard
        common = ['--profile','yoga-controller-delivery','--manager','system',
            '--state-dir','/home/jess/.local/state/omux-yoga-delivery-20261006',
            '--coordination-dir','/home/jess/.local/state/omux-execution-20261005']
        with patch.object(guard,'immutable') as tools:
            for addition in (['--reuse-owned-cache'],['--yoga-delivery-epoch','12345678-1234-4123-8123-123456789012'],
                             ['--repository-cache','/unrelated']):
                with self.assertRaises(ValueError): guard.main(common+addition+['--','run','//tools:yoga_controller_qualify'])
            tools.assert_not_called()
        with patch.object(guard,'immutable') as tools:
            with self.assertRaises(ValueError): guard.main(['--yoga-delivery-epoch','12345678-1234-4123-8123-123456789012',
                '--','test','//:docs_check'])
            tools.assert_not_called()
    def test_home_manager_home_prepare_preserves_custody_sampling_and_fixed_coordination(self):
        import execution_guard as guard
        from guard_dependency_profile import HOME_MANAGER_STATE, HOME_MANAGER_FETCH_LABEL, COORDINATION_DIRECTORY
        calls = []
        with patch.object(guard, 'private', side_effect=lambda path, **options: calls.append(('private', path))), \
                patch.object(guard, 'initialize_state', side_effect=lambda path, validator: calls.append(('initialize', path))), \
                patch.object(guard, 'check_free_space', side_effect=lambda path: calls.append(('space', path))):
            selected = guard.prepare_state(HOME_MANAGER_STATE, 'dependency-prefetch', COORDINATION_DIRECTORY,
                True, arguments=['test', HOME_MANAGER_FETCH_LABEL])
        self.assertEqual(selected, COORDINATION_DIRECTORY)
        self.assertEqual(calls, [('private', COORDINATION_DIRECTORY), ('initialize', HOME_MANAGER_STATE),
                                 ('private', HOME_MANAGER_STATE), ('space', HOME_MANAGER_STATE)])
        self.assertEqual(guard.DIAGNOSTIC_STAGE, 'state-free-space')

    def test_home_manager_home_prepare_refuses_other_scope_before_state_mutation(self):
        import execution_guard as guard
        from guard_dependency_profile import HOME_MANAGER_STATE, HOME_MANAGER_FETCH_LABEL, COORDINATION_DIRECTORY, FETCH_LABEL
        with patch.object(guard, 'private') as private, patch.object(guard, 'initialize_state') as initialize, \
                patch.object(guard, 'check_free_space') as space:
            for profile, arguments in (('dependency-prefetch', None), ('dependency-prefetch', ['test', FETCH_LABEL]),
                                       ('standard', ['test', HOME_MANAGER_FETCH_LABEL])):
                with self.subTest(profile=profile, arguments=arguments), self.assertRaises(ValueError):
                    guard.prepare_state(HOME_MANAGER_STATE, profile, COORDINATION_DIRECTORY,
                                        True, arguments=arguments)
            private.assert_not_called()
            initialize.assert_not_called()
            space.assert_not_called()

    def test_home_manager_home_network_producer_still_refuses_cache_reuse_before_tool_reads(self):
        from execution_guard import main
        from guard_dependency_profile import HOME_MANAGER_STATE, HOME_MANAGER_FETCH_LABEL, COORDINATION_DIRECTORY
        with patch('execution_guard.immutable') as tools:
            with self.assertRaises(ValueError):
                main(['--profile', 'dependency-prefetch', '--state-dir', str(HOME_MANAGER_STATE),
                      '--coordination-dir', str(COORDINATION_DIRECTORY), '--reuse-owned-cache',
                      '--', 'test', HOME_MANAGER_FETCH_LABEL])
            tools.assert_not_called()

    def test_yoga_production_preallocation_publication_and_command_join(self):
        import guard_yoga_profile as yoga
        from execution_guard import yoga_command
        from yoga_operator_launch import command_digest
        deadline = time.monotonic_ns() + 1100 * 10**9
        proof_id = '12345678-1234-4123-8123-123456789012'
        root = Path('/srv/yoga-source')
        run = Path('/srv/yoga-state') / proof_id
        tools = {name: '/nix/store/' + 'a' * 32 + '-controller/' + name for name in yoga.TOOLS}
        tools['bootstrap_closure'] = '/nix/store/' + 'a' * 32 + '-bootstrap'
        snapshot = {'device': 4, 'inode': 5, 'uid': 1000, 'mode': 0o700, 'pid': 200, 'start_ticks': 50}
        receipt = {'schemaVersion': 1, 'scope': 'yoga-local-guard-qualification-v1', 'hostAlias': 'yoga',
            'proofId': proof_id, 'deadlineMonotonicNs': deadline,
            'host': {'machineIdSha256': 'a' * 64, 'bootIdSha256': 'b' * 64, 'uid': 1000},
            'seat': {'sessionId': '3', 'seatId': 'seat0', 'uid': 1000}, 'operatorTerminal': '/dev/pts/4',
            'sourceRoot': str(root), 'sourceGraphSha256': 'c' * 64,
            'sourceFilesSha256': {name: 'd' * 64 for name in yoga.SOURCE_FILES},
            'sourceSocket': '/run/user/1000/wayland-0', 'compositorSnapshot': snapshot,
            'inputPaths': {name: '/srv/yoga-inputs/' + name for name in yoga.coordinator.INPUTS},
            'inputSha256': {name: 'e' * 64 for name in yoga.coordinator.INPUTS}, 'controllerTools': tools,
            'controllerInventory': {'path': '/srv/yoga-inputs/controller-inventory', 'sha256': 'f' * 64},
            'controllerNarProof': {'path': '/srv/yoga-inputs/controller-nar', 'sha256': 'f' * 64}}
        receipt['vaultWrapperAuthority'] = {
            'companion': {'path': '/srv/yoga-inputs/companion', 'sha256': '1' * 64},
            'nativeManifest': {'path': '/srv/yoga-inputs/native.json', 'sha256': '2' * 64},
            'registeredNativeManifest': {'path': '/nix/store/' + 'b' * 32 + '-native.json', 'sha256': '3' * 64},
            **{name: receipt[name] for name in ('controllerTools', 'controllerInventory', 'controllerNarProof')}}
        witness = {'source': receipt['sourceSocket'], 'destination': str(run / 'wayland.sock'),
                   'proof_root': str(run), 'uid': 1000, 'deadline_ns': deadline, 'snapshot': snapshot}
        content = b'{"public":"qualified-inventory-fixture"}'
        inventory = {'bytes': content, 'sha256': hashlib.sha256(content).hexdigest()}
        with patch.object(yoga, 'file_bytes', return_value=json.dumps(receipt).encode()), \
                patch.object(yoga, 'local_identity'), \
                patch.object(yoga, 'runtime_qualification', return_value=(receipt['inputSha256'], inventory)) as qualify, \
                patch.object(yoga, 'require_unit_absent'), \
                patch.object(yoga.display, 'capture_pinned', return_value=(witness, Mock())), \
                patch.object(Path, 'resolve', return_value=root):
            admission = yoga.preallocate('/srv/yoga-inputs/selection.json', 'f' * 64, deadline,
                manager='system', arguments=['run', yoga.LABEL], state_root='/srv/yoga-state', source_root=root,
                home=Path('/home/user'), tools=tools, graph_sha256='c' * 64, uid=1000, operator_descriptor=0)
            qualify.assert_called_once_with(receipt, deadline, retain_inventory=True)
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            with patch.object(yoga.inputs, 'open_parent', side_effect=lambda *args: os.open(fixture, os.O_RDONLY | os.O_DIRECTORY)), \
                    patch.object(yoga, 'file_bytes', side_effect=lambda *args, **options: (fixture / 'browser-inventory.json').read_bytes()):
                yoga.publish_repository_inventory(admission, run)
                command = yoga_command(tools['bazel'], run, ['run', yoga.LABEL], admission, manager='system')
                self.assertEqual(command[-1], yoga.LABEL)
                self.assertEqual(command.count('run'), 1)
                self.assertNotIn('--', command)
                self.assertIn('--output_base=' + str(run / 'output-base'), command)
                self.assertIn('--symlink_prefix=' + str(run / 'bazel-'), command)
                for flag in ('--batch', '--nosystem_rc', '--nohome_rc', '--noworkspace_rc', '--jobs=2',
                             '--spawn_strategy=sandboxed', '--remote_executor=', '--remote_cache=', '--disk_cache=',
                             '--sandbox_default_allow_network=false', '--lockfile_mode=error'):
                    self.assertIn(flag, command)
                for key, value in yoga.repository_bindings(admission, run).items():
                    self.assertIn('--repo_env=' + key + '=' + value, command)
                self.assertEqual(len(command_digest(command)), 64)
                with self.assertRaises(ValueError):
                    yoga_command('/nix/store/foreign/bazel', run, ['run', yoga.LABEL], admission, manager='system')
                (fixture / 'browser-inventory.json').write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    yoga_command(tools['bazel'], run, ['run', yoga.LABEL], admission, manager='system')

    def test_yoga_route_keeps_generic_runs_and_extra_arguments_refused(self):
        import guard_yoga_profile as yoga
        from execution_guard import yoga_command
        for arguments in (['run', yoga.LABEL], ['run', yoga.LABEL, '--', '--inside'], ['run', '//:other']):
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/srv/owned/run'), arguments)
        for arguments, manager in ((['run', yoga.LABEL], 'user'), (['run', '//:other'], 'system'),
                                   (['run', yoga.LABEL, '--', '--inside'], 'system'),
                                   (['build', yoga.LABEL], 'system')):
            with patch.object(yoga, 'repository_bindings') as bindings:
                with self.assertRaises(ValueError):
                    yoga_command('/store/bazel', Path('/srv/owned/run'), arguments, {}, manager=manager)
                bindings.assert_not_called()

    def test_yoga_caller_site_and_cache_flags_still_refuse_before_tool_reads(self):
        import guard_yoga_profile as yoga
        from execution_guard import main
        baseline = ['--profile', 'yoga-toolbar', '--manager', 'system',
                    '--state-dir', '/srv/yoga-state', '--yoga-qualification', '/srv/yoga-inputs/selection.json',
                    '--yoga-qualification-sha256', 'a' * 64, '--yoga-deadline-monotonic-ns',
                    str(time.monotonic_ns() + 1100 * 10**9)]
        for options in (['--site-inventory', '/srv/foreign-inventory'], ['--site-inventory-sha256', 'b' * 64],
                        ['--repository-cache', '/srv/foreign-cache'], ['--reuse-owned-cache'],
                        ['--nixpkgs-source', '/nix/store/foreign-source']):
            with patch('execution_guard.immutable') as tools:
                with self.assertRaises(ValueError):
                    main(baseline + options + ['--', 'run', yoga.LABEL])
                tools.assert_not_called()

    def test_controller_failures_use_only_finite_categories(self):
        from execution_guard import controller_diagnostic, controller_run
        diagnostics = []
        error = subprocess.TimeoutExpired(['sensitive-argv'], 15,
                                          output=b'sensitive-output', stderr=b'sensitive-error')
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            controller_run(['sensitive-argv'], operation='unit-readback', phase='monitor',
                diagnose=diagnostics.append, invoke=Mock(side_effect=error))
        self.assertIs(raised.exception, error)
        self.assertEqual(diagnostics, [{'operation': 'unit-readback', 'phase': 'monitor',
                                       'exception': 'TimeoutExpired', 'timeout_seconds': 15}])
        self.assertNotIn('sensitive', str(diagnostics))
        self.assertEqual(controller_diagnostic(error, 'sensitive', 'sensitive', float('inf')),
            {'operation': 'unknown', 'phase': 'unknown', 'exception': 'TimeoutExpired',
             'timeout_seconds': None})
        diagnostics.clear()
        with self.assertRaises(subprocess.CalledProcessError):
            controller_run(['sensitive'], operation='unit-stop', phase='cleanup',
                diagnose=diagnostics.append,
                invoke=Mock(return_value=SimpleNamespace(returncode=1, stdout=b'sensitive', stderr=b'sensitive')))
        self.assertEqual(diagnostics[0]['exception'], 'CalledProcessError')
        self.assertNotIn('sensitive', str(diagnostics))

    def test_controller_deadline_refuses_spawn_and_caps_remaining_time(self):
        from execution_guard import controller_run
        invoke = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'Id=owned\n'))
        diagnostics = []
        self.assertEqual(controller_run(['fixed'], operation='unit-readback', phase='cleanup',
            diagnose=diagnostics.append, timeout=2, deadline=15, clock=lambda: 14.75,
            invoke=invoke), 'Id=owned\n')
        self.assertEqual(invoke.call_args.kwargs['timeout'], 0.25)
        invoke.reset_mock()
        with self.assertRaises(subprocess.TimeoutExpired):
            controller_run(['fixed'], operation='unit-stop', phase='cleanup',
                diagnose=diagnostics.append, deadline=15, clock=lambda: 15, invoke=invoke)
        invoke.assert_not_called()
        self.assertEqual(diagnostics[-1]['timeout_seconds'], 0)

    def test_monitor_timeout_stays_failed_when_owned_cleanup_is_empty(self):
        from execution_guard import monitor_workload, cleanup_owned, controller_run
        diagnostics = []
        result = 125
        def read():
            return controller_run(['fixed'], operation='unit-readback', phase='monitor',
                diagnose=diagnostics.append, invoke=Mock(side_effect=subprocess.TimeoutExpired('fixed', 15)))
        with self.assertRaises(subprocess.TimeoutExpired):
            result = monitor_workload(read, 20, lambda: None, clock=lambda: 0)
        cleanup = cleanup_owned(deadline=15, readback=Mock(), authorize=Mock(), stop=Mock(),
                                observe=lambda: 'empty', clock=lambda: 0)
        self.assertEqual(cleanup['state'], 'empty')
        self.assertEqual(result, 125)
        self.assertEqual(diagnostics[0]['phase'], 'monitor')

    def test_cleanup_retry_stop_and_observation_share_original_deadline(self):
        from execution_guard import cleanup_owned
        clock = FakeClock()
        events = []
        state = ['populated']
        def read(timeout, deadline):
            events.append(('read', timeout, deadline))
            if len(events) == 1:
                clock.advance(timeout)
                raise subprocess.TimeoutExpired('fixed', timeout)
            return {'Id': 'owned'}
        def stop(timeout, deadline):
            events.append(('stop', timeout, deadline))
            clock.advance(10)
            state[0] = 'empty'
        authority = Mock()
        summary = cleanup_owned(deadline=15, readback=read, authorize=authority, stop=stop,
            observe=lambda: state[0], clock=clock, pause=clock.advance)
        self.assertEqual(summary['state'], 'empty')
        self.assertEqual(summary['readback_attempts'], 2)
        self.assertEqual(summary['stop'], 'succeeded')
        authority.assert_called_once_with({'Id': 'owned'})
        self.assertEqual([row[2] for row in events], [15, 15, 15])
        self.assertEqual([row[1] for row in events[:2]], [2, 2])
        self.assertLessEqual(events[-1][1], 15 - 2.1)
        self.assertLess(clock(), 15)

    def test_cleanup_query_timeout_budget_expires_without_stop(self):
        from execution_guard import cleanup_owned
        clock = FakeClock()
        budgets = []
        def read(timeout, deadline):
            self.assertEqual(deadline, 15)
            budgets.append(timeout)
            clock.advance(timeout)
            raise subprocess.TimeoutExpired('fixed', timeout)
        stop = Mock()
        summary = cleanup_owned(deadline=15, readback=read, authorize=Mock(), stop=stop,
            observe=lambda: 'populated', clock=clock, pause=clock.advance)
        self.assertEqual(summary['state'], 'deadline-exhausted')
        self.assertLessEqual(len(budgets), 8)
        self.assertTrue(all(0 < budget <= 2 for budget in budgets))
        self.assertAlmostEqual(clock(), 15)
        stop.assert_not_called()

    def test_cleanup_expired_before_or_during_ownership_never_stops(self):
        from execution_guard import cleanup_owned
        clock = FakeClock(15)
        read, stop, observe = Mock(), Mock(), Mock()
        summary = cleanup_owned(deadline=15, readback=read, authorize=Mock(), stop=stop,
                                observe=observe, clock=clock, pause=clock.advance)
        self.assertEqual(summary['state'], 'deadline-exhausted')
        read.assert_not_called()
        observe.assert_not_called()
        stop.assert_not_called()
        clock = FakeClock()
        summary = cleanup_owned(deadline=15, readback=lambda budget, end: {},
            authorize=lambda actual: clock.advance(15), stop=stop, observe=lambda: 'populated',
            clock=clock, pause=clock.advance)
        self.assertEqual(summary['state'], 'deadline-exhausted')
        stop.assert_not_called()

    def test_cleanup_observation_after_deadline_cannot_prove_empty(self):
        from execution_guard import cleanup_owned
        clock = FakeClock()
        read, stop = Mock(), Mock()
        def observe():
            clock.advance(15)
            return 'empty'
        summary = cleanup_owned(deadline=15, readback=read, authorize=Mock(), stop=stop,
                                observe=observe, clock=clock, pause=clock.advance)
        self.assertEqual(summary['state'], 'deadline-exhausted')
        read.assert_not_called()
        stop.assert_not_called()

    def test_cleanup_uncertain_stop_requires_original_empty_observation(self):
        from execution_guard import cleanup_owned
        for emptied in (False, True):
            clock = FakeClock()
            state = ['populated']
            def stop(budget, deadline):
                clock.advance(10)
                state[0] = 'empty' if emptied else 'populated'
                raise subprocess.TimeoutExpired('fixed', 10)
            summary = cleanup_owned(deadline=15, readback=lambda budget, end: {}, authorize=Mock(),
                stop=stop, observe=lambda: state[0], clock=clock, pause=clock.advance)
            self.assertEqual(summary['state'], 'empty' if emptied else 'deadline-exhausted')
            self.assertEqual(summary['stop'], 'unresolved')
            self.assertLessEqual(clock(), 15)

    def test_cleanup_changed_or_unproved_original_never_stops(self):
        from execution_guard import cleanup_owned
        for initial in ('changed', 'unproved'):
            read, stop = Mock(), Mock()
            summary = cleanup_owned(deadline=15, readback=read, authorize=Mock(), stop=stop,
                                    observe=lambda: initial, clock=lambda: 0)
            self.assertEqual(summary['state'], 'original-' + initial)
            read.assert_not_called()
            stop.assert_not_called()
        states = iter(('populated', 'changed'))
        stop = Mock()
        summary = cleanup_owned(deadline=15, readback=lambda budget, end: {}, authorize=Mock(),
                                stop=stop, observe=lambda: next(states), clock=lambda: 0)
        self.assertEqual(summary['state'], 'original-changed')
        stop.assert_not_called()

    def test_cleanup_refuses_foreign_epoch_group_and_process(self):
        from execution_guard import cleanup_owned, authorize_cleanup
        run = Path('/owned/run')
        unit = 'omux-execution-owned.service'
        cgroup = Path('/sys/fs/cgroup/system.slice') / unit
        actual = {'Id': unit, 'User': '1000', 'Group': '1000',
                  'Environment': 'OMUX_EXECUTION_GUARD=/owned/run',
                  'ExecStart': '{ path=/store/python ; argv[]=/store/python /controller --worker /owned/run -- fixed ; }',
                  'ControlGroup': '/system.slice/' + unit, 'MainPID': '123'}
        with patch('execution_guard.os.getuid', return_value=1000), patch('execution_guard.os.getgid', return_value=1000):
            authorize = lambda row: authorize_cleanup(row, unit=unit, manager='system', run=run,
                python='/store/python', worker='/controller', cgroup=cgroup, original_pid=123,
                original_ticks='456', pid_ticks=lambda pid: '456')
            authorize(actual)
            for changed in ({'Id': 'foreign'}, {'User': '0'}, {'Group': '0'},
                            {'Environment': 'OMUX_EXECUTION_GUARD=/foreign'}, {'ExecStart': 'foreign'},
                            {'ControlGroup': '/foreign/' + unit}, {'MainPID': '124'}):
                clock, stop = FakeClock(), Mock()
                summary = cleanup_owned(deadline=15, readback=lambda budget, end: {**actual, **changed},
                    authorize=authorize, stop=stop, observe=lambda: 'populated', clock=clock, pause=clock.advance)
                self.assertEqual(summary['ownership'], 'refused')
                self.assertEqual(summary['state'], 'deadline-exhausted')
                stop.assert_not_called()
            with self.assertRaises(ValueError):
                authorize_cleanup(actual, unit=unit, manager='system', run=run, python='/store/python',
                    worker='/controller', cgroup=cgroup, original_pid=123, original_ticks='456',
                    pid_ticks=lambda pid: 'new-process')

    def test_partial_dispatch_capture_requires_second_fresh_ownership_read(self):
        from execution_guard import cleanup_owned, capture_cleanup_pin, authorize_cleanup
        clock = FakeClock()
        pin = [None]
        state = ['populated']
        rows = []
        unit = 'omux-execution-owned.service'
        run = Path('/owned/run')
        name = '/system.slice/' + unit
        facts = {'Id': unit, 'User': '1000', 'Group': '1000',
                 'Environment': 'OMUX_EXECUTION_GUARD=/owned/run',
                 'ExecStart': '{ path=/store/python ; argv[]=/store/python /controller --worker /owned/run -- fixed ; }',
                 'ControlGroup': name, 'MainPID': '123'}
        selected = dict(unit=unit, manager='system', run=run, python='/store/python', worker='/controller')
        original = SimpleNamespace(path=Path('/sys/fs/cgroup') / name.lstrip('/'),
                                   observe=lambda: state[0], close=Mock())
        def read(budget, deadline):
            rows.append(dict(facts))
            return rows[-1]
        def authorize(row):
            if pin[0] is None:
                pin[0], pid, ticks = capture_cleanup_pin(row, **selected)
                self.assertEqual((pid, ticks), (123, '456'))
                return False
            self.assertEqual(len(rows), 2)
            authorize_cleanup(row, **selected, cgroup=pin[0].path,
                              original_pid=123, original_ticks='456', pid_ticks=lambda pid: '456')
        def stop(budget, deadline):
            self.assertEqual(len(rows), 2)
            state[0] = 'empty'
        with patch('execution_guard.os.getuid', return_value=1000), patch('execution_guard.os.getgid', return_value=1000), \
                patch('execution_guard.process_start_ticks', return_value='456'), \
                patch('execution_guard.Path.read_text', return_value='0::' + name + '\n'), \
                patch('execution_guard.CgroupPin', return_value=original) as capture:
            summary = cleanup_owned(deadline=15, readback=read, authorize=authorize, stop=stop,
                observe=lambda: pin[0].observe() if pin[0] else 'uncaptured', clock=clock, pause=clock.advance)
            capture.assert_called_once_with(original.path)
        self.assertEqual(summary['state'], 'empty')
        self.assertEqual(summary['readback_attempts'], 2)
        self.assertEqual(summary['ownership'], 'verified')

    def test_partial_dispatch_refuses_foreign_marker_and_kernel_group(self):
        from execution_guard import capture_cleanup_pin
        unit = 'omux-execution-owned.service'
        name = '/system.slice/' + unit
        actual = {'Id': unit, 'User': '1000', 'Group': '1000', 'MainPID': '123',
                  'Environment': 'OMUX_EXECUTION_GUARD=/owned/run', 'ControlGroup': name,
                  'ExecStart': '{ path=/store/python ; argv[]=/store/python /controller --worker /owned/run -- fixed ; }'}
        selected = dict(unit=unit, manager='system', run=Path('/owned/run'), python='/store/python', worker='/controller')
        with patch('execution_guard.os.getuid', return_value=1000), patch('execution_guard.os.getgid', return_value=1000), \
                patch('execution_guard.process_start_ticks', return_value='456'), \
                patch('execution_guard.Path.read_text', return_value='0::/foreign\n'), \
                patch('execution_guard.CgroupPin') as capture:
            for changed in ({'Environment': 'OMUX_EXECUTION_GUARD=/foreign'}, {}, {'MainPID': '0'}):
                with self.assertRaises(ValueError):
                    capture_cleanup_pin({**actual, **changed}, **selected)
            capture.assert_not_called()

    def test_pinned_original_group_refuses_empty_replacement_and_unwinds(self):
        from execution_guard import CgroupPin
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / 'original'
            original.mkdir()
            (original / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
            pin = CgroupPin(original)
            try:
                self.assertEqual(pin.observe(), 'populated')
                original.rename(Path(directory) / 'retained')
                original.mkdir()
                (original / 'cgroup.events').write_text('populated 0\n')
                self.assertEqual(pin.observe(), 'changed')
            finally:
                pin.close()
                pin.close()
        with patch('execution_guard.os.open', return_value=42), patch('execution_guard.os.fstat', side_effect=OSError('fixed')):
            with patch('execution_guard.os.close') as close:
                with self.assertRaises(OSError):
                    CgroupPin(Path('/fixed'))
                close.assert_called_once_with(42)

    def test_pre_epoch_state_custody_and_free_space_stages_are_distinct(self):
        import execution_guard as guard
        with patch('execution_guard.validate_coordination', return_value=Path('/owned/state')):
            with patch('execution_guard.private', side_effect=ValueError('sensitive')), patch('execution_guard.check_free_space') as free:
                with self.assertRaises(ValueError) as error:
                    guard.prepare_state(Path('/owned/state'), 'standard', None)
                self.assertEqual(guard.rejection_diagnostic(error.exception, guard.DIAGNOSTIC_STAGE),
                    'execution containment rejected; stage=state-custody; exception=ValueError')
                free.assert_not_called()
            with patch('execution_guard.private'), patch('execution_guard.check_free_space', side_effect=ValueError('sensitive')):
                with self.assertRaises(ValueError) as error:
                    guard.prepare_state(Path('/owned/state'), 'standard', None)
                self.assertEqual(guard.rejection_diagnostic(error.exception, guard.DIAGNOSTIC_STAGE),
                    'execution containment rejected; stage=state-free-space; exception=ValueError')

    def test_standard_formatter_requires_exact_finite_source_selection(self):
        base = ['run', '//:format', '--', 'src/main.zig', 'src/setup_collector.zig', 'src/setup_collector_tests.zig']
        for args in (base, base + ['src/engine.zig'], ['run', '//:format', '--', 'src']):
            selected = bazel_command('/store/bazel', Path('/owned/run'), args)
            self.assertEqual(selected[-len(args[1:]):], args[1:])
            self.assertIn('--sandbox_default_allow_network=false', selected)
        rejected = (['run', '//:format'], ['run', '//:format', '--'],
                    base + ['src/main.zig'], base + ['src/arbitrary.zig'],
                    base + ['src/engine.zig', 'src/engine.zig'], base + ['src/engine.zig', 'src/arbitrary.zig'],
                    base + ['src/../private.zig'], base + ['--check'], base + ['src/setup_verification/control.zig'],
                    ['run', '//:format', '--', 'tools'], ['run', '//:format', '--', '.'],
                    ['run', '//:format', '--', 'src/../tools'], ['run', '//:format', '--', '/absolute/src'],
                    ['run', '//:format', '--', 'src', '--check'], ['run', '//:format', '--', 'src', 'src'],
                    ['run', '//:arbitrary'] + base[2:])
        for args in rejected:
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/owned/run'), args)
        for profile in ('installed-browser', 'dependency-prefetch', 'codex-sdk', 'site'):
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/owned/run'), base, profile=profile)

    def test_portable_launcher_formatter_is_one_exact_standard_selection(self):
        arguments = ['run', '//delivery:linux_launcher_format', '--', 'delivery/linux_launcher.zig']
        selected = bazel_command('/store/bazel', Path('/owned/run'), arguments)
        self.assertEqual(selected[-len(arguments[1:]):], arguments[1:])
        self.assertIn('--sandbox_default_allow_network=false', selected)
        for changed in (arguments[:-1], arguments + ['--check'],
                        arguments[:-1] + ['delivery'],
                        arguments[:-1] + ['/absolute/linux_launcher.zig'],
                        arguments[:-1] + ['delivery/../tools/execution_guard.py'],
                        ['run', '//:format', '--', 'delivery/linux_launcher.zig']):
            with self.subTest(arguments=changed), self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/owned/run'), changed)
        for profile in ('installed-browser', 'dependency-prefetch', 'codex-sdk', 'site'):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/owned/run'), arguments, profile=profile)

    def test_site_requires_both_effective_masks_for_each_manager(self):
        from system_mask_policy import setting
        with tempfile.TemporaryDirectory() as temporary:
            service = FakeService(Path(temporary))
            for manager in ('user', 'system'):
                service.actual['InaccessiblePaths'] = ' '.join(blocked_paths())
                if manager == 'system':
                    service.actual['TemporaryFileSystem'] = setting(profile='site')
                with self.assertRaises(ValueError):
                    verify(service.actual, service.root, manager=manager, profile='site')
                service.actual['InaccessiblePaths'] = ' '.join(blocked_paths('site'))
                verify(service.actual, service.root, manager=manager, profile='site')
            self.assertEqual(service.actual['PrivateNetwork'], 'yes')

    def test_site_admission_rejects_generic_execution_before_tool_reads(self):
        from execution_guard import main
        baseline = ['--profile', 'site', '--site-phase', 'checks',
                    '--site-source', '/srv/fast-local/jess/git/omux.xoxd.ai',
                    '--site-inventory', '/owned/inventory.json', '--site-inventory-sha256', 'a' * 64,
                    '--site-qualification', '/owned/qualification.json', '--site-qualification-sha256', 'b' * 64]
        for arguments in (['test', '//...'], ['run', '//:dev'], ['test', '//:unit_tests', '--jobs=9'],
                          ['test', '//:unit_tests', '//:unit_tests']):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(baseline + ['--'] + arguments)
                reader.assert_not_called()
        with patch('execution_guard.immutable') as reader:
            with self.assertRaises(ValueError):
                main(baseline + ['--zig-sdk', '/nix/store/runtime-zig', '--', 'test', '//:unit_tests'])
            reader.assert_not_called()
        with self.assertRaises(ValueError):
            main(['--profile', 'standard', '--site-phase', 'checks', '--', 'test', '//:unit_tests'])

    def test_site_lock_network_exception_requires_exact_phase_and_command(self):
        from execution_guard import main
        from guard_site_profile import phase_isolation
        selected = ['mod', 'deps', '--lockfile_mode=update']
        with tempfile.TemporaryDirectory() as directory:
            service = FakeService(Path(directory))
            service.actual['InaccessiblePaths'] = ' '.join(blocked_paths('site'))
            isolation = {**SANDBOX, **phase_isolation('lock', selected)}
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='site', isolation=isolation)
            service.actual['PrivateNetwork'] = 'no'
            verify(service.actual, service.root, profile='site', isolation=isolation)
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='site')
        baseline = ['--profile', 'site', '--site-phase', 'lock', '--site-source', '/site',
                    '--site-inventory', '/owned/inventory.json', '--site-inventory-sha256', 'a' * 64,
                    '--site-qualification', '/owned/report.json', '--site-qualification-sha256', 'b' * 64]
        for args in (['mod', 'deps'], selected + ['--registry=unselected'], ['mod', 'tidy', '--lockfile_mode=update'],
                     ['test', '//:unit_tests'], ['build', '//:build']):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(baseline + ['--'] + args)
                reader.assert_not_called()
        for option in ('--zig-sdk', '--sdk-source-root', '--codex-recovery-source', '--nixpkgs-source'):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(baseline + [option, '/unrelated/input', '--'] + selected)
                reader.assert_not_called()

    def test_site_fetch_rejects_general_network_execution_before_tool_reads(self):
        from execution_guard import main
        from guard_site_profile import phase_isolation
        selected = ['fetch', '//:unit_tests']
        self.assertEqual(phase_isolation('fetch', selected), {'PrivateNetwork': 'no'})
        with tempfile.TemporaryDirectory() as directory:
            service = FakeService(Path(directory))
            service.actual['InaccessiblePaths'] = ' '.join(blocked_paths('site'))
            isolation = {**SANDBOX, **phase_isolation('fetch', selected)}
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='site', isolation=isolation)
            service.actual['PrivateNetwork'] = 'no'
            verify(service.actual, service.root, profile='site', isolation=isolation)
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='site')
        baseline = ['--profile', 'site', '--site-phase', 'fetch', '--site-source', '/site',
                    '--site-inventory', '/owned/inventory.json', '--site-inventory-sha256', 'a' * 64,
                    '--site-qualification', '/owned/report.json', '--site-qualification-sha256', 'b' * 64]
        for args in (['fetch'], ['fetch', '//...'], ['fetch', '//:unit_tests', '//:dev'],
                     selected + ['--build'], selected + ['--lockfile_mode=update'],
                     selected + ['//:unit_tests'], ['build', '//:build'], ['run', '//:preview']):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(baseline + ['--'] + args)
                reader.assert_not_called()
        for option in ('--zig-sdk', '--sdk-source-root', '--codex-recovery-source', '--nixpkgs-source'):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(baseline + [option, '/unrelated/input', '--'] + selected)
                reader.assert_not_called()

    def test_site_import_arguments_must_match_admitted_selection(self):
        from execution_guard import main
        selected = ['--profile', 'site', '--site-phase', 'import', '--site-source', '/site',
                    '--site-inventory', '/owned/inventory.json', '--site-inventory-sha256', 'a' * 64,
                    '--site-qualification', '/owned/report.json', '--site-qualification-sha256', 'b' * 64,
                    '--site-delivery-manifest', '/owned/manifest.json', '--site-delivery-manifest-sha256', 'c' * 64]
        for args in (['run', '//:preview'],
                     ['run', '//:import_extension_delivery', '--', '--manifest', '/other/manifest.json', '--sha256', 'c' * 64],
                     ['run', '//:import_extension_delivery', '--', '--manifest', '/owned/manifest.json', '--sha256', 'd' * 64]):
            with patch('execution_guard.immutable') as reader:
                with self.assertRaises(ValueError):
                    main(selected + ['--'] + args)
                reader.assert_not_called()

    def test_reference_import_selection_rejected_before_tool_admission(self):
        from execution_guard import main
        selected = ['--profile', 'site', '--site-phase', 'reference-import', '--site-source', '/site',
                    '--site-inventory', '/owned/inventory.json', '--site-inventory-sha256', 'a' * 64,
                    '--site-qualification', '/owned/report.json', '--site-qualification-sha256', 'b' * 64,
                    '--site-reference-bundle', '/owned/reference-bundle.json', '--site-reference-bundle-sha256', 'c' * 64]
        args = ['run', '//:import_reference', '--', '--bundle', '/owned/reference-bundle.json', '--sha256', 'c' * 64]
        cases = [(selected, ['run', '//:preview']),
                 (selected, args[:-1] + ['d' * 64]),
                 (selected, args[:4] + ['/other/reference-bundle.json'] + args[5:]),
                 (selected + ['--site-delivery-manifest', '/owned/metadata.json'], args),
                 (selected + ['--site-delivery-manifest-sha256', 'd' * 64], args),
                 (['--profile', 'standard', '--site-reference-bundle', '/owned/reference-bundle.json'], ['test', '//:all']),
                 (['--profile', 'site', '--site-phase', 'checks', '--site-reference-bundle-sha256', 'c' * 64], ['test', '//:unit_tests'])]
        for options, arguments in cases:
            with patch('execution_guard.immutable') as reader, self.assertRaises(ValueError):
                main(options + ['--'] + arguments)
            reader.assert_not_called()

    def test_site_inventory_accepts_original_epoch_output_with_exact_digest_and_suffix(self):
        # Model only external sandbox ancestry; retain real selected-root custody.
        def fixture_private(path, owner_only=True):
            self.assertEqual(path, state)
            self.assertIs(owner_only, True)
            self.assertEqual(state.resolve(strict=True), state)
            metadata = state.lstat()
            self.assertTrue(stat.S_ISDIR(metadata.st_mode))
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
        with tempfile.TemporaryDirectory() as directory, patch('execution_guard.private', side_effect=fixture_private):
            state = Path(directory).resolve(strict=True)
            epoch = state / '72bf2f84-641d-4ca2-8aeb-4e42d279aaf7'
            suffix = 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/cached_site_inventory_probe/test.outputs/inventory.json'
            inventory = epoch / suffix
            inventory.parent.mkdir(parents=True)
            content = b'{"public":"current-inventory-fixture"}\n'
            inventory.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual(selected_site_inventory(inventory, digest, state), inventory)
            for wrong in (state / 'unselected' / suffix,
                          epoch / suffix.replace('cached_site_inventory_probe', 'other_producer'),
                          inventory.with_name('other.json'),
                          state / '72BF2F84-641D-4CA2-8AEB-4E42D279AAF7' / suffix):
                with self.assertRaises(ValueError):
                    selected_site_inventory(wrong, digest, state)
            with self.assertRaises(ValueError):
                selected_site_inventory(inventory, '0' * 64, state)
            inventory.chmod(0o666)
            with self.assertRaises(ValueError):
                selected_site_inventory(inventory, digest, state)

    def test_closed_site_coordinator_selection_rejects_other_vectors_before_tool_admission(self):
        from execution_guard import main
        flags = ['--site-coordinator-inputs', '/owned/site-coordinator-inputs.json',
                 '--site-coordinator-inputs-sha256', 'a' * 64]
        vectors = [flags + ['--', 'test', '//:docs_check'],
                   flags + ['--', 'test', '//tools:site_coordinator_binary_qualification', '//:docs_check'],
                   ['--profile', 'site'] + flags + ['--', 'test', '//tools:site_coordinator_binary_qualification'],
                   ['--', 'test', '//tools:site_coordinator_binary_qualification']]
        for vector in vectors:
            with patch('execution_guard.immutable') as tools, self.assertRaises(ValueError):
                main(vector)
            tools.assert_not_called()

    def test_both_selected_site_coordinator_repo_values_enter_declared_command(self):
        import site_coordinator_selection as selected
        path = Path('/owned/site-coordinator-inputs.json')
        digest = 'a' * 64
        with patch.object(selected, 'admitted', return_value=True) as admission:
            command = bazel_command('/bazel', Path('/owned/run'),
                ['test', '//tools:site_coordinator_binary_qualification'],
                site_source=Path('/owned/omux.xoxd.ai'), site_coordinator_inputs=path,
                site_coordinator_inputs_sha256=digest)
        admission.assert_called_once_with('standard',
            ['test', '//tools:site_coordinator_binary_qualification'], path, digest)
        self.assertIn('--repo_env=OMUX_SITE_COORDINATOR_INPUTS=' + str(path), command)
        self.assertIn('--repo_env=OMUX_SITE_COORDINATOR_INPUTS_SHA256=' + digest, command)
        self.assertEqual(command[-1], '//tools:site_coordinator_binary_qualification')
        with patch.object(selected, 'admitted', return_value=True), self.assertRaises(ValueError):
            bazel_command('/bazel', Path('/owned/run'),
                ['test', '//tools:site_coordinator_binary_qualification'],
                site_coordinator_inputs=path, site_coordinator_inputs_sha256=digest)

    def test_reference_receipt_only_accepts_declared_stdout_producer(self):
        from execution_guard import selected_site_receipt
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / ('cache-v2-' + 'a' * 64) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/bin/reference-bundle.json'
            selected.parent.mkdir(parents=True)
            selected.write_text('{"provenance":{"sourceRevision":null,"sourceDirty":true}}\n')
            digest = hashlib.sha256(selected.read_bytes()).hexdigest()
            with patch('execution_guard.private'), patch('guard_site_profile.bounded_file') as reader:
                self.assertEqual(selected_site_receipt(selected, digest, root, root, 'reference'), selected)
                reader.assert_called_once_with(selected, digest, 2 * 1024 * 1024)
                for wrong in (selected.with_name('arbitrary.json'), selected.parent / 'delivery/chromium_dev_metadata.json'):
                    with self.assertRaises(ValueError):
                        selected_site_receipt(wrong, digest, root, root, 'reference')

    def test_site_receipt_selector_refuses_unowned_and_arbitrary_outputs(self):
        from execution_guard import selected_site_receipt
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / ('cache-v2-' + 'a' * 64) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/chromium_dev_metadata.json'
            selected.parent.mkdir(parents=True)
            selected.write_text('{}')
            digest = hashlib.sha256(b'{}').hexdigest()
            with patch('execution_guard.private'), patch('guard_site_profile.bounded_file') as reader:
                self.assertEqual(selected_site_receipt(selected, digest, root, root, 'manifest'), selected)
                reader.assert_called_once_with(selected, digest, 16384)
                for path in (root / 'manifest.json', selected.parent / 'arbitrary.json',
                             Path('/unselected') / selected.relative_to(root)):
                    with self.assertRaises(ValueError):
                        selected_site_receipt(path, digest, root, root, 'manifest')

    def test_sdk_cache_provenance_binds_inputs_but_not_selected_lane(self):
        from execution_guard import sdk_cache_provenance
        from guard_cache import stable_fingerprint
        plan = {'environment': {'PATH': '/nix/store/bash/bin:/nix/store/git/bin', 'STABLE_GIT_COMMIT': 'a' * 40},
                'physical_mode_policy': 'bazel-retained-export-all-regular-and-directories-0555-v1',
                'git_mode_authority': 'sha256-bound-source-receipt-Git-modes'}
        lanes = {'core': ('//sdk:core', 'fixed'), 'protocol': ('//sdk:protocol', None)}
        profile = sdk_cache_provenance(plan, '/fast/source', 'a' * 64, '/home/settings', 'b' * 64, 'c' * 64, lanes, {})
        tools = {'bazel': '/nix/store/fixture/bin/bazel'}
        key = lambda value: stable_fingerprint(Path.cwd(), tools, 1000, 1000, 'user', {'sdk': value})
        self.assertEqual(key(profile), key(dict(profile)))
        for field in ('source_receipt_sha256', 'settings_receipt_sha256', 'bundle_receipt_sha256'):
            changed = {**profile, field: 'd' * 64}
            self.assertNotEqual(key(profile), key(changed))
        for field, value in (('PATH', '/nix/store/other/bin'), ('STABLE_GIT_COMMIT', 'b' * 40)):
            changed = {**profile, 'environment': {**profile['environment'], field: value}}
            self.assertNotEqual(key(profile), key(changed))
        self.assertNotIn('lane', profile)
        self.assertEqual(profile['physical_mode_policy'], plan['physical_mode_policy'])
        self.assertEqual(profile['git_mode_authority'], plan['git_mode_authority'])
        for field in ('physical_mode_policy', 'git_mode_authority'):
            incomplete = dict(plan)
            del incomplete[field]
            with self.assertRaises(ValueError):
                sdk_cache_provenance(incomplete, '/fast/source', 'a' * 64, '/home/settings', 'b' * 64,
                                     'c' * 64, lanes, {})

    def test_sdk_output_base_and_resource_flags_are_owned(self):
        from execution_guard import sdk_owned_command
        plan = {'argv': ('/store/bazel', '--batch', '--ignore_all_rc_files',
                         '--output_base=/producer/fallback', 'test', '//sdk:fixed')}
        run = Path('/private/uuid')
        command = sdk_owned_command(plan, run, Path('/private/cache/output-base'))
        self.assertIn('--output_base=/private/cache/output-base', command)
        self.assertNotIn('--output_base=/producer/fallback', command)
        self.assertIn('--host_jvm_args=-Xmx768m', command)
        self.assertIn('--symlink_prefix=/private/uuid/bazel-', command)
        self.assertIn('--nocache_test_results', command)
        self.assertFalse(any('rules_zig' in value for value in command))
        with self.assertRaises(ValueError):
            sdk_owned_command({'argv': plan['argv'] + ('--output_base=/other',)}, run)

    def test_predispatch_diagnostic_contains_only_static_stage_and_category(self):
        from execution_guard import rejection_diagnostic
        class ArbitrarySecretNamedError(ValueError):
            pass
        message = rejection_diagnostic(ArbitrarySecretNamedError('sensitive payload /private/path'), 'tool/closure')
        self.assertEqual(message, 'execution containment rejected; stage=tool/closure; exception=ValueError')
        self.assertEqual(rejection_diagnostic(OSError('sensitive'), 'arbitrary-sensitive-stage'),
                         'execution containment rejected; stage=unknown; exception=OSError')
        self.assertNotIn('sensitive', message)

    def test_sampled_free_floor_refuses_low_available_blocks(self):
        from execution_guard import check_free_space, FREE_FLOOR
        with patch('execution_guard.os.statvfs', return_value=SimpleNamespace(f_bavail=FREE_FLOOR, f_frsize=1)):
            self.assertEqual(check_free_space(Path('/private/state')), FREE_FLOOR)
        with patch('execution_guard.os.statvfs', return_value=SimpleNamespace(f_bavail=FREE_FLOOR - 1, f_frsize=1)):
            with self.assertRaises(ValueError):
                check_free_space(Path('/private/state'))

    def test_recovery_repository_input_is_fixed_and_standard_only(self):
        from guard_dependency_profile import RECOVERY_DIRECTORY, recovery_source
        validator = Mock()
        self.assertEqual(recovery_source(RECOVERY_DIRECTORY, validator), RECOVERY_DIRECTORY)
        validator.assert_called_once_with(RECOVERY_DIRECTORY, owner_only=False)
        command = bazel_command('/store/bazel', Path('/private/run'), ['test', '//:producer'],
                                codex_recovery_source=RECOVERY_DIRECTORY)
        self.assertIn('--repo_env=OMUX_CODEX_RECOVERY_SOURCE=' + str(RECOVERY_DIRECTORY), command)
        for source, profile in ((Path('/private/arbitrary'), 'standard'),
                                (RECOVERY_DIRECTORY, 'installed-browser'),
                                (RECOVERY_DIRECTORY, 'dependency-prefetch')):
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/private/run'), ['test', '//:producer'],
                              codex_recovery_source=source, profile=profile)

    def test_browser_marker_requires_exact_masked_profile(self):
        arguments = ['test', '//delivery:installed_chromium_test']
        flag = '--test_env=OMUX_BROWSER_HOST_CONFIGURATION=host-configurations-unavailable'
        self.assertIn(flag, bazel_command('/store/bazel', Path('/private/run'), arguments,
                                         profile='installed-browser'))
        self.assertNotIn(flag, bazel_command('/store/bazel', Path('/private/run'), arguments))
        self.assertNotIn(flag, bazel_command('/store/bazel', Path('/private/run'),
                                            ['test', '//tools:fetch_codex_archives_bundle'],
                                            profile='dependency-prefetch'))
        with self.assertRaises(ValueError):
            bazel_command('/store/bazel', Path('/private/run'), ['test', '//:other'],
                          profile='installed-browser')

    def test_installed_browser_requires_effective_bluetooth_mask(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = FakeService(Path(temporary))
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='installed-browser')
            service.actual['InaccessiblePaths'] += ' /etc/bluetooth'
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, profile='installed-browser')
            service.actual['InaccessiblePaths'] += ' /etc/environment'
            verify(service.actual, service.root, profile='installed-browser')
        self.assertNotIn('/etc/bluetooth', blocked_paths())
        self.assertNotIn('/etc/environment', blocked_paths())
        with self.assertRaises(ValueError):
            blocked_paths('arbitrary')

    def test_system_browser_requires_regular_file_environment_mask(self):
        from system_mask_policy import setting
        with tempfile.TemporaryDirectory() as temporary:
            service = FakeService(Path(temporary))
            service.actual['TemporaryFileSystem'] = setting(profile='installed-browser')
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, manager='system', profile='installed-browser')
            service.actual['InaccessiblePaths'] += ' -/etc/environment'
            verify(service.actual, service.root, manager='system', profile='installed-browser')

    def test_only_exact_output_probe_lifts_bazel_display_limit(self):
        flag = '--experimental_ui_max_stdouterr_bytes=10485760'
        command = lambda args: bazel_command('/store/bazel', Path('/private/run'), args)
        self.assertIn(flag, command(['test', '//tools:execution_probe_output']))
        for arguments in (['build', '//tools:execution_probe_output'],
                          ['test', '//tools:execution_probe_output', '//:other'],
                          ['test', '//tools:all'], ['test', '//...']):
            self.assertNotIn(flag, command(arguments))

    def test_no_block_startup_waits_for_queued_inactive_job(self):
        states = iter([{'ActiveState': state} for state in ('inactive', 'activating', 'active')])
        actual, history = await_startup(lambda: next(states), clock=lambda: 0,
                                        pause=lambda seconds: None)
        self.assertEqual(actual['ActiveState'], 'active')
        self.assertEqual([row['ActiveState'] for row in history], ['inactive', 'activating', 'active'])

    def test_startup_failure_and_deadline_are_finite(self):
        actual, history = await_startup(lambda: {'ActiveState': 'failed'}, clock=lambda: 0,
                                        pause=lambda seconds: self.fail('failed service must not wait'))
        self.assertEqual(actual['ActiveState'], 'failed')
        self.assertEqual(len(history), 1)
        ticks = iter((0, 0, 10))
        actual, history = await_startup(lambda: {'ActiveState': 'inactive'},
                                        clock=lambda: next(ticks), pause=lambda seconds: None)
        self.assertEqual(actual['ActiveState'], 'inactive')
        self.assertEqual(len(history), 2)

    def test_dependency_network_override_is_verified_not_assumed(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = FakeService(Path(temporary))
            isolation = {**SANDBOX, 'PrivateNetwork': 'no'}
            with self.assertRaises(ValueError):
                verify(service.actual, service.root, isolation=isolation)
            service.actual['PrivateNetwork'] = 'no'
            verify(service.actual, service.root, isolation=isolation)
            with self.assertRaises(ValueError):
                service.admit()

    def test_pack_input_is_a_fixed_repository_environment_value(self):
        selected = Path('/public/fixed-pack')
        command = bazel_command('/store/bazel', Path('/private/run'), ['test', '//:fixture'],
                                codex_pack_directory=selected)
        self.assertIn('--repo_env=OMUX_CODEX_PACK_DIRECTORY=' + str(selected), command)
        self.assertIn('--batch', command)
        self.assertIn('--nocache_test_results', command)

    def test_site_nixpkgs_input_is_immutable_and_explicitly_scoped(self):
        selected = Path('/nix/store/fixture-site-nixpkgs-source')
        with patch('execution_guard.store_directory', return_value=selected) as validator:
            command = bazel_command('/store/bazel', Path('/private/run'), ['build', '//:site'],
                                    site_source=Path('/public/omux.xoxd.ai'), site_nixpkgs_source=selected)
            validator.assert_called_once_with(selected)
            self.assertIn('--repo_env=OMUX_SITE_NIXPKGS_EVALUATION_SOURCE=' + str(selected), command)
        with self.assertRaises(ValueError):
            bazel_command('/store/bazel', Path('/private/run'), ['build', '//:site'], site_nixpkgs_source=selected)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/private/run'), ['build', '//:site'],
                              site_source=Path('/public/omux.xoxd.ai'), site_nixpkgs_source=Path(directory))

    def test_exact_owned_cached_site_inventory_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            inventory = state / ('cache-' + 'a' * 64) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/cached_site_inventory_probe/test.outputs/inventory.json'
            inventory.parent.mkdir(parents=True)
            content = b'{"public":true}'
            inventory.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            with patch('execution_guard.private'):
                self.assertEqual(selected_site_inventory(inventory, digest, state), inventory)
                fast = Path('/srv/fast-local/jess/state/codex/fixture-fast-state')
                with patch('guard_dependency_profile.COORDINATION_DIRECTORY', state):
                    self.assertEqual(selected_site_inventory(inventory, digest, fast, state), inventory)
                    with self.assertRaises(ValueError):
                        selected_site_inventory(inventory, digest, fast, state / 'arbitrary')
                    with self.assertRaises(ValueError):
                        selected_site_inventory(state / 'private.json', digest, fast, state)
                with self.assertRaises(ValueError):
                    selected_site_inventory(inventory, digest, fast)
                with self.assertRaises(ValueError):
                    selected_site_inventory(inventory, 'b' * 64, state)
                with self.assertRaises(ValueError):
                    selected_site_inventory(state / 'private.json', digest, state)
                inventory.unlink()
                inventory.symlink_to(state / 'private.json')
                with self.assertRaises(OSError):
                    selected_site_inventory(inventory, digest, state)
            command = bazel_command('/store/bazel', state / 'run', ['build', '//:site'],
                                    site_inventory=inventory, site_inventory_sha256=digest)
            self.assertIn('--repo_env=OMUX_SITE_INVENTORY_SHA256=' + digest, command)

    def test_site_selection_only_reads_exact_public_sibling_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / 'oauth-mux'
            repository.mkdir()
            site = root / 'omux.xoxd.ai'
            site.mkdir()
            (site / 'tools').mkdir()
            for relative in ('flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'):
                (site / relative).write_text('public fixture')
                (site / relative).chmod(0o644)
            selected, digests = selected_site_source(site, repository)
            self.assertEqual(selected, site)
            self.assertEqual(set(digests), {'flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'})
            command = bazel_command('/store/bazel', root / 'run', ['test', '//:site_check'], site_source=selected)
            self.assertIn('--repo_env=OMUX_SITE_SOURCE=' + str(site), command)
            with self.assertRaises(ValueError):
                selected_site_source(repository, repository)
            alias = root / 'site-alias'
            alias.symlink_to(site, target_is_directory=True)
            with self.assertRaises(ValueError):
                selected_site_source(alias, repository)
            with self.assertRaises(ValueError):
                selected_site_source(site / '..' / 'omux.xoxd.ai', repository)
            (site / 'flake.lock').chmod(0o600)
            with self.assertRaises(ValueError):
                selected_site_source(site, repository)
            (site / 'flake.lock').unlink()
            (site / 'flake.lock').symlink_to(site / 'flake.nix')
            with self.assertRaises(OSError):
                selected_site_source(site, repository)

    def test_owned_site_selection_is_exact_and_cache_identity_stays_per_checkout(self):
        from guard_cache import stable_fingerprint
        from site_coordinator_qualification import SITE_VERSION_SHA256
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            repository = root / 'resident-continuity'
            repository.mkdir()
            site = root / 'omux-site-owned-v9'
            site.mkdir()
            (site / '.git').mkdir()
            (site / 'tools').mkdir()
            (site / '.bazelversion').write_bytes(b'9.0.1\n')
            for relative in ('flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'):
                (site / relative).write_text('public fixture')
                (site / relative).chmod(0o644)
            # Reuse the existing custody fixture's bounded version-reader seam:
            # temp roots may have a world-writable ancestor. The selector and
            # private-parent/Git/public-input filesystem checks here are real.
            with patch('guard_site_profile.bounded_file', return_value=b'9.0.1\n') as version:
                selected, digests = selected_site_source(site, repository)
                version.assert_called_once_with(site / '.bazelversion', SITE_VERSION_SHA256, 64)
            self.assertEqual(selected, site)
            self.assertEqual(set(digests), {'flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'})
            other = root / 'other-site'
            other.mkdir()
            with self.assertRaises(ValueError): selected_site_source(other, repository)
            alias = root / 'omux.xoxd.ai'
            alias.symlink_to(site, target_is_directory=True)
            with self.assertRaises(ValueError): selected_site_source(alias, repository)
            with self.assertRaises(ValueError): selected_site_source(site / '..' / site.name, repository)
            alias.unlink(); alias.mkdir()
            inputs = {'bazel': '/nix/store/public-bazel'}
            self.assertNotEqual(stable_fingerprint(site, inputs, os.getuid(), os.getgid(), 'system', {}),
                stable_fingerprint(alias, inputs, os.getuid(), os.getgid(), 'system', {}))

    def test_owned_site_selection_keeps_private_git_version_and_public_leaf_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            repository = root / 'resident-continuity'; repository.mkdir()
            site = root / 'omux-site-owned-v9'; site.mkdir()
            git = site / '.git'; git.mkdir()
            (site / 'tools').mkdir()
            for relative in ('flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'):
                (site / relative).write_text('public fixture'); (site / relative).chmod(0o644)
            with patch('guard_site_profile.bounded_file', return_value=b'9.0.1\n'):
                root.chmod(0o755)
                with self.assertRaises(ValueError): selected_site_source(site, repository)
                root.chmod(0o700)
                git.rmdir(); git.write_text('gitdir: /foreign/shared')
                with self.assertRaises(ValueError): selected_site_source(site, repository)
                git.unlink(); git.mkdir(); (git / 'commondir').write_text('/foreign/shared')
                with self.assertRaises(ValueError): selected_site_source(site, repository)
                (git / 'commondir').unlink(); (git / 'objects/info').mkdir(parents=True)
                (git / 'objects/info/alternates').write_text('/foreign/shared')
                with self.assertRaises(ValueError): selected_site_source(site, repository)
                (git / 'objects/info/alternates').unlink()
                leaf = site / 'flake.lock'; leaf.chmod(0o600)
                with self.assertRaises(ValueError): selected_site_source(site, repository)
                leaf.unlink(); leaf.symlink_to(site / 'flake.nix')
                with self.assertRaises(OSError): selected_site_source(site, repository)
            with patch('guard_site_profile.bounded_file', return_value=b'8.4.2\n'):
                with self.assertRaises(ValueError): selected_site_source(site, repository)

    def test_become_descriptor_predicates_without_payload(self):
        valid = dict(st_mode=stat.S_IFREG | 0o400, st_uid=1000, st_nlink=1, st_size=32)
        validate_become_metadata(SimpleNamespace(**valid), 1000)
        for replacement in ({'st_mode': stat.S_IFREG | 0o644}, {'st_uid': 0},
                            {'st_nlink': 2}, {'st_size': 0}, {'st_size': 4097},
                            {'st_mode': stat.S_IFLNK | 0o600}):
            with self.assertRaises(ValueError):
                validate_become_metadata(SimpleNamespace(**{**valid, **replacement}), 1000)

    def test_system_identity_requires_host_root_mapping_and_no_capabilities(self):
        actual = {'User': '1000', 'Group': '1000', 'PrivateUsers': 'no',
                  'CapabilityBoundingSet': '', 'AmbientCapabilities': '', 'StandardInput': 'null'}
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            worker = proc / '123'
            worker.mkdir()
            status = 'Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t0000\nCapPrm:\t0000\nCapAmb:\t0000\n'
            (worker / 'status').write_text(status)
            for name in ('uid_map', 'gid_map'):
                (worker / name).write_text('0 0 4294967295\n')
            with patch('execution_guard.os.getuid', return_value=1000), patch('execution_guard.os.getgid', return_value=1000):
                system_identity(actual, 123, proc)
                (worker / 'uid_map').write_text('1000 1000 1\n')
                with self.assertRaises(ValueError):
                    system_identity(actual, 123, proc)
                (worker / 'uid_map').write_text('0 0 4294967295\n')
                (worker / 'status').write_text(status.replace('CapEff:\t0000', 'CapEff:\t0001'))
                with self.assertRaises(ValueError):
                    system_identity(actual, 123, proc)
                (worker / 'status').write_text(status)
                for key in actual:
                    with self.assertRaises(ValueError):
                        system_identity({**actual, key: 'unexpected'}, 123, proc)

    def test_all_effective_limits_required(self):
        with tempfile.TemporaryDirectory() as directory:
            service = FakeService(Path(directory))
            service.admit()
            for key in (*PROPERTIES, *SANDBOX, 'InaccessiblePaths', 'UnsetEnvironment'):
                old = service.actual.pop(key)
                with self.assertRaises(ValueError):
                    service.admit()
                service.actual[key] = old


    def test_native_phase2_readback_keeps_actual_memory_tasks_cpu_and_remaining_deadline_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            service=FakeService(Path(directory))
            service.actual['RuntimeMaxUSec']='45min'
            verify(service.actual,service.root,profile='codex-native',
                runtime_seconds=2700,native_phase2=True)
            for profile,selected in (('codex-native',False),('standard',True),
                    ('yoga-controller-delivery',True)):
                with self.subTest(profile=profile,selected=selected),self.assertRaises(ValueError):
                    verify(service.actual,service.root,profile=profile,
                        runtime_seconds=2700,native_phase2=selected)
            for value in ('46min','infinity','2700'):
                with self.subTest(value=value),self.assertRaises(ValueError):
                    verify({**service.actual,'RuntimeMaxUSec':value},service.root,
                        profile='codex-native',runtime_seconds=2700,native_phase2=True)
            for key in ('MemoryMax','TasksMax','CPUQuotaPerSecUSec'):
                with self.subTest(key=key),self.assertRaises(ValueError):
                    verify({**service.actual,key:'max'},service.root,
                        profile='codex-native',runtime_seconds=2700,native_phase2=True)
            (service.root/'cpu.max').write_text('300000 100000')
            with self.assertRaises(ValueError):
                verify(service.actual,service.root,profile='codex-native',
                    runtime_seconds=2700,native_phase2=True)

    def test_kernel_limits_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            service = FakeService(Path(directory))
            for key in CGROUP:
                (service.root / key).write_text('max')
                with self.assertRaises(ValueError):
                    service.admit()
                (service.root / key).write_text(CGROUP[key])
            (service.root / 'cpu.max').write_text('max 100000')
            with self.assertRaises(ValueError):
                service.admit()
            (service.root / 'cpu.max').write_text('300000 100000')
            with self.assertRaises(ValueError):
                service.admit()

    def test_batch_and_owned_output_base(self):
        command = bazel_command('/nix/store/example/bin/bazel', Path('/private/uuid'), ['test', '//:docs_check'])
        self.assertEqual(command[1], '--batch')
        private_root = '--output_user_root=/private/uuid/bazel-user-root'
        self.assertEqual([flag for flag in command if flag.startswith('--output_user_root=')], [private_root])
        self.assertIn(private_root, command[:command.index('test')])
        self.assertIn('--output_base=/private/uuid/output-base', command)
        self.assertIn('--noworkspace_rc', command)
        self.assertIn('--remote_executor=', command)
        self.assertIn('--host_jvm_args=-Xmx1536m', command[:command.index('test')])
        self.assertIn('--host_jvm_args=-XX:ActiveProcessorCount=2', command[:command.index('test')])
        for args in ([], ['--batch', 'test'], ['test', '--output_base=/shared'],
                     ['--output_user_root=/shared', 'test', '//:docs_check'],
                     ['test', '//:docs_check', '--output_user_root=/shared'],
                     ['test', '--config=remote'], ['run', '//:delegate']):
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/private/uuid'), args)

    def test_controller_worker_policy_covers_owned_verbs_and_rejects_overrides(self):
        from execution_guard import controller_thread_profile
        policy = controller_thread_profile()
        flags = {'legacy_globbing_threads': '--legacy_globbing_threads=',
                 'fsvc_threads': '--experimental_fsvc_threads=',
                 'loading_phase_threads': '--loading_phase_threads='}
        cases = (
            ('standard', ['build', '//:omux']),
            ('standard', ['test', '//:docs_check']),
            ('codex-live', ['test', '//delivery:installed_codex_live_enrollment_test']),
            ('codex-live', ['test', '//delivery:installed_codex_live_continuity_test']),
            ('dependency-prefetch', ['test', '//tools:fetch_codex_archives_bundle']),
            ('installed-browser', ['test', '//delivery:installed_chromium_test']),
            ('standard', ['run', '//delivery:linux_launcher_format', '--',
                          'delivery/linux_launcher.zig']),
        )
        for profile, arguments in cases:
            with self.subTest(profile=profile, verb=arguments[0]):
                command = bazel_command('/store/bazel', Path('/owned/epoch'), arguments,
                                        profile=profile)
                for field, prefix in flags.items():
                    self.assertEqual([item for item in command if item.startswith(prefix)],
                                     [prefix + str(policy[field])])
                    self.assertGreater(command.index(prefix + str(policy[field])),
                                       command.index(arguments[0]))
                    self.assertLess(command.index(prefix + str(policy[field])),
                                    command.index(arguments[1]))
                self.assertEqual(command.count('--jobs=2'), 1)
                self.assertEqual(command.count('--host_jvm_args=-XX:ActiveProcessorCount=2'), 1)
        for flag in ('--legacy_globbing_threads=100', '--experimental_fsvc_threads=200',
                     '--loading_phase_threads=100', '--config=unbounded',
                     '--host_jvm_args=-XX:ActiveProcessorCount=100'):
            for arguments in (['test', '//:docs_check', flag],
                              ['build', flag, '//:omux'],
                              ['run', '//delivery:linux_launcher_format', '--', flag]):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    bazel_command('/store/bazel', Path('/owned/epoch'), arguments)
        policy['fsvc_threads'] = 200
        policy['loading_phase_threads'] = 200
        self.assertEqual(controller_thread_profile(),
                         {'legacy_globbing_threads': 2, 'fsvc_threads': 2, 'loading_phase_threads': 2})

    def test_controller_worker_policy_partitions_cache_without_changing_limits(self):
        from execution_guard import controller_thread_profile
        from guard_cache import stable_fingerprint
        with tempfile.TemporaryDirectory() as directory:
            inputs = {'bazel': '/nix/store/fixed-bazel/bin/bazel', 'java': '/nix/store/fixed-jdk'}
            execution = {'batch': True, 'jvm_heap_mib': 1536, 'active_processors': 2,
                         'jobs': 2, **controller_thread_profile()}
            def key(selected):
                return stable_fingerprint(directory, inputs, 1000, 1000, 'user',
                                          {'limits': PROPERTIES, 'execution': selected})
            current = key(execution)
            old = {name: value for name, value in execution.items()
                   if name not in controller_thread_profile()}
            self.assertNotEqual(current, key(old))
            without_loading = {name: value for name, value in execution.items() if name != 'loading_phase_threads'}
            self.assertNotEqual(current, key(without_loading))
            for field in controller_thread_profile():
                self.assertNotEqual(current, key({**execution, field: 100}))
            self.assertEqual(PROPERTIES['TasksMax'], '512')
            self.assertEqual(CGROUP['pids.max'], '512')
            self.assertEqual(PROPERTIES['MemoryMax'], '4294967296')
            self.assertEqual(PROPERTIES['CPUQuotaPerSecUSec'], '2s')
            self.assertEqual(PROPERTIES['RuntimeMaxUSec'], '20min')

    def test_fake_show_response(self):
        self.assertEqual(properties('MemoryMax=4294967296\nignored\nKillMode=control-group\n'),
                         {'MemoryMax': '4294967296', 'KillMode': 'control-group'})

    def test_provenance_is_a_narrow_explicit_pair(self):
        command = bazel_command('/store/bazel', Path('/private/uuid'), ['build', '//extensions:chromium_dev_package'],
                                source_commit='a' * 40, source_dirty='true')
        self.assertIn('--define=OMUX_SOURCE_COMMIT=' + 'a' * 40, command)
        self.assertIn('--define=OMUX_SOURCE_DIRTY=true', command)
        for commit, dirty in ((None, 'true'), ('a' * 40, None), ('a' * 39, 'false'),
                              ('a' * 40 + ' --config=remote', 'false'), ('a' * 40, '--remote_executor=x')):
            with self.assertRaises(ValueError):
                bazel_command('/store/bazel', Path('/private/uuid'), ['build', '//:omux'],
                              source_commit=commit, source_dirty=dirty)


class RetainedRuntimeCommandTests(unittest.TestCase):
    def test_unselected_command_clears_ambient_repository_selector(self):
        import guard_owner_runtime_input as retained
        with patch.dict(os.environ, {retained.VARIABLE: "/ambient/untrusted"}):
            command = bazel_command("/store/bazel", Path("/owned/epoch"), ["test", "//:docs_check"])
        self.assertIn("--repo_env=" + retained.VARIABLE + "=", command)
        self.assertNotIn("--repo_env=" + retained.VARIABLE + "=/ambient/untrusted", command)

    def test_only_fixed_offline_labels_forward_explicit_selection(self):
        import guard_owner_runtime_input as retained
        root = Path("/owned") / "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
        command = bazel_command("/store/bazel", Path("/owned/epoch"),
            ["test", "//tools:codex_owner_runtime_input_qualification"],
            codex_owner_runtime_directory=root)
        self.assertIn("--repo_env=" + retained.VARIABLE + "=" + str(root), command)
        self.assertIn("--sandbox_default_allow_network=false", command)
        for args, profile, other in (
                (["test", "//..."], "standard", {}),
                (["test", "//delivery:installed_native_interop_test"], "dependency-prefetch", {}),
                (["test", "//delivery:installed_native_interop_test"], "standard", {"site_source": Path("/site")})):
            with self.assertRaises(ValueError):
                bazel_command("/store/bazel", Path("/owned/epoch"), args,
                    profile=profile, codex_owner_runtime_directory=root, **other)

    def test_dynamic_standard_runtime_limit_cannot_exceed_original_budget(self):
        import yoga_delivery_settings as delivery
        self.assertEqual(delivery.effective_runtime("19min", 1150), 1140 * 1000000)
        with self.assertRaises(ValueError):
            delivery.effective_runtime("20min", 1150)


class ResidentEffectiveVerificationModels(unittest.TestCase):
    isolation = {**SANDBOX, "ProtectSystem":"strict", "PrivateTmp":"yes"}

    def resident_service(self,root,quota="1.900000s"):
        from system_mask_policy import setting
        from guard_resident_dispatch import unset_environment
        service = FakeService(root)
        service.actual.update(MemoryMax="4026531840",TasksMax="480",CPUQuotaPerSecUSec=quota,
            RuntimeMaxUSec="19min 30s",ProtectSystem="strict",PrivateTmp="yes",
            TemporaryFileSystem=setting(profile="standard"),
            UnsetEnvironment=" ".join(unset_environment(DELEGATION_ENV)))
        (root/"memory.max").write_text("4026531840")
        (root/"pids.max").write_text("480")
        (root/"cpu.max").write_text("190000 100000")
        return service

    def admit_resident(self,service):
        verify(service.actual,service.root,manager="system",isolation=self.isolation,
            profile="resident-enrollment",runtime_seconds=1170)

    def test_resident_full_readback_accepts_exact_equivalent_cpu_duration_units(self):
        with tempfile.TemporaryDirectory() as directory:
            for quota in ("1.900000s","1.900s","1.9s","1900ms","1900000us"):
                with self.subTest(quota=quota):
                    service = self.resident_service(Path(directory),quota)
                    self.admit_resident(service)
                    self.assertEqual(service.actual["MemoryMax"],"4026531840")
                    self.assertEqual((service.root/"pids.max").read_text(),"480")

    def test_resident_full_readback_refuses_nonexact_nonfinite_malformed_cpu_properties(self):
        with tempfile.TemporaryDirectory() as directory:
            for quota in ("1.900001s","1.899999s","2s","1s","1900001us","1899999us",
                    "NaNs","Infinitys","infinity","max","-1.9s","+1.9s","1.9e0s","1900000",
                    "1.900000s extra"," 1.900000s","1.900000s ","9"*1000+"s",None,True,1900000):
                with self.subTest(quota=quota):
                    service = self.resident_service(Path(directory),quota)
                    with self.assertRaises(ValueError):
                        self.admit_resident(service)

    def test_resident_full_readback_refuses_kernel_memory_tasks_swap_and_cpu_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            for key,value in (("memory.max","4026531841"),("memory.max","4026531839"),
                    ("pids.max","481"),("pids.max","479"),("memory.swap.max","1"),
                    ("memory.oom.group","0"),("cpu.max","190001 100000"),
                    ("cpu.max","200000 100000"),("cpu.max","max 100000"),("cpu.max","0 100000")):
                with self.subTest(key=key,value=value):
                    service = self.resident_service(Path(directory))
                    (service.root/key).write_text(value)
                    with self.assertRaises(ValueError):
                        self.admit_resident(service)

    def test_resident_normalized_cpu_does_not_bypass_other_properties_or_masks(self):
        with tempfile.TemporaryDirectory() as directory:
            for key,value in (("MemoryMax","4294967296"),("TasksMax","512"),("MemorySwapMax","1"),
                    ("PrivateNetwork","no"),("ProtectSystem","no"),("PrivateTmp","no"),
                    ("NoNewPrivileges","no"),("TemporaryFileSystem",""),
                    ("UnsetEnvironment",""),("RuntimeMaxUSec","20min")):
                with self.subTest(key=key,value=value):
                    service = self.resident_service(Path(directory))
                    service.actual[key] = value
                    with self.assertRaises(ValueError):
                        self.admit_resident(service)
            service = self.resident_service(Path(directory))
            (service.root/"memory.oom.group").unlink()
            with self.assertRaises(FileNotFoundError):
                self.admit_resident(service)

    def test_standard_and_native_existing_two_second_policy_remains_exact(self):
        self.assertEqual(PROPERTIES["CPUQuotaPerSecUSec"],"2s")
        self.assertEqual(PROPERTIES["MemoryMax"],"4294967296")
        self.assertEqual(PROPERTIES["TasksMax"],"512")
        with tempfile.TemporaryDirectory() as directory:
            for profile in ("standard","codex-native"):
                service = FakeService(Path(directory))
                kwargs = {"profile":profile}
                if profile == "codex-native":
                    kwargs["runtime_seconds"] = 1200
                verify(service.actual,service.root,**kwargs)
                for quota in ("1.900000s","1900ms","1900000us","1s","2.000000s","2000ms","2.000001s"):
                    with self.subTest(profile=profile,quota=quota):
                        changed = {**service.actual,"CPUQuotaPerSecUSec":quota}
                        with self.assertRaises(ValueError):
                            verify(changed,service.root,**kwargs)



class ResidentSetupIsolationModels(unittest.TestCase):
    def setup_arguments(self, label):
        import guard_resident_setup_dispatch as setup
        import guard_resident_vault_profile as vault
        is_vault = label in (vault.STANDARD_LABEL, vault.STANDARD_UNLOCK_LABEL)
        return SimpleNamespace(profile=setup.PROFILE, manager="system",
            resident_manifest=None, resident_enrollment_manifest=None if is_vault else Path("/owned/enrollment/input.json"),
            resident_vault_manifest=Path("/owned/vault/input.json") if is_vault else None,
            reuse_owned_cache=False, repository_cache=None, nixpkgs_source=None,
            source_commit="a"*40, source_dirty="false")

    def test_actual_dispatch_to_guard_isolation_resolves_each_exclusive_selected_manifest(self):
        import execution_guard as guard
        import guard_resident_dispatch as dispatch
        import guard_resident_setup_dispatch as setup
        for label in setup.LABELS:
            with self.subTest(label=label):
                args=self.setup_arguments(label)
                arguments=["run",label]
                selected=dispatch.select(args,arguments)
                actual=guard.resident_isolation(selected,args,arguments)
                self.assertIsNone(args.resident_manifest)
                self.assertEqual(actual, {**guard.SANDBOX, "PrivateNetwork":"yes",
                    "ProtectSystem":"strict", "PrivateTmp":"yes"})
                with self.assertRaises(ValueError):
                    selected.finite(arguments,args.manager,None,False)
                with self.assertRaises(ValueError):
                    selected.finite(arguments,args.manager,Path("/unrelated/input.json"),False)

    def test_dispatch_refuses_absent_or_cross_profile_setup_authority_and_unselected_labels(self):
        import guard_resident_dispatch as dispatch
        import guard_resident_setup_dispatch as setup
        import guard_resident_vault_profile as vault
        for label in setup.LABELS:
            args=self.setup_arguments(label)
            for field,value in (
                ("resident_enrollment_manifest",None), ("resident_vault_manifest",None),
                ("resident_manifest",Path("/other/input.json")),
                ("resident_enrollment_manifest",Path("/other/enrollment.json")),
                ("resident_vault_manifest",Path("/other/vault.json")), ("manager","user"),
                ("reuse_owned_cache",True), ("source_dirty","true")):
                if getattr(args,field,None)==value or (field in setup.FIELDS
                        and getattr(args,field,None) is not None and value is not None):
                    continue
                changed=SimpleNamespace(**vars(args))
                setattr(changed,field,value)
                with self.subTest(label=label,field=field),self.assertRaises(ValueError):
                    dispatch.select(changed,["run",label])
            for profile in ("standard","resident-continuity","resident-namespace","native-candidate"):
                changed=SimpleNamespace(**vars(args))
                changed.profile=profile
                with self.subTest(label=label,profile=profile),self.assertRaises(ValueError):
                    dispatch.select(changed,["run",label])
        for label in (vault.LABEL,vault.UNLOCK_LABEL,"//delivery:resident_vault_metadata",
                      "//delivery:resident_enrollment_extra"):
            args=self.setup_arguments(setup.LABELS[0])
            with self.subTest(label=label),self.assertRaises(ValueError):
                dispatch.select(args,["run",label])


class InstalledYogaReservedRegistrationModels(unittest.TestCase):
    def test_exact_new_profiles_refuse_before_tools_or_state_initialization(self):
        import execution_guard as guard
        import guard_yoga_installed_reserved as installed
        with patch.object(guard, 'immutable', side_effect=AssertionError('tool read')) as tools, \
                patch.object(guard, 'prepare_state', side_effect=AssertionError('state mutation')) as state, \
                patch.object(installed, 'admit', side_effect=AssertionError('public input read')) as admission:
            for profile in installed.PROFILES:
                for arguments in (['test', '//:docs_check'], installed.VECTORS[profile] + ['--untrusted']):
                    with self.assertRaises(ValueError):
                        guard.main(['--profile', profile, '--manager', 'system', '--source-commit', 'a' * 40,
                            '--source-dirty', 'false', '--', *arguments])
            for profile in ('standard', installed.SELECTION_PROFILE, installed.MODEL_PROFILE):
                with self.assertRaises(ValueError):
                    guard.main(['--profile', profile, '--manager', 'system', '--source-commit', 'a' * 40,
                        '--source-dirty', 'false', '--yoga-installed-producer-selection-sha256', 'b' * 64,
                        '--', *installed.VECTORS.get(profile, ['test', '//:docs_check'])])
            tools.assert_not_called()
            state.assert_not_called()
            admission.assert_not_called()

    def test_each_profile_reads_back_only_existing_reserved_caps_and_original_runtime(self):
        import execution_guard as guard
        import guard_yoga_installed_reserved as installed
        import guard_native_seed_plan_reserved as kernel
        for profile in installed.PROFILES:
            self.assertIn(profile, kernel.WORKLOAD_PROFILES)
            self.assertNotIn(profile, kernel.PROFILES)
            self.assertEqual(guard.workload_pids_observation(None, profile).expected_limit, 480)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for name, value in guard.CGROUP.items():
                    (root / name).write_text({'memory.max': str(installed.MEMORY), 'pids.max': '480'}.get(name, value))
                (root / 'cpu.max').write_text('190000 100000')
                actual = {**installed.properties(guard.PROPERTIES), **guard.SANDBOX, 'RuntimeMaxUSec': '17s',
                    'TemporaryFileSystem': guard.system_masks(profile='standard'),
                    'UnsetEnvironment': ' '.join(guard.DELEGATION_ENV)}
                guard.verify(actual, root, 'system', guard.SANDBOX, profile, runtime_seconds=17)
                for key, value in (('MemoryMax', '4294967296'), ('TasksMax', '512'),
                        ('CPUQuotaPerSecUSec', '2s'), ('RuntimeMaxUSec', '1200s'), ('PrivateNetwork', 'no')):
                    with self.assertRaises(ValueError):
                        guard.verify({**actual, key: value}, root, 'system', guard.SANDBOX, profile, runtime_seconds=17)

class AttendedYogaReservedRegistrationModels(unittest.TestCase):
    def test_exact_toolbar_and_model_requests_refuse_before_tools_or_state(self):
        import execution_guard as guard
        import guard_yoga_toolbar_reserved as reserved
        with patch.object(guard, 'immutable', side_effect=AssertionError('tool read')) as tools, \
                patch.object(guard, 'prepare_state', side_effect=AssertionError('state mutation')) as state, \
                patch.object(reserved, 'preallocate', side_effect=AssertionError('qualification read')) as admission:
            for profile in reserved.PROFILES:
                for arguments in (['run', '//delivery:yoga_installed_workspace'],
                        ['run', reserved.LABEL, '--untrusted'], ['test', '//:docs_check']):
                    with self.subTest(profile=profile,arguments=arguments),self.assertRaises(ValueError):
                        guard.main(['--profile',profile,'--manager','system','--',*arguments])
            tools.assert_not_called()
            state.assert_not_called()
            admission.assert_not_called()

    def test_same_derived_runtime_and_reserved_caps_are_required_for_both_profiles(self):
        import execution_guard as guard
        import guard_yoga_toolbar_reserved as reserved
        import guard_native_seed_plan_reserved as kernel
        import guard_yoga_profile as yoga
        for profile in reserved.PROFILES:
            self.assertIn(profile,kernel.WORKLOAD_PROFILES)
            self.assertNotIn(profile,kernel.PROFILES)
            self.assertEqual(guard.workload_pids_observation(None,profile).expected_limit,480)
            with tempfile.TemporaryDirectory() as temporary,patch.object(yoga,'verify_masks'):
                root=Path(temporary)
                for name,value in guard.CGROUP.items():
                    (root/name).write_text({'memory.max':str(reserved.MEMORY),'pids.max':'480'}.get(name,value))
                (root/'cpu.max').write_text('190000 100000')
                actual={**reserved.properties(guard.PROPERTIES),**guard.SANDBOX,'RuntimeMaxUSec':'17s',
                    'TemporaryFileSystem':guard.system_masks(profile='standard'),
                    'InaccessiblePaths':'/etc/environment',
                    'UnsetEnvironment':' '.join(guard.DELEGATION_ENV)}
                guard.verify(actual,root,'system',guard.SANDBOX,profile,runtime_seconds=17)
                for key,value in (('MemoryMax','4294967296'),('TasksMax','512'),
                        ('CPUQuotaPerSecUSec','2s'),('RuntimeMaxUSec','1200s'),('PrivateNetwork','no')):
                    with self.subTest(profile=profile,key=key),self.assertRaises(ValueError):
                        guard.verify({**actual,key:value},root,'system',guard.SANDBOX,profile,runtime_seconds=17)
                with self.assertRaises(ValueError):
                    guard.verify(actual,root,'system',guard.SANDBOX,profile,runtime_seconds=18)

    def test_original_yoga_launcher_identity_cannot_be_substituted_by_guard_worker(self):
        import execution_guard as guard
        unit='omux-proof-original.service';run=Path('/owned/epoch');python='/nix/store/fixed/bin/python3'
        worker='/sealed/tools/yoga_operator_launch.py'
        actual={'Id':unit,'User':str(os.getuid()),'Group':str(os.getgid()),
            'Environment':'OMUX_EXECUTION_GUARD='+str(run),
            'ExecStart':'path='+python+' ; argv[]='+python+' '+worker+' --worker '+str(run)+' -- run'}
        guard.unit_epoch_identity(actual,unit=unit,manager='system',run=run,python=python,worker=worker)
        for field,value in (('Id','another.service'),('Environment','OMUX_EXECUTION_GUARD=/other'),
                ('ExecStart',actual['ExecStart'].replace(worker,'/sealed/tools/execution_guard.py'))):
            with self.subTest(field=field),self.assertRaises(ValueError):
                guard.unit_epoch_identity({**actual,field:value},unit=unit,manager='system',run=run,python=python,worker=worker)


class InstalledYogaCommandTests(unittest.TestCase):
    def admission(self):
        import guard_yoga_profile as yoga
        return {'receipt': {'scope': yoga.INSTALLED_SCOPE,
                            'controllerTools': {'bazel': '/store/bazel'}}}

    def test_marker_without_concrete_capture_refuses_before_bazel_construction(self):
        import execution_guard as guard
        import guard_yoga_profile as yoga
        with patch.object(guard, 'bazel_command', side_effect=AssertionError('builder')) as builder:
            with self.assertRaises(ValueError):
                guard.yoga_command('/store/bazel', Path('/model/epoch'), ['run', yoga.LABEL],
                                   self.admission(), manager='system')
            builder.assert_not_called()

    def test_fixed_mini_graph_flags_and_source_stamp_refusal(self):
        import execution_guard as guard
        import guard_yoga_profile as yoga
        import guard_yoga_installed_workspace as inventory
        # Authority is synthetic here; concrete held file/alias tests are in
        # yoga_installed_workspace_test. This exercises actual command policy.
        with patch.object(inventory, 'verified', return_value=True):
            command = guard.yoga_command('/store/bazel', Path('/model/epoch'), ['run', yoga.LABEL],
                                         self.admission(), manager='system')
            self.assertIn('--repository_disable_download', command)
            self.assertIn('--repo_contents_cache=', command)
            self.assertNotIn('--@rules_zig//zig/settings:use_standalone_translate_c', command)
            self.assertEqual(command[-1], yoga.LABEL)
            for stamp in ({'source_commit': 'a'*40}, {'source_dirty': 'false'}):
                with patch.object(guard, 'bazel_command', side_effect=AssertionError('builder')) as builder:
                    with self.assertRaises(ValueError):
                        guard.yoga_command('/store/bazel', Path('/model/epoch'), ['run', yoga.LABEL],
                                           self.admission(), manager='system', **stamp)
                    builder.assert_not_called()


class RunRetirementFilesystemModels(unittest.TestCase):
    """Real tiny trees under Bazel; no controller, cgroup or provider execution."""
    def setUp(self):
        import execution_guard as guard
        self.guard = guard
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'state'
        self.state.mkdir(mode=0o700)
        self.run = self.state / '1ec6e1df-dad1-4974-9a4d-8172b2a5c337'
        self.run.mkdir(mode=0o700)
        self.output = self.run / 'output-base'
        self.output.mkdir(mode=0o700)
        (self.output / 'nested').mkdir()
        (self.output / 'nested/payload').write_bytes(b'payload')
        (self.run / 'bazel-user-root').mkdir(mode=0o700)
        (self.run / 'bazel-user-root/cache').write_bytes(b'cache')
        self.evidence = b'{"schema":1,"results":[]}\n'
        self.write('test-evidence.json', self.evidence)
        (self.run / 'test-evidence').mkdir(mode=0o700)
        (self.run / 'test-evidence/selected.evidence').write_bytes(b'durable evidence')
        self.write('test-evidence-other.json', b'other evidence')
        self.write('supervisor.json', b'private supervisor metadata')
        self.write('workload.log', b'bounded workload diagnostics')
        self.receipt = {'id': self.run.name, 'exit': 0, 'workload_exit': 0,
            'descendants_empty': True, 'controller_failure': None, 'verb': 'test',
            'profile': 'standard', 'targets': ['//tools:execution_guard_test'],
            'output_base': str(self.output),
            'cleanup': {'state': 'empty', 'stop': 'not-requested', 'ownership': 'unproved'},
            'original_cgroup_identity': {'device': 1, 'inode': 2},
            'test_evidence': {'state': 'preserved', 'manifest': 'test-evidence.json',
                              'sha256': hashlib.sha256(self.evidence).hexdigest()}}
        self.save_receipt()
        self.entry_ns = time.monotonic_ns()
        self.pin = guard.RunRetirement(self.state, self.run)
        self.addCleanup(self.pin.close)

    def write(self, name, raw):
        path = self.run / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def save_receipt(self):
        self.write('receipt.json', (json.dumps(self.receipt, sort_keys=True) + '\n').encode())

    def retire(self, **options):
        return self.pin.retire(terminal_published=True, original_entry_ns=self.entry_ns,
            original_deadline_ns=self.entry_ns + 1200 * 10**9, **options)

    def toolbar_products(self):
        label=self.guard.TOOLBAR_PREP_LABEL
        root=self.output/'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_public_artifact_prepare_producer/test.outputs'
        product=root/'yoga-public-toolbar';product.mkdir(mode=0o700,parents=True)
        for name in ('artifact.json','runfiles-inventory.json'):
            (product/name).write_bytes(b'{"fixture":"current public inputs; no execution authority"}')
            (product/name).chmod(0o600)
        actual=self.output/'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh.runfiles'
        actual.mkdir(mode=0o700,parents=True);(actual/'complete-public-input').write_bytes(b'original public bytes')
        rows={'schema':1,'results':[{'target':label,'configuration':'k8-fastbuild','state':'observed',
            'files':[{'source':'test.xml','state':'copied','bytes':20}]}]}
        raw=json.dumps(rows,sort_keys=True).encode();self.write('test-evidence.json',raw)
        self.receipt.update(targets=[label],yoga_public_artifact_preparation={'verified_after_cleanup':True})
        self.receipt['test_evidence']['sha256']=hashlib.sha256(raw).hexdigest();self.save_receipt()
        return actual,product

    def test_exact_toolbar_producer_retains_original_physical_runfiles_and_receipts(self):
        actual,product=self.toolbar_products();before=actual.stat().st_ino
        result=self.retire()
        self.assertEqual(result['children']['output-base'],'retained-declared-producer')
        self.assertEqual(actual.stat().st_ino,before)
        self.assertEqual((actual/'complete-public-input').read_bytes(),b'original public bytes')
        self.assertTrue((product/'artifact.json').is_file())
        self.assertEqual(result['retained_output_contract'],[self.guard.TOOLBAR_PREP_LABEL])
        self.assertEqual(self.retire(),result)

    def test_bare_build_and_partial_toolbar_products_receive_no_retention_credit(self):
        for failure in ('build','missing'):
            # Independent real filesystem cases, never reuse a removed root.
            with self.subTest(failure=failure):
                actual,product=self.toolbar_products()
                if failure=='build':self.receipt['verb']='build'
                else:(product/'runfiles-inventory.json').unlink()
                self.save_receipt();result=self.retire()
                self.assertEqual(result['retained_output_contract'],[])
                self.assertFalse(actual.exists())
                # Reset only this model's known test root for the next subcase.
                self.output.mkdir(mode=0o700)
                self.receipt['verb']='test'
                self.pin.bindings={}
                (self.run/'test-evidence-retirement.json').unlink()

    def delivered_roots(self):
        for name in self.guard.CONTENT_DELIVERY_RETIREMENT_CHILDREN:
            (self.run/name).mkdir(mode=0o700)
            (self.run/name/'disposable').write_bytes(b'owned transient bytes')
        evidence=self.run/'delivery-evidence'; evidence.mkdir(mode=0o700)
        (evidence/'test-evidence.json').write_bytes(b'{"schema":1}\n')
        (evidence/'test-evidence.json').chmod(0o600)
        (evidence/'workload.log').write_bytes(b'bounded delivery evidence')
        retained=self.run/'native-content-retained'; retained.mkdir(mode=0o700)
        (retained/'payload').write_bytes(b'durable SOURCE/HUB')
        self.write('source-phase-receipt.json',b'original SOURCE0 checkpoint')
        self.write('native-content-delivery-request.json',b'pinned request')
        (self.run/'unknown-output').mkdir(mode=0o700)
        (self.run/'unknown-output/keep').write_bytes(b'unknown scope')
        self.receipt.update(profile='native-siwc-catalog-content-source-reserved',
            native_siwc_content_publication={'kind':'transport'},native_siwc_content_delivery={
                'started':True,'phase':'complete','exit':0,'workload_exit':0,
                'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},
                'test_evidence':{'state':'preserved','manifest':'delivery-evidence/test-evidence.json',
                    'sha256':hashlib.sha256((evidence/'test-evidence.json').read_bytes()).hexdigest()}})
        self.save_receipt()

    def test_fixed_delivery_transient_roots_retire_without_retained_payload_or_evidence(self):
        self.delivered_roots()
        preserved={path:path.read_bytes() for path in (self.run/'source-phase-receipt.json',
            self.run/'native-content-delivery-request.json',self.run/'delivery-evidence/test-evidence.json',
            self.run/'delivery-evidence/workload.log',self.run/'native-content-retained/payload',
            self.run/'unknown-output/keep')}
        result=self.retire()
        self.assertEqual(result['state'],'complete')
        for name in self.guard.CONTENT_DELIVERY_RETIREMENT_CHILDREN:
            self.assertEqual(result['children'][name],'retired'); self.assertFalse((self.run/name).exists())
        for path,raw in preserved.items(): self.assertEqual(path.read_bytes(),raw)
        self.assertEqual(self.retire(),result)

    def test_unproved_delivery_defers_new_roots_even_when_source_empty_is_true(self):
        self.delivered_roots()
        self.receipt['native_siwc_content_delivery']['cleanup']['ownership']='unproved'
        self.save_receipt(); result=self.retire()
        self.assertEqual(result['delivery_retirement']['state'],'deferred-unqualified-delivery')
        for name in self.guard.CONTENT_DELIVERY_RETIREMENT_CHILDREN:
            self.assertEqual((self.run/name/'disposable').read_bytes(),b'owned transient bytes')

    def test_delivery_evidence_mutation_refuses_before_any_phase2_disposal(self):
        self.delivered_roots()
        (self.run/'delivery-evidence/test-evidence.json').write_bytes(b'{"changed":true}')
        result=self.retire(); self.assertEqual(result['state'],'refused')
        for name in self.guard.CONTENT_DELIVERY_RETIREMENT_CHILDREN: self.assertTrue((self.run/name).is_dir())
        self.assertEqual((self.run/'native-content-retained/payload').read_bytes(),b'durable SOURCE/HUB')

    def test_finished_fixed_children_retire_after_preserving_raw_evidence(self):
        kept = {name: (self.run/name).read_bytes() for name in
            ('receipt.json','supervisor.json','test-evidence.json','test-evidence-other.json','workload.log')}
        (self.run/'another-directory').mkdir()
        report = self.retire()
        self.assertEqual(report['state'], 'complete')
        self.assertEqual(report['removed_entries'], 5)
        self.assertEqual(report['removed_directories'], 3)
        self.assertIs(type(report['observed_allocated_blocks_512']), int)
        self.assertIn('filesystem_before',report)
        self.assertIn('filesystem_after',report)
        for name, raw in kept.items(): self.assertEqual((self.run/name).read_bytes(),raw)
        self.assertEqual((self.run/'test-evidence/selected.evidence').read_bytes(),b'durable evidence')
        self.assertTrue((self.run/'another-directory').is_dir())
        self.assertFalse(self.output.exists())
        self.assertFalse((self.run/'bazel-user-root').exists())
        self.assertEqual(json.loads((self.run/self.guard.RETIREMENT_REPORT).read_bytes()),report)

    def test_owned_external_symlinks_are_unlinked_without_following_targets(self):
        outside = self.state/'shared-cache'
        outside.mkdir(mode=0o700)
        (outside/'keep').write_bytes(b'external payload')
        (self.output/'nix-store-link').symlink_to(outside,target_is_directory=True)
        (self.output/'broken-link').symlink_to(outside/'missing')
        report = self.retire()
        self.assertEqual(report['state'],'complete')
        self.assertEqual(report['removed_symlinks'],2)
        self.assertEqual((outside/'keep').read_bytes(),b'external payload')

    def test_top_child_symlink_refuses_without_removing_link_or_target(self):
        self.output.rename(self.run/'saved-output')
        self.output.symlink_to(self.run/'saved-output',target_is_directory=True)
        report = self.retire()
        self.assertEqual(report['state'],'refused')
        self.assertTrue(self.output.is_symlink())
        self.assertEqual((self.run/'saved-output/nested/payload').read_bytes(),b'payload')
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())

    def test_run_replacement_is_refused_without_touching_either_tree(self):
        saved = self.state/'saved-run'
        self.run.rename(saved)
        self.run.mkdir(mode=0o700)
        (self.run/'output-base').mkdir()
        (self.run/'output-base/foreign').write_bytes(b'replacement')
        report = self.retire()
        self.assertEqual(report['state'],'refused')
        self.assertEqual(report['report_publication'],'refused')
        self.assertEqual((saved/'output-base/nested/payload').read_bytes(),b'payload')
        self.assertEqual((self.run/'output-base/foreign').read_bytes(),b'replacement')
        self.assertFalse((self.run/self.guard.RETIREMENT_REPORT).exists())

    def test_no_receipt_no_terminal_and_unqualified_cleanup_never_delete(self):
        self.assertEqual(self.pin.retire(terminal_published=False, original_entry_ns=self.entry_ns,
            original_deadline_ns=self.entry_ns + 1200 * 10**9)['reason'],'terminal-unpublished')
        (self.run/'receipt.json').unlink()
        self.assertEqual(self.retire()['state'],'refused')
        self.assertTrue(self.output.is_dir())
        (self.run/self.guard.RETIREMENT_REPORT).unlink(missing_ok=True)
        for changes in ({'descendants_empty':False}, {'controller_failure':{'exception':'OSError'}},
                {'cleanup':{'state':'original-changed','stop':'succeeded','ownership':'verified'}},
                {'cleanup':{'state':'empty','stop':'unresolved','ownership':'verified'}},
                {'cleanup':{'state':'empty','stop':'not-requested','ownership':'refused'}},
                {'original_cgroup_identity':None}):
            saved=dict(self.receipt)
            self.receipt.update(changes);self.save_receipt()
            report=self.retire()
            self.assertEqual(report['reason'],'cleanup-unqualified')
            self.assertTrue(self.output.is_dir())
            (self.run/self.guard.RETIREMENT_REPORT).unlink()
            self.receipt=saved

    def test_evidence_hash_change_blocks_deletion(self):
        self.write('test-evidence.json',b'changed')
        self.assertEqual(self.retire()['reason'],'evidence-unqualified')
        self.assertTrue(self.output.is_dir())

    def test_shared_output_base_is_excluded_and_its_sibling_cache_untouched(self):
        shared=self.state/'cache-key'
        shared.mkdir(mode=0o700)
        (shared/'output-base').mkdir()
        (shared/'output-base/payload').write_bytes(b'shared')
        self.receipt['output_base']=str(shared/'output-base');self.save_receipt()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'excluded-shared-or-external-output-base')
        self.assertEqual((shared/'output-base/payload').read_bytes(),b'shared')
        self.assertTrue(self.output.is_dir())
        self.assertFalse((self.run/'bazel-user-root').exists())

    def test_repeated_retirement_preserves_first_durable_counters_and_refuses_new_root(self):
        first=self.retire()
        self.assertEqual(self.retire(),first)
        self.output.mkdir()
        (self.output/'later').write_bytes(b'new data')
        self.assertEqual(self.retire()['state'],'refused')
        self.assertEqual((self.output/'later').read_bytes(),b'new data')

    def test_partial_failure_recovery_retires_remaining_child(self):
        actual=self.pin.walk
        failed=False
        def interrupted(directory,lineage,counts,*,remove):
            nonlocal failed
            if remove and lineage[0][2]=='bazel-user-root' and not failed:
                failed=True
                raise OSError('synthetic interruption')
            return actual(directory,lineage,counts,remove=remove)
        with patch.object(self.pin,'walk',side_effect=interrupted):
            first=self.retire()
        self.assertEqual(first['state'],'refused')
        self.assertFalse(self.output.exists())
        self.assertTrue((self.run/'bazel-user-root/cache').exists())
        recovered=self.retire()
        self.assertEqual(recovered['state'],'complete')
        self.assertEqual(recovered['children']['output-base'],'absent')
        self.assertFalse((self.run/'bazel-user-root').exists())

    def test_wide_tree_streams_entries_without_listdir_and_depth_is_bounded(self):
        for index in range(1024): (self.output/str(index)).write_bytes(b'x')
        with patch.object(self.guard.os,'listdir',side_effect=AssertionError('unbounded inventory')):
            report=self.retire()
        self.assertEqual(report['state'],'complete')
        self.assertEqual(report['removed_entries'],1029)

    def producer(self, label):
        self.receipt['targets']=[label]
        directory=self.output/'execroot/_main/bazel-out/k8-fastbuild/testlogs'/label[2:].replace(':','/')/'test.outputs'
        directory.mkdir(parents=True)
        for member in self.guard.RETAINED_OUTPUT_PRODUCTS[label]:
            path=directory/member
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'original declared product')
        self.evidence=json.dumps({'schema':1,'results':[{'target':label,'configuration':'k8-fastbuild',
            'state':'observed','files':[{'source':'test.xml','state':'copied','bytes':1}]}]}).encode()
        self.write('test-evidence.json',self.evidence)
        self.receipt['test_evidence']['sha256']=hashlib.sha256(self.evidence).hexdigest()
        self.save_receipt()
        return directory

    def test_named_successful_producer_holds_original_physical_root_only(self):
        self.producer('//tools:codex_native_sdk_carrier_seal_producer')
        identity=self.output.stat()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_physical_root'],{'device':identity.st_dev,'inode':identity.st_ino})
        self.assertEqual(report['receipt_sha256'],hashlib.sha256((self.run/'receipt.json').read_bytes()).hexdigest())
        self.assertIn('fresh qualification',report['proof_semantics'])
        self.assertTrue((self.output/'nested/payload').is_file())
        self.assertFalse((self.run/'bazel-user-root').exists())
        copied_run=self.state/'ffe63a8b-12cd-46ae-8fcd-7d03899668e0'
        copied_run.mkdir(mode=0o700)
        copied_output=copied_run/'output-base';copied_output.mkdir()
        (copied_output/'copied-product').write_bytes(b'payload')
        for name in ('receipt.json','test-evidence.json',self.guard.RETIREMENT_REPORT):
            (copied_run/name).write_bytes((self.run/name).read_bytes());(copied_run/name).chmod(0o600)
        copied_pin=self.guard.RunRetirement(self.state,copied_run)
        try:
            copied_report=copied_pin.retire(terminal_published=True, original_entry_ns=self.entry_ns,
                original_deadline_ns=self.entry_ns + 1200 * 10**9)
            self.assertEqual(copied_report['state'],'skipped')
            self.assertEqual(copied_report['reason'],'run-receipt-mismatch')
            self.assertTrue((copied_output/'copied-product').is_file())
        finally:copied_pin.close()

    def test_site_inventory_singleton_retains_its_original_physical_output(self):
        label='//tools:cached_site_inventory_probe'
        directory=self.producer(label)
        identity=self.output.stat()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        self.assertEqual(report['retained_physical_root'],{'device':identity.st_dev,'inode':identity.st_ino})
        self.assertEqual((directory/'inventory.json').read_bytes(),b'original declared product')

    def test_site_settings_singleton_retains_candidate_without_qualification_credit(self):
        label='//tools:site_coordinator_settings_producer'
        directory=self.producer(label)
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        self.assertEqual((directory/'site-coordinator-settings/site-coordinator-settings.json').read_bytes(),b'original declared product')

    def test_site_binary_singleton_retains_version_receipt_without_closure_credit(self):
        label='//tools:site_coordinator_binary_qualification'
        directory=self.producer(label)
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        self.assertEqual((directory/'site-coordinator-qualification/site-coordinator-qualification.json').read_bytes(),b'original declared product')

    def test_site_closure_singleton_requires_and_retains_both_original_outputs(self):
        label='//tools:site_coordinator_closure_qualification'
        directory=self.producer(label)
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        for leaf in ('site-coordinator-closure-qualification.json','coordinator-inventory.json'):
            self.assertEqual((directory/'site-coordinator-closure-qualification'/leaf).read_bytes(),b'original declared product')

    def test_site_closure_missing_companion_inventory_has_no_retention(self):
        directory=self.producer('//tools:site_coordinator_closure_qualification')
        (directory/'site-coordinator-closure-qualification/coordinator-inventory.json').unlink()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'missing-or-partial-declared-products')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_failed_site_settings_has_no_retention(self):
        self.producer('//tools:site_coordinator_settings_producer')
        self.receipt['exit']=2;self.receipt['workload_exit']=2;self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_site_prerequisite_combined_vector_has_no_singleton_retention(self):
        self.producer('//tools:cached_site_inventory_probe')
        self.receipt['targets'].append('//tools:site_coordinator_settings_producer');self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_fresh_schedule_retains_original_generated_payloads_with_obligations(self):
        label='//tools:native_flake_schedule_qualification'
        directory=self.producer(label)
        generated=directory/'generated/source/member'
        generated.parent.mkdir(parents=True);generated.write_bytes(b'original generated bytes')
        identity=self.output.stat()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        self.assertEqual(report['retained_physical_root'],{'device':identity.st_dev,'inode':identity.st_ino})
        self.assertEqual(generated.read_bytes(),b'original generated bytes')
        self.assertFalse((self.run/'bazel-user-root').exists())

    def test_fresh_seed_plan_retains_original_result_at_declared_path(self):
        label='//tools:native_flake_seed_plan_qualification'
        directory=self.producer(label)
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        self.assertEqual((directory/'native-flake-seed-plan.json').read_bytes(),b'original declared product')
        self.assertFalse((self.run/'bazel-user-root').exists())

    def test_fresh_reserved_registration_retains_all_three_original_leaves(self):
        label='//tools:codex_query_registration_reserved_producer'
        directory=self.producer(label)
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],[label])
        for member in ('query-registration.json','registration','store-paths'):
            self.assertEqual((directory/member).read_bytes(),b'original declared product')
        self.assertFalse((self.run/'bazel-user-root').exists())

    def test_missing_registration_leaf_does_not_retain_other_registration_products(self):
        directory=self.producer('//tools:codex_query_registration_reserved_producer')
        (directory/'registration').unlink()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'missing-or-partial-declared-products')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_failed_seed_plan_does_not_gain_payload_retention(self):
        self.producer('//tools:native_flake_seed_plan_qualification')
        self.receipt['exit']=1;self.receipt['workload_exit']=1;self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_schedule_with_unrelated_target_has_no_singleton_retention(self):
        self.producer('//tools:native_flake_schedule_qualification')
        self.receipt['targets'].append('//:docs_check');self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_missing_or_partial_product_has_no_retention_authority(self):
        directory=self.producer('//tools:codex_native_sdk_carrier_seal_producer')
        (directory/'sdk-private/sdk-carrier/payload.bin').unlink()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'missing-or-partial-declared-products')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_readonly_owned_bazel_directories_can_retire(self):
        (self.output/'nested').chmod(0o555)
        self.output.chmod(0o555)
        self.assertEqual(self.retire()['state'],'complete')
        self.assertFalse(self.output.exists())

    def test_original_retained_root_replacement_has_no_inherited_reference(self):
        self.producer('//tools:codex_native_sdk_carrier_seal_producer')
        first=self.retire()
        self.output.rename(self.run/'retained-original')
        self.output.mkdir()
        (self.output/'copy').write_bytes(b'copied')
        report=self.retire()
        self.assertEqual(first['state'],'complete')
        self.assertEqual(report['state'],'refused')
        self.assertEqual((self.output/'copy').read_bytes(),b'copied')

    def test_foreign_owned_entry_refuses_preflight_without_deleting_owned_entries(self):
        actual=self.guard.os.stat
        def foreign(name,*arguments,**keywords):
            info=actual(name,*arguments,**keywords)
            if name=='payload' and keywords.get('dir_fd') is not None:
                return SimpleNamespace(st_mode=info.st_mode,st_uid=os.getuid()+1,st_dev=info.st_dev)
            return info
        with patch.object(self.guard.os,'stat',side_effect=foreign):
            report=self.retire()
        self.assertEqual(report['state'],'refused')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())

    def test_exact_reserved_file_writer_vector_holds_its_source_root(self):
        self.producer('//tools:codex_native_source_file_writer_producer')
        self.receipt['targets']=['//tools:codex_native_source_file_writer_test',
            '//tools:codex_native_source_file_writer_producer',
            '//tools:codex_native_source_file_writer_metadata_producer']
        self.save_receipt()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')

    def catalog_producer(self):
        directory=self.producer('//tools:codex_native_siwc_catalog_source_producer')
        self.receipt['targets']=['//tools:codex_native_siwc_catalog_source_test',
            '//tools:codex_native_siwc_catalog_source_producer']
        self.save_receipt()
        return directory

    def test_exact_catalog_source_vector_retains_original_tree_and_hub_without_compiler_claim(self):
        directory=self.catalog_producer()
        source=directory/'native-siwc-catalog-source/source/codex-rs/core/src/broker_model_catalog.rs'
        hub=directory/'native-siwc-catalog-source/hub/source/data.bzl'
        for leaf in (source,hub):
            leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(b'public physical output fixture')
        identity=self.output.stat()
        report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],['//tools:codex_native_siwc_catalog_source_producer'])
        self.assertEqual(report['retained_physical_root'],{'device':identity.st_dev,'inode':identity.st_ino})
        self.assertEqual(source.read_bytes(),b'public physical output fixture')
        self.assertEqual(hub.read_bytes(),b'public physical output fixture')
        self.assertFalse((self.run/'bazel-user-root').exists())
        self.assertIn('fresh qualification',report['proof_semantics'])

    def test_bare_catalog_producer_does_not_inherit_retention_from_product_table(self):
        self.producer('//tools:codex_native_siwc_catalog_source_producer')
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_catalog_vector_with_unrelated_target_does_not_inherit_retention(self):
        self.catalog_producer()
        self.receipt['targets'].append('//:docs_check');self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_catalog_receipt_missing_from_exact_success_vector_retires_output(self):
        directory=self.catalog_producer()
        (directory/'native-siwc-catalog-source/source-receipt.json').unlink()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'missing-or-partial-declared-products')
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_catalog_failed_workload_does_not_retain_or_create_reuse_authority(self):
        self.catalog_producer()
        self.receipt.update(exit=1,workload_exit=1);self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_exact_catalog_models_vector_retains_both_source_and_actual_test_receipts(self):
        self.producer('//tools:codex_native_siwc_catalog_models_producer')
        self.receipt['targets']=['//tools:codex_native_siwc_catalog_models_test',
            '//tools:codex_native_siwc_catalog_models_producer'];self.save_receipt()
        original=self.output.stat();report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(report['retained_output_contract'],['//tools:codex_native_siwc_catalog_models_producer'])
        self.assertEqual(report['retained_physical_root'],{'device':original.st_dev,'inode':original.st_ino})
        self.assertTrue(self.output.exists());self.assertFalse((self.run/'bazel-user-root').exists())
        self.assertIn('fresh qualification',report['proof_semantics'])

    def test_catalog_models_missing_source_receipt_retires_even_with_model_receipt(self):
        directory=self.producer('//tools:codex_native_siwc_catalog_models_producer')
        self.receipt['targets']=['//tools:codex_native_siwc_catalog_models_test',
            '//tools:codex_native_siwc_catalog_models_producer'];self.save_receipt()
        (directory/'native-siwc-catalog-source/source-receipt.json').unlink()
        report=self.retire()
        self.assertEqual(report['retention_reason'],'missing-or-partial-declared-products')
        self.assertFalse(self.output.exists())

    def test_bare_catalog_models_target_has_no_retention_authority(self):
        self.producer('//tools:codex_native_siwc_catalog_models_producer')
        report=self.retire()
        self.assertEqual(report['retention_reason'],'no-successful-current-output-contract')
        self.assertFalse(self.output.exists())

    def test_failed_catalog_models_workload_never_retains_apparent_completed_receipts(self):
        self.producer('//tools:codex_native_siwc_catalog_models_producer')
        self.receipt.update(targets=['//tools:codex_native_siwc_catalog_models_test',
            '//tools:codex_native_siwc_catalog_models_producer'],exit=1,workload_exit=1);self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())


    def test_exact_tree_source_pair_retains_original_output_but_bare_or_failed_refuses(self):
        label='//tools:codex_native_siwc_catalog_tree_source_producer'
        self.producer(label)
        self.receipt['targets']=['//tools:codex_native_siwc_catalog_tree_source_test',label];self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retained_output_contract'],[label]);self.assertTrue(self.output.exists())
        self.assertNotIn(('test',label),self.guard.RETAINED_OUTPUT_VECTORS)

    def test_tree_models_retains_only_one_source_family_and_complete_models_receipt(self):
        label='//tools:codex_native_siwc_catalog_tree_models_producer'
        self.producer(label)
        self.receipt.update(profile='native-retained-sdk-tree-models-reserved',targets=[
            '//tools:codex_native_siwc_catalog_tree_models_test',label]);self.save_receipt()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[label])
        self.assertTrue(self.output.exists())

    def test_cli_exact_pair_keeps_all_four_nonempty_products_and_never_singleton_retention(self):
        label='//tools:codex_native_owned_history_cli_producer'
        self.producer(label)
        self.receipt.update(profile='native-owned-history-cli-reserved',targets=[
            '//tools:codex_native_owned_history_cli_test',label]);self.save_receipt()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[label])
        self.assertTrue(self.output.exists());self.assertNotIn(('test',label),self.guard.RETAINED_OUTPUT_VECTORS)

    def test_cli_partial_products_retire_instead_of_promoting_metadata(self):
        label='//tools:codex_native_owned_history_cli_producer'
        directory=self.producer(label)
        self.receipt.update(profile='native-owned-history-cli-reserved',targets=[
            '//tools:codex_native_owned_history_cli_test',label]);self.save_receipt()
        (directory/'native-owned-history-cli/runtime.tar.gz').unlink()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())


    def test_new_models_cli_profiles_have_fixed_480_pid_observation(self):
        for profile in ('native-retained-sdk-tree-models-reserved','native-owned-history-cli-reserved'):
            observation=self.guard.workload_pids_observation({},profile)
            self.assertEqual(observation.expected_limit,480)

    def test_bare_tree_source_has_no_successful_retention_contract(self):
        label='//tools:codex_native_siwc_catalog_tree_source_producer';self.producer(label)
        report=self.retire();self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_failed_tree_source_pair_does_not_keep_apparent_source_receipt(self):
        label='//tools:codex_native_siwc_catalog_tree_source_producer';self.producer(label)
        self.receipt.update(targets=['//tools:codex_native_siwc_catalog_tree_source_test',label],exit=3,workload_exit=3);self.save_receipt()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_tree_models_mixed_or_incomplete_source_family_refuses_retention(self):
        label='//tools:codex_native_siwc_catalog_tree_models_producer';directory=self.producer(label)
        # A legacy source receipt cannot replace the missing tree-owned product.
        (directory/'native-siwc-catalog-tree-source/source-receipt.json').unlink()
        extra=directory/'native-siwc-catalog-source/source-receipt.json'
        extra.parent.mkdir();extra.write_bytes(b'public mixed source receipt')
        self.receipt.update(profile='native-retained-sdk-tree-models-reserved',targets=[
            '//tools:codex_native_siwc_catalog_tree_models_test',label]);self.save_receipt()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())


    def test_cli_silent_streams_stay_in_retained_tree_without_fake_padding(self):
        label='//tools:codex_native_owned_history_cli_producer';directory=self.producer(label)
        for name in ('cli-stdout.log','cli-stderr.log'):
            (directory/'native-owned-history-cli'/name).write_bytes(b'')
        self.receipt.update(profile='native-owned-history-cli-reserved',targets=[
            '//tools:codex_native_owned_history_cli_test',label]);self.save_receipt()
        report=self.retire();self.assertEqual(report['retained_output_contract'],[label])
        for name in ('cli-stdout.log','cli-stderr.log'):
            self.assertEqual((directory/'native-owned-history-cli'/name).read_bytes(),b'')

    def test_depth_bound_refuses_before_any_tree_removal(self):
        directory=self.output
        for _ in range(self.guard.RETIREMENT_DEPTH):
            directory=directory/'d';directory.mkdir()
        self.assertEqual(self.retire()['state'],'refused')
        self.assertTrue((self.output/'nested/payload').is_file())

    def test_failed_producer_has_no_retention_or_reuse_authority(self):
        self.receipt.update(targets=['//tools:codex_native_sdk_carrier_seal_producer'],exit=1,workload_exit=1)
        self.save_receipt()
        report=self.retire()
        self.assertEqual(report['retained_output_contract'],[])
        self.assertFalse(self.output.exists())

    def test_retirement_budget_clamps_to_original_timeout_and_sixty_seconds(self):
        start=self.entry_ns
        now=[start+890*10**9]
        budget=self.guard.RetirementBudget(start,start+1200*10**9,
            timeout_seconds=900,clock=lambda:now[0])
        self.assertEqual(budget.deadline_ns,start+900*10**9)
        self.assertEqual(budget.work_deadline_ns,start+898*10**9)
        now[0]=budget.work_deadline_ns
        with self.assertRaises(self.guard.RetirementDeferred):budget.checkpoint()
        budget.checkpoint(final_report=True)
        now[0]=budget.deadline_ns
        with self.assertRaises(self.guard.RetirementDeferred):budget.checkpoint(final_report=True)
        now[0]=start+10*10**9
        budget=self.guard.RetirementBudget(start,start+1200*10**9,clock=lambda:now[0])
        self.assertEqual(budget.deadline_ns,now[0]+60*10**9)
        budget=self.guard.RetirementBudget(start,start+1200*10**9,
            timeout_seconds=60,clock=lambda:now[0])
        self.assertEqual(budget.deadline_ns,start+60*10**9)

    def test_expired_original_deadline_defers_without_new_walk_or_publication(self):
        receipt=(self.run/'receipt.json').read_bytes()
        with patch.object(self.pin,'walk',side_effect=AssertionError('work past original cutoff')):
            report=self.retire(clock=lambda:self.entry_ns+1200*10**9)
        self.assertEqual(report['state'],'deferred')
        self.assertEqual(report['reason'],'deadline')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual(report['report_publication'],'deferred-at-original-cutoff')
        self.assertEqual((self.run/'receipt.json').read_bytes(),receipt)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')
        self.assertFalse((self.run/self.guard.RETIREMENT_REPORT).exists())

    def test_cutoff_between_preflight_and_delete_preserves_payload_and_publishes_deferral(self):
        now=[self.entry_ns]
        actual=self.pin.walk
        def expire_after_preflight(directory,lineage,counts,*,remove):
            result=actual(directory,lineage,counts,remove=remove)
            if not remove and len(lineage)==1:
                now[0]=self.entry_ns+58*10**9
            return result
        with patch.object(self.pin,'walk',side_effect=expire_after_preflight):
            report=self.retire(clock=lambda:now[0])
        self.assertEqual(report['state'],'deferred')
        self.assertEqual(report['reason'],'deadline')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')
        self.assertEqual(json.loads((self.run/self.guard.RETIREMENT_REPORT).read_bytes()),report)

    def test_cutoff_after_one_unlink_records_actual_partial_counts_without_second_walk(self):
        now=[self.entry_ns]
        actual=self.guard.os.unlink
        removed=[]
        def expire_after_unlink(name,*args,**kwargs):
            result=actual(name,*args,**kwargs)
            removed.append(name)
            now[0]=self.entry_ns+58*10**9
            return result
        with patch.object(self.guard.os,'unlink',side_effect=expire_after_unlink):
            report=self.retire(clock=lambda:now[0])
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['reason'],'deadline')
        self.assertEqual(report['removed_entries'],1)
        self.assertEqual(removed,['payload'])
        self.assertTrue(self.output.is_dir())
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())
        self.assertEqual(json.loads((self.run/self.guard.RETIREMENT_REPORT).read_bytes()),report)
        self.assertEqual((self.run/'test-evidence.json').read_bytes(),self.evidence)

    def test_cancellation_at_entry_never_traverses_or_mutates_outputs(self):
        with patch.object(self.pin,'walk',side_effect=AssertionError('work after cancellation')):
            report=self.retire(cancelled=lambda:True)
        self.assertEqual(report['state'],'deferred')
        self.assertEqual(report['reason'],'cancelled')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())

    def test_cancellation_after_one_unlink_stops_and_records_exact_completed_mutation(self):
        cancelled=[False]
        actual=self.guard.os.unlink
        calls=[]
        def cancel_after_unlink(name,*args,**kwargs):
            result=actual(name,*args,**kwargs)
            calls.append(name)
            cancelled[0]=True
            return result
        with patch.object(self.guard.os,'unlink',side_effect=cancel_after_unlink):
            report=self.retire(cancelled=lambda:cancelled[0])
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['reason'],'cancelled')
        self.assertEqual(report['removed_entries'],1)
        self.assertEqual(calls,['payload'])
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())
        self.assertEqual(json.loads((self.run/self.guard.RETIREMENT_REPORT).read_bytes()),report)

    def test_keyboard_interrupt_propagates_after_metadata_only_deferral(self):
        actual=self.pin.walk
        error=KeyboardInterrupt()
        def interrupt_before_delete(directory,lineage,counts,*,remove):
            if remove:raise error
            return actual(directory,lineage,counts,remove=remove)
        with patch.object(self.pin,'walk',side_effect=interrupt_before_delete):
            with self.assertRaises(KeyboardInterrupt) as caught:self.retire()
        self.assertIs(caught.exception,error)
        report=json.loads((self.run/self.guard.RETIREMENT_REPORT).read_bytes())
        self.assertEqual(report['state'],'deferred')
        self.assertEqual(report['reason'],'cancelled')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')

    def test_test_evidence_is_read_once_for_hash_and_parsed_producer_decision(self):
        self.producer('//tools:codex_native_sdk_carrier_seal_producer')
        actual=self.pin.read_regular
        reads=[]
        def counted(name,*args,**kwargs):
            if name in ('receipt.json','test-evidence.json'):reads.append(name)
            return actual(name,*args,**kwargs)
        with patch.object(self.pin,'read_regular',side_effect=counted):report=self.retire()
        self.assertEqual(report['children']['output-base'],'retained-declared-producer')
        self.assertEqual(reads,['receipt.json','test-evidence.json'])
        self.assertEqual(report['test_evidence_sha256'],hashlib.sha256(self.evidence).hexdigest())

    def test_evidence_replacement_after_hash_refuses_before_any_payload_delete(self):
        actual=self.guard.json.loads
        swapped=[False]
        def replace_after_bound_hash(raw,*args,**kwargs):
            result=actual(raw,*args,**kwargs)
            if raw==self.evidence and not swapped[0]:
                swapped[0]=True
                replacement=self.run/'test-evidence-replacement.json'
                replacement.write_bytes(b'{"schema":1,"results":[]}\n')
                replacement.chmod(0o600)
                replacement.replace(self.run/'test-evidence.json')
            return result
        with patch.object(self.guard.json,'loads',side_effect=replace_after_bound_hash):report=self.retire()
        self.assertTrue(swapped[0])
        self.assertEqual(report['state'],'refused')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')
        self.assertTrue((self.run/'bazel-user-root/cache').is_file())

    def test_receipt_or_evidence_replacement_after_preflight_refuses_at_mutation_fence(self):
        actual=self.pin.walk
        replaced=[False]
        receipt_before=(self.run/'receipt.json').read_bytes()
        def replace_after_preflight(directory,lineage,counts,*,remove):
            result=actual(directory,lineage,counts,remove=remove)
            if not remove and len(lineage)==1 and not replaced[0]:
                replaced[0]=True
                replacement=self.run/'test-evidence-replacement.json'
                replacement.write_bytes(self.evidence);replacement.chmod(0o600)
                replacement.replace(self.run/'test-evidence.json')
            return result
        with patch.object(self.pin,'walk',side_effect=replace_after_preflight):report=self.retire()
        self.assertEqual(report['state'],'refused')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.run/'receipt.json').read_bytes(),receipt_before)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')

    def test_receipt_replacement_at_leaf_unlink_fence_refuses_deletion(self):
        actual=self.pin.fence_bound_evidence
        checks=[0]
        def replace_then_fence():
            checks[0]+=1
            # Startup decision and post-preflight fences precede directory chmod;
            # swap only once deletion traversal has opened its nested directory.
            if checks[0]==5:
                replacement=self.run/'test-evidence-replacement-receipt.json'
                replacement.write_bytes((self.run/'receipt.json').read_bytes())
                replacement.chmod(0o600);replacement.replace(self.run/'receipt.json')
            return actual()
        with patch.object(self.pin,'fence_bound_evidence',side_effect=replace_then_fence):report=self.retire()
        self.assertEqual(report['state'],'refused')
        self.assertEqual(report['removed_entries'],0)
        self.assertEqual((self.output/'nested/payload').read_bytes(),b'payload')

    def test_ordinary_shared_base_is_retained_while_ephemeral_user_root_retires(self):
        shared=self.state/'ordinary-check-v1-fixture'
        shared.mkdir(mode=0o700)
        (shared/'output-base').mkdir()
        (shared/'output-base/routine-output').write_bytes(b'shared routine cache')
        self.receipt['output_base']=str(shared/'output-base')
        self.receipt['ordinary_check_output']={'scope':self.guard.ORDINARY_CHECK_SCOPE,
            'physical_history_native_proof':False,'test_results_cached':False}
        self.save_receipt()
        before=(self.run/'receipt.json').read_bytes()
        report=self.retire()
        self.assertEqual(report['state'],'complete')
        self.assertEqual(report['children']['output-base'],'excluded-shared-or-external-output-base')
        self.assertEqual(report['children']['bazel-user-root'],'retired')
        self.assertEqual((shared/'output-base/routine-output').read_bytes(),b'shared routine cache')
        self.assertFalse((self.run/'bazel-user-root').exists())
        self.assertEqual((self.run/'receipt.json').read_bytes(),before)
        self.assertEqual((self.run/'test-evidence.json').read_bytes(),self.evidence)


class OrdinaryCheckReuseSelectionModels(unittest.TestCase):
    def test_only_closed_standard_test_subsets_select_ordinary_reuse(self):
        import execution_guard as guard
        args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                             source_dirty='false',reuse_owned_cache=False,arguments=[])
        self.assertEqual(len(guard.ORDINARY_CHECK_LABELS),24)
        self.assertTrue(guard.ordinary_check_reuse_selected(args,['test',*sorted(guard.ORDINARY_CHECK_LABELS)]))
        self.assertTrue(guard.ordinary_check_reuse_selected(args,['test','//tools:execution_guard_test','//:docs_check']))
        self.assertTrue(guard.ordinary_check_reuse_selected(args,['test','//:engine_test','//:unit_tests',
            '//:browser_attempt_transaction_test','//:oauth_oidc_signed_fixture_test','//:format_test','//:docs_check']))
        for vector in ([],['test'],['build','//:engine_test'],['run','//:docs_check'],
                ['test','//:engine_test','//:engine_test'],['test','//:engine_test','--nocache_test_results'],
                ['test','//:engine_test','//tools:codex_owner_status_source_producer'],
                ['test','//tools:native_flake_seed_plan_qualification'],['test','//:runtime_test'],
                ['test','//:format'],['test','//tools:codex_native_profile_test']):
            self.assertFalse(guard.ordinary_check_reuse_selected(args,vector))
        for profile in ('codex-sdk','codex-native','dependency-prefetch','resident-continuity',
                'native-file-writer-models-reserved','native-file-writer-source-reserved','site','codex-live'):
            changed=SimpleNamespace(**{**vars(args),'profile':profile})
            self.assertFalse(guard.ordinary_check_reuse_selected(changed,['test','//:engine_test']))
        for name,value in (('native_mode','qualification-cli'),('native_owned_candidate_cache',True),
                ('codex_pack_directory',Path('/selected')),('new_future_selector',0),
                ('resident_epoch','an-epoch')):
            changed=SimpleNamespace(**{**vars(args),name:value})
            self.assertFalse(guard.ordinary_check_reuse_selected(changed,['test','//:engine_test']))

    def test_exact_renewal_and_artifact_models_join_only_closed_ordinary_test_scope(self):
        import execution_guard as guard
        args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                             source_dirty='false',reuse_owned_cache=False)
        labels=['//:paired_renewal_test','//delivery:yoga_public_artifact_prepare_test']
        self.assertEqual(guard.ORDINARY_CHECK_SCOPE,'closed-standard-test-checkout-output-v1')
        for vector in (['test',labels[0]],['test',labels[1]],['test',*labels],
                ['test','//tools:execution_guard_test',*labels,'//:format_test','//:docs_check']):
            self.assertTrue(guard.ordinary_check_reuse_selected(args,vector))
        for vector in (['build',*labels],['run',labels[1]],['test',labels[0],labels[0]],
                ['test',labels[1],'--nocache_test_results'],
                ['test','//delivery:yoga_public_artifact_prepare_producer'],
                ['test',*labels,'//delivery:yoga_public_artifact_prepare_producer'],
                ['test','//:paired_renewal'],['test','//delivery:yoga_public_artifact_prepare'],
                ['test','//:queued_ingress_test'],
                ['test',labels[1],'//delivery:yoga_toolbar_consent_proof'],
                ['test',labels[0],'//tools:codex_native_sdk_carrier_seal_producer']):
            self.assertFalse(guard.ordinary_check_reuse_selected(args,vector))
        for values in ({'profile':'resident-continuity'}, {'profile':'native-sdk-carrier-seal-reserved'},
                {'profile':'site'}, {'site_inventory':Path('/selected/inventory.json')},
                {'codex_owner_runtime_directory':Path('/selected/runtime')},
                {'native_owned_candidate_cache':True}):
            changed=SimpleNamespace(**{**vars(args),**values})
            self.assertFalse(guard.ordinary_check_reuse_selected(changed,['test',*labels]))
        self.assertTrue(guard.toolbar_prepare_selected('standard','system',
            ['test','//delivery:yoga_public_artifact_prepare_producer']))

    def test_current_vault_and_hm_model_vectors_keep_special_effect_selectors_out_of_reuse(self):
        import execution_guard as guard
        args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                             source_dirty='false',reuse_owned_cache=False)
        vault=['test','//tools:guard_resident_standard_vault_test','//tools:guard_resident_enrollment_profile_test',
               '//delivery:resident_standard_vault_models','//delivery:resident_vault_models',
               '//tools:guard_resident_owned_update_test','//tools:execution_guard_test','//:format_test','//:docs_check']
        hm=['test','//tools:home_manager_realization_inputs_test','//tools:guard_home_manager_bundle_reserved_test',
            '//tools:guard_native_seed_plan_reserved_test','//tools:execution_guard_test',
            '//tools:nix_private_store_qualification_test','//:format_test','//:docs_check']
        for vector in (vault,hm):
            self.assertTrue(guard.ordinary_check_reuse_selected(args,vector))
            self.assertEqual(guard.toolbar_prepare_action_jobs('standard',vector,source_dirty='false'),2)
            for wrong in (['build',*vector[1:]],['run',vector[1]],vector+[vector[1]],vector+['--test_arg=model']):
                self.assertFalse(guard.ordinary_check_reuse_selected(args,wrong))
            for label in ('//tools:home_manager_linux_realization_inputs_producer',
                    '//tools:home_manager_acquired_evaluation','//tools:home_manager_retained_reconstruction_producer',
                    '//tools:nix_private_store_build_qualification',
                    '//delivery:resident_standard_vault_metadata','//delivery:resident_standard_vault_unlock',
                    '//delivery:resident_codex_live_continuity','//delivery:yoga_public_artifact_prepare_producer',
                    '//tools:codex_native_sdk_carrier_seal_producer','//tools:future_sdk_fixture_test'):
                self.assertFalse(guard.ordinary_check_reuse_selected(args,vector+[label]))
            for values in ({'profile':'resident-continuity'}, {'profile':'resident-enrollment'},
                    {'profile':'codex-sdk'}, {'profile':'native-siwc-catalog-content-source-reserved'},
                    {'profile':'home-manager-evaluation-reserved'}, {'profile':'home-manager-bundle-models-reserved'},
                    {'profile':'home-manager-realization-inputs-reserved'},
                    {'resident_manifest':Path('/selected/private.json')},
                    {'site_inventory':Path('/selected/inventory.json')},
                    {'sdk_source_root':Path('/selected/sdk')},
                    {'codex_owner_runtime_directory':Path('/selected/runtime')}):
                changed=SimpleNamespace(**{**vars(args),**values})
                self.assertFalse(guard.ordinary_check_reuse_selected(changed,vector))
        self.assertEqual(guard.ORDINARY_CHECK_SCOPE,'closed-standard-test-checkout-output-v1')

    def test_exact_browser_receiver_model_vector_never_admits_genuine_tuple_qualification(self):
        import execution_guard as guard
        args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                             source_dirty='false',reuse_owned_cache=False)
        browser=['test','//delivery:yoga_public_artifact_prepare_test',
            '//delivery:yoga_public_artifact_receive_test','//tools:execution_guard_test','//:format_test','//:docs_check']
        self.assertTrue(guard.ordinary_check_reuse_selected(args,browser))
        self.assertTrue(guard.ordinary_check_reuse_selected(args,['test','//delivery:yoga_public_artifact_receive_test']))
        self.assertEqual(guard.toolbar_prepare_action_jobs('standard',browser,source_dirty='false'),2)
        for label in ('//delivery:yoga_public_artifact_receive_qualification',
                '//delivery:yoga_public_artifact_prepare_producer', '//delivery:yoga_public_artifact_receive',
                '//delivery:yoga_toolbar_consent_proof','//tools:codex_native_sdk_carrier_seal_producer'):
            self.assertFalse(guard.ordinary_check_reuse_selected(args,browser+[label]))
            self.assertFalse(guard.ordinary_check_reuse_selected(args,['test',label]))
        for vector in (['build',*browser[1:]],['run',browser[2]],browser+[browser[2]],
                browser+['--test_env=OMUX_YOGA_PUBLIC_RECEIVE_SELECTION_PATH=/selected']):
            self.assertFalse(guard.ordinary_check_reuse_selected(args,vector))
        for values in ({'toolbar_artifact_selection':Path('/selected/toolbar-public-artifact-selection.json')},
                {'toolbar_artifact_selection_sha256':'b'*64}, {'site_inventory':Path('/selected/inventory.json')},
                {'profile':'yoga-toolbar-reserved-models'},{'profile':'codex-sdk'},
                {'resident_manifest':Path('/selected/private.json')}):
            changed=SimpleNamespace(**{**vars(args),**values})
            self.assertFalse(guard.ordinary_check_reuse_selected(changed,browser))
        self.assertEqual(guard.toolbar_prepare_action_jobs('standard',
            ['test',guard.TOOLBAR_RECEIVE_LABEL],source_dirty='false'),1)
        self.assertEqual(guard.ORDINARY_CHECK_SCOPE,'closed-standard-test-checkout-output-v1')

    def test_source_advance_and_target_subset_do_not_partition_ordinary_policy(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            inputs={'bazel':'/nix/store/fixture/bin/bazel','java':'/nix/store/fixture-jdk'}
            profile={'ordinary_check_scope':guard.ORDINARY_CHECK_SCOPE,'batch':True,'cache_test_results':False}
            first=guard.stable_fingerprint(root,inputs,1000,1000,'system',profile)
            args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                                 source_dirty='false',reuse_owned_cache=False)
            self.assertTrue(guard.ordinary_check_reuse_selected(args,['test','//:engine_test']))
            (root/'BUILD.bazel').write_text('declared source graph advances')
            args.source_commit='b'*40
            self.assertTrue(guard.ordinary_check_reuse_selected(args,['test','//:docs_check','//:format_test']))
            self.assertEqual(first,guard.stable_fingerprint(root,inputs,1000,1000,'system',profile))
            self.assertNotEqual(first,guard.stable_fingerprint(root,{**inputs,'java':'/nix/store/new-jdk'},
                1000,1000,'system',profile))

    def test_ordinary_commands_keep_batch_no_cached_tests_and_per_run_user_root(self):
        import execution_guard as guard
        run=Path('/owned/2a2d7631-f74f-49e4-af5e-23c01b430dc3')
        shared=Path('/owned/ordinary-check-v1-checkout/output-base')
        for vector in (['test','//:engine_test','//:docs_check'],
                ['test','//:paired_renewal_test','//:format_test','//:docs_check'],
                ['test','//delivery:yoga_public_artifact_prepare_test','//tools:execution_guard_test']):
            command=guard.bazel_command('/bazel',run,vector,output_base=shared)
            self.assertIn('--batch',command)
            self.assertIn('--nocache_test_results',command)
            self.assertEqual([item for item in command if item.startswith('--output_base=')],['--output_base='+str(shared)])
            self.assertEqual([item for item in command if item.startswith('--output_user_root=')],
                             ['--output_user_root='+str(run/'bazel-user-root')])
        fresh=guard.bazel_command('/bazel',run,['test','//tools:codex_owner_status_source_producer'])
        self.assertIn('--output_base='+str(run/'output-base'),fresh)


class OrdinaryCheckLeaseFilesystemModels(unittest.TestCase):
    """Real private tiny trees/locks/receipts; no Bazel or process launch.

    Only the enclosing test TMPDIR ancestry is isolated, as in guard_cache_test;
    the fixture state root, namespace, locks, base and receipts are real owned
    objects with production nofollow/private checks. No runtime trust override.
    """
    def setUp(self):
        import execution_guard as guard
        self.guard=guard
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.repository=self.root/'checkout';self.repository.mkdir(mode=0o700)
        self.first_id='19b0b8fc-0c2d-4f62-a9f0-bd5b314fa0ae'
        self.second_id='62200eb5-2d0e-48a5-a5f0-7f5607f52457'
        self.key='a'*64
        def fixture_state(path):
            if Path(path)!=self.state:raise ValueError('fixture state selection refused')
            descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            info=os.fstat(descriptor)
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
                os.close(descriptor);raise ValueError('fixture private state refused')
            return descriptor
        patcher=patch('guard_cache.trusted_directory',side_effect=fixture_state)
        patcher.start();self.addCleanup(patcher.stop)

    def lease(self,run_id=None,key=None,repository=None):
        return self.guard.OrdinaryCheckLease(self.state,key or self.key,run_id or self.first_id,
                                            repository or self.repository)

    def receipt(self,run_id,*,empty=True,targets=None,source='a'*40,graph=None):
        run=self.state/run_id;run.mkdir(mode=0o700,exist_ok=True)
        raw=(json.dumps({'id':run_id,'descendants_empty':empty,'verb':'test','profile':'standard',
            'targets':targets or ['//tools:execution_guard_test'], 'source_commit':source,
            'graph_sha256':graph or source[:32]*2},sort_keys=True)+'\n').encode()
        path=run/'receipt.json';path.write_bytes(raw);path.chmod(0o600)
        with path.open('rb') as held:os.fsync(held.fileno())
        return raw,hashlib.sha256(raw).hexdigest()

    def completed(self):
        lease=self.lease();lease.__enter__()
        lease.output_base.mkdir(mode=0o700)
        (lease.output_base/'payload').write_bytes(b'current routine output')
        raw,digest=self.receipt(self.first_id)
        lease.complete(True,digest);lease.close()
        return lease,raw

    def test_same_checkout_reuses_original_physical_base_after_bound_terminal_receipt(self):
        first,raw=self.completed()
        identity=first.output_base.stat()
        (self.repository/'BUILD.bazel').write_text('new source, same canonical checkout')
        with self.lease(self.second_id) as second:
            self.assertEqual(first.name,second.name)
            self.assertEqual(first.output_base,second.output_base)
            self.assertEqual((identity.st_dev,identity.st_ino),
                             (second.output_base.stat().st_dev,second.output_base.stat().st_ino))
            self.assertEqual((second.output_base/'payload').read_bytes(),b'current routine output')
            self.assertEqual((self.state/self.first_id/'receipt.json').read_bytes(),raw)
            _,digest=self.receipt(self.second_id,targets=['//:docs_check'],source='b'*40)
            second.complete(True,digest)
        self.assertEqual(len([name for name in os.listdir(self.state) if name.startswith('ordinary-check-v1-')]),1)

    def test_different_canonical_checkout_isolates_namespace(self):
        first,_=self.completed()
        other=self.root/'other-checkout';other.mkdir(mode=0o700)
        with self.lease(self.second_id,repository=other) as second:
            self.assertNotEqual(first.name,second.name)
            self.assertNotEqual(first.output_base,second.output_base)
            self.assertFalse(second.output_base.exists())

    def test_changed_fingerprint_refuses_same_namespace_without_creating_another_base(self):
        first,_=self.completed()
        marker=(first.output_base.parent/'owner.json').read_bytes()
        changed=self.lease(self.second_id,key='b'*64)
        self.assertEqual(changed.name,first.name)
        with self.assertRaises(ValueError):changed.__enter__()
        self.assertEqual((first.output_base.parent/'owner.json').read_bytes(),marker)
        self.assertEqual(len([name for name in os.listdir(self.state) if name.startswith('ordinary-check-v1-')]),1)

    def test_new_test_only_vectors_reuse_same_physical_base_with_distinct_epoch_receipts(self):
        inputs={'bazel':'/nix/store/fixture/bin/bazel','java':'/nix/store/fixture-jdk'}
        old_vector=['test','//:docs_check']
        new_vector=['test','//:paired_renewal_test','//delivery:yoga_public_artifact_prepare_test',
                    '//tools:execution_guard_test','//:format_test','//:docs_check']
        args=SimpleNamespace(profile='standard',manager='system',source_commit='a'*40,
                             source_dirty='false',reuse_owned_cache=False)
        self.assertTrue(self.guard.ordinary_check_reuse_selected(args,old_vector))
        self.assertTrue(self.guard.ordinary_check_reuse_selected(args,new_vector))
        previous={'ordinary_check_scope':'closed-standard-test-checkout-output-v1',
                  'limits':dict(self.guard.PROPERTIES),
                  'execution':{'batch':True,'cache_test_results':False,
                      'jobs':self.guard.toolbar_prepare_action_jobs('standard',old_vector,source_dirty='false')}}
        current={**previous,'ordinary_check_scope':self.guard.ORDINARY_CHECK_SCOPE,
                 'execution':{**previous['execution'],
                     'jobs':self.guard.toolbar_prepare_action_jobs('standard',new_vector,source_dirty='false')}}
        graph_file=self.repository/'BUILD.bazel'
        graph_file.write_bytes(b'first declared graph fixture')
        first_graph=hashlib.sha256(graph_file.read_bytes()).hexdigest()
        old_key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',previous)
        with self.lease(key=old_key) as first:
            first.output_base.mkdir(mode=0o700)
            payload=first.output_base/'payload';payload.write_bytes(b'ordinary cached public build data')
            first_raw,first_digest=self.receipt(self.first_id,targets=old_vector[1:],source='a'*40,graph=first_graph)
            first.complete(True,first_digest)
        identity=first.output_base.stat()
        graph_file.write_bytes(b'distinct declared graph fixture; Bazel invalidates action inputs')
        second_graph=hashlib.sha256(graph_file.read_bytes()).hexdigest()
        args.source_commit='b'*40
        new_key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',current)
        self.assertEqual(old_key,new_key)
        with self.lease(self.second_id,key=new_key) as second:
            self.assertEqual(second.name,first.name)
            self.assertEqual(second.output_base,first.output_base)
            self.assertEqual((identity.st_dev,identity.st_ino),
                             (second.output_base.stat().st_dev,second.output_base.stat().st_ino))
            self.assertEqual(payload.read_bytes(),b'ordinary cached public build data')
            for run_id,vector in ((self.first_id,old_vector),(self.second_id,new_vector)):
                run=self.state/run_id
                command=self.guard.bazel_command('/bazel',run,vector,output_base=second.output_base)
                self.assertIn('--batch',command)
                self.assertIn('--nocache_test_results',command)
                self.assertIn('--jobs=2',command)
                self.assertEqual([item for item in command if item.startswith('--output_base=')],
                                 ['--output_base='+str(first.output_base)])
                self.assertIn('--output_user_root='+str(run/'bazel-user-root'),command)
            second_raw,second_digest=self.receipt(self.second_id,targets=new_vector[1:],
                                                  source=args.source_commit,graph=second_graph)
            second.complete(True,second_digest)
        self.assertNotEqual(first_raw,second_raw)
        first_receipt=json.loads(first_raw);second_receipt=json.loads(second_raw)
        self.assertNotEqual(first_receipt['source_commit'],second_receipt['source_commit'])
        self.assertNotEqual(first_receipt['graph_sha256'],second_receipt['graph_sha256'])
        self.assertEqual((self.state/self.first_id/'receipt.json').read_bytes(),first_raw)
        marker=json.loads((first.output_base.parent/'owner.json').read_bytes())
        self.assertEqual(marker['key'],old_key)
        self.assertEqual(marker['last_run'],self.second_id)
        self.assertEqual(marker['cleanup_receipt_sha256'],second_digest)
        self.assertIs(marker['clean'],True)
        self.assertEqual(len([name for name in os.listdir(self.state) if name.startswith('ordinary-check-v1-')]),1)

    def test_current_vault_hm_and_browser_models_reuse_one_base_with_separate_source_graph_receipts(self):
        inputs={'bazel':'/nix/store/fixture/bin/bazel','java':'/nix/store/fixture-jdk'}
        profile={'ordinary_check_scope':self.guard.ORDINARY_CHECK_SCOPE,'limits':dict(self.guard.PROPERTIES),
                 'execution':{'batch':True,'cache_test_results':False,'jobs':2}}
        key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',profile)
        epochs=[(self.first_id,'a',['test','//tools:execution_guard_test','//:docs_check']),
            (self.second_id,'b',['test','//tools:home_manager_realization_inputs_test',
                '//tools:guard_home_manager_bundle_reserved_test','//tools:guard_native_seed_plan_reserved_test',
                '//tools:execution_guard_test','//tools:nix_private_store_qualification_test','//:format_test','//:docs_check']),
            ('9f7c195d-4378-4c8b-8aac-d417252c08ca','c',['test','//tools:guard_resident_standard_vault_test',
                '//tools:guard_resident_enrollment_profile_test','//delivery:resident_standard_vault_models',
                '//delivery:resident_vault_models','//tools:guard_resident_owned_update_test',
                '//tools:execution_guard_test','//:format_test','//:docs_check']),
            ('65935460-c2fa-4f1b-8f17-5c647e2095be','d',['test','//delivery:yoga_public_artifact_prepare_test',
                '//delivery:yoga_public_artifact_receive_test','//tools:execution_guard_test','//:format_test','//:docs_check'])]
        records=[];base_identity=None;selected_base=None
        for run_id,source,vector in epochs:
            graph_file=self.repository/'BUILD.bazel';graph_file.write_bytes(('public graph fixture '+source).encode())
            graph=hashlib.sha256(graph_file.read_bytes()).hexdigest()
            args=SimpleNamespace(profile='standard',manager='system',source_commit=source*40,
                                 source_dirty='false',reuse_owned_cache=False)
            self.assertTrue(self.guard.ordinary_check_reuse_selected(args,vector))
            self.assertEqual(self.guard.toolbar_prepare_action_jobs('standard',vector,source_dirty='false'),2)
            current_key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',profile)
            self.assertEqual(current_key,key)
            with self.lease(run_id,key=current_key) as current:
                if selected_base is None:
                    selected_base=current.output_base;selected_base.mkdir(mode=0o700)
                    (selected_base/'payload').write_bytes(b'ordinary public build data, not native authority')
                    info=selected_base.stat();base_identity=(info.st_dev,info.st_ino)
                self.assertEqual(current.output_base,selected_base)
                info=current.output_base.stat();self.assertEqual((info.st_dev,info.st_ino),base_identity)
                self.assertEqual((selected_base/'payload').read_bytes(),b'ordinary public build data, not native authority')
                run=self.state/run_id
                command=self.guard.bazel_command('/bazel',run,vector,output_base=current.output_base)
                self.assertIn('--batch',command);self.assertIn('--nocache_test_results',command)
                self.assertIn('--jobs=2',command)
                self.assertEqual([part for part in command if part.startswith('--output_base=')],
                                 ['--output_base='+str(selected_base)])
                self.assertIn('--output_user_root='+str(run/'bazel-user-root'),command)
                raw,digest=self.receipt(run_id,targets=vector[1:],source=source*40,graph=graph)
                current.complete(True,digest)
                records.append((run_id,raw,digest))
        self.assertEqual(len({json.loads(raw)['source_commit'] for _,raw,_ in records}),4)
        self.assertEqual(len({json.loads(raw)['graph_sha256'] for _,raw,_ in records}),4)
        for run_id,raw,_ in records:self.assertEqual((self.state/run_id/'receipt.json').read_bytes(),raw)
        marker=json.loads((selected_base.parent/'owner.json').read_bytes())
        self.assertEqual(marker['key'],key);self.assertEqual(marker['last_run'],records[-1][0])
        self.assertEqual(marker['cleanup_receipt_sha256'],records[-1][2]);self.assertIs(marker['clean'],True)
        self.assertEqual(len([name for name in os.listdir(self.state) if name.startswith('ordinary-check-v1-')]),1)

    def test_changed_containment_fingerprint_still_refuses_unchanged_owned_namespace(self):
        inputs={'bazel':'/nix/store/fixture/bin/bazel','java':'/nix/store/fixture-jdk'}
        profile={'ordinary_check_scope':self.guard.ORDINARY_CHECK_SCOPE,
                 'limits':dict(self.guard.PROPERTIES),'execution':{'batch':True,'cache_test_results':False}}
        old_key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',profile)
        changed_profile={**profile,'limits':{**profile['limits'],'MemoryMax':'3221225472'}}
        changed_key=self.guard.stable_fingerprint(self.repository,inputs,os.getuid(),os.getgid(),'system',changed_profile)
        self.assertNotEqual(old_key,changed_key)
        with self.lease(key=old_key) as first:
            first.output_base.mkdir(mode=0o700)
            payload=first.output_base/'payload';payload.write_bytes(b'original contained output')
            raw,digest=self.receipt(self.first_id)
            first.complete(True,digest)
        marker=first.output_base.parent/'owner.json';before=marker.read_bytes()
        identity=first.output_base.stat()
        changed=self.lease(self.second_id,key=changed_key)
        self.assertEqual(changed.name,first.name)
        with self.assertRaises(ValueError):changed.__enter__()
        self.assertEqual(marker.read_bytes(),before)
        self.assertEqual(payload.read_bytes(),b'original contained output')
        self.assertEqual((self.state/self.first_id/'receipt.json').read_bytes(),raw)
        self.assertEqual((identity.st_dev,identity.st_ino),
                         (first.output_base.stat().st_dev,first.output_base.stat().st_ino))
        self.assertEqual(len([name for name in os.listdir(self.state) if name.startswith('ordinary-check-v1-')]),1)

    def test_live_exclusive_lock_and_dirty_exit_refuse_reuse(self):
        with self.lease() as first:
            with self.assertRaises(BlockingIOError):self.lease(self.second_id).__enter__()
            with self.assertRaises(ValueError):first.complete(False,'a'*64)
        with self.assertRaises(ValueError):self.lease(self.second_id).__enter__()

    def test_absent_or_changed_last_terminal_receipt_refuses_reuse(self):
        first,raw=self.completed()
        receipt=self.state/self.first_id/'receipt.json'
        receipt.unlink()
        with self.assertRaises(FileNotFoundError):self.lease(self.second_id).__enter__()
        receipt.write_bytes(raw+b' ');receipt.chmod(0o600)
        with self.assertRaises(ValueError):self.lease(self.second_id).__enter__()
        self.assertEqual((first.output_base/'payload').read_bytes(),b'current routine output')

    def test_matching_digest_but_live_descendants_refuses_reuse(self):
        first,_=self.completed()
        _,digest=self.receipt(self.first_id,empty=False)
        marker=first.output_base.parent/'owner.json'
        value=json.loads(marker.read_bytes());value['cleanup_receipt_sha256']=digest
        marker.write_text(json.dumps(value)+'\n');marker.chmod(0o600)
        with self.assertRaises(ValueError):self.lease(self.second_id).__enter__()

    def test_symlink_namespace_base_and_private_mode_refuse_without_external_effects(self):
        first,_=self.completed()
        original=first.output_base.parent
        saved=self.state/'saved-ordinary-root';original.rename(saved)
        original.symlink_to(saved,target_is_directory=True)
        with self.assertRaises(OSError):self.lease(self.second_id).__enter__()
        self.assertTrue(original.is_symlink())
        original.unlink();saved.rename(original)
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (outside/'keep').write_bytes(b'external data')
        first.output_base.rename(original/'saved-output')
        first.output_base.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.lease(self.second_id).__enter__()
        self.assertEqual((outside/'keep').read_bytes(),b'external data')
        first.output_base.unlink();(original/'saved-output').rename(first.output_base)
        original.chmod(0o755)
        with self.assertRaises(ValueError):self.lease(self.second_id).__enter__()

    def test_private_copied_evidence_survives_later_shared_testlog_overwrite(self):
        with self.lease() as first:
            logs=first.output_base/'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/execution_guard_test'
            logs.mkdir(parents=True)
            epoch=1_000_000_000  # Whole-second synthetic epoch, independent of filesystem clock granularity.
            (logs/'test.log').write_bytes(b'first actual invocation log')
            (logs/'test.xml').write_bytes(b'<testsuite tests="1" failures="0"/>')
            for name in ('test.log','test.xml'):
                os.utime(logs/name,ns=(epoch,epoch))
            run=self.state/self.first_id;run.mkdir(mode=0o700)
            manifest=self.guard.capture_test_evidence(first.output_base,run,['//tools:execution_guard_test'],0,epoch)
            selected=next(row for row in manifest['results'][0]['files'] if row['source']=='test.log')
            self.assertEqual(selected['state'],'copied')
            copy=run/'test-evidence'/selected['file']
            before=copy.read_bytes()
            raw,digest=self.receipt(self.first_id)
            first.complete(True,digest)
        with self.lease(self.second_id) as second:
            self.assertEqual(first.output_base,second.output_base)
            (logs/'test.log').write_bytes(b'second invocation overwrites shared physical log')
            self.assertEqual(copy.read_bytes(),before)
            self.assertEqual(before,b'first actual invocation log')
            self.assertEqual((run/'receipt.json').read_bytes(),raw)





class SiteDevelopmentArtifactAdmissionModels(unittest.TestCase):
    def test_actual_cli_refuses_unrelated_partial_worker_and_non_output_vectors_before_tool_reads(self):
        import execution_guard as guard
        flags = ['--site-development-artifact-selection', '/owned/selection.json',
                 '--site-development-artifact-selection-sha256', 'a' * 64]
        vectors = [flags + ['--', 'test', '//:docs_check'],
                   ['--profile', 'site', '--site-phase', 'checks'] + flags + ['--', 'test', '//:unit_tests'],
                   ['--profile', 'site', '--site-phase', 'fetch'] + flags + ['--', 'fetch', '//:build'],
                   ['--profile', 'site', '--site-phase', 'lock'] + flags + ['--', 'mod', 'deps', '--lockfile_mode=update'],
                   ['--profile', 'site', '--site-phase', 'build', '--worker', '/owned/worker'] + flags + ['--', 'build', '//:build'],
                   ['--profile', 'site', '--site-phase', 'build'] + flags[:2] + ['--', 'build', '//:build'],
                   ['--profile', 'site', '--site-phase', 'build'] + flags[2:] + ['--', 'build', '//:build']]
        for vector in vectors:
            with patch.object(guard, 'immutable') as tools, patch.object(guard, 'worker') as worker, \
                    patch.object(guard, 'prepare_state') as state:
                with self.assertRaises(ValueError):
                    guard.main(vector)
                tools.assert_not_called()
                worker.assert_not_called()
                state.assert_not_called()

    def test_typed_none_and_original_selection_lineage_partition_existing_stable_fingerprint(self):
        import execution_guard as guard
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            inputs = {'bazel': '/nix/store/example/bin/bazel', 'java': '/nix/store/jdk'}
            baseline = {'site': {'proof_bindings': site.development_artifact_bindings(), 'development_artifact': None}}
            selected = {'schema_version': 1, 'selection': '/owned/input/selection.json', 'selection_sha256': 'a' * 64,
                        'output_base': '/owned/cache-v2-key/output-base',
                        'archive': {'path': '/owned/archive.zip', 'sha256': 'b' * 64, 'bytes': 12},
                        'manifest': {'path': '/owned/metadata.json', 'sha256': 'c' * 64}}
            def fingerprint(value):
                return guard.stable_fingerprint(directory, inputs, os.getuid(), os.getgid(), 'system', value)
            first = fingerprint(baseline)
            profile = {'site': {'proof_bindings': site.development_artifact_bindings(selected['selection'], 'a' * 64),
                                'development_artifact': selected}}
            self.assertNotEqual(first, fingerprint(profile))
            for key, value in (('selection', '/different/input/selection.json'), ('selection_sha256', 'd' * 64),
                               ('output_base', '/different/output-base'),
                               ('archive', {**selected['archive'], 'sha256': 'd' * 64}),
                               ('manifest', {**selected['manifest'], 'sha256': 'd' * 64})):
                changed = {'site': {**profile['site'], 'development_artifact': {**selected, key: value}}}
                self.assertNotEqual(fingerprint(profile), fingerprint(changed))

    def test_new_nondefault_selection_cannot_join_ordinary_check_reuse(self):
        import execution_guard as guard
        ordinary = SimpleNamespace(profile='standard')
        self.assertTrue(guard.ordinary_check_reuse_selected(ordinary, ['test', '//:docs_check']))
        ordinary.site_development_artifact_selection = '/owned/selection.json'
        self.assertFalse(guard.ordinary_check_reuse_selected(ordinary, ['test', '//:docs_check']))


class ToolbarPreparationContextModels(unittest.TestCase):
    def test_preallocation_admission_refuses_mixed_build_cache_and_wrong_profile(self):
        import execution_guard as guard
        label=guard.TOOLBAR_PREP_LABEL
        self.assertTrue(guard.toolbar_prepare_selected('standard','system',['test',label]))
        for profile,manager,arguments,reuse,dirty in [
                ('standard','system',['build',label],False,'false'),
                ('standard','system',['test',label,'//:docs_check'],False,'false'),
                ('installed-browser','system',['test',label],False,'false'),
                ('standard','user',['test',label],False,'false'),
                ('standard','system',['test',label],True,'false'),
                ('standard','system',['test',label],False,'true')]:
            with self.assertRaises(ValueError):guard.toolbar_prepare_selected(profile,manager,arguments,reuse,dirty)
        self.assertFalse(guard.toolbar_prepare_selected('standard','system',['test','//:docs_check']))

    def test_exact_fresh_context_is_added_once_under_original_clock(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as selected:
            source=Path(selected).resolve();run=source/'12345678-1234-4234-8234-123456789abc'
            entry=1000*10**9;until=entry+1200*10**9
            command=guard.bazel_command('bazel',run,['test',guard.TOOLBAR_PREP_LABEL],source_commit='a'*40,source_dirty='false')
            with patch.object(guard.time,'monotonic_ns',return_value=entry+10**9):
                new=guard.toolbar_prepare_command(command,run,entry,until,'a'*40,'b'*64,source)
                fields=[part for part in new if part.startswith('--test_env='+guard.TOOLBAR_PREP_VARIABLE)]
                self.assertEqual(len(fields),6)
                self.assertIn('--test_env='+guard.TOOLBAR_PREP_VARIABLE+'DEADLINE_NS='+str(until),fields)
                self.assertIn('--test_env='+guard.TOOLBAR_PREP_VARIABLE+'GRAPH_SHA256='+'b'*64,fields)
                self.assertIn('--nocache_test_results',new)
                self.assertEqual(command[-1],guard.TOOLBAR_PREP_LABEL)
                with self.assertRaises(ValueError):guard.toolbar_prepare_command(new,run,entry,until,'a'*40,'b'*64,source)
            with patch.object(guard.time,'monotonic_ns',return_value=until-30*10**9):
                with self.assertRaises(ValueError):guard.toolbar_prepare_command(command,run,entry,until,'a'*40,'b'*64,source)

    def test_only_exact_test_vector_has_toolbar_output_contract(self):
        import execution_guard as guard
        label=guard.TOOLBAR_PREP_LABEL
        self.assertEqual(guard.RETAINED_OUTPUT_VECTORS[('test',label)],(label,))
        for vector in [('build',label),('test',label,'//:docs_check'),('test','//delivery:yoga_toolbar_consent_proof')]:
            self.assertNotIn(vector,guard.RETAINED_OUTPUT_VECTORS)


class ToolbarWorkerAndInventoryModels(unittest.TestCase):
    def test_actual_main_worker_dispatch_reaches_owned_go_log_and_original_argv(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as selected:
            run=Path(selected).resolve();(run/'go').write_bytes(b'owned coordinator go')
            command=guard.bazel_command('/declared/bazel',run,['test',guard.TOOLBAR_PREP_LABEL],
                source_commit='a'*40,source_dirty='false')
            process=Mock();process.stdout=io.BytesIO(b'bounded public worker fixture\n');process.wait.return_value=0
            with patch.dict(guard.os.environ,{'OMUX_EXECUTION_GUARD':str(run)},clear=True),\
                    patch.object(guard.subprocess,'Popen',return_value=process) as launch,\
                    patch.object(guard,'toolbar_prepare_selected',side_effect=AssertionError('worker is not coordinator')) as selection:
                self.assertEqual(guard.main(['--worker',str(run),'--',*command]),0)
            selection.assert_not_called();self.assertEqual(launch.call_args.args[0],command)
            self.assertEqual((run/'workload.log').read_bytes(),b'bounded public worker fixture\n')
            self.assertEqual(stat.S_IMODE((run/'workload.log').stat().st_mode),0o600)

    def test_actual_main_worker_keeps_original_ownership_refusal_before_log_or_spawn(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as selected:
            run=Path(selected).resolve();command=guard.bazel_command('/declared/bazel',run,['test',guard.TOOLBAR_PREP_LABEL])
            for environment in ({},{'OMUX_EXECUTION_GUARD':str(run/'different')}):
                with patch.dict(guard.os.environ,environment,clear=True),patch.object(guard.subprocess,'Popen') as launch:
                    with self.assertRaisesRegex(ValueError,'worker ownership marker missing'):
                        guard.main(['--worker',str(run),'--',*command])
                launch.assert_not_called();self.assertFalse((run/'workload.log').exists())

    def test_actual_main_coordinator_keeps_exact_selection_and_requires_explicit_inventory_before_tools(self):
        import execution_guard as guard
        base=['--manager','system','--source-commit','a'*40,'--source-dirty','false']
        pair=['--site-inventory','/owned/public/inventory.json','--site-inventory-sha256',guard.TOOLBAR_PREP_INVENTORY_SHA256]
        for flags,arguments in [(base,['test',guard.TOOLBAR_PREP_LABEL]),
                (base+pair+['--site-source','/foreign/spa'],['test',guard.TOOLBAR_PREP_LABEL]),
                (base+pair,['build',guard.TOOLBAR_PREP_LABEL]),
                (base+pair,['test',guard.TOOLBAR_PREP_LABEL,'//:docs_check']),
                (base+pair+['--reuse-owned-cache'],['test',guard.TOOLBAR_PREP_LABEL]),
                (base+pair+['--manager','user'],['test',guard.TOOLBAR_PREP_LABEL])]:
            with self.subTest(flags=flags,arguments=arguments),patch.object(guard,'immutable') as reader:
                with self.assertRaises(ValueError):guard.main([*flags,'--',*arguments])
                reader.assert_not_called()

    def test_only_exact_inventory_pair_supplies_cached_repo_binding_without_spa_source(self):
        import execution_guard as guard
        fields=('site_source','site_nixpkgs_source','site_phase','site_qualification','site_qualification_sha256',
            'site_delivery_manifest','site_delivery_manifest_sha256','site_reference_bundle','site_reference_bundle_sha256',
            'site_coordinator_inputs','site_coordinator_inputs_sha256',
            'site_development_artifact_selection','site_development_artifact_selection_sha256')
        args=SimpleNamespace(**{name:None for name in fields},site_inventory=Path('/owned/public/inventory.json'),
            site_inventory_sha256=guard.TOOLBAR_PREP_INVENTORY_SHA256)
        self.assertTrue(guard.toolbar_prepare_inventory_request(args,True))
        self.assertFalse(guard.toolbar_prepare_inventory_request(args,False))
        for field,value in [('site_inventory',None),('site_inventory_sha256','0'*64)]+[(field,'unrelated') for field in fields]:
            altered=SimpleNamespace(**{**vars(args),field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):guard.toolbar_prepare_inventory_request(altered,True)
        command=guard.bazel_command('/declared/bazel',Path('/owned/new-epoch'),['test',guard.TOOLBAR_PREP_LABEL],
            site_inventory=args.site_inventory,site_inventory_sha256=args.site_inventory_sha256)
        self.assertIn('--repo_env=OMUX_SITE_INVENTORY='+str(args.site_inventory),command)
        self.assertIn('--repo_env=OMUX_SITE_INVENTORY_SHA256='+args.site_inventory_sha256,command)
        self.assertFalse(any(value.startswith('--repo_env=OMUX_SITE_SOURCE=') for value in command))
        self.assertEqual(guard.selected_profile('standard',['test',guard.TOOLBAR_PREP_LABEL],site_inputs=True),{'PrivateNetwork':'yes'})

    def setUp(self):
        import execution_guard as guard
        self.guard=guard;temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.state=Path(temporary.name).resolve();self.state.chmod(0o700)
        self.path=self.state/'12345678-1234-4234-8234-123456789abc/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/cached_site_inventory_probe/test.outputs/inventory.json'
        self.path.parent.mkdir(parents=True);self.raw=b'{"public":"synthetic inventory bytes; no execution authority"}\n'
        self.path.write_bytes(self.raw);self.path.chmod(0o444);self.sha=hashlib.sha256(self.raw).hexdigest()
        self.entry=1000*10**9;self.deadline=self.entry+1200*10**9;self.now=self.entry+10**9
        def private(path,owner_only=True):
            self.assertEqual(Path(path),self.state);self.assertTrue(owner_only)
            self.assertEqual(stat.S_IMODE(self.state.lstat().st_mode),0o700)
        # Explicit public inventory hash + trusted temporary-root seam only;
        # production constant and filesystem source readers are not relaxed.
        self.hash_patch=patch.object(guard,'TOOLBAR_PREP_INVENTORY_SHA256',self.sha);self.hash_patch.start();self.addCleanup(self.hash_patch.stop)
        self.private_patch=patch.object(guard,'private',side_effect=private);self.private_patch.start();self.addCleanup(self.private_patch.stop)
        self.clock_patch=patch.object(guard.time,'monotonic_ns',side_effect=lambda:self.now);self.clock_patch.start();self.addCleanup(self.clock_patch.stop)

    def snapshot(self):
        return self.guard.toolbar_prepare_inventory_snapshot(self.path,self.sha,self.state,None,self.entry,self.deadline)

    def test_full_snapshot_is_stable_across_own_new_epoch_creation_without_prior_proof_credit(self):
        before=self.snapshot();(self.state/'new-guardian-epoch').mkdir(mode=0o700);after=self.snapshot()
        self.assertEqual(before,after);self.assertEqual(before['bytes'],len(self.raw))
        self.assertFalse(before['execution_authority']);self.assertFalse(before['prior_producer_success_inherited'])
        self.assertEqual(len(before['named_roles'][-1]['witness']),9)
        self.assertEqual(len(before['named_roles'][0]['witness']),5)

    def test_same_bytes_replaced_leaf_and_original_parent_cannot_match_pre_dispatch_snapshot(self):
        before=self.snapshot();replacement=self.path.with_name('replacement');replacement.write_bytes(self.raw);replacement.chmod(0o444)
        replacement.replace(self.path);self.assertNotEqual(before,self.snapshot())
        current=self.snapshot();parent=self.path.parent;parent.rename(parent.with_name('old-test.outputs'))
        parent.mkdir();self.path.write_bytes(self.raw);self.path.chmod(0o444)
        self.assertNotEqual(current,self.snapshot())

    def test_snapshot_refuses_missing_foreign_copied_writable_and_alias_inputs(self):
        for path in (self.state.parent/'foreign.json',self.path.with_name('copied-inventory.json'),
                Path(str(self.path).replace('cached_site_inventory_probe','other_producer'))):
            with self.subTest(path=path),self.assertRaises(ValueError):
                self.guard.toolbar_prepare_inventory_snapshot(path,self.sha,self.state,None,self.entry,self.deadline)
        with self.assertRaises(ValueError):
            self.guard.toolbar_prepare_inventory_snapshot(self.path,'0'*64,self.state,None,self.entry,self.deadline)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.snapshot()
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):self.snapshot()
        copy=self.path.with_name('same-public-bytes');copy.write_bytes(self.raw);copy.chmod(0o444)
        self.path.symlink_to(copy)
        with self.assertRaises(OSError):self.snapshot()

    def test_same_bytes_mutation_during_actual_inventory_read_refuses_held_metadata(self):
        actual=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            data=actual(fd,count)
            if data and not changed and os.fstat(fd).st_ino==self.path.lstat().st_ino:
                self.path.chmod(0o600);self.path.write_bytes(self.raw);self.path.chmod(0o444);changed=True
            return data
        with patch.object(self.guard.os,'read',side_effect=read),self.assertRaises(ValueError):self.snapshot()
        self.assertTrue(changed)

    def test_reader_first_cause_survives_attempt_all_once_descriptor_close_failure(self):
        body=MemoryError('fixture read allocation');cleanup=OSError(5,'fixture close');closed=[];armed=False;actual=os.close
        def read(fd,count):
            nonlocal armed
            armed=True;raise body
        def close(fd):
            if armed:closed.append(fd)
            actual(fd)
            if armed and len(closed)==1:raise cleanup
        with patch.object(self.guard.os,'read',side_effect=read),patch.object(self.guard.os,'close',side_effect=close):
            with self.assertRaises(MemoryError) as error:self.snapshot()
        self.assertIs(error.exception,body);self.assertIs(error.exception.__cause__,cleanup)
        self.assertGreater(len(closed),3);self.assertEqual(len(closed),len(set(closed)))

    def test_original_snapshot_cutoff_after_all_descriptor_close_refuses_without_new_clock(self):
        actual_read=os.read;actual_close=os.close;armed=False;closed=[]
        def read(fd,count):
            nonlocal armed
            result=actual_read(fd,count);armed=True;return result
        def close(fd):
            actual_close(fd)
            if armed:closed.append(fd);self.now=self.deadline-30*10**9
        with patch.object(self.guard.os,'read',side_effect=read),patch.object(self.guard.os,'close',side_effect=close):
            with self.assertRaises(ValueError):self.snapshot()
        self.assertGreater(len(closed),3);self.assertEqual(len(closed),len(set(closed)))

    def acquisition_fault(self,phase,position):
        guard=self.guard;body=MemoryError('fixture registration boundary');opened=[];closed=[];calls=0
        actual_open=os.open;actual_close=os.close;actual_register=guard.toolbar_prepare_inventory_register
        def open_fd(*args,**kwargs):
            fd=actual_open(*args,**kwargs);opened.append(fd);return fd
        def close_fd(fd):closed.append(fd);actual_close(fd)
        def register(owned):
            nonlocal calls
            calls+=1
            if calls!=position:return actual_register(owned)
            if phase=='entry':raise body
            class InsertionFault:
                def append(proxy,slot):
                    self.assertIsNone(slot.fd)
                    if phase=='after':owned.append(slot)
                    raise body
            return actual_register(InsertionFault())
        with patch.object(guard,'toolbar_prepare_inventory_register',side_effect=register),\
                patch.object(guard.os,'open',side_effect=open_fd),patch.object(guard.os,'close',side_effect=close_fd):
            with self.assertRaises(MemoryError) as error:self.snapshot()
        self.assertIs(error.exception,body)
        # Failure belongs to an EMPTY slot, before this acquisition. Every
        # previously acquired real root/parent/leaf FD is closed exactly once.
        self.assertEqual(len(opened),position-1)
        self.assertEqual(closed,list(reversed(opened)))
        self.assertEqual(len(closed),len(set(closed)))
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_preregister_call_entry_fault_opens_no_unowned_fd_at_every_acquisition_slot(self):
        slots=len(self.path.relative_to(self.state).parts)+1
        self.assertEqual(slots,12)
        for position in range(1,slots+1):
            with self.subTest(position=position):self.acquisition_fault('entry',position)

    def test_preregister_before_and_after_insertion_faults_drain_all_prior_fds_once(self):
        slots=len(self.path.relative_to(self.state).parts)+1
        for phase in ('before','after'):
            for position in range(1,slots+1):
                with self.subTest(phase=phase,position=position):self.acquisition_fault(phase,position)

    def graph_fixture(self):
        root=self.state/'current-graph';root.mkdir()
        (root/'BUILD.bazel').write_bytes(b'# synthetic declared graph fixture\n')
        (root/'tools').mkdir();(root/'tools/role.py').write_bytes(b'# exact synthetic tool input\n')
        return root,self.guard.graph_digest(root)

    def finish(self,before,graph,expected):
        return self.guard.toolbar_prepare_inventory_finish(self.path,self.sha,self.state,None,
            self.entry,self.deadline,before,expected,lambda:self.guard.graph_digest(graph))

    def test_terminal_actual_graph_matches_only_with_held_input_roles_and_original_cutoff(self):
        graph,expected=self.graph_fixture();before=self.snapshot();opened=[];closed=[];observed=False
        actual_open=os.open;actual_close=os.close
        def open_fd(name,*args,**kwargs):
            nonlocal observed
            if Path(name)==graph/'BUILD.bazel':
                self.assertEqual(len(opened),12)
                for descriptor in opened:os.fstat(descriptor)
                observed=True
                return actual_open(name,*args,**kwargs)
            fd=actual_open(name,*args,**kwargs)
            if kwargs.get('dir_fd') is not None or Path(name)==self.state:opened.append(fd)
            return fd
        def close_fd(fd):closed.append(fd);actual_close(fd)
        with patch.object(self.guard.os,'open',side_effect=open_fd),patch.object(self.guard.os,'close',side_effect=close_fd):
            after,accepted=self.finish(before,graph,expected)
        self.assertTrue(observed);self.assertTrue(accepted);self.assertEqual(before,after)
        self.assertEqual(closed,list(reversed(opened)))
        self.assertFalse(after['execution_authority']);self.assertFalse(after['prior_producer_success_inherited'])
        for descriptor in opened:
            with self.assertRaises(OSError):os.fstat(descriptor)

    def test_terminal_actual_graph_same_bytes_inventory_write_refuses_final_full_metadata(self):
        graph,expected=self.graph_fixture();before=self.snapshot();actual_open=os.open;changed=False
        def open_fd(name,*args,**kwargs):
            nonlocal changed
            if Path(name)==graph/'BUILD.bazel' and not changed:
                self.path.chmod(0o600);self.path.write_bytes(self.raw);self.path.chmod(0o444);changed=True
            return actual_open(name,*args,**kwargs)
        with patch.object(self.guard.os,'open',side_effect=open_fd),self.assertRaises(ValueError):
            self.finish(before,graph,expected)
        self.assertTrue(changed);self.assertEqual(self.guard.graph_digest(graph),expected)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_terminal_actual_graph_same_bytes_parent_replacement_refuses_named_held_join(self):
        graph,expected=self.graph_fixture();before=self.snapshot();actual_open=os.open;changed=False
        def open_fd(name,*args,**kwargs):
            nonlocal changed
            if Path(name)==graph/'BUILD.bazel' and not changed:
                parent=self.path.parent;parent.rename(parent.with_name('old-test.outputs'))
                parent.mkdir();self.path.write_bytes(self.raw);self.path.chmod(0o444);changed=True
            return actual_open(name,*args,**kwargs)
        with patch.object(self.guard.os,'open',side_effect=open_fd),self.assertRaises(ValueError):
            self.finish(before,graph,expected)
        self.assertTrue(changed);self.assertEqual(self.guard.graph_digest(graph),expected)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_terminal_actual_graph_cannot_replace_original_cutoff_with_its_fresh_read_budget(self):
        graph,expected=self.graph_fixture();before=self.snapshot();actual_open=os.open;late=False;closed=[];actual_close=os.close
        def open_fd(name,*args,**kwargs):
            nonlocal late
            if Path(name)==graph/'BUILD.bazel':self.now=self.deadline-30*10**9;late=True
            return actual_open(name,*args,**kwargs)
        def close_fd(fd):closed.append(fd);actual_close(fd)
        with patch.object(self.guard.os,'open',side_effect=open_fd),patch.object(self.guard.os,'close',side_effect=close_fd):
            with self.assertRaises(ValueError):self.finish(before,graph,expected)
        self.assertTrue(late);self.assertEqual(len(closed),12);self.assertEqual(len(closed),len(set(closed)))
        # Actual graph's independent15s reader still succeeds; it cannot grant
        # this caller a new1170s window after the original one expired.
        self.assertEqual(self.guard.graph_digest(graph),expected)

    def test_terminal_actual_graph_mismatch_keeps_inventory_metadata_but_refuses_acceptance(self):
        graph,expected=self.graph_fixture();before=self.snapshot()
        (graph/'tools/role.py').write_bytes(b'# changed declared synthetic graph input\n')
        after,accepted=self.finish(before,graph,expected)
        self.assertFalse(accepted);self.assertEqual(before,after)
        self.assertNotEqual(self.guard.graph_digest(graph),expected)

    def test_terminal_actual_graph_failure_preserves_first_cause_and_drains_all_input_owners(self):
        graph,expected=self.graph_fixture();before=self.snapshot();actual_open=os.open;actual_close=os.close
        body=MemoryError('fixture terminal graph read allocation');cleanup=OSError(5,'fixture terminal close')
        closed=[];armed=False
        def open_fd(name,*args,**kwargs):
            nonlocal armed
            if Path(name)==graph/'BUILD.bazel':armed=True;raise body
            return actual_open(name,*args,**kwargs)
        def close_fd(fd):
            actual_close(fd)
            if armed:
                closed.append(fd)
                if len(closed)==1:raise cleanup
        with patch.object(self.guard.os,'open',side_effect=open_fd),patch.object(self.guard.os,'close',side_effect=close_fd):
            with self.assertRaises(MemoryError) as error:self.finish(before,graph,expected)
        self.assertIs(error.exception,body);self.assertIs(error.exception.__cause__,cleanup)
        self.assertEqual(len(closed),12);self.assertEqual(len(closed),len(set(closed)))
        for descriptor in closed:
            with self.assertRaises(OSError):os.fstat(descriptor)

    def test_actual_root_open_boundary_mode_change_refuses_held_admission_and_closes_fd(self):
        actual_open=os.open;actual_close=os.close;opened=[];closed=[];changed=False
        def open_fd(name,*args,**kwargs):
            nonlocal changed
            if Path(name)==self.state:
                # private(root) already observed0700 and released its own scope.
                # The newly held root must independently admit its actual mode.
                self.state.chmod(0o777);changed=True
            fd=actual_open(name,*args,**kwargs);opened.append(fd);return fd
        def close_fd(fd):closed.append(fd);actual_close(fd)
        try:
            with patch.object(self.guard.os,'open',side_effect=open_fd),patch.object(self.guard.os,'close',side_effect=close_fd):
                with self.assertRaisesRegex(ValueError,'toolbar-public-inventory-root-refused'):self.snapshot()
        finally:self.state.chmod(0o700)
        self.assertTrue(changed);self.assertEqual(len(opened),1);self.assertEqual(closed,opened)
        with self.assertRaises(OSError):os.fstat(opened[0])


class ToolbarPreparationSchedulingModels(unittest.TestCase):
    def test_exact_actual_builder_serializes_only_standard_preparer_and_keeps_other_policy(self):
        import execution_guard as guard
        run=Path('/owned/12345678-1234-4234-8234-123456789abc')
        vector=['test',guard.TOOLBAR_PREP_LABEL]
        actual=guard.bazel_command('/declared/bazel',run,vector,source_commit='a'*40,source_dirty='false')
        ordinary=guard.bazel_command('/declared/bazel',run,['test','//:docs_check'],
            source_commit='a'*40,source_dirty='false')
        self.assertEqual([part for part in actual if part.startswith('--jobs')],['--jobs=1'])
        self.assertLess(actual.index('test'),actual.index('--jobs=1'))
        self.assertLess(actual.index('--jobs=1'),actual.index(guard.TOOLBAR_PREP_LABEL))
        self.assertEqual(actual[-1],guard.TOOLBAR_PREP_LABEL)
        # Apart from the fixed requested label and scheduling, the actual
        # complete builder output must preserve every startup/action flag.
        self.assertEqual([part.replace('--jobs=1','--jobs=2').replace(guard.TOOLBAR_PREP_LABEL,'//:docs_check')
            for part in actual],ordinary)
        for profile,arguments in [('standard',['build',guard.TOOLBAR_PREP_LABEL]),
                ('standard',['test',guard.TOOLBAR_PREP_LABEL,'//:docs_check']),
                ('standard',['test','//delivery:yoga_toolbar_consent_proof']),
                ('installed-browser',vector),('yoga-toolbar',vector)]:
            with self.subTest(profile=profile,arguments=arguments):
                self.assertEqual(guard.toolbar_prepare_action_jobs(profile,arguments),2)
        self.assertEqual(guard.controller_thread_profile(),
            {'legacy_globbing_threads':2,'fsvc_threads':2,'loading_phase_threads':2})
        self.assertEqual(guard.PROPERTIES['MemoryMax'],'4294967296')
        self.assertEqual(guard.PROPERTIES['TasksMax'],'512')
        self.assertEqual(guard.PROPERTIES['CPUQuotaPerSecUSec'],'2s')
        self.assertEqual(guard.CGROUP['memory.swap.max'],'0')
        for flag in ('--host_jvm_args=-Xmx1536m','--host_jvm_args=-XX:ActiveProcessorCount=2',
                '--nocache_test_results','--remote_executor=','--remote_cache=','--disk_cache=',
                '--sandbox_default_allow_network=false'):
            self.assertIn(flag,actual)

    def test_final_actual_toolbar_command_requires_unique_action_jobs_and_preserves_original_context(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory).resolve();run=source/'12345678-1234-4234-8234-123456789abc'
            entry=1000*10**9;until=entry+1200*10**9
            command=guard.bazel_command('/declared/bazel',run,['test',guard.TOOLBAR_PREP_LABEL],
                source_commit='a'*40,source_dirty='false')
            with patch.object(guard.time,'monotonic_ns',return_value=entry+10**9):
                result=guard.toolbar_prepare_command(command,run,entry,until,'a'*40,'b'*64,source)
                self.assertEqual([part for part in result if part.startswith('--jobs')],['--jobs=1'])
                self.assertEqual(command.count('--jobs=1'),1)
                self.assertNotIn('--jobs=2',result)
                self.assertIn('--test_env='+guard.TOOLBAR_PREP_VARIABLE+'ENTRY_NS='+str(entry),result)
                self.assertIn('--test_env='+guard.TOOLBAR_PREP_VARIABLE+'DEADLINE_NS='+str(until),result)
                self.assertEqual(len([part for part in result if part.startswith('--test_env='+guard.TOOLBAR_PREP_VARIABLE)]),6)
                malformed=[]
                for flag in ('--jobs=2','--jobs=100','--jobs=01','--jobs','--jobs-extra=1'):
                    malformed.append([flag if part=='--jobs=1' else part for part in command])
                malformed.append([part for part in command if part!='--jobs=1'])
                malformed.append(command[:-1]+['--jobs=1']+command[-1:])
                misplaced=[part for part in command if part!='--jobs=1']
                misplaced.insert(misplaced.index('test'),'--jobs=1');malformed.append(misplaced)
                for candidate in malformed:
                    with self.subTest(candidate=candidate),self.assertRaisesRegex(ValueError,'toolbar-preparation-context-refused'):
                        guard.toolbar_prepare_command(candidate,run,entry,until,'a'*40,'b'*64,source)
            with patch.object(guard.time,'monotonic_ns',return_value=until-30*10**9):
                with self.assertRaises(ValueError):guard.toolbar_prepare_command(command,run,entry,until,'a'*40,'b'*64,source)
            self.assertEqual(guard.toolbar_prepare_action_jobs('standard',['test',guard.TOOLBAR_PREP_LABEL]),1)
            for reuse,dirty in ((True,'false'),(False,'true')):
                with self.assertRaises(ValueError):
                    guard.toolbar_prepare_selected('standard','system',['test',guard.TOOLBAR_PREP_LABEL],reuse,dirty)



class Runtime009SeedOwnedWorkerReentryModels(unittest.TestCase):
    def test_actual_main_preserves_owned_full_bazel_worker_and_coordinator_refusals(self):
        import sys
        import execution_guard as guard
        import codex_owner_runtime_seed as seed
        with tempfile.TemporaryDirectory(dir=os.environ.get('TEST_TMPDIR')) as selected:
            root = Path(selected).resolve()
            root.chmod(0o700)
            run = root / '12345678-1234-4234-8234-123456789abc'
            run.mkdir(mode=0o700)
            child = root / 'synthetic-bazel'
            entry = time.monotonic_ns()
            deadline = entry + 1200 * 10**9
            command = guard.bazel_command(str(child), run, seed.ARGUMENTS,
                source_commit='a' * 40, source_dirty='false')
            command = seed.augment(command, run, entry, deadline, 'a' * 40, 'b' * 64, root)
            self.assertEqual(command[0], str(child))
            self.assertEqual(command[-2:], seed.ARGUMENTS[-2:])
            self.assertGreater(len(command), len(seed.ARGUMENTS))
            # Real declared locked-Python child accepts the actual builder argv;
            # no worker/Popen mock, nested Bazel, service or provider is invoked.
            child.write_text('#!' + sys.executable + '\nimport sys\n'
                + 'if sys.argv[1:] != ' + repr(command[1:]) + ': raise SystemExit(7)\n'
                + 'sys.stdout.write("OMUX_SYNTHETIC_SEED_WORKER_OK\\n")\n')
            child.chmod(0o700)
            (run / 'go').write_bytes(b'synthetic already-admitted worker gate')
            with patch.dict(os.environ, {'OMUX_EXECUTION_GUARD': str(root / 'foreign')}):
                with self.assertRaisesRegex(ValueError, 'worker ownership marker missing'):
                    guard.main(['--worker', str(run), '--', *command])
            self.assertFalse((run / 'workload.log').exists())
            with patch.dict(os.environ, {'OMUX_EXECUTION_GUARD': str(run)}):
                self.assertEqual(guard.main(['--worker', str(run), '--', *command]), 0)
            self.assertEqual((run / 'workload.log').read_bytes(), b'OMUX_SYNTHETIC_SEED_WORKER_OK\n')
            self.assertEqual(stat.S_IMODE((run / 'workload.log').stat().st_mode), 0o600)
            for arguments in (['test', seed.LABEL],
                    seed.ARGUMENTS + ['//:docs_check'], command):
                with self.subTest(coordinator_arguments=arguments):
                    with self.assertRaisesRegex(ValueError, 'runtime-seed-selection'):
                        guard.main(['--manager', 'system', '--source-commit', 'a' * 40,
                                    '--source-dirty', 'false', '--', *arguments])
            self.assertEqual((run / 'workload.log').read_bytes(), b'OMUX_SYNTHETIC_SEED_WORKER_OK\n')


class RetainedOrdinaryNativeSchedulingModels(unittest.TestCase):
    def test_actual_retained_pair_builder_serializes_clean_actions_and_keeps_complete_input_flags(self):
        import execution_guard as guard
        run=Path('/owned/12345678-1234-4234-8234-123456789abc')
        retained=Path('/owned/retained/runtime009')
        arguments=['test','//tools:codex_owner_runtime_input_qualification',
            '//delivery:installed_retained_ordinary_native_tui_test']
        def command(dirty):
            return guard.bazel_command('/declared/bazel',run,arguments,
                source_commit='a'*40,source_dirty=dirty,codex_owner_runtime_directory=retained)
        clean=command('false');dirty=command('true')
        self.assertEqual([part for part in clean if part.startswith('--jobs')],['--jobs=1'])
        self.assertEqual([part for part in dirty if part.startswith('--jobs')],['--jobs=2'])
        self.assertLess(clean.index('test'),clean.index('--jobs=1'))
        self.assertLess(clean.index('--jobs=1'),clean.index(arguments[1]))
        self.assertEqual(clean[-2:],arguments[-2:])
        self.assertEqual([part.replace('--jobs=1','--jobs=2')
            .replace('--define=OMUX_SOURCE_DIRTY=false','--define=OMUX_SOURCE_DIRTY=true') for part in clean],dirty)
        self.assertIn('--repo_env=OMUX_CODEX_OWNER_RUNTIME_DIRECTORY='+str(retained),clean)
        self.assertFalse(any(part.startswith('--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE=') for part in clean))
        self.assertEqual(guard.toolbar_prepare_action_jobs('standard',arguments,source_dirty='false'),1)
        self.assertEqual(guard.toolbar_prepare_action_jobs('standard',arguments,source_dirty='true'),2)
        for flag in ('--host_jvm_args=-Xmx1536m','--host_jvm_args=-XX:ActiveProcessorCount=2',
                '--nocache_test_results','--remote_executor=','--remote_cache=','--disk_cache=',
                '--spawn_strategy=sandboxed','--strategy=TestRunner=processwrapper-sandbox',
                '--sandbox_default_allow_network=false','--lockfile_mode=error'):
            self.assertIn(flag,clean)
        self.assertEqual(guard.controller_thread_profile(),
            {'legacy_globbing_threads':2,'fsvc_threads':2,'loading_phase_threads':2})
        self.assertEqual(guard.PROPERTIES['MemoryMax'],'4294967296')
        self.assertEqual(guard.PROPERTIES['TasksMax'],'512')
        self.assertEqual(guard.PROPERTIES['CPUQuotaPerSecUSec'],'2s')
        self.assertEqual(guard.CGROUP['memory.swap.max'],'0')

    def test_native_jobs_policy_requires_exact_order_profile_and_clean_provenance_without_new_admission(self):
        import execution_guard as guard
        from guard_owner_runtime_input import finite
        arguments=['test','//tools:codex_owner_runtime_input_qualification',
            '//delivery:installed_retained_ordinary_native_tui_test']
        for profile,vector,dirty in [('standard',arguments,None),('standard',arguments,'true'),
                ('standard',arguments,False),('standard',['test',*reversed(arguments[1:])],'false'),
                ('standard',['build',*arguments[1:]],'false'),('standard',['test',arguments[1]],'false'),
                ('standard',['test',arguments[2]],'false'),('standard',arguments+['//:docs_check'],'false'),
                ('standard',arguments+['--jobs=1'],'false'),('installed-browser',arguments,'false')]:
            with self.subTest(profile=profile,vector=vector,dirty=dirty):
                self.assertEqual(guard.toolbar_prepare_action_jobs(profile,vector,source_dirty=dirty),2)
        self.assertEqual(guard.toolbar_prepare_action_jobs('standard',['test',guard.TOOLBAR_PREP_LABEL]),1)
        self.assertTrue(guard.toolbar_prepare_selected('standard','system',['test',guard.TOOLBAR_PREP_LABEL]))
        for vector,unrelated in ((arguments,('/foreign/nixpkgs',)),
                (arguments+['//:unrelated'],()),(arguments+['--jobs=1'],())):
            with self.subTest(vector=vector,unrelated=unrelated),self.assertRaises(ValueError):
                finite('standard',vector,unrelated)
        run=Path('/owned/12345678-1234-4234-8234-123456789abc')
        retained=Path('/owned/retained/runtime009')
        for options in ({'source_commit':'a'*40,'source_dirty':None},
                {'source_commit':None,'source_dirty':'false'},
                {'source_commit':'a'*40,'source_dirty':'false','nixpkgs_source':Path('/foreign/nixpkgs')}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                guard.bazel_command('/declared/bazel',run,arguments,codex_owner_runtime_directory=retained,**options)
        with self.assertRaises(ValueError):
            guard.bazel_command('/declared/bazel',run,arguments+['--jobs=1'])



class MetadataWorkerTerminalModels(unittest.TestCase):
    @contextlib.contextmanager
    def channel(self):
        import execution_guard as guard
        import guard_resident_vault_profile as vault
        with tempfile.TemporaryDirectory() as temporary:
            run=Path(temporary)/"11111111-2222-3333-4444-555555555555";run.mkdir(mode=0o700)
            with patch.object(vault.resident,"open_directory",side_effect=lambda path,private=False:
                    os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)):
                owner=vault.MetadataOutput(run,time.monotonic_ns()+120*10**9)
                try:
                    owner.bind("a"*40,"b"*64,"c"*64,"d"*64)
                    environment={**owner.environment(),"OMUX_EXECUTION_GUARD":str(run),
                        vault.DEADLINE_VARIABLE:str(owner.deadline_ns)}
                    row={"uid":os.getuid(),"pid":101,"start_ticks":7}
                    observation={"schema":"omux-existing-vault-metadata-v2","broker":row,
                        "manager":dict(row,pid=102,owner=":1.2"),"secret_service":dict(row,pid=103,owner=":1.3"),
                        "provider":"standard-secret-service","default_collection":"/collection/existing",
                        "default_exists":True,"locked":False,"items_read":False,"secrets_read":False,"provider_invocation":False}
                    payload={"schema":"omux-resident-standard-vault-action-v1","purpose":"observe-standard-vault",
                        "observation":observation,"unlock_dispatched":False,"client_status":"not-dispatched",
                        "unlock_effect_scope":"not-dispatched","unchanged_service_owner":True,"unchanged_default_collection":True}
                    payload.update({key:False for key in ("factor_material_access","provider_invocation","omux_datastore_access",
                        "omux_wrapping_key_regeneration","resident_key_readiness_proven","resident_custody_proven",
                        "normal_os_unlock_passed","native_support")})
                    producer=vault.MetadataOutput.consume(environment)
                    try:producer.publish(payload);terminal=producer.terminal_frame()
                    finally:producer.close()
                    frame=(vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n").decode("ascii")
                    admission=SimpleNamespace(manifest="/private/input.json",environment=lambda:
                        {key:value for key,value in environment.items() if key!="OMUX_EXECUTION_GUARD"})
                    command=guard.resident_enrollment_command("/declared/bazel",run,["run",vault.STANDARD_LABEL],admission,
                        source_commit="a"*40,source_dirty="false")
                    (run/"go").write_bytes(b"go")
                    yield guard,vault,owner,environment,run,command,frame,terminal,payload
                finally:owner.close()

    def test_actual_worker_private_pipe_accepts_one_creator_and_parent_holds_both_files(self):
        with self.channel() as (guard,vault,owner,environment,run,command,frame,terminal,payload):
            actual_popen=guard.subprocess.Popen
            def child(parts,**options):
                self.assertEqual(parts,command)
                return actual_popen([sys.executable,"-I","-B","-c",
                    "import sys;print('public build diagnostic');sys.stdout.write(sys.argv[1]);sys.stdout.flush()",frame],**options)
            with patch.dict(guard.os.environ,environment,clear=True),patch.object(guard.subprocess,"Popen",side_effect=child):
                self.assertEqual(guard.worker(run,command),0)
            owner.pin_ack();owner.verify_output()
            self.assertIsNotNone(owner.output_fd);self.assertIsNotNone(owner.ack_fd)
            self.assertEqual(owner.output_snapshot[0],tuple(terminal["leaf"]))
            self.assertEqual(owner.output_snapshot[1],vault.MetadataOutput.metadata_bytes(payload))

    def test_actual_private_pipe_nonzero_child_never_produces_accepted_ack(self):
        with self.channel() as (guard,vault,_,environment,run,command,frame,_,_):
            actual_popen=guard.subprocess.Popen
            with patch.dict(guard.os.environ,environment,clear=True),patch.object(guard.subprocess,"Popen",side_effect=lambda parts,**options:
                    actual_popen([sys.executable,"-I","-B","-c","import sys;print(sys.argv[1]);sys.exit(7)",frame],**options)):
                with self.assertRaises(ValueError):guard.worker(run,command)
            self.assertFalse((run/vault.ACK_NAME).exists())

    def test_canonical_context_matches_actual_properties_split_and_same_command_tuple(self):
        with self.channel() as (guard,_,owner,_,run,command,_,_,_):
            environment=owner.environment()
            rendered="Environment="+shlex.join([key+"="+value for key,value in environment.items()])+"\n"
            actual=guard.properties(rendered)
            self.assertTrue({key+"="+value for key,value in environment.items()}.issubset(
                set(actual["Environment"].split())))
            for key,value in environment.items():
                self.assertEqual(command.count("--run_env="+key+"="+value),1)
                self.assertEqual(shlex.quote(key+"="+value),key+"="+value)



class ToolbarReceiverModels(unittest.TestCase):
    def receiver_args(self,root):
        return SimpleNamespace(profile='standard',manager='system',reuse_owned_cache=False,
            source_dirty='false',coordination_dir=root,
            toolbar_artifact_selection=root/'toolbar-public-artifact-selection.json',
            toolbar_artifact_selection_sha256='a'*64,site_source=None,site_inventory=None,
            site_inventory_sha256=None,site_nixpkgs_source=None,site_phase=None,
            site_qualification=None,site_qualification_sha256=None,site_delivery_manifest=None,
            site_delivery_manifest_sha256=None,site_reference_bundle=None,site_reference_bundle_sha256=None,
            site_coordinator_inputs=None,site_coordinator_inputs_sha256=None,
            site_development_artifact_selection=None,site_development_artifact_selection_sha256=None)

    def test_only_exact_fresh_receiver_and_owned_selection_role_are_admitted(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);args=self.receiver_args(root)
            path=args.toolbar_artifact_selection;path.write_bytes(b'public selector role, content not yet qualified');path.chmod(0o600)
            self.assertTrue(guard.toolbar_receive_selected(args,['test',guard.TOOLBAR_RECEIVE_LABEL]))
            for field,value in [('profile','yoga-toolbar'),('manager','user'),('reuse_owned_cache',True),
                    ('source_dirty','true'),('toolbar_artifact_selection_sha256','bad'),
                    ('site_inventory',root/'unrelated'),('site_development_artifact_selection',root/'other')]:
                original=getattr(args,field);setattr(args,field,value)
                with self.subTest(field=field),self.assertRaises(ValueError):
                    guard.toolbar_receive_selected(args,['test',guard.TOOLBAR_RECEIVE_LABEL])
                setattr(args,field,original)
            for vector in (['build',guard.TOOLBAR_RECEIVE_LABEL],['test',guard.TOOLBAR_RECEIVE_LABEL,'//:docs_check']):
                with self.subTest(vector=vector),self.assertRaises(ValueError):guard.toolbar_receive_selected(args,vector)
            path.chmod(0o644)
            with self.assertRaises(ValueError):guard.toolbar_receive_selected(args,['test',guard.TOOLBAR_RECEIVE_LABEL])
            path.chmod(0o600)
            with self.assertRaises(ValueError):guard.toolbar_receive_selected(args,['test','//:docs_check'])
            args.toolbar_artifact_selection=args.toolbar_artifact_selection_sha256=None
            self.assertFalse(guard.toolbar_receive_selected(args,['test','//:docs_check']))

    def test_actual_receiver_builder_has_jobs1_and_exact_original_context_without_override(self):
        import execution_guard as guard
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory).resolve();run=source/'12345678-1234-4234-8234-123456789abc'
            path=source/'toolbar-public-artifact-selection.json';entry=1000*10**9;deadline=entry+1200*10**9
            command=guard.bazel_command('/declared/bazel',run,['test',guard.TOOLBAR_RECEIVE_LABEL],
                source_commit='a'*40,source_dirty='false')
            self.assertEqual([part for part in command if part.startswith('--jobs')],['--jobs=1'])
            with patch.object(guard.time,'monotonic_ns',return_value=entry+10**9):
                actual=guard.toolbar_receive_command(command,run,entry,deadline,'a'*40,'b'*64,source,path,'c'*64)
                injected=[part for part in actual if part.startswith('--test_env='+guard.TOOLBAR_RECEIVE_VARIABLE)]
                self.assertEqual(len(injected),8)
                self.assertIn('--test_env='+guard.TOOLBAR_RECEIVE_VARIABLE+'ENTRY_NS='+str(entry),actual)
                self.assertIn('--test_env='+guard.TOOLBAR_RECEIVE_VARIABLE+'DEADLINE_NS='+str(deadline),actual)
                self.assertEqual([part for part in actual if part not in injected],command)
                with self.assertRaises(ValueError):guard.toolbar_receive_command(actual,run,entry,deadline,'a'*40,'b'*64,source,path,'c'*64)
                with self.assertRaises(ValueError):guard.toolbar_receive_command(command[:-1]+['//:docs_check'],run,entry,deadline,'a'*40,'b'*64,source,path,'c'*64)
            with patch.object(guard.time,'monotonic_ns',return_value=deadline-30*10**9):
                with self.assertRaises(ValueError):guard.toolbar_receive_command(command,run,entry,deadline,'a'*40,'b'*64,source,path,'c'*64)
            self.assertEqual(guard.PROPERTIES['MemoryMax'],'4294967296')
            self.assertEqual(guard.PROPERTIES['TasksMax'],'512')
            self.assertEqual(guard.CGROUP['memory.swap.max'],'0')


if __name__ == '__main__':
    unittest.main()
