"""Pure fake-controller predicates; run only through the declared Bazel target.

Live acceptance still requires bounded declared stress actions: exceed 512 tasks,
4 GiB memory, 8 MiB output, runtime deadline and cancellation, then read back
empty descendants. These tests do not perform those workloads or call systemd.
"""
import tempfile
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
        run=Path('/private/11111111-1111-4111-8111-111111111111')
        admission=SimpleNamespace(facts={'scope':namespace.SCOPE},manifest=Path('/public/input.json'),environment=lambda:{'OMUX_RESIDENT_NAMESPACE_EPOCH':run.name})
        command=resident.command(bazel_command,'/nix/store/public/bin/bazel',run,['run',namespace.LABEL],admission,
            source_commit='1'*40,source_dirty='false',repository_cache=resident.REPOSITORY_CACHE,nixpkgs_source=resident.NIXPKGS)
        self.assertIn('run',command); self.assertNotIn('build',command)
        self.assertEqual(command[-1],namespace.LABEL)
        for flag in ('--batch','--disable_download','--repo_contents_cache=','--spawn_strategy=linux-sandbox','--disk_cache=',
            '--repository_cache='+str(resident.REPOSITORY_CACHE),'--run_env=OMUX_RESIDENT_NAMESPACE_EPOCH='+run.name): self.assertIn(flag,command)
        self.assertFalse(any(part.startswith('--repo_env=OMUX_CODEX_FRESH_RUNTIME_SELECTION=') and part.split('=',2)[-1] for part in command))
        with self.assertRaises(ValueError): resident.command(bazel_command,'/nix/store/public/bin/bazel',run,['run',namespace.LABEL,'--'],admission,source_commit='1'*40,source_dirty='false')

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
        pauses = []
        def pause(seconds): pauses.append(seconds); clock.advance(seconds)
        def iteration(): observations.sample(pin, 'monitor'); sequence.append('iteration')
        result = monitor_workload(lambda: next(replies), 10, iteration, clock=clock, pause=pause)
        self.assertIsNone(observe_pids_before_cleanup(observations, pin))
        sequence.append('cleanup'); observations.finish(pin)
        self.assertEqual(result, 0); self.assertEqual(pauses, [0.5])
        self.assertEqual(sequence, ['sample', 'sample', 'iteration', 'sample', 'iteration', 'sample', 'cleanup'])
        self.assertEqual(observations.receipt()['monitor_samples'], 2)
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
            (site / 'flake.lock').chmod(0o600)
            with self.assertRaises(ValueError):
                selected_site_source(site, repository)
            (site / 'flake.lock').unlink()
            (site / 'flake.lock').symlink_to(site / 'flake.nix')
            with self.assertRaises(OSError):
                selected_site_source(site, repository)

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
        self.assertIn('--output_base=/private/uuid/output-base', command)
        self.assertIn('--noworkspace_rc', command)
        self.assertIn('--remote_executor=', command)
        self.assertIn('--host_jvm_args=-Xmx1536m', command[:command.index('test')])
        self.assertIn('--host_jvm_args=-XX:ActiveProcessorCount=2', command[:command.index('test')])
        for args in ([], ['--batch', 'test'], ['test', '--output_base=/shared'],
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


if __name__ == '__main__':
    unittest.main()
