import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock
import yoga_controller_delivery as delivery
import guard_yoga_delivery_profile as profile

class DeliveryTests(unittest.TestCase):
    def host_key_fixture(self):
        import contextlib
        import tempfile
        from pathlib import Path
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        temporary = stack.enter_context(tempfile.TemporaryDirectory(dir=delivery.os.environ.get('TEST_TMPDIR')))
        source = Path(temporary) / 'public-pin'
        source.write_bytes(b'public-fixture'.ljust(97, b'x'))
        source.chmod(0o600)
        stack.enter_context(patch.object(delivery, 'KNOWN_HOSTS_SOURCE', str(source)))
        stack.enter_context(patch.object(delivery, 'KNOWN_HOSTS_SHA256',
            delivery.hashlib.sha256(source.read_bytes()).hexdigest()))
        # Model trusted ancestor admission; retain real FDs/stat/name changes.
        stack.enter_context(patch.object(delivery, 'host_key_directory', return_value=True))
        stack.enter_context(patch.object(delivery.time, 'monotonic', return_value=0))
        return source

    def test_known_host_input_retains_named_file_and_all_ancestor_custody(self):
        source = self.host_key_fixture()
        authority = delivery.KnownHostAuthority(str(source), 1200)
        descriptor = authority.fd
        authority.check()
        self.assertGreater(len(authority.parents), 1)
        source.rename(source.with_name('previous'))
        source.write_bytes(b'public-fixture'.ljust(97, b'x'))
        source.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'known-hosts'):
            authority.check()
        authority.close()
        with self.assertRaises(OSError):
            delivery.os.fstat(descriptor)

    def test_known_host_input_refuses_actual_named_ancestor_replacement(self):
        original = self.host_key_fixture()
        parent = original.parent / 'selected'
        parent.mkdir(mode=0o700)
        source = parent / 'public-pin'
        original.rename(source)
        with patch.object(delivery, 'KNOWN_HOSTS_SOURCE', str(source)):
            authority = delivery.KnownHostAuthority(str(source), 1200)
            parent.rename(parent.with_name('previous-parent'))
            parent.mkdir(mode=0o700)
            source.write_bytes(b'public-fixture'.ljust(97, b'x'))
            source.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'known-hosts'):
                authority.check()
            authority.close()

    def test_known_host_input_refuses_changed_declared_alias_and_bytes(self):
        source = self.host_key_fixture()
        alias = source.with_name('declared')
        alias.symlink_to(source.name)
        authority = delivery.KnownHostAuthority(str(alias), 1200)
        source.write_bytes(b'changed'.ljust(97, b'x'))
        with self.assertRaisesRegex(ValueError, 'known-hosts'):
            authority.check()
        authority.close()
        source.write_bytes(b'public-fixture'.ljust(97, b'x'))
        authority = delivery.KnownHostAuthority(str(alias), 1200)
        alias.unlink()
        alias.symlink_to(source.name)
        with self.assertRaisesRegex(ValueError, 'declared-alias'):
            authority.check()
        authority.close()

    def test_ssh_trust_options_precede_operator_config_and_after_failure_recheck(self):
        source = self.host_key_fixture()
        authority = delivery.KnownHostAuthority(str(source), 1200)
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.ssh, backend.options, backend.deadline, backend.env = 'fixed', ['-F', 'operator'], 1200, {}
        backend.known_hosts = authority
        with patch.object(delivery, 'owned_io', return_value=(255, b'', b'Host key verification failed')) as call, \
                patch.object(authority, 'check', wraps=authority.check) as check:
            with self.assertRaises(delivery.GateError):
                backend.call('fixed-os-bootstrap')
        command = call.call_args.args[0]
        self.assertLess(command.index('-oUserKnownHostsFile=' + str(source)), command.index('-F'))
        for option in ('-oStrictHostKeyChecking=yes', '-oUpdateHostKeys=no',
                       '-oGlobalKnownHostsFile=/dev/null', '-oKnownHostsCommand=none',
                       '-oVerifyHostKeyDNS=no', '-oHostKeyAlgorithms=ssh-ed25519',
                       '-oHostKeyAlias=100.104.152.110'):
            self.assertIn(option, command)
        self.assertEqual(check.call_count, 2)
        authority.close()

    def test_known_host_failed_entry_recheck_releases_every_retained_descriptor(self):
        source = self.host_key_fixture()
        authority = delivery.KnownHostAuthority(str(source), 1200)
        descriptors = [authority.fd, *authority.parents]
        with patch.object(authority, 'check', side_effect=delivery.GateError('known-hosts-entry-changed')):
            with self.assertRaisesRegex(delivery.GateError, 'known-hosts-entry-changed'):
                with authority:
                    self.fail('entry refusal must prevent body')
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                delivery.os.fstat(descriptor)

    def test_returned_ssh_failure_survives_postcall_key_refusal(self):
        source = self.host_key_fixture()
        authority = delivery.KnownHostAuthority(str(source), 1200)
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.ssh, backend.options, backend.deadline, backend.env = 'fixed', [], 1200, {}
        backend.known_hosts = authority
        with patch.object(authority, 'check', side_effect=[None, delivery.GateError('known-hosts-changed')]), \
                patch.object(delivery, 'owned_io', return_value=(255, b'', b'Host key verification failed')):
            with self.assertRaisesRegex(delivery.GateError, 'store-transport') as caught:
                backend.call('fixed-os-bootstrap')
        self.assertEqual(caught.exception.hints['sshExitStatus'], 255)
        self.assertTrue(caught.exception.hints['stderrFlags']['host_key_rejected'])
        self.assertTrue(caught.exception.host_key_authority_recheck_failed)
        authority.close()

    def test_ssh_primary_cleanup_failure_survives_postcall_key_refusal(self):
        source = self.host_key_fixture()
        authority = delivery.KnownHostAuthority(str(source), 1200)
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.ssh, backend.options, backend.deadline, backend.env = 'fixed', [], 1200, {}
        backend.known_hosts = authority
        with patch.object(authority, 'check', side_effect=[None, delivery.GateError('known-hosts-changed')]), \
                patch.object(delivery, 'owned_io', side_effect=delivery.GateError('child-reap-unproved')):
            with self.assertRaisesRegex(delivery.GateError, 'child-reap-unproved') as caught:
                backend.call('fixed-os-bootstrap')
        self.assertTrue(caught.exception.host_key_authority_recheck_failed)
        authority.close()
    def test_ssh_failure_reports_only_finite_stage_status_and_boolean_observations(self):
        stderr = b'Host key verification failed. private-sample-must-not-escape'
        failure = delivery.ssh_failure('authenticated-os-qualification', 255, stderr)
        self.assertEqual(str(failure), 'store-transport')
        self.assertEqual(set(failure.hints), {'schemaVersion', 'stage', 'sshExitStatus', 'stderrFlags'})
        self.assertEqual(failure.hints['stage'], 'authenticated-os-qualification')
        self.assertEqual(failure.hints['sshExitStatus'], 255)
        self.assertTrue(failure.hints['stderrFlags']['host_key_rejected'])
        self.assertTrue(all(type(value) is bool for value in failure.hints['stderrFlags'].values()))
        self.assertNotIn('private-sample', json.dumps(failure.hints))
        self.assertFalse(failure.hints['stderrFlags']['os_bootstrap_predicate_refused'])
        for stage, status in (('caller-command', 255), ('qualified-nix-readonly', 0),
                              ('authenticated-os-qualification', True), ('qualified-nix-readonly', 256)):
            with self.assertRaises(ValueError):
                delivery.ssh_failure(stage, status, stderr)

    def test_ssh_failure_adds_only_exact_closed_remote_step_observation(self):
        marker = b'omux-yoga-bootstrap-failure-v1:hm-marker-resolution:missing-input'
        failure = delivery.ssh_failure('authenticated-os-qualification',1,
            marker+b'\nNo such file: private-fixture-must-not-escape')
        self.assertEqual(failure.hints['osBootstrapFailure'],
                         {'step':'hm-marker-resolution','category':'missing-input'})
        self.assertTrue(failure.hints['stderrFlags']['missing_tool_mentioned'])
        self.assertNotIn('private-fixture',json.dumps(failure.hints))
        unobserved = delivery.ssh_failure('authenticated-os-qualification',1,b'No such file')
        self.assertNotIn('osBootstrapFailure',unobserved.hints)
        duplicate = delivery.ssh_failure('authenticated-os-qualification',1,marker+b'\n'+marker)
        self.assertNotIn('osBootstrapFailure',duplicate.hints)

    def test_nonzero_qualify_ssh_status_retains_closed_observations_after_owned_cleanup(self):
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.ssh, backend.options, backend.deadline, backend.env = 'fixed', [], 1200, {}
        backend.known_hosts = Mock()
        backend.known_hosts.options.return_value = []
        with patch.object(delivery.time, 'monotonic', return_value=0), \
                patch.object(delivery, 'owned_io', return_value=(255, b'', b'Connection refused')) as bounded:
            with self.assertRaises(delivery.GateError) as captured:
                backend.call('fixed-os-bootstrap')
        self.assertEqual(str(captured.exception), 'store-transport')
        self.assertTrue(captured.exception.hints['stderrFlags']['connection_refused'])
        self.assertEqual(captured.exception.hints['stage'], 'authenticated-os-qualification')
        self.assertEqual(bounded.call_args.args[0][-2:], ['yoga', 'fixed-os-bootstrap'])
        self.assertEqual(bounded.call_args.args[2], 1170)

    def test_readonly_nix_failure_stage_does_not_claim_os_qualification(self):
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.deadline, backend.authority = 1200, {'remote': None}
        with patch.object(delivery.qualification, 'remote_command', return_value='fixed-command'), \
                patch.object(backend, 'call', side_effect=delivery.ssh_failure(
                    'qualified-nix-readonly', 1, b'remote-bootstrap-qualification-refused')) as call:
            with self.assertRaises(delivery.GateError) as captured:
                backend.nix_call('--offline')
        call.assert_called_once_with('fixed-command', 2 * 1024 * 1024, stage='qualified-nix-readonly')
        self.assertTrue(captured.exception.hints['stderrFlags']['os_bootstrap_predicate_refused'])
        self.assertEqual(captured.exception.hints['stage'], 'qualified-nix-readonly')

    def test_setup_failure_unwinds_owned_child(self):
        child = Mock(pid=321, returncode=0)
        with patch.object(delivery.subprocess, 'Popen', return_value=child), \
                patch.object(delivery.os, 'getpgid', return_value=321), \
                patch.object(delivery.os, 'killpg') as kill, \
                patch.object(delivery.selectors, 'DefaultSelector', side_effect=RuntimeError('setup')), \
                patch.object(delivery.time, 'monotonic', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'setup'):
                delivery.owned_io(['fixed'], {}, 20, 10)
            kill.assert_called_once_with(321, delivery.signal.SIGKILL)
            child.wait.assert_called_once()
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            child.poll.assert_not_called()

    def test_exit_observed_unreaped_until_signal_then_wait(self):
        order = []
        child = Mock(pid=321, returncode=0)
        child.wait.side_effect = lambda **kwargs: order.append('reap')
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(delivery.subprocess, 'Popen', return_value=child), \
                patch.object(delivery.os, 'getpgid', return_value=321), \
                patch.object(delivery.os, 'waitid', return_value=object()) as observe, \
                patch.object(delivery.os, 'killpg', side_effect=lambda *args: order.append('signal')), \
                patch.object(delivery.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(delivery.time, 'monotonic', return_value=0):
            delivery.owned_io(['fixed'], {}, 20, 10)
            self.assertEqual(order, ['signal', 'reap'])
            self.assertTrue(observe.call_args.args[2] & delivery.os.WNOWAIT)
            child.poll.assert_not_called()
            selector.close.assert_called_once()

    def test_authority_refused_before_ssh_spawn(self):
        authority = {'sshPath': delivery.qualification.SSH, 'sshSha256': '0'*64, 'remote': None}
        with patch.object(delivery.qualification, 'executable_hash', side_effect=ValueError('digest')), \
                patch.object(delivery.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'digest'):
                delivery.Backend(authority['sshPath'], [], 20, authority)
            spawn.assert_not_called()

    def test_local_digest_deadline_precedes_open(self):
        with patch.object(delivery.time, 'monotonic', return_value=20), \
                patch.object(delivery.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                delivery.qualify_ssh('/nix/store/fixed/bin/ssh', '0'*64, 20)
            opened.assert_not_called()

    def test_local_digest_rejects_owner_writable_and_closes(self):
        info = SimpleNamespace(st_mode=delivery.stat.S_IFREG | 0o755,
                               st_uid=0, st_size=1)
        with patch.object(delivery.time, 'monotonic', return_value=0), \
                patch.object(delivery.os, 'open', return_value=7), \
                patch.object(delivery.os, 'fstat', return_value=info), \
                patch.object(delivery.os, 'close') as closed:
            with self.assertRaisesRegex(ValueError, 'custody'):
                delivery.qualify_ssh('/nix/store/fixed/bin/ssh', '0'*64, 20)
            closed.assert_called_once_with(7)

    def test_final_fence_rejects_exhaustion(self):
        with patch.object(delivery.time, 'monotonic', return_value=20):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                delivery.fence(20)

    def test_duplicate_json_fields_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-json'):
            delivery.strict_json(b'{"trusted":true,"trusted":false}')

    def test_exact_graph_admission(self):
        label = '//tools:yoga_controller_qualify'
        self.assertEqual(profile.selected(['run', label]), {'PrivateNetwork': 'no'})
        for arguments in (['test', label], ['run', '//...'],
                          ['run', label, '//:docs_check'], ['run', '//tools:yoga_controller_copy']):
            with self.assertRaises(ValueError):
                profile.selected(arguments)

    def test_registry_is_not_content_proof(self):
        row = {'path': '/nix/store/' + 'a'*32 + '-input', 'narSize': 1,
               'narHash': 'sha256:' + '0'*64, 'references': []}
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.nix = '/nix/store/' + 'b'*32 + '-nix/bin/nix'
        with patch.object(backend, 'nix_call', side_effect=[json.dumps({row['path']: row}).encode(),
                ('sha256:' + '1'*64).encode()]):
            with self.assertRaisesRegex(ValueError, 'content-mismatch'):
                backend.verify([row])

    def test_schema_rejects_duplicate_fields(self):
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.deadline = 1200
        with patch.object(delivery.qualification.time, 'monotonic_ns', return_value=0), \
                patch.object(backend, 'call', return_value=b'{"uid":1000,"uid":1000}'):
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                backend.qualify()

    def test_shared_deadline_does_not_reset(self):
        backend = delivery.Backend.__new__(delivery.Backend)
        backend.deadline = 50
        with patch.object(delivery.time, 'monotonic', return_value=21), \
                patch.object(delivery, 'owned_io') as bounded:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                backend.call('fixed-read-only-command')
            bounded.assert_not_called()

    def test_child_primary_failure_survives_independent_cleanup_failures(self):
        child = Mock(pid=321,returncode=0)
        child.stdout.close.side_effect = OSError('pipe')
        with patch.object(delivery.subprocess,'Popen',return_value=child), \
                patch.object(delivery.os,'getpgid',return_value=321), \
                patch.object(delivery.os,'killpg',side_effect=OSError('signal')) as kill, \
                patch.object(delivery.selectors,'DefaultSelector',side_effect=ValueError('primary-output')), \
                patch.object(delivery.time,'monotonic',return_value=0), \
                patch.object(delivery.signal,'signal',return_value=delivery.signal.SIG_DFL):
            with self.assertRaisesRegex(ValueError,'primary-output') as captured:
                delivery.owned_io(['fixed'],{},20,10)
        child.wait.assert_called_once(); child.stderr.close.assert_called_once()
        self.assertEqual(len(captured.exception.__notes__),1)
        self.assertIn('child-group-cleanup-failed',captured.exception.__notes__[0])
        self.assertIn('child-resource-release-failed',captured.exception.__notes__[0])

    def test_cancellation_during_setup_still_signals_original_unreaped_group(self):
        child = Mock(pid=321,returncode=0)
        handlers,restored = {},[]
        def signal_handler(signum,handler):
            if callable(handler): handlers[signum] = handler
            else: restored.append(signum)
            return delivery.signal.SIG_DFL
        def created(*args,**kwargs):
            handlers[delivery.signal.SIGTERM](delivery.signal.SIGTERM,None)
            return child
        with patch.object(delivery.subprocess,'Popen',side_effect=created), \
                patch.object(delivery.os,'getpgid',return_value=321), \
                patch.object(delivery.os,'killpg') as kill, \
                patch.object(delivery.time,'monotonic',return_value=0), \
                patch.object(delivery.signal,'signal',side_effect=signal_handler):
            with self.assertRaisesRegex(ValueError,'cancelled'):
                delivery.owned_io(['fixed'],{},20,10)
        kill.assert_called_once_with(321,delivery.signal.SIGKILL)
        child.wait.assert_called_once(); child.poll.assert_not_called()
        self.assertEqual(set(restored),{delivery.signal.SIGINT,delivery.signal.SIGTERM,delivery.signal.SIGHUP})

    def test_declared_public_alias_rebinding_is_refused(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root/'original'; other = root/'other'; alias = root/'alias'
            original.write_bytes(b'original'); other.write_bytes(b'other'); alias.symlink_to(original.name)
            # The fixture uses physical temp paths without admitting /tmp custody.
            actual_resolve = Path.resolve
            def resolve(path,*args,**kwargs):
                if path == alias:
                    resolve.calls += 1
                    if resolve.calls == 2: return other
                return actual_resolve(path,*args,**kwargs)
            resolve.calls = 0
            actual_fstat = delivery.os.fstat
            def public_fixture(descriptor):
                info = actual_fstat(descriptor)
                if delivery.stat.S_ISDIR(info.st_mode):
                    values = {name:getattr(info,name) for name in ('st_dev','st_ino','st_uid','st_mode')}
                    values.update(st_uid=0,st_mode=delivery.stat.S_IFDIR|0o555)
                    return SimpleNamespace(**values)
                return info
            with patch.object(Path,'resolve',resolve),patch.object(delivery.time,'monotonic',return_value=0), \
                    patch.object(delivery.os,'fstat',side_effect=public_fixture):
                with self.assertRaisesRegex(ValueError,'public-input-changed'): delivery.read_public(alias,4096,20)
            self.assertEqual(resolve.calls,2)

    def test_expired_original_deadline_never_restarts_child_reap_wait(self):
        child = Mock(pid=321,returncode=0)
        selector = Mock(); selector.get_map.return_value = {}
        with patch.object(delivery.subprocess,'Popen',return_value=child), \
                patch.object(delivery.os,'getpgid',return_value=321), \
                patch.object(delivery.os,'waitid',return_value=object()), \
                patch.object(delivery.os,'killpg') as kill, \
                patch.object(delivery.selectors,'DefaultSelector',return_value=selector), \
                patch.object(delivery.time,'monotonic',side_effect=[0,0,0,20]), \
                patch.object(delivery.signal,'signal',return_value=delivery.signal.SIG_DFL):
            with self.assertRaisesRegex(ValueError,'child-reap-unproved'): delivery.owned_io(['fixed'],{},20,10)
        child.wait.assert_not_called(); kill.assert_called_once_with(321,delivery.signal.SIGKILL)
        selector.close.assert_called_once(); child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()

    def test_cleanup_only_failure_marks_incomplete_after_successful_read(self):
        child = Mock(pid=321,returncode=0); child.stdout.close.side_effect = OSError('release')
        selector = Mock(); selector.get_map.return_value = {}
        with patch.object(delivery.subprocess,'Popen',return_value=child), \
                patch.object(delivery.os,'getpgid',return_value=321), \
                patch.object(delivery.os,'waitid',return_value=object()), \
                patch.object(delivery.os,'killpg'), \
                patch.object(delivery.selectors,'DefaultSelector',return_value=selector), \
                patch.object(delivery.time,'monotonic',return_value=0), \
                patch.object(delivery.signal,'signal',return_value=delivery.signal.SIG_DFL):
            with self.assertRaisesRegex(ValueError,'child-resource-release-failed') as captured:
                delivery.owned_io(['fixed'],{},20,10)
        self.assertTrue(captured.exception.cleanup_incomplete)
        child.wait.assert_called_once(); child.stderr.close.assert_called_once(); selector.close.assert_called_once()

    def test_remote_reference_types_refuse_before_set_sort(self):
        row = {'path':'/nix/store/'+'a'*32+'-input','narSize':1,'narHash':'sha256:'+'0'*64,'references':[]}
        for references in ([{}],[[]],[False],['/tmp/reference'],[42,'/nix/store/'+'b'*32+'-input']):
            actual = dict(row,references=references)
            with self.assertRaisesRegex(ValueError,'registration-content'): delivery.registry({row['path']:actual},[row])

if __name__ == '__main__':
    unittest.main()
