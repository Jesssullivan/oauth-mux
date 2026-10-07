"""Injected Yoga admission predicates; no seat, store, executor or browser IO."""
import copy
from contextlib import nullcontext
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import guard_yoga_profile as yoga


class YogaProfileTests(unittest.TestCase):
    def setUp(self):
        self.deadline = time.monotonic_ns() + 1100 * 10**9
        self.uid = 1000
        self.root = Path('/srv/yoga-source')
        self.tools = {name: '/nix/store/' + 'a' * 32 + '-controller/' + name for name in yoga.TOOLS}
        self.tools['bootstrap_closure'] = '/nix/store/' + 'a' * 32 + '-bootstrap-closure'
        self.snapshot = {'device': 4, 'inode': 5, 'uid': self.uid, 'mode': 0o700, 'pid': 200, 'start_ticks': 50}
        self.receipt = {'schemaVersion': 1, 'scope': 'yoga-local-guard-qualification-v1', 'hostAlias': 'yoga',
            'proofId': '12345678-1234-4123-8123-123456789012', 'deadlineMonotonicNs': self.deadline,
            'host': {'machineIdSha256': 'a' * 64, 'bootIdSha256': 'b' * 64, 'uid': self.uid},
            'seat': {'sessionId': '3', 'seatId': 'seat0', 'uid': self.uid}, 'operatorTerminal': '/dev/pts/4',
            'sourceRoot': str(self.root), 'sourceGraphSha256': 'c' * 64,
            'sourceFilesSha256': {name: 'd' * 64 for name in yoga.SOURCE_FILES},
            'sourceSocket': '/run/user/1000/wayland-0', 'compositorSnapshot': self.snapshot,
            'inputPaths': {name: '/srv/yoga-inputs/' + name for name in yoga.coordinator.INPUTS},
            'inputSha256': {name: 'e' * 64 for name in yoga.coordinator.INPUTS}, 'controllerTools': self.tools,
            'controllerInventory': {'path': '/srv/yoga-inputs/controller-inventory', 'sha256': 'f' * 64},
            'controllerNarProof': {'path': '/srv/yoga-inputs/controller-nar', 'sha256': 'f' * 64}}
        self.receipt['vaultWrapperAuthority'] = {
            'companion': {'path': '/srv/yoga-inputs/companion', 'sha256': '1' * 64},
            'nativeManifest': {'path': '/srv/yoga-inputs/native.json', 'sha256': '2' * 64},
            'registeredNativeManifest': {'path': '/nix/store/' + 'b' * 32 + '-native.json', 'sha256': '3' * 64},
            **{name: copy.deepcopy(self.receipt[name]) for name in ('controllerTools', 'controllerInventory', 'controllerNarProof')}}
        self.arguments = dict(manager='system', arguments=['run', yoga.LABEL], state_root='/srv/yoga-state',
            source_root=self.root, home=Path('/home/user'), tools=self.tools, graph_sha256='c' * 64,
            uid=self.uid, operator_descriptor=0)
        self.pin = Mock()
        witness = {'source': self.receipt['sourceSocket'], 'destination': '/srv/yoga-state/' + self.receipt['proofId'] + '/wayland.sock',
                   'proof_root': '/srv/yoga-state/' + self.receipt['proofId'], 'uid': self.uid,
                   'deadline_ns': self.deadline, 'snapshot': self.snapshot}
        self.capture = Mock(return_value=(witness, self.pin))
        content = b'{"public":"qualified-browser-inventory"}'
        self.inventory = {'bytes': content, 'sha256': hashlib.sha256(content).hexdigest()}

    def test_wrapper_envelope_rejects_missing_proof_extra_fields_and_outer_substitution(self):
        for edit in (lambda value: value['vaultWrapperAuthority'].pop('controllerNarProof'),
                     lambda value: value['vaultWrapperAuthority'].update(extra=True),
                     lambda value: value['vaultWrapperAuthority']['controllerInventory'].update(sha256='0' * 64),
                     lambda value: value['vaultWrapperAuthority']['nativeManifest'].update(path='/home/user/native.json')):
            value = copy.deepcopy(self.receipt); edit(value)
            with self.assertRaises(ValueError):
                yoga.schema(value, self.deadline, self.root, self.tools, 'c' * 64, self.uid)

    def test_wrapper_capture_passes_exact_selected_inputs_and_original_deadline(self):
        validator, custody = Mock(), Mock()
        with patch.object(yoga, 'wrapper_modules', return_value=(validator, custody)):
            result = yoga.wrapper_capture(self.receipt, self.deadline)
        self.assertIs(result, custody.AuthorityCapture.return_value)
        args, options = custody.AuthorityCapture.call_args
        self.assertEqual(args, (self.receipt['vaultWrapperAuthority'],
            {name: self.receipt['inputPaths'][name] for name in ('dbus_session', 'dbus_daemon', 'keyring')},
            {name: self.receipt['inputSha256'][name] for name in ('dbus_session', 'dbus_daemon', 'keyring')}, self.deadline))
        self.assertIs(options['validator'], validator)

    def test_wrapper_modules_execute_only_hash_captured_selected_source_bytes(self):
        code = b'MODEL_VALUE="captured-source"\n'
        with patch.object(yoga, 'file_bytes', return_value=code) as captured:
            modules = yoga.wrapper_modules(self.receipt, self.deadline)
        self.assertTrue(all(module.MODEL_VALUE == 'captured-source' for module in modules))
        self.assertEqual(captured.call_count, 2)
        for call in captured.call_args_list:
            relative = str(call.args[0].relative_to(self.root))
            self.assertEqual(call.kwargs['expected'], self.receipt['sourceFilesSha256'][relative])
            self.assertEqual(call.args[2], self.deadline)

    def preallocate(self, value=None, **options):
        with patch.object(yoga, 'file_bytes', return_value=json.dumps(value or self.receipt).encode()), \
                patch.object(yoga, 'local_identity') as identity, \
                patch.object(yoga, 'runtime_qualification', return_value=(self.receipt['inputSha256'], self.inventory)) as runtime, \
                patch.object(yoga, 'require_unit_absent'), \
                patch.object(yoga.display, 'capture_pinned', self.capture), \
                patch.object(Path, 'resolve', return_value=self.root):
            result = yoga.preallocate('/srv/yoga-inputs/selection.json', 'f' * 64, self.deadline,
                                     **{**self.arguments, **options})
            identity.assert_called_once()
            runtime.assert_called_once()
            return result

    def test_qualified_preallocation_holds_original_pin_and_deadline(self):
        result = self.preallocate()
        self.assertIs(result['pin'], self.pin)
        self.assertEqual(result['witness']['deadline_ns'], self.deadline)
        self.capture.assert_called_once()
        self.pin.close.assert_not_called()
        self.assertEqual(result['browserInventory'], self.inventory)

    def test_qualified_inventory_publication_is_exclusive_exact_and_private(self):
        admission = self.preallocate()
        root = Path(admission['witness']['proof_root'])
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            def parent(*args):
                self.assertEqual(args[0], str(root / 'browser-inventory.json'))
                return os.open(fixture, os.O_RDONLY | os.O_DIRECTORY)
            with patch.object(yoga.inputs, 'open_parent', side_effect=parent), \
                    patch.object(yoga, 'file_bytes', side_effect=lambda *args, **options: (fixture / 'browser-inventory.json').read_bytes()):
                bindings = yoga.publish_repository_inventory(admission, root)
                self.assertEqual(bindings, {'OMUX_SITE_INVENTORY': str(root / 'browser-inventory.json'),
                    'OMUX_SITE_INVENTORY_SHA256': self.inventory['sha256'],
                    'OMUX_BAZEL_BOOTSTRAP_CLOSURE': self.tools['bootstrap_closure']})
                published = fixture / 'browser-inventory.json'
                self.assertEqual(published.read_bytes(), self.inventory['bytes'])
                self.assertEqual(stat.S_IMODE(published.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    yoga.publish_repository_inventory(admission, root)
                self.assertEqual(published.read_bytes(), self.inventory['bytes'])
                published.write_bytes(b'changed-public-metadata')
                with self.assertRaises(ValueError):
                    yoga.repository_bindings(admission, root)

    def test_unbound_inventory_or_other_epoch_never_creates_publication(self):
        admission = self.preallocate()
        root = admission['witness']['proof_root']
        with patch.object(yoga.inputs, 'open_parent') as opener:
            for candidate in (root + '-foreign', '/home/user/' + self.receipt['proofId']):
                with self.assertRaises(ValueError):
                    yoga.publish_repository_inventory(admission, candidate)
            admission['browserInventory'] = {**self.inventory, 'sha256': '0' * 64}
            with self.assertRaises(ValueError):
                yoga.publish_repository_inventory(admission, root)
            opener.assert_not_called()

    def test_repository_binding_refuses_unpublished_and_bootstrap_manifest_alias(self):
        admission = self.preallocate()
        root = admission['witness']['proof_root']
        with self.assertRaises(ValueError):
            yoga.repository_bindings(admission, root)
        admission['publishedInventory'] = {'path': root + '/browser-inventory.json', 'sha256': self.inventory['sha256']}
        admission['receipt']['controllerTools']['bootstrap_closure'] += '/native.json'
        with patch.object(yoga, 'file_bytes', return_value=self.inventory['bytes']), self.assertRaises(ValueError):
            yoga.repository_bindings(admission, root)

    def test_runtime_retains_exact_embedded_inventory_only_after_qualification(self):
        value = copy.deepcopy(self.receipt)
        controller = '/nix/store/' + 'a' * 32 + '-controller'
        browser = '/nix/store/' + 'b' * 32 + '-chromium'
        node = '/nix/store/' + 'c' * 32 + '-node'
        value['inputPaths'].update(chromium=browser + '/bin/chromium', node=node + '/bin/node',
            **{name: controller + '/' + name for name in ('dbus_session', 'dbus_daemon', 'keyring')})
        rows = [{'path': controller, 'narSize': 100}, {'path': self.tools['bootstrap_closure'], 'narSize': 100}]
        inventory_bytes = json.dumps({'paths': [{'path': browser}, {'path': node}]}).encode()
        runtime = {'inventoryBase64': base64.b64encode(inventory_bytes).decode(),
                   'inventorySha256': hashlib.sha256(inventory_bytes).hexdigest(),
                   'packages': {'chromium': {'out': browser}, 'node': {'out': node}}}
        nar = {'schemaVersion': 1, 'passed': True, 'inventorySha256': 'f' * 64,
               'descriptorSha256': 'a' * 64, 'verifiedPaths': 2, 'verifiedRegularInputs': 1,
               'verifiedNarBytes': 200, 'contentRehashed': True, 'linkTargetsFollowed': False,
               'executionAuthority': False, 'flakeMappingVerified': False, 'realized': False}
        # The declared authority adapter is injected; its exact captured bytes
        # are compiled by the production qualification path, with no pathname reopen.
        code = b'import json\nMAX_AUTHORITY=16777216\nMAX_INPUT=8388608\nparse=json.loads\nvalidate_authority=json.loads\nreceipt_from_input=json.loads\n'
        def reader(path, *args, **options):
            if str(path).endswith('browser_runtime_authority.py'):
                return code
            if str(path) == value['inputPaths']['runtime_authority']:
                return json.dumps(runtime).encode()
            if str(path) == value['controllerInventory']['path']:
                return json.dumps({'paths': rows}).encode()
            if str(path) == value['controllerNarProof']['path']:
                return json.dumps(nar).encode()
            return b'declared-fixture-source'
        with patch.object(yoga, 'file_bytes', side_effect=reader), patch.object(yoga, 'registered_rows') as registered, \
                patch.object(yoga.inputs, 'check_inputs', return_value=value['inputSha256']) as checked, \
                patch.object(yoga, 'wrapper_capture', return_value=nullcontext()) as wrappers:
            digests, retained = yoga.runtime_qualification(value, self.deadline, retain_inventory=True)
            self.assertEqual(digests, value['inputSha256'])
            self.assertEqual(retained, {'bytes': inventory_bytes, 'sha256': runtime['inventorySha256']})
            self.assertEqual(registered.call_count, 2)
            checked.assert_called_once()
            wrappers.assert_called_once_with(value, self.deadline)
            checked.reset_mock()
            runtime['inventorySha256'] = '0' * 64
            with self.assertRaises(ValueError):
                yoga.runtime_qualification(value, self.deadline, retain_inventory=True)
            checked.assert_not_called()

    def test_invalid_selector_scope_uid_and_digest_tuple_never_capture_or_allocate(self):
        changes = [lambda value: value.update(hostAlias='other'),
                   lambda value: value.update(scope='remote-proof'),
                   lambda value: value['host'].update(uid=1001),
                   lambda value: value['seat'].update(uid=1001),
                   lambda value: value.update(deadlineMonotonicNs=self.deadline + 1),
                   lambda value: value['inputPaths'].pop('node'),
                   lambda value: value['inputSha256'].update(node='invalid'),
                   lambda value: value.update(sourceRoot='/srv/other-source'),
                   lambda value: value['controllerTools'].update(bazel='/usr/bin/bazel'),
                   lambda value: value.update(operatorTerminal='/tmp/events'),
                   lambda value: value.update(sourceSocket='/run/user/1001/wayland-0')]
        for change in changes:
            value = copy.deepcopy(self.receipt)
            change(value)
            with self.assertRaises(ValueError):
                self.preallocate(value)
        for options in ({'manager': 'user'}, {'arguments': ['run', yoga.LABEL, '--', '--inside']},
                        {'state_root': '/home/user/state'}, {'state_root': '/srv/../state'}):
            with self.assertRaises(ValueError):
                self.preallocate(**options)
        self.capture.assert_not_called()

    def test_missing_live_seat_or_unrealized_inputs_fail_before_capture(self):
        for name in ('local_identity', 'runtime_qualification'):
            with patch.object(yoga, 'file_bytes', return_value=json.dumps(self.receipt).encode()), \
                    patch.object(yoga, 'local_identity'), patch.object(yoga, 'runtime_qualification'), \
                    patch.object(yoga, 'require_unit_absent'), \
                    patch.object(yoga, name, side_effect=ValueError('unqualified')), \
                    patch.object(yoga.display, 'capture_pinned', self.capture), \
                    patch.object(Path, 'resolve', return_value=self.root):
                with self.assertRaises(ValueError):
                    yoga.preallocate('/srv/yoga-inputs/selection.json', 'f' * 64, self.deadline, **self.arguments)
        self.capture.assert_not_called()

    def test_changed_compositor_closes_owned_pin_before_rejection(self):
        self.capture.return_value[0]['snapshot'] = dict(self.snapshot, start_ticks=51)
        with self.assertRaises(ValueError):
            self.preallocate()
        self.pin.close.assert_called_once()

    def test_expired_or_missing_cleanup_budget_refuses_before_read(self):
        with patch.object(yoga, 'file_bytes') as reader:
            for deadline in (0, True, time.monotonic_ns() - 1, time.monotonic_ns() + 10**9):
                with self.assertRaises(ValueError):
                    yoga.preallocate('/srv/yoga-inputs/selection.json', 'f' * 64, deadline, **self.arguments)
            reader.assert_not_called()

    def test_local_identity_requires_current_host_boot_root_seat_and_matching_audit_session(self):
        machine, boot = b'machine\n', b'boot\n'
        value = copy.deepcopy(self.receipt)
        value['host'].update(machineIdSha256=hashlib.sha256(machine).hexdigest(), bootIdSha256=hashlib.sha256(boot).hexdigest())
        session = b'UID=1000\nSEAT=seat0\nTYPE=wayland\nACTIVE=1\nREMOTE=0\nAUDIT=42\n'
        def reader(path, *args, **options):
            if path == '/etc/machine-id':
                return machine
            if path == '/proc/sys/kernel/random/boot_id':
                return boot
            if path.startswith('/run/systemd/sessions/'):
                self.assertEqual(options.get('owner'), 0)
                return session
            return b'42\n' if path.endswith('/sessionid') else b'1000\n'
        with patch.object(yoga, 'file_bytes', side_effect=reader), patch.object(yoga.os, 'isatty', return_value=True), \
                patch.object(yoga.os, 'ttyname', return_value='/dev/pts/4'), \
                patch.object(yoga.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_uid=1000)):
            yoga.local_identity(value, self.deadline, self.uid, 0)
            for changed in (session.replace(b'REMOTE=0', b'REMOTE=1'), session.replace(b'AUDIT=42', b'AUDIT=43'),
                            session.replace(b'ACTIVE=1', b'ACTIVE=0'), session.replace(b'UID=1000', b'UID=1001')):
                session = changed
                with self.assertRaises(ValueError):
                    yoga.local_identity(value, self.deadline, self.uid, 0)

    def test_effective_masks_and_exact_singleton_readonly_bind_are_required(self):
        home = Path('/home/user')
        bind = ['/run/user/1000/wayland-0:/srv/proof/wayland.sock']
        properties = {'TemporaryFileSystem': yoga.mask_setting(home), 'InaccessiblePaths': '/etc/environment',
                      'BindReadOnlyPaths': bind[0], 'BindPaths': ''}
        yoga.verify_masks(properties, home, bind)
        for change in ({'TemporaryFileSystem': yoga.masks.setting(home=home, profile='installed-browser')},
                       {'BindReadOnlyPaths': bind[0] + ' /run/user/1000:/srv/broad'},
                       {'BindPaths': bind[0]}, {'InaccessiblePaths': ''}):
            with self.assertRaises(ValueError):
                yoga.verify_masks({**properties, **change}, home, bind)

    def test_operator_ingress_rejects_partial_multiple_oversized_and_early_records(self):
        admission = {'operatorDescriptor': 0, 'witness': {'deadline_ns': self.deadline}}
        support = SimpleNamespace(admitted=True, events=[], receive_event=Mock())
        with patch.object(yoga.select, 'select', return_value=([0], [], [])), patch.object(yoga.os, 'write') as writer:
            for payload in (b'{}', b'{}\n{}\n', b'x' * 2049, b''):
                with patch.object(yoga.os, 'read', return_value=payload), self.assertRaises(ValueError):
                    yoga.pump_event(admission, support, 4)
            support.admitted = False
            with self.assertRaises(ValueError):
                yoga.pump_event(admission, support, 4)
            writer.assert_not_called()
            support.receive_event.assert_not_called()

    def test_operator_record_only_flows_into_guard_owned_pipe(self):
        admission = {'operatorDescriptor': 0, 'witness': {'deadline_ns': self.deadline}}
        support = SimpleNamespace(admitted=True, events=[], receive_event=Mock())
        payload = b'{"case":"denial"}\n'
        with patch.object(yoga.select, 'select', return_value=([0], [], [])), \
                patch.object(yoga.os, 'read', return_value=payload), patch.object(yoga.os, 'write', return_value=len(payload)) as writer:
            yoga.pump_event(admission, support, 4)
        writer.assert_called_once_with(4, payload)
        support.receive_event.assert_called_once()

    def test_duplicate_and_nonfinite_receipt_values_refuse(self):
        for payload in (b'{"scope":1,"scope":2}', b'{"deadline":NaN}'):
            with self.assertRaises(ValueError):
                yoga.decode(payload)

    def test_preexisting_uuid_unit_refuses_without_stop_or_launch(self):
        proof_id = self.receipt['proofId']
        unit = 'omux-execution-' + proof_id + '.service'
        facts = f'Id={unit}\nLoadState=loaded\nActiveState=active\nMainPID=123\nControlGroup=/system.slice/{unit}\n'.encode()
        with patch.object(yoga.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=facts)) as run:
            with self.assertRaises(ValueError):
                yoga.require_unit_absent('/nix/store/fixed-systemctl', proof_id, self.deadline)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('stop', run.call_args.args[0])

    def test_failed_launch_cannot_own_or_stop_an_existing_same_uid_unit(self):
        proof_id = self.receipt['proofId']
        unit = 'omux-execution-' + proof_id + '.service'
        root = '/srv/yoga-state/' + proof_id
        facts = {'Id': unit, 'User': '1000', 'Group': '1000', 'MainPID': '123',
                 'ControlGroup': '/system.slice/' + unit,
                 'Environment': 'OMUX_EXECUTION_GUARD=' + root,
                 'ExecStart': 'path=/nix/store/fixed-python ; argv[]=/nix/store/fixed-python /srv/source/tools/yoga_operator_launch.py --worker ' + root + ' -- run'}
        with patch.object(yoga.os, 'getuid', return_value=1000), patch.object(yoga.os, 'getgid', return_value=1000):
            with self.assertRaises(ValueError):
                yoga.owns_unit(facts, unit=unit, run=root, nonce='new-private-nonce', plan_sha256='a' * 64,
                               worker='/srv/source/tools/yoga_operator_launch.py', python='/nix/store/fixed-python')


if __name__ == '__main__':
    unittest.main()
