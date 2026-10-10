"""Synthetic metadata/custody models only; no c106 or host execution proof."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import yoga_installed_selection as assembly
import yoga_installed_workspace as workspace


class SelectionTests(unittest.TestCase):
    def test_bound_output_base_supports_only_two_existing_roots_and_fresh_uuid(self):
        epoch = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        for root in workspace._ASSEMBLY_COORDS:
            base = root / epoch / 'output-base'
            self.assertEqual(workspace.assembly_base(base), base)
            for suffix in ('execroot/_main/test.runfiles/_main/tools/source.py',
                    'sandbox/processwrapper-sandbox/7/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'):
                path = base / suffix
                self.assertEqual(workspace.assembly_base(path, child=True), base)
                self.assertEqual(assembly.output_base(path, selected_base=base), base)

    def test_arbitrary_nearby_private_and_cache_roots_refuse_before_metadata(self):
        epoch = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        invalid = [Path('/home/private') / epoch / 'output-base']
        for root in workspace._ASSEMBLY_COORDS:
            invalid += [Path(str(root) + '-other') / epoch / 'output-base',
                root / ('cache-v2-' + 'a' * 64) / 'output-base',
                root / 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA' / 'output-base',
                root / epoch / 'output-base' / 'foreign']
        for path in invalid:
            with self.subTest(path=path), patch.object(workspace.os, 'open') as opened, \
                    patch.object(workspace.os, 'lstat') as inspected, self.assertRaises(ValueError):
                workspace.AssemblyContext(path, time.monotonic() + 30)
            opened.assert_not_called(); inspected.assert_not_called()

    def test_cross_epoch_and_cross_root_aliases_refuse_before_resolution(self):
        selected = workspace._ASSEMBLY_COORDS[0] / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' / 'output-base'
        foreign = [workspace._ASSEMBLY_COORDS[1] / selected.parent.name / 'output-base',
            workspace._ASSEMBLY_COORDS[0] / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' / 'output-base']
        suffix = 'execroot/_main/test.runfiles/'
        for base in foreign:
            with patch.object(workspace, 'safe_resolve') as resolved:
                with self.assertRaises(ValueError):
                    assembly.declared_inventory(base / suffix / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json',
                        'browserInventory', selected_base=selected)
                with self.assertRaises(ValueError):
                    assembly.declared_controller(base / suffix / '_main/tools/source.py', 'source.py', selected_base=selected)
                with self.assertRaises(ValueError):
                    assembly.support.declared(base / suffix / '_main/delivery/codex_device_acquisition_component.py',
                        lambda path: assembly.output_base(path, selected_base=selected))
                with self.assertRaises(ValueError):
                    assembly.output_parent(base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs',
                        selected_base=selected)
                resolved.assert_not_called()

    def test_home_inventory_without_held_context_retains_historical_refusal(self):
        base = workspace._ASSEMBLY_COORDS[1] / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' / 'output-base'
        path = base / 'external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
        with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
            workspace.PhysicalCapture(path, workspace.INVENTORY_SHA['browserInventory'], 1024,
                time.monotonic() + 30, declared_inventory='browserInventory')
        opened.assert_not_called()

    def context_fixture(self, temporary):
        root = Path(temporary) / 'execution-root'; root.mkdir(mode=0o700)
        epoch = root / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; epoch.mkdir(mode=0o700)
        base = epoch / 'output-base'; base.mkdir(mode=0o755)
        def parent(path):
            # Fixture-only sticky /tmp allowance; production uses the actual
            # strict no-follow walker through every ancestor.
            directory = Path(path).parent
            self.assertTrue(directory == root or directory.is_relative_to(root))
            return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return root, base, parent

    def test_actual_context_holds_owner_private_modes_and_directory_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    context.recheck()
                    root.chmod(0o755)
                    with self.assertRaises(ValueError): context.recheck()
                    root.chmod(0o700)
                    base.rename(base.with_name('held-original'))
                    base.mkdir(mode=0o755)
                    with self.assertRaises(ValueError): context.recheck()
                finally: context.close()

    def test_actual_context_refuses_foreign_owner_and_unprivate_epoch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            uid = os.getuid()
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                with patch.object(workspace.os, 'getuid', return_value=uid + 1), self.assertRaises(ValueError):
                    workspace.AssemblyContext(base, time.monotonic() + 30)
                base.parent.chmod(0o755)
                with self.assertRaises(ValueError): workspace.AssemblyContext(base, time.monotonic() + 30)

    def test_bound_capture_rejects_other_epoch_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    other = root / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' / 'output-base'
                    path = other / 'external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
                    with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
                        workspace.PhysicalCapture(path, workspace.INVENTORY_SHA['browserInventory'], 1024,
                            time.monotonic() + 30, declared_inventory='browserInventory', _assembly_context=context)
                    opened.assert_not_called()
                finally: context.close()

    def test_bound_capture_reads_actual_pinned_file_and_rechecks_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            directory = base / 'external' / assembly.INVENTORY_REPOS['browserInventory']
            directory.mkdir(parents=True, mode=0o700)
            path = directory / 'inventory.json'; content = b'{"public":true}\n'
            path.write_bytes(content); path.chmod(0o600)
            digest = hashlib.sha256(content).hexdigest()
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent), \
                    patch.dict(workspace.INVENTORY_SHA, {'browserInventory': digest}):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    held = workspace.PhysicalCapture(path, digest, 1024, time.monotonic() + 30,
                        declared_inventory='browserInventory', _assembly_context=context)
                    try:
                        self.assertEqual(held.bytes(1024), content)
                        path.write_bytes(b'{"changed":true}\n')
                        with self.assertRaises(ValueError): held.check()
                    finally: held.close()
                finally: context.close()

    def test_refusal_phase_is_closed_and_has_no_execution_authority(self):
        diagnostic = assembly._AssemblyDiagnostic()
        for phase in assembly._PHASES:
            diagnostic.enter(phase)
            self.assertEqual(json.loads(diagnostic.refusal()), {'schemaVersion': 1,
                'scope': 'yoga-installed-selection-refusal-v1', 'phase': phase,
                'executionAuthority': False, 'toolbarConsentProved': False,
                'browserInvoked': False, 'providerInvoked': False})
        diagnostic.enter('request')
        for invalid in ('/home/private/input', 'exception-canary', None, [], {}):
            with self.assertRaises(ValueError): diagnostic.enter(invalid)
            self.assertEqual(diagnostic.phase, 'request')

    def test_main_refusal_reports_phase_without_exception_or_input_text(self):
        def refuse(*args, **kwargs):
            kwargs['_diagnostic'].enter('controller-package')
            raise ValueError('exception-canary /home/private/input')
        argv = ['selector', '--browser-inventory', '/private/browser-canary',
            '--controller-inventory', '/private/controller-canary', '--controller-file',
            '/private/source-canary', '--controller-support-file', '/private/support-canary']
        stderr = io.StringIO()
        with patch.object(assembly.sys, 'argv', argv), \
                patch.dict(os.environ, {'OMUX_INSTALLED_SELECTION_DEADLINE_NS': '999999999999999',
                    'TEST_UNDECLARED_OUTPUTS_DIR': '/private/output-canary'}), \
                patch.object(assembly, 'assemble', side_effect=refuse) as selected, \
                redirect_stderr(stderr), self.assertRaises(SystemExit) as refused:
            assembly.main()
        self.assertEqual(refused.exception.code, 125)
        selected.assert_called_once()
        lines = stderr.getvalue().splitlines()
        self.assertEqual(lines[0], 'installed-toolbar-selection-assembly-refused')
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['phase'], 'controller-package')
        self.assertNotIn('canary', stderr.getvalue())
        self.assertNotIn('/private/', stderr.getvalue())
        self.assertNotIn('/home/', stderr.getvalue())

    def test_bad_deadline_refusal_stays_before_assembly(self):
        argv = ['selector', '--browser-inventory', 'browser', '--controller-inventory',
            'controller', '--controller-file', 'source', '--controller-support-file', 'support']
        stderr = io.StringIO()
        with patch.object(assembly.sys, 'argv', argv), \
                patch.dict(os.environ, {'OMUX_INSTALLED_SELECTION_DEADLINE_NS': 'invalid'}), \
                patch.object(assembly, 'assemble') as selected, redirect_stderr(stderr), \
                self.assertRaises(SystemExit) as refused:
            assembly.main()
        self.assertEqual(refused.exception.code, 125)
        selected.assert_not_called()
        self.assertEqual(json.loads(stderr.getvalue().splitlines()[1])['phase'], 'request')

    def test_declared_inventory_only_uses_exact_public_repository_file(self):
        base = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base'
        for name, repository in assembly.INVENTORY_REPOS.items():
            alias = base / 'execroot/_main/test.runfiles' / repository / 'inventory.json'
            expected = base / 'external' / repository / 'inventory.json'
            with patch.object(workspace, 'safe_resolve', return_value=expected) as resolve:
                self.assertEqual(assembly.declared_inventory(alias, name), expected)
                resolve.assert_called_once_with(str(alias), frozenset(), declared_paths=(alias, expected))
            with patch.object(workspace, 'safe_resolve') as resolve, self.assertRaises(ValueError):
                assembly.declared_inventory('/home/private/inventory.json', name)
            resolve.assert_not_called()
            with patch.object(workspace, 'safe_resolve', return_value=Path('/home/private/file')):
                with self.assertRaises(ValueError): assembly.declared_inventory(alias, name)

    def test_measurement_reuses_actual_held_reader_and_none_stays_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'source.py'
            path.write_bytes(b'public source\n'); path.chmod(0o600)
            # Fixture exemption only: allow the test's canonical sticky /tmp
            # ancestor, while production keeps its full strict nofollow walk.
            def parent(selected):
                self.assertEqual(Path(selected).parent, root)
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            until = time.monotonic() + 30
            with patch.object(workspace.payload, 'parent', side_effect=parent):
                with self.assertRaises(ValueError):
                    workspace.PhysicalCapture(path, None, 1024, until, controller_root=root)
                held = workspace.PhysicalCapture.measure(path, 1024, until, controller_root=root)
                try:
                    self.assertEqual(held.sha, hashlib.sha256(b'public source\n').hexdigest())
                    self.assertEqual(held.bytes(1024), b'public source\n')
                    path.write_bytes(b'changed public source\n')
                    with self.assertRaises(ValueError): held.check()
                finally: held.close()

    def test_declared_inventory_bad_pin_or_path_refuses_before_open(self):
        path = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
        for selected, digest in ((path, '0' * 64), (Path('/home/private/inventory.json'), workspace.INVENTORY_SHA['browserInventory'])):
            with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
                workspace.PhysicalCapture(selected, digest, 1024, time.monotonic() + 30, declared_inventory='browserInventory')
            opened.assert_not_called()

    def test_fixed_input_inventory_is_exact_and_artifact_pins_remain_independent(self):
        self.assertEqual(set(assembly.INPUT_KEYS), workspace.payload.INPUTS)
        self.assertEqual(set(assembly.INPUT_SHA), workspace.payload.INPUTS)
        for name, (digest, _) in workspace.ARTIFACTS.items(): self.assertEqual(assembly.INPUT_SHA[name], digest)
        self.assertEqual(assembly.INPUT_SHA['observer'], workspace.ORIGIN_SOURCE_SHA['delivery/yoga_toolbar_observer.mjs'])

    def test_publish_actual_three_files_and_no_adoption_or_extra_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            coord = Path(temporary)
            output = coord / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
            output.mkdir(parents=True, mode=0o700)
            files = {'selection.json': b'{"synthetic":true}\n', 'browser-inventory.json': b'{"public":1}\n',
                     'controller-inventory.json': b'{"public":2}\n'}
            def parent(selected):
                self.assertEqual(Path(selected).parent, output)
                return os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            with patch.object(assembly, 'COORD', coord), patch.object(workspace.payload, 'parent', side_effect=parent):
                root = assembly.publish(output, files, time.monotonic() + 30)
                self.assertEqual(set(os.listdir(root)), set(files))
                for name, content in files.items():
                    self.assertEqual((root / name).read_bytes(), content)
                    self.assertEqual((root / name).stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): assembly.publish(output, files, time.monotonic() + 30)
                with self.assertRaises(ValueError): assembly.publish(output, dict(files, foreign=b'public'), time.monotonic() + 30)

    def test_historical_bootstrap_substitution_cannot_be_blessed_by_measured_map(self):
        for key, expected in assembly.BOOTSTRAP_SHA.items():
            physical = Path(assembly.BOOTSTRAP_PATH[key])
            assembly.historical_pin(key, physical, expected)
            # A rewritten fileSha256 agreeing with substituted public bytes
            # still cannot change the independent historical executable pin.
            changed = hashlib.sha256(b'self-consistent substituted bootstrap').hexdigest()
            rewritten = {key: changed}
            with self.subTest(key=key), self.assertRaises(ValueError):
                assembly.historical_pin(key, physical, rewritten[key])
            with self.assertRaises(ValueError):
                assembly.historical_pin(key, physical.parent / 'foreign', expected)

    def test_full_output_namespace_accepts_real_execroot_shapes_and_refuses_before_open(self):
        base = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base'
        suffix = 'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
        for prefix in ('', 'sandbox/linux-sandbox/0/', 'sandbox/linux-sandbox/17/', 'sandbox/processwrapper-sandbox/7/'):
            selected = base / (prefix + suffix)
            self.assertEqual(assembly.output_parent(selected), selected)
        for suffix in ('foreign/delivery/yoga_installed_selection/test.outputs',
                       'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_installed_selection/test.outputs',
                       'sandbox/linux-sandbox/01/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs',
                       'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/yoga_installed_selection/test.outputs'):
            with patch.object(workspace.payload, 'parent') as opened, self.assertRaises(ValueError):
                assembly.publish(base / suffix, {'selection.json': b'1', 'browser-inventory.json': b'2',
                                                 'controller-inventory.json': b'3'}, time.monotonic() + 30)
            opened.assert_not_called()

    def test_publication_refuses_canonical_parent_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            coord = Path(temporary)
            output = coord / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
            output.mkdir(parents=True, mode=0o700)
            files = {'selection.json': b'1', 'browser-inventory.json': b'2', 'controller-inventory.json': b'3'}
            def parent(selected):
                self.assertEqual(Path(selected).parent, output)
                return os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            original = workspace.verify_output
            def replace_parent(*args):
                original(*args)
                output.rename(output.with_name('held-original'))
                output.mkdir(mode=0o700)
            with patch.object(assembly, 'COORD', coord), patch.object(workspace.payload, 'parent', side_effect=parent), \
                    patch.object(workspace, 'verify_output', side_effect=replace_parent):
                with self.assertRaises(ValueError):
                    assembly.publish(output, files, time.monotonic() + 30)
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual(set(os.listdir(output.with_name('held-original') / 'installed-toolbar-selection')), set(files))

    def test_shared_resolver_refuses_private_extra_hop_before_metadata(self):
        alias = str(assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/external/public/inventory.json')
        with patch.object(workspace.os, 'lstat') as observed, self.assertRaises(ValueError):
            workspace.safe_resolve('/home/private/file', frozenset(), declared_paths=(Path(alias),))
        observed.assert_not_called()


if __name__ == '__main__': unittest.main()
