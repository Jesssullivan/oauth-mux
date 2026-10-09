"""Synthetic metadata/custody models only; no c106 or host execution proof."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import yoga_installed_selection as assembly
import yoga_installed_workspace as workspace


class SelectionTests(unittest.TestCase):
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
