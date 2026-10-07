"""Actual declared artifact staging and synthetic control transport only.

No daemon, browser, provider, service manager, native session store or real HOME
is accessed. Execute exclusively through the declared Bazel test target.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from dev_stage import HOST, StageError, artifact, stage

CORE, DAEMON, EXTENSION, METADATA = (Path(argument) for argument in sys.argv[1:5])
del sys.argv[1:5]
_runtime_parser = argparse.ArgumentParser(add_help=False)
_runtime_parser.add_argument('--runtime-file', type=Path, action='append', default=[])
_runtime_parser.add_argument('--runtime-files', default='')
_runtime_parser.add_argument('--patchelf', type=Path, required=True)
_runtime_parser.add_argument('--ca-bundle', type=Path, required=True)
RUNTIME, _remaining_arguments = _runtime_parser.parse_known_args(sys.argv[1:])
RUNTIME.runtime_file.extend(Path(path) for path in RUNTIME.runtime_files.split())
sys.argv[1:] = _remaining_arguments
# test_cli consumes one declared binary argument when imported. Restore this
# test's own arguments immediately; reuse only its provider-free peer class.
_original_arguments = list(sys.argv)
try:
    sys.argv[:] = [sys.argv[0], str(CORE)]
    from test_cli import ControlPeer
finally:
    sys.argv[:] = _original_arguments


class DevStageRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='omux-stage-', dir=Path('/tmp').resolve())
        self.addCleanup(self.workspace.cleanup)
        self.base = Path(self.workspace.name)
        self.root = self.base / 'stage'
        self.metadata = json.loads(artifact(METADATA))
        self.home = self.base / 'h'
        self.state = self.base / 's'
        self.home.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.environment = {'HOME': str(self.home), 'XDG_STATE_HOME': str(self.state),
                            'XDG_DATA_HOME': str(self.base / 'd'), 'OMUX_INSTANCE': 'default',
                            'PATH': '', 'LC_ALL': 'C'}

    def stage(self, replace=False):
        return stage(self.root, CORE, DAEMON, EXTENSION, self.metadata, replace,
                     runtime_files=RUNTIME.runtime_file, patchelf=RUNTIME.patchelf, ca_bundle=RUNTIME.ca_bundle)

    def invoke(self, command, binary=None, payload=b''):
        result = subprocess.run([str(binary or self.root / 'bin/omux'), *command],
                                env=self.environment, input=payload, cwd=self.base,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        category = 'staged-cli-failed'
        if b'error while loading shared libraries:' in result.stderr:
            category = 'loader-library-missing'
        elif result.returncode == 127:
            category = 'staged-executable-unavailable'
        self.assertEqual(result.returncode, 0, category)
        self.assertLessEqual(len(result.stdout), 2 * 1024 * 1024)
        self.assertTrue(result.stderr == b'', 'unexpected staged CLI diagnostic')
        return result.stdout

    def test_actual_artifacts_have_verified_channel_and_native_cli_outputs(self):
        receipt = self.stage()
        self.assertEqual(receipt['metadata']['channel'], 'development')
        self.assertEqual(receipt['metadata']['instance'], 'dev')
        self.assertEqual(receipt['metadata']['native_host'], HOST)
        self.assertEqual(receipt['distribution'], 'portable-linux')
        for name, source in (('core', CORE), ('daemon', DAEMON)):
            expected = hashlib.sha256(artifact(source)).hexdigest()
            self.assertEqual(hashlib.sha256(artifact(self.root / 'current/source' / name)).hexdigest(), expected)
        manifest = json.loads(artifact(self.root / 'current/chromium/manifest.json'))
        self.assertEqual(manifest['version'], self.metadata['extension']['version'])
        channel = artifact(self.root / 'current/chromium/shared/channel.mjs')
        self.assertIn(b'export const NATIVE_HOST = "ai.xoxd.omux.dev";', channel)
        for command in (['--help'], ['--version'], ['reference']):
            self.assertEqual(self.invoke(command), self.invoke(command, CORE))
        reference = json.loads(self.invoke(['reference']))
        self.assertIsInstance(reference, dict)
        self.assertIn('product', reference)

    def test_staged_cli_selects_development_socket_without_explicit_state_override(self):
        self.stage()
        if sys.platform == 'darwin':
            base = self.home / 'Library/Application Support'
            development, default = base / 'Omux-dev', base / 'Omux'
        else:
            development, default = self.state / 'omux-dev', self.state / 'omux'
        for directory in (development, default):
            directory.mkdir(parents=True, mode=0o700)
            (directory / 'run').mkdir(mode=0o700)
        with ControlPeer(development / 'run/control.sock', 'read-only') as dev_peer, \
                ControlPeer(default / 'run/control.sock', 'read-only') as default_peer:
            response = json.loads(self.invoke(['rpc', 'state.snapshot', '-'], payload=b'{}'))
            self.assertEqual(response['result']['revision'], 7)
        self.assertFalse(dev_peer.failure)
        self.assertFalse(default_peer.failure)
        self.assertEqual([request['method'] for request in dev_peer.requests], ['system.handshake', 'state.snapshot'])
        self.assertEqual(default_peer.requests, [])
        self.assertEqual({path.name for path in development.iterdir()}, {'run'})

    def test_owned_replacement_preserves_registered_path_and_refuses_unrelated_files(self):
        self.stage()
        host = self.root / 'bin/omux-native-host'
        before = host.stat()
        launcher = artifact(host)
        old = os.readlink(self.root / 'current')
        self.stage(True)
        self.assertNotEqual(os.readlink(self.root / 'current'), old)
        self.assertEqual(host.stat().st_ino, before.st_ino)
        self.assertEqual(artifact(host), launcher)
        self.assertFalse(host.is_symlink())
        self.assertTrue((self.root / old).is_dir())
        active = os.readlink(self.root / 'current')
        unrelated = self.root / 'bin/user-file'
        unrelated.write_bytes(b'preserve unrelated data')
        with self.assertRaises(StageError):
            self.stage(True)
        self.assertEqual(os.readlink(self.root / 'current'), active)
        self.assertEqual(unrelated.read_bytes(), b'preserve unrelated data')
        unowned = self.base / 'unowned'
        unowned.mkdir(mode=0o700)
        (unowned / 'user-file').write_bytes(b'preserve unrelated data')
        with self.assertRaises(StageError):
            stage(unowned, CORE, DAEMON, EXTENSION, self.metadata,
                  runtime_files=RUNTIME.runtime_file, patchelf=RUNTIME.patchelf, ca_bundle=RUNTIME.ca_bundle)
        self.assertFalse((unowned / 'current').exists())


if __name__ == '__main__':
    unittest.main()
