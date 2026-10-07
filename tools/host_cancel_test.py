import os
from pathlib import Path
import signal
import tempfile
import unittest
import sys
from host_cancel import PROOF, cancel, declared_ssh
from unittest.mock import patch

DECLARED_SSH = None
if '--ssh' in sys.argv:
    index = sys.argv.index('--ssh')
    DECLARED_SSH = sys.argv[index + 1]
    del sys.argv[index:index + 2]

class CancellationTest(unittest.TestCase):
    def test_finite_scan_bound_refuses_without_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.fixture(root, pid=124, proof='other')
            with patch('host_cancel.MAX_PROCESSES', 1):
                self.assertEqual(cancel(root, '/declared/ssh', send=lambda *args:self.fail('signal'))['outcome'], 'process-bound')
    def test_actual_declared_ssh_identity(self):
        self.assertIsNotNone(DECLARED_SSH)
        self.assertRegex(declared_ssh(DECLARED_SSH), r'^/nix/store/[0-9a-z]{32}-[^/]+/bin/ssh$')
    def test_declared_wrapper_exact_grammar(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = Path(tmp) / 'wrapper'
            prefix = b'/nix/store/' + b'a' * 32
            content = b'#!' + prefix + b'-bash/bin/bash\nset -eu\nexec \'' + prefix + b'-openssh/bin/ssh\' "$@"\n'
            wrapper.write_bytes(content)
            original = Path.resolve
            def resolve(path, strict=False):
                return path if str(path).startswith('/nix/store/') else original(path, strict=strict)
            with patch.object(Path, 'resolve', resolve):
                self.assertEqual(declared_ssh(wrapper), '/nix/store/' + 'a' * 32 + '-openssh/bin/ssh')
                for changed in [content + b'extra\n', content.replace(prefix + b'-openssh', b'/usr'), content.replace(b'set -eu', b'set +e')]:
                    wrapper.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        declared_ssh(wrapper)
    def fixture(self, root, pid=123, proof=PROOF, host='neo', leader=True):
        path = root / str(pid)
        path.mkdir()
        (path / 'comm').write_bytes(b'ssh\n')
        (path / 'cmdline').write_bytes(b'ssh\0' + host.encode() + b'\0' + proof.encode() + b'\0')
        fields = ['S','1',str(pid if leader else 9),str(pid)] + ['0'] * 15 + ['123456']
        (path / 'stat').write_text(str(pid) + ' (ssh) ' + ' '.join(fields))
        (path / 'exe').symlink_to('/declared/ssh')
        return path
    def test_exact_unique_identity_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.fixture(root)
            sent = []
            def send(pid, sig):
                sent.append((pid,sig))
                for entry in path.iterdir():
                    entry.unlink()
                path.rmdir()
            self.assertEqual(cancel(root, '/declared/ssh', send=send)['outcome'], 'terminated')
            self.assertEqual(sent, [(123, signal.SIGTERM)])
    def test_other_proof_host_executable_and_nonleader_rejected(self):
        for change in [{'proof':'other'}, {'host':'pzm'}, {'leader':False}]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root, **change)
                self.assertEqual(cancel(root, '/declared/ssh', send=lambda *args:self.fail('signal'))['outcome'], 'absent')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.assertEqual(cancel(root, '/different/ssh', send=lambda *args:self.fail('signal'))['outcome'], 'absent')
    def test_ambiguity_never_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.fixture(root, pid=124)
            self.assertEqual(cancel(root, '/declared/ssh', send=lambda *args:self.fail('signal'))['outcome'], 'ambiguous')

if __name__ == '__main__':
    unittest.main()
