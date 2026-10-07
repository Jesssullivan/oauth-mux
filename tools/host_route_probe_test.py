import unittest
import sys
from pathlib import Path
import tempfile
import time
from unittest.mock import patch
from host_route_probe import summarize, NAMES, observe

class PresenceSchemaTest(unittest.TestCase):
    def output(self):
        keys = [*NAMES, 'org.nixos.nix-daemon', 'systems.determinate.nix-daemon', 'nix_daemon_socket', 'listener.8980', 'listener.8981', 'dev.tinyland.gf-reapi-darwin-cell', 'dev.tinyland.gf-reapi-darwin-worker', 'dev.tinyland.gf-reapi-darwin-cell.plist', 'dev.tinyland.gf-reapi-darwin-worker.plist', *('credential.' + name for name in ('authz/jwks.json', 'tls/ca.crt', 'tls/cell.crt', 'tls/cell.key', 'tls/worker.crt', 'tls/worker.key'))]
        return ''.join(key + '=absent\n' for key in keys).encode('ascii')

    def test_only_complete_bounded_presence_schema_is_admitted(self):
        output = self.output()
        self.assertTrue(all(value is False for value in summarize(output).values()))
        for altered in (output + b'private=value\n', output + output.splitlines()[0] + b'\n', output.replace(b'=absent', b'=secret', 1), b'x' * 8193, b'\xff', output.split(b'\n', 1)[1]):
            with self.subTest(length=len(altered)), self.assertRaises((ValueError, UnicodeError)):
                summarize(altered)

    def test_observer_bounds_output_during_read(self):
        with self.assertRaisesRegex(ValueError, 'output'):
            observe([sys.executable, '-I', '-S', '-c', 'import os; os.write(1,b"x"*16384)'], {})

    def test_observer_terminates_exited_leader_descendant_holding_pipe(self):
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / 'owned-child'
            code = 'import os,time; child=os.fork(); open(' + repr(str(marker)) + ',"w").write(str(child)) if child else None; os._exit(0) if child else time.sleep(60)'
            with patch('host_route_probe.MAX_SECONDS', 0.2), self.assertRaisesRegex(ValueError, 'deadline'):
                observe([sys.executable, '-I', '-S', '-c', code], {})
            child = int(marker.read_text())
            state = Path('/proc') / str(child) / 'stat'
            deadline = time.monotonic() + 2
            while state.exists() and time.monotonic() < deadline:
                try:
                    observed = state.read_text().split(') ', 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if observed == 'Z':
                    break
                time.sleep(0.01)
            try:
                observed = state.read_text().split(') ', 1)[1].split()[0]
            except FileNotFoundError:
                return
            self.assertEqual(observed, 'Z')

if __name__ == '__main__':
    unittest.main()
