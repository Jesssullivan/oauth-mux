"""Declared offline evaluator boundary models; no Home Manager/Apple proof.

Real child pipe/ownership tests execute only when this Bazel target is selected.
Tiny printed definitions are intentionally synthetic process-boundary fixtures.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import home_manager_darwin_evaluation as subject


class EvaluationModels(unittest.TestCase):
    def definition(self):
        return {'schemaVersion': 1, 'kind': subject.generated.KIND,
            'scope': 'genuine-pinned-darwin-home-manager-evaluation-only', 'activation': 'unproved',
            'generatedBytes': 'unrealized-unverified', 'appleAcceptance': 'unproved',
            'runtimeCollector': 'darwin-live-binding-unimplemented',
            'generationPath': '/model/generation', 'generationDerivation': '/model/generation.drv',
            'homeFilesPath': '/model/home-files', 'agentsPath': '/model/agents',
            'agentSourcePath': '/model/plist', 'agentText': 'public synthetic child result',
            'homeFiles': {'model.json': {'source': '/model/json', 'text': '{}', 'kind': 'regular'}},
            'channel': 'development', 'identity': 'ai.xoxd.omux.dev', 'homeDirectory': '/Users/model',
            'desiredProgramArguments': [], 'generatedProgramArguments': [],
            'artifact': {'root': '/model/app', 'manifestSha256': 'a'*64,
                'narHash': 'sha256-'+'A'*43+'=', 'sourceRevision': 'a'*40},
            'predicates': {'synthetic-process-boundary-only': True}}

    def child(self, code):
        return [sys.executable, '-I', '-B', '-c', code]

    def run_child(self, code):
        children = []
        original = subject.subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        try:
            with tempfile.TemporaryDirectory() as home, patch.object(subject.subprocess, 'Popen', side_effect=spawn):
                return subject.evaluate(self.child(code), home, time.monotonic_ns()+30*10**9)
        finally:
            self.assertEqual(len(children), 1)
            child = children[0]
            self.assertIsNotNone(child.returncode)
            self.assertTrue(child.stdout.closed and child.stderr.closed)
            with self.assertRaises(ProcessLookupError): os.getpgid(child.pid)

    def test_real_owned_child_returns_only_unrealized_definition_and_retires_pipes(self):
        raw = json.dumps(self.definition()).encode()
        result = self.run_child('import sys;sys.stdout.buffer.write('+repr(raw)+')')
        self.assertEqual(result, raw)
        self.assertEqual(json.loads(result)['activation'], 'unproved')
        self.assertEqual(json.loads(result)['generatedBytes'], 'unrealized-unverified')

    def test_real_child_nonzero_duplicate_fields_and_oversized_pipes_refuse(self):
        rows = ['raise SystemExit(3)', "print('{\"schemaVersion\":1,\"schemaVersion\":1}')",
                'import sys;sys.stdout.buffer.write(b"x"*70000)',
                'import sys;sys.stderr.buffer.write(b"x"*40000)']
        for code in rows:
            with self.subTest(code=code), self.assertRaises(ValueError): self.run_child(code)

    def test_expired_original_clock_never_spawns_child_or_rebases(self):
        now = time.monotonic_ns()
        entry = now-600*10**9
        with self.assertRaises(ValueError):
            subject.original_clock({'OMUX_DARWIN_HM_ENTRY_NS': str(entry),
                'OMUX_DARWIN_HM_DEADLINE_NS': str(entry+1200*10**9)})
        with tempfile.TemporaryDirectory() as home, patch.object(subject.subprocess, 'Popen', side_effect=AssertionError('expired caller spawned')):
            with self.assertRaises(ValueError): subject.evaluate(self.child('print(1)'), home, now)

    def test_exact_original_integer_envelope_rejects_padded_future_and_extended_controls(self):
        now = time.monotonic_ns()
        for entry, deadline in [(' '+str(now), str(now+1200*10**9)),
                (str(now+60*10**9), str(now+1260*10**9)),
                (str(now), str(now+1201*10**9))]:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                subject.original_clock({'OMUX_DARWIN_HM_ENTRY_NS': entry, 'OMUX_DARWIN_HM_DEADLINE_NS': deadline})

    def test_declared_command_is_offline_builder_free_and_escapes_nix_interpolation(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ('nixpkgs.tar', 'home-manager.tar', 'app.tar'): (root/name).write_bytes(b'command-only public archive fixture')
            expression = root/'candidate-${builtins.abort "bad"}.nix'; expression.write_text('public fixture')
            args = argparse.Namespace(nix='/declared/nix', expression=str(expression), nixpkgs_archive=str(root/'nixpkgs.tar'),
                home_manager_archive=str(root/'home-manager.tar'), artifact_archive=str(root/'app.tar'), artifact_nar='sha256-'+'A'*43+'=',
                source_revision='a'*40, channel='development', extension_id='a'*32)
            argv = subject.command(args)
            self.assertEqual(argv[:5], ['/declared/nix', '--extra-experimental-features', 'nix-command', '--store', 'dummy://?read-only=false'])
            self.assertIn('--offline', argv)
            self.assertEqual(argv[-1].count('builtins.fetchTarball'), 3)
            self.assertEqual(argv[-1].count('file://'), 3)
            self.assertNotIn('https://', argv[-1])
            self.assertIn('\\${builtins.abort', argv[-1])
            for option, value in [('allow-import-from-derivation', 'false'), ('builders', ''), ('substituters', ''), ('max-jobs', '0')]:
                self.assertTrue(any(argv[i:i+3] == ['--option', option, value] for i in range(len(argv)-2)))
            self.assertEqual(subject.owned.evaluator_environment(root), {'HOME': str(root), 'PATH': '', 'NIX_PATH': '',
                'NIX_CONFIG': '', 'NIX_CONF_DIR': str(root), 'NIX_USER_CONF_FILES': ''})


if __name__ == '__main__': unittest.main()
