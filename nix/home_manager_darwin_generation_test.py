"""Small real-filesystem topology/refusal models, never a fake HM evaluation."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import home_manager_darwin_generation as subject


class GeneratedModels(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # Darwin's default temp path can traverse /var's system symlink; use
        # the actual physical path of this exclusively created fixture root.
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.generation, self.agents, self.home, self.sources, self.app = [self.root/name
            for name in ('generation', 'agents', 'home-files', 'sources', 'app')]
        for root in (self.generation, self.agents, self.home, self.sources, self.app): root.mkdir(mode=0o700)
        self.label = 'ai.xoxd.omux.dev'
        text = '<plist><dict><key>fixture</key><string>public topology only</string></dict></plist>\n'
        self.agent = self.sources/(self.label+'.plist')
        self.agent.write_text(text); self.agent.chmod(0o444)
        record = self.sources/'host.json'
        record.write_text('{"name":"ai.xoxd.omux.dev","path":"/model/channel-bound/omux-native-host"}\n'); record.chmod(0o444)
        browser = 'Library/Application Support/Google/Chrome/NativeMessagingHosts/'+self.label+'.json'
        leaf = self.home/browser
        leaf.parent.mkdir(parents=True); leaf.symlink_to(record)
        (self.home/'Applications').mkdir()
        (self.home/'Applications/Omux-dev.app').symlink_to(self.app, target_is_directory=True)
        (self.generation/'LaunchAgents').symlink_to(self.agents, target_is_directory=True)
        (self.generation/'home-files').symlink_to(self.home, target_is_directory=True)
        (self.agents/(self.label+'.plist')).symlink_to(self.agent)
        for directory, _, _ in os.walk(self.root, followlinks=False):
            if Path(directory) != self.root: Path(directory).chmod(0o555)
        self.spec = {'generationPath': str(self.generation), 'agentsPath': str(self.agents),
            'homeFilesPath': str(self.home), 'agentSourcePath': str(self.agent), 'agentText': text,
            'identity': self.label, 'channel': 'development', 'homeFiles': {
                browser: {'source': str(record), 'text': record.read_text(), 'kind': 'regular'},
                'Applications/Omux-dev.app': {'source': str(self.app), 'text': None, 'kind': 'directory'}}}
        self.aliases = {str(self.agent): self.agent, str(record): record}
        self.until = time.monotonic_ns()+60*10**9

    def tearDown(self):
        for directory, _, files in os.walk(self.root, followlinks=False):
            Path(directory).chmod(0o700)
            for name in files:
                path = Path(directory)/name
                if not path.is_symlink(): path.chmod(0o600)
        self.temporary.cleanup()

    def observe_with_captured_fds(self, callback=None):
        captured = []
        original = subject.Held.__init__
        def capture(held, *args):
            original(held, *args)
            captured.extend(row[1] for row in held.chain)
            if held.fd is not None: captured.append(held.fd)
        try:
            with patch.object(subject.Held, '__init__', capture):
                return subject.observe(self.spec, self.aliases, self.until, before_final=callback)
        finally:
            self.assertTrue(captured)
            for fd in set(captured):
                with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_links_bytes_and_cleanup_remain_observation_only(self):
        raw = self.observe_with_captured_fds()
        report = json.loads(raw)
        self.assertEqual(report['scope'], 'selected-generation-topology-and-bytes-only')
        self.assertEqual(report['agentSha256'], subject.sha(self.agent.read_bytes()))
        self.assertEqual(report['regularSources'], 2)
        self.assertEqual(report['generationPath'], str(self.generation))
        self.assertEqual(report['generationWitness'], list(subject.witness(self.generation.stat())))
        self.assertEqual(report['regularSourceBodies'], [{'source': path, 'sha256': subject.sha(alias.read_bytes()),
            'bytes': len(alias.read_bytes()), 'mode': 0o444} for path, alias in sorted(self.aliases.items())])
        self.assertEqual(report['genuineEvaluatorReceipt'], 'not-authenticated-by-this-observer')
        for name in ('activation', 'appleAcceptance', 'liveService', 'liveHandoff'):
            self.assertEqual(report[name], 'unproved')
        self.assertEqual(report['nativePeer'], 'unsupported')

    def test_missing_or_wrong_declared_body_alias_refuses(self):
        other = self.root/'other'; other.write_bytes(self.agent.read_bytes()); other.chmod(0o444)
        for wrong in ({}, {**self.aliases, str(self.agent): other}):
            with self.subTest(wrong=list(wrong)), self.assertRaises(ValueError):
                subject.observe(self.spec, wrong, self.until)

    def test_wrong_actual_generation_link_and_extra_agent_refuse(self):
        for wrong in ('link', 'extra'):
            with self.subTest(wrong=wrong):
                if wrong == 'link':
                    self.generation.chmod(0o700)
                    (self.generation/'LaunchAgents').unlink()
                    (self.generation/'LaunchAgents').symlink_to(self.home)
                    self.generation.chmod(0o555)
                else:
                    self.agents.chmod(0o700); (self.agents/'extra.plist').write_bytes(b'extra'); self.agents.chmod(0o555)
                with self.assertRaises(ValueError): self.observe_with_captured_fds()
                if wrong == 'link':
                    self.generation.chmod(0o700); (self.generation/'LaunchAgents').unlink()
                    (self.generation/'LaunchAgents').symlink_to(self.agents); self.generation.chmod(0o555)

    def test_final_control_callback_source_bytes_and_identical_replacement_refuse(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                original = self.agent.read_bytes()
                seen = []
                def mutate():
                    seen.append(True)
                    if replacement:
                        self.sources.chmod(0o700); self.agent.rename(self.sources/'displaced')
                        self.agent.write_bytes(original); self.agent.chmod(0o444); self.sources.chmod(0o555)
                    else:
                        self.agent.chmod(0o600); self.agent.write_bytes(b'changed public plist'); self.agent.chmod(0o444)
                with self.assertRaises(ValueError): self.observe_with_captured_fds(mutate)
                self.assertEqual(seen, [True])
                self.agent.chmod(0o600); self.agent.write_bytes(original); self.agent.chmod(0o444)

    def test_final_control_callback_namespace_and_body_alias_mutation_refuse(self):
        original_alias = self.aliases[str(self.agent)]
        other = self.root/'same-content-other'; other.write_bytes(self.agent.read_bytes()); other.chmod(0o444)
        for wrong in ('namespace', 'alias'):
            seen = []
            def mutate():
                seen.append(wrong)
                if wrong == 'namespace':
                    self.agents.chmod(0o700); (self.agents/'late.plist').write_bytes(b'late'); self.agents.chmod(0o555)
                else: self.aliases[str(self.agent)] = other
            with self.subTest(wrong=wrong), self.assertRaises(ValueError): self.observe_with_captured_fds(mutate)
            self.assertEqual(seen, [wrong])
            if wrong == 'namespace':
                self.agents.chmod(0o700); (self.agents/'late.plist').unlink(); self.agents.chmod(0o555)
            self.aliases[str(self.agent)] = original_alias

    def test_final_callback_expiry_refuses_and_closes_original_descriptors(self):
        stack = ExitStack()
        def expire(): stack.enter_context(patch.object(subject.time, 'monotonic_ns', return_value=self.until))
        try:
            with self.assertRaises(ValueError): self.observe_with_captured_fds(expire)
        finally: stack.close()

    def test_close_failure_still_attempts_remaining_descriptors_and_refuses(self):
        original = os.close
        closing, failed = [], []
        def close(fd):
            original(fd)
            if closing and not failed:
                failed.append(fd); raise OSError('model close refusal after actual close')
        with patch.object(subject.os, 'close', side_effect=close):
            with self.assertRaises(OSError): self.observe_with_captured_fds(lambda: closing.append(True))
        self.assertEqual(len(failed), 1)

    def test_first_root_metadata_fault_retires_actual_opened_descriptor_without_report(self):
        original_open, original_stat = os.open, os.fstat
        roots, attempted = [], []
        def opened(path, *args, **kwargs):
            fd = original_open(path, *args, **kwargs)
            if path == '/': roots.append(fd)
            return fd
        def metadata(fd):
            if roots and fd == roots[0] and not attempted:
                attempted.append(fd)
                raise OSError('model first root fstat refusal')
            return original_stat(fd)
        output = io.StringIO()
        with patch.object(subject.os, 'open', side_effect=opened), patch.object(subject.os, 'fstat', side_effect=metadata), redirect_stdout(output):
            with self.assertRaises(OSError): subject.observe(self.spec, self.aliases, self.until)
        self.assertEqual(attempted, roots)
        self.assertEqual(len(roots), 1)
        self.assertEqual(output.getvalue(), '')
        with self.assertRaises(OSError): original_stat(roots[0])

    def test_interrupted_actual_root_fd_transfer_attempts_one_real_close_without_report(self):
        original_set, original_close = subject.Held.__setattr__, os.close
        faults, closes = [], []
        def transfer(held, name, value):
            pending = getattr(held, 'pending', None)
            chain = getattr(held, 'chain', [])
            if name == 'pending' and value is None and pending is not None and chain \
                    and chain[-1][1] == pending and not faults:
                faults.append(pending)
                raise KeyboardInterrupt('model interrupted pending-to-chain transfer')
            return original_set(held, name, value)
        def closed(fd):
            closes.append(fd); return original_close(fd)
        output = io.StringIO()
        with patch.object(subject.Held, '__setattr__', transfer), patch.object(subject.os, 'close', side_effect=closed), redirect_stdout(output):
            with self.assertRaises(KeyboardInterrupt): subject.observe(self.spec, self.aliases, self.until)
        self.assertEqual(len(faults), 1)
        self.assertEqual(closes, faults)
        self.assertEqual(output.getvalue(), '')
        with self.assertRaises(OSError): os.fstat(faults[0])

    def selected_layout(self):
        definition = {**self.spec, 'schemaVersion': 1, 'kind': subject.KIND,
            'scope': 'genuine-pinned-darwin-home-manager-evaluation-only',
            'activation': 'unproved', 'generatedBytes': 'unrealized-unverified',
            'appleAcceptance': 'unproved', 'runtimeCollector': 'darwin-live-binding-unimplemented',
            'generationDerivation': str(self.root/'model-generation.drv'), 'homeDirectory': '/Users/model',
            'desiredProgramArguments': [], 'generatedProgramArguments': [],
            'artifact': {'root': str(self.app), 'manifestSha256': 'a'*64,
                'narHash': 'sha256-'+'A'*43+'=', 'sourceRevision': 'a'*40},
            'predicates': {'synthetic-topology-only': True}}
        selected = self.root/'definition.json'
        raw = json.dumps(definition).encode(); selected.write_bytes(raw)
        (self.root/'spec-alias.json').symlink_to(selected)
        sources = {}
        for index, (path, alias) in enumerate(sorted(self.aliases.items())):
            name = 'source-alias-'+str(index)
            (self.root/name).symlink_to(alias)
            sources[path] = {'sha256': subject.sha(alias.read_bytes()), 'alias': name}
        layout = self.root/'selected-layout.json'
        layout.write_text(json.dumps({'schemaVersion': 1, 'kind': subject.SELECT, 'selection': {
            'spec': {'path': str(selected), 'sha256': subject.sha(raw), 'alias': 'spec-alias.json'},
            'sources': sources}}))
        return layout

    def test_actual_main_stdout_write_and_flush_expiry_refuse_with_all_original_fds_closed(self):
        layout = self.selected_layout()
        for fault in ('write', 'flush'):
            entry = time.monotonic_ns(); until = entry+600*10**9
            captured, seams = [], []
            original = subject.Held.__init__
            def capture(held, *args):
                original(held, *args)
                captured.extend(row[1] for row in held.chain)
                if held.fd is not None: captured.append(held.fd)
            expiry = ExitStack()
            class Output(io.StringIO):
                def write(self, raw):
                    result = super().write(raw)
                    if fault == 'write':
                        seams.append('write'); expiry.enter_context(patch.object(subject.time, 'monotonic_ns', return_value=until))
                    return result
                def flush(self):
                    super().flush()
                    if fault == 'flush':
                        seams.append('flush'); expiry.enter_context(patch.object(subject.time, 'monotonic_ns', return_value=until))
            output = Output()
            try:
                with self.subTest(fault=fault), patch.object(subject.sys, 'argv', ['model', '--layout', str(layout),
                        '--entry-monotonic-ns', str(entry), '--deadline-monotonic-ns', str(entry+1200*10**9)]), \
                        patch.object(subject.Held, '__init__', capture), redirect_stdout(output):
                    with self.assertRaises(ValueError): subject.main()
            finally: expiry.close()
            self.assertEqual(seams, [fault])
            self.assertEqual(json.loads(output.getvalue())['genuineEvaluatorReceipt'], 'not-authenticated-by-this-observer')
            self.assertTrue(captured)
            for fd in set(captured):
                with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_main_final_control_layout_retarget_refuses_and_retires_original_fds(self):
        layout = self.selected_layout()
        other = self.root/'identical-layout.json'; other.write_bytes(layout.read_bytes())
        spec_path = self.root/'definition.json'
        captured, spec_reads, faults = [], [], []
        original_init, original_read = subject.Held.__init__, subject.Held.read
        def capture(held, *args):
            original_init(held, *args); captured.extend(row[1] for row in held.chain)
            if held.fd is not None: captured.append(held.fd)
        # A separate alias parent is outside every held physical input chain;
        # parent timestamps must not substitute for this exact mapping check.
        with tempfile.TemporaryDirectory() as transport:
            transport = Path(transport).resolve(strict=True)
            selected = transport/'layout.json'; selected.symlink_to(layout)
            (transport/'spec-alias.json').symlink_to(spec_path)
            for index, (_, source) in enumerate(sorted(self.aliases.items())):
                (transport/('source-alias-'+str(index))).symlink_to(source)
            generation_stamp = subject.witness(self.generation.stat())
            original_bodies = {path: alias.read_bytes() for path, alias in self.aliases.items()}
            def read(held):
                raw = original_read(held)
                if held.path == spec_path:
                    spec_reads.append(True)
                    if len(spec_reads) == 2:
                        faults.append(True); selected.unlink(); selected.symlink_to(other)
                return raw
            entry = time.monotonic_ns(); output = io.StringIO()
            with patch.object(subject.sys, 'argv', ['model', '--layout', str(selected),
                    '--entry-monotonic-ns', str(entry), '--deadline-monotonic-ns', str(entry+1200*10**9)]), \
                    patch.object(subject.Held, '__init__', capture), patch.object(subject.Held, 'read', read), redirect_stdout(output):
                with self.assertRaises(ValueError): subject.main()
            self.assertEqual(faults, [True])
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(subject.witness(self.generation.stat()), generation_stamp)
            self.assertEqual({path: alias.read_bytes() for path, alias in self.aliases.items()}, original_bodies)
            self.assertEqual(layout.read_bytes(), other.read_bytes())
            self.assertTrue(captured)
            for fd in set(captured):
                with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_main_cold_layout_has_no_future_object_read_or_success_output(self):
        layout = self.root/'layout.json'
        layout.write_text(json.dumps({'schemaVersion': 1, 'kind': subject.SELECT, 'selection': None}))
        entry = time.monotonic_ns()
        output = io.StringIO()
        with patch.object(subject.sys, 'argv', ['model', '--layout', str(layout),
                '--entry-monotonic-ns', str(entry), '--deadline-monotonic-ns', str(entry+1200*10**9)]), \
                patch.object(subject, 'observe', side_effect=AssertionError('cold selection reached generation')), \
                redirect_stdout(output):
            with self.assertRaises(ValueError): subject.main()
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__': unittest.main()
