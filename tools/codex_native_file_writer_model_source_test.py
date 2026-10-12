"""Exact real native delta/full map and actual owned-publication fault predicates.

Parent guardian/full SDK/query child are explicit seams, never model-qualified.
"""
from contextlib import ExitStack, contextmanager
import copy
import io
import sys
from types import SimpleNamespace
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_file_writer_model_source as model
from codex_native_source_file_writer_test import cleanup

source = model.source
ROOT = Path(__file__).parent.parent


class FileWriterModelSourceTests(unittest.TestCase):
    def setUp(self):
        self.old = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
        self.raw_control, self.control = model.controls()
        self.raw_patch = model.model_patch(self.control)
        self.before = {name: ('100644', (ROOT / 'integrations/codex-upstream/file-writer-models/model-preimages' / model.PREIMAGE_FILES[name]).read_bytes())
            for name in model.PATHS}
        self.before['unrelated'] = ('100644', b'public unchanged source fixture\n')

    def tearDown(self): source.DEADLINE = self.old

    def test_actual_four_delta_has_no_production_or_model_body_changes(self):
        after = model.transform(self.before, self.raw_patch, self.control)
        self.assertEqual(set(after), set(self.before))
        self.assertEqual(after['unrelated'], self.before['unrelated'])
        for name in model.PATHS:
            self.assertEqual(source.sha(after[name][1]), self.control['delta']['paths'][name]['after']['sha256'])
        for name in ('codex-rs/login/src/auth/default_client.rs', 'codex-rs/login/src/auth/revoke.rs'):
            self.assertEqual(after[name][1].replace(b'#[cfg(all(test, not(feature = "omux-native-file-writer-storage-models")))]', b'#[cfg(test)]'), self.before[name][1])
        self.assertIn(b'omux-native-file-writer-storage-models = []', after['codex-rs/login/Cargo.toml'][1])

    def test_wrong_predecessor_mode_missing_and_changed_byte_refuse(self):
        for name in model.PATHS:
            variants = ({key: value for key, value in self.before.items() if key != name},
                {**self.before, name: ('100755', self.before[name][1])},
                {**self.before, name: ('100644', self.before[name][1] + b'changed')})
            for files in variants:
                with self.assertRaises(ValueError): model.transform(files, self.raw_patch, self.control)

    def test_rehashed_duplicate_bad_position_unknown_path_refuse(self):
        first = self.raw_patch.index(b'diff --git ', 1)
        at = self.raw_patch.index(b'@@ -'); end = self.raw_patch.index(b'\n', at)
        for raw in (self.raw_patch + self.raw_patch[:first],
                    self.raw_patch[:at] + self.raw_patch[at:end].replace(b'+', b'+999', 1) + self.raw_patch[end:],
                    self.raw_patch.replace(b'a/codex-rs/login/BUILD.bazel', b'a/unknown', 1)):
            controls = copy.deepcopy(self.control)
            controls['delta']['patch'].update(sha256=source.sha(raw), bytes=len(raw))
            with self.assertRaises(ValueError): model.transform(self.before, raw, controls)

    def test_same_namespace_unrelated_bytes_and_after_pins_are_exact(self):
        after = model.transform(self.before, self.raw_patch, self.control)
        for files in ({**after, 'extra': ('100644', b'extra')},
                      {**after, 'unrelated': ('100644', b'drift')},
                      {**after, next(iter(model.PATHS)): ('100644', b'wrong')}):
            with self.assertRaises(ValueError): model.validate_transition(self.before, files, self.control)

    def test_report_keeps_ten_parent_patches_and_every_capability_false(self):
        after = model.transform(self.before, self.raw_patch, self.control)
        parent = self.parent_report()
        report = model.make_report(parent, after, self.control, model.configuration()[1])
        self.assertEqual(report['patch_sha256'][:-1], parent['patch_sha256'])
        self.assertEqual(len(report['patch_sha256']), 11)
        self.assertTrue(all(report[name] is False for name in model.FALSE_FLAGS))
        self.assertIsNone(report['generated_hub'])
        self.assertEqual(report['inventory_sha256'], source.sha(source.canonical(report['source_inventory'])))
        self.assertEqual(report['graph_files']['codex-rs/login/BUILD.bazel']['sha256'], source.sha(after['codex-rs/login/BUILD.bazel'][1]))

    def parent_report(self):
        return {'kind': model.tenth.KIND, 'status': 'verified-tenth-file-writer-source-uncompiled',
            'inventory_sha256': model.configuration()[1]['parent']['inventory_sha256'],
            **{flag: False for flag in model.tenth.FLAGS}, 'patch_sha256': ['a' * 64] * 10, 'patches': [{'patch_sha256': 'a' * 64, 'paths': []}] * 10,
            'graph_files': {'codex-rs/login/BUILD.bazel': {'sha256': source.sha(self.before['codex-rs/login/BUILD.bazel'][1])}}}

    def hub(self):
        def row(deps=(), dev=(), aliases=None):
            return {'aliases': aliases or {}, 'binaries': {}, 'build_deps': [], 'build_deps_by_platform': {},
                'crate_features': [], 'crate_features_by_platform': {}, 'deps': list(deps), 'deps_by_platform': {},
                'dev_deps': list(dev), 'dev_deps_by_platform': {}, 'shared_libraries': {}}
        m = model.binding.metadata
        data = {m.PACKAGE: row((m.ROLLOUT, m.HISTORY), aliases={m.ROLLOUT: 'codex_rollout', m.HISTORY: 'codex_history'}),
            'codex-rs/app-server': row(dev=('@crates//:hmac-0.12.1',)),
            'codex-rs/login': row(dev=('//codex-rs/core/tests/common', '@crates//:tiny_http-0.12.0')),
            'unrelated': row(('@crates//:libc-0.2.186',))}
        old = {'BUILD.bazel': b'public build\n', 'defs.bzl': b'public definitions\n', 'data.bzl': ('DEP_DATA = ' + repr(data) + '\n').encode()}
        new = copy.deepcopy(data)
        new[m.PACKAGE]['deps'].remove(m.ROLLOUT); del new[m.PACKAGE]['aliases'][m.ROLLOUT]
        additions = ['@crates//:hmac-0.12.1', '@crates//:libc-0.2.186', '@crates//:zeroize-1.8.2']
        new['codex-rs/app-server']['dev_deps'].remove(additions[0])
        new['codex-rs/app-server']['deps'] = sorted(additions)
        new['codex-rs/login']['deps'] = sorted(additions)
        return old, {**old, 'data.bzl': ('DEP_DATA = ' + repr(new) + '\n').encode()}, new

    def test_complete_hub_adds_exact_normal_edges_without_feature_or_dev_pruning(self):
        old, new, unused = self.hub()
        self.assertIs(model.verify_hub(old, new), True)

    def test_extra_missing_platform_alias_feature_and_unrelated_hub_edges_refuse(self):
        old, good, new = self.hub()
        for changed in ('deps', 'dev_deps', 'aliases', 'crate_features', 'deps_by_platform'):
            data = copy.deepcopy(new)
            row = data['unrelated']
            if changed in ('deps', 'dev_deps', 'crate_features'): row[changed].append('extra')
            elif changed == 'aliases': row[changed]['extra'] = 'extra'
            else: row[changed]['unix'] = ['extra']
            with self.assertRaises(ValueError): model.verify_hub(old, {**good, 'data.bzl': ('DEP_DATA = ' + repr(data)).encode()})
        for bad in ({**good, 'defs.bzl': b'changed'}, {**good, 'extra.bzl': b'extra'},
                    {name: raw for name, raw in good.items() if name != 'BUILD.bazel'}):
            with self.assertRaises(ValueError): model.verify_hub(old, bad)

    def test_additional_workspace_dev_dependency_is_not_silently_dropped(self):
        old, good, unused = self.hub()
        data = model.binding.metadata.dep_data(old['data.bzl'])
        data['codex-rs/login']['dev_deps'].append('//another/workspace/helper')
        with self.assertRaises(ValueError): model.verify_hub({**old, 'data.bzl': ('DEP_DATA = ' + repr(data)).encode()}, good)

    def run_producer(self, directory, at_exit=None):
        outer = self
        @contextmanager
        def parent(config, inputs, retained):
            root = directory / 'parent'
            fd = source.write_source(root, outer.before); os.fchmod(fd, 0o555); os.close(fd)
            tree = model.tenth.TreeWitness(root / 'source', outer.before)
            retained.append(tree)
            yield None, None, [tree], outer.before, outer.parent_report()
            if at_exit is not None: at_exit(directory / 'out')
            tree.check()
        inputs = type('InputsSeam', (), {'check': lambda unused: None})()
        with patch.object(model, 'parent_source', parent):
            published = model.Publication()
            try:
                report = model.produce(directory / 'out', inputs, directory / 'unused', published)
                published.full(); published.fence()
                return report
            finally: published.close()

    def test_real_publication_source_receipt_byte_readback_and_fd_cleanup(self):
        root = Path(tempfile.mkdtemp())
        try:
            report = self.run_producer(root)
            self.assertEqual((root / 'out').stat().st_mode & 0o777, 0o555)
            self.assertEqual((root / 'out/source-receipt.json').read_bytes(), source.encoded(report))
        finally: cleanup(root)

    def test_mutation_during_last_parent_finish_refuses_same_byte_replacement_and_body_edit(self):
        for replace in (False, True):
            root = Path(tempfile.mkdtemp())
            try:
                def mutate(output):
                    leaf = output / 'source/unrelated'
                    leaf.parent.chmod(0o700)
                    if replace:
                        old = leaf.read_bytes(); leaf.unlink(); leaf.write_bytes(old)
                    else:
                        leaf.chmod(0o600); leaf.write_bytes(b'changed public fixture\n')
                    leaf.chmod(0o555); leaf.parent.chmod(0o555)
                with self.assertRaises((ValueError, OSError)): self.run_producer(root, mutate)
            finally: cleanup(root)

    def test_actual_last_receipt_body_read_replacement_refuses_original_writer(self):
        root = Path(tempfile.mkdtemp())
        real_read = source.read
        state = {'mutated': False}
        try:
            def read(fd, name, maximum):
                raw, mode = real_read(fd, name, maximum)
                path = Path('/proc/self/fd/' + str(fd)).resolve()
                if name == 'source-receipt.json' and path == root / 'out' and (root / 'out').stat().st_mode & 0o777 == 0o555 and not state['mutated']:
                    state['mutated'] = True
                    path.chmod(0o700)
                    leaf = path / name; leaf.unlink(); leaf.write_bytes(raw); leaf.chmod(0o444); path.chmod(0o555)
                return raw, mode
            with patch.object(source, 'read', side_effect=read), self.assertRaises(ValueError): self.run_producer(root)
            self.assertTrue(state['mutated'])
        finally: cleanup(root)

    def test_final_source_and_output_physical_fence_keeps_owned_late_io_separate(self):
        root = Path(tempfile.mkdtemp())
        published = model.Publication()
        try:
            files = {'one': ('100644', b'public')}
            fd = source.write_source(root / 'out', files)
            raw = b'public receipt\n'; receipt, anchor = model.publish_receipt(fd, raw)
            tree = model.tenth.TreeWitness(root / 'out', {'source/one': files['one'], 'source-receipt.json': ('100644', raw)}, root_mode=0o700, receipt_name='source-receipt.json')
            before = model.tenth.witness(os.fstat(fd)); os.fchmod(fd, 0o555)
            tree.accept_root_seal(before, model.tenth.witness(os.fstat(fd)))
            published.bind(root / 'out', fd, receipt, anchor, tree, files, None, raw)
            published.full()
            leaf = root / 'out/source/one'; leaf.chmod(0o600); leaf.write_bytes(b'public'); leaf.chmod(0o555)
            with self.assertRaises(ValueError): published.fence()
            published.close()
            with self.assertRaises(OSError): os.fstat(receipt)
        finally:
            published.close(); cleanup(root)

    def test_original_integer_deadline_is_not_reset_and_refuses_wrong_context(self):
        source.DEADLINE = None; model.query.DEADLINE = None
        now = time.monotonic_ns(); entry = now - 1_000_000; until = entry + 1200*10**9
        env = {model.MODE: model.PROFILE, model.ENTRY: str(entry), model.UNTIL: str(until),
            'TEST_TIMEOUT': '840', 'TEST_UNDECLARED_OUTPUTS_DIR': '/declared/public',
            'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab',
            'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT': 'a' * 40, 'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256': 'b' * 64}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(model.admission(), (entry, until, float((entry + 600*10**9)/10**9)))
        for change in ({model.MODE: 'old-source-mode'}, {model.UNTIL: str(until+1)}, {'TEST_TIMEOUT': '60'}):
            with patch.dict(os.environ, {**env, **change}, clear=True), self.assertRaises(ValueError): model.admission()

    def test_outer_xml_failure_is_not_success_on_new_declared_proof_route(self):
        with self.assertRaises(ValueError): model.material.declared_xml_success(b'<testsuites failures="1"><testsuite tests="1" failures="0" errors="0" skipped="0"/></testsuites>')

    def inputs_fixture(self, root):
        repository = root / 'external/models'
        (repository / 'input').mkdir(parents=True, mode=0o700)
        leaf = root / 'public-proof.json'
        leaf.write_bytes(b'{"public":true}\n'); leaf.chmod(0o555)
        (repository / 'input/0').symlink_to(leaf)
        raw = source.encoded({'kind': model.INPUT_KIND, 'selection': {},
            'inputs': [{'path': str(leaf), 'alias': 'input/0'}]})
        (repository / 'source-inputs.json').write_bytes(raw)
        (repository / 'source-inputs.json').chmod(0o644)
        runfiles = root / 'runfiles'
        runfiles.mkdir(); (runfiles / 'models').symlink_to(repository, target_is_directory=True)
        return runfiles, leaf, repository

    def test_real_declared_input_alias_byte_and_same_byte_identity_join(self):
        root = Path(tempfile.mkdtemp())
        owner = None
        try:
            runfiles, leaf, repository = self.inputs_fixture(root)
            owner = model.Inputs(runfiles, [['_main', model.REPOSITORY, 'models']])
            raw = owner.read(leaf, source.sha(leaf.read_bytes()), source.DEADLINE)
            self.assertEqual(raw, b'{"public":true}\n')
            old = leaf.read_bytes(); leaf.unlink(); leaf.write_bytes(old); leaf.chmod(0o555)
            with self.assertRaises(ValueError): owner.check_all()
            fd = owner.held[str(leaf)][1]
            owner.close(); owner = None
            with self.assertRaises(OSError): os.fstat(fd)
        finally:
            if owner is not None: owner.close()
            # runfiles alias must not let fixture cleanup traverse a foreign root.
            if (root / 'runfiles/models').is_symlink(): (root / 'runfiles/models').unlink()
            cleanup(root)

    def test_real_declared_alias_retarget_and_replacement_refuse(self):
        for replace in (False, True):
            root = Path(tempfile.mkdtemp()); owner = None
            try:
                runfiles, leaf, repository = self.inputs_fixture(root)
                owner = model.Inputs(runfiles, [['_main', model.REPOSITORY, 'models']])
                alias = repository / 'input/0'; alias.unlink()
                if replace: alias.symlink_to(leaf)
                else:
                    other = root / 'other'; other.write_bytes(leaf.read_bytes()); other.chmod(0o555)
                    alias.symlink_to(other)
                with self.assertRaises(ValueError): owner.check_all()
            finally:
                if owner is not None: owner.close()
                if (root / 'runfiles/models').is_symlink(): (root / 'runfiles/models').unlink()
                cleanup(root)

    def test_sdk_selected_hub_reads_every_declared_regular_and_rejects_nested_or_device(self):
        prefix = 'repositories/' + model.binding.metadata.HUB + '/'
        rows = {('sdk', prefix + name): {'kind': 'file', 'size': len(raw)}
            for name, raw in self.hub()[0].items()}
        owner = type('SDKSeam', (), {})(); owner.expected = rows
        values = self.hub()[0]
        calls = []
        def read(role, name, maximum):
            calls.append((role, name)); return values[name[len(prefix):]]
        owner.read_regular = read
        self.assertEqual(model.original_hub(owner), values)
        self.assertEqual(len(calls), len(values))
        for name, row in ((prefix + 'nested/data', {'kind': 'file', 'size': 1}),
                          (prefix + 'device', {'kind': 'device', 'size': 0})):
            owner.expected = {**rows, ('sdk', name): row}
            with self.assertRaises(ValueError): model.original_hub(owner)

    def test_actual_main_late_sdk_phase_refuses_held_proof_alias_and_control_drift(self):
        # Entire actual main/Inputs/HeldControls/Publication flow executes; only
        # parent admission, full SDK/NAR and query child are explicit seams.
        import codex_native_carrier_metadata as metadata
        for fault in ('none', 'proof-bytes', 'proof-replace', 'proof-alias', 'proof-alias-parent', 'carrier-alias', 'control', 'metadata', 'receipt',
                      'source-fence', 'output-fence', 'source-exit', 'output-exit',
                      'carrier-alias-fence', 'source-extra-name', 'source-directory-replace',
                      'directory-fd-bound', 'directory-fstat', 'directory-close'):
            root = Path(tempfile.mkdtemp())
            state = {'entered': False, 'finished': False, 'closed': False, 'fd_fault': False, 'close_fault': False}
            retained_fds = []
            real_enroll, real_fstat, real_close = model.MemberDirectories.enroll, os.fstat, os.close
            def enroll(owner, fd):
                value = real_enroll(owner, fd); retained_fds.append(fd); return value
            def checked_fstat(fd):
                if fault == 'directory-fstat' and fd in retained_fds and not state['fd_fault']:
                    state['fd_fault'] = True
                    raise OSError('owned post-enrollment fstat fault')
                return real_fstat(fd)
            def checked_close(fd):
                real_close(fd)
                if fault == 'directory-close' and fd in retained_fds and not state['close_fault']:
                    state['close_fault'] = True
                    raise OSError('owned descriptor retired despite close error')
            try:
                runfiles, proof_leaf, repository = self.inputs_fixture(root)
                controls_root = root / 'controls'; controls_root.mkdir()
                for name in (model.CONFIG, model.CONTROLS, self.control['delta']['patch']['path'],
                             self.control['delta']['manifest']['path'], self.control['tests']['path']):
                    target = controls_root / name; target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / name).read_bytes())
                selector = controls_root / metadata.CONFIG; selector.parent.mkdir(parents=True, exist_ok=True)
                selector.write_bytes(b'{"public":"selected fixture seam"}\n')
                extra = root / 'proofs'; extra.mkdir()
                roles = {}
                aliases = []
                for role in metadata.PROOF_ALIASES:
                    path = extra / (role + '.json')
                    raw = b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>' if role == 'test_xml' else b'{"public":true}\n'
                    path.write_bytes(raw); path.chmod(0o555)
                    roles[role] = {'path': str(path), 'sha256': source.sha(raw), 'alias': metadata.PROOF_ALIASES[role]}
                    aliases.append((path, path))
                descriptor = extra / 'proof-inputs.json'; descriptor.write_bytes(source.encoded({'kind': metadata.PROOF_KIND, 'proofs': roles})); descriptor.chmod(0o444)
                proof_inputs = SimpleNamespace(aliases=[(descriptor, descriptor)] + aliases,
                    sha256=source.sha(descriptor.read_bytes()), document={'proofs': roles}, recheck=lambda deadline: None,
                    record=lambda: {'public': 'proof qualification seam'})
                declaration_file = extra / 'selection.json'; declaration_file.write_bytes(b'{"public":true}\n'); declaration_file.chmod(0o444)
                declaration = {'selection_path': str(declaration_file), 'selection_sha256': source.sha(declaration_file.read_bytes())}
                carrier_alias_parent = root / 'carrier-aliases'; carrier_alias_parent.mkdir()
                carrier_physical = extra / 'payload.bin'; carrier_physical.write_bytes(b'public transport alias seam'); carrier_physical.chmod(0o444)
                carrier_alias = carrier_alias_parent / 'payload.bin'; carrier_alias.symlink_to(carrier_physical)
                outputs = root / 'outputs'; outputs.mkdir()
                old, good, unused = self.hub()
                native_parent = self.parent_report()
                @contextmanager
                def parent(config, inputs, retained):
                    inputs.read(proof_leaf, source.sha(proof_leaf.read_bytes()), source.DEADLINE)
                    fd = source.write_source(root / 'parent', self.before); os.fchmod(fd, 0o555); os.close(fd)
                    tree = model.tenth.TreeWitness(root / 'parent/source', self.before); retained.append(tree)
                    yield None, None, [tree], self.before, native_parent
                    tree.check()
                @contextmanager
                def scoped(deadline): yield
                def mutate(path, replace=False):
                    raw = path.read_bytes()
                    path.parent.chmod(0o700)
                    if replace:
                        path.unlink(); path.write_bytes(raw)
                    else:
                        path.chmod(0o600); path.write_bytes(raw)
                    path.chmod(0o555)
                def inplace(path):
                    raw = path.read_bytes()
                    path.chmod(0o600)
                    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    path.chmod(0o555)
                def terminal_fault(stage):
                    if fault == 'source-' + stage: inplace(root / 'parent/source/unrelated')
                    elif fault == 'output-' + stage: inplace(outputs / model.OUTPUT / 'source/unrelated')
                    elif stage == 'fence' and fault == 'carrier-alias-fence':
                        carrier_alias.unlink(); carrier_alias.symlink_to(carrier_physical)
                    elif stage == 'fence' and fault == 'source-extra-name':
                        parent = root / 'parent/source'; parent.chmod(0o700)
                        (parent / 'extra').write_bytes(b'public extra'); parent.chmod(0o555)
                    elif stage == 'fence' and fault == 'source-directory-replace':
                        parent = root / 'parent/source/codex-rs/login/src'; parent.chmod(0o700)
                        original = parent / 'auth'; original.rename(parent / 'old-auth')
                        original.mkdir()
                        for name in ('default_client.rs', 'revoke.rs'):
                            leaf = original / name; leaf.write_bytes((parent / 'old-auth' / name).read_bytes()); leaf.chmod(0o555)
                        original.chmod(0o555); parent.chmod(0o555)
                class SDK:
                    def __init__(self, alias, physical, carrier_root, pin, entry, until, context):
                        self.carrier_pin = pin; self.expected = {}; self.catalogue = SimpleNamespace(raw=b'public SDK seam')
                        self.context = context
                    def __enter__(self): state['entered'] = True; return self
                    def mapping(self): return {'repositories': {}, 'module_overrides': {}, 'graph_files': {}, 'registry_cache': str(model.query.EXPORT_ROOT / 'registry-cache'), 'inventory_sha256': 'a'*64, 'mapping_sha256': 'b'*64, 'registry_inventory_sha256': 'c'*64}
                    def finish(self):
                        state['finished'] = True
                        if fault == 'proof-bytes': mutate(proof_leaf)
                        elif fault == 'proof-replace': mutate(extra / 'outer_receipt.json', True)
                        elif fault == 'proof-alias':
                            alias = repository / 'input/0'; alias.unlink(); alias.symlink_to(proof_leaf)
                        elif fault == 'proof-alias-parent':
                            repository.chmod(0o700)
                            (repository / 'input').rename(repository / 'old-input')
                            (repository / 'input').mkdir()
                            (repository / 'input/0').symlink_to(proof_leaf)
                        elif fault == 'carrier-alias':
                            carrier_alias.unlink(); carrier_alias.symlink_to(carrier_physical)
                        elif fault == 'control': mutate(controls_root / model.CONFIG)
                        elif fault == 'metadata': mutate(selector)
                        elif fault == 'receipt': mutate(outputs / model.OUTPUT / 'source-receipt.json', True)
                    def fence(self): terminal_fault('fence')
                    def __exit__(self, *unused):
                        state['closed'] = True
                        if unused[0] is None: terminal_fault('exit')
                sdk_module = SimpleNamespace(declared_manifest=lambda runfiles, rows: (root / 'manifest', root / 'manifest'), HeldOriginalSDK=SDK)
                entry = time.monotonic_ns(); until = entry + 1200*10**9
                env = {model.MODE: model.PROFILE, model.ENTRY: str(entry), model.UNTIL: str(until), 'TEST_TIMEOUT': '840',
                    'TEST_SRCDIR': str(runfiles), 'TEST_UNDECLARED_OUTPUTS_DIR': str(outputs),
                    'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab',
                    'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT': 'a'*40, 'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256': 'b'*64}
                (runfiles / '_repo_mapping').write_bytes(('_main,' + model.REPOSITORY + ',models\n').encode())
                (runfiles / '_repo_mapping').chmod(0o444)
                source.DEADLINE = model.query.DEADLINE = None
                captured = io.StringIO()
                with ExitStack() as patch_scope:
                    patch_scope.enter_context(patch.dict(os.environ, env, clear=True))
                    patch_scope.enter_context(patch.object(model.sys, 'argv', ['model-source']))
                    patch_scope.enter_context(patch.object(model.binding.ninth.parent, 'ROOT', controls_root))
                    patch_scope.enter_context(patch.object(model, 'parent_source', parent))
                    patch_scope.enter_context(patch.object(model, 'regenerate', return_value=(good, {'public': 'query seam'}, {'status': 'declared-fixture'})))
                    patch_scope.enter_context(patch.dict(sys.modules, {'codex_original_sdk_inputs': sdk_module}))
                    patch_scope.enter_context(patch.object(metadata, 'proof_scope', scoped))
                    patch_scope.enter_context(patch.object(metadata, 'selection', return_value={'carrier': {'receipt_sha256': 'd'*64}}))
                    patch_scope.enter_context(patch.object(metadata, 'declared_carrier', return_value=(root / 'carrier', ((carrier_alias, carrier_physical),), declaration)))
                    patch_scope.enter_context(patch.object(metadata, 'declared_proofs', return_value=proof_inputs))
                    patch_scope.enter_context(patch.object(metadata, 'qualify_producer', return_value={'public': 'qualification seam'}))
                    patch_scope.enter_context(patch.object(metadata, 'recheck_aliases'))
                    patch_scope.enter_context(patch.object(model.query, 'declared_query_tools'))
                    patch_scope.enter_context(patch.object(model.query, 'QUERY_REPOSITORY', root / 'query'))
                    patch_scope.enter_context(patch.object(model, 'MAX_DIRECTORY_FDS', 2 if fault == 'directory-fd-bound' else 16384))
                    patch_scope.enter_context(patch.object(model.MemberDirectories, 'enroll', enroll))
                    patch_scope.enter_context(patch.object(model.os, 'fstat', checked_fstat))
                    patch_scope.enter_context(patch.object(model.os, 'close', checked_close))
                    patch_scope.enter_context(patch('sys.stdout', captured))
                    if fault == 'none': model.main()
                    else:
                        with self.assertRaises((ValueError, OSError)): model.main()
                self.assertTrue(state['entered'] and state['closed'])
                self.assertEqual(state['finished'], fault not in ('directory-fd-bound', 'directory-fstat'))
                for fd in retained_fds:
                    with self.assertRaises(OSError): real_fstat(fd)
                if fault == 'directory-fstat': self.assertTrue(state['fd_fault'])
                if fault == 'directory-close': self.assertTrue(state['close_fault'])
                self.assertEqual('native-file-writer-model-source: exact' in captured.getvalue(), fault == 'none')
                self.assertIsNone(source.DEADLINE); self.assertIsNone(model.query.DEADLINE)
            finally:
                if (root / 'runfiles/models').is_symlink(): (root / 'runfiles/models').unlink()
                cleanup(root)
                source.DEADLINE = time.monotonic() + 120

    def test_directory_budget_is_one_owner_across_copies_and_refusal_retires_fds(self):
        root = Path(tempfile.mkdtemp())
        trees, owner, held = [], model.MemberDirectories(), []
        try:
            files = {'public': ('100644', b'public model')}
            for index in range(2):
                fd = source.write_source(root / str(index), files); os.close(fd)
                trees.append(model.tenth.TreeWitness(root / str(index) / 'source', files))
            with patch.object(model, 'MAX_DIRECTORY_FDS', 3):
                owner.capture(trees[0]); held.extend(owner.fds)
                with self.assertRaises(ValueError): owner.capture(trees[1])
                held = list(owner.fds)
            self.assertEqual(len(held), 3)
        finally:
            owner.close()
            for fd in held:
                with self.assertRaises(OSError): os.fstat(fd)
            for tree in trees: tree.close()
            cleanup(root)

    def test_terminal_flat_member_join_refuses_link_and_extra_namespace(self):
        for fault in ('none', 'link', 'extra'):
            root = Path(tempfile.mkdtemp()); tree = None; owner = model.MemberDirectories()
            try:
                files = {'public': ('100644', b'public model'), 'link': ('120000', b'public')}
                fd = source.write_source(root / 'selected', files); os.close(fd)
                tree = model.tenth.TreeWitness(root / 'selected/source', files)
                owner.capture(tree)
                if fault != 'none':
                    tree.root.chmod(0o700)
                    if fault == 'link':
                        (tree.root / 'link').unlink(); (tree.root / 'link').symlink_to('public')
                    else: (tree.root / 'extra').write_bytes(b'public extra')
                    tree.root.chmod(0o555)
                    with self.assertRaises(ValueError): owner.terminal()
                else: owner.terminal()
            finally:
                owner.close()
                if tree is not None: tree.close()
                cleanup(root)

    def test_directory_close_retires_all_and_propagates_first_cleanup_error(self):
        root = Path(tempfile.mkdtemp()); tree = None; owner = model.MemberDirectories()
        real_close = os.close
        try:
            files = {'nested/public': ('100644', b'public model')}
            fd = source.write_source(root / 'selected', files); os.close(fd)
            tree = model.tenth.TreeWitness(root / 'selected/source', files); owner.capture(tree)
            held = list(owner.fds); retired = []
            def close(fd):
                real_close(fd); retired.append(fd)
                if len(retired) <= 2: raise OSError('retired-' + str(len(retired)))
            with patch.object(model.os, 'close', close):
                with self.assertRaisesRegex(OSError, 'retired-1'): owner.close()
            self.assertEqual(retired, list(reversed(held)))
            self.assertEqual(owner.fds, [])
            for fd in held:
                with self.assertRaises(OSError): os.fstat(fd)
        finally:
            owner.close()
            if tree is not None: tree.close()
            cleanup(root)

    def test_inert_preimages_keep_original_build_bytes_without_a_native_subpackage(self):
        self.assertEqual(set(model.PREIMAGE_FILES), model.PATHS)
        root = ROOT / 'integrations/codex-upstream/file-writer-models/model-preimages'
        selected = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
        self.assertEqual(selected, set(model.PREIMAGE_FILES.values()))
        self.assertTrue(all(Path(path).name not in ('BUILD', 'BUILD.bazel') for path in selected))
        for logical, stored in model.PREIMAGE_FILES.items():
            self.assertEqual(source.sha((root / stored).read_bytes()), self.control['delta']['paths'][logical]['before']['sha256'])
        build = (ROOT / 'integrations/codex-upstream/file-writer-models/BUILD.bazel').read_text()
        self.assertIn('srcs = inert_model_preimages([', build)
        self.assertNotIn('glob(', build)
        for stored in selected: self.assertIn('"model-preimages/' + stored + '"', build)
        rule = (ROOT / 'tools/codex_native_file_writer_model_source_inputs.bzl').read_text()
        self.assertIn('paths != expected', rule)
        self.assertIn('("BUILD", "BUILD.bazel")', rule)

    def test_declared_graph_keeps_new_source_and_sdk_authorities_explicit(self):
        macro = (ROOT / 'tools/codex_native_file_writer_model_source_targets.bzl').read_text()
        self.assertIn('@omux_native_file_writer_model_source_inputs//:inputs', macro)
        self.assertIn('@omux_original_native_sdk_inputs//:inputs', macro)
        self.assertIn('@omux_protocol_history_query_tools//:inputs', macro)
        self.assertNotIn('_OWNER_STATUS_PERSISTENCE_METADATA_DATA', macro)
        rule = (ROOT / 'tools/codex_native_file_writer_model_source_inputs.bzl').read_text()
        self.assertIn('len(inventory) == 8553', rule)
        self.assertIn('len(paths) == 8562', rule)
        self.assertNotIn('watch_tree', rule)
        self.assertNotIn('readdir', rule)
        self.assertIn('native_file_writer_model_source_targets(', (ROOT / 'tools/BUILD.bazel').read_text())
        controls_build = (ROOT / "integrations/codex-upstream/file-writer-models/BUILD.bazel").read_text()
        self.assertIn('visibility = ["//tools:__pkg__"]', controls_build)
        self.assertIn('exports_files(["qualified-parent.json", "BUILD.bazel"])', controls_build)
        self.assertIn('"//integrations/codex-upstream/file-writer-models:BUILD.bazel"', macro)


if __name__ == '__main__': unittest.main()
