"""Real tiny descriptor/custody models; original N10 guardian is an explicit seam."""
from contextlib import ExitStack, contextmanager
import copy
import errno
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import codex_native_n10_source_intake as intake

family, source, tenth = intake.family, intake.source, intake.tenth


class N10ContentIntakeTests(unittest.TestCase):
    def setUp(self):
        self.deadline = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
    def tearDown(self): source.DEADLINE = self.deadline

    @contextmanager
    def fixture(self, mode=0o444, *, extra=False, declaration_mode=0o444, model_proof=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'outside').write_bytes(b'public outside fixture')
            bundle = root / 'n10'
            files = {'a': ('100644', b'alpha'), 'd/b': ('100755', b'beta'), 'd/link': ('120000', b'b')}
            inventory = {name: {'mode': logical, 'sha256': source.sha(raw)} for name, (logical, raw) in files.items()}
            report = {'tracked_files': len(files), 'source_bytes': sum(len(raw) for logical, raw in files.values()),
                'source_inventory': inventory, 'graph_files': {'a': {'sha256': source.sha(b'alpha')}}}
            fd = source.write_source(bundle, files)
            raw = source.encoded(report)
            receipt, unused = family.publish_receipt(fd, raw)
            os.close(receipt); os.chmod(bundle / 'source-receipt.json', mode)
            os.fchmod(fd, 0o555); os.close(fd)
            evidence_dir = root / 'test-evidence'; evidence_dir.mkdir()
            results, proofs = [], []
            targets = (['//tools:codex_native_siwc_catalog_content_source_test',
                '//tools:codex_native_siwc_catalog_content_source_producer'] if model_proof else family.parent_guard.ARGUMENTS[1:])
            profile = 'native-siwc-catalog-content-source-reserved' if model_proof else family.parent_guard.PROFILE
            repository_name = 'omux_native_siwc_catalog_model_inputs' if model_proof else intake.REPOSITORY
            input_kind = 'omux-native-siwc-catalog-model-input-v1' if model_proof else intake.INPUT_KIND
            for index, target in enumerate(targets):
                entries = []
                for role in ('test.log', 'test.xml'):
                    body = ('public evidence ' + str(index) + role).encode()
                    digest = source.sha(body); name = digest + '.evidence'
                    leaf = evidence_dir / name; leaf.write_bytes(body); leaf.chmod(0o600); proofs.append(leaf)
                    entries.append({'source': role, 'state': 'copied', 'file': name, 'sha256': digest, 'bytes': len(body)})
                results.append({'target': target, 'state': 'observed', 'files': entries})
            index_raw = source.encoded({'schema': 1, 'targets': targets, 'results': results})
            index_path = root / 'test-evidence.json'; index_path.write_bytes(index_raw); index_path.chmod(0o600)
            outer_raw = source.encoded({'profile': profile, 'targets': targets,
                'exit': 0, 'workload_exit': 0, 'test_evidence': {'sha256': source.sha(index_raw)}})
            outer_path = root / 'receipt.json'; outer_path.write_bytes(outer_raw); outer_path.chmod(0o600)
            proofs = [outer_path, index_path] + proofs
            selected = {'root': str(bundle), 'receipt_sha256': source.sha(raw), 'receipt_bytes': len(raw),
                'inventory_sha256': source.sha(source.canonical(inventory)),
                'producer': {'receipt': str(outer_path), 'sha256': source.sha(outer_raw),
                    'source_commit': 'a' * 40, 'graph_sha256': 'b' * 64}}
            repository = root / 'external' / repository_name
            aliases = repository / 'input'
            aliases.mkdir(parents=True)
            paths = ([str(bundle / 'source-receipt.json')] + [str(bundle / 'source' / name) for name in sorted(files)]
                + [str(path) for path in proofs] + ([str(root / 'outside')] if extra else []))
            rows = []
            for index, path in enumerate(paths):
                alias = 'input/' + str(index)
                (repository / alias).symlink_to(path)
                rows.append({'path': path, 'alias': alias})
            (repository / 'source-inputs.json').write_bytes(source.encoded(
                {'kind': input_kind, 'selection': selected, 'inputs': rows}))
            (repository / 'source-inputs.json').chmod(declaration_mode)
            runfiles = root / 'runfiles'; runfiles.mkdir()
            (runfiles / repository_name).symlink_to(repository, target_is_directory=True)
            try: yield root, bundle, runfiles, selected, report, files
            finally:
                for path in (bundle, bundle / 'source', bundle / 'source/d'):
                    if path.exists(): os.chmod(path, 0o700)

    def owners(self, stack, runfiles, selected):
        inputs = stack.enter_context(intake.Inputs(runfiles, [['_main', intake.REPOSITORY, intake.REPOSITORY]]))
        return inputs, inputs.hold_source(selected)

    def test_real_capture_preserves_all_logical_modes_bytes_links_and_original_witnesses(self):
        for mode in (0o444, 0o555):
            with self.fixture(mode) as (root, bundle, runfiles, selected, report, expected), ExitStack() as stack:
                inputs, captured = self.owners(stack, runfiles, selected)
                files, members, parents = intake.capture_files(report, inputs, captured)
                self.assertEqual(dict(files), expected)
                physical_members = {'source/' + name: value for name, value in files.items()}
                physical_members['source-receipt.json'] = ('100644', captured.raw)
                tree = tenth.TreeWitness(bundle, physical_members, receipt_name='source-receipt.json' if mode == 0o444 else None)
                stack.callback(tree.close)
                self.assertTrue(all(tree.members[name] == value for name, value in members.items()))
                self.assertTrue(all(tree.members[name][0] == value for name, value in parents.items()))
                captured.accept(report, files); tree.check(); inputs.check_all()

    def test_wrong_member_digest_count_total_or_graph_refuses_actual_capture(self):
        with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
            inputs, captured = self.owners(stack, runfiles, selected)
            variants = []
            for field, value in (('tracked_files', 4), ('source_bytes', report['source_bytes'] + 1)):
                bad = copy.deepcopy(report); bad[field] = value; variants.append(bad)
            bad = copy.deepcopy(report); bad['source_inventory']['a']['sha256'] = 'a' * 64; variants.append(bad)
            bad = copy.deepcopy(report); bad['graph_files']['a']['sha256'] = 'a' * 64; variants.append(bad)
            for bad in variants:
                with self.assertRaises(ValueError): intake.capture_files(bad, inputs, captured)

    def test_tiny_receipt_never_passes_production_N10_identity_validation(self):
        with self.fixture() as (unused, bundle, unused_runfiles, selected, report, unused_files):
            with self.assertRaises((ValueError, KeyError)):
                intake.validate_report((bundle / 'source-receipt.json').read_bytes(), selected)
            changed = {**selected, 'receipt_sha256': 'a' * 64}
            with self.assertRaises(ValueError):
                intake.validate_report((bundle / 'source-receipt.json').read_bytes(), changed)

    def test_readonly_member_and_internal_literal_alias_are_required(self):
        for fault in ('writable', 'external-link', 'alias-retarget'):
            with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
                inputs, captured = self.owners(stack, runfiles, selected)
                if fault == 'writable': os.chmod(bundle / 'source/a', 0o644)
                elif fault == 'external-link':
                    os.chmod(bundle / 'source/d', 0o700)
                    (bundle / 'source/d/link').unlink(); (bundle / 'source/d/link').symlink_to(root / 'outside')
                    os.chmod(bundle / 'source/d', 0o555)
                else:
                    alias = inputs.rows[str(bundle / 'source/a')]
                    alias.unlink(); alias.symlink_to(bundle / 'source/d/b')
                with self.assertRaises((ValueError, OSError)): intake.capture_files(report, inputs, captured)

    def test_member_open_exhaustion_drains_registered_parent_without_quota_change(self):
        with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
            inputs, captured = self.owners(stack, runfiles, selected)
            baseline = set(os.listdir('/proc/self/fd'))
            original = os.open
            def limited(name, *args, **kwargs):
                if name == 'a' and kwargs.get('dir_fd') is not None: raise OSError(errno.EMFILE, 'fixture')
                return original(name, *args, **kwargs)
            with patch.object(intake.os, 'open', side_effect=limited):
                with self.assertRaises(OSError): intake.capture_files(report, inputs, captured)
            self.assertEqual(set(os.listdir('/proc/self/fd')), baseline)

    def test_first_held_fstat_failure_still_closes_both_new_capture_descriptors(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'control'; path.write_bytes(b'public'); path.chmod(0o444)
            inputs = object.__new__(intake.Inputs); inputs.stack = ExitStack(); inputs.held = {}
            opened = []; original_open, original_fstat = os.open, os.fstat
            def record(*args, **kwargs):
                fd = original_open(*args, **kwargs); opened.append((fd, args[0])); return fd
            def fail(fd):
                if opened and fd == opened[-1][0] and opened[-1][1] == path.name:
                    raise OSError(errno.EIO, 'fixture')
                return original_fstat(fd)
            try:
                with patch.object(intake.os, 'open', side_effect=record), patch.object(intake.os, 'fstat', side_effect=fail):
                    with self.assertRaises(OSError): inputs._capture(path, 64)
            finally: inputs.close()
            self.assertTrue(opened)
            for fd in {fd for fd, unused_name in opened}:
                with self.assertRaises(OSError): original_fstat(fd)

    def test_content_source_first_close_error_retires_and_attempts_all_three_real_fds(self):
        owner = object.__new__(intake.ContentSource)
        owned = [os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC) for unused in range(3)]
        owner.receipt, owner.tree, owner.held = owned
        original, called = os.close, []
        def close(fd):
            called.append(fd); original(fd)
            if fd == owned[0]: raise OSError(errno.EIO, 'fixture')
        with patch.object(intake.os, 'close', side_effect=close):
            with self.assertRaises(OSError): owner.__exit__(None, None, None)
        self.assertEqual(called, owned)
        self.assertEqual((owner.receipt, owner.tree, owner.held), (None, None, None))
        for fd in owned:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_source_intake_avoids_old_ancestry_and_keeps_original_source_fds_after_context(self):
        # Only original guardian/receipt identity are seams. Full actual tiny
        # Inputs, content bytes, nine-field tree and retained owner are real.
        with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
            inputs = stack.enter_context(intake.Inputs(runfiles, [['_main', intake.REPOSITORY, intake.REPOSITORY]]))
            trees = []; stack.callback(lambda: [tree.close() for tree in trees])
            required = {str(bundle / 'source-receipt.json')}
            with patch.object(intake, 'configuration', return_value=(b'fixture', {'parent': selected})), \
                    patch.object(intake, 'validate_report', return_value=report), \
                    patch.object(family, 'guardian', side_effect=lambda *args, **kwargs:
                        ({'fixture': True}, set(required) | set(inputs.provenance_paths))), \
                    patch.object(intake.binding, 'SourceProofSession', side_effect=AssertionError('old ancestry')):
                with intake.source_intake({'parent': selected}, inputs, trees) as (owner, captured, ancestors, files, actual):
                    self.assertIs(owner, inputs); self.assertEqual(actual, report)
                    self.assertEqual(ancestors, trees); self.assertEqual(dict(files)['a'][1], b'alpha')
                    original_fds = (captured.held, captured.tree, captured.receipt)
                self.assertTrue(all(os.fstat(fd) for fd in original_fds))
                captured.recheck(); inputs.check_all(); trees[0].check()
            inputs.close()
            for fd in original_fds:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_flat_terminal_rejects_late_byte_replace_name_or_link_drift(self):
        for fault in ('inplace', 'samebyte-replace', 'extra-name', 'directory-replace', 'link-change'):
            with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
                inputs, captured = self.owners(stack, runfiles, selected)
                files, unused_members, unused_parents = intake.capture_files(report, inputs, captured)
                captured.accept(report, files)
                members = {'source/' + name: value for name, value in files.items()}
                members['source-receipt.json'] = ('100644', captured.raw)
                tree = tenth.TreeWitness(bundle, members, receipt_name='source-receipt.json'); stack.callback(tree.close)
                retained = family.MemberDirectories(); stack.callback(retained.close); retained.capture(tree)
                # Models actual mutation inside the final SDK fence/exit interval;
                # the final source phase is the real retained flat join, no hash.
                if fault == 'inplace':
                    path = bundle / 'source/a'; path.chmod(0o644); path.write_bytes(b'omega'); path.chmod(0o555)
                elif fault == 'samebyte-replace':
                    directory = bundle / 'source'; directory.chmod(0o700)
                    replacement = directory / 'next'; replacement.write_bytes(b'alpha'); replacement.chmod(0o555)
                    replacement.replace(directory / 'a'); directory.chmod(0o555)
                elif fault == 'extra-name':
                    directory = bundle / 'source'; directory.chmod(0o700)
                    (directory / 'extra').write_bytes(b'x'); directory.chmod(0o555)
                elif fault == 'directory-replace':
                    directory = bundle / 'source'; directory.chmod(0o700)
                    (directory / 'd').rename(directory / 'old-d'); (directory / 'd').mkdir(mode=0o555)
                    directory.chmod(0o555)
                    stack.callback(lambda: os.chmod(directory / 'old-d', 0o700))
                else:
                    directory = bundle / 'source/d'; directory.chmod(0o700)
                    (directory / 'link').unlink(); (directory / 'link').symlink_to('../a'); directory.chmod(0o555)
                with self.assertRaises((ValueError, OSError)): retained.terminal()

    def test_owner_private_original_proof_mode_requires_exact_selected_role(self):
        # Actual coordinator metadata0600 is historical provenance only. Every
        # refusal retires its Inputs scope; a fresh fixture models each case.
        for case in ('unadmitted', 'positive', 'source0600', 'wrongrole', 'proof0644'):
            with self.fixture(extra=case == 'wrongrole') as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
                inputs, captured = self.owners(stack, runfiles, selected)
                if case == 'unadmitted':
                    with self.assertRaises(ValueError):
                        inputs.read(root / 'receipt.json', selected['producer']['sha256'], source.DEADLINE)
                    continue
                with patch.object(intake, 'configuration', return_value=(b'fixture', {'parent': selected})):
                    inputs.admit_provenance(selected)
                self.assertEqual(len(inputs.provenance_paths), 8)
                if case == 'positive':
                    for path in inputs.provenance_paths:
                        self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)
                        raw = Path(path).read_bytes()
                        self.assertEqual(inputs.read(path, source.sha(raw), source.DEADLINE), raw)
                elif case == 'source0600':
                    (bundle / 'source/a').chmod(0o600)
                    with self.assertRaises(ValueError): intake.capture_files(report, inputs, captured)
                elif case == 'wrongrole':
                    path = root / 'outside'; path.chmod(0o600)
                    with self.assertRaises(ValueError): inputs.read(path, source.sha(path.read_bytes()), source.DEADLINE)
                else:
                    path = next(Path(path) for path in inputs.provenance_paths if Path(path).name.endswith('.evidence'))
                    path.chmod(0o644)
                    with self.assertRaises(ValueError): inputs.read(path, source.sha(path.read_bytes()), source.DEADLINE)

    def test_original_proof_bad_pin_foreign_uid_and_replaced_parent_refuse(self):
        for fault in ('badpin', 'foreignuid', 'replaced-parent', 'samebyte-replace'):
            with self.fixture() as (root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
                inputs, captured = self.owners(stack, runfiles, selected)
                with patch.object(intake, 'configuration', return_value=(b'fixture', {'parent': selected})):
                    inputs.admit_provenance(selected)
                leaf = next(Path(path) for path in inputs.provenance_paths if Path(path).name.endswith('.evidence'))
                raw = leaf.read_bytes()
                if fault == 'badpin':
                    with self.assertRaises(ValueError): inputs.read(leaf, 'a' * 64, source.DEADLINE)
                elif fault == 'foreignuid':
                    original_stat = os.stat
                    def foreign(name, *args, **kwargs):
                        row = original_stat(name, *args, **kwargs)
                        if name == leaf.name:
                            return SimpleNamespace(st_mode=row.st_mode, st_uid=row.st_uid + 1,
                                st_nlink=row.st_nlink, st_size=row.st_size)
                        return row
                    with patch.object(intake.os, 'stat', side_effect=foreign):
                        with self.assertRaises(ValueError): inputs.read(leaf, source.sha(raw), source.DEADLINE)
                elif fault == 'replaced-parent':
                    leaf.parent.rename(root / 'old-evidence'); (root / 'test-evidence').mkdir()
                    (root / 'test-evidence' / leaf.name).write_bytes(raw)
                    (root / 'test-evidence' / leaf.name).chmod(0o600)
                    with self.assertRaises((ValueError, OSError)): inputs.read(leaf, source.sha(raw), source.DEADLINE)
                else:
                    # Capture the original physical proof before modelling a
                    # late same-byte replacement. Role/alias admission alone
                    # does not establish its unopened leaf's inode witness.
                    self.assertEqual(inputs.read(leaf, source.sha(raw), source.DEADLINE), raw)
                    original_anchor = inputs.held[str(leaf)][2]
                    self.assertEqual(tenth.witness(os.fstat(inputs.held[str(leaf)][1])), original_anchor)
                    self.assertEqual(tenth.witness(leaf.stat()), original_anchor)
                    replacement = leaf.parent / 'replacement'; replacement.write_bytes(raw); replacement.chmod(0o600)
                    replacement.replace(leaf)
                    self.assertNotEqual(tenth.witness(leaf.stat()), original_anchor)
                    with self.assertRaises(ValueError): inputs.read(leaf, source.sha(raw), source.DEADLINE)

    def test_generated_control_0644_is_exact_role_and_late_drift_refuses(self):
        for fault in ('positive', 'wider-write', 'late-body', 'samebyte-replace', 'wrongrole'):
            with self.fixture(declaration_mode=0o664 if fault == 'wider-write' else 0o644) as (
                    root, bundle, runfiles, selected, report, unused), ExitStack() as stack:
                if fault == 'wider-write':
                    with self.assertRaises(ValueError): self.owners(stack, runfiles, selected)
                    continue
                inputs, captured = self.owners(stack, runfiles, selected)
                self.assertEqual(stat.S_IMODE(inputs.path.stat().st_mode), 0o644)
                inputs.check_all()
                if fault == 'positive':
                    files, unused_members, unused_parents = intake.capture_files(report, inputs, captured)
                    captured.accept(report, files); inputs.check_all()
                elif fault == 'late-body':
                    raw = inputs.path.read_bytes()
                    inputs.path.write_bytes(raw[:-1] + b' ')
                    with self.assertRaises(ValueError): inputs.check_all()
                elif fault == 'samebyte-replace':
                    replacement = inputs.path.parent / 'replacement'
                    replacement.write_bytes(inputs.raw); replacement.chmod(0o644); replacement.replace(inputs.path)
                    with self.assertRaises(ValueError): inputs.check_all()
                else:
                    with self.assertRaises(ValueError):
                        inputs._capture(bundle / 'source-receipt.json', source.MAX_METADATA, declaration=True)

    def test_original_expired_cutoff_refuses_without_capture_or_clock_reset(self):
        with self.fixture() as (unused_root, unused_bundle, runfiles, selected, report, unused_files), ExitStack() as stack:
            inputs, captured = self.owners(stack, runfiles, selected)
            original = source.DEADLINE
            source.DEADLINE = time.monotonic() - 1
            try:
                with self.assertRaises(ValueError): intake.capture_files(report, inputs, captured)
                self.assertLess(source.DEADLINE, time.monotonic())
            finally: source.DEADLINE = original

    def test_selected_content_model_proof_0600_is_exact_authenticated_role(self):
        repository = 'omux_native_siwc_catalog_model_inputs'
        for fault in ('none', 'wrongrole', 'source0600', 'proof0644', 'badpin', 'replaced-parent'):
            with self.fixture(model_proof=True, declaration_mode=0o644, extra=fault == 'wrongrole') as (root, bundle, runfiles, selected, report, files), ExitStack() as stack:
                owner = stack.enter_context(intake.ModelProofInputs(runfiles, [['_main', repository, repository]]))
                self.assertEqual(stat.S_IMODE(owner.path.stat().st_mode), 0o644)
                owner.admit_content_provenance(selected)
                self.assertEqual(len(owner.provenance_paths), 6)
                for path in owner.provenance_paths:
                    raw = Path(path).read_bytes()
                    self.assertEqual(owner.read(path, source.sha(raw), source.DEADLINE), raw)
                if fault == 'none': owner.check_all(); continue
                if fault == 'wrongrole': path = root / 'outside'; path.chmod(0o600)
                elif fault == 'source0600': path = bundle / 'source/a'; path.chmod(0o600)
                else: path = next(Path(path) for path in owner.provenance_paths if Path(path).name.endswith('.evidence'))
                raw = path.read_bytes()
                if fault == 'proof0644': path.chmod(0o644)
                elif fault == 'replaced-parent':
                    path.parent.rename(root / 'old-evidence'); (root / 'test-evidence').mkdir()
                    replacement = root / 'test-evidence' / path.name
                    replacement.write_bytes(raw); replacement.chmod(0o600)
                with self.assertRaises((ValueError, OSError)):
                    owner.read(path, 'a' * 64 if fault == 'badpin' else source.sha(raw), source.DEADLINE)

    def test_selected_model_role_cannot_admit_original_N10_or_unbound_proof(self):
        repository = 'omux_native_siwc_catalog_model_inputs'
        with self.fixture(model_proof=True, declaration_mode=0o644) as (root, bundle, runfiles, selected, report, files), ExitStack() as stack:
            owner = stack.enter_context(intake.ModelProofInputs(runfiles, [['_main', repository, repository]]))
            with self.assertRaises(ValueError):
                owner.read(root / 'receipt.json', selected['producer']['sha256'], source.DEADLINE)
            with self.assertRaises(ValueError):
                owner.admit_content_provenance({**selected, 'receipt_sha256': 'a' * 64})
        with self.fixture(model_proof=True, declaration_mode=0o644) as (root, bundle, runfiles, selected, report, files), ExitStack() as stack:
            owner = stack.enter_context(intake.ModelProofInputs(runfiles, [['_main', repository, repository]]))
            with self.assertRaises(ValueError):
                intake._authenticate_provenance(owner, selected, family.parent_guard.PROFILE, family.parent_guard.ARGUMENTS[1:])

    @contextmanager
    def carrier_fixture(self, *, report_mode=0o555, fault=None):
        import codex_native_carrier_metadata as metadata
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            epoch = root / '12345678-1234-1234-1234-123456789abc'; epoch.mkdir()
            evidence = epoch / 'test-evidence'; evidence.mkdir()
            bodies = {'test_log': b'public carrier log fixture',
                'test_xml': b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>'}
            entries, roles = [], {}
            for role, original in (('test_log', 'test.log'), ('test_xml', 'test.xml')):
                raw = bodies[role]; digest = source.sha(raw)
                leaf = evidence / (digest + '.evidence'); leaf.write_bytes(raw); leaf.chmod(0o600)
                roles[role] = {'path': str(leaf), 'sha256': digest, 'alias': metadata.PROOF_ALIASES[role]}
                entries.append({'source': original, 'state': 'copied', 'file': leaf.name, 'sha256': digest, 'bytes': len(raw)})
            index = epoch / 'test-evidence.json'
            index_raw = source.encoded({'schema': 1, 'targets': [metadata.SEAL_TARGET],
                'results': [{'target': metadata.SEAL_TARGET, 'state': 'observed', 'files': entries}]})
            index.write_bytes(index_raw); index.chmod(0o600)
            outer = epoch / 'receipt.json'; outer_raw = source.encoded({'test_evidence': {'sha256': source.sha(index_raw)}})
            outer.write_bytes(outer_raw); outer.chmod(0o600)
            report = epoch / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json'
            report.parent.mkdir(parents=True)
            report_raw = b'{"public":"program report fixture"}'; report.write_bytes(report_raw); report.chmod(report_mode)
            for role, path in (('outer_receipt', outer), ('test_evidence', index), ('program_report', report)):
                roles[role] = {'path': str(path), 'sha256': source.sha(path.read_bytes()), 'alias': metadata.PROOF_ALIASES[role]}
            selected = {'qualification': {'producer': {'receipt': str(outer), 'sha256': source.sha(outer_raw)},
                'report': {'path': str(report), 'sha256': source.sha(report_raw)}}}
            if fault == 'wrongrole': roles['outer_receipt'] = {**roles['outer_receipt'], 'path': roles['test_log']['path']}
            elif fault == 'source-role': selected['qualification']['report']['path'] = str(epoch / 'source.rs')
            repository = root / 'external' / metadata.PROOF_REPOSITORY
            (repository / 'proof').mkdir(parents=True)
            for row in roles.values(): (repository / row['alias']).symlink_to(row['path'])
            doc = repository / 'proof-inputs.json'; doc.write_bytes(source.encoded({'kind': metadata.PROOF_KIND, 'proofs': roles})); doc.chmod(0o644)
            runfiles = root / 'runfiles'; runfiles.mkdir()
            (runfiles / metadata.PROOF_REPOSITORY).symlink_to(repository)
            if fault == 'badpin': outer.chmod(0o600); outer.write_bytes(b'public changed outer')
            # This uses actual declaration decoding/role paths/alias joins. The
            # original producer policy/status is deliberately NOT qualified.
            yield metadata, root, epoch, runfiles, repository, selected, roles

    def test_actual_carrier_proof_roles_accept_only_current_pinned_owner600_and_readonly_bytes(self):
        for mode in (0o555, 0o600):
            with self.carrier_fixture(report_mode=mode) as (metadata, root, epoch, runfiles, repository, selected, roles):
                token = metadata._SCOPE.set(source.DEADLINE)
                fds = []
                try:
                    proofs = metadata.declared_proofs(runfiles, [['_main', metadata.PROOF_REPOSITORY, metadata.PROOF_REPOSITORY]], selected, source.DEADLINE)
                    with family.HeldControls() as owner:
                        owner.add(proofs.aliases[0][0], proofs.sha256, 65536)
                        actual = owner.carrier_proofs(selected, proofs, source.DEADLINE)
                        self.assertEqual(set(actual), set(metadata.PROOF_ALIASES))
                        for role, raw in actual.items(): self.assertEqual(source.sha(raw), roles[role]['sha256'])
                        self.assertEqual(len(owner.held), 6)
                        owner.full(); proofs.recheck(source.DEADLINE)
                        fds = [fd for parent, fd, anchor, parent_anchor in owner.held.values()]
                    for fd in fds:
                        with self.assertRaises(OSError): os.fstat(fd)
                finally: metadata._SCOPE.reset(token)

    def test_actual_carrier_proof_role_bad_pin_foreign_uid_writable_or_scope_refuses(self):
        for fault in ('badpin', 'foreignuid', 'writable', 'cached-writable', 'wrongrole', 'source-role', 'foreign-cutoff'):
            with self.carrier_fixture(fault=fault) as (metadata, root, epoch, runfiles, repository, selected, roles):
                token = metadata._SCOPE.set(source.DEADLINE)
                try:
                    if fault in ('wrongrole', 'source-role'):
                        with self.assertRaises(ValueError):
                            metadata.declared_proofs(runfiles, [['_main', metadata.PROOF_REPOSITORY, metadata.PROOF_REPOSITORY]], selected, source.DEADLINE)
                        continue
                    proofs = metadata.declared_proofs(runfiles, [['_main', metadata.PROOF_REPOSITORY, metadata.PROOF_REPOSITORY]], selected, source.DEADLINE)
                    with family.HeldControls() as owner, ExitStack() as patches:
                        owner.add(proofs.aliases[0][0], proofs.sha256, 65536)
                        if fault == 'writable': (epoch / 'receipt.json').chmod(0o644)
                        elif fault == 'cached-writable':
                            path = Path(roles['program_report']['path']); path.chmod(0o644)
                            owner.add(repository / roles['program_report']['alias'], roles['program_report']['sha256'])
                        elif fault == 'foreignuid':
                            original_stat = os.stat
                            def foreign(name, *args, **kwargs):
                                row = original_stat(name, *args, **kwargs)
                                if name == 'receipt.json' and kwargs.get('dir_fd') is not None:
                                    return SimpleNamespace(st_mode=row.st_mode, st_uid=row.st_uid+1, st_nlink=row.st_nlink, st_size=row.st_size)
                                return row
                            patches.enter_context(patch.object(family.os, 'stat', side_effect=foreign))
                        with self.assertRaises(ValueError):
                            owner.carrier_proofs(selected, proofs, source.DEADLINE+1 if fault == 'foreign-cutoff' else source.DEADLINE)
                finally: metadata._SCOPE.reset(token)

    def test_actual_carrier_proof_final_alias_leaf_or_parent_drift_refuses_held_owner(self):
        for fault in ('alias', 'leaf-replace', 'parent-replace'):
            with self.carrier_fixture() as (metadata, root, epoch, runfiles, repository, selected, roles):
                token = metadata._SCOPE.set(source.DEADLINE)
                try:
                    proofs = metadata.declared_proofs(runfiles, [['_main', metadata.PROOF_REPOSITORY, metadata.PROOF_REPOSITORY]], selected, source.DEADLINE)
                    with family.HeldControls() as owner:
                        owner.add(proofs.aliases[0][0], proofs.sha256, 65536)
                        owner.carrier_proofs(selected, proofs, source.DEADLINE)
                        if fault == 'alias':
                            alias = repository / metadata.PROOF_ALIASES['outer_receipt']
                            alias.unlink(); alias.symlink_to(epoch / 'receipt.json')
                        elif fault == 'leaf-replace':
                            leaf = epoch / 'receipt.json'; replacement = epoch / 'replacement'
                            replacement.write_bytes(leaf.read_bytes()); replacement.chmod(0o600); replacement.replace(leaf)
                        else:
                            directory = epoch / 'test-evidence'; directory.rename(epoch / 'old-evidence'); directory.mkdir()
                            for original in (epoch / 'old-evidence').iterdir():
                                leaf = directory / original.name; leaf.write_bytes(original.read_bytes()); leaf.chmod(0o600)
                        with self.assertRaises(ValueError): owner.fence()
                finally: metadata._SCOPE.reset(token)

    def test_default_control_and_source_owner600_remain_refused_after_carrier_role_addition(self):
        with tempfile.TemporaryDirectory() as temporary:
            leaf = Path(temporary) / 'ordinary-control'; leaf.write_bytes(b'public ordinary control'); leaf.chmod(0o600)
            with family.HeldControls() as owner:
                with self.assertRaises(ValueError): owner.add(leaf, source.sha(leaf.read_bytes()))
        with self.fixture() as (root, bundle, runfiles, selected, report, files), ExitStack() as stack:
            inputs, captured = self.owners(stack, runfiles, selected)
            (bundle / 'source/a').chmod(0o600)
            with self.assertRaises(ValueError): intake.capture_files(report, inputs, captured)


if __name__ == '__main__': unittest.main()
