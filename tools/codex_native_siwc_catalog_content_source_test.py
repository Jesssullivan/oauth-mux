"""Exact native delta regressions plus content-intake ownership/API models."""
import copy
import io
import errno
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import codex_native_siwc_catalog_content_source as content
import codex_native_siwc_catalog_source_test as regression
from codex_native_n10_source_intake_test import N10ContentIntakeTests
from codex_transported_sdk_inputs_test import TransportedSDKTests


class ContentSourceTests(regression.CatalogSourceTests):
    # Seven inherited methods exercise the unchanged real V4/catalog parser,
    # native intermediate bytes, default controller and old graph declarations.
    def parent_report(self):
        record = content.intake_record()
        return {'kind': record['input_kind'], 'status': 'verified-tenth-file-writer-source-uncompiled',
            'inventory_sha256': record['input_inventory_sha256'],
            'tracked_files': record['input_members'], 'source_bytes': record['input_source_bytes'],
            'patch_sha256': record['historical_patch_sha256'],
            'patches': [{'patch_sha256': pin, 'paths': []} for pin in record['historical_patch_sha256']],
            'graph_files': {}, **{name: False for name in content.tenth.FLAGS}}

    def report(self):
        # Production original receipt qualification is not claimed by this
        # report-schema fixture. The actual fourteen-path transform is real.
        files = content.catalog.transform(self.before, self.raw, self.control)
        return content.make_report(self.parent_report(), files, content.previous.controls()[1],
            content.previous.configuration()[1])

    def test_content_report_keeps_actual_twenty_fifteen_names_and_denies_ancestor_reexecution(self):
        report = self.report()
        self.assertEqual(report['kind'], content.KIND)
        self.assertEqual(report['status'], content.STATUS)
        self.assertFalse(report['historical_ancestor_reexecution'])
        self.assertFalse(report['native_runtime_qualified'])
        self.assertEqual(report['source_intake'], content.intake_record())
        self.assertEqual(report['patch_sha256'][:10], self.parent_report()['patch_sha256'])
        self.assertEqual(len(report['patch_sha256']), 12)
        contract = report['native_test_contract']
        self.assertEqual(len(contract['core_unit_tests']) + len(contract['tui_unit_tests']) + len(contract['app_server_unit_tests']), 20)
        self.assertEqual(len(report['native_v4_test_contract']['expected']), 15)
        self.assertTrue(all(report[name] is False for name in content.previous.FALSE_FLAGS))

    def test_content_report_refuses_wrong_input_count_bytes_inventory_or_history(self):
        parent = self.parent_report()
        files = content.catalog.transform(self.before, self.raw, self.control)
        variants = [{**parent, 'tracked_files': 1}, {**parent, 'source_bytes': 1},
            {**parent, 'inventory_sha256': 'a' * 64}, {**parent, 'patch_sha256': ['a' * 64] * 10}]
        for value in variants:
            with self.assertRaises(ValueError):
                content.make_report(value, files, content.previous.controls()[1], content.previous.configuration()[1])

    def test_method_join_refuses_missing_or_promoted_observations(self):
        report = self.report()
        variants = [{**report, 'kind': content.catalog.KIND},
            {**report, 'historical_ancestor_reexecution': True}, {**report, 'native_runtime_qualified': True}]
        for key, value in (('method', 'receipt-only'), ('selector_sha256', 'a' * 64), ('input_members', 1),
                ('historical_ancestor_reexecution', True), ('native_runtime_qualified', True)):
            changed = copy.deepcopy(report); changed['source_intake'][key] = value; variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError): content.validate_report_method(changed)

    def test_named_content_entry_uses_existing_lifetime_with_actual_intake_factory(self):
        with patch.object(content.previous, 'main') as run:
            content.main()
        self.assertIs(run.call_args.kwargs['_producer'], content.produce)
        self.assertIs(run.call_args.kwargs['_input_factory'], content.intake.Inputs)
        self.assertIs(run.call_args.kwargs['_sdk_factory'], content.transported.open_sdk)
        self.assertIs(run.call_args.kwargs['_retainer'], content.retain_controls)
        self.assertEqual(run.call_args.kwargs['_output'], content.OUTPUT)
        with patch.object(content.previous, 'produce') as run:
            content.produce('output', 'inputs', 'work', 'publication')
        self.assertIs(run.call_args.kwargs['_source_intake'], content.intake.source_intake)
        self.assertIs(run.call_args.kwargs['_transform'], content.catalog.compose)
        self.assertIs(run.call_args.kwargs['_report'], content.make_report)
        self.assertIs(run.call_args.kwargs['_regenerator'], content.transported.regenerate)
        self.assertIs(run.call_args.kwargs['_sdk_record'], content.transported.record)

    def test_retainer_captures_selector_and_static_sdk_lineage_controls(self):
        captures = []
        raw, unused = content.intake.configuration()
        class Owner:
            def add(self, path, digest=None, maximum=None):
                captures.append((path, digest, maximum))
                return raw
        with patch.object(content.catalog, 'retain_controls', return_value=('config', 'control')):
            self.assertEqual(content.retain_controls(Owner()), ('config', 'control'))
        self.assertEqual(captures[0][1], content.intake.CONFIG_SHA)
        self.assertEqual({path.name for path, digest, maximum in captures},
            {'native-n10-content-input.json', 'native-acquisition-inputs.json', 'native-acquisition-n9-binding.json'})
        self.assertEqual(captures[-1][1], content.binding.N9_WITNESS_SHA)

    def test_actual_entrypoint_redacts_sensitive_exception_fields_and_keeps_exit_one(self):
        canary = 'TEST-ONLY-sensitive-diagnostic-canary'
        class SensitiveValueError(ValueError):
            def __str__(self): raise AssertionError('exception text accessed')
            def __repr__(self): raise AssertionError('exception repr accessed')
        class SensitiveOSError(OSError):
            def __getattribute__(self, name):
                if name in ('args', 'errno', 'filename', 'filename2', 'strerror'):
                    raise AssertionError('exception payload attribute accessed')
                return super().__getattribute__(name)
            def __str__(self): raise AssertionError('OS exception text accessed')
            def __repr__(self): raise AssertionError('OS exception repr accessed')
        failures = ((SensitiveValueError(canary), 'ValueError', 0), (KeyError(canary), 'KeyError', 0),
            (TypeError(canary), 'TypeError', 0), (UnicodeError(canary), 'UnicodeError', 0),
            (IndexError(canary), 'IndexError', 0),
            (SensitiveOSError(errno.EACCES, canary, canary), 'OSError', errno.EACCES),
            (OSError(65534, canary, canary), 'OSError', 0))
        for error, category, number in failures:
            error.account_payload = error.token_payload = canary
            error.__cause__ = ValueError(canary); error.__context__ = OSError(canary)
            def fail(): raise error
            stderr, stdout = io.StringIO(), io.StringIO()
            with patch.object(content, 'main', fail), patch('sys.stderr', stderr), patch('sys.stdout', stdout):
                with self.assertRaises(SystemExit) as caught: content.entrypoint()
            self.assertEqual(caught.exception.code, 1)
            diagnostic = stderr.getvalue()
            self.assertNotIn(canary, diagnostic)
            self.assertNotIn('SensitiveValueError', diagnostic)
            self.assertIn('; class=' + category + '; errno=' + str(number) + '; locus=', diagnostic)
            self.assertLessEqual(len(diagnostic.encode()), content.MAX_DIAGNOSTIC_BYTES)
            self.assertEqual(stdout.getvalue(), '')

    def test_actual_memory_first_cause_uses_live_trace_and_closed_redacted_exit(self):
        canary = "TEST-ONLY-memory-diagnostic-canary"
        class SensitiveMemoryError(MemoryError):
            def __str__(self): raise AssertionError("memory exception text accessed")
            def __repr__(self): raise AssertionError("memory exception repr accessed")
            def with_traceback(self,unused): raise AssertionError("dynamic traceback method accessed")
            def __getattribute__(self,name):
                if name in ("args","__traceback__","account_payload","token_payload"):
                    raise AssertionError("memory payload attribute accessed")
                return super().__getattribute__(name)
        first, cleanup = SensitiveMemoryError(canary), OSError(canary)
        first.account_payload = first.token_payload = canary
        observed, diagnostics, attempts = [], [], []
        def fail_cleanup(): attempts.append(True);raise cleanup
        def fail():
            try:
                with content.parent.carrier._ProofExitStack() as stack:
                    stack.callback(fail_cleanup)
                    raise first
            except MemoryError as error:
                observed.append(error)
                # Actual traceback is still alive here; unittest.assertRaises
                # would remove it on context exit. No fake frame is supplied.
                diagnostics.append(content.refusal_diagnostic(error))
                self.assertIs(error.__cause__,cleanup)
                raise
        stderr, stdout = io.StringIO(), io.StringIO()
        with patch.object(content,"main",fail), patch("sys.stderr",stderr), patch("sys.stdout",stdout):
            with self.assertRaises(SystemExit) as caught: content.entrypoint()
        self.assertEqual(caught.exception.code,1);self.assertEqual(observed,[first]);self.assertEqual(attempts,[True])
        self.assertIn(MemoryError,content.REFUSAL_ERRORS)
        for diagnostic in diagnostics+[stderr.getvalue()]:
            self.assertIn("; class=MemoryError; errno=0; locus=",diagnostic)
            self.assertIn("sdk-carrier:",diagnostic)
            self.assertLessEqual(len(diagnostic.encode()),content.MAX_DIAGNOSTIC_BYTES)
            for forbidden in (canary,"SensitiveMemoryError","fail_cleanup",".py"):
                self.assertNotIn(forbidden,diagnostic)
        self.assertEqual(stdout.getvalue(),"")

    def test_actual_trusted_refusal_locus_is_closed_module_role_and_bounded_line(self):
        try: content.source.require(False)
        except ValueError as error: diagnostic = content.refusal_diagnostic(error)
        locus = diagnostic.split('; locus=', 1)[1].split('; truncated=', 1)[0].split(',')
        self.assertEqual(locus[0], 'unknown:0')
        self.assertTrue(any(row.startswith('source-io:') and int(row.split(':')[1]) > 0 for row in locus))
        for row in locus:
            self.assertLessEqual(int(row.split(':')[1]), content.MAX_SOURCE_LINE)
        self.assertNotIn('require', diagnostic)
        self.assertNotIn('.py', diagnostic)

    def test_unknown_sensitive_traceback_frames_are_bounded_and_never_named(self):
        canary = 'TEST-ONLY-sensitive-traceback-canary'
        namespace = {'payload': canary, '__name__': canary, 'secret_environment': canary}
        # Real unknown traceback frames carry a sensitive filename/name/global.
        # No fake provider/source success or project parser is involved.
        exec(compile('def secret_frame(depth):\n    if depth: return secret_frame(depth - 1)\n    raise ValueError(payload)\n',
            canary, 'exec'), namespace)
        try: namespace['secret_frame'](80)
        except ValueError as error: diagnostic = content.refusal_diagnostic(error)
        rows = diagnostic.split('; locus=', 1)[1].split('; truncated=', 1)[0].split(',')
        self.assertEqual(rows, ['unknown:0'] * content.MAX_TRACE_ROWS)
        self.assertTrue(diagnostic.endswith('; truncated=1'))
        self.assertLessEqual(len(diagnostic.encode()), content.MAX_DIAGNOSTIC_BYTES)
        self.assertNotIn(canary, diagnostic); self.assertNotIn('secret_frame', diagnostic)
        self.assertNotIn('secret_environment', diagnostic)

    def test_diagnostic_io_refusal_keeps_original_exit_and_unhandled_failures_propagate(self):
        class RefusingWriter:
            def write(self, unused): raise OSError('TEST-ONLY-diagnostic-write-canary')
        with patch.object(content, 'main', side_effect=ValueError('TEST-ONLY-original-canary')), \
                patch('sys.stderr', RefusingWriter()):
            with self.assertRaises(SystemExit) as caught: content.entrypoint()
        self.assertEqual(caught.exception.code, 1)
        failure = RuntimeError('TEST-ONLY-unhandled-canary')
        with patch.object(content, 'main', side_effect=failure), patch('sys.stderr', io.StringIO()) as stderr:
            with self.assertRaises(RuntimeError) as caught: content.entrypoint()
        self.assertIs(caught.exception, failure); self.assertEqual(stderr.getvalue(), '')

    def test_actual_nested_controller_reaches_intake_child_and_final_fences_on_original_clock(self):
        # Actual wrapper -> previous.main -> actual Inputs/intake/Publication.
        # Original N10 receipt/guardian, SDK/provider/query qualification are
        # explicit seams; this does not qualify the tiny source as genuine.
        import codex_native_carrier_metadata as metadata
        fixture = N10ContentIntakeTests()
        source, family = content.source, content.parent
        old_source, old_query = source.DEADLINE, family.query.DEADLINE
        for fault in ('none', 'child-refusal'):
            with fixture.fixture(declaration_mode=0o644) as (root, bundle, runfiles, selected, report, files):
                outputs = root / 'outputs'; outputs.mkdir()
                controls_root = root / 'controls'; controls_root.mkdir()
                selector = controls_root / metadata.CONFIG
                selector.parent.mkdir(parents=True); selector.write_bytes(b'public metadata seam'); selector.chmod(0o444)
                proofs_root = root / 'sdk-proof'; proofs_root.mkdir()
                descriptor = proofs_root / 'proof-inputs.json'; descriptor.write_bytes(b'public proof seam'); descriptor.chmod(0o444)
                selection_leaf = proofs_root / 'selection.json'; selection_leaf.write_bytes(b'public carrier seam'); selection_leaf.chmod(0o444)
                declaration = {'selection_path': str(selection_leaf), 'selection_sha256': source.sha(selection_leaf.read_bytes())}
                proofs = SimpleNamespace(aliases=[(descriptor, descriptor)], sha256=source.sha(descriptor.read_bytes()),
                    document={'proofs': {}}, recheck=lambda cutoff: None, record=lambda: {'public': 'qualification seam'})
                (runfiles / '_repo_mapping').write_bytes(('_main,' + content.intake.REPOSITORY + ',' + content.intake.REPOSITORY + '\n').encode())
                (runfiles / '_repo_mapping').chmod(0o444)
                entry = time.monotonic_ns(); until = entry + 1200*10**9
                cutoff = float((entry + 600*10**9) / 10**9)
                env = {family.MODE: family.PROFILE, family.ENTRY: str(entry), family.UNTIL: str(until), 'TEST_TIMEOUT': '840',
                    'TEST_SRCDIR': str(runfiles), 'TEST_UNDECLARED_OUTPUTS_DIR': str(outputs),
                    'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab',
                    'OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT': 'a'*40, 'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256': 'b'*64}
                phases, closed_fds = [], []
                def clock(phase):
                    self.assertEqual((source.DEADLINE, family.query.DEADLINE), (cutoff, cutoff))
                    self.assertEqual(family.producer_context()['entry_monotonic_ns'], entry)
                    self.assertEqual(family.producer_context()['deadline_monotonic_ns'], until)
                    phases.append(phase)
                class SDK:
                    def __init__(self, alias, physical, carrier, pin, actual_entry, actual_until, context):
                        self_case.assertEqual((actual_entry, actual_until), (entry, until))
                        self_case.assertEqual(context, family.declaration_context(family.producer_context()))
                    def __enter__(self): clock('sdk-enter'); return self
                    def finish(self): clock('sdk-finish')
                    def fence(self): clock('sdk-fence')
                    def __exit__(self, *args): clock('sdk-close')
                self_case = self
                sdk_module = SimpleNamespace(declared_manifest=lambda *args: (root / 'manifest', root / 'manifest'), HeldOriginalSDK=SDK)
                @contextmanager
                def proof_scope(cutoff): yield
                def producer(output, inputs, work, publication, **kwargs):
                    clock('intake')
                    with content.intake.source_intake({'parent': selected}, inputs, publication.parents) as (owner, captured, trees, actual_files, actual_report):
                        self.assertIs(owner, inputs); self.assertEqual(dict(actual_files), files)
                        closed_fds.extend((captured.held, captured.tree, captured.receipt))
                        fd = source.write_source(output, actual_files)
                        raw = source.encoded({'public': 'tiny publication seam'})
                        receipt, anchor = family.publish_receipt(fd, raw)
                        before = content.tenth.witness(os.fstat(fd))
                        members = {'source/' + name: row for name, row in actual_files.items()}
                        members['source-receipt.json'] = ('100644', raw)
                        tree = content.tenth.TreeWitness(output, members, root_mode=0o700, receipt_name='source-receipt.json')
                        os.fchmod(fd, 0o555)
                        tree.accept_root_seal(before, content.tenth.witness(os.fstat(fd)))
                        publication.bind(output, fd, receipt, anchor, tree, actual_files, None, raw)
                    return {'public': 'child seam'}
                def child(published, sdk, actual_report, retained, inputs, actual_entry, actual_until, actual_cutoff):
                    clock('child')
                    self.assertEqual((actual_entry, actual_until, actual_cutoff), (entry, until, cutoff))
                    self.assertEqual(published.files, files)
                    if fault == 'child-refusal': raise ValueError('public child refusal seam')
                class Extra:
                    def full(self): clock('extra-full')
                    def evidence_full(self): clock('extra-evidence')
                    def fence(self): clock('extra-fence')
                    def short(self): clock('extra-short')
                config = (b'public config seam', {'parent': selected})
                control = (b'public controls seam', {'public': True})
                def retain(owner): return config, control
                source.DEADLINE = family.query.DEADLINE = cutoff
                try:
                    with ExitStack() as patches:
                        patches.enter_context(patch.dict(os.environ, env, clear=True))
                        patches.enter_context(patch.object(content.previous.sys, 'argv', ['native-content']))
                        patches.enter_context(patch.object(content.binding.ninth.parent, 'ROOT', controls_root))
                        patches.enter_context(patch.object(content.previous, 'configuration', return_value=config))
                        patches.enter_context(patch.object(content.previous, 'controls', return_value=control))
                        patches.enter_context(patch.object(content.intake, 'configuration', return_value=(b'fixture', {'parent': selected})))
                        patches.enter_context(patch.object(content.intake, 'validate_report', return_value=report))
                        patches.enter_context(patch.object(family, 'guardian', side_effect=lambda row, owner:
                            ({'public': 'guardian seam'}, {str(bundle / 'source-receipt.json')} | set(owner.provenance_paths))))
                        patches.enter_context(patch.object(content, 'produce', side_effect=producer))
                        # This is the existing source/clock/guardian seam, not
                        # transported SDK qualification. Real packed IO/NAR tests
                        # live in TransportedSDKTests imported above.
                        patches.enter_context(patch.object(content.transported,'open_sdk',side_effect=
                            lambda carrier,pin,actual_entry,actual_until,context,*unused:
                                SDK(root/'manifest',root/'manifest',carrier,pin,actual_entry,actual_until,context)))
                        patches.enter_context(patch.object(metadata, 'proof_scope', proof_scope))
                        patches.enter_context(patch.object(metadata, 'selection', return_value={'carrier': {'receipt_sha256': 'd'*64}}))
                        patches.enter_context(patch.object(metadata, 'declared_carrier', return_value=(root / 'carrier', (), declaration)))
                        patches.enter_context(patch.object(metadata, 'declared_proofs', return_value=proofs))
                        # Carrier-role authentication is a separate actual IO
                        # model; this SDK/guardian fixture is an explicit seam.
                        patches.enter_context(patch.object(family.HeldControls, 'carrier_proofs',
                            return_value={'test_xml': b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>'}))
                        patches.enter_context(patch.object(metadata, 'qualify_producer', return_value={'public': 'qualified seam'}))
                        patches.enter_context(patch.object(metadata, 'recheck_aliases'))
                        patches.enter_context(patch.object(family.query, 'declared_query_tools'))
                        patches.enter_context(patch('builtins.print'))
                        admitted = (entry, until, cutoff, source.encoded(family.producer_context()))
                        if fault == 'none': content.main(_child=child, _extra=Extra(), _retainer=retain, _admitted=admitted)
                        else:
                            try:
                                content.main(_child=child, _extra=Extra(), _retainer=retain, _admitted=admitted)
                            except ValueError as failure:
                                diagnostic = content.refusal_diagnostic(failure)
                            else:
                                self.fail('actual nested controller did not refuse')
                            self.assertIn('content-controller:', diagnostic)
                            self.assertIn('siwc-controller:', diagnostic)
                            self.assertNotIn('public child refusal seam', diagnostic)
                            self.assertLessEqual(len(diagnostic.encode()), content.MAX_DIAGNOSTIC_BYTES)
                        clock('driver-post-return')
                    self.assertIn('intake', phases); self.assertIn('child', phases); self.assertIn('sdk-close', phases)
                    if fault == 'none': self.assertIn('extra-short', phases); self.assertIn('sdk-finish', phases)
                    for fd in closed_fds:
                        with self.assertRaises(OSError): os.fstat(fd)
                finally:
                    # The admitted outer driver, not nested main, retires clock.
                    source.DEADLINE = family.query.DEADLINE = None
                    for directory in sorted(outputs.rglob('*'), key=lambda path: len(path.parts), reverse=True):
                        if directory.is_dir(): directory.chmod(0o700)
                    source.DEADLINE, family.query.DEADLINE = old_source, old_query


if __name__ == '__main__': unittest.main()
