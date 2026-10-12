"""One genuine maintained login-crate child inside fresh source/HUB/SDK custody."""
from contextlib import ExitStack
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import codex_native_file_writer_model_source as family
import codex_native_profile as native

source = family.source
TARGET = "//codex-rs/login:login-file-writer-storage-tests"
KIND = "omux-native-file-writer-models-v1"
MAX_LOG = 16 * 1024 * 1024


def expected_tests():
    unused, controls = family.controls()
    value = family.decode(family.pinned_artifact(controls['tests']))
    source.require(set(value) == {'schema_version', 'kind', 'status', 'target', 'summary', 'expected'}
        and value['schema_version'] == 1 and value['kind'] == 'omux-native-file-writer-model-exact-tests-v1'
        and value['target'] == TARGET and value['status'] == 'DECLARED-UNRUN'
        and value['summary'] == {'passed': 19, 'failed': 0, 'ignored': 0}
        and type(value['expected']) is list and len(value['expected']) == 19
        and len(set(value['expected'])) == 19 and all(type(name) is str and
            re.fullmatch(r'auth::storage::tests::managed_file_writer_models::[A-Za-z0-9_]{1,256}', name)
            is not None for name in value['expected']))
    return tuple(value['expected'])


def accept_log(raw, expected):
    source.require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG and len(expected) == 19 and len(set(expected)) == 19)
    rows = re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)\r?$', raw, re.MULTILINE)
    source.require(len(rows) == 19 and len({name for name, unused in rows}) == 19
        and {name.decode('ascii') for name, unused in rows} == set(expected)
        and all(result == b'ok' for unused, result in rows))
    runs = re.findall(rb'^running ([0-9]+) tests\r?$', raw, re.MULTILINE)
    source.require(runs == [b'19'])
    summaries = re.findall(rb'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9]+(?:[.][0-9]+)?s\r?$', raw, re.MULTILINE)
    source.require(len(summaries) == 1 and summaries[0][:5] == (b'ok', b'19', b'0', b'0', b'0'))
    return {'tests': list(expected), 'passed': 19, 'failed': 0, 'ignored': 0,
        'filtered_out': int(summaries[0][5]), 'log_sha256': source.sha(raw), 'log_bytes': len(raw)}


def project_hub(plan, mapping, hub, original_root):
    """Closed one-token transformation; all original argv policy remains exact."""
    source.require(type(plan) is dict and type(mapping) is dict and family.binding.metadata.HUB in mapping['repositories'])
    name = family.binding.metadata.HUB
    original = str(Path(original_root) / 'repositories' / name)
    source.require(mapping['repositories'][name] == original and Path(hub).is_absolute())
    token = '--override_repository=' + name + '=' + original
    source.require(plan['argv'].count(token) == 1)
    result = {**plan, 'argv': list(plan['argv']), 'environment': dict(plan['environment'])}
    index = result['argv'].index(token)
    result['argv'][index] = '--override_repository=' + name + '=' + str(hub)
    source.require([i for i, (before, after) in enumerate(zip(plan['argv'], result['argv'])) if before != after] == [index])
    return result


def native_plan(published, sdk, report, work, cutoff):
    source.require(not work.exists() and report['kind'] == family.KIND and len(report['patch_sha256']) == 11
        and all(report[name] is False for name in family.FALSE_FLAGS) and published.active)
    sdk.check(); published.full()
    source.require(report['generated_hub'] == {name: {'sha256': source.sha(raw), 'bytes': len(raw)}
        for name, raw in sorted(published.hub.items())})
    mapping = sdk.mapping()
    tools = family.query_tools.verify_repository(family.query.QUERY_REPOSITORY, cutoff)
    source.require(tools['status'] == 'declared-fixed-query-tools-byte-qualified' and tools['inputs_rechecked'] is True)
    work.mkdir(mode=0o700)
    candidate = SimpleNamespace(source=published.path / 'source', root=work,
        lease=SimpleNamespace(output_base=work / 'output-base'))
    args = SimpleNamespace(native_export_root=family.query.EXPORT_ROOT, native_mode='file-writer-models')
    # The hashed maintained wrapper supplies exact nineteen libtest filters.
    # No umbrella filter/extra argv is used to fabricate executed coverage.
    plan = native.command_from_verified_inputs(args, work, family.query.LOCKED_PATH,
        tools['query_tools']['tools']['bash'], candidate, (report, mapping),
        {'file-writer-models': ('test', (TARGET,), '')}, gates=None)
    original = list(plan['argv'])
    plan = project_hub(plan, mapping, published.path / 'hub/source', family.query.EXPORT_ROOT)
    remaining = math.floor(cutoff - time.monotonic() - 90)
    source.require(remaining > 0 and plan['argv'][-1] == TARGET
        and plan['argv'].count('--test_timeout=1200') == 1 and not any(token.startswith('--test_arg=') for token in plan['argv']))
    plan['argv'] = [('--test_timeout=' + str(remaining)) if token == '--test_timeout=1200' else token for token in plan['argv']]
    plan['environment']['CARGO_NET_OFFLINE'] = 'true'
    plan['argv'].insert(plan['argv'].index('test') + 1, '--repo_env=CARGO_NET_OFFLINE=true')
    source.require(tools['query_tools']['tools']['bazel'] == native.BAZEL == family.query.BAZEL)
    plan['qualified_query_tools'] = tools
    plan['original_mapping'] = mapping
    plan['original_argv_sha256'] = source.sha(source.canonical(original))
    plan['projected_hub'] = {'root': str(published.path / 'hub/source'), 'files': report['generated_hub']}
    source.require(family.query_tools.verify_repository(family.query.QUERY_REPOSITORY, cutoff) == tools)
    return plan


class ChildStreams:
    """Owned original stdout/stderr writer FDs survive sealing and readback."""
    def __init__(self, root):
        self.path = root
        self.fds, self.anchors = {}, {}
        self.parent = None
        try:
            root.mkdir(mode=0o700)
            self.parent = source.directory(root)
            for name in ('stdout', 'stderr'):
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
                self.fds[name] = fd
                source.require(stat.S_ISREG(os.fstat(fd).st_mode))
            self.root_anchor = family.tenth.witness(os.fstat(self.parent))
        except BaseException:
            self.close(); raise

    def seal(self):
        for name, fd in self.fds.items():
            source.tick(); os.fsync(fd); os.fchmod(fd, 0o444)
            self.anchors[name] = family.tenth.witness(os.fstat(fd))
            source.require(self.anchors[name] == family.tenth.witness(os.stat(name, dir_fd=self.parent, follow_symlinks=False)))
        os.fsync(self.parent)

    def fence(self):
        source.tick()
        source.require(family.tenth.witness(os.fstat(self.parent)) == self.root_anchor)
        named = source.directory(self.path)
        try: source.require(family.tenth.witness(os.fstat(named)) == self.root_anchor)
        finally: os.close(named)
        family.tenth.exact_names(self.parent, {'stdout', 'stderr'})
        for name, anchor in self.anchors.items():
            source.require(family.tenth.witness(os.fstat(self.fds[name])) == anchor == family.tenth.witness(
                os.stat(name, dir_fd=self.parent, follow_symlinks=False)))

    def bytes(self, name):
        self.fence()
        source.require(name in self.anchors)
        raw, mode = source.read(self.parent, name, MAX_LOG)
        source.require(mode == 0o444 and family.tenth.witness(os.fstat(self.fds[name])) == self.anchors[name]
            == family.tenth.witness(os.stat(name, dir_fd=self.parent, follow_symlinks=False)))
        return raw

    def close(self):
        first = None
        retired, self.fds = list(self.fds.values()), {}
        if self.parent is not None: retired.append(self.parent); self.parent = None
        for fd in reversed(retired):
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


def run_once(plan, streams, cutoff):
    source.require(cutoff == source.DEADLINE and cutoff - time.monotonic() > 90)
    child, error = None, None
    try:
        child = subprocess.Popen(plan['argv'], cwd=plan['cwd'], env=plan['environment'],
            stdin=subprocess.DEVNULL, stdout=streams.fds['stdout'], stderr=streams.fds['stderr'], close_fds=True)
        while child.poll() is None:
            source.require(time.monotonic() < cutoff - 90 and all(os.fstat(fd).st_size <= MAX_LOG for fd in streams.fds.values()))
            time.sleep(min(0.05, max(0, cutoff - 90 - time.monotonic())))
        source.require(type(child.returncode) is int and child.returncode == 0)
        source.require(all(os.fstat(fd).st_size <= MAX_LOG for fd in streams.fds.values()))
        streams.seal()
    except BaseException as failure: error = failure
    finally:
        alive = False
        if child is not None:
            try: alive = child.poll() is None
            except BaseException as failure:
                alive = True
                if error is None: error = failure
            if alive:
                try: child.kill()
                except BaseException as failure:
                    if error is None: error = failure
                try: child.wait(timeout=max(0.001, min(15, cutoff - time.monotonic())))
                except BaseException as failure:
                    if error is None: error = failure
    if error is not None: raise error


def actual_test_directory(output_base):
    root = output_base / 'execroot/_main/bazel-out'
    fd = source.directory(root)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                source.tick(); source.require(len(names) < 64)
                names.append(entry.name)
        selected = [name for name in names if re.fullmatch(r'[A-Za-z0-9_.-]+-opt', name)]
        source.require(len(selected) == 1)
        return root / selected[0] / 'testlogs/codex-rs/login/login-file-writer-storage-tests'
    finally: os.close(fd)


def read_actual(path, owner):
    """Retain the exact named role, parent and captured physical leaf together."""
    path = Path(path)
    source.require(path.is_absolute() and path.name in ('test.log', 'test.xml'))
    # Every component of the fixed output-role parent is opened nofollow.
    # A whole target-directory redirect is not an admitted alias mapping.
    parent = source.directory(path.parent)
    try:
        anchor = family.tenth.witness(os.fstat(parent))
        physical = path.resolve(strict=True)
        source.require(physical.parent == path.parent)
        raw = owner.add(path, maximum=MAX_LOG)
        source.require(owner.aliases[-1][0] == path and owner.aliases[-1][1] == physical
            and owner.aliases[-1][4] == anchor
            and family.tenth.witness(os.fstat(parent)) == anchor)
        named = source.directory(path.parent)
        try: source.require(family.tenth.witness(os.fstat(named)) == anchor)
        finally: os.close(named)
        owner.fence()
        return raw, physical
    finally: os.close(parent)


def publish_result(path, report, owner, *, prepared=None, evidence=None, _evidence_names=None):
    """Join original owned directory/writers; retain bounded child evidence."""
    if prepared is None:
        path.mkdir(mode=0o700)
        parent, initial = source.directory(path), None
    else:
        parent, initial = prepared
    writers, error, result = [], None, None
    close_parent = prepared is None
    try:
        if initial is not None:
            source.require(family.tenth.witness(os.fstat(parent)) == initial)
            named = source.directory(path)
            try: source.require(family.tenth.witness(os.fstat(named)) == initial)
            finally: os.close(named)
        family.tenth.exact_names(parent, set())
        raw = source.encoded(report)
        source.require(0 < len(raw) <= source.MAX_METADATA)
        evidence = {} if evidence is None else evidence
        evidence_names = {'native-test.log', 'native-test.xml', 'native-stdout.log', 'native-stderr.log'} if _evidence_names is None else set(_evidence_names)
        source.require(0 < len(evidence_names) <= 10 and all(type(name) is str and re.fullmatch(r'[a-z-]+[.](log|xml)', name) is not None for name in evidence_names)
            and type(evidence) is dict and (not evidence or set(evidence) == evidence_names))
        bodies = {**evidence, 'models-receipt.json': raw}
        anchors = {}
        for name, body in bodies.items():
            source.require(type(body) is bytes and len(body) <= (source.MAX_METADATA if name == 'models-receipt.json' else MAX_LOG))
            writer = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            writers.append(writer)  # enrollment precedes the first writer fstat
            pending = memoryview(body)
            while pending:
                source.tick(); count = os.write(writer, pending); source.require(count > 0); pending = pending[count:]
            os.fchmod(writer, 0o444); os.fsync(writer)
            anchor = family.tenth.witness(os.fstat(writer)); anchors[name] = (writer, anchor)
            source.require(family.tenth.witness(os.stat(name, dir_fd=parent, follow_symlinks=False)) == anchor)
        os.fchmod(parent, 0o555); os.fsync(parent)
        root_anchor = family.tenth.witness(os.fstat(parent))
        for name, body in bodies.items():
            file = path / name
            if body:
                source.require(owner.add(file, source.sha(body), len(body)) == body
                    and owner.held[str(file)][2] == anchors[name][1])
            else:
                owner.add_alias(file, file)
                source.require(owner.aliases[-1][5] == anchors[name][1])
        family.tenth.exact_names(parent, set(bodies))
        for name, (writer, anchor) in anchors.items():
            source.require(family.tenth.witness(os.fstat(writer)) == anchor == family.tenth.witness(
                os.stat(name, dir_fd=parent, follow_symlinks=False)))
        source.require(family.tenth.witness(os.fstat(parent)) == root_anchor)
        named = source.directory(path)
        try: source.require(family.tenth.witness(os.fstat(named)) == root_anchor)
        finally: os.close(named)
        result = {'path': str(path / 'models-receipt.json'), 'sha256': source.sha(raw), 'bytes': len(raw)}
    except BaseException as failure: error = failure
    finally:
        retired = list(reversed(writers)) + ([parent] if close_parent else [])
        for fd in retired:
            try: os.close(fd)
            except BaseException as failure:
                if error is None: error = failure
    if error is not None: raise error
    return result


def native_child(published, sdk, report, retained, inputs, entry, until, cutoff, _phase=None):
    def phase(name):
        if _phase is not None: _phase(name)
    phase('child-admission')
    source.require(cutoff == source.DEADLINE and time.monotonic_ns() < entry + 600*10**9)
    inputs.check_all(); retained.full(); sdk.fence(); published.fence()
    temporary = Path(os.environ['TEST_TMPDIR']).resolve(strict=True)
    held_temporary = source.directory(temporary)
    try: source.require(os.fstat(held_temporary).st_uid == os.getuid())
    finally: os.close(held_temporary)
    work = temporary / 'model-native-work'
    phase('child-plan')
    plan = native_plan(published, sdk, report, work, cutoff)
    source.require(family.producer_context() == report['producer_context'])
    expected = expected_tests()
    phase('child-streams')
    streams = ChildStreams(work / 'driver-streams')
    result_parent = published.path.parent / 'native-file-writer-models'
    result_fd = None
    try:
        phase('child-output-setup')
        result_parent.mkdir(mode=0o700)
        result_fd = source.directory(result_parent)
        result_anchor = family.tenth.witness(os.fstat(result_fd))
        # Allocate every global output child before retaining directory anchors.
        # The actual child is preceded by the same-held original SDK bulk sweep
        # and a flat authenticated SOURCE/output member observation.
        phase('child-preflight')
        published.capture()
        inputs.check_all(); retained.full(); published.fence(); sdk.fence()
        retained.fence(); inputs.check(); published.terminal()
        phase('child-run')
        run_once(plan, streams, cutoff)
        phase('child-evidence')
        output = actual_test_directory(work / 'output-base')
        raw_log, log_physical = read_actual(output / 'test.log', retained)
        raw_xml, xml_physical = read_actual(output / 'test.xml', retained)
        phase('child-acceptance')
        family.material.declared_xml_success(raw_xml)
        accepted = accept_log(raw_log, expected)
        source.require(family.query_tools.verify_repository(family.query.QUERY_REPOSITORY, cutoff) == plan['qualified_query_tools'])
        stream_rows, evidence = {}, {'native-test.log': raw_log, 'native-test.xml': raw_xml}
        for name in ('stdout', 'stderr'):
            raw = streams.bytes(name)
            row = {'path': str(streams.path / name), 'sha256': source.sha(raw), 'bytes': len(raw)}
            # Empty stderr is valid. HeldControls is metadata-positive-only, so
            # retain nonempty streams and keep the original stream writer owner.
            if raw: retained.add(streams.path / name, row['sha256'], MAX_LOG)
            retained.add_alias(streams.path / name, streams.path / name)
            source.require(retained.aliases[-1][5] == streams.anchors[name])
            stream_rows[name] = row
            evidence['native-' + name + '.log'] = raw
        result = {'schema_version': 1, 'kind': KIND, 'status': 'executed-maintained-storage-models-test-only',
            'target': TARGET, 'producer_context': report['producer_context'],
            'original_entry_monotonic_ns': entry, 'original_outer_deadline_monotonic_ns': until,
            'original_proof_deadline_monotonic_ns': entry + 600*10**9,
            'source': {'receipt_path': str(published.path / 'source-receipt.json'), 'receipt_sha256': source.sha(published.raw),
                'inventory_sha256': report['inventory_sha256'], 'patch_sha256': report['patch_sha256'], 'graph_files': report['graph_files']},
            'generated_hub': report['generated_hub'], 'original_sdk': report['original_sdk'],
            'sdk_input_qualification': report['sdk_input_qualification'],
            'plan': plan, 'stdout_stderr': stream_rows,
            'test_log': {'path': str(log_physical), 'alias': str(output / 'test.log'), 'sha256': source.sha(raw_log), 'bytes': len(raw_log)},
            'test_xml': {'path': str(xml_physical), 'alias': str(output / 'test.xml'), 'sha256': source.sha(raw_xml), 'bytes': len(raw_xml)},
            'retained_evidence': {name: {'path': str(result_parent / name), 'sha256': source.sha(raw), 'bytes': len(raw)}
                for name, raw in evidence.items()},
            'actual_libtest': accepted, 'storage_models_compiled': True, 'storage_models_passed': True,
            'default_login_regression_passed': False, 'native_compiled': False, 'ordinary_native_qualified': False,
            'issuer_qualified': False, 'scheduler_qualified': False, 'provider_qualified': False}
        phase('child-publication')
        row = publish_result(result_parent, result, retained, prepared=(result_fd, result_anchor), evidence=evidence)
        phase('child-final-fences')
        inputs.check_all(); retained.full(); sdk.fence(); published.fence(); streams.fence()
        phase('child-close')
        return row
    finally:
        first = None
        for cleanup in (streams.close, (lambda: os.close(result_fd)) if result_fd is not None else (lambda: None)):
            try: cleanup()
            except BaseException as failure:
                if first is None: first = failure
        if first is not None: raise first


CHILD_PHASES = frozenset((
    'child-admission',
    'child-plan',
    'child-streams',
    'child-output-setup',
    'child-preflight',
    'child-run',
    'child-evidence',
    'child-acceptance',
    'child-publication',
    'child-final-fences',
    'child-close',
))
REFUSAL_ERRORS = (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError, subprocess.SubprocessError)


def refusal_category(error):
    # Ordered closed types only: never format exception messages or attributes.
    for kind, category in ((UnicodeError, 'unicode'), (ValueError, 'invariant'),
            (OSError, 'os'), (KeyError, 'key'), (TypeError, 'type'),
            (IndexError, 'index'), (subprocess.SubprocessError, 'subprocess')):
        if isinstance(error, kind): return category
    return 'unclassified'


def main():
    current = 'driver-admission'
    def phase(name):
        nonlocal current
        source.require(type(name) is str and name in family.SOURCE_PHASES | CHILD_PHASES)
        current = name
    try:
        source.require(sys.argv == [sys.argv[0]])
        result, envelope = [], []
        def execute(*arguments):
            envelope.append((arguments[5], arguments[6]))
            result.append(native_child(*arguments, _phase=phase))
        family.main(execute, _phase=phase)
        current = 'driver-final-acceptance'
        source.require(len(result) == len(envelope) == 1)
        entry, until = envelope[0]
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
        print('native-file-writer-models: actual maintained login storage tests 19 passed; 0 failed; 0 ignored', flush=True)
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
    except REFUSAL_ERRORS as error:
        try:
            print('native file-writer models refused; phase=' + current + '; category=' + refusal_category(error), file=sys.stderr)
        finally:
            # Diagnostic IO cannot replace the original refusal or cleanup exit.
            raise error from None


if __name__ == '__main__':
    try: main()
    except REFUSAL_ERRORS:
        raise SystemExit(1) from None
