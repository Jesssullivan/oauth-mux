"""Private per-epoch copies of selected Bazel test evidence before cache reuse.

Caller supplies verified owned output/run directories and the wall-clock epoch
admission time. Missing, stale, unsupported and failed copies stay explicit;
files alone never turn a failed Bazel invocation into a passing proof.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 256
FILES = ('test.log', 'test.xml', 'test.outputs_manifest/MANIFEST',
         'test.outputs_manifest/ANNOTATIONS')
# Preserve only the two metadata outputs of this exact declared producer. Do
# not traverse arbitrary test outputs, archive payloads or runtime state.
LIVE_LABEL = '//delivery:installed_codex_live_continuity_test'
LIVE_FILES = ('test.outputs/codex-live-proof.json',)
LIVE_ENROLLMENT_LABEL = '//delivery:installed_codex_live_enrollment_test'
LIVE_ENROLLMENT_FILES = ('test.outputs/codex-live-enrollment-proof.json',)
SOURCE_RECEIPT_LABEL = '//tools:runtime_source_receipt'
SOURCE_RECEIPT_FILES = ('test.outputs/runtime-source-receipt/receipt.json',
                       'test.outputs/runtime-source-receipt/source-inventory.json')
WRAPPER_COMPANION_LABEL = '//tools:yoga_wrapper_companion'
WRAPPER_COMPANION_FILES = ('test.outputs/wrapper-companion.json',
                           'test.outputs/wrapper-companion-production.json')
LABEL = re.compile(r'//([A-Za-z0-9_.+/-]*):([A-Za-z0-9_.+-]+)\Z')


def label_path(label):
    match = LABEL.fullmatch(label)
    if not match or '..' in Path(match[1]).parts:
        raise ValueError('exact explicit test label required')
    return Path(match[1]) / match[2]


def open_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        os.close(descriptor)
        raise ValueError('owned non-writable evidence directory required')
    return descriptor


def descend(directory, relative):
    descriptor = os.dup(directory)
    try:
        for part in Path(relative).parts:
            if part in ('.', '..') or '/' in part:
                raise ValueError('unsafe evidence path')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def copy_file(directory, relative, destination, epoch_start_ns, remaining, *, destination_directory=None):
    parts = Path(relative).parts
    parent = descend(directory, Path(*parts[:-1]))
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                raise ValueError('source evidence is not an owned regular file')
            if file_identity(before) != file_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)):
                return {'state': 'changed-during-copy', 'bytes': 0}
            if before.st_mtime_ns < epoch_start_ns:
                return {'state': 'stale', 'bytes': 0}
            if before.st_size > remaining:
                return {'state': 'over-budget', 'bytes': 0}
            content = source.read(remaining + 1)
            after = os.fstat(source.fileno())
            if len(content) > remaining:
                return {'state': 'over-budget', 'bytes': 0}
            if (len(content) != before.st_size or file_identity(before) != file_identity(after)
                    or file_identity(before) != file_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))):
                return {'state': 'changed-during-copy', 'bytes': 0}
        # Reopen the selected parent from its held test directory before
        # publication; a stable old FD alone cannot detect directory replacement.
        selected_parent = descend(directory, Path(*parts[:-1]))
        try:
            if file_identity(os.fstat(selected_parent)) != file_identity(os.fstat(parent)):
                return {'state': 'changed-during-copy', 'bytes': 0}
        finally:
            os.close(selected_parent)
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=destination_directory)
        with os.fdopen(output, 'wb') as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        return {'state': 'copied', 'bytes': len(content),
                'sha256': hashlib.sha256(content).hexdigest(), 'file': Path(destination).name}
    finally:
        os.close(parent)


ENGINE_SHARD_LABEL = '//:engine_sharded_test'
ENGINE_SHARD_COUNT = 3
ENGINE_FUNCTION_COUNT = 447
ENGINE_RECEIPT = 'test.outputs/engine-shard-coverage.json'
ENGINE_RECEIPT_LIMIT = 512 * 1024


def engine_inventory(names):
    if (type(names) is not list or len(names) != ENGINE_FUNCTION_COUNT
            or any(type(name) is not str or not 0 < len(name) <= 512
                   or any(not 32 <= ord(char) <= 126 for char in name) for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('engine-inventory')
    digest = hashlib.sha256(b'omux.engine-test-inventory.v1\0')
    digest.update(len(names).to_bytes(4, 'little'))
    for index, name in enumerate(names):
        raw = name.encode('ascii')
        digest.update(index.to_bytes(4, 'little'))
        digest.update(len(raw).to_bytes(4, 'little'))
        digest.update(raw)
    return digest.hexdigest()


def engine_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('engine-duplicate-field')
            result[key] = value
        return result
    if type(raw) is not bytes or not 0 < len(raw) <= ENGINE_RECEIPT_LIMIT:
        raise ValueError('engine-receipt-bound')
    return json.loads(raw, object_pairs_hook=pairs)


def engine_document(doc, expected_index):
    keys = {'schema_version', 'kind', 'target', 'full_count', 'shard_count',
            'shard_index', 'selected_count', 'inventory_sha256', 'names', 'results',
            'sdk_version', 'sdk_log_errors', 'sdk_leaked_tests', 'scope', 'user_outcome_measured'}
    if (type(doc) is not dict or set(doc) != keys
            or type(doc['schema_version']) is not int or doc['schema_version'] != 1
            or doc['kind'] != 'omux-engine-test-shard-v1' or doc['target'] != ENGINE_SHARD_LABEL
            or type(doc['full_count']) is not int or doc['full_count'] != ENGINE_FUNCTION_COUNT
            or type(doc['shard_count']) is not int or doc['shard_count'] != ENGINE_SHARD_COUNT
            or type(doc['shard_index']) is not int or doc['shard_index'] != expected_index
            or type(doc['selected_count']) is not int or doc['selected_count'] != 149
            or doc['sdk_version'] != '0.17.0'
            or doc['scope'] != 'fixture-function-execution-and-original-sdk-teardown'
            or doc['user_outcome_measured'] is not False):
        raise ValueError('engine-receipt-scope')
    identity = engine_inventory(doc['names'])
    if doc['inventory_sha256'] != identity:
        raise ValueError('engine-inventory-digest')
    results = doc['results']
    if type(results) is not list or len(results) != ENGINE_FUNCTION_COUNT:
        raise ValueError('engine-result-count')
    selected = []
    failures = []
    logged = 0
    leaked_tests = 0
    for index, row in enumerate(results):
        if (type(row) is not dict or set(row) != {'index', 'status', 'log_errors', 'allocator_leaks', 'fuzz', 'elapsed_ns'}
                or type(row['index']) is not int or row['index'] != index
                or type(row['log_errors']) is not int or not 0 <= row['log_errors'] <= 2**64-1
                or type(row['allocator_leaks']) is not int or not 0 <= row['allocator_leaks'] <= 2**64-1
                or type(row['fuzz']) is not bool or not (row['elapsed_ns'] is None
                    or type(row['elapsed_ns']) is int and 0 <= row['elapsed_ns'] <= 2**64-1)):
            raise ValueError('engine-result-fields')
        if index % ENGINE_SHARD_COUNT == expected_index:
            if row['status'] not in ('pass', 'fail', 'skip'):
                raise ValueError('engine-unfinished-selected')
            selected.append(index)
            logged += row['log_errors']
            leaked_tests += row['allocator_leaks'] != 0
            if row['status'] != 'pass' or row['log_errors'] or row['allocator_leaks'] or row['fuzz']:
                failures.append(index)
        elif (row['status'] != 'unselected' or row['log_errors'] or row['allocator_leaks']
                or row['fuzz'] or row['elapsed_ns'] is not None):
            raise ValueError('engine-foreign-completion')
    for field in ('sdk_log_errors', 'sdk_leaked_tests'):
        if type(doc[field]) is not int or not 0 <= doc[field] <= 2**64-1:
            raise ValueError('engine-sdk-count')
    # Saturated per-test log deltas cannot turn the SDK's global error into zero.
    if doc['sdk_log_errors'] or doc['sdk_leaked_tests']:
        failures.append(-1)
    if doc['sdk_leaked_tests'] != leaked_tests or doc['sdk_log_errors'] < min(logged, 2**64-1):
        raise ValueError('engine-sdk-disagreement')
    return identity, doc['names'], selected, failures


def engine_xml(raw):
    import xml.etree.ElementTree as ET
    if not 0 < len(raw) <= 1024 * 1024 or b'<!DOCTYPE' in raw.upper():
        raise ValueError('engine-xml-bound')
    root = ET.fromstring(raw)
    cases = list(root.iter('testcase'))
    suites = list(root.iter('testsuite'))
    if len(cases) != 1 or not suites or any(
            child.tag in ('failure', 'error', 'skipped') for child in root.iter()):
        raise ValueError('engine-xml-failure')
    if any(suite.get('failures', '0') != '0' or suite.get('errors', '0') != '0'
           or suite.get('skipped', '0') != '0' for suite in suites):
        raise ValueError('engine-xml-status')


def retained_engine_file(directory, entry, limit):
    if entry is None or entry.get('state') != 'copied':
        raise ValueError('engine-missing-retained-file')
    name = entry.get('file', '')
    if re.fullmatch(r'[0-9a-f]{64}\.evidence', name) is None:
        raise ValueError('engine-retained-name')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > limit
                or file_identity(before) != file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))):
            raise ValueError('engine-retained-identity')
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError('engine-retained-short-read')
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        if (len(raw) != before.st_size or len(raw) > limit
                or file_identity(os.fstat(fd)) != file_identity(before)
                or file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != file_identity(before)
                or hashlib.sha256(raw).hexdigest() != entry.get('sha256')
                or len(raw) != entry.get('bytes')):
            raise ValueError('engine-retained-changed')
        return raw
    finally:
        os.close(fd)


def reconcile_engine_shards(evidencefd, rows, bazel_status):
    result = {'schema_version': 1, 'state': 'unqualified', 'target': ENGINE_SHARD_LABEL,
              'required_shards': ENGINE_SHARD_COUNT, 'required_functions': ENGINE_FUNCTION_COUNT,
              'complete_union': False, 'all_passed': False,
              'unsharded_reference_passed': False, 'user_outcome_measured': False}
    try:
        selected_rows = [row for row in rows if row.get('target') == ENGINE_SHARD_LABEL]
        if len(selected_rows) != ENGINE_SHARD_COUNT:
            raise ValueError('engine-shard-row-count')
        if len({row.get('configuration') for row in selected_rows}) != 1:
            raise ValueError('engine-mixed-configuration')
        common = None
        common_names = None
        indices = []
        seen_shards = set()
        failed = []
        for row in selected_rows:
            shard = row.get('shard_index')
            if type(shard) is not int or shard not in range(ENGINE_SHARD_COUNT) or shard in seen_shards:
                raise ValueError('engine-shard-identity')
            seen_shards.add(shard)
            prefix = 'shard_%d_of_%d/' % (shard + 1, ENGINE_SHARD_COUNT)
            members = {entry['source']: entry for entry in row['files']}
            if len(members) != len(row['files']):
                raise ValueError('engine-duplicate-member')
            retained_engine_file(evidencefd, members.get(prefix + 'test.log'), 4 * 1024 * 1024)
            xml = retained_engine_file(evidencefd, members.get(prefix + 'test.xml'), 1024 * 1024)
            doc = engine_json(retained_engine_file(evidencefd, members.get(prefix + ENGINE_RECEIPT), ENGINE_RECEIPT_LIMIT))
            identity, names, completed, failures = engine_document(doc, shard)
            if common is None:
                common, common_names = identity, names
            elif common != identity or common_names != names:
                raise ValueError('engine-mixed-inventory')
            indices += completed
            failed += failures
            engine_xml(xml)
        if len(indices) != ENGINE_FUNCTION_COUNT or sorted(indices) != list(range(ENGINE_FUNCTION_COUNT)):
            raise ValueError('engine-union-coverage')
        result.update(complete_union=True, inventory_sha256=common, completed_functions=len(indices))
        if bazel_status != 0 or failed:
            raise ValueError('engine-failed-functions-or-invocation')
        result.update(state='complete', all_passed=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, SyntaxError, RecursionError):
        # No raw names, result payloads, exception text or paths in diagnostics.
        result['cause'] = 'coverage_or_outcome_unqualified'
    return result


def capture(output_base, run, labels, bazel_status, epoch_start_ns):
    if (not isinstance(epoch_start_ns, int) or epoch_start_ns <= 0 or
            not isinstance(bazel_status, int) or len(labels) > 64 or len(set(labels)) != len(labels)):
        raise ValueError('bounded exact epoch inputs required')
    output_base, run = Path(output_base), Path(run)
    root = open_directory(output_base)
    runfd = open_directory(run)
    testroot = None
    evidencefd = None
    used = 0
    copied = 0
    rows = []
    configurations = []
    try:
        os.mkdir('test-evidence', mode=0o700, dir_fd=runfd)
        evidencefd = descend(runfd, 'test-evidence')
        try:
            testroot = descend(root, 'execroot/_main/bazel-out')
            configurations = sorted(name for name in os.listdir(testroot)
                                    if re.fullmatch(r'[A-Za-z0-9_.+-]+', name)
                                    and stat.S_ISDIR(os.stat(name, dir_fd=testroot, follow_symlinks=False).st_mode))
            if len(configurations) > 32:
                raise ValueError('test configuration inventory exceeds bound')
        except FileNotFoundError:
            pass
        for label in labels:
            try:
                relative = label_path(label)
            except ValueError:
                rows.append({'target': label, 'state': 'unsupported-label', 'files': []})
                continue
            found = False
            for configuration in configurations:
                directory = None
                try:
                    directory = descend(testroot, Path(configuration) / 'testlogs' / relative)
                    found = True
                    entries = []
                    members = FILES + (SOURCE_RECEIPT_FILES if label == SOURCE_RECEIPT_LABEL else ()) + (LIVE_FILES if label == LIVE_LABEL else ()) + (LIVE_ENROLLMENT_FILES if label == LIVE_ENROLLMENT_LABEL else ()) + (WRAPPER_COMPANION_FILES if label == WRAPPER_COMPANION_LABEL else ())
                    if label == ENGINE_SHARD_LABEL:
                        # Only this exact declared engine target gets shard
                        # descendants; no generic recursive evidence import.
                        for shard in range(ENGINE_SHARD_COUNT):
                            shard_entries = []
                            prefix = 'shard_%d_of_%d/' % (shard + 1, ENGINE_SHARD_COUNT)
                            for selected in FILES + (ENGINE_RECEIPT,):
                                member = prefix + selected
                                if copied >= MAX_FILES:
                                    shard_entries.append({'source': member, 'state': 'file-budget-exhausted'})
                                    continue
                                filename = hashlib.sha256((label + '\0' + configuration + '\0' + member).encode()).hexdigest() + '.evidence'
                                try:
                                    result = copy_file(directory, member, filename, epoch_start_ns,
                                                       MAX_BYTES - used, destination_directory=evidencefd)
                                except FileNotFoundError:
                                    result = {'state': 'missing', 'bytes': 0}
                                except (OSError, ValueError):
                                    result = {'state': 'copy-refused', 'bytes': 0}
                                used += result.get('bytes', 0)
                                copied += result['state'] == 'copied'
                                shard_entries.append({'source': member, **result})
                            rows.append({'target': label, 'configuration': configuration,
                                         'shard_index': shard, 'state': 'observed', 'files': shard_entries})
                        continue
                    for member in members:
                        if copied >= MAX_FILES:
                            entries.append({'source': member, 'state': 'file-budget-exhausted'})
                            continue
                        filename = hashlib.sha256((label + '\0' + configuration + '\0' + member).encode()).hexdigest() + '.evidence'
                        try:
                            result = copy_file(directory, member, filename, epoch_start_ns,
                                               MAX_BYTES - used, destination_directory=evidencefd)
                        except FileNotFoundError:
                            result = {'state': 'missing', 'bytes': 0}
                        except (OSError, ValueError):
                            result = {'state': 'copy-refused', 'bytes': 0}
                        used += result.get('bytes', 0)
                        copied += result['state'] == 'copied'
                        entries.append({'source': member, **result})
                    rows.append({'target': label, 'configuration': configuration,
                                 'state': 'observed', 'files': entries})
                except FileNotFoundError:
                    continue
                except (OSError, ValueError):
                    rows.append({'target': label, 'configuration': configuration,
                                 'state': 'directory-refused', 'files': []})
                    found = True
                finally:
                    if directory is not None:
                        os.close(directory)
            if not found:
                rows.append({'target': label, 'state': 'missing-test-directory', 'files': []})
        if file_identity(os.fstat(evidencefd)) != file_identity(os.stat(
                'test-evidence', dir_fd=runfd, follow_symlinks=False)):
            raise ValueError('epoch evidence directory changed before manifest publication')
        manifest = {'schema': 1, 'bazel_exit': bazel_status, 'epoch_start_ns': epoch_start_ns,
                    'targets': list(labels), 'bytes': used, 'copied_files': copied,
                    'results': rows, 'acceptance': 'evidence copies preserve invocation status; no inferred PASS'}
        if ENGINE_SHARD_LABEL in labels:
            manifest['engine_shards'] = reconcile_engine_shards(evidencefd, rows, bazel_status)
        descriptor = os.open('test-evidence.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=runfd)
        with os.fdopen(descriptor, 'w') as target:
            target.write(json.dumps(manifest, sort_keys=True) + '\n')
            target.flush()
            os.fsync(target.fileno())
        os.fsync(evidencefd)
        os.fsync(runfd)
        return manifest
    finally:
        if evidencefd is not None:
            os.close(evidencefd)
        if testroot is not None:
            os.close(testroot)
        os.close(runfd)
        os.close(root)
