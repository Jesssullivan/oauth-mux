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
