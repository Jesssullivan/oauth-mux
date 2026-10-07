"""Serialized batch-Bazel output-base reuse, fenced by verified cleanup.

The supervisor supplies an exact graph digest and holds its existing global
execution lock. This additional cache lock is held across the entire invocation.
No Bazel server is introduced. Historical per-run logs/receipts stay elsewhere.
Dirty cache state always refuses reuse; recovery needs separate owned-process
inspection and must not erase the failed epoch's evidence.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid


def graph_digest(repository):
    """Bind graph definitions/tool rule sources, leaving action data to Bazel.

    Application bytes are intentionally excluded: Bazel hashes declared action
    inputs. Per-run source/artifact epochs remain separate evidence obligations.
    """
    repository = Path(repository).resolve(strict=True)
    selected = []
    deadline = time.monotonic() + 15
    traversed = 0
    path_bytes = 0
    fixed = {'BUILD', 'BUILD.bazel', 'MODULE.bazel', 'MODULE.bazel.lock',
             'WORKSPACE', 'WORKSPACE.bazel', 'flake.nix', 'flake.lock',
             '.bazelrc', '.bazelversion'}
    output_links = {'bazel-bin', 'bazel-out', 'bazel-testlogs', 'bazel-' + repository.name}
    for directory, subdirs, files in os.walk(repository, followlinks=False):
        traversed += len(subdirs) + len(files)
        if traversed > 200000 or time.monotonic() > deadline:
            raise ValueError('graph traversal exceeds its finite budget')
        # Root .direnv is operator shell state, never a declared repository
        # graph input. Nested directories with this name are not exempted.
        excluded = {'.git'} | ({'.direnv'} if Path(directory) == repository else set())
        if any((Path(directory) / name).is_symlink() for name in subdirs
               if name not in excluded and not (Path(directory) == repository and name in output_links)):
            raise ValueError('external symlink directories cannot establish a complete graph binding')
        subdirs[:] = sorted(name for name in subdirs if name not in excluded
                            and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(repository)
            if (name in fixed or path.suffix in ('.bzl', '.nix')
                    or (relative.parts[0] == 'tools' and path.suffix in
                        ('.py', '.json', '.patch', '.zig', '.h'))):
                if path.is_symlink():
                    raise ValueError('graph inputs must not be mutable external symlinks')
                selected.append(relative.as_posix())
                path_bytes += len(relative.as_posix().encode())
                if len(selected) > 4096 or len(str(relative)) > 4096 or path_bytes > 128 * 1024:
                    raise ValueError('graph input inventory exceeds bound')
    if not selected:
        raise ValueError('repository graph definitions missing')
    digest = hashlib.sha256()
    total = 0
    for relative in sorted(selected):
        path = repository / relative
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise ValueError('graph input must be a bounded regular file')
            content = source.read(16 * 1024 * 1024 + 1)
            total += len(content)
            if len(content) > 16 * 1024 * 1024 or total > 64 * 1024 * 1024 or time.monotonic() > deadline:
                raise ValueError('graph input exceeds bound')
        digest.update(relative.encode() + b'\0' + hashlib.sha256(content).digest())
    return digest.hexdigest(), selected


def fingerprint(repository, graph_digest, inputs):
    if not re.fullmatch(r'[0-9a-f]{64}', graph_digest):
        raise ValueError('exact graph digest required')
    if not inputs or any(not isinstance(value, str) or not value.startswith('/nix/store/')
                         or any(char.isspace() for char in value) or '..' in Path(value).parts
                         for value in inputs.values()):
        raise ValueError('immutable tool and closure inputs required')
    payload = {'repository': str(Path(repository).resolve(strict=True)),
               'graph_sha256': graph_digest, 'inputs': inputs}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stable_fingerprint(repository, inputs, uid, gid, manager, profile):
    """Policy v2: Bazel invalidates graph/action data; containment partitions reuse."""
    if not inputs or any(not isinstance(value, str) or not value.startswith('/nix/store/')
                         or any(char.isspace() for char in value) or '..' in Path(value).parts
                         for value in inputs.values()):
        raise ValueError('immutable tool and closure inputs required')
    if manager not in ('user', 'system') or uid < 1 or gid < 0 or not isinstance(profile, dict):
        raise ValueError('exact unprivileged containment profile required')
    payload = {'policy': 2, 'repository': str(Path(repository).resolve(strict=True)),
               'uid': uid, 'gid': gid, 'manager': manager, 'profile': profile, 'inputs': inputs}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def trusted_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute trusted state root required')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.getuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('untrusted state ancestor')
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('state root must be owned and 0700')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_marker(directory):
    descriptor = os.open('owner.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor) as source:
        info = os.fstat(source.fileno())
        if (info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode)):
            raise ValueError('cache marker ownership rejected')
        text = source.read(4097)
        if len(text) > 4096:
            raise ValueError('cache marker exceeds bound')
        return json.loads(text)


def write_marker(directory, payload):
    temporary = '.owner-' + str(uuid.uuid4())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, 'w') as output:
            output.write(json.dumps(payload, sort_keys=True) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, 'owner.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise


def verify_cleanup_receipt(state_root, run_id, expected_digest):
    if str(uuid.UUID(run_id)) != run_id:
        raise ValueError('cleanup run UUID rejected')
    parent = trusted_directory(state_root)
    run = None
    try:
        run = os.open(run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        descriptor = os.open('receipt.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=run)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('cleanup receipt ownership rejected')
            content = source.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected_digest:
            raise ValueError('cleanup receipt digest rejected')
        receipt = json.loads(content)
        if receipt.get('id') != run_id or receipt.get('descendants_empty') is not True:
            raise ValueError('previous descendant cleanup unproved')
    finally:
        if run is not None:
            os.close(run)
        os.close(parent)


class CacheLease:
    def __init__(self, state_root, key, run_id, policy_version=1):
        if not re.fullmatch(r'[0-9a-f]{64}', key) or str(uuid.UUID(run_id)) != run_id:
            raise ValueError('cache fingerprint or run UUID rejected')
        if policy_version not in (1, 2):
            raise ValueError('unsupported cache ownership policy')
        self.state_root = Path(state_root)
        self.key = key
        self.run_id = run_id
        self.policy_version = policy_version
        self.name = ('cache-' if policy_version == 1 else 'cache-v2-') + key
        self.directory = None
        self.lock = None
        self.output_base = self.state_root / self.name / 'output-base'

    def __enter__(self):
        parent = trusted_directory(self.state_root)
        try:
            created = False
            name = self.name
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            self.directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(self.directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('cache directory ownership rejected')
            self.lock = os.open('cache.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                                0o600, dir_fd=self.directory)
            info = os.fstat(self.lock)
            if (info.st_uid != os.getuid() or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode)):
                raise ValueError('cache lock ownership rejected')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if created:
                write_marker(self.directory, {'schema': self.policy_version, 'key': self.key,
                             'clean': True, 'last_run': None, 'cleanup_receipt_sha256': None})
            previous = read_marker(self.directory)
            if (set(previous) != {'schema', 'key', 'clean', 'last_run', 'cleanup_receipt_sha256'}
                    or previous['schema'] != self.policy_version or previous['key'] != self.key
                    or previous['clean'] is not True):
                raise ValueError('cache reuse requires verified previous cleanup')
            if previous['last_run'] is not None and not re.fullmatch(
                    r'[0-9a-f]{64}', previous['cleanup_receipt_sha256'] or ''):
                raise ValueError('previous cleanup receipt binding missing')
            if previous['last_run'] is not None:
                verify_cleanup_receipt(self.state_root, previous['last_run'],
                                       previous['cleanup_receipt_sha256'])
            try:
                base = os.open('output-base', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=self.directory)
            except FileNotFoundError:
                pass
            else:
                try:
                    info = os.fstat(base)
                    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                        raise ValueError('cache output-base ownership rejected')
                finally:
                    os.close(base)
            # Persist dirty before any Bazel admission; crash leaves a refusal fence.
            write_marker(self.directory, {'schema': self.policy_version, 'key': self.key,
                         'clean': False, 'last_run': self.run_id, 'cleanup_receipt_sha256': None})
            return self
        except BaseException:
            self.close()
            raise
        finally:
            os.close(parent)

    def complete(self, descendants_empty, cleanup_receipt_sha256):
        if descendants_empty is not True or not re.fullmatch(r'[0-9a-f]{64}', cleanup_receipt_sha256):
            raise ValueError('verified empty descendants and durable receipt digest required')
        marker = read_marker(self.directory)
        if marker.get('last_run') != self.run_id or marker.get('key') != self.key or marker.get('clean') is not False:
            raise ValueError('cache lease ownership changed')
        verify_cleanup_receipt(self.state_root, self.run_id, cleanup_receipt_sha256)
        marker.update(clean=True, cleanup_receipt_sha256=cleanup_receipt_sha256)
        write_marker(self.directory, marker)

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None

    def __exit__(self, *ignored):
        self.close()  # Never infer cleanup from a normal Python return.
