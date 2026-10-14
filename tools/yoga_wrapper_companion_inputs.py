"""Closed public companion inputs and retained named descriptor custody.

No project imports, directory discovery, command, clock, cache, or authority flag.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PUBLIC = ('/home/jess/.local/state/omux-execution-20261005',
          '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
SCOPE = 'yoga-wrapper-companion-public-input-v1'
OUTPUT_STATE = '/home/jess/.local/state/omux-yoga-delivery-20261006'
SHA = re.compile('[a-f0-9]{64}')
UUID = re.compile('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
MAXIMUM = 65536
RESERVE_NS = 30*10**9


def require(value):
    if value is not True:
        raise ValueError('wrapper-companion-input-refused')


def tick(deadline):
    require(type(deadline) is int and 0 < deadline-time.monotonic_ns() <= 1200*10**9)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return identity(info)[:5]


def selected_path(value):
    require(type(value) is str and str(Path(value)) == value
        and not {'.', '..'}.intersection(value.split('/'))
        and not any(ord(c) < 33 or c == '\\' for c in value)
        and any(value.startswith(root+'/') for root in PUBLIC))
    return Path(value)


def selection(path, sha):
    require(type(sha) is str and SHA.fullmatch(sha) is not None)
    return selected_path(str(path)), sha


def output_path(value):
    # Bazel's exact target output beneath this admitted coordinator's private
    # state. This does not widen public request/receipt/data selection.
    require(type(value) is str and str(Path(value)) == value
        and not {'.', '..'}.intersection(value.split('/')))
    require(value.startswith(OUTPUT_STATE+'/'))
    relative = value[len(OUTPUT_STATE)+1:]
    parts = relative.split('/')
    require(len(parts) >= 2 and UUID.fullmatch(parts[0]) is not None and parts[1] == 'output-base')
    suffix = '/'.join(parts[2:])
    role = 'bazel-out/k8-fastbuild/testlogs/tools/yoga_wrapper_companion/test.outputs'
    require(suffix == 'execroot/_main/'+role or re.fullmatch(
        r'sandbox/linux-sandbox/[1-9][0-9]{0,9}/execroot/_main/'+re.escape(role), suffix) is not None)
    return Path(value)


def pin(value, *, receipt=False):
    require(type(value) is dict and set(value) == ({'epoch', 'path', 'sha256', 'bytes'}
        if receipt else {'path', 'sha256', 'bytes'})
        and type(value['sha256']) is str and SHA.fullmatch(value['sha256']) is not None
        and type(value['bytes']) is int and 0 < value['bytes'] <= 8*1024**2)
    selected_path(value['path'])
    if receipt:
        require(type(value['epoch']) is str and UUID.fullmatch(value['epoch']) is not None
            and value['path'] in {root+'/'+value['epoch']+'/receipt.json' for root in PUBLIC})


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('wrapper-companion-input-refused')))


def schema(raw):
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'selector',
        'selectedData', 'controllerNarProducer', 'controllerNarProof'}
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['scope'] == SCOPE)
    for role in ('selector', 'controllerNarProducer'):
        pin(value[role], receipt=True)
    for role, producer in (('selectedData', 'selector'), ('controllerNarProof', 'controllerNarProducer')):
        pin(value[role])
        require(Path(value[role]['path']).is_relative_to(Path(value[producer]['path']).parent)
            and value[role]['path'] != value[producer]['path'])
    require(value['selector']['epoch'] != value['controllerNarProducer']['epoch'])
    return value


class HeldRequest:
    def __init__(self, path, sha, deadline):
        self.chain, self.fd = [], None
        self.maximum = MAXIMUM
        self.path, self.sha, self.deadline = selected_path(str(path)), sha, deadline
        require(type(sha) is str and SHA.fullmatch(sha) is not None)
        try:
            tick(deadline)
            current = Path('/')
            fd = os.open(current, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for part in self.path.parts[1:-1]:
                tick(deadline); current /= part
                fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                    dir_fd=self.chain[-1][1])
                self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for _, fd, _ in self.chain:
                info = os.fstat(fd)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
            self.fd = os.open(self.path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                dir_fd=self.chain[-1][1])
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o444, 0o600) and info.st_nlink == 1
                and 0 < info.st_size <= self.maximum)
            self.saved = identity(info)
            self.raw = self.read()
            require(hashlib.sha256(self.raw).hexdigest() == sha)
            self.value = schema(self.raw)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def read(self, deadline=None):
        deadline = self.deadline if deadline is None else deadline
        raw = b''
        while len(raw) <= self.maximum:
            tick(deadline)
            data = os.pread(self.fd, min(65536, self.maximum+1-len(raw)), len(raw))
            if not data:
                break
            raw += data
        require(len(raw) == self.saved[6] and len(raw) <= self.maximum)
        return raw

    def anchored(self, deadline=None):
        tick(self.deadline if deadline is None else deadline)
        require(self.fd is not None)
        for index, (path, fd, saved) in enumerate(self.chain):
            named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1], follow_symlinks=False)
            require(saved == directory_identity(os.fstat(fd)) == directory_identity(named))
        require(self.saved == identity(os.fstat(self.fd)) == identity(os.stat(self.path.name,
            dir_fd=self.chain[-1][1], follow_symlinks=False)))
    def recheck(self, *, cleanup=False):
        require(type(cleanup) is bool)
        cutoff = self.deadline if cleanup else self.deadline-RESERVE_NS
        self.anchored(cutoff)
        require(self.read(cutoff) == self.raw)
        self.anchored(cutoff)

    def facts(self, *, cleanup=False):
        self.recheck(cleanup=cleanup)
        return {'scope': SCOPE, 'request_sha256': self.sha,
            'selector_epoch': self.value['selector']['epoch'],
            'controller_nar_producer_epoch': self.value['controllerNarProducer']['epoch']}

    def close(self):
        held = ([] if self.fd is None else [self.fd]) + [row[1] for row in reversed(self.chain)]
        self.fd, self.chain = None, []
        failed = False
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                failed = True
        require(not failed)


class HeldPublic:
    def __init__(self, selected, deadline):
        pin(selected)
        path, sha = selected["path"], selected["sha256"]
        self.chain, self.fd = [], None
        self.maximum = 8*1024**2
        self.path, self.sha, self.deadline = selected_path(str(path)), sha, deadline
        require(type(sha) is str and SHA.fullmatch(sha) is not None)
        try:
            tick(deadline)
            current = Path('/')
            fd = os.open(current, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for part in self.path.parts[1:-1]:
                tick(deadline); current /= part
                fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                    dir_fd=self.chain[-1][1])
                self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for _, fd, _ in self.chain:
                info = os.fstat(fd)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
            self.fd = os.open(self.path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                dir_fd=self.chain[-1][1])
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o444, 0o600) and info.st_nlink == 1
                and 0 < info.st_size <= self.maximum)
            self.saved = identity(info)
            self.raw = self.read()
            require(hashlib.sha256(self.raw).hexdigest() == sha)
            require(len(self.raw) == selected["bytes"])
            self.recheck()
        except BaseException:
            self.close()
            raise

    def read(self, deadline=None):
        deadline = self.deadline if deadline is None else deadline
        raw = b''
        while len(raw) <= self.maximum:
            tick(deadline)
            data = os.pread(self.fd, min(65536, self.maximum+1-len(raw)), len(raw))
            if not data:
                break
            raw += data
        require(len(raw) == self.saved[6] and len(raw) <= self.maximum)
        return raw

    def anchored(self, deadline=None):
        tick(self.deadline if deadline is None else deadline)
        require(self.fd is not None)
        for index, (path, fd, saved) in enumerate(self.chain):
            named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1], follow_symlinks=False)
            require(saved == directory_identity(os.fstat(fd)) == directory_identity(named))
        require(self.saved == identity(os.fstat(self.fd)) == identity(os.stat(self.path.name,
            dir_fd=self.chain[-1][1], follow_symlinks=False)))
    def recheck(self, *, cleanup=False):
        require(type(cleanup) is bool)
        cutoff = self.deadline if cleanup else self.deadline-RESERVE_NS
        self.anchored(cutoff)
        require(self.read(cutoff) == self.raw)
        self.anchored(cutoff)

    def close(self):
        held = ([] if self.fd is None else [self.fd]) + [row[1] for row in reversed(self.chain)]
        self.fd, self.chain = None, []
        failed = False
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                failed = True
        require(not failed)


class HeldSource:
    def __init__(self, name, sha, size, deadline):
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+\.py', name) is not None
            and type(sha) is str and SHA.fullmatch(sha) is not None
            and type(size) is int and 0 < size <= 1024**2)
        path = Path(__file__).resolve().parent/name
        selected = {'bytes': size}
        self.chain, self.fd = [], None
        self.maximum = 1024**2
        self.path, self.sha, self.deadline = Path(path), sha, deadline
        require(type(sha) is str and SHA.fullmatch(sha) is not None)
        try:
            tick(deadline)
            current = Path('/')
            fd = os.open(current, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for part in self.path.parts[1:-1]:
                tick(deadline); current /= part
                fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                    dir_fd=self.chain[-1][1])
                self.chain.append((current, fd, directory_identity(os.fstat(fd))))
            for _, fd, _ in self.chain:
                info = os.fstat(fd)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
            self.fd = os.open(self.path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                dir_fd=self.chain[-1][1])
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o444, 0o600, 0o644) and info.st_nlink == 1
                and 0 < info.st_size <= self.maximum)
            self.saved = identity(info)
            self.raw = self.read()
            require(hashlib.sha256(self.raw).hexdigest() == sha)
            require(len(self.raw) == selected["bytes"])
            self.recheck()
        except BaseException:
            self.close()
            raise

    def read(self, deadline=None):
        deadline = self.deadline if deadline is None else deadline
        raw = b''
        while len(raw) <= self.maximum:
            tick(deadline)
            data = os.pread(self.fd, min(65536, self.maximum+1-len(raw)), len(raw))
            if not data:
                break
            raw += data
        require(len(raw) == self.saved[6] and len(raw) <= self.maximum)
        return raw

    def anchored(self, deadline=None):
        tick(self.deadline if deadline is None else deadline)
        require(self.fd is not None)
        for index, (path, fd, saved) in enumerate(self.chain):
            named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1], follow_symlinks=False)
            require(saved == directory_identity(os.fstat(fd)) == directory_identity(named))
        require(self.saved == identity(os.fstat(self.fd)) == identity(os.stat(self.path.name,
            dir_fd=self.chain[-1][1], follow_symlinks=False)))
    def recheck(self, *, cleanup=False):
        require(type(cleanup) is bool)
        cutoff = self.deadline if cleanup else self.deadline-RESERVE_NS
        self.anchored(cutoff)
        require(self.read(cutoff) == self.raw)
        self.anchored(cutoff)

    def close(self):
        held = ([] if self.fd is None else [self.fd]) + [row[1] for row in reversed(self.chain)]
        self.fd, self.chain = None, []
        failed = False
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                failed = True
        require(not failed)
