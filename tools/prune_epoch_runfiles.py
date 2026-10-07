"""Bounded manual pruning of old receipt-bound UUID runfiles; never cache roots.

Operator plan: {"current_epoch": UUID, "epochs": [{"uuid": UUID,
"receipt_sha256": HEX}]}. Controller holds execution.lock; admission verifies
its live supervisor identity and /proc/locks owner. It takes an epoch lock and preserves
testlogs, regular bin outputs, receipts and workload logs. Sandbox deletion is
deliberately excluded: failed sandbox actions can contain unique evidence.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from guard_cache import trusted_directory

MAX_FILES = 1000000
MAX_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 120
MAX_AUDIT_BYTES = 8 * 1024 * 1024
AUDIT_BATCH = 256


class Bound:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.files = 0
        self.bytes = 0

    def tick(self):
        self.files += 1
        if self.files > MAX_FILES or time.monotonic() > self.deadline:
            raise ValueError('finite prune budget exhausted')


def exact_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('canonical UUID required')
    return value


def directory(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        os.close(fd)
        raise ValueError('owned non-writable directory required')
    return fd


def read_file(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > limit:
            raise ValueError('bounded owned regular file required')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(data) > limit or (info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('file changed during read')
        return data


def read_plan(path):
    # Public declared runfiles may be symlinks. Resolve once; exact digest binds
    # bytes, while final nofollow/nonblock opening prevents boundary substitution.
    resolved = Path(path).resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_size > 16384):
            raise ValueError('bounded owned immutable public plan required')
        data = stream.read(16385)
        after = os.fstat(stream.fileno())
        if len(data) > 16384 or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('operator plan changed during read')
        return data


def absent_pid(pid):
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 2:
        raise ValueError('recorded process identity missing')
    # Reused PIDs also refuse: this conservative check never signals a process.
    if Path('/proc', str(pid)).exists():
        raise ValueError('recorded PID exists; inspect identity separately')


def controller_admission(root, state_root, current):
    """Read-only authentication of the supervising lock; never release it."""
    context = Path(os.environ.get('OMUX_EXECUTION_GUARD', ''))
    if str(context) != str(Path(state_root) / current):
        raise ValueError('exact current guard environment required')
    run = directory(root, current)
    try:
        supervisor = json.loads(read_file(run, 'supervisor.json', 4096))
    finally:
        os.close(run)
    pid = supervisor.get('pid')
    if supervisor.get('id') != current or not isinstance(pid, int) or pid < 2:
        raise ValueError('exact supervisor identity required')
    proc = Path('/proc', str(pid))
    if proc.stat().st_uid != os.getuid():
        raise ValueError('foreign supervisor')
    text = (proc / 'stat').read_text()
    start_ticks = text[text.rindex(')') + 2:].split()[19]
    if start_ticks != supervisor.get('start_ticks'):
        raise ValueError('supervisor PID reused')
    unit = 'omux-execution-' + current + '.service'
    group_lines = Path('/proc/self/cgroup').read_text().splitlines()
    if not any(unit in Path(line.split(':', 2)[2]).parts for line in group_lines):
        raise ValueError('helper outside exact current guard cgroup')
    lock = os.open('execution.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=root)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('unsafe global lock')
        device = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        rows = Path('/proc/locks').read_text().splitlines()
        matched = False
        for row in rows:
            fields = row.split()
            if len(fields) < 8 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE'] or fields[4] != str(pid):
                continue
            major, minor, inode = fields[5].split(':')
            if (int(major, 16), int(minor, 16), int(inode)) == device:
                matched = True
        if not matched:
            raise ValueError('exact supervisor global lock owner unavailable')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(lock, fcntl.LOCK_UN)
        raise ValueError('supervisor lock unexpectedly available')
    finally:
        os.close(lock)


def verify_dead(receipt, epoch):
    if receipt.get('id') != epoch or receipt.get('descendants_empty') is not True:
        raise ValueError('exact verified cleanup receipt required')
    properties = receipt.get('observed_properties') or {}
    absent_pid(int(properties.get('MainPID', '0')))
    supervisor = receipt.get('supervisor')
    if supervisor is not None:
        if not str(supervisor.get('start_ticks', '')).isdigit():
            raise ValueError('supervisor start identity missing')
        absent_pid(supervisor.get('pid'))
    expected = 'omux-execution-' + epoch + '.service'
    group = properties.get('ControlGroup')
    if (receipt.get('unit') != expected or not isinstance(group, str)
            or not group.startswith('/') or '..' in Path(group).parts
            or Path(group).name != expected):
        raise ValueError('exact recorded unit cgroup required')
    root = Path('/sys/fs/cgroup')
    current = root
    for part in Path(group).parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return  # Retired exact unit group; receipt already fenced descendants.
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('cgroup boundary changed')
    events = (current / 'cgroup.events').read_text()
    if 'populated 0' not in events.splitlines():
        raise ValueError('recorded cgroup populated or unknown')


class Audit:
    """Bounded summary journal: root intents are durable before mutation."""
    def __init__(self, fd):
        self.fd = fd
        self.bytes = 0
        self.pending = 0
        self.removed = 0

    def write(self, row, durable=False, terminal=False):
        data = (json.dumps(row, sort_keys=True) + '\n').encode()
        limit = MAX_AUDIT_BYTES if terminal else MAX_AUDIT_BYTES - 2048
        if self.bytes + len(data) > limit:
            raise ValueError('finite audit byte budget exhausted')
        position = 0
        while position < len(data):
            written = os.write(self.fd, data[position:])
            if written <= 0:
                raise OSError('audit write made no progress')
            position += written
        self.bytes += len(data)
        if durable:
            os.fsync(self.fd)

    def removed_member(self):
        self.removed += 1
        self.pending += 1
        if self.pending >= AUDIT_BATCH:
            self.checkpoint()

    def checkpoint(self):
        if self.pending:
            self.write({'checkpoint_removed': self.removed}, durable=True)
            self.pending = 0


def inventory(fd, prefix, bound, rows):
    for name in sorted(os.listdir(fd)):
        bound.tick()
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        path = prefix + '/' + name
        if info.st_uid != os.getuid():
            raise ValueError('foreign evidence member')
        if stat.S_ISDIR(info.st_mode):
            child = directory(fd, name)
            try:
                inventory(child, path, bound, rows)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            data = read_file(fd, name, MAX_BYTES - bound.bytes)
            bound.bytes += len(data)
            rows.append({'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        elif stat.S_ISLNK(info.st_mode):
            rows.append({'path': path, 'symlink': os.readlink(name, dir_fd=fd)})
        else:
            raise ValueError('unsupported evidence member')


def remove_tree(parent, name, relative, bound, audit):
    bound.tick()
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if info.st_uid != os.getuid():
        raise ValueError('foreign prune member')
    if stat.S_ISDIR(info.st_mode):
        child = directory(parent, name)
        try:
            for entry in sorted(os.listdir(child)):
                remove_tree(child, entry, relative + '/' + entry, bound, audit)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=parent)
    elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        os.unlink(name, dir_fd=parent)
    else:
        raise ValueError('unsupported prune member')
    audit.removed_member()


def find_runfiles(fd, prefix, bound, result):
    for name in sorted(os.listdir(fd)):
        bound.tick()
        # Only configuration bin trees are passed here; never testlogs.
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if name.endswith('.runfiles'):
            if stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                if len(result) >= 256:
                    raise ValueError('runfiles candidate descriptor budget exhausted')
                result.append((os.dup(fd), name, prefix + '/' + name))
        elif stat.S_ISDIR(info.st_mode):
            child = directory(fd, name)
            try:
                find_runfiles(child, prefix + '/' + name, bound, result)
            finally:
                os.close(child)


def prune(root, row, current, apply):
    epoch = exact_uuid(row['uuid'])
    if epoch == current or not re.fullmatch(r'[0-9a-f]{64}', row['receipt_sha256']):
        raise ValueError('current epoch or invalid receipt binding')
    run = directory(root, epoch)
    candidates = []
    descriptors = [run]
    audit = None
    journal = None
    try:
        lock = os.open('prune.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=run)
        descriptors.append(lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        content = read_file(run, 'receipt.json', 1024 * 1024)
        if hashlib.sha256(content).hexdigest() != row['receipt_sha256']:
            raise ValueError('receipt digest mismatch')
        receipt = json.loads(content)
        if receipt.get('cache_key') is not None:
            raise ValueError('cache producer excluded')
        verify_dead(receipt, epoch)
        base = directory(run, 'output-base')
        descriptors.append(base)
        parent = base
        for name in ('execroot', '_main', 'bazel-out'):
            parent = directory(parent, name)
            descriptors.append(parent)
        bound, evidence = Bound(), []
        for configuration in sorted(os.listdir(parent)):
            info = os.stat(configuration, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                continue
            config = directory(parent, configuration)
            try:
                for name in ('testlogs', 'bin'):
                    try:
                        child = directory(config, name)
                    except FileNotFoundError:
                        continue
                    try:
                        relative = 'execroot/_main/bazel-out/' + configuration + '/' + name
                        if name == 'testlogs':
                            inventory(child, relative, bound, evidence)
                        else:
                            find_runfiles(child, relative, bound, candidates)
                    finally:
                        os.close(child)
            finally:
                os.close(config)
        audit = os.open('prune-audit.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=run)
        if not stat.S_ISREG(os.fstat(audit).st_mode) or os.fstat(audit).st_uid != os.getuid():
            raise ValueError('unsafe audit destination')
        journal = Audit(audit)
        journal.write({'schema': 2, 'epoch': epoch, 'receipt_sha256': row['receipt_sha256'],
                       'apply': apply, 'test_evidence_manifest': evidence,
                       'candidates': [path for _, _, path in candidates], 'sandbox': 'preserved'}, durable=True)
        if apply:
            verify_dead(receipt, epoch)
            for fd, name, path in candidates:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                journal.write({'root_intent': path, 'inode': info.st_ino,
                               'device': info.st_dev, 'mode': info.st_mode}, durable=True)
                remove_tree(fd, name, path, bound, journal)
                journal.checkpoint()
                journal.write({'root_complete': path, 'removed_total': journal.removed}, durable=True)
        journal.write({'complete': True, 'apply': apply, 'visited': bound.files,
                       'removed_total': journal.removed}, durable=True, terminal=True)
    except BaseException:
        if journal is not None:
            journal.write({'complete': False, 'resumable': True,
                           'removed_total': journal.removed}, durable=True, terminal=True)
        raise
    finally:
        for fd, _, _ in candidates:
            os.close(fd)
        if audit is not None:
            os.close(audit)
        for fd in reversed(descriptors):
            os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state-root', required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    root = trusted_directory(args.state_root)
    try:
        content = read_plan(args.plan)
        if not re.fullmatch(r'[0-9a-f]{64}', args.plan_sha256) or hashlib.sha256(content).hexdigest() != args.plan_sha256:
            raise ValueError('exact operator plan digest required')
        plan = json.loads(content)
        selected = plan.get('current_epoch', 'from_guard')
        current = exact_uuid(Path(os.environ.get('OMUX_EXECUTION_GUARD', '')).name
                             if selected == 'from_guard' else selected)
        controller_admission(root, args.state_root, current)
        rows = plan['epochs']
        if not isinstance(rows, list) or not 1 <= len(rows) <= 8 or len({row['uuid'] for row in rows}) != len(rows):
            raise ValueError('one to eight distinct epochs required')
        for row in rows:
            controller_admission(root, args.state_root, current)
            prune(root, row, current, args.apply)
    finally:
        os.close(root)


if __name__ == '__main__':
    main()
