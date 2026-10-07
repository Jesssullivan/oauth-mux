"""One exact cancelled browser output base: preserve custody, then bounded retire.

This is deliberately not a generic cache cleanup API. No markers, locks, epoch
logs or other caches are removed. Root owns manual declared execution admission.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from guard_cache import trusted_directory
from prune_epoch_runfiles import Audit, directory, read_file, remove_tree, verify_dead

STATE = '/home/jess/.local/state/omux-execution-20261005'
KEY = '4f9d8aed02dfeed365f13725eada27bbf397e4410dd2aa4730841df5e4126e02'
CACHE = 'cache-v2-' + KEY
EPOCH = '9f9c6dc1-4c90-4e77-bc67-2df2a723a043'
MARKER_SHA = '1b7d284038752f40cf14a99884add213b6a7d3f19ad638332030af11a7b8e2c3'
RECEIPT_SHA = '668f533a1139667f173c0152368c145c83d62a9a9a94f2bdf48ab09a97327527'
DEBUG = ('java.log.unknown.jess.log.java.20261005-040656.2577192',
         'command-26d7ff75-b4b1-4cf9-9d02-91445acac492.profile.gz',
         'javalog.properties', 'README', 'DO_NOT_BUILD_HERE')


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + 180
        self.files = 0

    def tick(self):
        self.files += 1
        if self.files > 2000000 or time.monotonic() > self.deadline:
            raise ValueError('retirement finite budget exhausted')


def write_new(parent, name, content):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def verify_binding(marker, receipt):
    if hashlib.sha256(marker).hexdigest() != MARKER_SHA or hashlib.sha256(receipt).hexdigest() != RECEIPT_SHA:
        raise ValueError('fixed cache custody digest mismatch')
    value = json.loads(marker)
    record = json.loads(receipt)
    if (value.get('schema') != 2 or value.get('clean') is not True
            or value.get('key') != KEY or value.get('last_run') != EPOCH
            or value.get('cleanup_receipt_sha256') != RECEIPT_SHA
            or record.get('cache_key') != KEY
            or record.get('output_base') != STATE + '/' + CACHE + '/output-base'
            or record.get('test_evidence', {}).get('files') != 0):
        raise ValueError('fixed clean cancelled cache receipt required')
    verify_dead(record, EPOCH)
    return record


def admission(home):
    # Current guard may reside on fast storage. Its root is used only for
    # authentication, while coordination remains the original home lock.
    context = Path(os.environ.get('OMUX_EXECUTION_GUARD', ''))
    if not context.is_absolute() or context.name == EPOCH:
        raise ValueError('separate exact current guard required')
    from prune_epoch_runfiles import exact_uuid
    current = exact_uuid(context.name)
    parent = trusted_directory(str(context.parent))
    run = directory(parent, current)
    try:
        supervisor = json.loads(read_file(run, 'supervisor.json', 4096))
    finally:
        os.close(run)
        os.close(parent)
    pid = supervisor.get('pid')
    if supervisor.get('id') != current or not isinstance(pid, int) or pid < 2:
        raise ValueError('exact current supervisor required')
    proc = Path('/proc', str(pid))
    if proc.stat().st_uid != os.getuid():
        raise ValueError('foreign controller')
    text = (proc / 'stat').read_text()
    if text[text.rindex(')') + 2:].split()[19] != supervisor.get('start_ticks'):
        raise ValueError('controller PID reused')
    unit = 'omux-execution-' + current + '.service'
    if not any(unit in Path(line.split(':', 2)[2]).parts
               for line in Path('/proc/self/cgroup').read_text().splitlines()):
        raise ValueError('outside current controller cgroup')
    lock = os.open('execution.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=home)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('unsafe coordination lock')
        matched = False
        for row in Path('/proc/locks').read_text().splitlines():
            fields = row.split()
            if len(fields) < 8 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE'] or fields[4] != str(pid):
                continue
            major, minor, inode = fields[5].split(':')
            if (int(major, 16), int(minor, 16), int(inode)) == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
                matched = True
        if not matched:
            raise ValueError('home coordination lock not held by exact controller')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(lock, fcntl.LOCK_UN)
        raise ValueError('home coordination lock unexpectedly available')
    finally:
        os.close(lock)


def preserve_debug(base, epoch):
    try:
        os.mkdir('browser-cache-retirement-evidence', 0o700, dir_fd=epoch)
        fresh = True
    except FileExistsError:
        fresh = False
    saved = directory(epoch, 'browser-cache-retirement-evidence')
    try:
        if fresh:
            rows = []
            used = 0
            for name in DEBUG:
                content = read_file(base, name, 4 * 1024 * 1024 - used)
                used += len(content)
                write_new(saved, name, content)
                rows.append({'file': name, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
            manifest = {'schema': 1, 'key': KEY, 'marker_sha256': MARKER_SHA,
                        'receipt_sha256': RECEIPT_SHA, 'files': rows}
            write_new(saved, 'manifest.json', (json.dumps(manifest, sort_keys=True) + '\n').encode())
            os.fsync(saved)
        manifest = json.loads(read_file(saved, 'manifest.json', 16384))
        if (manifest.get('key') != KEY or manifest.get('marker_sha256') != MARKER_SHA
                or manifest.get('receipt_sha256') != RECEIPT_SHA
                or {row['file'] for row in manifest['files']} != set(DEBUG)):
            raise ValueError('retained debug custody mismatch')
        for row in manifest['files']:
            content = read_file(saved, row['file'], 4 * 1024 * 1024)
            if len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
                raise ValueError('retained debug evidence changed')
        return manifest
    finally:
        os.close(saved)


def compiled_inventory(fd, relative, budget, rows):
    for name in sorted(os.listdir(fd)):
        budget.tick()
        if name.endswith('.runfiles'):
            continue
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if info.st_uid != os.getuid():
            raise ValueError('foreign derived output')
        path = relative + '/' + name
        if stat.S_ISDIR(info.st_mode):
            child = directory(fd, name)
            try:
                compiled_inventory(child, path, budget, rows)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            if len(rows) >= 10000 or len(path) > 4096:
                raise ValueError('compiled output inventory budget exhausted')
            rows.append({'path': path, 'bytes': info.st_size,
                         'disposition': 'superseded-unshipped-derived-output'})
        elif not stat.S_ISLNK(info.st_mode):
            raise ValueError('unsupported derived output')


def run(apply=False):
    budget = Budget()
    home = trusted_directory(STATE)
    cache = epoch = lock = base = auditfd = None
    journal = None
    try:
        admission(home)
        cache = directory(home, CACHE)
        epoch = directory(home, EPOCH)
        lock = os.open('cache.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=cache)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('unsafe exact cache lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = read_file(cache, 'owner.json', 4096)
        receipt = read_file(epoch, 'receipt.json', 1024 * 1024)
        verify_binding(marker, receipt)
        base = directory(cache, 'output-base')
        kept = preserve_debug(base, epoch)
        compiled = []
        try:
            saved_inventory = json.loads(read_file(epoch, 'browser-cache-compiled-inventory.json', 1024 * 1024))
        except FileNotFoundError:
            saved_inventory = None
        if saved_inventory is not None:
            if saved_inventory.get('key') != KEY or saved_inventory.get('receipt_sha256') != RECEIPT_SHA:
                raise ValueError('retained compiled inventory binding mismatch')
            compiled = saved_inventory['files']
        parent = base
        opened = []
        try:
            for name in (() if saved_inventory is not None else ('execroot', '_main', 'bazel-out')):
                parent = directory(parent, name)
                opened.append(parent)
            for config in ([] if saved_inventory is not None else sorted(os.listdir(parent))):
                if not stat.S_ISDIR(os.stat(config, dir_fd=parent, follow_symlinks=False).st_mode):
                    continue
                configfd = directory(parent, config)
                try:
                    try:
                        binfd = directory(configfd, 'bin')
                    except FileNotFoundError:
                        continue
                    try:
                        compiled_inventory(binfd, 'execroot/_main/bazel-out/' + config + '/bin', budget, compiled)
                    finally:
                        os.close(binfd)
                finally:
                    os.close(configfd)
        finally:
            for fd in reversed(opened):
                os.close(fd)
        if saved_inventory is None:
            payload = (json.dumps({'key': KEY, 'receipt_sha256': RECEIPT_SHA, 'files': compiled}, sort_keys=True) + '\n').encode()
            if len(payload) > 1024 * 1024:
                raise ValueError('compiled inventory byte budget exhausted')
            write_new(epoch, 'browser-cache-compiled-inventory.json', payload)
            os.fsync(epoch)
        auditfd = os.open('browser-cache-retirement.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=epoch)
        info = os.fstat(auditfd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('unsafe retirement audit')
        journal = Audit(auditfd)
        journal.write({'schema': 1, 'apply': apply, 'key': KEY, 'receipt_sha256': RECEIPT_SHA,
                       'marker_sha256': MARKER_SHA, 'preserved_debug': kept,
                       'compiled_inventory': compiled, 'root_inode': os.fstat(base).st_ino,
                       'intent': 'remove-only-fixed-output-base'}, durable=True)
        if apply:
            admission(home)
            verify_binding(read_file(cache, 'owner.json', 4096), read_file(epoch, 'receipt.json', 1024 * 1024))
            remove_tree(cache, 'output-base', 'output-base', budget, journal)
            journal.checkpoint()
            os.fsync(cache)
        journal.write({'complete': True, 'apply': apply, 'removed_total': journal.removed,
                       'retained': ['owner.json', 'cache.lock', 'epoch-receipt-log-evidence']}, durable=True, terminal=True)
    except BaseException:
        if journal is not None:
            journal.write({'complete': False, 'resumable': True,
                           'removed_total': journal.removed}, durable=True, terminal=True)
        raise
    finally:
        for fd in (auditfd, base, lock, epoch, cache, home):
            if fd is not None:
                os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    run(parser.parse_args().apply)
