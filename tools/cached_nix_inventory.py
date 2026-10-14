"""Bounded read-only inventory of already registered Nix paths; never realizes inputs.

Nix local?read-only=true uses SQLite immutable and is unsafe against a live
daemon-written database. This fallback uses mode=ro and a transaction snapshot.
Stored NAR hashes are metadata, not a fresh content-integrity attestation.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time

MAX_PATHS = 4096
MAX_REFS = 65536
MAX_INPUT = 131072
MAX_SECONDS = 30
STORE = re.compile(r'/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]{1,211}')
HASH = re.compile(r'(?:sha256:[0-9a-f]{64}|sha256-[A-Za-z0-9+/]{43}=)')


def bounded_bytes(path):
    with open(path, 'rb') as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError('input-size')
    return data


def roots_from_input(value):
    if value.get('schemaVersion') != 1 or value.get('system') != 'x86_64-linux':
        raise ValueError('unsupported-input')
    packages = value.get('packages')
    if not isinstance(packages, dict) or set(packages) != {'node', 'python', 'pnpm', 'bash', 'coreutils', 'chromium'}:
        raise ValueError('unsupported-packages')
    helpers = value.get('helperTools')
    if not isinstance(helpers, list) or not 1 <= len(helpers) <= 32:
        raise ValueError('helper-bound')
    roots = sorted(set([item['out'] for item in packages.values()] + helpers))
    if any(not isinstance(item, str) or not STORE.fullmatch(item) for item in roots):
        raise ValueError('invalid-root')
    return roots


def snapshot_inventory(database, roots, exists=os.path.exists, *, absolute_deadline=None):
    now = time.monotonic()
    if absolute_deadline is None:
        deadline = now + MAX_SECONDS
    else:
        if (type(absolute_deadline) is not float or not math.isfinite(absolute_deadline)
                or not 0 < absolute_deadline-now <= MAX_SECONDS):
            raise ValueError('inventory-deadline')
        deadline = absolute_deadline
    rows = {}
    refs_count = 0
    # mode=ro prevents creation/writes; unlike immutable, SQLite retains locking
    # and observes a consistent read transaction even while the daemon writes.
    def check_optional():
        if absolute_deadline is not None:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise ValueError('inventory-deadline')
            return remaining
        return 2
    def busy_budget():
        if absolute_deadline is not None:
            remaining = check_optional()
            connection.execute('PRAGMA busy_timeout=' + str(int(min(2, remaining)*1000)))
            check_optional()
    connection = sqlite3.connect(Path(database).absolute().as_uri() + '?mode=ro', uri=True,
                                 timeout=min(2, check_optional()))
    try:
        check_optional()
        connection.execute('PRAGMA query_only=ON')
        check_optional()
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        busy_budget()
        connection.execute('BEGIN')
        check_optional()
        pending = list(roots)
        while pending:
            if time.monotonic() > deadline:
                raise ValueError('inventory-deadline')
            path = pending.pop()
            if path in rows:
                continue
            if len(rows) >= MAX_PATHS or not STORE.fullmatch(path) or not exists(path):
                raise ValueError('missing-or-bounded-path')
            busy_budget()
            metadata = connection.execute('SELECT id, hash, narSize FROM ValidPaths WHERE path = ?', (path,)).fetchone()
            check_optional()
            if metadata is None or not isinstance(metadata[1], str) or not HASH.fullmatch(metadata[1]) or not isinstance(metadata[2], int) or metadata[2] < 0:
                raise ValueError('invalid-registration')
            references = []
            busy_budget()
            cursor = connection.execute('SELECT v.path FROM Refs r LEFT JOIN ValidPaths v ON v.id = r.reference WHERE r.referrer = ? ORDER BY v.path', (metadata[0],))
            for (reference,) in cursor:
                check_optional()
                refs_count += 1
                if refs_count > MAX_REFS or not isinstance(reference, str) or not STORE.fullmatch(reference):
                    raise ValueError('reference-bound')
                references.append(reference)
            rows[path] = {'path': path, 'narHash': metadata[1], 'narSize': metadata[2], 'references': references}
            pending.extend(references)
        # Roots are mandatory, and every traversed reference must be resolved.
        if any(ref not in rows for row in rows.values() for ref in row['references']):
            raise ValueError('incomplete-reference-graph')
        check_optional()
        result = [rows[path] for path in sorted(rows)]
    finally:
        connection.close()
    check_optional()
    return result


def produce(roots_path, lock_path, expected_roots, expected_lock, database):
    roots_bytes, lock_bytes = bounded_bytes(roots_path), bounded_bytes(lock_path)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    if not re.fullmatch(r'[a-f0-9]{64}', expected_roots) or digest(roots_bytes) != expected_roots:
        raise ValueError('roots-digest')
    if not re.fullmatch(r'[a-f0-9]{64}', expected_lock) or digest(lock_bytes) != expected_lock:
        raise ValueError('lock-digest')
    value = json.loads(roots_bytes)
    lock = json.loads(lock_bytes)
    if lock['nodes']['nixpkgs']['locked']['rev'] != '1c3fe55ad329cbcb28471bb30f05c9827f724c76':
        raise ValueError('unapproved-site-lock')
    roots = roots_from_input(value)
    return {'schemaVersion': 1, 'system': value['system'], 'mode': 'local-sqlite-readonly-snapshot',
            'provenance': {'rootsSha256': expected_roots, 'flakeLockSha256': expected_lock},
            'roots': roots, 'packages': value['packages'], 'helperTools': value['helperTools'],
            'paths': snapshot_inventory(database, roots), 'contentRehashed': False,
            'realized': False, 'published': False}


def persist_inventory(inventory, directory):
    """Persist public evidence only into Bazel's already owned output directory."""
    output = (json.dumps(inventory, sort_keys=True) + '\n').encode()
    if len(output) > 8 * 1024 * 1024:
        raise ValueError('output-bound')
    root = Path(directory)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError('output-directory')
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(directory_fd)
        if stat.st_uid != os.getuid():
            raise ValueError('output-ownership')
        descriptor = os.open('inventory.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(directory_fd)
    return {'schemaVersion': 1, 'passed': True, 'artifact': 'inventory.json',
            'sha256': hashlib.sha256(output).hexdigest(), 'bytes': len(output),
            'roots': len(inventory['roots']), 'paths': len(inventory['paths']),
            'contentRehashed': False, 'realized': False, 'published': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('roots', 'lock', 'roots-sha256', 'lock-sha256'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--database', default='/nix/var/nix/db/db.sqlite')
    args = parser.parse_args()
    try:
        inventory = produce(args.roots, args.lock, args.roots_sha256, args.lock_sha256, args.database)
        directory = os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR')
        if directory:
            print(json.dumps(persist_inventory(inventory, directory), sort_keys=True))
            return 0
        output = json.dumps(inventory, sort_keys=True)
        if len(output.encode()) > 8 * 1024 * 1024:
            raise ValueError('output-bound')
        print(output)
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        # Never print database diagnostics or operator input contents.
        print(json.dumps({'schemaVersion': 1, 'passed': False, 'gate': 'cached-inventory-unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
