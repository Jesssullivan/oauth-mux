"""Stream existing paths through declared Nix NAR serialization; never realize them."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

MAX_PATHS = 4096
MAX_INPUT = 8 * 1024 * 1024
MAX_BYTES = 16 * 1024 * 1024 * 1024
GLOBAL_SECONDS = 600
PATH_SECONDS = 120
STORE = re.compile(r'/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]{1,211}')


def expected_hash(value):
    if isinstance(value, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', value):
        return value[7:]
    if isinstance(value, str) and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', value):
        raw = base64.b64decode(value[7:], validate=True)
        if len(raw) == 32:
            return raw.hex()
    raise ValueError('nar-hash')


def parse_inventory(content, digest):
    if len(content) > MAX_INPUT or not re.fullmatch(r'[a-f0-9]{64}', digest) or hashlib.sha256(content).hexdigest() != digest:
        raise ValueError('inventory-digest-or-bound')
    value = json.loads(content)
    rows = value['paths']
    if value['schemaVersion'] != 1 or not isinstance(rows, list) or not 1 <= len(rows) <= MAX_PATHS:
        raise ValueError('inventory-schema')
    seen = set()
    total = 0
    for row in rows:
        path = row['path']
        if not isinstance(path, str) or not STORE.fullmatch(path) or path in seen:
            raise ValueError('inventory-path')
        seen.add(path)
        expected_hash(row['narHash'])
        size = row['narSize']
        if type(size) is not int or size <= 0:
            raise ValueError('inventory-size')
        total += size
        if total > MAX_BYTES:
            raise ValueError('aggregate-byte-bound')
    if not set(value['roots']).issubset(seen) or any(ref not in seen for row in rows for ref in row['references']):
        raise ValueError('incomplete-inventory')
    return rows


def confirm_nar(count, digest, row):
    if count != row['narSize'] or digest != expected_hash(row['narHash']):
        raise ValueError('nar-mismatch')


def stream_nar(nix, row, global_deadline):
    with tempfile.TemporaryDirectory(prefix='omux-nar-config-') as scratch:
        return _stream_nar(nix, row, global_deadline, scratch)


def _stream_nar(nix, row, global_deadline, scratch):
    process = subprocess.Popen([nix, '--extra-experimental-features', 'nix-command',
                                '--store', 'dummy://', 'nar', 'dump-path', row['path']],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True,
                               env={'PATH': '', 'NIX_CONFIG': '', 'NIX_PATH': '',
                                    'HOME': scratch, 'NIX_CONF_DIR': scratch,
                                    'NIX_USER_CONF_FILES': ''})
    count = 0
    digest = hashlib.sha256()
    deadline = min(global_deadline, time.monotonic() + PATH_SECONDS)
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('nar-deadline')
                for key, _ in selected.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        break
                    count += len(chunk)
                    if count > row['narSize'] or count > MAX_BYTES:
                        raise ValueError('nar-byte-bound')
                    digest.update(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise ValueError('nar-command')
        confirm_nar(count, digest.hexdigest(), row)
        return count
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()


def verify(content, digest, nix, stream=stream_nar):
    rows = parse_inventory(content, digest)
    deadline = time.monotonic() + GLOBAL_SECONDS
    total = 0
    for row in rows:
        if time.monotonic() >= deadline:
            raise ValueError('global-deadline')
        total += stream(nix, row, deadline)
        if total > MAX_BYTES:
            raise ValueError('aggregate-byte-bound')
    return {'schemaVersion': 1, 'passed': True, 'inventorySha256': digest,
            'verifiedPaths': len(rows), 'verifiedNarBytes': total,
            'contentRehashed': True, 'realized': False,
            'flakeMappingVerified': False, 'published': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--nix', required=True)
    args = parser.parse_args()
    handlers = {}
    try:
        nix = Path(args.nix).resolve(strict=True)
        if not str(nix).startswith('/nix/store/') or not nix.is_file() or not os.access(nix, os.X_OK):
            raise ValueError('declared-nix')
        with open(args.inventory, 'rb') as stream:
            content = stream.read(MAX_INPUT + 1)
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            handlers[signum] = signal.signal(signum, interrupted)
        print(json.dumps(verify(content, args.sha256, str(nix)), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        print(json.dumps({'schemaVersion': 1, 'passed': False, 'gate': 'cached-nar-verification-unavailable'}))
        return 2
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
