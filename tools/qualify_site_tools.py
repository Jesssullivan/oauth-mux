"""Evaluate shared site tool selection from an explicitly cached, rehashed source."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import re
import signal
import subprocess
import tempfile
import time

from cached_nix_inventory import bounded_bytes, roots_from_input
from verify_cached_nars import STORE

MAX_EVALUATION_BYTES = 1024 * 1024 * 1024
MIN_FREE_BYTES = 512 * 1024 * 1024
MAX_EVALUATION_ENTRIES = 200000

class QualificationError(ValueError):
    def __init__(self, phase, code, details=None):
        super().__init__(code)
        self.phase, self.code, self.details = phase, code, details or {}


def exception_diagnostics(error):
    allowed = {'QualificationError', 'FileNotFoundError', 'PermissionError', 'OSError',
               'ValueError', 'JSONDecodeError', 'KeyError', 'TypeError', 'TimeoutExpired',
               'CalledProcessError', 'KeyboardInterrupt', 'UnicodeDecodeError'}
    name = type(error).__name__
    result = {'exceptionType': name if name in allowed else 'SupportedFailure'}
    number = getattr(error, 'errno', None)
    if type(number) is int and 0 <= number <= 4095:
        result['errno'] = number
    return result


def public_diagnostics(stderr):
    text = stderr.decode('utf-8', errors='replace').lower()
    categories = []
    for needles, category in [
        (('syntax error', 'unexpected token'), 'syntax'),
        (('unrecognised flag', 'unrecognized flag', 'unknown flag'), 'unsupported-option'),
        (('import from derivation', 'allow-import-from-derivation'), 'ifd-disabled'),
        (('dummy store', 'does not support', 'cannot add'), 'store-operation-unavailable'),
        (('no such file', 'does not exist'), 'missing-input'),
        (('permission denied', 'read-only file system'), 'permission'),
        (('attribute', 'missing'), 'attribute-or-input'),
    ]:
        if any(needle in text for needle in needles):
            categories.append(category)
    return {'categories': categories or ['nix-command-failed'], 'stderrBytes': len(stderr),
            'text': sanitize_public_diagnostic(stderr)}


def sanitize_public_diagnostic(stderr):
    text = stderr.decode('utf-8', errors='replace')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = ''.join(character for character in text if character in '\n\t' or character.isprintable())
    text = re.sub(r'[A-Za-z][A-Za-z0-9+.-]*://[^\s\'"<>]+', '<url>', text)
    text = re.sub(r'(?<![A-Za-z0-9])/(?:[^\s\'"<>:,;\[\]{}()]+/?)+', '<path>', text)
    text = re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<address>', text)
    source_lines = text.splitlines()
    selected = [line for line in source_lines if 'error:' in line.lower()][:8]
    selected += source_lines[:8] + source_lines[-8:]
    lines = []
    for line in selected[:24]:
        if re.search(r'token|password|cookie|authorization|secret|otp|private.?key', line, re.I):
            line = '<redacted sensitive diagnostic>'
        lines.append(line)
    return '\n'.join(lines).encode()[:4096].decode(errors='ignore')


def public_mapping(actual):
    if not isinstance(actual, dict) or set(actual) != {'packages', 'helperTools'}:
        return None
    packages = actual['packages']
    if not isinstance(packages, dict) or set(packages) != {'node', 'python', 'pnpm', 'bash', 'coreutils', 'chromium'}:
        return None
    for package in packages.values():
        if not isinstance(package, dict) or not set(package).issubset({'out', 'version'}) or not isinstance(package.get('out'), str) or not STORE.fullmatch(package['out']):
            return None
        if 'version' in package and (not isinstance(package['version'], str) or not re.fullmatch(r'[A-Za-z0-9._+-]{1,64}', package['version'])):
            return None
    helpers = actual['helperTools']
    if not isinstance(helpers, list) or len(helpers) > 32 or any(not isinstance(path, str) or not STORE.fullmatch(path) for path in helpers):
        return None
    return actual


def bound_input(path, expected):
    content = bounded_bytes(path)
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError('declared-input-digest')
    return content


def nix_string(value):
    return json.dumps(value).replace('${', '\\${')


def compare_selection(actual, roots):
    expected = {'packages': roots['packages'], 'helperTools': roots['helperTools']}
    if actual != expected:
        safe = public_mapping(actual)
        fingerprint = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        details = {'expectedMappingSha256': fingerprint(expected)}
        if safe is not None:
            details.update({'actualMappingSha256': fingerprint(safe), 'actualMapping': safe,
                            'changedPackages': [name for name in expected['packages'] if expected['packages'][name] != safe['packages'][name]],
                            'helpersChanged': expected['helperTools'] != safe['helperTools']})
        raise QualificationError('output-comparison', 'selected-output-mismatch', details)


def check_private_store(root):
    total, count = 0, 0
    def walk_error(error):
        # Nix may rename/remove a transient entry after directory enumeration.
        # Other inaccessible directories cannot be omitted from accounting.
        if error.errno != errno.ENOENT:
            raise error
    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        count += len(directories) + len(files)
        if count > MAX_EVALUATION_ENTRIES:
            raise QualificationError('shared-selection-evaluation', 'private-store-entry-bound')
        for filename in files:
            try:
                stat = os.lstat(Path(directory) / filename)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    # Its entry remains charged above; the vanished object no
                    # longer consumes retained bytes. Later scans account for
                    # any replacement at its current name.
                    continue
                raise
            total += stat.st_size
            if total > MAX_EVALUATION_BYTES:
                raise QualificationError('shared-selection-evaluation', 'private-store-byte-bound')
    filesystem = os.statvfs(root)
    if filesystem.f_bavail * filesystem.f_frsize < MIN_FREE_BYTES:
        raise QualificationError('shared-selection-evaluation', 'private-store-free-space-floor')


def mapping_command(nix, expression, private_store):
    return [nix, '--extra-experimental-features', 'nix-command', '--store', 'dummy://',
            'eval', '--eval-store', str(private_store), '--offline', '--impure',
            '--option', 'allow-import-from-derivation', 'false',
            '--option', 'eval-cache', 'false', '--option', 'substituters', '',
            '--option', 'builders', '', '--option', 'max-jobs', '0',
            '--json', '--expr', expression]


def wait_unreaped(process, deadline):
    while True:
        status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if status is not None:
            return status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired('owned evaluator', 120)
        time.sleep(0.01)


def cleanup_owned_group(process):
    if process.returncode is not None:
        raise ValueError('evaluator leader was reaped before group cleanup')
    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if os.getpgid(process.pid) != process.pid:
        raise ValueError('owned evaluator process group changed')
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def evaluate(command, scratch, json_output=True, phase='shared-selection-evaluation', private_store=None):
    if private_store is not None:
        check_private_store(private_store)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True,
                               env={'PATH': '', 'HOME': scratch, 'NIX_CONFIG': '',
                                    'NIX_CONF_DIR': scratch, 'NIX_USER_CONF_FILES': ''})
    output = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + 120
    next_store_check = time.monotonic()
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ, True)
            selected.register(process.stderr, selectors.EVENT_READ, False)
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise QualificationError(phase, 'evaluation-deadline')
                if private_store is not None and time.monotonic() >= next_store_check:
                    check_private_store(private_store)
                    next_store_check = time.monotonic() + 1
                for key, _ in selected.select(1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    target = output if key.data else stderr
                    target.extend(chunk)
                    if len(target) > (32768 if key.data else 8192):
                        raise QualificationError(phase, 'evaluation-stream-bound')
        if wait_unreaped(process, deadline) != 0:
            raise QualificationError(phase, 'nix-command-failed', public_diagnostics(stderr))
        if private_store is not None:
            check_private_store(private_store)
        return json.loads(output) if json_output else output.decode('ascii').strip()
    finally:
        cleanup_owned_group(process)
        process.stdout.close()
        process.stderr.close()


def qualify(args):
    args.failure_phase = 'input-binding'
    inputs = {name: bound_input(getattr(args, name), getattr(args, name + '_sha256'))
              for name in ('roots', 'lock', 'selection', 'flake')}
    roots = json.loads(inputs['roots'])
    roots_from_input(roots)
    lock = json.loads(inputs['lock'])
    pinned = lock['nodes']['nixpkgs']['locked']
    if pinned['rev'] != '1c3fe55ad329cbcb28471bb30f05c9827f724c76':
        raise ValueError('site-pin')
    args.failure_phase = 'source-declaration'
    declaration_bytes = bounded_bytes(args.source_input)
    declaration = json.loads(declaration_bytes)
    if declaration.get('schemaVersion') != 1 or declaration.get('narHash') != pinned['narHash'] or declaration.get('revision') != pinned['rev'] or declaration.get('system') != 'x86_64-linux':
        raise ValueError('source-declaration-binding')
    source = declaration['source']
    if not STORE.fullmatch(source) or not Path(source).is_dir():
        raise ValueError('declared-source')
    nix = str(Path(args.nix).resolve(strict=True))
    if not nix.startswith('/nix/store/') or not os.access(nix, os.X_OK):
        raise ValueError('declared-nix')
    if b'import ./tools/tool-selection.nix' not in inputs['flake']:
        raise ValueError('shared-selection-not-referenced')
    with tempfile.TemporaryDirectory(prefix='omux-site-evaluation-') as scratch:
        args.failure_phase = 'source-nar-hash'
        # Hash the actual source NAR directly; no registered size is needed and
        # no database/daemon/realization is consulted through the dummy store.
        source_hash = evaluate([nix, '--extra-experimental-features', 'nix-command',
                                '--store', 'dummy://', 'hash', 'path', '--type',
                                'sha256', '--sri', source], scratch, json_output=False, phase='source-nar-hash')
        if source_hash != pinned['narHash']:
            raise ValueError('source-nar-hash-mismatch')
        selection = Path(scratch) / 'selection.nix'
        selection.write_bytes(inputs['selection'])
        # Paths are Nix strings, never shell text; JSON encoding is valid for
        # these bounded store/scratch paths (no interpolation-bearing source).
        expression = ('let pkgs = import (builtins.toPath ' + nix_string(source) +
                      ') { system = "x86_64-linux"; config = {}; overlays = []; }; selected = import (builtins.toPath ' +
                      nix_string(str(selection)) + ') { inherit pkgs; }; in '
                      '{ inherit (selected) packages helperTools; }')
        args.failure_phase = 'shared-selection-evaluation'
        private_store = Path(scratch) / 'evaluation-store'
        private_store.mkdir(mode=0o700)
        actual = evaluate(mapping_command(nix, expression, private_store), scratch,
                          private_store=private_store)
    compare_selection(actual, roots)
    return {'schemaVersion': 1, 'passed': True, 'mode': 'shared-selection-offline-evaluation',
            'provenance': {name + 'Sha256': getattr(args, name + '_sha256') for name in inputs},
            'sourceInputSha256': hashlib.sha256(declaration_bytes).hexdigest(),
            'nixpkgsRevision': pinned['rev'], 'nixpkgsSourceNarHash': pinned['narHash'],
            'sourceContentRehashed': True, 'selectedOutputsMatched': True,
            'evaluationStore': 'private-local-temporary', 'evaluationStoreByteLimit': MAX_EVALUATION_BYTES,
            'wholeFlakeEvaluated': False, 'realized': False, 'browserExecuted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('roots', 'lock', 'selection', 'flake'):
        parser.add_argument('--' + name, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--nix', required=True)
    parser.add_argument('--source-input', required=True)
    args = parser.parse_args()
    handlers = {}
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            handlers[signum] = signal.signal(signum, interrupted)
        print(json.dumps(qualify(args), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        known_codes = {'declared-input-digest', 'site-pin', 'source-declaration-binding', 'declared-source', 'declared-nix', 'shared-selection-not-referenced', 'source-nar-hash-mismatch'}
        result = {'schemaVersion': 1, 'passed': False, 'gate': 'site-selection-qualification-unavailable',
                  'phase': getattr(args, 'failure_phase', 'input-binding'), 'code': 'bounded-input-or-execution-unavailable'}
        result.update(exception_diagnostics(error))
        if isinstance(error, QualificationError):
            result.update({'phase': error.phase, 'code': error.code, 'diagnostics': error.details})
        elif isinstance(error, ValueError) and str(error) in known_codes:
            result['code'] = str(error)
        print(json.dumps(result, sort_keys=True))
        return 2
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
