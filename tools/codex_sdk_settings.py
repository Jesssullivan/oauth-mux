"""Derive the exact locked SDK test PATH without realization or daemon access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from fetch_codex_archives import PINNED_NIX
from qualify_site_tools import evaluate, mapping_command

ROOT = Path(__file__).parent.parent
SOURCE = Path('/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source')
FLAKE_SHA = '2c7fbc134cf1d46c435b5cb1fcba9b5b335745d3efff84c55e334ad2523c9d4f'
LOCK_SHA = '2dc0211d0aa355e3011a17bbfacbf81140a79bf736f9facb53d2836019a51cb8'
REVISION = '0726a0ecb6d4e08f6adced58726b95db924cef57'
NAR = 'sha256-EHq1/OX139R1RvBzOJ0aMRT3xnWyqtHBRUBuO1gFzjI='
TOOLS = ('bash', 'coreutils', 'python3', 'git', 'gawk', 'gnugrep', 'gnused', 'findutils')
EXECUTABLES = ('bash', 'env', 'python3', 'git', 'awk', 'grep', 'sed', 'find')
DECLARATION = 'codexTestPath = pkgs.lib.makeBinPath [ ' + ' '.join('pkgs.' + tool for tool in TOOLS) + ' ];'
SUFFIX = 'codex-sdk-settings'


def require(value, message):
    if not value:
        raise ValueError(message)


def read_input(path, expected):
    descriptor = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024 * 1024, 'declared input bound')
        content = os.read(descriptor, 1024 * 1024 + 1)
        require(hashlib.sha256(content).hexdigest() == expected, 'declared input digest')
        return content
    finally:
        os.close(descriptor)


def validate_inputs(flake, lock):
    require(flake.decode().count(DECLARATION) == 1, 'locked tool declaration drift')
    pinned = json.loads(lock)['nodes']['nixpkgs']['locked']
    require(pinned['rev'] == REVISION and pinned['narHash'] == NAR, 'locked source drift')


def expression():
    selection = '; '.join(tool + ' = toString pkgs.' + tool for tool in TOOLS)
    return ('let pkgs = import ' + str(SOURCE) + ' { system = "x86_64-linux"; config = {}; overlays = []; }; in { ' +
            selection + '; testPath = pkgs.lib.makeBinPath [ ' + ' '.join('pkgs.' + tool for tool in TOOLS) + ' ]; }')


def verify_mapping(mapping, exists=os.path.isfile, executable=lambda path: os.access(path, os.X_OK)):
    require(isinstance(mapping, dict) and set(mapping) == set(TOOLS) | {'testPath'}, 'tool mapping shape')
    paths = []
    binaries = {}
    for tool, name in zip(TOOLS, EXECUTABLES):
        root = mapping[tool]
        require(isinstance(root, str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/:\s]+', root), 'tool output path')
        binary = root + '/bin/' + name
        require(exists(binary) and executable(binary), 'locked tool unavailable: ' + tool)
        binaries[tool] = binary
        paths.append(root + '/bin')
    require(mapping['testPath'] == ':'.join(paths), 'locked PATH mismatch')
    return mapping['testPath'], binaries


def rc_bytes(distdir, test_path):
    require(isinstance(distdir, str) and distdir.startswith('/') and
            not any(character.isspace() for character in distdir) and
            not any(part in ('', '.', '..') for part in distdir.split('/')[1:]), 'distdir must be explicit canonical path')
    return ('common --distdir=' + distdir + '\ntest --test_env=PATH=' + test_path + '\n').encode()


def produce(nix, distdir, output, evaluator=evaluate):
    report = {'schema_version': 1, 'status': 'blocked', 'native_support': False,
              'native_proof': False, 'flake_sha256': FLAKE_SHA, 'lock_sha256': LOCK_SHA,
              'nixpkgs_source': str(SOURCE), 'nixpkgs_revision': REVISION, 'nixpkgs_nar_hash': NAR,
              'tool_order': list(TOOLS), 'distdir': str(distdir), 'realization': False,
              'scope': 'fixed source eval plus actual executable availability; no compilation or continuity proof'}
    output.mkdir(mode=0o700)
    try:
        require(Path(nix).resolve(strict=True) == PINNED_NIX, 'evaluator pin mismatch')
        require(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir(), 'locked source unavailable')
        require(distdir.resolve(strict=True) == distdir and distdir.is_dir(), 'distdir custody')
        validate_inputs(read_input(ROOT / 'flake.nix', FLAKE_SHA), read_input(ROOT / 'flake.lock', LOCK_SHA))
        with tempfile.TemporaryDirectory(prefix='codex-settings-eval-', dir=os.environ['TEST_TMPDIR']) as scratch:
            observed = evaluator([str(PINNED_NIX), '--extra-experimental-features', 'nix-command',
                                  '--store', 'dummy://', 'hash', 'path', '--type', 'sha256', '--sri', str(SOURCE)],
                                 scratch, json_output=False, phase='codex-settings-source-hash')
            require(observed == NAR, 'source NAR mismatch')
            private_store = Path(scratch) / 'evaluation-store'
            private_store.mkdir(mode=0o700)
            mapping = evaluator(mapping_command(str(PINNED_NIX), expression(), private_store), scratch,
                                phase='codex-settings-evaluation', private_store=private_store)
        test_path, binaries = verify_mapping(mapping)
        content = rc_bytes(str(distdir), test_path)
        with (output / 'sdk-settings.bazelrc').open('xb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        report.update(status='verified-locked-settings', test_path=test_path, tools=binaries,
                      bash=binaries['bash'], all_tools_available=True,
                      rc_sha256=hashlib.sha256(content).hexdigest(), rc_bytes=len(content))
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['blocked_reason'] = type(error).__name__
        if isinstance(error, ValueError):
            report['blocked_reason'] = str(error)[:128]
    with (output / 'sdk-settings-receipt.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return 0 if report['status'] == 'verified-locked-settings' else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nix', required=True)
    parser.add_argument('--distdir', type=Path, required=True)
    args = parser.parse_args()
    output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True) / SUFFIX
    return produce(args.nix, args.distdir, output)


if __name__ == '__main__':
    raise SystemExit(main())
