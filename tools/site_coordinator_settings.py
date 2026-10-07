"""Offline candidate settings only; never qualifies or invokes the coordinator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from codex_sdk_settings import read_input, require
from fetch_codex_archives import PINNED_NIX
from qualify_site_tools import evaluate, mapping_command

SITE = Path('/srv/fast-local/jess/git/omux.xoxd.ai')
SOURCE = Path('/nix/store/l61vfkyy0qrnz9bmgx84fa7z3bjzhyp4-source')
REVISION = '1c3fe55ad329cbcb28471bb30f05c9827f724c76'
NAR = 'sha256-bxrdOn8SCOv8tN4JbTF/TXq7kjo9ag4M+C8yzzIRYbE='
INPUTS = {
    'flake.nix': 'ae04bb4a08b0627ca0c778e1cb8163d8493b60f9caaf65d6b400659afd6f7039',
    'flake.lock': '8bf597bc60b2cf908a5e1772256e178e9593d0474434f4407ee1247bed38197a',
    'tools/offline-site-roots.json': '0414b0102496d85ec10818d45dc127c605a51a18ae2f7df53db6e5d1e9a72d27',
    'tools/tool-selection.nix': '6ab7f828fcf92df8394869029462541ce0a495bcd14ff7dc9c25c4c469abc2c7',
}
EXPECTED_BAZEL = '/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1'
EXPECTED_JDK = '/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7'


def expression():
    # All interpolated strings are fixed source constants, never operator expressions.
    return ('let pkgs = import ' + str(SOURCE) + ' { system = "x86_64-linux"; config = {}; overlays = []; }; '
            'in { bazel = toString pkgs.bazel_9; bazel_version = pkgs.bazel_9.version; '
            'java_home = toString pkgs.jdk_headless; java_version = pkgs.jdk_headless.version; }')


def validate_inputs(contents):
    require(set(contents) == set(INPUTS), 'site input set differs')
    for name, expected in INPUTS.items():
        require(hashlib.sha256(contents[name]).hexdigest() == expected, 'site input digest differs: ' + name)
    locked = json.loads(contents['flake.lock'])['nodes']['nixpkgs']['locked']
    require(locked['rev'] == REVISION and locked['narHash'] == NAR, 'site lock source differs')


def candidate(mapping, exists=os.path.isfile, executable=lambda path: os.access(path, os.X_OK),
              canonical=lambda path: str(Path(path).resolve(strict=True))):
    require(isinstance(mapping, dict) and set(mapping) == {'bazel', 'bazel_version', 'java_home', 'java_version'},
            'coordinator mapping shape')
    require(mapping['bazel_version'] == '9.0.1' and mapping['java_version'] == '21.0.10+7', 'coordinator versions differ')
    for key, binary in (('bazel', 'bazel'), ('java_home', 'java')):
        root = mapping[key]
        require(isinstance(root, str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._-]+', root), 'coordinator output path')
        require(canonical(root) == root, 'coordinator output root is not canonical: ' + key)
        path = root + '/bin/' + binary
        require(exists(path) and executable(path), 'coordinator executable unavailable: ' + key)
        permitted = {path}
        if key == 'java_home':
            permitted.add(root + '/lib/openjdk/bin/java')
        require(canonical(path) in permitted, 'coordinator executable is not canonical: ' + key)
    matches = mapping['bazel'] == EXPECTED_BAZEL and mapping['java_home'] == EXPECTED_JDK
    return dict(mapping, bazel=mapping['bazel'] + '/bin/bazel', runtime_outputs_match=matches,
                status='candidate-settings-only', execution_authority=False, binary_versions_verified=False,
                closure_verified=False)


def produce(nix, inputs, output, evaluator=evaluate):
    report = {'schema_version': 1, 'status': 'blocked', 'execution_authority': False,
              'source': str(SOURCE), 'source_revision': REVISION, 'source_nar_hash': NAR,
              'input_sha256': INPUTS, 'realization': False}
    output.mkdir(mode=0o700)
    try:
        require(Path(nix).resolve(strict=True) == PINNED_NIX, 'evaluator pin mismatch')
        validate_inputs({name: read_input(Path(inputs[name]), digest) for name, digest in INPUTS.items()})
        require(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir(), 'site source unavailable')
        with tempfile.TemporaryDirectory(prefix='site-coordinator-eval-', dir=os.environ['TEST_TMPDIR']) as scratch:
            observed = evaluator([str(PINNED_NIX), '--extra-experimental-features', 'nix-command', '--store', 'dummy://',
                                  'hash', 'path', '--type', 'sha256', '--sri', str(SOURCE)], scratch,
                                 json_output=False, phase='site-coordinator-source-hash')
            require(observed == NAR, 'site source NAR differs')
            store = Path(scratch) / 'evaluation-store'
            store.mkdir(mode=0o700)
            mapping = evaluator(mapping_command(str(PINNED_NIX), expression(), store), scratch,
                                phase='site-coordinator-evaluation', private_store=store)
        report.update(candidate(mapping))
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['blocked_reason'] = str(error)[:160] if isinstance(error, ValueError) else type(error).__name__
    content = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    with (output / 'site-coordinator-settings.json').open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'status': report['status'], 'receipt_sha256': hashlib.sha256(content).hexdigest(),
                      'execution_authority': False}, sort_keys=True))
    return 0 if report['status'] == 'candidate-settings-only' else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nix', required=True)
    for name in INPUTS:
        parser.add_argument('--' + name.replace('/', '-').replace('.', '-'), required=True)
    args = vars(parser.parse_args())
    inputs = {name: args[name.replace('/', '_').replace('.', '_').replace('-', '_')] for name in INPUTS}
    return produce(args['nix'], inputs, Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True) / 'site-coordinator-settings')


if __name__ == '__main__':
    raise SystemExit(main())
