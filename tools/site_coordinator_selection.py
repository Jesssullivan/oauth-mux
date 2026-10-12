"""Closed public selectors for genuine site prerequisite outputs; never executes tools."""
import hashlib
import json
from pathlib import Path
import re
import stat

from site_coordinator_qualification import CANDIDATE_SHA256, file_bytes

ROOTS = (Path('/home/jess/.local/state/omux-execution-20261005'),
         Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'))
VARIABLE = 'OMUX_SITE_COORDINATOR_INPUTS'
SHA_VARIABLE = VARIABLE + '_SHA256'
LABELS = {'//tools:site_coordinator_binary_qualification': False,
          '//tools:site_coordinator_closure_qualification': True}
SUFFIXES = {
    'candidate': 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/site_coordinator_settings_producer/test.outputs/site-coordinator-settings/site-coordinator-settings.json',
    'version': 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/site_coordinator_binary_qualification/test.outputs/site-coordinator-qualification/site-coordinator-qualification.json',
}
EPOCH = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'duplicate site coordinator selection field')
        result[key] = value
    return result


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact selection digest required')
    return value


def location(value, kind):
    require(type(value) is str and value.startswith('/') and not any(c.isspace() for c in value),
            'canonical selected producer path required')
    path = Path(value)
    require('..' not in path.parts and str(path) == value, 'selected path alias rejected')
    root = next((root for root in ROOTS if path.is_relative_to(root)), None)
    require(root is not None, 'selected output outside owned execution state')
    parts = path.relative_to(root).parts
    suffix = ('site-coordinator-inputs.json',) if kind == 'selection' else Path(SUFFIXES[kind]).parts
    require(len(parts) > 1 and re.fullmatch(EPOCH, parts[0]) and parts[1:] == suffix,
            'only exact current epoch producer outputs accepted')
    return path


def owned_bytes(path, maximum):
    require(Path(path).resolve(strict=True) == Path(path), 'selected input aliases rejected')
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'single-link regular selection required')
    return file_bytes(path, maximum)[0]


def read_descriptor(path, expected_sha256):
    path = location(str(path), 'selection')
    content = owned_bytes(path, 16384)
    require(hashlib.sha256(content).hexdigest() == digest(expected_sha256), 'selection bytes differ')
    value = json.loads(content, object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == {'schema_version', 'candidate', 'version'} and
            type(value['schema_version']) is int and value['schema_version'] == 1, 'selection schema differs')
    for kind in ('candidate', 'version'):
        row = value[kind]
        if row is None and kind == 'version':
            continue
        require(type(row) is dict and set(row) == {'path', 'sha256'}, 'selected receipt fields differ')
        location(row['path'], kind)
        digest(row['sha256'])
    require(value['candidate']['sha256'] == CANDIDATE_SHA256, 'candidate immutable input binding differs')
    return value


def admitted(profile, arguments, path=None, expected_sha256=None):
    selected = profile == 'standard' and len(arguments) == 2 and arguments[0] == 'test' and arguments[1] in LABELS
    if path is None and expected_sha256 is None:
        require(not selected, 'fresh site producer selection required')
        return False
    require(selected and path is not None and expected_sha256 is not None,
            'coordinator selection requires one exact standard producer target')
    value = read_descriptor(path, expected_sha256)
    require(not LABELS[arguments[1]] or value['version'] is not None, 'closure requires selected version receipt')
    require(LABELS[arguments[1]] or value['version'] is None, 'version producer forbids a selected version receipt')
    for kind, row in value.items():
        if kind not in SUFFIXES or row is None:
            continue
        require(hashlib.sha256(owned_bytes(row['path'], 65536)).hexdigest() == row['sha256'],
                'selected original producer bytes differ')
    return True


def projected(selection, sha_file, candidate_file, version_file=None):
    # The repository copies exact descriptor and payload bytes into declared data.
    raw = file_bytes(Path(selection).resolve(strict=True), 16384)[0]
    expected = file_bytes(Path(sha_file).resolve(strict=True), 65)[0]
    require(expected.endswith(b'\n') and len(expected) == 65, 'selection digest file differs')
    require(hashlib.sha256(raw).hexdigest() == digest(expected[:-1].decode('ascii')), 'declared selection bytes differ')
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == {'schema_version', 'candidate', 'version'} and
            type(value['schema_version']) is int and value['schema_version'] == 1, 'selection schema differs')
    for kind, path in (('candidate', candidate_file), ('version', version_file)):
        row = value[kind]
        if kind == 'version' and path is None:
            require(row is None, 'version producer forbids version input')
            continue
        require(type(row) is dict and set(row) == {'path', 'sha256'}, 'selected receipt fields differ')
        location(row['path'], kind)
        digest(row['sha256'])
        content = file_bytes(Path(path).resolve(strict=True), 65536)[0]
        require(hashlib.sha256(content).hexdigest() == row['sha256'], 'declared producer bytes differ')
    require(value['candidate']['sha256'] == CANDIDATE_SHA256, 'candidate immutable input binding differs')
    return value
