"""Qualify the fixed site's complete registered Bazel/JDK closure without realization.

The existing candidate and binary/version receipts remain separate evidence.
Only the outer controller can admit a site workload; this producer never does.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess

from cached_nix_inventory import MAX_REFS, snapshot_inventory
from site_coordinator_qualification import file_bytes
from verify_cached_nars import MAX_INPUT, MAX_PATHS, STORE, parse_inventory, verify

STATE = Path('/home/jess/.local/state/omux-execution-20261005')
CACHE = STATE / 'cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee'
TESTLOGS = CACHE / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools'
CANDIDATE = TESTLOGS / 'site_coordinator_settings_producer/test.outputs/site-coordinator-settings/site-coordinator-settings.json'
CANDIDATE_SHA256 = '48253bf1b32bc341baadbe77e9fc983ad898c338166009e92e9e2f0047e7e55c'
VERSION_RECEIPT = TESTLOGS / 'site_coordinator_binary_qualification/test.outputs/site-coordinator-qualification/site-coordinator-qualification.json'
VERSION_RECEIPT_SHA256 = 'a1d7e2b974c6a548245b88c07a7cce921dd1fcb31758d0ee5c50511ca3780ccd'
SITE = Path('/srv/fast-local/jess/git/omux.xoxd.ai')
SOURCE = '/nix/store/l61vfkyy0qrnz9bmgx84fa7z3bjzhyp4-source'
REVISION = '1c3fe55ad329cbcb28471bb30f05c9827f724c76'
SOURCE_NAR = 'sha256-bxrdOn8SCOv8tN4JbTF/TXq7kjo9ag4M+C8yzzIRYbE='
INPUTS = {
    'flake.nix': 'ae04bb4a08b0627ca0c778e1cb8163d8493b60f9caaf65d6b400659afd6f7039',
    'flake.lock': '8bf597bc60b2cf908a5e1772256e178e9593d0474434f4407ee1247bed38197a',
    'tools/offline-site-roots.json': '0414b0102496d85ec10818d45dc127c605a51a18ae2f7df53db6e5d1e9a72d27',
    'tools/tool-selection.nix': '6ab7f828fcf92df8394869029462541ce0a495bcd14ff7dc9c25c4c469abc2c7',
}
SITE_VERSION_SHA256 = '59b003a1f3465ae6084432329f8265e860cbaac0bd4a92a4f3ea6b979a6eed66'
BAZEL_ROOT = '/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1'
JDK = '/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7'
ROOTS = tuple(sorted((BAZEL_ROOT, JDK)))
BAZEL = BAZEL_ROOT + '/bin/bazel'
BAZEL_NATIVE = BAZEL_ROOT + '/bin/.bazel-9.0.1-linux-x86_64-wrapped'
JAVA_NATIVE = JDK + '/lib/openjdk/bin/java'
NIX = '/nix/store/fphbr6vvc2fdmx02nkagnbx0nv04f709-nix-2.34.6/bin/nix'
DATABASE = '/nix/var/nix/db/db.sqlite'
BINARIES = {
    'bazel': {'path': BAZEL_NATIVE, 'sha256': 'd8f861255a5db95bdadceca1ec7bed4c34bcc3fd44a35ab76ba4a8f1f4ab25f6', 'bytes': 43577663, 'mode': '0o555'},
    'java': {'path': JAVA_NATIVE, 'sha256': '8d1dd46c09ca913c91b2c5267e758395f35a33dbd04b227be68ea700d0e451bb', 'bytes': 21288, 'mode': '0o555'},
}
WRAPPERS = {
    'bazel_wrapper': {'path': BAZEL, 'sha256': '8efb4b7a078f9d43980aaff910b405516b12a10efe3dfc7ece752a466ad3f42b', 'bytes': 9017, 'mode': '0o555'},
    'bazel_package_wrapper': {'path': BAZEL_ROOT + '/bin/bazel-9.0.1-linux-x86_64', 'sha256': '2219e541668563d30c2ae37092d227710607e22912a75f4ddf4bee88796bc303', 'bytes': 3885, 'mode': '0o555'},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(payload):
    return json.loads(payload, object_pairs_hook=unique_object)


def selected_receipt(path, selected_digest, expected_digest):
    require(selected_digest == expected_digest, 'receipt selection differs from fixed producer')
    content, facts = file_bytes(path, 65536)
    require(facts['sha256'] == expected_digest, 'retained receipt bytes differ')
    return decode(content)


def validate_evidence(candidate, version, inputs, site_version):
    require(type(candidate) is dict and candidate.get('schema_version') == 1 and
            candidate.get('status') == 'candidate-settings-only', 'candidate schema/status differs')
    expected = {'bazel': BAZEL, 'java_home': JDK, 'bazel_version': '9.0.1',
                'java_version': '21.0.10+7', 'source': SOURCE, 'source_revision': REVISION,
                'source_nar_hash': SOURCE_NAR, 'input_sha256': INPUTS}
    require(all(candidate.get(key) == value for key, value in expected.items()), 'candidate pin/provenance differs')
    require(candidate.get('runtime_outputs_match') is True and candidate.get('realization') is False and
            candidate.get('execution_authority') is False and candidate.get('closure_verified') is False and
            candidate.get('binary_versions_verified') is False, 'candidate claim boundary differs')
    require(type(version) is dict and version.get('schema_version') == 1 and
            version.get('status') == 'version-and-byte-qualified-site-coordinator' and
            version.get('binary_versions_verified') is True and version.get('closure_verified') is False and
            version.get('execution_authority') is False, 'binary receipt claim boundary differs')
    require(all(version.get(key) == expected[key] for key in ('bazel', 'java_home', 'bazel_version', 'java_version')) and
            version.get('candidate') == str(CANDIDATE) and version.get('candidate_sha256') == CANDIDATE_SHA256,
            'binary receipt candidate binding differs')
    require(version.get('binaries') == BINARIES and
            all(version.get(key) == facts for key, facts in WRAPPERS.items()), 'binary receipt native identities differ')
    require(version.get('site_bazelversion') == {'sha256': SITE_VERSION_SHA256, 'bytes': 6, 'mode': '0o644'},
            'binary receipt site version binding differs')
    require(set(inputs) == set(INPUTS), 'site input set differs')
    require(all(hashlib.sha256(inputs[name]).hexdigest() == digest for name, digest in INPUTS.items()),
            'site input bytes differ')
    locked = decode(inputs['flake.lock'])['nodes']['nixpkgs']['locked']
    require(locked.get('rev') == REVISION and locked.get('narHash') == SOURCE_NAR, 'site lock source differs')
    require(hashlib.sha256(site_version).hexdigest() == SITE_VERSION_SHA256 and site_version == b'9.0.1\n',
            'site Bazel version bytes differ')


def immutable_store_object(path):
    """Check canonical registered objects without following top-level aliases."""
    require(isinstance(path, str) and STORE.fullmatch(path), 'closure store path differs')
    require(str(Path(path).resolve(strict=True)) == path, 'closure store alias rejected')
    parent = os.open('/nix/store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1775, 'immutable store custody differs')
        info = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        require((stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and info.st_uid == 0 and
                not info.st_mode & 0o222, 'registered closure object is writable or foreign')
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    finally:
        os.close(parent)


def current_binary_identities():
    observed = {}
    for key, expected in {**BINARIES, **WRAPPERS}.items():
        payload, facts = file_bytes(expected['path'], 256 * 1024 * 1024, immutable=True)
        require(dict(facts, path=expected['path']) == expected, 'current coordinator binary bytes differ')
        require(payload.startswith(b'#!' if key in WRAPPERS else b'\x7fELF'), 'coordinator executable format differs')
        observed[key] = dict(facts, path=expected['path'])
    java_entry = str((Path(JDK) / 'bin/java').resolve(strict=True))
    require(java_entry in (JDK + '/bin/java', JAVA_NATIVE), 'Java executable alias differs')
    java_bytes, java_facts = file_bytes(java_entry, 256 * 1024 * 1024, immutable=True)
    require(java_bytes.startswith(b'\x7fELF') and dict(java_facts, path=JAVA_NATIVE) == BINARIES['java'],
            'JDK Java entry bytes differ from qualified native identity')
    return observed


def closure_inventory(rows):
    require(type(rows) is list and 1 <= len(rows) <= MAX_PATHS, 'closure path bound')
    references = 0
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'narHash', 'narSize', 'references'} and
                type(row['references']) is list, 'closure row schema differs')
        refs = row['references']
        references += len(refs)
        require(references <= MAX_REFS and
                all(isinstance(ref, str) and STORE.fullmatch(ref) for ref in refs) and refs == sorted(set(refs)),
                'closure reference schema or bound differs')
    inventory = {'schemaVersion': 1, 'system': 'x86_64-linux',
                 'mode': 'local-sqlite-readonly-snapshot', 'roots': list(ROOTS), 'paths': rows,
                 'provenance': {'candidateSha256': CANDIDATE_SHA256,
                                'binaryQualificationSha256': VERSION_RECEIPT_SHA256,
                                'inputSha256': INPUTS},
                 'contentRehashed': False, 'realized': False, 'published': False}
    content = (json.dumps(inventory, sort_keys=True, separators=(',', ':')) + '\n').encode()
    digest = hashlib.sha256(content).hexdigest()
    require(len(content) <= MAX_INPUT, 'closure inventory byte bound')
    parsed = parse_inventory(content, digest)
    graph = {row['path']: row['references'] for row in parsed}
    require([row['path'] for row in parsed] == sorted(graph), 'closure rows are not canonical')
    reachable, pending = set(), list(ROOTS)
    while pending:
        path = pending.pop()
        if path not in reachable:
            reachable.add(path)
            pending.extend(graph[path])
    require(reachable == set(graph), 'closure contains unrelated paths')
    return inventory, content, digest


def qualify_closure(rows, nix, verifier=verify, observer=immutable_store_object):
    require(nix == NIX, 'NAR serializer pin differs')
    inventory, content, digest = closure_inventory(rows)
    prior = {row['path']: observer(row['path']) for row in inventory['paths']}
    receipt = verifier(content, digest, nix)
    require(type(receipt) is dict and receipt.get('schemaVersion') == 1 and receipt.get('passed') is True and
            receipt.get('contentRehashed') is True and receipt.get('realized') is False and
            receipt.get('published') is False and receipt.get('flakeMappingVerified') is False and
            receipt.get('inventorySha256') == digest and type(receipt.get('verifiedPaths')) is int and
            receipt['verifiedPaths'] == len(rows) and type(receipt.get('verifiedNarBytes')) is int and
            receipt['verifiedNarBytes'] == sum(row['narSize'] for row in rows), 'NAR qualification coverage differs')
    require(all(observer(path) == info for path, info in prior.items()), 'closure object custody changed')
    return inventory, content, digest, receipt


def write_exclusive(directory, name, content):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private evidence directory required')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def produce(nix, candidate_sha256, version_sha256, output, snapshotter=snapshot_inventory,
            verifier=verify, observer=immutable_store_object):
    candidate = selected_receipt(CANDIDATE, candidate_sha256, CANDIDATE_SHA256)
    version = selected_receipt(VERSION_RECEIPT, version_sha256, VERSION_RECEIPT_SHA256)
    require(SITE.resolve(strict=True) == SITE, 'site source alias rejected')
    inputs = {name: file_bytes(SITE / name, 1024 * 1024)[0] for name in INPUTS}
    site_version = file_bytes(SITE / '.bazelversion', 64)[0]
    validate_evidence(candidate, version, inputs, site_version)
    resolved_nix = str(Path(nix).resolve(strict=True))
    require(resolved_nix == NIX, 'declared Nix pin differs')
    nix_bytes, nix_facts = file_bytes(NIX, 256 * 1024 * 1024, immutable=True)
    require(nix_bytes.startswith(b'\x7fELF') and int(nix_facts['mode'], 8) & 0o111, 'NAR serializer is not immutable native executable')
    identities = current_binary_identities()
    rows = snapshotter(DATABASE, list(ROOTS))
    inventory, content, digest, nar = qualify_closure(rows, resolved_nix, verifier, observer)
    require(current_binary_identities() == identities, 'coordinator native identity changed')
    # Rebind mutable retained evidence and site inputs after the bounded NAR pass.
    require(selected_receipt(CANDIDATE, candidate_sha256, CANDIDATE_SHA256) == candidate and
            selected_receipt(VERSION_RECEIPT, version_sha256, VERSION_RECEIPT_SHA256) == version,
            'selected evidence changed')
    validate_evidence(candidate, version,
                      {name: file_bytes(SITE / name, 1024 * 1024)[0] for name in INPUTS},
                      file_bytes(SITE / '.bazelversion', 64)[0])
    report = {'schema_version': 1, 'status': 'verified-site-toolchain',
              'bazel': BAZEL, 'bazel_executable': BAZEL_NATIVE, 'java_home': JDK,
              'bazel_version': '9.0.1', 'java_version': '21.0.10+7',
              'binary_versions_verified': True, 'closure_verified': True, 'execution_authority': False,
              'closure_binding': 'complete-registered-reference-closure',
              'roots': list(ROOTS), 'inventory': 'coordinator-inventory.json',
              'inventory_sha256': digest, 'verified_paths': len(rows),
              'verified_nar_bytes': nar['verifiedNarBytes'], 'nar_verification': nar,
              'candidate': str(CANDIDATE), 'candidate_sha256': CANDIDATE_SHA256,
              'binary_qualification': str(VERSION_RECEIPT), 'binary_qualification_sha256': VERSION_RECEIPT_SHA256,
              'source': SOURCE, 'source_revision': REVISION, 'source_nar_hash': SOURCE_NAR,
              'source_binding': 'exact-retained-offline-candidate-receipt; not freshly rehashed here',
              'input_sha256': INPUTS, 'site_bazelversion_sha256': SITE_VERSION_SHA256,
              'binaries': {key: identities[key] for key in BINARIES},
              'wrappers': {key: identities[key] for key in WRAPPERS},
              'dispatch_binding': 'fixed native ELF; generic workspace-dispatch launcher not executed',
              'nix': dict(nix_facts, path=NIX), 'database_mode': 'sqlite-mode-ro-transaction-snapshot',
              'content_rehashed': True, 'link_targets_followed': False, 'realized': False, 'published': False}
    output = Path(output)
    require(output.is_absolute() and '..' not in output.parts, 'canonical evidence output required')
    output.mkdir(mode=0o700)
    write_exclusive(output, 'coordinator-inventory.json', content)
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    write_exclusive(output, 'site-coordinator-closure-qualification.json', report_bytes)
    return {'status': report['status'], 'receipt_sha256': hashlib.sha256(report_bytes).hexdigest(),
            'inventory_sha256': digest, 'verified_paths': len(rows), 'execution_authority': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nix', required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--binary-qualification-sha256', required=True)
    args = parser.parse_args()
    try:
        output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True) / 'site-coordinator-closure-qualification'
        result = produce(args.nix, args.candidate_sha256, args.binary_qualification_sha256, output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError, KeyboardInterrupt):
        print(json.dumps({'status': 'site-coordinator-closure-qualification-unavailable',
                          'closure_verified': False, 'execution_authority': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
