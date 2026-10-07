"""Finite SPA admission and source fences; this module never launches tools."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from site_coordinator_qualification import BAZEL, BAZEL_NATIVE, JDK, CANDIDATE_SHA256, file_bytes

SITE_SOURCE = Path('/srv/fast-local/jess/git/omux.xoxd.ai')
RUNTIME_SOURCE = Path('/srv/fast-local/jess/git/oauth-mux')
MASKS = ('/etc/bluetooth', '/etc/environment')
QUALIFICATION_LABELS = {'//:qualified_site_tools_test', '//:nix_file_inventory_test', '//:reference_check',
                        '//tools:qualified_site_tools_test', '//tools:nix_file_inventory_test'}
CHECK_LABELS = {'//:unit_tests', '//:svelte_check', '//:reference_check', '//:archive_check'}
BUILD_LABELS = {'//:build', '//:site_archive'}
FETCH_LABELS = QUALIFICATION_LABELS | CHECK_LABELS | BUILD_LABELS | {'//:import_extension_delivery'}
PROOF_FILES = {'mapping': ('delivery/proofs/mapping-96136df1.log', 'd992fe7f4124ce731ae5338b204b993767f3b40b50883d1be1598e3ac367178d'),
               'nar': ('delivery/proofs/nar-120f8b34.log', '42688569613bb69896d4c07f601a543c6b73f89efd27d340158462fb7fd27375')}


def finite_phase(phase, arguments):
    if phase == 'lock':
        if arguments != ['mod', 'deps', '--lockfile_mode=update']:
            raise ValueError('site lock phase permits only exact dependency metadata regeneration')
        return list(arguments)
    permitted = {'qualification': ('test', QUALIFICATION_LABELS), 'checks': ('test', CHECK_LABELS),
                 'build': ('build', {'//:build'}), 'archive': ('build', {'//:site_archive'}),
                 'fetch': ('fetch', FETCH_LABELS)}
    if phase not in permitted:
        raise ValueError('unknown site phase')
    verb, labels = permitted[phase]
    if (not arguments or arguments[0] != verb or len(arguments) < 2 or
            len(set(arguments[1:])) != len(arguments[1:]) or not set(arguments[1:]) <= labels):
        raise ValueError('site phase requires finite explicit labels')
    return list(arguments)


def phase_isolation(phase, arguments):
    if phase == 'import':
        if (len(arguments) != 7 or arguments[:3] != ['run', '//:import_extension_delivery', '--'] or
                arguments[3] != '--manifest' or arguments[5] != '--sha256'):
            raise ValueError('only the exact metadata importer is accepted')
    else:
        finite_phase(phase, arguments)
    return {'PrivateNetwork': 'no' if phase in ('lock', 'fetch') else 'yes'}


def bounded_file(path, expected, maximum):
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('exact source input digest required')
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('canonical source input path required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError('source input ancestor custody rejected')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o022 or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
            raise ValueError('bounded owned source input required')
        content = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, maximum + 1 - len(content))):
            content.extend(chunk)
            if len(content) > maximum:
                raise ValueError('source input exceeds bound')
        after = os.fstat(fd)
        if (len(content) != info.st_size or hashlib.sha256(content).hexdigest() != expected or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('source input bytes differ')
        return bytes(content)
    finally:
        os.close(fd)


def source_binding(source, version_sha256):
    if Path(source) != SITE_SOURCE or SITE_SOURCE.resolve(strict=True) != SITE_SOURCE:
        raise ValueError('only the exact physical sibling site source is accepted')
    if bounded_file(SITE_SOURCE / '.bazelversion', version_sha256, 64).strip() != b'9.0.1':
        raise ValueError('site requires its separately qualified Bazel 9.0.1')


def read_qualification(path, expected_sha256):
    try:
        return _read_qualification(path, expected_sha256)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed coordinator qualification') from error


def _read_qualification(path, expected_sha256):
    """Receipt SHA is independently selected by the operator, never self-attested."""
    import site_coordinator_closure_qualification as full
    report = full.decode(bounded_file(path, expected_sha256, 65536))
    if (report.get('schema_version') != 1 or report.get('status') != 'verified-site-toolchain' or
            report.get('bazel_executable') != str(BAZEL_NATIVE) or
            report.get('binary_qualification') != str(full.VERSION_RECEIPT) or
            report.get('binary_qualification_sha256') != full.VERSION_RECEIPT_SHA256 or
            report.get('candidate') != str(full.CANDIDATE) or
            report.get('candidate_sha256') != full.CANDIDATE_SHA256 or
            report.get('roots') != list(full.ROOTS) or report.get('inventory') != 'coordinator-inventory.json' or
            report.get('closure_binding') != 'complete-registered-reference-closure' or
            report.get('binary_versions_verified') is not True or report.get('execution_authority') is not False or
            report.get('published') is not False or report.get('link_targets_followed') is not False):
        raise ValueError('complete independent coordinator qualification required')
    candidate = full.selected_receipt(full.CANDIDATE, full.CANDIDATE_SHA256, full.CANDIDATE_SHA256)
    version = full.selected_receipt(full.VERSION_RECEIPT, full.VERSION_RECEIPT_SHA256, full.VERSION_RECEIPT_SHA256)
    full.validate_evidence(candidate, version,
        {name: bounded_file(SITE_SOURCE / name, digest, 1024 * 1024) for name, digest in full.INPUTS.items()},
        bounded_file(SITE_SOURCE / '.bazelversion', full.SITE_VERSION_SHA256, 64))
    if (report.get('input_sha256') != full.INPUTS or
            report.get('site_bazelversion_sha256') != full.SITE_VERSION_SHA256 or
            report.get('binaries') != full.BINARIES or report.get('wrappers') != full.WRAPPERS):
        raise ValueError('qualification input/binary pins differ')
    inventory_bytes = bounded_file(Path(path).parent / report['inventory'], report.get('inventory_sha256'), 8 * 1024 * 1024)
    inventory = full.decode(inventory_bytes)
    canonical, content, digest = full.closure_inventory(inventory.get('paths'))
    if inventory != canonical or inventory_bytes != content or digest != report['inventory_sha256']:
        raise ValueError('coordinator closure inventory differs')
    nar = report.get('nar_verification', {})
    count = len(canonical['paths'])
    size = sum(row['narSize'] for row in canonical['paths'])
    if (nar.get('schemaVersion') != 1 or nar.get('passed') is not True or
            nar.get('contentRehashed') is not True or nar.get('realized') is not False or
            nar.get('published') is not False or nar.get('flakeMappingVerified') is not False or
            nar.get('inventorySha256') != digest or type(nar.get('verifiedPaths')) is not int or
            nar['verifiedPaths'] != count or type(nar.get('verifiedNarBytes')) is not int or
            nar['verifiedNarBytes'] != size or report.get('verified_paths') != count or
            report.get('verified_nar_bytes') != size):
        raise ValueError('coordinator full NAR byte coverage is unproved')
    for row in canonical['paths']:
        full.immutable_store_object(row['path'])
    identities = full.current_binary_identities()
    if any(identities[key] != facts for key, facts in {**full.BINARIES, **full.WRAPPERS}.items()):
        raise ValueError('current native coordinator identity differs')
    selected = dict(report, receipt_sha256=expected_sha256)
    toolchain_binding(BAZEL_NATIVE, JDK, selected)
    return selected


def validate_delivery_metadata(content):
    import site_coordinator_closure_qualification as full
    value = full.decode(content)
    def shape(item, fields):
        if type(item) is not dict or set(item) != set(fields):
            raise ValueError('unexpected delivery metadata fields')
    shape(value, ('schema_version', 'channel', 'instance', 'source', 'artifact', 'extension',
                  'native_host', 'protocol_version', 'capability_limits', 'signing'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            type(value['protocol_version']) is not int or value['protocol_version'] != 1 or
            value['channel'] != 'development' or value['instance'] != 'dev' or
            value['native_host'] != 'ai.xoxd.omux.dev'):
        raise ValueError('development delivery channel/schema required')
    shape(value['source'], ('commit', 'dirty'))
    shape(value['artifact'], ('filename', 'sha256', 'bytes', 'format'))
    shape(value['extension'], ('id', 'version', 'browser'))
    source, artifact, extension = value['source'], value['artifact'], value['extension']
    def matches(pattern, item):
        return isinstance(item, str) and re.fullmatch(pattern, item)
    if (not matches('[a-f0-9]{40}|[a-f0-9]{64}', source['commit']) or type(source['dirty']) is not bool or
            not matches(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip', artifact['filename']) or
            not matches('[a-f0-9]{64}', artifact['sha256']) or type(artifact['bytes']) is not int or
            not 0 < artifact['bytes'] <= 9007199254740991 or artifact['format'] != 'zip' or
            not matches('[a-p]{32}', extension['id']) or not matches(r'\d+(\.\d+){0,3}', extension['version']) or
            extension['browser'] != 'chromium'):
        raise ValueError('delivery metadata provenance/artifact differs')
    limits = {'max_message_bytes': 262144, 'max_secret_bytes': 8192, 'max_capsule_bytes': 131072,
              'provider_acquisition': 'experimental', 'native_continuity': 'unproved'}
    if value['capability_limits'] != limits or value['signing'] != {'status': 'unsigned', 'store_publication': 'unpublished'}:
        raise ValueError('delivery capability/publication claim differs')
    return value


def required_masks(observed):
    if not set(MASKS).issubset(observed):
        raise ValueError('both host configuration masks must be verified before site execution')


def proof_bindings(inventory, inventory_sha256, inventory_validator, state_root, coordination_root):
    """Reuse the controller's exact retained inventory selector; no new path lane."""
    selected = inventory_validator(inventory, inventory_sha256, state_root, coordination_root)
    result = {'OMUX_SITE_INVENTORY': str(selected), 'OMUX_SITE_INVENTORY_SHA256': inventory_sha256}
    for name, (relative, digest) in PROOF_FILES.items():
        if digest is None:
            raise ValueError('fresh Bazel 9 mapping receipt not yet retained and bound')
        path = RUNTIME_SOURCE / relative
        bounded_file(path, digest, 8 * 1024 * 1024)
        result['OMUX_SITE_' + name.upper()] = str(path)
        result['OMUX_SITE_' + name.upper() + '_SHA256'] = digest
    return result


def toolchain_binding(bazel, java_home, qualification):
    if not qualification or qualification.get('status') != 'verified-site-toolchain':
        raise ValueError('site Bazel/JDK qualification missing; execution is blocked')
    if Path(bazel) != BAZEL_NATIVE or Path(java_home) != JDK:
        raise ValueError('site dispatch requires the fixed native Bazel ELF and JDK')
    for key, path in (('bazel', BAZEL), ('java_home', JDK)):
        if (not str(path).startswith('/nix/store/') or '..' in path.parts or
                str(path) != qualification.get(key)):
            raise ValueError('site toolchain must match independently verified immutable inputs')
    if qualification.get('bazel_version') != '9.0.1' or not re.fullmatch('[0-9a-f]{64}', qualification.get('receipt_sha256', '')):
        raise ValueError('version-bound site toolchain evidence missing')
    if (qualification.get('candidate_sha256') != CANDIDATE_SHA256 or
            qualification.get('closure_verified') is not True or
            qualification.get('content_rehashed') is not True or
            qualification.get('realized') is not False):
        raise ValueError('full closure and independent candidate evidence required')


def command(bazel, java_home, qualification, output_base, phase, arguments, bindings=None, run=None):
    toolchain_binding(bazel, java_home, qualification)
    if phase == 'import':
        if (len(arguments) != 7 or arguments[:3] != ['run', '//:import_extension_delivery', '--'] or
                arguments[3] != '--manifest' or arguments[5] != '--sha256'):
            raise ValueError('only the exact metadata importer is accepted')
        selected = importer_arguments(arguments[4], arguments[6], qualification.get('delivery_manifest'))
    else:
        selected = finite_phase(phase, arguments)
    output_base = Path(output_base)
    if not output_base.is_absolute() or '..' in output_base.parts or output_base.is_relative_to(SITE_SOURCE):
        raise ValueError('private external owned output base required')
    tests = ['--nocache_test_results', '--nozip_undeclared_test_outputs', '--test_output=errors',
             '--strategy=TestRunner=processwrapper-sandbox', '--test_env=TZ=UTC'] if selected[0] == 'test' else []
    inputs = ['--repo_env=' + key + '=' + value for key, value in sorted((bindings or {}).items())]
    symlinks = ['--symlink_prefix=' + str(Path(run) / 'bazel-')] if run else []
    startup = [str(bazel), '--batch', '--nosystem_rc', '--nohome_rc', '--noworkspace_rc',
            '--server_javabase=' + str(java_home),
            '--host_jvm_args=-Xmx1536m', '--host_jvm_args=-XX:ActiveProcessorCount=2',
            '--output_base=' + str(output_base)]
    registries = [
            '--registry=https://raw.githubusercontent.com/tinyland-inc/bazel-registry/5b85ae10730928abece3bb57994adcfb59c9a6ee/',
            '--registry=https://bcr.bazel.build']
    if phase == 'lock':
        # Bazel 9 mod does not inherit the build command's action options.
        # Outer containment owns resource/delegation bounds; this command only
        # loads the pinned dependency graph and regenerates its metadata.
        return startup + ['mod', '--loading_phase_threads=2', '--lockfile_mode=update'] + registries + inputs + ['deps']
    fetch = ['--nobuild', '--loading_phase_threads=2'] if phase == 'fetch' else []
    # Pinned bazel-lib CopyFile uses a declared hermetic coreutils cp tool and
    # explicitly requires no-sandbox. Keep this one mnemonic local inside the
    # verified outer service; every other action retains sandboxed dispatch.
    copy_strategy = [] if phase == 'fetch' else ['--strategy=CopyFile=local']
    return startup + [selected[0], '--jobs=2', '--lockfile_mode=error'] + fetch + registries + copy_strategy + [
            '--enable_bzlmod', '--incompatible_strict_action_env',
            '--remote_executor=', '--remote_cache=', '--disk_cache=', '--spawn_strategy=sandboxed',
            '--sandbox_default_allow_network=false'] + inputs + symlinks + tests + selected[1:]


def importer_arguments(manifest, expected_sha256, selected_manifest):
    if selected_manifest is None or Path(manifest) != Path(selected_manifest):
        raise ValueError('import must select the exact retained runtime manifest')
    validate_delivery_metadata(bounded_file(manifest, expected_sha256, 16384))
    return ['run', '//:import_extension_delivery', '--', '--manifest', str(manifest), '--sha256', expected_sha256]


def source_snapshot(source):
    """Freeze SPA graph and declared application inputs, excluding generated state."""
    source = Path(source)
    excluded = {'.git', '.direnv', '.svelte-kit', 'build', 'dist', 'node_modules',
                '.pnpm-store', 'test-results', 'coverage', '.claude', '.huskycat'}
    links = {'bazel-bin', 'bazel-out', 'bazel-testlogs', 'bazel-' + source.name}
    rows, total = {}, 0
    deadline = time.monotonic() + 15
    for directory, subdirs, files in os.walk(source, followlinks=False):
        root = Path(directory) == source
        subdirs[:] = sorted(name for name in subdirs if not (root and name in excluded | links))
        for name in subdirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('site source directory aliases rejected')
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(source).as_posix()
            if root and name in links:
                continue
            if root and not (name in {'BUILD.bazel', 'MODULE.bazel', 'MODULE.bazel.lock', 'flake.nix', 'flake.lock',
                                     '.bazelrc', '.bazelversion', '.npmrc', '.prettierrc', '.prettierignore'} or
                             path.suffix in {'.mjs', '.js', '.ts', '.json', '.yaml', '.bzl', '.nix'}):
                continue
            if not root and Path(relative).parts[0] not in {'tools', 'src', 'scripts', 'static', 'docs'}:
                continue
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024 * 1024:
                    raise ValueError('site source requires bounded regular inputs')
                payload = bytearray()
                while chunk := os.read(fd, 1024 * 1024):
                    payload.extend(chunk)
                    total += len(chunk)
                    if total > 64 * 1024 * 1024 or time.monotonic() > deadline:
                        raise ValueError('site source inventory exceeds bound')
                after = os.fstat(fd)
                if (before.st_size != len(payload) or
                        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ValueError('site source changed during snapshot')
                rows[relative] = hashlib.sha256(payload).hexdigest()
                if len(rows) > 4096:
                    raise ValueError('site source inventory exceeds bound')
            finally:
                os.close(fd)
    if not rows:
        raise ValueError('site source inventory is empty')
    return rows


def verify_source_snapshot(before, after, phase):
    permitted = ({'src/lib/content/extension-delivery.json'} if phase == 'import' else
                 {'MODULE.bazel.lock'} if phase == 'lock' else set())
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    if changed - permitted:
        raise ValueError('site source changed outside the selected metadata import')
    return sorted(changed)


def retain_lockfile(source, run, expected_sha256, stage):
    """Preserve exact prior/final lock bytes; never edit or normalize them."""
    if Path(source) != SITE_SOURCE or stage not in ('before', 'after'):
        raise ValueError('only the selected site lock evidence is accepted')
    run = Path(run)
    if not run.is_absolute() or '..' in run.parts:
        raise ValueError('owned absolute epoch required for lock evidence')
    if expected_sha256 is None:
        if stage != 'after':
            raise ValueError('prior lock evidence requires its independently sampled source digest')
        _, facts = file_bytes(SITE_SOURCE / 'MODULE.bazel.lock', 16 * 1024 * 1024)
        expected_sha256 = facts['sha256']
    content = bounded_file(SITE_SOURCE / 'MODULE.bazel.lock', expected_sha256, 16 * 1024 * 1024)
    directory = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private owned epoch required for lock evidence')
        name = 'site-MODULE.bazel.lock.' + stage
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory)
        return {'file': name, 'sha256': expected_sha256, 'bytes': len(content)}
    finally:
        os.close(directory)
