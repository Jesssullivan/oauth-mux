"""Finite SPA admission and source fences; this module never launches tools."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from site_coordinator_qualification import BAZEL, BAZEL_NATIVE, JDK, CANDIDATE_SHA256, file_bytes

MASKS = ('/etc/bluetooth', '/etc/environment')
QUALIFICATION_LABELS = {'//:qualified_site_tools_test', '//:nix_file_inventory_test', '//:reference_check',
                        '//tools:qualified_site_tools_test', '//tools:nix_file_inventory_test'}
CHECK_LABELS = {'//:unit_tests', '//:svelte_check', '//:reference_check', '//:archive_check'}
BUILD_LABELS = {'//:build', '//:site_archive'}
FETCH_LABELS = QUALIFICATION_LABELS | CHECK_LABELS | BUILD_LABELS | {'//:import_extension_delivery', '//:import_reference'}
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
    if phase in ('import', 'reference-import'):
        import_shape(phase, arguments)
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


def physical_source(source):
    source = Path(source)
    if (not source.is_absolute() or '..' in source.parts or
            any(char.isspace() for char in str(source))):
        raise ValueError('canonical physical site source required')
    try:
        if source.resolve(strict=True) != source or not source.is_dir():
            raise ValueError('site source aliases rejected')
    except (OSError, RuntimeError) as error:
        raise ValueError('physical site source unavailable') from error
    return source


def source_binding(source, version_sha256):
    """Admit an independent task-owned checkout, never the dirty shared sibling."""
    source = physical_source(source)
    parent = source.parent.stat()
    checkout = source.stat()
    if (parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700 or
            checkout.st_uid != os.getuid() or checkout.st_mode & 0o022):
        raise ValueError('site checkout requires a private owned parent and owned source')
    git = source / '.git'
    try:
        info = git.lstat()
    except OSError as error:
        raise ValueError('independent site repository required') from error
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or
            any(path.exists() or path.is_symlink() for path in
                (git / 'objects/info/alternates', git / 'commondir'))):
        raise ValueError('shared Git metadata or alternate object stores rejected')
    if bounded_file(source / '.bazelversion', version_sha256, 64).strip() != b'9.0.1':
        raise ValueError('site requires its separately qualified Bazel 9.0.1')
    return source


def read_qualification(path, expected_sha256, source):
    try:
        return _read_qualification(path, expected_sha256, source)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed coordinator qualification') from error


def _read_qualification(path, expected_sha256, source):
    """Receipt SHA is independently selected by the operator, never self-attested."""
    import site_coordinator_closure_qualification as full
    report = full.decode(bounded_file(path, expected_sha256, 65536))
    if (report.get('schema_version') != 1 or report.get('status') != 'verified-site-toolchain' or
            report.get('bazel_executable') != str(BAZEL_NATIVE) or
            report.get('candidate_sha256') != full.CANDIDATE_SHA256 or
            report.get('roots') != list(full.ROOTS) or report.get('inventory') != 'coordinator-inventory.json' or
            report.get('closure_binding') != 'complete-registered-reference-closure' or
            report.get('binary_versions_verified') is not True or report.get('execution_authority') is not False or
            report.get('published') is not False or report.get('link_targets_followed') is not False):
        raise ValueError('complete independent coordinator qualification required')
    from site_coordinator_selection import location, digest
    candidate_path = location(report.get('candidate'), 'candidate')
    version_path = location(report.get('binary_qualification'), 'version')
    version_sha256 = digest(report.get('binary_qualification_sha256'))
    candidate = full.decode(bounded_file(candidate_path, full.CANDIDATE_SHA256, 65536))
    version = full.decode(bounded_file(version_path, version_sha256, 65536))
    full.validate_evidence(candidate, version,
        {name: bounded_file(Path(source) / name, digest, 1024 * 1024) for name, digest in full.INPUTS.items()},
        bounded_file(Path(source) / '.bazelversion', full.SITE_VERSION_SHA256, 64),
        candidate_origin=candidate_path)
    if (report.get('input_sha256') != full.INPUTS or
            report.get('site_bazelversion_sha256') != full.SITE_VERSION_SHA256 or
            report.get('binaries') != full.BINARIES or report.get('wrappers') != full.WRAPPERS):
        raise ValueError('qualification input/binary pins differ')
    inventory_bytes = bounded_file(Path(path).parent / report['inventory'], report.get('inventory_sha256'), 8 * 1024 * 1024)
    inventory = full.decode(inventory_bytes)
    canonical, content, digest = full.closure_inventory(inventory.get('paths'), version_sha256=version_sha256)
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


DEVELOPMENT_SELECTION_ENV = 'OMUX_SITE_DEVELOPMENT_ARTIFACT_SELECTION'
DEVELOPMENT_SELECTION_SHA_ENV = DEVELOPMENT_SELECTION_ENV + '_SHA256'
DEVELOPMENT_ARCHIVE_SUFFIX = ('output-base', 'execroot', '_main', 'bazel-out', 'k8-fastbuild',
                              'bin', 'extensions', 'chromium_dev_package.zip')
DEVELOPMENT_MANIFEST_SUFFIX = ('output-base', 'execroot', '_main', 'bazel-out', 'k8-fastbuild',
                               'bin', 'delivery', 'chromium_dev_metadata.json')
DEVELOPMENT_ARCHIVE_MAX = 16 * 1024 * 1024


def admitted_development_artifact(profile, phase, arguments, selection, digest):
    """Optional public byte selection, never an import or enrollment operation."""
    if selection is None and digest is None:
        return False
    if (selection is None or digest is None or profile != 'site' or
            not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
        raise ValueError('development artifact requires a complete site selection')
    if phase not in ('checks', 'build', 'archive'):
        raise ValueError('development artifact selection is exclusive to site output phases')
    finite_phase(phase, arguments)
    if phase == 'checks' and '//:archive_check' not in arguments[1:]:
        raise ValueError('selected development bytes require the archive check')
    return True


def development_artifact_bindings(selection=None, digest=None):
    # Explicit empty values override inherited repository-environment controls.
    if (selection is None) != (digest is None):
        raise ValueError('incomplete development artifact repository controls')
    return {DEVELOPMENT_SELECTION_ENV: str(selection) if selection is not None else '',
            DEVELOPMENT_SELECTION_SHA_ENV: digest if digest is not None else ''}


def _development_canonical(value):
    if (not isinstance(value, str) or not value or str(Path(value)) != value or
            not Path(value).is_absolute() or '..' in Path(value).parts or
            any(char.isspace() or char in '\\\x00' for char in value)):
        raise ValueError('canonical development artifact path required')
    return Path(value)


def _development_namespace(value, cache=False):
    import uuid
    if cache and re.fullmatch('cache-v2-[0-9a-f]{64}', value):
        return True
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _development_location(value, roots, suffix, cache=False):
    path = _development_canonical(value)
    for root in roots:
        root = _development_canonical(str(root))
        if path.is_relative_to(root):
            parts = path.relative_to(root).parts
            if (len(parts) == 1 + len(suffix) and parts[1:] == tuple(suffix) and
                    _development_namespace(parts[0], cache)):
                return root, parts
    raise ValueError('development artifact is outside its exact owned role')


def _development_directory_identity(info):
    # Stable across phases: authorized epoch creation can change root timestamps.
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def _development_file_identity(info):
    # Full local custody witness, used for held AND named files/directories.
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _development_close(held):
    """Detach ownership before trying every FD once; propagate the first failure."""
    pending = tuple(reversed(held))
    held.clear()
    first = None
    for fd in pending:
        try:
            os.close(fd)
        except BaseException as error:
            if first is None:
                first = error
    if first is not None:
        raise first


def _development_hold(held, fd):
    try:
        held.append(fd)
    except BaseException as error:
        try:
            os.close(fd)
        except BaseException as close_error:
            raise error from close_error
        raise
    return fd


def _development_root(root, cutoff):
    """Hold the selected root's named ancestor lineage through the whole stage."""
    held = []
    links = []
    try:
        _development_hold(held, os.open('/', os.O_RDONLY | os.O_DIRECTORY))
        for part in root.parts[1:]:
            if time.monotonic_ns() >= cutoff:
                raise ValueError('development artifact original deadline exhausted')
            parent = held[-1]
            child = _development_hold(held,
                os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
            info = os.fstat(child)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError('development root ancestor custody rejected')
            links.append((parent, part, child, _development_file_identity(info)))
        return held, links
    except BaseException as error:
        try:
            _development_close(held)
        except BaseException as close_error:
            raise error from close_error
        raise


class _DevelopmentOwners:
    """One finite read stage owns all four roles until its joint final fence."""
    def __init__(self, cutoff):
        self.cutoff = cutoff
        self.groups = []

    def tick(self):
        if time.monotonic_ns() >= self.cutoff:
            raise ValueError('development artifact original deadline exhausted')

    def adopt(self, held, links):
        try:
            group = {'held': held, 'links': links, 'leaf': None,
                     'root_fd': held[-1], 'root_full': _development_file_identity(os.fstat(held[-1]))}
            self.groups.append(group)
            return group
        except BaseException as error:
            try:
                _development_close(held)
            except BaseException as close_error:
                raise error from close_error
            raise

    def metadata_fence(self):
        for group in self.groups:
            self.tick()
            if _development_file_identity(os.fstat(group['root_fd'])) != group['root_full']:
                raise ValueError('original development artifact root changed during stage')
            leaf = group['leaf']
            if leaf is not None:
                if (_development_file_identity(os.fstat(leaf['fd'])) != leaf['identity'] or
                        _development_file_identity(os.stat(leaf['name'], dir_fd=leaf['parent'],
                            follow_symlinks=False)) != leaf['identity']):
                    raise ValueError('original held or named development file changed')
            for parent, name, child, original in group['links']:
                self.tick()
                if (_development_file_identity(os.fstat(child)) != original or
                        _development_file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
                    raise ValueError('original held or named development lineage changed')

    def fence(self):
        # Rehash retained original roles after the ZIP read, then jointly fence
        # every held/named full-nine witness after the LAST rehash as well.
        self.metadata_fence()
        for group in self.groups:
            self.tick()
            leaf = group['leaf']
            if leaf is None:
                raise ValueError('development role did not complete its original read')
            os.lseek(leaf['fd'], 0, os.SEEK_SET)
            digest, count = hashlib.sha256(), 0
            while True:
                self.tick()
                chunk = os.read(leaf['fd'], min(65536, leaf['maximum'] + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > leaf['maximum']:
                    raise ValueError('development artifact exceeds final bound')
                digest.update(chunk)
            if count != leaf['bytes'] or digest.hexdigest() != leaf['sha256']:
                raise ValueError('original development artifact bytes changed during stage')
        self.metadata_fence()
        self.tick()

    def close(self):
        groups, self.groups = self.groups, []
        first = None
        for group in reversed(groups):
            try:
                _development_close(group['held'])
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first


def _development_read(root, parts, expected, maximum, cutoff, *, owners,
                      retain=True, private_root=True):
    """Hash one original regular file and retain all its owners for final fencing."""
    owners.tick()
    held, links = _development_root(root, cutoff)
    group = owners.adopt(held, links)
    root_fd = held[-1]
    root_info = os.fstat(root_fd)
    if (root_info.st_uid != os.getuid() or root_info.st_mode & 0o022 or
            (private_root and stat.S_IMODE(root_info.st_mode) != 0o700)):
        raise ValueError('development artifact requires a private owned root')
    root_dev = root_info.st_dev
    for part in parts[:-1]:
        owners.tick()
        parent = held[-1]
        child = _development_hold(held,
            os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
        info = os.fstat(child)
        if (info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_dev != root_dev):
            raise ValueError('development artifact directory custody rejected')
        links.append((parent, part, child, _development_file_identity(info)))
    parent = held[-1]
    leaf = _development_hold(held,
        os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent))
    info = os.fstat(leaf)
    identity = _development_file_identity(info)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or
            info.st_nlink != 1 or info.st_dev != root_dev or not 0 < info.st_size <= maximum):
        raise ValueError('bounded owned development artifact required')
    digest, count = hashlib.sha256(), 0
    content = bytearray() if retain else None
    while True:
        owners.tick()
        chunk = os.read(leaf, min(65536, maximum + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        if count > maximum:
            raise ValueError('development artifact exceeds bound')
        digest.update(chunk)
        if retain:
            content.extend(chunk)
    actual = digest.hexdigest()
    owners.tick()
    if count != info.st_size or (expected is not None and actual != expected):
        raise ValueError('original development artifact bytes differ')
    group['leaf'] = {'fd': leaf, 'parent': parent, 'name': parts[-1], 'identity': identity,
                     'sha256': actual, 'bytes': count, 'maximum': maximum}
    owners.metadata_fence()
    return (bytes(content) if retain else None,
            {'sha256': actual, 'bytes': count, 'file_identity': identity,
             'root_identity': _development_directory_identity(root_info),
             'directory_identities': [_development_directory_identity(os.fstat(item[2])) for item in links]})


def _development_decode(content):
    import site_coordinator_closure_qualification as full
    try:
        return full.decode(content)
    except RecursionError as error:
        raise ValueError('public development JSON nesting exceeds decoder bound') from error


def _development_equal(left, right):
    # JSON booleans must never compare equal to numeric schema/fact fields.
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(_development_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(_development_equal(a, b) for a, b in zip(left, right))
    return left == right


def development_artifact(selection, digest, state_root, coordination_root, source,
                         original_deadline_ns, *, original=None):
    if selection is None and digest is None:
        if original is not None:
            raise ValueError('selected development artifact disappeared')
        return None
    if (selection is None or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or
            type(original_deadline_ns) is not int):
        raise ValueError('exact development selection and original deadline required')
    # Each read stage has a finite allowance inside the same original entry deadline.
    cutoff = min(original_deadline_ns, time.monotonic_ns() + 15 * 10**9)
    owners = _DevelopmentOwners(cutoff)
    first = None
    try:
        result = _development_artifact_read(selection, digest, state_root, coordination_root,
            source, cutoff, owners, original)
        owners.fence()
    except BaseException as error:
        first = error
    try:
        owners.close()
    except BaseException as close_error:
        if first is not None:
            raise first from close_error
        raise
    if first is not None:
        raise first
    # No successful return after validation or all-attempt closure consumes the
    # original stage cutoff. This is the SAME cutoff, never a fresh allowance.
    owners.tick()
    return result


def _development_artifact_read(selection, digest, state_root, coordination_root, source,
                               cutoff, owners, original):
    roots = (Path(state_root), Path(coordination_root))
    descriptor_root, descriptor_parts = _development_location(str(selection), roots,
        ('site-development-artifact-selection.json',))
    raw, descriptor_facts = _development_read(descriptor_root, descriptor_parts, digest, 8192, cutoff, owners=owners)
    value = _development_decode(raw)
    def shape(item, fields):
        if type(item) is not dict or set(item) != set(fields):
            raise ValueError('unexpected development selection fields')
    shape(value, ('schema_version', 'archive', 'manifest'))
    shape(value['archive'], ('path', 'sha256', 'bytes'))
    shape(value['manifest'], ('path', 'sha256'))
    archive, manifest = value['archive'], value['manifest']
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            type(archive['bytes']) is not int or not 0 < archive['bytes'] <= DEVELOPMENT_ARCHIVE_MAX or
            any(not isinstance(item, str) or not re.fullmatch('[0-9a-f]{64}', item)
                for item in (archive['sha256'], manifest['sha256']))):
        raise ValueError('development selection schema/digests/bounds differ')
    archive_root, archive_parts = _development_location(archive['path'], roots, DEVELOPMENT_ARCHIVE_SUFFIX, True)
    manifest_root, manifest_parts = _development_location(manifest['path'], roots, DEVELOPMENT_MANIFEST_SUFFIX, True)
    if archive_root != manifest_root or archive_parts[0] != manifest_parts[0]:
        raise ValueError('development ZIP and metadata require the same original output base')
    raw_manifest, manifest_facts = _development_read(manifest_root, manifest_parts, manifest['sha256'], 16384, cutoff, owners=owners)
    try:
        metadata = validate_delivery_metadata(raw_manifest)
    except RecursionError as error:
        raise ValueError('public development metadata nesting exceeds decoder bound') from error
    if (metadata['extension']['id'] != 'bggghdafplhajiailkafeihemlalagmm' or
            metadata['artifact'] != {'filename': DEVELOPMENT_ARCHIVE_SUFFIX[-1],
                'sha256': archive['sha256'], 'bytes': archive['bytes'], 'format': 'zip'}):
        raise ValueError('selected development package and metadata differ')
    source = _development_canonical(str(source))
    wrapper, wrapper_facts = _development_read(source, ('src', 'lib', 'content', 'extension-delivery.json'),
        None, 32768, cutoff, owners=owners, private_root=False)
    imported = _development_decode(wrapper)
    shape(imported, ('manifest', 'manifest_sha256'))
    if not _development_equal(imported, {'manifest': metadata, 'manifest_sha256': manifest['sha256']}):
        raise ValueError('selected development metadata is not the exact imported snapshot')
    _, archive_facts = _development_read(archive_root, archive_parts, archive['sha256'],
        DEVELOPMENT_ARCHIVE_MAX, cutoff, owners=owners, retain=False)
    if archive_facts['bytes'] != archive['bytes']:
        raise ValueError('selected development ZIP size differs')
    result = {'schema_version': 1, 'selection': str(selection), 'selection_sha256': digest,
              'output_base': str(archive_root / archive_parts[0] / 'output-base'),
              'archive': archive, 'manifest': manifest, 'descriptor_facts': descriptor_facts,
              'manifest_facts': manifest_facts, 'archive_facts': archive_facts,
              'imported_snapshot_facts': wrapper_facts,
              'publication': 'unpublished', 'native_continuity': 'unproved'}
    if original is not None and result != original:
        raise ValueError('original development selection changed between stages')
    return result


def required_masks(observed):
    if not set(MASKS).issubset(observed):
        raise ValueError('both host configuration masks must be verified before site execution')


def proof_bindings(inventory, inventory_sha256, inventory_validator, state_root, coordination_root, runtime_source):
    """Reuse the controller's exact retained inventory selector; no new path lane."""
    selected = inventory_validator(inventory, inventory_sha256, state_root, coordination_root)
    result = {'OMUX_SITE_INVENTORY': str(selected), 'OMUX_SITE_INVENTORY_SHA256': inventory_sha256}
    for name, (relative, digest) in PROOF_FILES.items():
        if digest is None:
            raise ValueError('fresh Bazel 9 mapping receipt not yet retained and bound')
        path = Path(runtime_source) / relative
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


def command(bazel, java_home, qualification, output_base, phase, arguments, bindings=None, run=None, *, source):
    toolchain_binding(bazel, java_home, qualification)
    if phase in ('import', 'reference-import'):
        import_shape(phase, arguments)
        selected = (reference_importer_arguments(arguments[4], arguments[6], qualification.get('reference_bundle'))
                    if phase == 'reference-import' else
                    importer_arguments(arguments[4], arguments[6], qualification.get('delivery_manifest')))
    else:
        selected = finite_phase(phase, arguments)
    output_base = Path(output_base)
    if not output_base.is_absolute() or '..' in output_base.parts or output_base.is_relative_to(Path(source)):
        raise ValueError('private external owned output base required')
    tests = ['--nocache_test_results', '--nozip_undeclared_test_outputs', '--test_output=errors',
             '--strategy=TestRunner=processwrapper-sandbox', '--test_env=TZ=UTC'] if selected[0] == 'test' else []
    controls = development_artifact_bindings()
    controls.update(bindings or {})
    admitted_development_artifact('site', phase, arguments,
        controls[DEVELOPMENT_SELECTION_ENV] or None, controls[DEVELOPMENT_SELECTION_SHA_ENV] or None)
    inputs = ['--repo_env=' + key + '=' + value for key, value in sorted(controls.items())]
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


def import_shape(phase, arguments):
    target, option = (('//:import_reference', '--bundle') if phase == 'reference-import' else
                      ('//:import_extension_delivery', '--manifest'))
    if (phase not in ('import', 'reference-import') or len(arguments) != 7 or
            arguments[:3] != ['run', target, '--'] or arguments[3] != option or
            arguments[5] != '--sha256'):
        raise ValueError('only the exact selected importer is accepted')


def admitted_import(phase, arguments, manifest=None, manifest_sha256=None, bundle=None, bundle_sha256=None):
    """Validate exclusive CLI selections before any executable/input admission."""
    import_shape(phase, arguments)
    if phase == 'reference-import':
        if manifest is not None or manifest_sha256 is not None:
            raise ValueError('reference import forbids extension metadata selection')
        selected, digest, option, target = bundle, bundle_sha256, '--bundle', '//:import_reference'
    else:
        if bundle is not None or bundle_sha256 is not None:
            raise ValueError('extension import forbids runtime reference selection')
        selected, digest, option, target = manifest, manifest_sha256, '--manifest', '//:import_extension_delivery'
    if (selected is None or not re.fullmatch('[0-9a-f]{64}', digest or '') or
            arguments != ['run', target, '--', option, str(selected), '--sha256', digest]):
        raise ValueError('site import requires its exact admitted producer path and digest')
    return list(arguments)


def reference_importer_arguments(bundle, expected_sha256, selected_bundle):
    if selected_bundle is None or Path(bundle) != Path(selected_bundle):
        raise ValueError('import must select the exact retained runtime reference')
    # The Bazel importer owns full public schema validation. This boundary binds
    # raw producer bytes only; it never stamps or normalizes provenance.
    bounded_file(bundle, expected_sha256, 2 * 1024 * 1024)
    return ['run', '//:import_reference', '--', '--bundle', str(bundle), '--sha256', expected_sha256]


def verify_reference_outputs(source, bundle, expected_sha256):
    producer = bounded_file(bundle, expected_sha256, 2 * 1024 * 1024)
    imported = bounded_file(Path(source) / 'src/lib/content/reference-bundle.json', expected_sha256, 2 * 1024 * 1024)
    digest_bytes = (expected_sha256 + '\n').encode('ascii')
    sidecar = bounded_file(Path(source) / 'src/lib/content/reference-bundle.sha256',
                           hashlib.sha256(digest_bytes).hexdigest(), 65)
    if imported != producer or sidecar != digest_bytes:
        raise ValueError('reference import did not preserve exact producer/digest bytes')


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
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                        before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > 16 * 1024 * 1024):
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
                 {'src/lib/content/reference-bundle.json', 'src/lib/content/reference-bundle.sha256'}
                 if phase == 'reference-import' else {'MODULE.bazel.lock'} if phase == 'lock' else set())
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    if changed - permitted:
        raise ValueError('site source changed outside the selected phase outputs')
    return sorted(changed)


def retain_lockfile(source, run, expected_sha256, stage):
    """Preserve exact prior/final lock bytes; never edit or normalize them."""
    source = physical_source(source)
    if stage not in ('before', 'after'):
        raise ValueError('only selected site lock evidence stages are accepted')
    run = Path(run)
    if not run.is_absolute() or '..' in run.parts:
        raise ValueError('owned absolute epoch required for lock evidence')
    if expected_sha256 is None:
        if stage != 'after':
            raise ValueError('prior lock evidence requires its independently sampled source digest')
        _, facts = file_bytes(source / 'MODULE.bazel.lock', 16 * 1024 * 1024)
        expected_sha256 = facts['sha256']
    content = bounded_file(source / 'MODULE.bazel.lock', expected_sha256, 16 * 1024 * 1024)
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
