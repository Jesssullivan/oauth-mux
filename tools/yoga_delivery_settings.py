"""Guard-owned Yoga qualification custody and finite original-deadline settings."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import guard_yoga_delivery_profile as profile
import yoga_executable_qualification as executable

UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
INVENTORY = '2be4ecfe05837c67a7267aa216dbae683f2d44d07e96198d3475f3fbd124c7f8'
SOURCE_RECEIPT = 'f52825eb9235da1e5c23beb51536b390ef81b1dd2ba5c604f8a6ace40b11f50a'
# Raw registered closure bytes recorded in the exact d631 guard receipt.
# The unchanged inventory separately records its canonical action manifest
# as b24fb333... and the same registered object as this raw digest.
NATIVE = '7f19ccff61a0d5981641a73ab65067eac6de77e13e146b4be06ac6b36652bd41'
TOOLS = {
    # execution_guard.immutable resolves this generation's python3 -> python3.13.
    # The store root/bootstrap manifest/inventory generation remain unchanged.
    'python': '/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin/python3.13',
    'systemd_run': '/nix/store/9rpism89x6lyjcwzzkp6kana25rs03nn-systemd-260.1/bin/systemd-run',
    'systemctl': '/nix/store/9rpism89x6lyjcwzzkp6kana25rs03nn-systemd-260.1/bin/systemctl',
    'bazel': '/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel',
    'closure': '/nix/store/12waya019j1aiimr0j91lpdfk145xi9i-omux-bazel-closure',
    'bootstrap_closure': executable.BOOTSTRAP_ROOT,
    'zig_sdk': '/nix/store/vv1k6176b445ln4dphbx1k29wagrin3z-zig-sdk-0.17.0',
    'java_home': '/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7',
}
QUALIFICATION_FIELDS = frozenset(('schemaVersion', 'scope', 'bootstrapManifestSha256',
    'inventorySha256', 'sourceReceiptSha256', 'sshPath', 'sshSha256', 'remote'))
CLEANUP_RESERVE_NS = 15 * 10**9
DIRECTORY_PINS = {}

def require(value, reason):
    if not value:
        raise ValueError(reason)

def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate-guard-qualification-field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-guard-qualification')))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def budget(deadline_ns, reserve_ns=0):
    require(type(deadline_ns) is int and type(reserve_ns) is int and reserve_ns >= 0,
            'invalid-original-delivery-deadline')
    remaining = deadline_ns - time.monotonic_ns() - reserve_ns
    require(remaining > 0, 'original-delivery-deadline-exhausted')
    return remaining / 10**9

def finite(arguments, manager, epoch, unrelated):
    profile.selected(arguments)
    require(manager == 'system' and not any(unrelated), 'fixed-system-delivery-without-unrelated-inputs-required')
    mode = profile.MODES[arguments[1]]
    require(epoch is None if mode == 'qualify' else type(epoch) is str and UUID.fullmatch(epoch),
            'inspect-verify-require-one-prior-qualify-epoch')

def tools(actual, native_sha256, bootstrap_sha256):
    require(actual == TOOLS and native_sha256 == NATIVE and bootstrap_sha256 == executable.BOOTSTRAP_SHA,
            'unchanged-d631-controller-tools-required')

def qualification(value):
    require(type(value) is dict and set(value) == QUALIFICATION_FIELDS
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['scope'] == 'yoga-authenticated-OS-executable-qualification-v1'
            and value['bootstrapManifestSha256'] == executable.BOOTSTRAP_SHA
            and value['inventorySha256'] == INVENTORY and value['sourceReceiptSha256'] == SOURCE_RECEIPT
            and value['sshPath'] == executable.SSH and type(value['sshSha256']) is str
            and executable.SHA.fullmatch(value['sshSha256']), 'fixed-qualification-binding-required')
    executable.remote_schema(value['remote'])
    return value

def witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def release(descriptors):
    """Attempt every release; retain a primary exception independently."""
    primary = sys.exc_info()[1]
    failed = False
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException:
            failed = True
    if failed:
        if primary is not None:
            primary.add_note('qualification-custody-release-incomplete')
        else:
            raise ValueError('qualification-custody-release-incomplete')

def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))

def trusted_directory(path, deadline_ns):
    """Hold the whole nofollow ancestor chain; no close-before-transfer gap."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) <= 32, 'exact-owned-directory-required')
    descriptors, identities, names = [], [], []
    try:
        budget(deadline_ns)
        descriptors.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        identities.append(directory_identity(os.fstat(descriptors[-1])))
        for component in path.parts[1:]:
            budget(deadline_ns)
            descriptors.append(os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=descriptors[-1]))
            names.append(component)
            info = os.fstat(descriptors[-1])
            require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022, 'owned-directory-ancestor-custody')
            identities.append(directory_identity(info))
        info = os.fstat(descriptors[-1])
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private-owned-directory-required')
        DIRECTORY_PINS[descriptors[-1]] = (descriptors, identities, names)
        return descriptors[-1]
    except BaseException:
        release(reversed(descriptors))
        raise

def check_directory(descriptor, deadline_ns):
    require(descriptor in DIRECTORY_PINS, 'retained-directory-custody-required')
    descriptors, identities, names = DIRECTORY_PINS[descriptor]
    for index, held in enumerate(descriptors):
        budget(deadline_ns)
        require(directory_identity(os.fstat(held)) == identities[index], 'held-directory-custody-changed')
        if index:
            current = os.stat(names[index - 1], dir_fd=descriptors[index - 1], follow_symlinks=False)
            require(directory_identity(current) == identities[index], 'owned-directory-ancestor-rebound')
    return [list(value) for value in identities]

def close_directory(descriptor):
    pin = DIRECTORY_PINS.pop(descriptor, None)
    release(reversed(pin[0]) if pin else [descriptor])

def lock_witness(descriptor, deadline_ns):
    directory = trusted_directory(profile.COORDINATION, deadline_ns)
    try:
        held = os.fstat(descriptor)
        current = os.stat('execution.lock', dir_fd=directory, follow_symlinks=False)
        fields = lambda info: (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink)
        require(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and stat.S_IMODE(held.st_mode) == 0o600
                and held.st_nlink == 1 and fields(held) == fields(current), 'original-home-lock-custody-changed')
        return {'device': held.st_dev, 'inode': held.st_ino, 'uid': held.st_uid,
                'mode': 0o600, 'links': 1, 'ancestors': check_directory(directory, deadline_ns)}
    finally:
        close_directory(directory)

def read_owned(directory, name, maximum, deadline_ns, *, capture=False):
    budget(deadline_ns)
    require('/' not in name and name not in ('.', '..'), 'exact-qualification-filename-required')
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum,
                'private-qualification-file-custody')
        data = bytearray()
        while True:
            budget(deadline_ns)
            piece = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
            require(len(data) <= maximum, 'qualification-file-bound')
        require(len(data) == before.st_size and witness(before) == witness(os.fstat(descriptor))
                == witness(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'qualification-file-changed')
        return (bytes(data), witness(before)) if capture else bytes(data)
    finally:
        release([descriptor])

def prior_receipt(receipt, epoch, graph_sha256, expected_limits, expected_lock):
    require(type(receipt) is dict and receipt.get('id') == receipt.get('artifact_epoch') == epoch
            and type(receipt.get('exit')) is int and receipt['exit'] == 0
            and type(receipt.get('workload_exit')) is int and receipt['workload_exit'] == 0
            and receipt.get('descendants_empty') is True and 'controller_failure' in receipt
            and receipt['controller_failure'] is None and 'rejection' in receipt and receipt['rejection'] is None
            and type(receipt.get('cleanup')) is dict and receipt['cleanup'].get('state') == 'empty'
            and receipt.get('verb') == 'run' and receipt.get('targets') == ['//tools:yoga_controller_qualify']
            and receipt.get('profile') == profile.PROFILE and receipt.get('manager') == 'system'
            and receipt.get('coordination_directory') == str(profile.COORDINATION)
            and receipt.get('coordination_lock') == str(profile.COORDINATION / 'execution.lock')
            and receipt.get('graph_sha256') == graph_sha256 and receipt.get('limits') == expected_limits
            and receipt.get('closure_manifest_sha256') == NATIVE
            and receipt.get('bootstrap_manifest_sha256') == executable.BOOTSTRAP_SHA,
            'successful-same-graph-qualify-guard-epoch-required')
    record = receipt.get('yoga_delivery')
    require(type(record) is dict and record.get('source_verified_after_cleanup') is True
            and record.get('controller_tools') == TOOLS and record.get('mode') == 'qualify'
            and record.get('coordination_lock_witness') == expected_lock
            and record.get('remote_owned_containment_verified') is False
            and record.get('copy_performed') is False and record.get('remote_cleanup') == 'unknown'
            and type(record.get('qualification')) is dict
            and set(record['qualification']) == {'path', 'sha256'}
            and record['qualification']['path'] == 'qualification.json'
            and type(record['qualification']['sha256']) is str
            and executable.SHA.fullmatch(record['qualification']['sha256']), 'guard-owned-qualification-extraction-required')
    return record['qualification']['sha256']

def select_prior(epoch, graph_sha256, expected_limits, deadline_ns, expected_lock):
    """Called only under existing HOME execution lock; no caller path/hash."""
    require(type(epoch) is str and UUID.fullmatch(epoch), 'exact-prior-qualify-epoch-required')
    directory = trusted_directory(profile.STATE / epoch, deadline_ns)
    try:
        directory_identity = witness(os.fstat(directory))
        receipt_data, receipt_identity = read_owned(directory, 'receipt.json', 1024 * 1024, deadline_ns, capture=True)
        receipt = decode(receipt_data)
        approved = prior_receipt(receipt, epoch, graph_sha256, expected_limits, expected_lock)
        content, content_identity = read_owned(directory, 'qualification.json', 16384, deadline_ns, capture=True)
        require(hashlib.sha256(content).hexdigest() == approved, 'guard-extraction-digest-differs')
        require(canonical(qualification(decode(content))) == content, 'guard-extraction-not-canonical')
        ancestors = check_directory(directory, deadline_ns)
        named = trusted_directory(profile.STATE / epoch, deadline_ns)
        try:
            require(witness(os.fstat(named)) == directory_identity == witness(os.fstat(directory)),
                    'prior-qualification-directory-rebound')
        finally:
            close_directory(named)
        # Preserve independently checked terminal receipt lineage in the new epoch.
        return {'path': str(profile.STATE / epoch / 'qualification.json'), 'sha256': approved,
                'producer_epoch': epoch, 'producer_receipt_sha256': hashlib.sha256(receipt_data).hexdigest(),
                'directory_identity': list(directory_identity), 'receipt_identity': list(receipt_identity),
                'qualification_identity': list(content_identity), 'ancestor_identities': ancestors}
    finally:
        close_directory(directory)

def recheck(prior, graph_sha256, expected_limits, deadline_ns, expected_lock):
    require(select_prior(prior['producer_epoch'], graph_sha256, expected_limits, deadline_ns, expected_lock) == prior,
            'prior-guard-qualification-chain-changed-before-launch')

def extract(log, deadline_ns):
    budget(deadline_ns)
    candidates = []
    require(type(log) is bytes and 0 < len(log) <= 8 * 1024 * 1024, 'bounded-owned-delivery-log-required')
    for line in log.splitlines():
        budget(deadline_ns)
        if not line.startswith(b'{'):
            continue
        value = decode(line)
        if type(value) is dict and value.get('scope') == 'yoga-controller-destination-readonly-v1':
            candidates.append(value)
    require(len(candidates) == 1, 'one-exact-qualify-result-required')
    result = candidates[0]
    require(result.get('schemaVersion') == 1 and type(result.get('schemaVersion')) is int
            and result.get('mode') == 'qualify' and result.get('passed') is True
            and result.get('inventorySha256') == INVENTORY and result.get('sourceReceiptSha256') == SOURCE_RECEIPT
            and result.get('copyPerformed') is False and result.get('remoteCleanup') == 'unknown'
            and result.get('remoteOwnedContainmentVerified') is False
            and result.get('destinationRegistrationVerified') is False
            and result.get('destinationContentRehashed') is False
            and result.get('offlineGraphVerified') is False and result.get('wrapperExecutionAuthority') is False,
            'successful-readonly-qualify-result-required')
    host_key = result.get('sshHostKeyAuthority')
    require(type(host_key) is dict and type(host_key.get('byteCount')) is int and host_key == {
        'scope': 'existing-neo-yoga-ed25519-host-pin-2026-10-04',
        'sha256': 'e2931feebc4e623a9e0946dab4989729c48793ca90f60ed7922df026c26b77d8',
        'byteCount': 97}, 'exact-existing-ssh-host-pin-result-required')
    return canonical(qualification(result['qualification']))

def publish(run, content, deadline_ns):
    budget(deadline_ns)
    directory = trusted_directory(run, deadline_ns)
    try:
        descriptor = os.open('qualification.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        try:
            view = memoryview(content)
            while view:
                budget(deadline_ns)
                written = os.write(descriptor, view)
                require(written > 0, 'guard-extraction-short-write')
                view = view[written:]
            os.fsync(descriptor)
        finally:
            release([descriptor])
        os.fsync(directory)
        require(read_owned(directory, 'qualification.json', 16384, deadline_ns) == content,
                'guard-extraction-publication-differs')
        check_directory(directory, deadline_ns)
        return {'path': 'qualification.json', 'sha256': hashlib.sha256(content).hexdigest()}
    finally:
        close_directory(directory)

def finish(run, arguments, workload_exit, empty, source_verified, deadline_ns, lock):
    record = {'mode': profile.MODES[arguments[1]], 'controller_tools': TOOLS,
              'source_verified_after_cleanup': source_verified, 'qualification': None,
              'coordination_lock_witness': lock,
              'copy_performed': False, 'remote_owned_containment_verified': False, 'remote_cleanup': 'unknown'}
    if record['mode'] == 'qualify' and workload_exit == 0 and empty and source_verified:
        directory = trusted_directory(run, deadline_ns)
        try:
            log = read_owned(directory, 'workload.log', 8 * 1024 * 1024, deadline_ns)
            check_directory(directory, deadline_ns)
        finally:
            close_directory(directory)
        record['qualification'] = publish(run, extract(log, deadline_ns), deadline_ns)
    return record

def runtime_seconds(deadline_ns):
    seconds = int(budget(deadline_ns, CLEANUP_RESERVE_NS))
    require(seconds > 0, 'delivery-runtime-reserve-exhausted')
    return min(1200, seconds)

def effective_runtime(value, maximum):
    """Finite systemctl duration parser; no unitless or infinite values."""
    require(type(value) is str and len(value) <= 64 and type(maximum) is int and 0 < maximum <= 1200,
            'delivery-effective-runtime-invalid')
    matches = list(re.finditer(r'([0-9]+(?:\.[0-9]{1,6})?)(us|ms|s|min|h)', value))
    require(matches and ''.join(match.group(0) for match in matches) == value.replace(' ', ''),
            'delivery-effective-runtime-invalid')
    scales = {'us': 1, 'ms': 1000, 's': 1000000, 'min': 60000000, 'h': 3600000000}
    total = sum(int(float(match.group(1)) * scales[match.group(2)]) for match in matches)
    require(0 < total <= maximum * 1000000, 'delivery-effective-runtime-exceeds-original-budget')
    return total
