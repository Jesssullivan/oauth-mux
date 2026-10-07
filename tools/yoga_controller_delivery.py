"""Fixed Yoga inspect/verify backend; no copy, trust mutation or remote cleanup."""
import argparse
import hashlib
import json
import selectors
import signal
import stat
import subprocess
import os
import sys
from pathlib import Path
import re
import shlex
import time
from host_closure_transfer import SSH_OPTIONS, GateError, category, diagnostic_flags
from ssh_policy import operator_config
from verify_cached_nars import parse_inventory, expected_hash
import yoga_executable_qualification as qualification

LABEL = '//tools:yoga_controller_delivery'
HOST = 'yoga'
INVENTORY_SHA = '2be4ecfe05837c67a7267aa216dbae683f2d44d07e96198d3475f3fbd124c7f8'
RECEIPT_SHA = 'f52825eb9235da1e5c23beb51536b390ef81b1dd2ba5c604f8a6ace40b11f50a'
EPOCH = 'd6311994-5212-4034-ac93-49b06405db88'
STORE = re.compile(r'/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+/bin/nix')
RESERVE = 30

def require(value, reason):
    if not value:
        raise GateError(reason)

def ssh_failure(stage, status, stderr):
    """Finite observations only; no stderr, host/user text or command output."""
    require(stage in ('authenticated-os-qualification', 'qualified-nix-readonly'),
            'finite-ssh-operation-stage-required')
    require(type(status) is int and 0 < status <= 255
            and type(stderr) is bytes and len(stderr) <= 65536,
            'finite-ssh-operation-failure-required')
    flags = diagnostic_flags(stderr)
    flags['os_bootstrap_predicate_refused'] = b'remote-bootstrap-qualification-refused' in stderr
    flags['os_bootstrap_custody_release_incomplete'] = b'remote-custody-release-incomplete' in stderr
    hints = {'schemaVersion': 1, 'stage': stage, 'sshExitStatus': status,
             'stderrFlags': flags}
    observed = qualification.remote_failure(stderr)
    if observed is not None:
        hints['osBootstrapFailure'] = observed
    return GateError(category(stderr), hints=hints)

def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(GateError('nonfinite-json')))

def fence(deadline):
    require(time.monotonic() < deadline, 'shared-deadline-exhausted')

def owned_io(command, env, deadline, bound):
    fence(deadline)
    buffers = {True: bytearray(), False: bytearray()}
    cleanup_errors = []
    selector = None
    proc = None
    cancelled = False
    previous = []
    def cancellation(signum, frame):
        # Set a finite flag, including during Popen/setup; cleanup never runs
        # asynchronously against a partially initialized child or selector.
        nonlocal cancelled
        cancelled = True
    def check(selected_deadline):
        require(not cancelled, 'owned-child-cancelled')
        fence(selected_deadline)
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous.append((signum, signal.signal(signum, cancellation)))
        check(deadline)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env=env)
        # No poll/wait is permitted here: retain zombie leader as PGID anchor.
        require(os.getpgid(proc.pid) == proc.pid, 'child-group-anchor')
        check(deadline)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, True)
        selector.register(proc.stderr, selectors.EVENT_READ, False)
        while selector.get_map() or os.waitid(os.P_PID, proc.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            check(deadline - 5)
            for key, _ in selector.select(min(0.25, max(0, deadline - time.monotonic() - 5))):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(data)
                require(len(buffers[key.data]) <= (bound if key.data else 65536),
                        'bounded-operation-output')
    finally:
        primary = sys.exc_info()[1]
        # This child has not been reaped; its original group ID cannot be reused.
        if proc is not None:
            try:
                require(os.getpgid(proc.pid) == proc.pid, 'child-group-anchor-lost')
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                cleanup_errors.append('child-group-anchor-unavailable')
            except BaseException:
                cleanup_errors.append('child-group-cleanup-failed')
            try:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'child-reap-deadline-exhausted')
                proc.wait(timeout=min(5, remaining))
            except BaseException:
                cleanup_errors.append('child-reap-unproved')
        resources = (selector,) + ((proc.stdout, proc.stderr) if proc is not None else ())
        for resource in resources:
            if resource is not None:
                try:
                    resource.close()
                except BaseException:
                    cleanup_errors.append('child-resource-release-failed')
        for signum, handler in reversed(previous):
            try:
                signal.signal(signum, handler)
            except BaseException:
                cleanup_errors.append('child-signal-restore-failed')
        if cleanup_errors:
            category = ','.join(sorted(set(cleanup_errors)))
            if primary is not None:
                primary.add_note('owned-child-cleanup:' + category)
            else:
                failure = GateError(category)
                failure.cleanup_incomplete = True
                raise failure
    check(deadline)
    return proc.returncode, bytes(buffers[True]), bytes(buffers[False])

def selected(inventory, receipt):
    rows = parse_inventory(inventory, INVENTORY_SHA)
    require(len(rows) == 472 and sum(row['narSize'] for row in rows) == 2829689512,
            'fixed-controller-inventory-required')
    require(hashlib.sha256(receipt).hexdigest() == RECEIPT_SHA,
            'fixed-controller-receipt-required')
    strict_json(inventory)
    evidence = strict_json(receipt)
    require(evidence['id'] == EPOCH and evidence['artifact_epoch'] == EPOCH
            and type(evidence['exit']) is int and evidence['exit'] == 0
            and type(evidence['workload_exit']) is int and evidence['workload_exit'] == 0
            and evidence['descendants_empty'] is True,
            'terminal-controller-evidence-required')
    return rows

def registry(actual, rows):
    require(type(actual) is dict and set(actual) == {row['path'] for row in rows},
            'destination-registration-set')
    for row in rows:
        item = actual[row['path']]
        def predicate(value, name):
            if not value:
                raise GateError('destination-registration-content', hints={
                    'schemaVersion': 1, 'stage': 'destination-registry', 'predicate': name})
        predicate(type(item) is dict, 'row-object')
        predicate(type(item.get('narSize')) is int, 'nar-size-type')
        predicate(item['narSize'] == row['narSize'], 'nar-size-value')
        # Malformed hashes preserve the existing finite generic input refusal.
        predicate(expected_hash(item.get('narHash')) == expected_hash(row['narHash']), 'nar-hash-value')
        predicate(type(item.get('references')) is list, 'references-list')
        predicate(all(type(reference) is str and qualification.STORE_ROOT.fullmatch(reference)
                      for reference in item['references']), 'reference-path')
        predicate(len(item['references']) == len(set(item['references'])), 'reference-unique')
        predicate(sorted(item['references']) == sorted(row['references']), 'reference-topology')

PROBE = r'''set -eu
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64
test "$(id -un)" = jsullivan2
omux_nix=$(readlink -f /nix/var/nix/profiles/default/bin/nix)
case "$omux_nix" in /nix/store/*/bin/nix) ;; *) exit 3 ;; esac
test -x "$omux_nix" && test ! -L "$omux_nix"
printf 'nix=%s\n' "$omux_nix"
printf 'uid=%s\n' "$(id -u)"
df -Pk /nix/store | awk 'NR==2 {print "availableKiB=" $4}'
'''

def qualify_ssh(path, expected, deadline):
    fence(deadline)
    require(path.startswith('/nix/store/'), 'local-ssh-authority-path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and not before.st_mode & 0o222 and before.st_mode & 0o111
                and 0 < before.st_size <= 64 * 1024**2, 'local-ssh-authority-custody')
        digest = hashlib.sha256()
        count = 0
        while True:
            fence(deadline)
            data = os.read(descriptor, 65536)
            if not data:
                break
            count += len(data)
            require(count <= before.st_size, 'local-ssh-size-changed')
            digest.update(data)
        fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode,
                               info.st_uid, info.st_mtime_ns, info.st_ctime_ns)
        require(count == before.st_size and fields(before) == fields(os.fstat(descriptor))
                == fields(os.lstat(path)), 'local-ssh-authority-changed')
        require(digest.hexdigest() == expected, 'local-ssh-executable-digest')
        fence(deadline)
    finally:
        os.close(descriptor)

# Existing Neo trust, recorded in both Oct4 Lab receipts; never a scanned key.
# docs/agent-notes/2026-10-04-TIN-3692-neo-switch-state-and-hook-refusal.md:48
# docs/agent-notes/2026-10-04-TIN-3692-lab-yoga-state-and-switch-route.md:21
# Historical HOME alias currently resolves through the declared HM .claude link.
KNOWN_HOSTS_SOURCE = '/srv/fast-local/jess/state/claude/agent-notes-rescue/2026-10-04/lab-yoga-known-hosts'
KNOWN_HOSTS_SHA256 = 'e2931feebc4e623a9e0946dab4989729c48793ca90f60ed7922df026c26b77d8'
KNOWN_HOSTS_BYTES = 97

def host_key_record():
    return {'scope': 'existing-neo-yoga-ed25519-host-pin-2026-10-04',
            'sha256': KNOWN_HOSTS_SHA256, 'byteCount': KNOWN_HOSTS_BYTES}

def host_key_directory(info):
    return info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022

class KnownHostAuthority:
    """Hold imported operator trust and every named/descriptor witness."""
    def __init__(self, path, deadline):
        self.deadline, self.parents, self.identities, self.fd = deadline, [], [], None
        self.logical = Path(path).absolute()
        self.resolved = self.logical.resolve(strict=True)
        require(str(self.resolved) == KNOWN_HOSTS_SOURCE, 'fixed-known-hosts-declared-target-required')
        self.alias = self.file_identity(os.lstat(self.logical))
        try:
            fence(deadline)
            self.parents.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            self.identities.append(self.directory_identity(os.fstat(self.parents[-1])))
            for component in self.resolved.parts[1:-1]:
                fence(deadline)
                self.parents.append(os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                            dir_fd=self.parents[-1]))
                info = os.fstat(self.parents[-1])
                require(host_key_directory(info), 'known-hosts-ancestor-custody')
                self.identities.append(self.directory_identity(info))
            self.fd = os.open(self.resolved.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                              dir_fd=self.parents[-1])
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and info.st_size == KNOWN_HOSTS_BYTES, 'known-hosts-public-file-custody')
            self.identity = self.file_identity(info)
            self.check()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def file_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    @staticmethod
    def directory_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)

    def check(self):
        fence(self.deadline)
        require(self.fd is not None and self.logical.resolve(strict=True) == self.resolved
                and self.file_identity(os.lstat(self.logical)) == self.alias,
                'known-hosts-declared-alias-changed')
        for index, descriptor in enumerate(self.parents):
            fence(self.deadline)
            require(self.directory_identity(os.fstat(descriptor)) == self.identities[index],
                    'known-hosts-held-ancestor-changed')
            if index:
                named = os.stat(self.resolved.parts[index], dir_fd=self.parents[index - 1],
                                follow_symlinks=False)
                require(self.directory_identity(named) == self.identities[index],
                        'known-hosts-named-ancestor-changed')
        require(self.file_identity(os.fstat(self.fd)) == self.identity
                == self.file_identity(os.stat(self.resolved.name, dir_fd=self.parents[-1],
                                               follow_symlinks=False))
                == self.file_identity(os.lstat(self.resolved)), 'known-hosts-leaf-changed')
        data = os.pread(self.fd, KNOWN_HOSTS_BYTES + 1, 0)
        require(len(data) == KNOWN_HOSTS_BYTES and hashlib.sha256(data).hexdigest() == KNOWN_HOSTS_SHA256,
                'known-hosts-public-pin-digest')
        require(self.file_identity(os.fstat(self.fd)) == self.identity, 'known-hosts-readback-changed')
        fence(self.deadline)

    def options(self):
        return ['-oUserKnownHostsFile=' + str(self.logical), '-oGlobalKnownHostsFile=/dev/null',
                '-oKnownHostsCommand=none', '-oVerifyHostKeyDNS=no', '-oUpdateHostKeys=no',
                '-oHostKeyAlgorithms=ssh-ed25519', '-oHostKeyAlias=100.104.152.110']

    def close(self):
        descriptors = ([self.fd] if self.fd is not None else []) + list(reversed(self.parents))
        self.fd, self.parents = None, []
        qualification.release(descriptors)

    def __enter__(self):
        try:
            self.check()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, kind, primary, traceback):
        changed, cleanup = None, None
        try:
            self.check()
        except BaseException as error:
            changed = error
        try:
            self.close()
        except BaseException as error:
            cleanup = error
        if primary is not None:
            if changed is not None:
                primary.host_key_authority_recheck_failed = True
            if cleanup is not None:
                primary.add_note('known-hosts-custody-release-incomplete')
        elif changed is not None:
            if cleanup is not None:
                changed.add_note('known-hosts-custody-release-incomplete')
            raise changed
        elif cleanup is not None:
            cleanup.add_note('known-hosts-custody-release-incomplete')
            raise cleanup
        return False

class Backend:
    def __init__(self, ssh, options, deadline, authority, known_hosts=None):
        self.ssh, self.options, self.deadline = ssh, options, deadline
        self.authority = authority
        require(type(authority) is dict and set(authority) == {'sshPath', 'sshSha256', 'remote'}
                and authority['sshPath'] == ssh == qualification.SSH
                and type(authority['sshSha256']) is str and qualification.SHA.fullmatch(authority['sshSha256']),
                'controller-executable-authority-schema')
        qualification.executable_hash(ssh, int(deadline * 10**9), authority['sshSha256'])
        if authority['remote'] is not None:
            qualification.remote_schema(authority['remote'])
        require(isinstance(known_hosts, KnownHostAuthority), 'declared-existing-host-key-authority-required')
        self.known_hosts = known_hosts
        known_hosts.check()
        fence(deadline)
        self.env = {key: value for key, value in os.environ.items()
                    if key in ('HOME', 'SSH_AUTH_SOCK')}

    def call(self, script, bound=2 * 1024 * 1024, *, stage='authenticated-os-qualification'):
        remaining = self.deadline - time.monotonic() - RESERVE
        require(remaining > 0, 'shared-deadline-exhausted')
        self.known_hosts.check()
        primary = None
        try:
            status, output, error = owned_io([self.ssh, *self.known_hosts.options(),
                                            *SSH_OPTIONS, *self.options, HOST, script], self.env,
                                           min(self.deadline, time.monotonic() + remaining), bound)
            if status:
                raise ssh_failure(stage, status, error)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                self.known_hosts.check()
            except BaseException:
                if primary is not None:
                    primary.host_key_authority_recheck_failed = True
                else:
                    raise
        return output

    def nix_call(self, arguments, bound=2 * 1024 * 1024):
        return self.call(qualification.remote_command(int(self.deadline * 10**9),
            self.authority['remote'], shlex.split(arguments)), bound, stage='qualified-nix-readonly')

    def qualify(self):
        output = strict_json(self.call(qualification.remote_command(int(self.deadline * 10**9)), 8192))
        return qualification.remote_schema(output)

    def inspect(self):
        require(self.qualify() == self.authority['remote'], 'remote-qualification-changed')
        info = strict_json(self.nix_call(
            '--extra-experimental-features nix-command store info --json --store daemon', 8192))
        require(type(info) is dict and type(info.get('trusted')) is bool,
                'destination-daemon-trust-schema')
        return {'hostAlias': HOST, 'system': 'x86_64-linux',
                'authentication': 'existing-SSH-strict-host-key',
                'executableQualification': self.authority['remote'],
                'availableBytes': None,
                'daemonClientTrusted': info['trusted']}

    def verify(self, rows):
        names = ' '.join(shlex.quote(row['path']) for row in rows)
        actual = strict_json(self.nix_call(
            '--extra-experimental-features nix-command path-info --offline --json ' + names))
        registry(actual, rows)
        # Rehash actual destination bytes, rather than trusting its registry.
        for row in rows:
            output = self.nix_call(
                '--extra-experimental-features nix-command hash path --type sha256 --sri '
                + shlex.quote(row['path']), 4096).decode('ascii').strip()
            require(expected_hash(output) == expected_hash(row['narHash']),
                    'destination-nar-content-mismatch')

def read_public(path, maximum, deadline):
    fence(deadline)
    logical = Path(path)
    resolved = logical.resolve(strict=True)
    parents = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    descriptor = None
    identities = []
    try:
        for component in resolved.parts[1:-1]:
            fence(deadline)
            parents.append(os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=parents[-1]))
            info = os.fstat(parents[-1])
            sticky = str(Path(*resolved.parts[:len(parents)])) == '/nix/store' and stat.S_IMODE(info.st_mode) == 0o1775
            require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky and info.st_uid == 0),
                    'public-input-ancestor-custody')
            identities.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
        descriptor = os.open(resolved.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parents[-1])
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid())
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum,
                'public-input-custody')
        pieces = bytearray()
        while True:
            fence(deadline)
            data = os.read(descriptor, min(65536, maximum + 1 - len(pieces)))
            if not data:
                break
            pieces.extend(data)
            require(len(pieces) <= maximum, 'public-input-bound')
        fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
                               info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
        require(len(pieces) == before.st_size and logical.resolve(strict=True) == resolved and fields(before) == fields(os.fstat(descriptor))
                == fields(os.stat(resolved.name, dir_fd=parents[-1], follow_symlinks=False)) == fields(os.lstat(resolved)),
                'public-input-changed')
        for index, identity in enumerate(identities, 1):
            current = os.stat(resolved.parts[index], dir_fd=parents[index - 1], follow_symlinks=False)
            require((current.st_dev, current.st_ino, current.st_uid, current.st_mode) == identity,
                    'public-input-ancestor-rebound')
        return bytes(pieces)
    finally:
        qualification.release(([descriptor] if descriptor is not None else []) + list(reversed(parents)))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', required=True)
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--mode', choices=('qualify', 'inspect', 'verify'), required=True)
    parser.add_argument('--authority')
    parser.add_argument('--bootstrap-manifest', required=True)
    parser.add_argument('--known-hosts', required=True)
    args = parser.parse_args()
    require(os.environ.get('OMUX_YOGA_DELIVERY_MODE') == args.mode, 'fixed-guard-mode-envelope-required')
    deadline_text = os.environ.get('OMUX_YOGA_DELIVERY_DEADLINE_NS', '')
    authority_sha256 = os.environ.get('OMUX_YOGA_DELIVERY_AUTHORITY_SHA256', '')
    require(re.fullmatch(r'[0-9]{1,20}', deadline_text), 'guard-deadline-envelope-required')
    deadline = int(deadline_text) / 10**9
    require(RESERVE < deadline - time.monotonic() <= 1200, 'deadline-bound')
    rows = selected(read_public(args.inventory, 8 * 1024**2, deadline),
                    read_public(args.receipt, 8 * 1024**2, deadline))
    local = qualification.local_authority(read_public(args.bootstrap_manifest, 2 * 1024**2, deadline),
                                           rows, int(deadline * 10**9))
    if args.mode == 'qualify':
        require(args.authority is None and not authority_sha256, 'qualification-cannot-self-select-authority')
        authority = dict(local, remote=None)
    else:
        require(args.authority is not None and qualification.SHA.fullmatch(authority_sha256),
                'prior-guard-qualified-OS-receipt-required')
        authority_data = read_public(args.authority, 16384, deadline)
        require(hashlib.sha256(authority_data).hexdigest() == authority_sha256, 'prior-qualification-digest')
        evidence = strict_json(authority_data)
        require(type(evidence) is dict and set(evidence) == {'schemaVersion', 'scope', 'bootstrapManifestSha256',
            'inventorySha256', 'sourceReceiptSha256', 'sshPath', 'sshSha256', 'remote'}
            and type(evidence['schemaVersion']) is int and evidence['schemaVersion'] == 1
            and evidence['scope'] == 'yoga-authenticated-OS-executable-qualification-v1'
            and evidence['bootstrapManifestSha256'] == qualification.BOOTSTRAP_SHA
            and evidence['inventorySha256'] == INVENTORY_SHA and evidence['sourceReceiptSha256'] == RECEIPT_SHA
            and all(evidence[key] == local[key] for key in local), 'prior-qualification-controller-binding')
        authority = dict(local, remote=qualification.remote_schema(evidence['remote']))
    result = {'schemaVersion': 1, 'scope': 'yoga-controller-destination-readonly-v1',
              'inventorySha256': INVENTORY_SHA, 'sourceReceiptSha256': RECEIPT_SHA,
              'mode': args.mode, 'passed': False, 'remoteCleanup': 'unknown',
              'remoteOwnedContainmentVerified': False, 'copyPerformed': False,
              'destinationRegistrationVerified': False, 'destinationContentRehashed': False,
              'offlineGraphVerified': False, 'wrapperExecutionAuthority': False}
    try:
        with KnownHostAuthority(args.known_hosts, deadline) as known_hosts, operator_config() as options:
            backend = Backend(str(Path(args.ssh).resolve(strict=True)), options, deadline, authority, known_hosts)
            if args.mode == 'qualify':
                result['qualification'] = dict(schemaVersion=1,
                    scope='yoga-authenticated-OS-executable-qualification-v1',
                    bootstrapManifestSha256=qualification.BOOTSTRAP_SHA,
                    inventorySha256=INVENTORY_SHA, sourceReceiptSha256=RECEIPT_SHA,
                    **local, remote=backend.qualify())
            else:
                result['destination'] = backend.inspect()
            if args.mode == 'verify':
                backend.verify(rows)
                result['destinationRegistrationVerified'] = True
                result['destinationContentRehashed'] = True
        fence(deadline)
        result['sshHostKeyAuthority'] = host_key_record()
        result['narByteCountAuthority'] = 'registration size only; destination content independently SHA256-rehashed'
        result['passed'] = True
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, KeyboardInterrupt) as error:
        result['gate'] = str(error) if isinstance(error, GateError) else 'destination-input-or-operation-unavailable'
        if getattr(error, 'host_key_authority_recheck_failed', False):
            result['hostKeyAuthorityRecheck'] = 'failed'
        if isinstance(error, GateError) and error.hints:
            result['operationFailure'] = error.hints
        result['localCleanup'] = 'incomplete' if getattr(error, 'cleanup_incomplete', False) or getattr(error, '__notes__', ()) else 'completed-or-not-started'
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 2

if __name__ == '__main__':
    raise SystemExit(main())
