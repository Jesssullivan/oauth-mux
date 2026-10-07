"""Copy only the authorized exact Darwin closure through declared Nix and SSH."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from ssh_policy import operator_config

CLOSURE = '/nix/store/9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure'
METADATA_CLOSURE = '/nix/store/y8ymfapxc856x19kgqvj65l9xkfi76iz-closure-info'
HASHES = {'native.json': 'fdfeb78902a8fb28d2e7cff6c4516558c9b0b5e9c4b154b2981a49e561b25087', 'store-paths': '1fb5ca0076bc83a7cc5fb36e73abc4f15a892db8930aa56ff6fc1bbc57e32153', 'registration': '4c4d533eb8fa4d87215d292ad9ea8dfd9c2629d1538d51cad0430591f01cb3d3'}
STORE_PATH = r'/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+'
SSH_OPTIONS = ['-oBatchMode=yes', '-oConnectTimeout=10', '-oConnectionAttempts=1', '-oStrictHostKeyChecking=yes', '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no', '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no']

class GateError(ValueError):
    def __init__(self, name, hints=None):
        super().__init__(name)
        self.hints = hints or {}

def diagnostic_flags(stderr):
    value = stderr.decode('utf-8', errors='replace').lower()
    patterns = {'connection_refused': ('connection refused',), 'connection_timed_out': ('timed out',), 'connection_reset': ('connection reset',), 'host_key_rejected': ('host key verification failed',), 'host_unresolved': ('could not resolve hostname',), 'ssh_auth_rejected': ('permission denied (publickey',), 'daemon_mentioned': ('daemon',), 'daemon_socket_mentioned': ('daemon-socket', 'daemon socket', 'unix socket'), 'stdio_mentioned': ('stdio',), 'protocol_parse_mentioned': ('magic', 'serialization', 'serialisation', 'invalid reply', 'unexpected reply', 'bad message'), 'shell_startup_mentioned': ('last login', 'welcome', 'motd', 'banner', 'zsh:', 'bash:'), 'permission_mentioned': ('permission', 'denied', 'access rights', 'not executable'), 'trust_refusal_mentioned': ('not trusted', 'trusted user', 'not privileged'), 'store_capacity_mentioned': ('no space left', 'disk quota', 'insufficient space'), 'write_refusal_mentioned': ('read-only file system', 'cannot write', 'permission denied'), 'missing_tool_mentioned': ('no such file', 'command not found', 'cannot execute', 'execvp'), 'unsupported_operation_mentioned': ('unrecognised', 'unrecognized', 'unknown command', 'unknown flag', 'unexpected argument', 'invalid option', 'does not support', 'not supported'), 'stream_eof_mentioned': ('end-of-file', 'end of file', 'broken pipe')}
    return {name: any(pattern in value for pattern in needles) for name, needles in patterns.items()}

def public_version(output):
    if len(output) > 256:
        raise GateError('version-output-bound')
    text = output.decode('ascii').strip()
    match = re.fullmatch(r'(?:nix|nix-daemon)(?: \([A-Za-z0-9 ._+-]{1,80}\))? ([0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})?(?:[A-Za-z0-9+._-]{0,32}))', text)
    return match[1] if match else None

def bounded(command, env, seconds=60, bound=2 * 1024 * 1024):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=env)
    buffers = {True: bytearray(), False: bytearray()}
    deadline = time.monotonic() + seconds
    handlers = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.signal(signum, interrupted)
    with selectors.DefaultSelector() as selected:
        selected.register(proc.stdout, selectors.EVENT_READ, True)
        selected.register(proc.stderr, selectors.EVENT_READ, False)
        try:
            while selected.get_map() or proc.poll() is None:
                if time.monotonic() >= deadline:
                    raise GateError('bounded-operation-deadline')
                for key, _ in selected.select(min(1, max(0, deadline - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        selected.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(data)
                    if len(buffers[key.data]) > (bound if key.data else 65536):
                        raise GateError('bounded-operation-output')
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                status = proc.wait(timeout=5)
            finally:
                proc.stdout.close()
                proc.stderr.close()
                for signum, handler in handlers.items():
                    signal.signal(signum, handler)
    return status, bytes(buffers[True]), bytes(buffers[False])

def category(stderr):
    text = stderr.decode('utf-8', errors='replace').lower()
    for needles, name in [(('not privileged', 'not trusted', 'untrusted client', 'trusted user', 'not allowed to disable signature'), 'destination-trust-refused'), (('no space left', 'disk quota', 'not enough space', 'insufficient space'), 'store-capacity'), (('read-only file system', 'cannot write', 'unable to write'), 'store-write'), (('hash mismatch', 'nar hash', 'conflicting', 'already registered'), 'hash-or-registration-conflict'), (('interrupted', 'broken pipe', 'unexpected end-of-file', 'end of file', 'connection reset'), 'interrupted-transport'), (('signature',), 'store-signature-or-trust'), (('permission denied', 'operation not permitted'), 'store-or-ssh-permission'), (('unknown store', 'unsupported store', 'protocol mismatch', 'protocol version', 'stdio'), 'store-protocol'), (('cannot execute', 'executing', 'execvp'), 'store-tool-execution'), (('not valid', 'does not exist', 'no such file'), 'store-input-missing'), (('connection', 'host key', 'resolve hostname'), 'store-transport')]:
        if any(needle in text for needle in needles):
            return name
    return 'declared-nix-operation-failed'

def store_paths(data):
    if len(data) > 32768:
        raise GateError('store-path-metadata-bound')
    paths = data.decode('ascii').splitlines()
    if len(paths) != 126 or len(set(paths)) != len(paths) or any(not re.fullmatch(STORE_PATH, path) for path in paths):
        raise GateError('exact-store-path-schema')
    return paths

def local_metadata():
    members = {}
    for name, expected in HASHES.items():
        with (Path(CLOSURE) / name).open('rb') as stream:
            data = stream.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
            raise GateError('exact-closure-metadata-mismatch')
        members[name] = data
    native = json.loads(members['native.json'])
    if native['system'] != 'aarch64-darwin' or native['apple']['sdk_version'] != '14.4':
        raise GateError('exact-closure-platform-mismatch')
    paths = store_paths(members['store-paths'])
    return paths, registration_metadata(members['registration'], paths)

def registration_metadata(data, paths):
    lines = data.decode('ascii').splitlines()
    if len(lines) != 1018:
        raise GateError('fixed-registration-line-count')
    records = {}
    cursor = 0
    alphabet = '0123456789abcdfghijklmnpqrsvwxyz'
    while cursor < len(lines):
        if cursor + 5 > len(lines):
            raise GateError('fixed-registration-schema')
        path, hash_text, size, deriver, count = lines[cursor:cursor + 5]
        if not re.fullmatch(STORE_PATH, path) or path in records or not re.fullmatch(r'sha256:[0-9abcdfghijklmnpqrsvwxyz]{52}', hash_text) or not re.fullmatch(r'[1-9][0-9]{0,15}', size) or not re.fullmatch(r'[0-9]{1,3}', count) or (deriver and not re.fullmatch(STORE_PATH + r'\.drv', deriver)):
            raise GateError('fixed-registration-schema')
        cursor += 5
        refs = lines[cursor:cursor + int(count)]
        if len(refs) != int(count) or len(set(refs)) != len(refs) or any(not re.fullmatch(STORE_PATH, ref) for ref in refs):
            raise GateError('fixed-registration-references')
        cursor += len(refs)
        number = 0
        for character in hash_text.split(':', 1)[1]:
            number = number * 32 + alphabet.index(character)
        if number >= 1 << 256:
            raise GateError('fixed-registration-hash-range')
        sri = 'sha256-' + base64.b64encode(number.to_bytes(32, 'little')).decode('ascii')
        records[path] = {'narHash': sri, 'narSize': int(size), 'references': sorted(refs)}
    if set(records) != set(paths) or any(ref not in records for record in records.values() for ref in record['references']):
        raise GateError('fixed-registration-set')
    return records

def registered(output, paths, expected):
    value = json.loads(output)
    if not isinstance(value, dict) or len(value) > 256:
        raise GateError('registration-schema')
    if set(value) != set(paths + [CLOSURE, METADATA_CLOSURE]):
        raise GateError('exact-complete-registration-set')
    if set(expected) != set(paths):
        raise GateError('fixed-registration-set')
    if any(not re.fullmatch(STORE_PATH, path) or not isinstance(info, dict) or type(info.get('narSize')) is not int or info['narSize'] <= 0 or not isinstance(info.get('narHash'), str) or not re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', info['narHash']) or not isinstance(info.get('references'), list) or any(not isinstance(ref, str) or not re.fullmatch(STORE_PATH, ref) for ref in info['references']) for path, info in value.items()):
        raise GateError('registration-schema')
    for path, record in expected.items():
        info = value[path]
        if {key: sorted(info[key]) if key == 'references' else info[key] for key in record} != record:
            raise GateError('fixed-registration-nar-or-reference-mismatch')
    if any(ref not in value for info in value.values() for ref in info['references']):
        raise GateError('unexpected-recursive-reference')
    return {'registered_path_count': len(value), 'nar_bytes': sum(info['narSize'] for info in value.values()), 'registration_identity_sha256': hashlib.sha256(json.dumps({path: {'narHash': info['narHash'], 'narSize': info['narSize'], 'references': sorted(info['references'])} for path, info in value.items()}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}

def remote_probe(ssh, options, host, env):
    command = r'''set -eu
omux_nix=/nix/var/nix/profiles/default/bin/nix-daemon
omux_parent=$(cd -P "${omux_nix%/*}" && pwd -P)
omux_nix="$omux_parent/${omux_nix##*/}"
omux_daemon="$omux_nix"
omux_hops=0
while test -L "$omux_nix"; do
  omux_hops=$((omux_hops + 1)); test "$omux_hops" -le 16 || exit 3
  omux_target=$(readlink "$omux_nix")
  case "$omux_target" in /*) omux_nix="$omux_target" ;; *) omux_nix="${omux_nix%/*}/$omux_target" ;; esac
done
omux_parent=$(cd -P "${omux_nix%/*}" && pwd -P)
omux_nix="$omux_parent/${omux_nix##*/}"
case "$omux_nix" in /nix/store/*/bin/nix|/nix/store/*/bin/nix-daemon) ;; *) printf 'daemon-rejected\n' >&2; exit 3 ;; esac
test -x "$omux_nix" && test ! -L "$omux_nix" || exit 3
case "$omux_daemon" in /nix/store/*/bin/nix-daemon) ;; *) printf 'daemon-alias-rejected\n' >&2; exit 3 ;; esac
printf 'daemon=%s\n' "$omux_daemon"
if omux_version=$("$omux_daemon" --version 2>/dev/null); then omux_status=0; else omux_status=$?; fi
case "$omux_version" in *[!A-Za-z0-9\ ._+\(\)-]*) omux_version=unavailable ;; esac
test "${#omux_version}" -le 256 || exit 3
printf 'daemon_version=%s\ndaemon_version_exit_code=%s\n' "$omux_version" "$omux_status"
''' + 'omux_closure=' + shlex.quote(CLOSURE) + '\n' + r'''if test -d "$omux_closure" && test ! -L "$omux_closure"; then
  printf 'closure=present\n'
  for omux_member in native.json store-paths registration; do
    omux_hash=$(/usr/bin/shasum -a 256 "$omux_closure/$omux_member"); omux_hash=${omux_hash%% *}
    printf '%s=%s\n' "$omux_member" "$omux_hash"
  done
  omux_declared=0
  omux_present=0
  while IFS= read -r omux_path; do
    case "$omux_path" in /nix/store/*) ;; *) exit 3 ;; esac
    case "$omux_path" in */../*|*/./*|*//*) exit 3 ;; esac
    omux_declared=$((omux_declared + 1)); test "$omux_declared" -le 126 || exit 3
    if test -e "$omux_path"; then omux_present=$((omux_present + 1)); fi
  done < "$omux_closure/store-paths"
  printf 'declared_members=%s\nphysical_members=%s\n' "$omux_declared" "$omux_present"
else printf 'closure=absent\n'; fi
'''
    status, output, error = bounded([ssh, *options, *SSH_OPTIONS, host, command], env, seconds=30, bound=8192)
    if status:
        raise GateError(category(error), diagnostic_flags(error))
    fields = {}
    for line in output.decode('ascii').splitlines():
        key, value = line.split('=', 1)
        if key in fields or key not in {'daemon', 'daemon_version', 'daemon_version_exit_code', 'closure', 'declared_members', 'physical_members', *HASHES}:
            raise GateError('remote-probe-schema')
        fields[key] = value
    if not re.fullmatch(STORE_PATH + r'/bin/nix-daemon', fields.get('daemon', '')) or fields.get('closure') not in {'present', 'absent'}:
        raise GateError('remote-probe-schema')
    if not re.fullmatch(r'[0-9]{1,3}', fields.get('daemon_version_exit_code', '')) or int(fields['daemon_version_exit_code']) > 255:
        raise GateError('remote-version-status-schema')
    if fields['closure'] == 'present' and {name: fields.get(name) for name in HASHES} != HASHES:
        raise GateError('exact-remote-closure-metadata-mismatch')
    if fields['closure'] == 'present' and (fields.get('declared_members') != '126' or not re.fullmatch(r'[0-9]{1,3}', fields.get('physical_members', '')) or int(fields['physical_members']) > 126):
        raise GateError('exact-remote-closure-member-schema')
    if fields['closure'] == 'absent' and set(fields) != {'daemon', 'daemon_version', 'daemon_version_exit_code', 'closure'}:
        raise GateError('remote-probe-schema')
    return fields

def immutable_sibling_cli(daemon):
    if not re.fullmatch(STORE_PATH + r'/bin/nix-daemon', daemon):
        raise GateError('remote-daemon-path-schema')
    return daemon.rsplit('/', 1)[0] + '/nix'

def local_daemon_comparison(ssh, options, host, env, daemon):
    cli = immutable_sibling_cli(daemon)
    command = 'omux_cli=' + shlex.quote(cli) + '; test -x "$omux_cli" && test ! -L "$omux_cli" || exit 3; exec "$omux_cli" --extra-experimental-features nix-command store info --json --store daemon'
    try:
        status, output, error = bounded([ssh, *options, *SSH_OPTIONS, host, command], env, seconds=30, bound=8192)
    except OSError:
        raise GateError('local-daemon-adapter-operation-unavailable') from None
    if status:
        raise GateError(category(error), diagnostic_flags(error))
    try:
        connection = json.loads(output)
    except (ValueError, UnicodeError):
        raise GateError('local-daemon-response-framing', {
            'response_empty': not output.strip(),
            'response_has_json_object_prefix': output.lstrip().startswith(b'{'),
            'response_has_warning_prefix': output.lstrip().lower().startswith(b'warning:'),
            'response_has_nix_help_marker': b'Usage:' in output or b'Synopsis' in output,
        }) from None
    if not isinstance(connection, dict) or type(connection.get('trusted')) is not bool:
        raise GateError('local-daemon-trust-schema-unavailable')
    return {'local_daemon_store_connected': True, 'local_daemon_client_trusted': connection['trusted']}

def coordinator_info(nix, env):
    status, output, error = bounded([nix, '--version'], env, bound=8192)
    if status:
        raise GateError(category(error), diagnostic_flags(error))
    version = public_version(output)
    status, output, error = bounded([nix, '--extra-experimental-features', 'nix-command', 'store', 'info', '--json', '--store', 'daemon'], env, seconds=30, bound=8192)
    if status:
        raise GateError(category(error), diagnostic_flags(error))
    try:
        connection = json.loads(output)
    except (ValueError, UnicodeError):
        raise GateError('coordinator-store-info-response-framing') from None
    if not isinstance(connection, dict) or type(connection.get('trusted')) is not bool:
        raise GateError('coordinator-store-info-trust-schema-unavailable')
    return {'coordinator_nix_version': version, 'coordinator_store_info_command_supported': True, 'coordinator_daemon_store_connected': True, 'coordinator_daemon_client_trusted': connection['trusted']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nix', required=True)
    parser.add_argument('--ssh', required=True)
    parser.add_argument('--mode', choices=('inspect', 'inspect-pzm', 'protocol-neo', 'protocol-pzm', 'local-daemon-pzm', 'coordinator-info', 'pull-neo', 'push-pzm'), required=True)
    args = parser.parse_args()
    result = {'mode': args.mode, 'closure_basename': CLOSURE.rsplit('/', 1)[1], 'passed': False, 'worker_routing_proved': False}
    try:
        # Bazel output aliases are shared by concurrent configurations. Pin each
        # declared executable's actual runfile before starting a long transfer.
        args.ssh = str(Path(args.ssh).resolve(strict=True))
        args.nix = str(Path(args.nix).resolve(strict=True))
        if args.mode == 'coordinator-info':
            env = {name: value for name, value in os.environ.items() if name in {'HOME', 'SSH_AUTH_SOCK'}}
            result.update(coordinator_info(args.nix, env))
            result['scope'] = 'read-only declared coordinator Nix command and local daemon trust metadata; no SSH or copy'
            result['passed'] = True
            print(json.dumps(result, sort_keys=True))
            return 0
        with operator_config() as options, tempfile.TemporaryDirectory(prefix='omux-exact-closure-') as scratch:
            binary = Path(scratch) / 'bin'
            binary.mkdir(mode=0o700)
            (binary / 'ssh').symlink_to(Path(args.ssh).absolute())
            env = {name: value for name, value in os.environ.items() if name in {'HOME', 'SSH_AUTH_SOCK'}}
            env.update({'PATH': str(binary), 'NIX_SSHOPTS': shlex.join([*options, *SSH_OPTIONS])})
            host = 'pzm' if args.mode in {'push-pzm', 'inspect-pzm', 'protocol-pzm', 'local-daemon-pzm'} else 'neo'
            remote = remote_probe(args.ssh, options, host, env)
            result['remote_closure_metadata_matches'] = remote['closure'] == 'present'
            result['remote_daemon_version_command_available'] = remote['daemon_version_exit_code'] == '0'
            result['remote_nix_version'] = public_version(remote['daemon_version'].encode('ascii'))
            status, local_version, error = bounded([args.nix, '--version'], env, bound=8192)
            if status:
                raise GateError(category(error), diagnostic_flags(error))
            result['coordinator_nix_version'] = public_version(local_version)
            result['same_nix_release_line'] = bool(result['remote_nix_version'] and result['coordinator_nix_version'] and result['remote_nix_version'].split('.')[:2] == result['coordinator_nix_version'].split('.')[:2])
            if remote['closure'] == 'present':
                result['remote_physical_member_count'] = int(remote['physical_members'])
            if args.mode == 'local-daemon-pzm':
                result.update(local_daemon_comparison(args.ssh, options, host, env, remote['daemon']))
                result['scope'] = 'read-only PZM local daemon socket and client trust metadata; no SSH-ng protocol retry or copy'
                result['passed'] = True
                print(json.dumps(result, sort_keys=True))
                return 0
            remote_store = 'ssh-ng://' + host + '?remote-program=' + remote['daemon']
            status, output, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'store', 'ping', '--json', '--store', remote_store], env, bound=8192)
            if status:
                raise GateError(category(error), diagnostic_flags(error))
            connection = json.loads(output)
            if not isinstance(connection, dict) or type(connection.get('trusted')) is not bool:
                raise GateError('remote-store-trust-schema-unavailable')
            result['remote_store_protocol_connected'] = True
            result['remote_store_client_trusted'] = connection['trusted']
            result['per_copy_signature_override_authority_present'] = connection['trusted']
            if args.mode == 'push-pzm' and not connection['trusted']:
                raise GateError('destination-trust-refused')
            if args.mode in {'protocol-pzm', 'protocol-neo'}:
                result['scope'] = 'read-only remote store protocol and client trust metadata; no copy'
                result['passed'] = True
                print(json.dumps(result, sort_keys=True))
                return 0
            if args.mode == 'pull-neo':
                if remote['closure'] != 'present':
                    raise GateError('exact-source-closure-absent')
                result['source_trust'] = 'authenticated existing Neo SSH; three exact metadata hashes; unsigned source accepted only for this exact recursive copy'
                result['signature_provenance_proved'] = False
                status, _, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'copy', '--no-check-sigs', '--from', remote_store, CLOSURE], env, seconds=1800)
                if status:
                    raise GateError(category(error), diagnostic_flags(error))
            paths, expected = local_metadata()
            status, output, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'path-info', '--offline', '--recursive', '--json', CLOSURE], env)
            if status:
                raise GateError(category(error), diagnostic_flags(error))
            result['coordinator'] = registered(output, paths, expected)
            coordinator_records = json.loads(output)
            for extra in (CLOSURE, METADATA_CLOSURE):
                status, actual, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'hash', 'path', '--type', 'sha256', '--sri', extra], env, bound=8192)
                if status:
                    raise GateError(category(error), diagnostic_flags(error))
                if actual.decode('ascii').strip() != coordinator_records[extra]['narHash']:
                    raise GateError('extra-closure-nar-integrity-mismatch')
            result['coordinator']['fixed_registration_reconciled'] = True
            result['coordinator']['declared_member_count'] = len(paths)
            result['coordinator']['physical_members_present'] = all(Path(path).exists() for path in paths)
            if not result['coordinator']['physical_members_present']:
                raise GateError('complete-materialization-missing')
            if args.mode in {'push-pzm', 'inspect-pzm'}:
                if args.mode == 'push-pzm':
                    result['source_trust'] = 'fixed registration reconciled coordinator; authenticated existing PZM SSH; unsigned source accepted only for this exact recursive copy'
                    result['signature_provenance_proved'] = False
                    status, _, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'copy', '--no-check-sigs', '--to', remote_store, CLOSURE], env, seconds=1800)
                    if status:
                        raise GateError(category(error), diagnostic_flags(error))
                status, output, error = bounded([args.nix, '--extra-experimental-features', 'nix-command', 'path-info', '--store', remote_store, '--recursive', '--json', CLOSURE], env)
                if status:
                    raise GateError(category(error), diagnostic_flags(error))
                result['pzm'] = registered(output, paths, expected)
                if result['pzm']['registration_identity_sha256'] != result['coordinator']['registration_identity_sha256']:
                    raise GateError('coordinator-target-registration-identity-mismatch')
                result['pzm']['fixed_registration_reconciled'] = True
                remote = remote_probe(args.ssh, options, host, env)
                result['remote_closure_metadata_matches'] = remote['closure'] == 'present'
                if remote['closure'] == 'present':
                    result['remote_physical_member_count'] = int(remote['physical_members'])
                if not result['remote_closure_metadata_matches']:
                    raise GateError('exact-target-closure-absent')
                if remote['physical_members'] != '126':
                    raise GateError('complete-target-materialization-missing')
            result['passed'] = True
    except (OSError, ValueError, UnicodeError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        result['gate'] = str(error) if isinstance(error, GateError) else 'bounded-input-or-operation-unavailable'
        if isinstance(error, GateError) and error.hints:
            result['failure_hints'] = error.hints
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 2

if __name__ == '__main__':
    raise SystemExit(main())
