"""Bounded presence-only observation of the named PZM REAPI operator lane."""
import argparse
import json
import os
import re
import subprocess
from ssh_policy import operator_config
from host_closure_transfer import bounded

MAX_SECONDS = 30

NAMES = ('BAZEL_REMOTE_EXECUTOR', 'BAZEL_REMOTE_CACHE', 'BAZEL_REMOTE_INSTANCE_NAME', 'BAZEL_CREDENTIAL_HELPER', 'GF_BAZEL_SUBSTRATE_MODE', 'GF_BAZEL_REMOTE_EXECUTION_PLATFORM', 'NIX_REMOTE', 'NIX_CONFIG', 'NIX_GET_COMPLETIONS')
COMMAND = r'''set -eu
for label in dev.tinyland.gf-reapi-darwin-cell dev.tinyland.gf-reapi-darwin-worker; do
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then value=present; else value=absent; fi
  printf '%s=%s\n' "$label" "$value"
  if test -f "/Library/LaunchDaemons/$label.plist" && test ! -L "/Library/LaunchDaemons/$label.plist"; then value=present; else value=absent; fi
  printf '%s.plist=%s\n' "$label" "$value"
done
for label in org.nixos.nix-daemon systems.determinate.nix-daemon; do
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then value=present; else value=absent; fi
  printf '%s=%s\n' "$label" "$value"
done
if test -S /nix/var/nix/daemon-socket/socket; then value=present; else value=absent; fi
printf 'nix_daemon_socket=%s\n' "$value"
for port in 8980 8981; do
  if /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then value=present; else value=absent; fi
  printf 'listener.%s=%s\n' "$port" "$value"
done
for file in authz/jwks.json tls/ca.crt tls/cell.crt tls/cell.key tls/worker.crt tls/worker.key; do
  if test -f "/etc/gf-reapi-darwin/$file" && test ! -L "/etc/gf-reapi-darwin/$file"; then value=present; else value=absent; fi
  printf 'credential.%s=%s\n' "$file" "$value"
done
''' + '\n'.join('if test -n "${' + name + ('+x' if name == 'NIX_GET_COMPLETIONS' else ':-') + '}"; then value=present; else value=absent; fi\nprintf "' + name + '=%s\\n" "$value"' for name in NAMES)

def summarize(output):
    if len(output) > 8192:
        raise ValueError('presence output bound')
    expected = {*NAMES, 'org.nixos.nix-daemon', 'systems.determinate.nix-daemon', 'nix_daemon_socket', 'listener.8980', 'listener.8981', 'dev.tinyland.gf-reapi-darwin-cell', 'dev.tinyland.gf-reapi-darwin-worker', 'dev.tinyland.gf-reapi-darwin-cell.plist', 'dev.tinyland.gf-reapi-darwin-worker.plist', *('credential.' + name for name in ('authz/jwks.json', 'tls/ca.crt', 'tls/cell.crt', 'tls/cell.key', 'tls/worker.crt', 'tls/worker.key'))}
    fields = {}
    for line in output.decode('ascii').splitlines():
        match = re.fullmatch(r'([A-Za-z0-9./_-]+)=(present|absent)', line)
        if not match or match[1] not in expected or match[1] in fields:
            raise ValueError('presence schema rejected')
        fields[match[1]] = match[2] == 'present'
    if set(fields) != expected:
        raise ValueError('presence fields missing')
    return fields

def observe(command, env):
    status, output, _ = bounded(command, env, seconds=MAX_SECONDS, bound=8192)
    if status:
        raise ValueError('host observation unavailable')
    return summarize(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', required=True)
    args = parser.parse_args()
    try:
        with operator_config() as options:
            env = {name: value for name, value in os.environ.items() if name in {'HOME', 'PATH', 'SSH_AUTH_SOCK'}}
            fields = observe([args.ssh, *options, '-oBatchMode=yes', '-oConnectTimeout=10', '-oConnectionAttempts=1', '-oStrictHostKeyChecking=yes', '-oForwardAgent=no', '-oClearAllForwardings=yes', 'pzm', COMMAND], env)
        print(json.dumps({'host_alias': 'pzm', 'scope': 'fixed presence only; no credential contents or service changes', 'passed': True, 'present': fields, 'readiness_proved': False}, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired, KeyboardInterrupt):
        print(json.dumps({'host_alias': 'pzm', 'passed': False, 'gate': 'bounded presence observation unavailable'}, sort_keys=True))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
