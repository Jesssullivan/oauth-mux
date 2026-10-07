"""Declared finite containment probes; never call a host manager or Nix daemon.

Manual Bazel targets select delegation, cancellation, daemon-session, or output.
Cancellation requires the external guard supervisor to be interrupted AFTER
probe-cancel.ready.json appears. Children expire themselves after 45 seconds;
there are exactly two children and no recursion. Probe completion alone does not
prove cleanup: pair exact PID/start-time records with the guard receipt and
outside /proc readback. No executable invocation is permitted outside Bazel.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

CHILD_SECONDS = 45
OUTPUT_BYTES = 9 * 1024 * 1024


def identity(pid=None):
    pid = os.getpid() if pid is None else pid
    text = Path('/proc/' + str(pid) + '/stat').read_text()
    # Process names may contain spaces or parentheses.
    fields = text[text.rindex(')') + 2:].split()
    return {'pid': pid, 'start_ticks': fields[19],
            'cgroup': Path('/proc/' + str(pid) + '/cgroup').read_text().strip(),
            'session': os.getsid(pid)}


def record(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(json.dumps(payload, sort_keys=True) + '\n')


def owned_run():
    path = Path(os.environ.get('OMUX_EXECUTION_GUARD', ''))
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ValueError('probe requires declared guard environment inheritance')
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError('private guard run required')
    return path


def daemon_child(marker):
    # Parent's new session is deliberately distinct from the TestRunner group.
    if os.fork():
        return 0
    os.setsid()
    record(marker, {'phase': 'finite-daemon-child', 'identity': identity(),
                    'self_expiry_seconds': CHILD_SECONDS})
    until = time.monotonic() + CHILD_SECONDS
    while time.monotonic() < until:
        time.sleep(0.1)
    os._exit(0)


def session_probe(run, cancellation):
    prefix = 'cancel' if cancellation else 'daemon'
    children = []
    for index in range(2):
        marker = run / ('probe-' + prefix + '-child-' + str(index) + '.json')
        child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                  '--child-marker', str(marker)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        children.append((child, marker))
    until = time.monotonic() + 5
    while time.monotonic() < until and not all(marker.exists() for _, marker in children):
        time.sleep(0.05)
    if not all(marker.exists() for _, marker in children):
        raise ValueError('finite child readiness failed')
    evidence = [json.loads(marker.read_text()) for _, marker in children]
    current = identity()
    if any(item['identity']['cgroup'] != current['cgroup'] or
           item['identity']['session'] == current['session'] for item in evidence):
        raise ValueError('child escaped cgroup or failed to establish distinct session')
    record(run / ('probe-' + prefix + '.ready.json'),
           {'phase': prefix + '-ready', 'parent': current, 'children': evidence,
            'acceptance': 'requires external guard cleanup and exact PID/start-time readback'})
    for child, _ in children:
        child.wait(timeout=5)
    if cancellation:
        # External cancellation should arrive first; finite failure avoids hanging.
        time.sleep(CHILD_SECONDS + 2)
        return 1
    return 0


def denied_socket(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(0.5)
        try:
            channel.connect(path)
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR,
                                   errno.ECONNREFUSED):
                raise
            return {'path': path, 'errno': error.errno, 'reachable': False}
    raise ValueError('host delegation socket remains reachable: ' + path)


def delegation_probe(run):
    paths = ['/run/user/' + str(os.getuid()) + '/bus',
             '/run/user/' + str(os.getuid()) + '/systemd/private',
             '/run/dbus/system_bus_socket', '/run/systemd/private',
             '/nix/var/nix/daemon-socket/socket']
    results = [denied_socket(path) for path in paths]
    record(run / 'probe-delegation.json', {'phase': 'delegation-denied', 'sockets': results,
           'acceptance': 'ENOENT/refused requires pre-dispatch host availability evidence'})
    return 0


def overflow(stream):
    block = b'containment-output-probe\n' * 2048
    remaining = OUTPUT_BYTES
    while remaining:
        data = block[:remaining]
        stream.write(data)
        remaining -= len(data)
    stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=['delegation', 'daemon-session', 'cancellation', 'output'])
    parser.add_argument('--child-marker', type=Path)
    args = parser.parse_args()
    if args.child_marker:
        return daemon_child(args.child_marker)
    run = owned_run()
    if args.phase == 'delegation':
        return delegation_probe(run)
    if args.phase in ('daemon-session', 'cancellation'):
        return session_probe(run, args.phase == 'cancellation')
    if args.phase == 'output':
        record(run / 'probe-output.ready.json', {'phase': 'output-overflow',
               'finite_bytes': OUTPUT_BYTES, 'expected_guard_exit': 125})
        overflow(sys.stdout.buffer)
        return 1  # test_output=errors exposes the finite payload to the guard.
    parser.error('explicit phase required')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.exit('finite containment probe rejected')
